
import os
import json
import logging
import pandas as pd
import mysql.connector
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MYSQL_DB_NAME = "sift_benchmarks"
# Assuming standard paths
CODEMIRAGE_TEST_CSV = os.path.join("data", "sift", "test.csv")
CODEMIRAGE_TRAIN_CSV = os.path.join("data", "sift", "train.csv")

def load_codemirage_metadata():
    """Loads metadata (source, variant) from CSVs, indexed by 'cm-{index}'."""
    metadata = {}
    for csv_path in [CODEMIRAGE_TEST_CSV, CODEMIRAGE_TRAIN_CSV]:
        if os.path.exists(csv_path):
            logger.info(f"Loading metadata from {csv_path}...")
            try:
                df = pd.read_csv(csv_path)
                for index, row in df.iterrows():
                    variant = row.get('variant')
                    if pd.isna(variant):
                         variant = 'Normal'
                    
                    item_id = f"cm-{index}"
                    metadata[item_id] = {
                        "source": row.get('source', 'Unknown'),
                        "variant": variant,
                        "code": row.get('code') or row.get('snippet') or row.get('content'),
                        "language": row.get('language', 'Unknown')
                    }
            except Exception as e:
                logger.error(f"Error loading {csv_path}: {e}")
    return metadata

def backfill():
    load_dotenv()
    host = os.getenv("DB_HOST", "localhost")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    
    try:
        cnx = mysql.connector.connect(host=host, user=user, password=password, database=MYSQL_DB_NAME)
        cursor = cnx.cursor(dictionary=True, buffered=True)
        update_cursor = cnx.cursor(buffered=True)

        logger.info("Connecting to MySQL...")
        
        # 1. Load CSV Metadata
        meta_map = load_codemirage_metadata()
        
        # 2. Fetch all records needing backfill
        # We check records where ground_truth is NULL or variant is NULL or code_snippet IS NULL
        cursor.execute("SELECT id, example_id, sift_score, sift_issues FROM benchmark_results WHERE ground_truth IS NULL OR variant IS NULL OR code_snippet IS NULL")
        rows = cursor.fetchall()
        
        logger.info(f"Found {len(rows)} records to backfill.")
        
        updated_count = 0
        
        for row in rows:
            record_id = row['id']
            example_id = row['example_id']
            score = row['sift_score']
            issues_json = row['sift_issues']
            
            # Lookup metadata
            meta = meta_map.get(example_id)
            if not meta:
                logger.warning(f"Metadata not found for {example_id}, skipping.")
                continue
                
            source = meta['source']
            variant = meta['variant']
            
            code = meta.get('code', '')
            language = meta.get('language', 'Unknown')
            
            # Metric Calculation Logic
            # GT: Human=0, AI=1
            ground_truth = 0 if source == 'Human' else 1
            
            # Prediction: Score < 70 OR Hallucinated Import/Logic Gap
            sift_prediction = 0
            try:
                issues_list = json.loads(issues_json) if issues_json else []
                flagged_types = [i.get('type') for i in issues_list]
                
                # Sift < 70 OR Specific Issues
                if (score is not None and score < 70) or \
                   'Hallucinated Import' in flagged_types or \
                   'Logic Gap' in flagged_types:
                    sift_prediction = 1
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON for issue in {example_id}")
                pass

            # Update DB
            update_query = """
                UPDATE benchmark_results 
                SET ground_truth = %s, sift_prediction = %s, variant = %s, source = %s, code_snippet = %s, language = %s
                WHERE id = %s
            """
            update_cursor.execute(update_query, (ground_truth, sift_prediction, variant, source, code, language, record_id))
            updated_count += 1
            
            if updated_count % 100 == 0:
                logger.info(f"Updated {updated_count} records...")
                cnx.commit()
        
        cnx.commit()
        logger.info(f"Backfill complete. Updated {updated_count} records.")
        
        cursor.close()
        update_cursor.close()
        cnx.close()
        
    except mysql.connector.Error as err:
        logger.error(f"MySQL Error: {err}")

if __name__ == "__main__":
    backfill()
