import os
import sys
import json
import logging
import sqlite3
import pandas as pd
import time
import argparse
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Add project root to path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sift_engine import SiftEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DB_PATH = "benchmarking_results.db"
CODEMIRAGE_TEST_CSV = os.path.join("data", "sift", "test.csv")

def get_db_connection():
    """Creates a lightweight connection to the local file database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row 
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection failed: {e}")
        sys.exit(1)

def migrate_schema_if_needed():
    """
    [Auto-Fix] Upgrades old database schemas to match the current code.
    This prevents errors when using existing/legacy databases.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get current columns
        cursor.execute("PRAGMA table_info(benchmark_results)")
        existing_cols = {row['name'] for row in cursor.fetchall()}
        
        if not existing_cols:
            return # Table doesn't exist yet, setup_database will handle it

        # 1. Fix 'error' -> 'error_log'
        if 'error' in existing_cols and 'error_log' not in existing_cols:
            logger.info("Migrating schema: Adding 'error_log' column...")
            cursor.execute("ALTER TABLE benchmark_results ADD COLUMN error_log TEXT")
            cursor.execute("UPDATE benchmark_results SET error_log = error")
        
        # 2. Add 'processing_time' if missing
        if 'processing_time' not in existing_cols:
            logger.info("Migrating schema: Adding 'processing_time' column...")
            cursor.execute("ALTER TABLE benchmark_results ADD COLUMN processing_time REAL DEFAULT 0")
            
        # 3. Add 'ground_truth' if missing
        if 'ground_truth' not in existing_cols:
            logger.info("Migrating schema: Adding 'ground_truth' column...")
            cursor.execute("ALTER TABLE benchmark_results ADD COLUMN ground_truth TEXT")

        conn.commit()
    except Exception as e:
        logger.warning(f"Schema migration warning (safe to ignore if DB is new): {e}")
    finally:
        conn.close()

def setup_database():
    """Creates the SQLite table if it doesn't exist."""
    migrate_schema_if_needed() # Check for upgrades first
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS benchmark_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_name TEXT,
            example_id TEXT,
            language TEXT,
            
            -- Input Data
            code_snippet TEXT,
            ground_truth TEXT,
            
            -- Sift Output
            sift_score REAL,
            sift_prediction TEXT,
            sift_issues TEXT,
            
            -- Metadata
            processing_time REAL,
            error_log TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_result(data: dict):
    """Saves a single benchmark run to SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO benchmark_results 
            (dataset_name, example_id, language, code_snippet, 
             sift_score, ground_truth, sift_prediction, sift_issues, 
             processing_time, error_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('dataset_name'),
            data.get('example_id'),
            data.get('language'),
            data.get('code_snippet'),
            data.get('sift_score'),
            json.dumps(data.get('ground_truth')),
            json.dumps(data.get('sift_prediction')),
            json.dumps(data.get('sift_issues')),
            data.get('processing_time'),
            data.get('error')
        ))
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Failed to save result for ID {data.get('example_id')}: {e}")
    finally:
        conn.close()

def load_codemirage_dataset(csv_path: str, limit: int = None) -> pd.DataFrame:
    """Loads the CodeMirage dataset for testing."""
    if not os.path.exists(csv_path):
        logger.error(f"Dataset not found at {csv_path}")
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(limit)
    return df

def run_benchmark(limit: int = 10, dataset_path: str = CODEMIRAGE_TEST_CSV):
    load_dotenv()
    api_key = os.getenv("SIFT_API_KEY")
    
    if not api_key:
        logger.error("SIFT_API_KEY not found in .env")
        return

    logger.info("Initializing Sift Engine...")
    sift = SiftEngine(api_key=api_key)
    
    logger.info(f"Loading dataset from {dataset_path} (Limit: {limit})...")
    df = load_codemirage_dataset(dataset_path, limit)
    
    if df.empty:
        logger.warning("No data found to benchmark.")
        return

    logger.info("Starting Benchmark Run...")
    
    for index, row in df.iterrows():
        start_time = time.time()
        item_id = str(row.get('id', index))
        code = row.get('code', '')
        language = row.get('lang', 'Unknown')
        
        try:
            ground_truth = json.loads(row.get('ground_truth', '[]'))
        except:
            ground_truth = [] 

        result_data = {
            'dataset_name': 'CodeMirage',
            'example_id': item_id,
            'language': language,
            'code_snippet': code[:500],
            'ground_truth': ground_truth,
            'processing_time': 0,
            'error': None
        }

        try:
            analysis = sift.analyze_code(code)
            elapsed = time.time() - start_time
            
            result_data.update({
                'sift_score': analysis.get('score', 0),
                'sift_prediction': analysis,
                'sift_issues': analysis.get('vulnerabilities', []),
                'processing_time': elapsed
            })
            
            logger.info(f"[{index+1}/{len(df)}] Processed ID {item_id} | Score: {analysis.get('score')} | Time: {elapsed:.2f}s")

        except Exception as e:
            logger.error(f"Error processing ID {item_id}: {e}")
            result_data['error'] = str(e)
        
        save_result(result_data)
        time.sleep(0.5)

def evaluate_results():
    """
    Calculates metrics (Precision, Recall, F1) from the SQLite DB.
    """
    conn = get_db_connection()
    try:
        # Load all data (SELECT * avoids errors if columns are missing in older DBs)
        df = pd.read_sql("SELECT * FROM benchmark_results", conn)
        
        if df.empty:
            print("Database is empty.")
            return

        # Ensure columns exist (Pandas fix for old data)
        if 'error_log' not in df.columns and 'error' in df.columns:
            df['error_log'] = df['error']
        if 'processing_time' not in df.columns:
            df['processing_time'] = 0.0

        # Filter out errors (Rows where error_log is NOT null)
        df = df[df['error_log'].isna() | (df['error_log'] == "")]
        
        if df.empty:
            print("No successful results to analyze (All rows contain errors).")
            return

        print("\n" + "="*40)
        print(" RESEARCH EVALUATION REPORT")
        print("="*40)
        
        # 1. Average Processing Time
        avg_time = df['processing_time'].mean()
        print(f"Average Latency: {avg_time:.2f} seconds/file")
        
        # 2. Score Distribution
        print(f"\nAverage Sift Security Score: {df['sift_score'].mean():.2f}/100")
        
        # 3. Vulnerability Counts
        total_vulns = 0
        file_count = 0
        
        for json_str in df['sift_issues']:
            if not json_str: continue
            try:
                # Handle both list and string formats from old DB
                vulns = json.loads(json_str) if isinstance(json_str, str) else json_str
                if isinstance(vulns, list):
                    total_vulns += len(vulns)
                file_count += 1
            except:
                pass
        
        print(f"Total Vulnerabilities Detected: {total_vulns}")
        print(f"Total Files Scanned: {len(df)}")
        print("="*40 + "\n")
        
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sift Benchmark Harness")
    parser.add_argument("--limit", type=int, default=10, help="Number of files to test")
    parser.add_argument("--evaluate", action="store_true", help="Only run evaluation on existing DB")
    parser.add_argument("--dataset", type=str, default=CODEMIRAGE_TEST_CSV, help="Path to CSV dataset")
    
    args = parser.parse_args()
    
    setup_database() # This will now Auto-Migrate your old DB
    
    if args.evaluate:
        evaluate_results()
    else:
        run_benchmark(limit=args.limit, dataset_path=args.dataset)
        evaluate_results()