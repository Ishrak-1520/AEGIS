
import mysql.connector
import json
import os
from dotenv import load_dotenv

def analyze_failures():
    load_dotenv()
    cnx = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database="sift_benchmarks"
    )
    cursor = cnx.cursor(dictionary=True)

    print("\n=== FALSE NEGATIVES (Missed Hallucinations) ===")
    cursor.execute("SELECT example_id, sift_score, sift_issues, source FROM benchmark_results WHERE ground_truth=1 AND sift_prediction=0 LIMIT 5")
    for r in cursor.fetchall():
        print(f"ID: {r['example_id']} | Source: {r['source']} | Score: {r['sift_score']}")
        print(f"Issues: {r['sift_issues']}")
        print("-" * 20)

    print("\n=== FALSE POSITIVES (Wrongly Flagged Clean Code) ===")
    cursor.execute("SELECT example_id, sift_score, sift_issues FROM benchmark_results WHERE ground_truth=0 AND sift_prediction=1 LIMIT 5")
    for r in cursor.fetchall():
        print(f"ID: {r['example_id']} | Score: {r['sift_score']}")
        print(f"Issues: {r['sift_issues']}")
        print("-" * 20)
    
    cnx.close()

if __name__ == "__main__":
    analyze_failures()
