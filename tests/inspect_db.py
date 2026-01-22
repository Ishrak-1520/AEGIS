import sqlite3
import pandas as pd
import os

DB_PATH = "benchmarking_results.db"

if not os.path.exists(DB_PATH):
    print(f"❌ ERROR: File '{DB_PATH}' not found in this directory.")
    print(f"   Current Directory: {os.getcwd()}")
    exit()

print(f"✅ Found database: {DB_PATH}")

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    if not tables:
        print("❌ The database exists but has NO tables. It is completely empty.")
    else:
        print(f"\n📊 Found {len(tables)} table(s):")
        for t in tables:
            table_name = t[0]
            # Count rows in each table
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            print(f"   - Table: '{table_name}' | Rows: {count}")
            
            # Show first row sample
            if count > 0:
                print(f"     [Sample Data from '{table_name}']:")
                df = pd.read_sql(f"SELECT * FROM {table_name} LIMIT 1", conn)
                print(df.to_string(index=False))
                print("-" * 40)

    conn.close()

except Exception as e:
    print(f"❌ Error reading database: {e}")