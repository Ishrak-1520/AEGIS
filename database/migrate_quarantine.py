import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cyberguard.db')
print(f"Migrating database at: {db_path}")

conn = sqlite3.connect(db_path)
try:
    conn.execute("ALTER TABLE quarantine ADD COLUMN encryption_key TEXT")
    conn.commit()
    print("✅ Added encryption_key column to quarantine table")
except Exception as e:
    print(f"⚠️ Migration note: {e}")
finally:
    conn.close()
