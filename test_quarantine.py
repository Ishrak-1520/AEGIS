"""
Test Secure Quarantine
"""
import sys
import os
import time
import hashlib

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.quarantine import quarantine_manager
from database.db_manager import db_manager

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        sha256.update(f.read())
    return sha256.hexdigest()

def test_secure_quarantine():
    print("\n[TEST] Secure Quarantine")
    
    # Create a test file
    test_file = os.path.abspath("test_virus.txt")
    content = b"This is a test virus file content. It should be encrypted."
    with open(test_file, "wb") as f:
        f.write(content)
        
    original_hash = calculate_hash(test_file)
    print(f"Created test file: {test_file} (Hash: {original_hash[:8]})")
    
    try:
        # Quarantine file
        print("Quarantining file...")
        success = quarantine_manager.quarantine_file(test_file, "TEST_THREAT", "Test Virus")
        
        if success:
            print("✅ Quarantined successfully")
            
            # Check if original is gone
            if not os.path.exists(test_file):
                print("✅ Original file removed")
            else:
                print("❌ Original file still exists")
                
            # Get quarantine record
            quarantined_files = quarantine_manager.get_quarantined_files()
            if not quarantined_files:
                print("❌ No quarantine record found")
                return
                
            record = quarantined_files[0] # Most recent
            q_path = record['quarantine_path']
            q_id = record['id']
            
            print(f"Quarantine Path: {q_path}")
            
            # Check encryption
            with open(q_path, 'rb') as f:
                q_content = f.read()
                
            if q_content == content:
                print("❌ FAILED: Quarantine file is NOT encrypted (matches original)")
            else:
                print("✅ SUCCESS: Quarantine file is encrypted (content differs)")
                
            # Restore file
            print("Restoring file...")
            success = quarantine_manager.restore_file(q_id)
            
            if success:
                print("✅ Restored successfully")
                
                if os.path.exists(test_file):
                    restored_hash = calculate_hash(test_file)
                    if restored_hash == original_hash:
                        print("✅ SUCCESS: Restored file matches original")
                    else:
                        print("❌ FAILED: Restored file corrupted")
                else:
                    print("❌ FAILED: Restored file not found")
            else:
                print("❌ Restore failed")
                
        else:
            print("❌ Quarantine failed")
            
    except Exception as e:
        print(f"Test error: {e}")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
            print("Cleaned up test file")

if __name__ == "__main__":
    print("="*60)
    print("TESTING SECURE QUARANTINE")
    print("="*60)
    
    test_secure_quarantine()
