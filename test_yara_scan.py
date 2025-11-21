"""
Test YARA Scanning
"""
import sys
import os
import time

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import FileScanner

def test_yara_detection():
    print("\n[TEST] YARA Detection")
    
    scanner = FileScanner()
    
    # Create a suspicious file (PowerShell)
    test_file = "test_suspicious.ps1"
    with open(test_file, "w") as f:
        f.write("powershell -w hidden -enc BASE64COMMAND")
        
    print(f"Created suspicious file: {test_file}")
    
    try:
        # Scan file
        print("Scanning...")
        result = scanner.scan_file(test_file)
        
        print(f"Result Status: {result['status']}")
        if result['threat']:
            print(f"Threat Name: {result['threat']['name']}")
            print(f"Threat Level: {result['threat']['level']}")
            
            if "YARA" in result['threat']['name']:
                print("✅ SUCCESS: YARA Detection confirmed")
            else:
                print(f"⚠️ WARNING: Detected as {result['threat']['name']} (Not YARA?)")
        else:
            print("❌ FAILED: No threat detected")
            
    except Exception as e:
        print(f"Test error: {e}")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
            print("Cleaned up test file")

if __name__ == "__main__":
    print("="*60)
    print("TESTING YARA SCANNER")
    print("="*60)
    
    test_yara_detection()
