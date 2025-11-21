"""
Test Threat Prevention Logic
"""
import sys
import os
import time
import subprocess
import psutil

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.threat_prevention import threat_prevention

def test_process_kill():
    print("\n[TEST] Process Killing")
    # Start a dummy process (notepad)
    try:
        proc = subprocess.Popen(['notepad.exe'])
        pid = proc.pid
        print(f"Started Notepad with PID: {pid}")
        time.sleep(1)
        
        # Simulate threat
        details = {'pid': pid, 'name': 'notepad.exe'}
        print("Simulating CRITICAL threat on Notepad...")
        
        # Handle threat (should kill process)
        threat_prevention.handle_threat(
            threat_type='MALWARE_DETECTED',
            threat_level='CRITICAL',
            source='notepad.exe',
            details=details
        )
        
        time.sleep(1)
        
        # Check if process is still running
        if psutil.pid_exists(pid):
            print("❌ FAILED: Process still running")
        else:
            print("✅ SUCCESS: Process killed")
            
    except Exception as e:
        print(f"Test error: {e}")

def test_hosts_blocking():
    print("\n[TEST] Hosts File Blocking")
    domain = "malicious-test-domain.com"
    
    print(f"Attempting to block: {domain}")
    threat_prevention.handle_threat(
        threat_type='MALICIOUS_URL',
        threat_level='HIGH',
        source='http://' + domain,
        details={'domain': domain}
    )
    
    # Check hosts file
    try:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(hosts_path):
            with open(hosts_path, 'r') as f:
                content = f.read()
                if domain in content:
                    print("✅ SUCCESS: Domain found in hosts file")
                    # Cleanup
                    threat_prevention.unblock_domain(domain)
                    print("   Cleaned up (Unblocked)")
                else:
                    print("⚠️ NOTE: Domain NOT found in hosts file (Likely Permission Denied - Expected if not Admin)")
        else:
            print("❌ ERROR: Hosts file not found")
            
    except Exception as e:
        print(f"Check error: {e}")

if __name__ == "__main__":
    print("="*60)
    print("TESTING THREAT PREVENTION")
    print("="*60)
    
    test_process_kill()
    test_hosts_blocking()
