import sys
import os
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_bridge import AegisAPI

def test_threat_queue():
    print("Initializing AegisAPI...")
    api = AegisAPI()
    
    # Create dummy threat data
    threat_data = {
        'type': 'TEST_THREAT',
        'level': 'CRITICAL',
        'confidence': 99.9,
        'patterns': ['Test Pattern'],
        'keywords': ['test', 'threat'],
        'description': 'This is a test threat to verify popup alerts.',
        'timestamp': datetime.now().isoformat(),
        'source': 'Test Script',
        'process': 'test_process.exe',
        'screen_text_sample': 'This is a test of the emergency broadcast system.',
        'recommended_actions': ['Verify popup appears', 'Click dismiss']
    }
    
    print("Simulating threat detection...")
    api._on_threat_detected(threat_data)
    
    print("Checking threat queue...")
    alerts = api.get_pending_threat_alerts()
    
    if len(alerts) == 1:
        print("SUCCESS: Threat correctly queued and retrieved.")
        print(f"Threat Data: {alerts[0]['description']}")
        return True
    else:
        print(f"FAILURE: Expected 1 alert, got {len(alerts)}")
        return False

if __name__ == "__main__":
    test_threat_queue()
