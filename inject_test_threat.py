import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_bridge import AegisAPI
from datetime import datetime

def inject_test_threat():
    print("Initializing AegisAPI...")
    api = AegisAPI()
    
    # Create a test threat
    test_threat = {
        'type': 'SCREEN_THREAT',
        'level': 'HIGH',
        'confidence': 95.5,
        'patterns': ['Phishing Indicators', 'Suspicious URLs'],
        'keywords': ['urgent', 'verify', 'account', 'click', 'here'],
        'description': 'Potential phishing attempt detected',
        'timestamp': datetime.now().isoformat(),
        'source': 'Real-Time Protection (Test)',
        'process': 'chrome.exe',
        'screen_text_sample': 'URGENT: Verify your account now! Click here to confirm your identity.',
        'recommended_actions': [
            '⚠️ Close suspicious window immediately',
            '🚫 Do not enter any personal information',
            '📧 Verify sender email address'
        ]
    }
    
    print("Injecting test threat into queue...")
    api._on_threat_detected(test_threat)
    
    print("Checking queue...")
    alerts = api.get_pending_threat_alerts()
    print(f"Alerts in queue: {len(alerts)}")
    
    if len(alerts) > 0:
        print("SUCCESS: Threat injected and retrievable!")
        print(f"Threat details: {alerts[0]['description']}")
    else:
        print("ERROR: Threat not in queue")

if __name__ == "__main__":
    inject_test_threat()
    print("\nNow check the AEGIS UI for the popup alert!")
    print("It should appear in the bottom-right corner within 2 seconds.")
