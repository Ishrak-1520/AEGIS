import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.api_bridge import AegisAPI
from core.realtime_protection import realtime_protection

def test_rtp_toggle():
    print("Initializing AegisAPI...")
    api = AegisAPI()
    
    print(f"Initial RTP Status: {realtime_protection.is_active}")
    
    print("Attempting to enable RTP...")
    success = api.toggle_rtp(True)
    
    print(f"Toggle Result: {success}")
    print(f"Final RTP Status: {realtime_protection.is_active}")
    
    if success and realtime_protection.is_active:
        print("SUCCESS: RTP enabled successfully.")
    else:
        print("FAILURE: RTP failed to enable.")
        # Check dependencies
        print(f"NLP Available: {realtime_protection.NLP_AVAILABLE if hasattr(realtime_protection, 'NLP_AVAILABLE') else 'Unknown'}") 
        # Note: NLP_AVAILABLE is a module-level variable, not class attribute, so we can't access it easily via instance unless we import it or check internal state if exposed.
        # But we can check if start_protection failed.

if __name__ == "__main__":
    test_rtp_toggle()
