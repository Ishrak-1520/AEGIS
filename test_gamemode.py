"""
Test Game Mode / Fullscreen Detection Logic
"""
import sys
import os
import time
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.realtime_protection import realtime_protection

def test_game_mode_logic():
    print("="*60)
    print("TESTING GAME MODE / FULLSCREEN LOGIC")
    print("="*60)
    
    # Mock data
    process_name = "game.exe"
    result = {'confidence': 90.0, 'patterns_detected': ['Suspicious']}
    
    # Case 1: Fullscreen + MEDIUM Threat -> Should be SUPPRESSED
    print("\n[CASE 1] Fullscreen Game + MEDIUM Threat")
    should_alert = realtime_protection._should_trigger_alert(
        threat_level='MEDIUM',
        result=result,
        process_name=process_name,
        is_fullscreen=True
    )
    print(f"Result: {'✅ SUPPRESSED' if not should_alert else '❌ ALERTED (Failed)'}")
    
    # Case 2: Fullscreen Game + CRITICAL Threat -> Should ALERT
    print("\n[CASE 2] Fullscreen Game + CRITICAL Threat")
    should_alert = realtime_protection._should_trigger_alert(
        threat_level='CRITICAL',
        result=result,
        process_name=process_name,
        is_fullscreen=True
    )
    print(f"Result: {'✅ ALERTED' if should_alert else '❌ SUPPRESSED (Failed)'}")
    
    # Case 3: Windowed App + MEDIUM Threat -> Should ALERT
    print("\n[CASE 3] Windowed App + MEDIUM Threat")
    should_alert = realtime_protection._should_trigger_alert(
        threat_level='MEDIUM',
        result=result,
        process_name="browser.exe",
        is_fullscreen=False
    )
    print(f"Result: {'✅ ALERTED' if should_alert else '❌ SUPPRESSED (Failed)'}")

if __name__ == "__main__":
    test_game_mode_logic()
