"""
Test Real-Time Protection System
"""
import time
from core.realtime_protection import realtime_protection

def threat_callback(threat_data):
    print(f"\\n{'='*60}")
    print(f"THREAT DETECTED!")
    print(f"{'='*60}")
    print(f"Level: {threat_data.get('level', 'UNKNOWN')}")
    print(f"Confidence: {threat_data.get('confidence', 0):.1f}%")
    print(f"Patterns: {', '.join(threat_data.get('patterns', []))}")
    print(f"Description: {threat_data.get('description', '')}")
    print(f"{'='*60}\\n")

# Register callback
realtime_protection.register_threat_callback(threat_callback)

# Try to start protection
print("Attempting to start Real-Time Protection...")
success = realtime_protection.start_protection()

if success:
    print("✓ Real-Time Protection STARTED successfully!")
    print(f"  Scan Interval: {realtime_protection.scan_interval}s")
    print(f"  Threat Sensitivity: {realtime_protection.threat_sensitivity}")
    print("\\nMonitoring screen for 30 seconds...")
    print("(Open a webpage with phishing content to test detection)\\n")
    
    # Monitor for 30 seconds
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\\nInterrupted by user")
    
    # Stop protection
    print("\\nStopping Real-Time Protection...")
    realtime_protection.stop_protection()
    
    # Show stats
    stats = realtime_protection.get_statistics()
    print("\\nStatistics:")
    print(f"  Scans Performed: {stats['scans_performed']}")
    print(f"  Threats Detected: {stats['threats_detected']}")
    print(f"  Is Active: {stats['is_active']}")
else:
    print("✗ Failed to start Real-Time Protection!")
    print("\\nPossible reasons:")
    print("1. Tesseract OCR not installed")
    print("2. PIL/Pillow not installed")
    print("3. NLP module not available")
    print("\\nCheck the logs above for specific error messages.")
