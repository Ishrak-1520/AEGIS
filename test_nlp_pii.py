"""
Test NLP PII Detection
"""
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ai.nlp_model import get_nlp_detector

def test_pii_detection():
    print("\n[TEST] NLP PII Detection")
    
    detector = get_nlp_detector()
    
    # Test text with PII
    test_text = """
    URGENT: Please verify your account immediately.
    We need you to confirm your payment details.
    Credit Card: 4532-1234-5678-9012
    SSN: 123-45-6789
    Email: victim@example.com
    Phone: 555-0199
    """
    
    print("Analyzing text...")
    print("-" * 40)
    print(test_text.strip())
    print("-" * 40)
    
    result = detector.analyze_text(test_text)
    
    print(f"\nThreat Level: {result['threat_level']}")
    print(f"Threat Score: {result['threat_score']}")
    print("Patterns Detected:")
    for pattern in result['patterns_detected']:
        print(f"  - {pattern}")
        
    # Verification
    patterns = result['patterns_detected']
    pii_detected = any("PII Detected" in p for p in patterns)
    
    if pii_detected:
        print("\n✅ SUCCESS: PII Detected")
    else:
        print("\n❌ FAILED: PII NOT Detected")
        
    if result['threat_level'] in ['HIGH', 'CRITICAL']:
        print("✅ SUCCESS: Threat level appropriate")
    else:
        print(f"⚠️ WARNING: Threat level {result['threat_level']} might be too low for PII leak")

if __name__ == "__main__":
    print("="*60)
    print("TESTING NLP ENHANCEMENTS")
    print("="*60)
    
    test_pii_detection()
