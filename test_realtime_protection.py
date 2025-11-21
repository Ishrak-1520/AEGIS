"""
Real-Time Protection Feature Test
Tests the core functionality without requiring full GUI
"""

import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from core.realtime_protection import realtime_protection, RealTimeProtection
        print("  ✓ realtime_protection module imported")
    except ImportError as e:
        print(f"  ✗ Failed to import realtime_protection: {e}")
        return False
    
    try:
        from gui.popup_alerts import RealTimeThreatAlert, show_realtime_threat_alert
        print("  ✓ popup_alerts module imported")
    except ImportError as e:
        print(f"  ✗ Failed to import popup_alerts: {e}")
        return False
    
    try:
        from ai.nlp_model import get_nlp_detector
        print("  ✓ nlp_model imported")
    except ImportError as e:
        print(f"  ✗ Failed to import nlp_model: {e}")
        return False
    
    return True


def test_nlp_detection():
    """Test NLP threat detection with sample texts"""
    print("\nTesting NLP threat detection...")
    
    try:
        from ai.nlp_model import get_nlp_detector
        detector = get_nlp_detector()
        
        # Test safe text
        safe_result = detector.analyze_text("Hello, this is a normal message.")
        print(f"  Safe text: {safe_result['threat_level']} (confidence: {safe_result['confidence']:.1f}%)")
        assert safe_result['threat_level'] == 'SAFE', "Safe text incorrectly flagged"
        
        # Test phishing text
        phishing_result = detector.analyze_text(
            "Urgent! Your account has been suspended. Verify your account immediately by clicking this link."
        )
        print(f"  Phishing text: {phishing_result['threat_level']} (confidence: {phishing_result['confidence']:.1f}%)")
        assert phishing_result['threat_level'] in ['MEDIUM', 'HIGH', 'CRITICAL'], "Phishing text not detected"
        
        # Test scam text
        scam_result = detector.analyze_text(
            "Congratulations! You have won $1,000,000 in the lottery. Send payment processing fee now!"
        )
        print(f"  Scam text: {scam_result['threat_level']} (confidence: {scam_result['confidence']:.1f}%)")
        assert scam_result['threat_level'] in ['MEDIUM', 'HIGH', 'CRITICAL'], "Scam text not detected"
        
        print("  ✓ NLP detection working correctly")
        return True
        
    except Exception as e:
        print(f"  ✗ NLP detection test failed: {e}")
        return False


def test_realtime_protection_api():
    """Test Real-Time Protection API methods"""
    print("\nTesting Real-Time Protection API...")
    
    try:
        from core.realtime_protection import realtime_protection
        
        # Test initial state
        assert realtime_protection.is_active == False, "Should start inactive"
        print("  ✓ Initial state: inactive")
        
        # Test statistics
        stats = realtime_protection.get_statistics()
        assert 'is_active' in stats, "Statistics missing is_active"
        assert 'scans_performed' in stats, "Statistics missing scans_performed"
        assert 'scan_interval' in stats, "Statistics missing scan_interval"
        print(f"  ✓ Statistics: {stats}")
        
        # Test configuration methods
        realtime_protection.set_scan_interval(5.0)
        assert realtime_protection.scan_interval == 5.0, "Scan interval not set"
        print("  ✓ Scan interval configuration works")
        
        realtime_protection.set_threat_sensitivity('HIGH')
        assert realtime_protection.threat_sensitivity == 'HIGH', "Sensitivity not set"
        print("  ✓ Threat sensitivity configuration works")
        
        # Test callback registration
        callback_called = []
        def test_callback(threat_data):
            callback_called.append(threat_data)
        
        realtime_protection.register_threat_callback(test_callback)
        assert len(realtime_protection.threat_callbacks) > 0, "Callback not registered"
        print("  ✓ Callback registration works")
        
        # Note: We don't actually start protection here to avoid OCR dependency in tests
        
        print("  ✓ All API methods working")
        return True
        
    except Exception as e:
        print(f"  ✗ API test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_threat_classification():
    """Test threat classification logic"""
    print("\nTesting threat classification...")
    
    try:
        from core.realtime_protection import RealTimeProtection
        rtp = RealTimeProtection()
        
        # Test different sensitivity levels
        test_cases = [
            ('CRITICAL', {'threat_sensitivity': 'LOW'}, True),
            ('HIGH', {'threat_sensitivity': 'LOW'}, True),
            ('MEDIUM', {'threat_sensitivity': 'LOW'}, False),
            ('LOW', {'threat_sensitivity': 'LOW'}, False),
            
            ('CRITICAL', {'threat_sensitivity': 'MEDIUM'}, True),
            ('HIGH', {'threat_sensitivity': 'MEDIUM'}, True),
            ('MEDIUM', {'threat_sensitivity': 'MEDIUM'}, True),
            ('LOW', {'threat_sensitivity': 'MEDIUM'}, False),
            
            ('CRITICAL', {'threat_sensitivity': 'HIGH'}, True),
            ('HIGH', {'threat_sensitivity': 'HIGH'}, True),
            ('MEDIUM', {'threat_sensitivity': 'HIGH'}, True),
            ('LOW', {'threat_sensitivity': 'HIGH'}, True),
        ]
        
        for threat_level, config, expected_alert in test_cases:
            rtp.threat_sensitivity = config['threat_sensitivity']
            result = {
                'threat_level': threat_level,
                'confidence': 75.0,
                'patterns_detected': ['Test Pattern']
            }
            
            should_alert = rtp._should_trigger_alert(threat_level, result)
            
            if should_alert == expected_alert:
                print(f"  ✓ {threat_level} at {config['threat_sensitivity']} sensitivity: {'Alert' if should_alert else 'No alert'}")
            else:
                print(f"  ✗ {threat_level} at {config['threat_sensitivity']} sensitivity: Expected {'alert' if expected_alert else 'no alert'}, got {'alert' if should_alert else 'no alert'}")
                return False
        
        print("  ✓ Threat classification logic correct")
        return True
        
    except Exception as e:
        print(f"  ✗ Classification test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database_logging():
    """Test database logging functionality"""
    print("\nTesting database logging...")
    
    try:
        from database.db_manager import db_manager
        
        # Log a test threat
        threat_id = db_manager.log_threat(
            threat_type='REALTIME_SCREEN_THREAT',
            threat_level='HIGH',
            source='Test Script',
            details='Test threat for RTP feature',
            action_taken='Test',
            confidence_score=85.5
        )
        
        assert threat_id > 0, "Threat not logged to database"
        print(f"  ✓ Threat logged with ID: {threat_id}")
        
        # Log a test event
        event_id = db_manager.log_event(
            'RTP_TEST',
            'INFO',
            'Real-Time Protection test event'
        )
        
        assert event_id > 0, "Event not logged to database"
        print(f"  ✓ Event logged with ID: {event_id}")
        
        # Retrieve recent threats
        threats = db_manager.get_threat_logs(limit=5)
        assert len(threats) > 0, "Could not retrieve threats"
        print(f"  ✓ Retrieved {len(threats)} recent threats")
        
        print("  ✓ Database logging working")
        return True
        
    except Exception as e:
        print(f"  ✗ Database logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("Real-Time Protection Feature Test Suite")
    print("=" * 70)
    print()
    
    tests = [
        ("Module Imports", test_imports),
        ("NLP Threat Detection", test_nlp_detection),
        ("RTP API Methods", test_realtime_protection_api),
        ("Threat Classification", test_threat_classification),
        ("Database Logging", test_database_logging),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
        print()
    
    print("=" * 70)
    print("Test Results Summary")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{test_name:.<50} {status}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print()
    print(f"Total: {len(results)} tests | Passed: {passed} | Failed: {failed}")
    print()
    
    if failed == 0:
        print("🎉 All tests passed! Real-Time Protection is working correctly.")
        return 0
    else:
        print(f"⚠️  {failed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
