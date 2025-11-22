"""
AEGIS Backend API Integration Tests
Tests all API methods exposed through pywebview
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.api_bridge import AegisAPI
import time

def test_api_initialization():
    """Test API initialization"""
    print("\n=== Testing API Initialization ===")
    try:
        api = AegisAPI()
        print("✅ API initialized successfully")
        return api
    except Exception as e:
        print(f"❌ API initialization failed: {e}")
        return None

def test_system_stats(api):
    """Test system statistics retrieval"""
    print("\n=== Testing System Stats ===")
    try:
        stats = api.get_system_stats()
        print(f"✅ System stats retrieved:")
        print(f"   CPU: {stats['cpu']}%")
        print(f"   Memory: {stats['memory']}%")
        print(f"   Disk: {stats['disk']}%")
        
        # Validate data
        assert 0 <= stats['cpu'] <= 100, "CPU should be 0-100%"
        assert 0 <= stats['memory'] <= 100, "Memory should be 0-100%"
        assert 0 <= stats['disk'] <= 100, "Disk should be 0-100%"
        print("✅ System stats validation passed")
        return True
    except Exception as e:
        print(f"❌ System stats test failed: {e}")
        return False

def test_rtp_status(api):
    """Test Real-Time Protection status"""
    print("\n=== Testing RTP Status ===")
    try:
        status = api.get_rtp_status()
        print(f"✅ RTP status retrieved:")
        print(f"   Running: {status.get('is_running', False)}")
        print(f"   Files Monitored: {status.get('files_monitored', 0)}")
        print(f"   Threats Blocked: {status.get('threats_blocked', 0)}")
        return True
    except Exception as e:
        print(f"❌ RTP status test failed: {e}")
        return False

def test_rtp_toggle(api):
    """Test RTP toggle functionality"""
    print("\n=== Testing RTP Toggle ===")
    try:
        # Get initial status
        initial_status = api.get_rtp_status()
        initial_state = initial_status.get('is_running', False)
        print(f"   Initial RTP state: {initial_state}")
        
        # Toggle OFF
        print("   Toggling RTP OFF...")
        api.toggle_rtp(False)
        time.sleep(1)
        status_off = api.get_rtp_status()
        print(f"   RTP state after OFF: {status_off.get('is_running', False)}")
        
        # Toggle ON
        print("   Toggling RTP ON...")
        api.toggle_rtp(True)
        time.sleep(1)
        status_on = api.get_rtp_status()
        print(f"   RTP state after ON: {status_on.get('is_running', False)}")
        
        print("✅ RTP toggle test passed")
        return True
    except Exception as e:
        print(f"❌ RTP toggle test failed: {e}")
        return False

def test_password_manager(api):
    """Test Password Manager functionality"""
    print("\n=== Testing Password Manager ===")
    try:
        # Get initial passwords
        initial_passwords = api.get_passwords()
        initial_count = len(initial_passwords)
        print(f"   Initial password count: {initial_count}")
        
        # Add test password
        print("   Adding test password...")
        result = api.add_password(
            website="test-aegis.com",
            username="testuser@aegis.com",
            password="TestPass123!",
            category="Testing"
        )
        print(f"   Add result: {result}")
        
        # Verify password was added
        updated_passwords = api.get_passwords()
        new_count = len(updated_passwords)
        print(f"   Updated password count: {new_count}")
        
        # Find and delete test password
        test_password = None
        for pwd in updated_passwords:
            if pwd.get('website') == 'test-aegis.com':
                test_password = pwd
                break
        
        if test_password:
            print(f"   Deleting test password (ID: {test_password['id']})...")
            api.delete_password(test_password['id'])
            final_passwords = api.get_passwords()
            final_count = len(final_passwords)
            print(f"   Final password count: {final_count}")
            
            if final_count == initial_count:
                print("✅ Password Manager test passed")
                return True
            else:
                print("⚠️  Password count mismatch after deletion")
                return False
        else:
            print("⚠️  Test password not found after adding")
            return False
            
    except Exception as e:
        print(f"❌ Password Manager test failed: {e}")
        return False

def test_quarantine(api):
    """Test Quarantine functionality"""
    print("\n=== Testing Quarantine ===")
    try:
        items = api.get_quarantined_items()
        print(f"✅ Quarantined items retrieved: {len(items)} items")
        
        if items:
            print("   Sample quarantined items:")
            for item in items[:3]:  # Show first 3
                print(f"   - {item.get('file_path', 'N/A')} ({item.get('threat_name', 'Unknown')})")
        else:
            print("   No items currently in quarantine")
        
        return True
    except Exception as e:
        print(f"❌ Quarantine test failed: {e}")
        return False

def test_nlp_analyzer(api):
    """Test NLP Threat Analyzer"""
    print("\n=== Testing NLP Analyzer ===")
    try:
        # Test safe text
        print("   Testing safe text...")
        safe_result = api.analyze_text("Hello, how are you today?")
        print(f"   Safe text result: {safe_result.get('classification', 'N/A')}")
        
        # Test suspicious text
        print("   Testing suspicious text...")
        suspicious_result = api.analyze_text(
            "URGENT! Click here to claim your prize! Enter your credit card number now!"
        )
        print(f"   Suspicious text result: {suspicious_result.get('classification', 'N/A')}")
        
        print("✅ NLP Analyzer test passed")
        return True
    except Exception as e:
        print(f"❌ NLP Analyzer test failed: {e}")
        return False

def test_logs(api):
    """Test system logs retrieval"""
    print("\n=== Testing System Logs ===")
    try:
        logs = api.get_recent_logs(10)
        print(f"✅ System logs retrieved: {len(logs)} entries")
        
        if logs:
            print("   Recent log entries:")
            for log in logs[:3]:  # Show first 3
                timestamp = log.get('timestamp', 'N/A')
                event_type = log.get('event_type', 'N/A')
                print(f"   - [{timestamp}] {event_type}")
        else:
            print("   No log entries found")
        
        return True
    except Exception as e:
        print(f"❌ System logs test failed: {e}")
        return False

def test_scanner(api):
    """Test scanner functionality"""
    print("\n=== Testing Scanner ===")
    try:
        # Note: We won't actually run a full scan in tests
        # Just verify the methods are callable
        print("   Verifying scanner methods...")
        
        # Check scan progress (should be idle)
        progress = api.get_scan_progress()
        print(f"   Scan status: {progress.get('status', 'unknown')}")
        
        print("✅ Scanner test passed (methods callable)")
        return True
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        return False

def test_version(api):
    """Test version retrieval"""
    print("\n=== Testing Version ===")
    try:
        version = api.get_version()
        print(f"✅ Version retrieved: {version}")
        assert "AEGIS" in version, "Version should contain 'AEGIS'"
        return True
    except Exception as e:
        print(f"❌ Version test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("AEGIS BACKEND API INTEGRATION TESTS")
    print("=" * 60)
    
    # Initialize API
    api = test_api_initialization()
    if not api:
        print("\n❌ Cannot proceed without API initialization")
        return
    
    # Run all tests
    tests = [
        ("System Stats", lambda: test_system_stats(api)),
        ("RTP Status", lambda: test_rtp_status(api)),
        ("RTP Toggle", lambda: test_rtp_toggle(api)),
        ("Password Manager", lambda: test_password_manager(api)),
        ("Quarantine", lambda: test_quarantine(api)),
        ("NLP Analyzer", lambda: test_nlp_analyzer(api)),
        ("System Logs", lambda: test_logs(api)),
        ("Scanner", lambda: test_scanner(api)),
        ("Version", lambda: test_version(api)),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n❌ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

if __name__ == "__main__":
    main()
