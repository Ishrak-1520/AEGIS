import sys
import os
import json
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.nlp_model import get_nlp_detector
from core.api_bridge import AegisAPI
from database.db_manager import db_manager

class TestNLPEnhanced(unittest.TestCase):
    def setUp(self):
        self.detector = get_nlp_detector()
        self.api = AegisAPI()
        
    def test_match_indices(self):
        """Test that analysis returns correct start/end indices"""
        text = "URGENT: Please reset password immediately."
        result = self.detector.analyze_text(text)
        
        self.assertIn('matches', result)
        matches = result['matches']
        self.assertTrue(len(matches) > 0)
        
        # Check for specific match "URGENT"
        urgent_match = next((m for m in matches if 'urgent' in m['text'].lower()), None)
        self.assertIsNotNone(urgent_match)
        self.assertEqual(urgent_match['text'], 'URGENT')
        self.assertEqual(urgent_match['start'], 0)
        self.assertEqual(urgent_match['end'], 6)
        
        # Check for "reset password"
        pwd_match = next((m for m in matches if 'reset password' in m['text'].lower()), None)
        self.assertIsNotNone(pwd_match)
        self.assertEqual(text[pwd_match['start']:pwd_match['end']], 'reset password')

    def test_history_logging(self):
        """Test that analysis is logged with full details"""
        # Clear history first
        self.api.clear_nlp_history()
        
        text = "Test threat for history logging"
        result = self.api.analyze_text(text)
        
        # Check history
        history = self.api.get_nlp_history()
        self.assertTrue(len(history) > 0)
        
        latest = history[0]
        # Check if it matches the result structure
        self.assertEqual(latest['threat_class'], result['threat_class'])
        self.assertEqual(latest['threat_score'], result['threat_score'])
        self.assertIn('matches', latest)

    def test_text_limit(self):
        """Test that text is truncated if too long"""
        long_text = "a" * 100005
        result = self.detector.analyze_text(long_text)
        # We can't easily check the internal truncation without mocking, 
        # but we can check it doesn't crash and returns a result.
        self.assertIsNotNone(result)
        self.assertEqual(result['threat_class'], 'SAFE') # "a" is safe

if __name__ == '__main__':
    unittest.main()
