"""
Test Suite for File Scanner
Tests malware detection and file scanning functionality
"""

import os
import sys
import pytest
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import FileScanner


class TestFileScanner:
    """Test cases for FileScanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance"""
        return FileScanner()
    
    @pytest.fixture
    def test_file(self):
        """Create temporary test file"""
        filename = "test_scan_file.txt"
        with open(filename, 'w') as f:
            f.write("This is a test file")
        yield filename
        # Cleanup
        if os.path.exists(filename):
            os.remove(filename)
    
    def test_scan_clean_file(self, scanner, test_file):
        """Test scanning a clean file"""
        result = scanner.scan_file(test_file)
        
        assert result['status'] in ['CLEAN', 'ERROR']
        assert result['file'] == test_file
        assert result['hash'] is not None
    
    def test_scan_nonexistent_file(self, scanner):
        """Test scanning non-existent file"""
        result = scanner.scan_file("nonexistent_file.xyz")
        
        assert result['status'] == 'ERROR'
    
    def test_add_signature(self, scanner):
        """Test adding malware signature"""
        scanner.add_signature(
            'test_sig_001',
            'abcdef1234567890',
            'Test Malware',
            'HIGH',
            'Test signature'
        )
        
        assert 'test_sig_001' in scanner.signatures
    
    def test_signature_persistence(self):
        """Test that signatures are saved to file"""
        scanner = FileScanner()
        
        sig_id = 'persist_test'
        scanner.add_signature(
            sig_id,
            'test_hash_123',
            'Test',
            'LOW',
            'Persistence test'
        )
        
        # Create new scanner instance
        scanner2 = FileScanner()
        
        # Signature should be loaded
        assert sig_id in scanner2.signatures


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
