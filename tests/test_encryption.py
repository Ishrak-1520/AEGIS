"""
Test Suite for Encryption Module
Tests AES-256 encryption, password hashing, and key derivation
"""

import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.encryption import EncryptionManager, encryption_manager


class TestEncryptionManager:
    """Test cases for EncryptionManager"""
    
    def test_generate_salt(self):
        """Test salt generation"""
        salt1 = EncryptionManager.generate_salt()
        salt2 = EncryptionManager.generate_salt()
        
        assert len(salt1) == 32  # 256 bits
        assert len(salt2) == 32
        assert salt1 != salt2  # Should be unique
    
    def test_password_hashing(self):
        """Test password hashing"""
        password = "TestPassword123!"
        hash1, salt1 = EncryptionManager.hash_password(password)
        hash2, salt2 = EncryptionManager.hash_password(password)
        
        assert hash1 != hash2  # Different salts = different hashes
        assert salt1 != salt2
    
    def test_password_verification(self):
        """Test password verification"""
        password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"
        
        hash_val, salt = EncryptionManager.hash_password(password)
        
        # Correct password should verify
        assert EncryptionManager.verify_password(password, hash_val, salt)
        
        # Wrong password should not verify
        assert not EncryptionManager.verify_password(wrong_password, hash_val, salt)
    
    def test_encryption_decryption(self):
        """Test AES-256 encryption and decryption"""
        password = "MasterPassword123!"
        salt = EncryptionManager.generate_salt()
        key = EncryptionManager.derive_key(password, salt)
        
        plaintext = "This is a secret message!"
        
        # Encrypt
        encrypted = encryption_manager.encrypt(plaintext, key)
        
        # Decrypt
        decrypted = encryption_manager.decrypt(encrypted, key)
        
        assert decrypted == plaintext
    
    def test_encryption_with_wrong_key(self):
        """Test that wrong key fails decryption"""
        password1 = "Password1"
        password2 = "Password2"
        salt = EncryptionManager.generate_salt()
        
        key1 = EncryptionManager.derive_key(password1, salt)
        key2 = EncryptionManager.derive_key(password2, salt)
        
        plaintext = "Secret data"
        encrypted = encryption_manager.encrypt(plaintext, key1)
        
        # Decryption with wrong key should fail
        decrypted = encryption_manager.decrypt(encrypted, key2)
        assert decrypted is None or decrypted != plaintext
    
    def test_password_generation(self):
        """Test password generator"""
        pwd1 = EncryptionManager.generate_password(16)
        pwd2 = EncryptionManager.generate_password(16)
        
        assert len(pwd1) == 16
        assert len(pwd2) == 16
        assert pwd1 != pwd2  # Should be random
    
    def test_password_strength_evaluation(self):
        """Test password strength evaluation"""
        # Weak password
        weak = encryption_manager.evaluate_password_strength("abc")
        assert weak['strength'] in ['Very Weak', 'Weak']
        
        # Strong password
        strong = encryption_manager.evaluate_password_strength("MySecureP@ssw0rd2024!")
        assert strong['strength'] in ['Strong', 'Medium']
        assert strong['score'] > 60
    
    def test_file_hashing(self):
        """Test file hash calculation"""
        # Create temporary file
        test_file = "test_file.txt"
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        try:
            hash1 = EncryptionManager.hash_file(test_file, 'sha256')
            hash2 = EncryptionManager.hash_file(test_file, 'sha256')
            
            assert hash1 is not None
            assert hash2 is not None
            assert hash1 == hash2  # Same file = same hash
            assert len(hash1) == 64  # SHA-256 = 64 hex chars
        finally:
            # Cleanup
            if os.path.exists(test_file):
                os.remove(test_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
