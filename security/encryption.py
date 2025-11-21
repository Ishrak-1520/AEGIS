"""
Encryption Module
Provides AES-256 encryption with PBKDF2 key derivation
Secure password handling and data encryption utilities
"""

import os
import base64
import hashlib
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionManager:
    """
    Handles all encryption/decryption operations
    Uses AES-256-GCM for data encryption
    Uses PBKDF2-HMAC-SHA256 for key derivation
    """
    
    # Security parameters
    PBKDF2_ITERATIONS = 100000  # NIST recommendation
    SALT_LENGTH = 32  # 256 bits
    KEY_LENGTH = 32  # 256 bits for AES-256
    
    def __init__(self):
        """Initialize encryption manager"""
        self.backend = default_backend()
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate cryptographically secure random salt"""
        return secrets.token_bytes(EncryptionManager.SALT_LENGTH)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: Master password
            salt: Cryptographic salt
            iterations: Number of PBKDF2 iterations
            
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=EncryptionManager.KEY_LENGTH,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hash password for storage using PBKDF2
        
        Args:
            password: Plain text password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (password_hash, salt) as base64 strings
        """
        if salt is None:
            salt = EncryptionManager.generate_salt()
        
        # Derive key from password
        key = EncryptionManager.derive_key(password, salt)
        
        # Return base64 encoded hash and salt
        password_hash = base64.b64encode(key).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        return password_hash, salt_b64
    
    @staticmethod
    def verify_password(password: str, stored_hash: str, salt_b64: str) -> bool:
        """
        Verify password against stored hash
        
        Args:
            password: Password to verify
            stored_hash: Base64 encoded stored password hash
            salt_b64: Base64 encoded salt
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt = base64.b64decode(salt_b64)
            computed_hash, _ = EncryptionManager.hash_password(password, salt)
            return secrets.compare_digest(computed_hash, stored_hash)
        except Exception:
            return False
    
    def encrypt(self, plaintext: str, key: bytes) -> str:
        """
        Encrypt plaintext using AES-256-GCM
        
        Args:
            plaintext: Text to encrypt
            key: 256-bit encryption key
            
        Returns:
            Base64 encoded encrypted data (nonce + tag + ciphertext)
        """
        return self.encrypt_bytes(plaintext.encode('utf-8'), key)

    def encrypt_bytes(self, data: bytes, key: bytes) -> str:
        """
        Encrypt bytes using AES-256-GCM
        
        Args:
            data: Bytes to encrypt
            key: 256-bit encryption key
            
        Returns:
            Base64 encoded encrypted data
        """
        # Generate random nonce (12 bytes for GCM)
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Combine nonce + tag + ciphertext
        encrypted_data = nonce + encryptor.tag + ciphertext
        
        # Return base64 encoded
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_b64: str, key: bytes) -> Optional[str]:
        """
        Decrypt data encrypted with AES-256-GCM
        
        Args:
            encrypted_b64: Base64 encoded encrypted data
            key: 256-bit decryption key
            
        Returns:
            Decrypted plaintext or None if decryption fails
        """
        decrypted_bytes = self.decrypt_bytes(encrypted_b64, key)
        return decrypted_bytes.decode('utf-8') if decrypted_bytes else None

    def decrypt_bytes(self, encrypted_b64: str, key: bytes) -> Optional[bytes]:
        """
        Decrypt data to bytes
        
        Args:
            encrypted_b64: Base64 encoded encrypted data
            key: 256-bit decryption key
            
        Returns:
            Decrypted bytes or None if decryption fails
        """
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_b64)
            
            # Extract components
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    @staticmethod
    def hash_file(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate cryptographic hash of file
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha1, md5)
            
        Returns:
            Hexadecimal hash string or None on error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"File hashing error: {e}")
            return None
    
    @staticmethod
    def hash_bytes(data: bytes, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of byte data
        
        Args:
            data: Bytes to hash
            algorithm: Hash algorithm
            
        Returns:
            Hexadecimal hash string
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.hexdigest()
    
    @staticmethod
    def generate_password(length: int = 16, 
                         use_uppercase: bool = True,
                         use_lowercase: bool = True,
                         use_digits: bool = True,
                         use_special: bool = True) -> str:
        """
        Generate cryptographically secure random password
        
        Args:
            length: Password length
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include digits
            use_special: Include special characters
            
        Returns:
            Generated password
        """
        charset = ''
        if use_lowercase:
            charset += 'abcdefghijklmnopqrstuvwxyz'
        if use_uppercase:
            charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if use_digits:
            charset += '0123456789'
        if use_special:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not charset:
            raise ValueError("At least one character type must be selected")
        
        # Generate password ensuring at least one char from each selected type
        password = []
        
        if use_lowercase:
            password.append(secrets.choice('abcdefghijklmnopqrstuvwxyz'))
        if use_uppercase:
            password.append(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
        if use_digits:
            password.append(secrets.choice('0123456789'))
        if use_special:
            password.append(secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?'))
        
        # Fill remaining length with random characters
        for _ in range(length - len(password)):
            password.append(secrets.choice(charset))
        
        # Shuffle password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def evaluate_password_strength(password: str) -> dict:
        """
        Evaluate password strength
        
        Args:
            password: Password to evaluate
            
        Returns:
            Dictionary with strength metrics
        """
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate strength score (0-100)
        score = 0
        
        # Length scoring
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        
        # Character diversity
        if has_lower:
            score += 15
        if has_upper:
            score += 15
        if has_digit:
            score += 15
        if has_special:
            score += 20
        
        # Bonus for length
        if length >= 16:
            score += 10
        
        # Determine strength level
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Medium"
        elif score >= 40:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'score': min(score, 100),
            'strength': strength,
            'length': length,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_special': has_special
        }
    
    @staticmethod
    def secure_delete(data):
        """
        Securely wipe sensitive data from memory
        Note: Python's memory management makes this challenging,
        but we do our best to overwrite the data
        """
        try:
            if isinstance(data, bytearray):
                # Overwrite with zeros (only works with bytearray, not bytes)
                for i in range(len(data)):
                    data[i] = 0
            elif isinstance(data, (str, bytes)):
                # Strings and bytes are immutable in Python, can't overwrite
                # Just delete reference
                del data
        except Exception:
            pass


# Singleton instance
encryption_manager = EncryptionManager()
