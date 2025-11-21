"""
Password Manager Module
Secure password storage, generation, and management
Uses AES-256 encryption with session key
"""

import os
import sys
from typing import List, Dict, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.encryption import encryption_manager
from security.auth import auth_manager
from database.db_manager import db_manager


class PasswordManager:
    """
    Manages secure password storage and retrieval
    All passwords encrypted with user's session key
    """
    
    def __init__(self):
        """Initialize password manager"""
        pass
    
    def add_password(self, website: str, username: str, password: str,
                    category: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """
        Add password to vault
        
        Args:
            website: Website/service name
            username: Username/email
            password: Password to store
            category: Optional category
            notes: Optional notes
            
        Returns:
            True if successful
        """
        try:
            # Get session key
            session_key = auth_manager.get_session_key()
            if not session_key:
                raise ValueError("User not authenticated")
            
            # Encrypt password
            encrypted_password = encryption_manager.encrypt(password, session_key)
            
            # Store in database
            db_manager.store_password(
                website,
                username,
                encrypted_password,
                category,
                notes
            )
            
            db_manager.log_event(
                'PASSWORD_ADDED',
                'INFO',
                f'Password added for {website}'
            )
            
            return True
            
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
    
    def get_password(self, password_id: int) -> Optional[str]:
        """
        Retrieve and decrypt password
        
        Args:
            password_id: Password record ID
            
        Returns:
            Decrypted password or None
        """
        try:
            # Get session key
            session_key = auth_manager.get_session_key()
            if not session_key:
                return None
            
            # Get encrypted password from database
            record = db_manager.get_password_by_id(password_id)
            if not record:
                return None
            
            # Decrypt password
            decrypted = encryption_manager.decrypt(
                record['encrypted_password'],
                session_key
            )
            
            return decrypted
            
        except Exception as e:
            print(f"Error retrieving password: {e}")
            return None
    
    def get_all_passwords(self) -> List[Dict]:
        """
        Get all password records (without decrypting)
        
        Returns:
            List of password records
        """
        try:
            return db_manager.get_all_passwords()
        except Exception as e:
            print(f"Error getting passwords: {e}")
            return []
    
    def update_password(self, password_id: int, new_password: str) -> bool:
        """
        Update existing password
        
        Args:
            password_id: Password record ID
            new_password: New password
            
        Returns:
            True if successful
        """
        try:
            # Get session key
            session_key = auth_manager.get_session_key()
            if not session_key:
                return False
            
            # Encrypt new password
            encrypted = encryption_manager.encrypt(new_password, session_key)
            
            # Update database
            db_manager.update_password(password_id, encrypted)
            
            db_manager.log_event(
                'PASSWORD_UPDATED',
                'INFO',
                f'Password updated (ID: {password_id})'
            )
            
            return True
            
        except Exception as e:
            print(f"Error updating password: {e}")
            return False
    
    def delete_password(self, password_id: int) -> bool:
        """
        Delete password from vault
        
        Args:
            password_id: Password record ID
            
        Returns:
            True if successful
        """
        try:
            db_manager.delete_password(password_id)
            
            db_manager.log_event(
                'PASSWORD_DELETED',
                'INFO',
                f'Password deleted (ID: {password_id})'
            )
            
            return True
            
        except Exception as e:
            print(f"Error deleting password: {e}")
            return False
    
    def generate_password(self, length: int = 16,
                         use_uppercase: bool = True,
                         use_lowercase: bool = True,
                         use_digits: bool = True,
                         use_special: bool = True) -> str:
        """
        Generate strong random password
        
        Args:
            length: Password length
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include digits
            use_special: Include special characters
            
        Returns:
            Generated password
        """
        return encryption_manager.generate_password(
            length,
            use_uppercase,
            use_lowercase,
            use_digits,
            use_special
        )
    
    def check_password_strength(self, password: str) -> Dict:
        """
        Evaluate password strength
        
        Args:
            password: Password to check
            
        Returns:
            Strength metrics dictionary
        """
        return encryption_manager.evaluate_password_strength(password)
    
    def search_passwords(self, query: str) -> List[Dict]:
        """
        Search passwords by website or username
        
        Args:
            query: Search query
            
        Returns:
            Matching password records
        """
        all_passwords = self.get_all_passwords()
        query_lower = query.lower()
        
        results = []
        for pwd in all_passwords:
            if (query_lower in pwd['website'].lower() or
                query_lower in pwd['username'].lower()):
                results.append(pwd)
        
        return results


# Global instance
password_manager = PasswordManager()
