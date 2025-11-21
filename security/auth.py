"""
Authentication Module
Handles user authentication and session management
"""

import os
import time
from typing import Optional, Dict
from datetime import datetime, timedelta
import threading

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.encryption import EncryptionManager, encryption_manager
from database.db_manager import DatabaseManager, db_manager


class AuthenticationManager:
    """
    Manages user authentication and session handling
    Implements secure login with master password
    """
    
    def __init__(self, db: Optional[DatabaseManager] = None, crypto: Optional[EncryptionManager] = None):
        """Initialize authentication manager"""
        self.db = db or db_manager
        self.crypto = crypto or encryption_manager
        self.current_user = None
        self.session_key = None
        self.session_start = None
        self.session_timeout = 30  # minutes
        self._lock = threading.Lock()
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register new user with master password
        
        Args:
            username: Username
            password: Master password
            
        Returns:
            True if registration successful, False otherwise
        """
        try:
            # Validate password strength
            strength = self.crypto.evaluate_password_strength(password)
            if strength['score'] < 60:
                raise ValueError("Password too weak. Use at least 12 characters with mixed case, digits, and symbols.")
            
            # Hash password
            password_hash, salt = self.crypto.hash_password(password)
            
            # Create user
            user_id = self.db.create_user(username, password_hash, salt)
            
            if user_id:
                self.db.log_event(
                    'USER_REGISTRATION',
                    'INFO',
                    f'New user registered: {username}'
                )
                return True
            return False
            
        except ValueError as e:
            print(f"Registration error: {e}")
            return False
        except Exception as e:
            print(f"Registration failed: {e}")
            return False
    
    def login(self, username: str, password: str) -> bool:
        """
        Authenticate user with master password
        
        Args:
            username: Username
            password: Master password
            
        Returns:
            True if login successful, False otherwise
        """
        with self._lock:
            try:
                # Get user from database
                user = self.db.get_user(username)
                if not user:
                    return False
                
                # Verify password
                if not self.crypto.verify_password(
                    password, 
                    user['password_hash'], 
                    user['salt']
                ):
                    self.db.log_event(
                        'LOGIN_FAILED',
                        'WARNING',
                        f'Failed login attempt for user: {username}'
                    )
                    return False
                
                # Create session
                self.current_user = username
                self.session_start = datetime.now()
                
                # Derive session key from password
                import base64
                salt = base64.b64decode(user['salt'])
                self.session_key = self.crypto.derive_key(password, salt)
                
                # Update last login
                self.db.update_last_login(username)
                
                self.db.log_event(
                    'LOGIN_SUCCESS',
                    'INFO',
                    f'User logged in: {username}'
                )
                
                return True
                
            except Exception as e:
                print(f"Login error: {e}")
                return False
    
    def logout(self):
        """Logout current user and clear session"""
        with self._lock:
            if self.current_user:
                self.db.log_event(
                    'LOGOUT',
                    'INFO',
                    f'User logged out: {self.current_user}'
                )
            
            # Clear session data
            self.current_user = None
            if self.session_key:
                # Attempt to securely wipe key
                self.crypto.secure_delete(self.session_key)
            self.session_key = None
            self.session_start = None
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        if not self.current_user or not self.session_key:
            return False
        
        # Check session timeout
        if self.session_start:
            elapsed = datetime.now() - self.session_start
            if elapsed > timedelta(minutes=self.session_timeout):
                self.logout()
                return False
        
        return True
    
    def get_session_key(self) -> Optional[bytes]:
        """
        Get current session encryption key
        
        Returns:
            Session key if authenticated, None otherwise
        """
        if self.is_authenticated():
            return self.session_key
        return None
    
    def get_current_user(self) -> Optional[str]:
        """Get current authenticated username"""
        if self.is_authenticated():
            return self.current_user
        return None
    
    def refresh_session(self):
        """Refresh session timeout"""
        if self.is_authenticated():
            self.session_start = datetime.now()
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change user's master password
        
        Args:
            old_password: Current password
            new_password: New password
            
        Returns:
            True if password changed successfully
        """
        if not self.is_authenticated() or not self.current_user:
            return False
        
        try:
            # Verify old password
            user = self.db.get_user(self.current_user)
            if not user:
                return False
            
            if not self.crypto.verify_password(
                old_password,
                user['password_hash'],
                user['salt']
            ):
                return False
            
            # Validate new password strength
            strength = self.crypto.evaluate_password_strength(new_password)
            if strength['score'] < 60:
                raise ValueError("New password too weak")
            
            # Hash new password
            new_hash, new_salt = self.crypto.hash_password(new_password)
            
            # Update database
            conn = self.db._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                (new_hash, new_salt, self.current_user)
            )
            conn.commit()
            
            self.db.log_event(
                'PASSWORD_CHANGED',
                'INFO',
                f'Password changed for user: {self.current_user}'
            )
            
            # Update session key
            import base64
            salt = base64.b64decode(new_salt)
            self.session_key = self.crypto.derive_key(new_password, salt)
            
            return True
            
        except Exception as e:
            print(f"Password change error: {e}")
            return False
    
    def has_users(self) -> bool:
        """Check if any users exist in database"""
        conn = self.db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        result = cursor.fetchone()
        return result['count'] > 0 if result else False


# Singleton instance
auth_manager = AuthenticationManager()
