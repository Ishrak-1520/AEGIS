"""
Quarantine Module
Manages quarantine of infected files
Provides restore and permanent deletion capabilities
"""

import os
import shutil
from typing import Dict, List, Optional
from datetime import datetime
import sys
import base64
import secrets

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from security.encryption import encryption_manager


class QuarantineManager:
    """
    Manages file quarantine operations
    Isolates infected files and provides recovery options
    """
    
    def __init__(self, quarantine_dir: Optional[str] = None):
        """
        Initialize quarantine manager
        
        Args:
            quarantine_dir: Path to quarantine directory
        """
        self.quarantine_dir = quarantine_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'quarantine'
        )
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def quarantine_file(self, file_path: str, threat_type: str,
                       threat_name: str) -> bool:
        """
        Move file to quarantine (Encrypted)
        
        Args:
            file_path: Path to infected file
            threat_type: Type of threat detected
            threat_name: Name of threat
            
        Returns:
            True if quarantine successful
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            # Calculate file hash for tracking
            file_hash = encryption_manager.hash_file(file_path)
            if not file_hash:
                return False
            
            # Generate quarantine filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            original_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{file_hash[:8]}_{original_name}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Generate unique encryption key for this file
            key = secrets.token_bytes(32)
            key_b64 = base64.b64encode(key).decode('utf-8')
            
            # Read and encrypt file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            encrypted_content_b64 = encryption_manager.encrypt_bytes(content, key)
            
            # Write encrypted content to quarantine
            with open(quarantine_path, 'w') as f:
                f.write(encrypted_content_b64)
            
            # Securely delete original file
            # For now, just remove it. Secure wipe is harder on SSDs.
            os.remove(file_path)
            
            # Add to database with encryption key
            db_manager.add_to_quarantine(
                file_path,
                quarantine_path,
                file_hash,
                f"{threat_type}: {threat_name}",
                encryption_key=key_b64
            )
            
            # Log event
            db_manager.log_event(
                'FILE_QUARANTINED',
                'INFO',
                f'File quarantined (Encrypted): {original_name}',
                f'Threat: {threat_name}'
            )
            
            return True
            
        except Exception as e:
            print(f"Quarantine error: {e}")
            return False
    
    def restore_file(self, quarantine_id: int) -> bool:
        """
        Restore file from quarantine to original location
        
        Args:
            quarantine_id: Quarantine record ID
            
        Returns:
            True if restore successful
        """
        try:
            # Get quarantine record
            conn = db_manager._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM quarantine WHERE id = ? AND restored = 0 AND deleted = 0",
                (quarantine_id,)
            )
            record = cursor.fetchone()
            
            if not record:
                return False
            
            record = dict(record)
            original_path = record['original_path']
            quarantine_path = record['quarantine_path']
            encryption_key_b64 = record.get('encryption_key')
            
            print(f"DEBUG: Restoring {quarantine_path} -> {original_path}")
            print(f"DEBUG: Key present: {bool(encryption_key_b64)}")
            
            if not os.path.exists(quarantine_path):
                print(f"DEBUG: Quarantine file not found: {quarantine_path}")
                return False
            
            # Restore file
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            if encryption_key_b64:
                # Decrypt
                try:
                    key = base64.b64decode(encryption_key_b64)
                    with open(quarantine_path, 'r') as f:
                        encrypted_content_b64 = f.read()
                    
                    decrypted_content = encryption_manager.decrypt_bytes(encrypted_content_b64, key)
                    
                    if decrypted_content is None:
                        print("DEBUG: Failed to decrypt quarantined file (decrypt_bytes returned None)")
                        return False
                    
                    with open(original_path, 'wb') as f:
                        f.write(decrypted_content)
                except Exception as e:
                    print(f"DEBUG: Decryption exception: {e}")
                    return False
            else:
                # Legacy support (unencrypted move)
                shutil.move(quarantine_path, original_path)
            
            # Update database
            db_manager.restore_from_quarantine(quarantine_id)
            
            # Log event
            db_manager.log_event(
                'FILE_RESTORED',
                'INFO',
                f'File restored from quarantine: {os.path.basename(original_path)}'
            )
            
            return True
            
        except Exception as e:
            print(f"Restore error: {e}")
            return False
    
    def delete_quarantined(self, quarantine_id: int) -> bool:
        """
        Permanently delete quarantined file
        
        Args:
            quarantine_id: Quarantine record ID
            
        Returns:
            True if deletion successful
        """
        try:
            # Get quarantine record
            conn = db_manager._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM quarantine WHERE id = ? AND deleted = 0",
                (quarantine_id,)
            )
            record = cursor.fetchone()
            
            if not record:
                return False
            
            record = dict(record)
            quarantine_path = record['quarantine_path']
            
            # Delete file if exists
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            # Update database
            db_manager.delete_from_quarantine(quarantine_id)
            
            # Log event
            db_manager.log_event(
                'FILE_DELETED',
                'INFO',
                f'Quarantined file permanently deleted'
            )
            
            return True
            
        except Exception as e:
            print(f"Delete error: {e}")
            return False
    
    def get_quarantined_files(self) -> List[Dict]:
        """
        Get list of quarantined files
        
        Returns:
            List of quarantine records
        """
        return db_manager.get_quarantined_files()
    
    def cleanup_old_quarantine(self, days: int = 30):
        """
        Delete quarantined files older than specified days
        
        Args:
            days: Age threshold in days
        """
        try:
            conn = db_manager._get_connection()
            cursor = conn.cursor()
            
            # Find old quarantine records
            cursor.execute(
                """SELECT id, quarantine_path FROM quarantine 
                   WHERE deleted = 0 
                   AND quarantined_at < datetime('now', '-' || ? || ' days')""",
                (days,)
            )
            
            old_records = cursor.fetchall()
            
            for record in old_records:
                self.delete_quarantined(record['id'])
            
            db_manager.log_event(
                'QUARANTINE_CLEANUP',
                'INFO',
                f'Cleaned up {len(old_records)} old quarantined files'
            )
            
        except Exception as e:
            print(f"Cleanup error: {e}")


# Global instance
quarantine_manager = QuarantineManager()
