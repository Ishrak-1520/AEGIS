"""
Database Manager Module
Handles all database operations for CyberGuard Pro
Implements secure data access layer with encryption support
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import threading
import json


class DatabaseManager:
    """
    Thread-safe database manager for CyberGuard Pro
    Handles all CRUD operations and database initialization
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_path: str = "cyberguard.db"):
        """Singleton pattern to ensure single database connection"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, db_path: str = "cyberguard.db"):
        """Initialize database connection and create tables"""
        if not hasattr(self, 'initialized'):
            self.db_path = db_path
            self.conn = None
            self.cursor = None
            self._local = threading.local()
            self.initialized = True
            self._initialize_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _initialize_database(self):
        """Create database tables from schema file"""
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            conn = self._get_connection()
            try:
                conn.executescript(schema_sql)
                conn.commit()
            except sqlite3.Error as e:
                print(f"Database initialization error: {e}")
                raise
    
    # ==================== User Management ====================
    
    def create_user(self, username: str, password_hash: str, salt: str) -> int:
        """Create new user account"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("Username already exists")
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user by username"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def update_last_login(self, username: str):
        """Update user's last login timestamp"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET last_login = ? WHERE username = ?",
            (datetime.now(), username)
        )
        conn.commit()
    
    # ==================== Scan History ====================
    
    def add_scan_record(self, scan_type: str, scan_path: str, 
                       threats_found: int, files_scanned: int,
                       scan_duration: float, results: Dict) -> int:
        """Record scan operation"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO scan_history 
               (scan_type, scan_path, threats_found, files_scanned, 
                scan_duration, results)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_type, scan_path, threats_found, files_scanned,
             scan_duration, json.dumps(results))
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scan history"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Password Management ====================
    
    def store_password(self, website: str, username: str, 
                      encrypted_password: str, category: str = None,
                      notes: str = None) -> int:
        """Store encrypted password"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO stored_passwords 
               (website, username, encrypted_password, category, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (website, username, encrypted_password, category, notes)
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_all_passwords(self) -> List[Dict[str, Any]]:
        """Retrieve all stored passwords"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM stored_passwords ORDER BY website")
        return [dict(row) for row in cursor.fetchall()]
    
    def get_password_by_id(self, password_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve specific password by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM stored_passwords WHERE id = ?", (password_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def update_password(self, password_id: int, encrypted_password: str):
        """Update stored password"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """UPDATE stored_passwords 
               SET encrypted_password = ?, updated_at = ?
               WHERE id = ?""",
            (encrypted_password, datetime.now(), password_id)
        )
        conn.commit()
    
    def delete_password(self, password_id: int):
        """Delete stored password"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM stored_passwords WHERE id = ?", (password_id,))
        conn.commit()
    
    # ==================== Threat Logging ====================
    
    def log_threat(self, threat_type: str, threat_level: str,
                   source: str, details: str, action_taken: str,
                   confidence_score: Optional[float] = None) -> int:
        """Log detected threat"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO threat_logs 
               (threat_type, threat_level, source, details, 
                action_taken, confidence_score)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (threat_type, threat_level, source, details, 
             action_taken, confidence_score)
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_threat_logs(self, limit: int = 100, 
                       threat_level: str = None) -> List[Dict[str, Any]]:
        """Retrieve threat logs with optional filtering"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if threat_level:
            cursor.execute(
                """SELECT * FROM threat_logs 
                   WHERE threat_level = ? 
                   ORDER BY timestamp DESC LIMIT ?""",
                (threat_level, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat statistics for dashboard"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN threat_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN threat_level = 'LOW' THEN 1 ELSE 0 END) as low
            FROM threat_logs
            WHERE timestamp >= datetime('now', '-7 days')
        """)
        
        row = cursor.fetchone()
        return dict(row) if row else {}
    
    # ==================== Quarantine Management ====================
    
    def add_to_quarantine(self, original_path: str, quarantine_path: str,
                         file_hash: str, threat_type: str) -> int:
        """Add file to quarantine"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO quarantine 
               (original_path, quarantine_path, file_hash, threat_type)
               VALUES (?, ?, ?, ?)""",
            (original_path, quarantine_path, file_hash, threat_type)
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_quarantined_files(self) -> List[Dict[str, Any]]:
        """Get all quarantined files"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT * FROM quarantine 
               WHERE restored = 0 AND deleted = 0 
               ORDER BY quarantined_at DESC"""
        )
        return [dict(row) for row in cursor.fetchall()]
    
    def restore_from_quarantine(self, quarantine_id: int):
        """Mark file as restored from quarantine"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE quarantine SET restored = 1 WHERE id = ?",
            (quarantine_id,)
        )
        conn.commit()
    
    def delete_from_quarantine(self, quarantine_id: int):
        """Mark quarantined file as deleted"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE quarantine SET deleted = 1 WHERE id = ?",
            (quarantine_id,)
        )
        conn.commit()
    
    # ==================== System Events ====================
    
    def log_event(self, event_type: str, severity: str, 
                  message: str, details: str = None) -> int:
        """Log system event"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO system_events 
               (event_type, severity, message, details)
               VALUES (?, ?, ?, ?)""",
            (event_type, severity, message, details)
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_system_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve system events"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM system_events ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Malware Signatures ====================
    
    def add_signature(self, signature_hash: str, signature_name: str,
                     threat_level: str, description: str = None) -> int:
        """Add malware signature to database"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO malware_signatures 
                   (signature_hash, signature_name, threat_level, description)
                   VALUES (?, ?, ?, ?)""",
                (signature_hash, signature_name, threat_level, description)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return -1  # Signature already exists
    
    def check_signature(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if file hash matches known malware signature"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM malware_signatures WHERE signature_hash = ?",
            (file_hash,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    # ==================== Network Monitoring ====================
    
    def log_connection(self, local_address: str, remote_address: str,
                      remote_port: int, protocol: str, status: str,
                      process_name: str, is_suspicious: bool = False) -> int:
        """Log network connection"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO network_connections 
               (local_address, remote_address, remote_port, protocol, 
                status, process_name, is_suspicious)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (local_address, remote_address, remote_port, protocol,
             status, process_name, int(is_suspicious))
        )
        conn.commit()
        return cursor.lastrowid
    
    def get_network_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent network connections"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT * FROM network_connections 
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== Settings Management ====================
    
    def set_setting(self, key: str, value: str):
        """Store application setting"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT OR REPLACE INTO settings (key, value, updated_at)
               VALUES (?, ?, ?)""",
            (key, value, datetime.now())
        )
        conn.commit()
    
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """Retrieve application setting"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else default
    
    # ==================== Cleanup & Maintenance ====================
    
    def cleanup_old_logs(self, days: int = 30):
        """Remove logs older than specified days"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """DELETE FROM threat_logs 
               WHERE timestamp < datetime('now', '-' || ? || ' days')""",
            (days,)
        )
        cursor.execute(
            """DELETE FROM system_events 
               WHERE timestamp < datetime('now', '-' || ? || ' days')""",
            (days,)
        )
        cursor.execute(
            """DELETE FROM network_connections 
               WHERE timestamp < datetime('now', '-' || ? || ' days')""",
            (days,)
        )
        conn.commit()
    
    def close(self):
        """Close database connections"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
db_manager = DatabaseManager()
