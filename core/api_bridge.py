import json
import sys
import os
import threading
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.monitor import system_monitor
from core.scanner import FileScanner
from security.password_manager import password_manager
from core.quarantine import quarantine_manager
from core.realtime_protection import realtime_protection
from ai.nlp_model import get_nlp_detector
from database.db_manager import db_manager

class AegisAPI:
    """
    API Bridge between Python backend and React frontend.
    Methods here are exposed to Javascript via pywebview.
    """
    def __init__(self):
        self.scanner = FileScanner()
        self.scan_thread = None
        self.scan_progress = {'status': 'idle', 'progress': 0, 'file': '', 'results': []}
        
        # Window reference for focusing
        self.main_window = None
        
        # Start system monitor
        if not system_monitor.monitoring:
            system_monitor.start_monitoring()
            
        # Threat Alert Queue
        self.threat_alert_queue = []
        self.max_queue_size = 10
        
        # Register RTP callback
        if hasattr(realtime_protection, 'register_threat_callback'):
            realtime_protection.register_threat_callback(self._on_threat_detected)
    
    def set_window(self, window):
        """Set the main window reference for focusing"""
        self.main_window = window

    # --- System Stats ---
    def get_system_stats(self):
        """Get current system statistics"""
        stats = system_monitor.get_system_stats()
        # Format for frontend
        return {
            'cpu': stats.get('cpu', {}).get('percent', 0),
            'memory': stats.get('memory', {}).get('percent', 0),
            'disk': stats.get('disk', {}).get('percent', 0)
        }

    # --- Scanner ---
    def start_scan(self, scan_type):
        """Start a scan in a background thread"""
        if self.scan_thread and self.scan_thread.is_alive():
            return {'status': 'error', 'message': 'Scan already in progress'}

        self.scan_progress = {'status': 'scanning', 'progress': 0, 'file': 'Initializing...', 'results': []}
        
        if scan_type == 'quick':
            self.scan_thread = threading.Thread(target=self._run_quick_scan)
        elif scan_type == 'full':
            self.scan_thread = threading.Thread(target=self._run_full_scan)
        else:
            return {'status': 'error', 'message': 'Invalid scan type'}
            
        self.scan_thread.start()
        return {'status': 'started', 'type': scan_type}

    def _run_quick_scan(self):
        """Run quick scan and update progress"""
        def progress_callback(percent, file_path, result):
            self.scan_progress['progress'] = int(percent)
            self.scan_progress['file'] = os.path.basename(file_path)
            if result['status'] == 'INFECTED':
                self.scan_progress['results'].append({
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'status': 'threat',
                    'threat': result['threat']
                })

        try:
            self.scanner.quick_scan(progress_callback=progress_callback)
            self.scan_progress['status'] = 'completed'
            self.scan_progress['progress'] = 100
        except Exception as e:
            self.scan_progress['status'] = 'error'
            self.scan_progress['error'] = str(e)

    def _run_full_scan(self):
        """Run full scan (user home dir)"""
        def progress_callback(percent, file_path, result):
            self.scan_progress['progress'] = int(percent)
            self.scan_progress['file'] = os.path.basename(file_path)
            if result['status'] == 'INFECTED':
                self.scan_progress['results'].append({
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'status': 'threat',
                    'threat': result['threat']
                })

        try:
            home_dir = os.path.expanduser("~")
            self.scanner.scan_directory(home_dir, recursive=True, progress_callback=progress_callback)
            self.scan_progress['status'] = 'completed'
            self.scan_progress['progress'] = 100
        except Exception as e:
            self.scan_progress['status'] = 'error'
            self.scan_progress['error'] = str(e)

    def get_scan_progress(self):
        """Get current scan progress"""
        return self.scan_progress

    def stop_scan(self):
        """Stop current scan"""
        if self.scanner:
            self.scanner.stop_scan()
        self.scan_progress['status'] = 'stopped'
        return {'status': 'stopped'}

    # --- Password Manager ---
    def get_passwords(self):
        """Get all passwords (decrypted for display)"""
        # Note: In a real app, we might want to only send encrypted and decrypt on demand
        # For this UI integration, we'll send the list.
        # Ideally, we should prompt for master password first.
        # Assuming session is active or we just list them.
        passwords = password_manager.get_all_passwords()
        # Decrypt for display (be careful in production!)
        # For now, let's just return the list, frontend can request decryption
        return passwords

    def add_password(self, website, username, password, category=None):
        return password_manager.add_password(website, username, password, category)

    def delete_password(self, password_id):
        return password_manager.delete_password(password_id)

    # --- Quarantine ---
    def get_quarantined_items(self):
        return quarantine_manager.get_quarantined_files()

    def restore_quarantine_item(self, item_id):
        return quarantine_manager.restore_file(item_id)

    def delete_quarantine_item(self, item_id):
        return quarantine_manager.delete_quarantined(item_id)

    # --- Real-Time Protection ---
    def get_rtp_status(self):
        stats = realtime_protection.get_statistics()
        # Map backend fields to frontend expectations
        return {
            'is_running': stats.get('is_active', False),
            'files_monitored': stats.get('scans_performed', 0),
            'threats_blocked': stats.get('threats_detected', 0)
        }

    def toggle_rtp(self, enabled):
        if enabled:
            return realtime_protection.start_protection()
        else:
            return realtime_protection.stop_protection()

    def get_pending_threat_alerts(self):
        """Get and clear pending threat alerts"""
        alerts = self.threat_alert_queue.copy()
        self.threat_alert_queue.clear()
        return alerts

    def _on_threat_detected(self, threat_data):
        """Callback when RTP detects threat"""
        # Add to queue for React UI
        self.threat_alert_queue.append(threat_data)
        
        # Limit queue size
        if len(self.threat_alert_queue) > self.max_queue_size:
            self.threat_alert_queue.pop(0)

    # --- NLP Threat Detection ---
    def analyze_text(self, text):
        detector = get_nlp_detector()
        return detector.analyze_text(text)

    # --- Logs/Reports ---
    def get_recent_logs(self, limit=50):
        return db_manager.get_system_events(limit)

    def get_version(self):
        return "2.0.0 (AEGIS)"
