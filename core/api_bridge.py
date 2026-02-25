import json
import sys
import os
import threading
import queue
import webview

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
from core.sift_engine import SiftEngine

class AegisAPI:
    """
    API Bridge between Python backend and React frontend.
    Methods here are exposed to Javascript via pywebview.
    """
    def __init__(self, network_alert_queue=None, sniffer_service=None):
        self.scanner = FileScanner()
        self.scan_thread = None
        self.scan_progress = {'status': 'idle', 'progress': 0, 'file': '', 'results': []}
        
        # Window reference for focusing
        self._main_window = None
        
        # Start system monitor
        if not system_monitor.monitoring:
            system_monitor.start_monitoring()
            
        # Threat Alert Queue (for RTP)
        self.threat_alert_queue = []
        self.max_queue_size = 10
        
        # NIDS Integration
        self._network_alert_queue = network_alert_queue
        self._sniffer_service = sniffer_service
        self._network_alerts_cache = []  # Cache for polled alerts
        
        # Register RTP callback
        if hasattr(realtime_protection, 'register_threat_callback'):
            realtime_protection.register_threat_callback(self._on_threat_detected)
            
        # Sift Engine Initialization
        sift_api_key = os.getenv('SIFT_API_KEY')
        self.sift_engine = SiftEngine(api_key=sift_api_key) if sift_api_key else None
        if not self.sift_engine:
            print("WARNING: SIFT_API_KEY not found. Sift features will be disabled.", flush=True)
    
    def set_window(self, window):
        """Set the main window reference for focusing"""
        self._main_window = window

    def browse_directory(self):
        """Open directory picker dialog"""
        print("DEBUG: browse_directory called", flush=True)
        if self._main_window:
            print("DEBUG: Opening file dialog...", flush=True)
            try:
                # Handle deprecation of FOLDER_DIALOG
                dialog_type = getattr(webview, 'FOLDER_DIALOG', 10) # Fallback to old constant
                if hasattr(webview, 'FileDialog'):
                    dialog_type = webview.FileDialog.FOLDER
                
                result = self._main_window.create_file_dialog(dialog_type)
                print(f"DEBUG: Dialog result: {result}", flush=True)
                return result[0] if result else None
            except Exception as e:
                print(f"DEBUG: Dialog error: {e}", flush=True)
                return None
        print("DEBUG: No main window set", flush=True)
        return None

    def browse_file(self):
        """Open file picker dialog"""
        if self._main_window:
            try:
                # Handle deprecation of OPEN_DIALOG
                dialog_type = getattr(webview, 'OPEN_DIALOG', 10) # Fallback
                if hasattr(webview, 'FileDialog'):
                    dialog_type = webview.FileDialog.OPEN
                
                result = self._main_window.create_file_dialog(dialog_type)
                return result[0] if result else None
            except Exception:
                return None
        return None

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
    def start_scan(self, scan_type, target_path=None):
        """Start a scan in a background thread"""
        if self.scan_thread and self.scan_thread.is_alive():
            return {'status': 'error', 'message': 'Scan already in progress'}

        self.scan_progress = {'status': 'scanning', 'progress': 0, 'file': 'Initializing...', 'results': []}
        
        if scan_type == 'quick':
            self.scan_thread = threading.Thread(target=self._run_quick_scan)
        elif scan_type == 'full':
            self.scan_thread = threading.Thread(target=self._run_full_scan)
        elif scan_type == 'custom':
            if not target_path:
                return {'status': 'error', 'message': 'No path specified'}
            self.scan_thread = threading.Thread(target=self._run_custom_scan, args=(target_path,))
        else:
            return {'status': 'error', 'message': 'Invalid scan type'}
            
        self.scan_thread.start()
        return {'status': 'started', 'type': scan_type}

    def _run_quick_scan(self):
        """Run quick scan and update progress"""
        def progress_callback(percent, file_path, result):
            self.scan_progress['progress'] = int(percent)
            self.scan_progress['file'] = os.path.basename(file_path)
            if result['status'] in ['INFECTED', 'SUSPICIOUS']:
                self.scan_progress['results'].append({
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'status': 'threat' if result['status'] == 'INFECTED' else 'suspicious',
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
            if result['status'] in ['INFECTED', 'SUSPICIOUS']:
                self.scan_progress['results'].append({
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'status': 'threat' if result['status'] == 'INFECTED' else 'suspicious',
                    'threat': result['threat']
                })

        try:
            home_dir = os.path.expanduser("~")
            # For full scan, we might want to be careful about scanning everything.
            # Let's scan Documents, Downloads, Desktop for now to avoid system file permission issues
            # or scan the whole user dir but expect errors.
            self.scanner.scan_directory(home_dir, recursive=True, progress_callback=progress_callback)
            self.scan_progress['status'] = 'completed'
            self.scan_progress['progress'] = 100
        except Exception as e:
            self.scan_progress['status'] = 'error'
            self.scan_progress['error'] = str(e)

    def _run_custom_scan(self, target_path):
        """Run custom scan on file or directory"""
        def progress_callback(percent, file_path, result):
            self.scan_progress['progress'] = int(percent)
            self.scan_progress['file'] = os.path.basename(file_path)
            if result['status'] in ['INFECTED', 'SUSPICIOUS']:
                self.scan_progress['results'].append({
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'status': 'threat' if result['status'] == 'INFECTED' else 'suspicious',
                    'threat': result['threat']
                })

        try:
            if os.path.isfile(target_path):
                # Scan single file
                self.scan_progress['file'] = os.path.basename(target_path)
                result = self.scanner.scan_file(target_path)
                progress_callback(100, target_path, result)
            else:
                # Scan directory
                self.scanner.scan_directory(target_path, recursive=True, progress_callback=progress_callback)
            
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

    def get_nlp_history(self):
        """Get recent NLP analysis history"""
        # Get more events to ensure we find NLP ones
        events = db_manager.get_system_events(200)
        history = []
        for event in events:
            if event['event_type'] == 'NLP_ANALYSIS':
                try:
                    details = event.get('details')
                    if details and isinstance(details, str) and details.strip().startswith('{'):
                        result = json.loads(details)
                        # Ensure timestamp is present (it should be in the result, but fallback to event timestamp)
                        if 'timestamp' not in result:
                            result['timestamp'] = event['timestamp']
                        history.append(result)
                except Exception as e:
                    print(f"Error parsing NLP history item: {e}")
                    continue
        return history

    def clear_nlp_history(self):
        """Clear NLP analysis history"""
        db_manager.delete_system_events('NLP_ANALYSIS')
        return {'status': 'success'}

    # --- Logs/Reports ---
    def get_recent_logs(self, limit=50):
        return db_manager.get_system_events(limit)

    def get_version(self):
        return "2.0.0 (AEGIS)"

    # --- Network Intrusion Detection (NIDS) ---
    def get_network_alerts(self):
        """
        Get pending network alerts from the NIDS sniffer.
        Returns up to 10 alerts and clears them from queue.
        """
        alerts = []
        if self._network_alert_queue:
            # Drain up to 10 alerts from queue
            for _ in range(10):
                try:
                    alert = self._network_alert_queue.get_nowait()
                    alerts.append(alert)
                except queue.Empty:
                    break
        return alerts

    def get_nids_status(self):
        """
        Get the current status of the NIDS sniffer service.
        """
        if self._sniffer_service:
            return self._sniffer_service.get_statistics()
        return {
            "is_active": False,
            "total_packets": 0,
            "total_flows": 0,
            "threats_detected": 0,
            "error": "Sniffer not initialized"
        }

    def toggle_nids(self, enabled):
        """
        Start or stop the NIDS sniffer.
        Note: Currently only supports checking status, as sniffer
        is started at application launch.
        """
        if self._sniffer_service:
            if not enabled:
                self._sniffer_service.stop()
                return {"status": "stopped"}
            else:
                # Sniffer already running from startup
                if self._sniffer_service.is_active():
                    return {"status": "already_running"}
                else:
                    return {"status": "error", "message": "Restart application to re-enable NIDS"}
        return {"status": "error", "message": "Sniffer not available"}

    # --- Sift Code Analysis ---
    def sift_detect_language(self, code_content: str) -> str:
        """
        Detect programming language of the code snippet.
        """
        if not self.sift_engine:
            return "Sift Engine not initialized (Missing API Key)"
        return self.sift_engine.detect_language(code_content)

    def sift_analyze_code(self, code_content: str, language: str) -> dict:
        """
        Analyze code for security vulnerabilities.
        """
        if not self.sift_engine:
            return {"error": "Sift Engine not initialized (Missing API Key)"}
        return self.sift_engine.analyze_code(code_content, filename=language)
