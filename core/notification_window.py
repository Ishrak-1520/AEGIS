"""
Notification Window Manager
Creates separate pywebview windows for system-wide threat notifications
Uses the same React components as the main AEGIS UI
"""
import webview
import threading
import time
import os
from typing import Dict, Any, Optional

class NotificationWindowManager:
    """Manages system-wide notification windows"""
    
    def __init__(self):
        self.active_window = None
        self.window_lock = threading.Lock()
        self.is_window_active = False
    
    def show_threat_notification(self, threat_data: Dict[str, Any]):
        """
        Show a system-wide notification window with threat data
        
        Args:
            threat_data: Dictionary containing threat information
        """
        # Only show one notification at a time
        if self.is_window_active:
            return
        
        # Create new notification window in a separate thread
        thread = threading.Thread(
            target=self._create_notification_window,
            args=(threat_data,),
            daemon=True
        )
        thread.start()
    
    def _create_notification_window(self, threat_data: Dict[str, Any]):
        """Create the notification window (runs in separate thread)"""
        
        with self.window_lock:
            if self.is_window_active:
                return
            
            self.is_window_active = True
            
            try:
                # Get the built notification HTML path
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                notification_html = os.path.join(
                    project_root,
                    'ui',
                    'frontend',
                    'dist',
                    'notification.html'
                )
                
                if not os.path.exists(notification_html):
                    print(f"Error: notification.html not found at {notification_html}")
                    self.is_window_active = False
                    return
                
                # Create a small API for the notification window
                class NotificationAPI:
                    def __init__(self, threat_data, manager):
                        self.threat_data = threat_data
                        self.manager = manager
                    
                    def get_threat_data(self):
                        """Get the current threat data"""
                        return self.threat_data
                    
                    def dismiss(self):
                        """Dismiss the notification"""
                        self.manager.close_notification()
                    
                    def view_details(self):
                        """View full details"""
                        print(f"View details clicked: {self.threat_data.get('description')}")
                        # Keep window open to show dialog
                        return True
                
                api = NotificationAPI(threat_data, self)
                
                # Window dimensions
                window_width = 400
                window_height = 200
                
                # Create the notification window
                self.active_window = webview.create_window(
                    '',  # No title for frameless window
                    notification_html,
                    js_api=api,
                    width=window_width,
                    height=window_height,
                    resizable=False,
                    frameless=True,
                    on_top=True,
                    background_color='#1a1a1a',
                    hidden=False
                )
                
                # Auto-dismiss after 30 seconds
                dismiss_timer = threading.Timer(30.0, self.close_notification)
                dismiss_timer.daemon = True
                dismiss_timer.start()
                
                # Start the window (this blocks until window closes)
                webview.start()
                
            except Exception as e:
                print(f"Error creating notification window: {e}")
                import traceback
                traceback.print_exc()
            finally:
                self.is_window_active = False
                self.active_window = None
    
    def close_notification(self):
        """Close the active notification window"""
        if self.active_window:
            try:
                self.active_window.destroy()
            except:
                pass


# Global instance
notification_manager = NotificationWindowManager()


def show_notification(threat_data: Dict[str, Any]):
    """
    Show a system-wide notification for a threat
    
    Args:
        threat_data: Dictionary containing threat information
    """
    notification_manager.show_threat_notification(threat_data)
