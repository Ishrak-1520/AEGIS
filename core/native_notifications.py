"""
Native Windows Notification System for Threat Alerts
Creates always-on-top notification windows that appear over other applications
"""
import tkinter as tk
from tkinter import ttk
import threading
from datetime import datetime
from typing import Optional, Callable

class ThreatNotificationWindow:
    """Creates a native Windows notification popup for threats"""
    
    def __init__(self, threat_data: dict, on_view_details: Optional[Callable] = None):
        self.threat_data = threat_data
        self.on_view_details = on_view_details
        self.root = None
        self.auto_dismiss_timer = None
        
    def show(self):
        """Show the notification window"""
        # Create in a separate thread to avoid blocking
        thread = threading.Thread(target=self._create_window, daemon=True)
        thread.start()
    
    def _create_window(self):
        """Create the notification window (runs in separate thread)"""
        self.root = tk.Tk()
        
        # Window configuration
        self.root.title("AEGIS Threat Alert")
        self.root.geometry("400x180")
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Position in bottom-right corner
        x = screen_width - 420  # 400 width + 20 padding
        y = screen_height - 240  # 180 height + 60 padding (for taskbar)
        self.root.geometry(f"400x180+{x}+{y}")
        
        # Make window always on top and remove window decorations
        self.root.attributes('-topmost', True)
        self.root.overrideredirect(False)  # Keep title bar for now
        
        # Set colors based on threat level
        level = self.threat_data.get('level', 'MEDIUM')
        colors = {
            'CRITICAL': {'bg': '#8B0000', 'fg': '#FFFFFF'},
            'HIGH': {'bg': '#CD5C5C', 'fg': '#FFFFFF'},
            'MEDIUM': {'bg': '#FFA500', 'fg': '#000000'},
            'LOW': {'bg': '#FFD700', 'fg': '#000000'}
        }
        color_scheme = colors.get(level, colors['MEDIUM'])
        
        self.root.configure(bg='#1a1a1a')
        
        # Create header
        header_frame = tk.Frame(self.root, bg=color_scheme['bg'], height=40)
        header_frame.pack(fill=tk.X, padx=2, pady=2)
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(
            header_frame,
            text=f"⚠️ {level} THREAT DETECTED",
            bg=color_scheme['bg'],
            fg=color_scheme['fg'],
            font=('Segoe UI', 12, 'bold'),
            anchor='w',
            padx=10
        )
        header_label.pack(fill=tk.BOTH, expand=True)
        
        # Create content frame
        content_frame = tk.Frame(self.root, bg='#2a2a2a')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Description
        desc = self.threat_data.get('description', 'Suspicious activity detected')
        desc_label = tk.Label(
            content_frame,
            text=desc[:80] + '...' if len(desc) > 80 else desc,
            bg='#2a2a2a',
            fg='#FFFFFF',
            font=('Segoe UI', 9),
            wraplength=370,
            justify='left',
            anchor='w',
            padx=10,
            pady=5
        )
        desc_label.pack(fill=tk.X)
        
        # Source info
        source = self.threat_data.get('source', 'Unknown')
        confidence = self.threat_data.get('confidence', 0)
        info_text = f"Source: {source} | Confidence: {confidence:.1f}%"
        info_label = tk.Label(
            content_frame,
            text=info_text,
            bg='#2a2a2a',
            fg='#AAAAAA',
            font=('Segoe UI', 8),
            anchor='w',
            padx=10
        )
        info_label.pack(fill=tk.X)
        
        # Buttons frame
        button_frame = tk.Frame(content_frame, bg='#2a2a2a')
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # View Details button
        view_btn = tk.Button(
            button_frame,
            text="View Full Details",
            command=self._on_view_details,
            bg='#0066CC',
            fg='#FFFFFF',
            font=('Segoe UI', 9, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=5
        )
        view_btn.pack(side=tk.LEFT, padx=5)
        
        # Dismiss button
        dismiss_btn = tk.Button(
            button_frame,
            text="Dismiss",
            command=self._dismiss,
            bg='#444444',
            fg='#FFFFFF',
            font=('Segoe UI', 9),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=5
        )
        dismiss_btn.pack(side=tk.LEFT, padx=5)
        
        # Auto-dismiss timer (30 seconds)
        self.auto_dismiss_timer = self.root.after(30000, self._dismiss)
        
        self.root.mainloop()
    
    def _on_view_details(self):
        """Handle View Details button click"""
        if self.on_view_details:
            self.on_view_details(self.threat_data)
        self._dismiss()
    
    def _dismiss(self):
        """Dismiss the notification"""
        if self.auto_dismiss_timer:
            self.root.after_cancel(self.auto_dismiss_timer)
        if self.root:
            self.root.destroy()


def show_threat_notification(threat_data: dict, on_view_details: Optional[Callable] = None):
    """
    Show a native Windows notification for a threat
    
    Args:
        threat_data: Dictionary containing threat information
        on_view_details: Optional callback when user clicks "View Details"
    """
    notification = ThreatNotificationWindow(threat_data, on_view_details)
    notification.show()


# Test function
if __name__ == "__main__":
    test_threat = {
        'level': 'HIGH',
        'confidence': 95.5,
        'description': 'Potential phishing attempt detected on screen',
        'source': 'Real-Time Protection (chrome.exe)',
        'patterns': ['Phishing Indicators', 'Suspicious URLs'],
        'keywords': ['urgent', 'verify', 'account']
    }
    
    def on_details(threat):
        print(f"User clicked View Details for: {threat['description']}")
    
    print("Showing test notification...")
    show_threat_notification(test_threat, on_details)
