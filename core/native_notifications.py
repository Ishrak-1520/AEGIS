"""
Native Windows Notification System for Threat Alerts
Creates OS-level notifications (Windows Toast) that appear over other applications
"""
import threading
import sys
import os
import subprocess
from typing import Optional, Callable
from .system_logger import system_logger

def _send_windows_toast(threat_data: dict):
    """
    Sends a native Windows Toast notification via PowerShell.
    """
    level = threat_data.get('level', 'MEDIUM').upper()
    desc = threat_data.get('description', 'Suspicious activity detected')
    source = threat_data.get('source', 'Unknown')
    
    title = f"⚠️ CyberGuard {level} THREAT"
    message = f"[{source}] {desc}"
    
    # Clean inputs to prevent PowerShell injection
    safe_title = title.replace("'", "''").replace('"', '""')
    safe_message = message.replace("'", "''").replace('"', '""')
    
    # Define audio based on level
    audio_src = "ms-winsoundevent:Notification.Default"
    if level in ["HIGH", "CRITICAL"]:
        audio_src = "ms-winsoundevent:Notification.Looping.Alarm"
    
    toast_xml = f"""
    <toast duration="long">
        <visual>
            <binding template="ToastText02">
                <text id="1">{safe_title}</text>
                <text id="2" hint-wrap="true">{safe_message}</text>
            </binding>
        </visual>
        <audio src="{audio_src}"/>
    </toast>
    """
    
    ps_script = f"""
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml('{toast_xml}')

    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CyberGuard Pro")
    $notifier.Show($toast)
    """
    
    try:
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = 0x08000000  # CREATE_NO_WINDOW
            
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            creationflags=creation_flags,
            timeout=5
        )
    except Exception as e:
        system_logger.log_error(f"Failed to send Windows toast: {e}", "app")

def show_threat_notification(threat_data: dict, on_view_details: Optional[Callable] = None):
    """
    Show a native Windows notification for a threat
    
    Args:
        threat_data: Dictionary containing threat information
        on_view_details: Optional callback (Not deeply supported in pure PS script without event loop, kept for compat)
    """
    if sys.platform != "win32":
        system_logger.log_warning("Native OS notifications are only active on Windows.", "app")
        return
        
    threading.Thread(
        target=_send_windows_toast,
        args=(threat_data,),
        daemon=True
    ).start()

# Test function
if __name__ == "__main__":
    test_threat = {
        'level': 'HIGH',
        'confidence': 95.5,
        'description': 'Potential phishing attempt detected on screen',
        'source': 'Real-Time Protection',
        'patterns': ['Phishing Indicators', 'Suspicious URLs'],
        'keywords': ['urgent', 'verify', 'account']
    }
    
    print("Showing test native notification...")
    show_threat_notification(test_threat, None)
    import time
    time.sleep(3)

