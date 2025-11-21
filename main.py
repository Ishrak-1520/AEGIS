"""
Main Application Entry Point
CyberGuard Pro - AI-Powered Cybersecurity Application
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication, QSplashScreen, QMessageBox
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QFont

# Import application modules
from gui.login import LoginWindow
from gui.dashboard import Dashboard
from database.db_manager import db_manager
from core.system_logger import system_logger


class CyberGuardApp:
    """
    Main application class
    Coordinates GUI, security modules, and system components
    """
    
    def __init__(self):
        """Initialize application"""
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("CyberGuard Pro")
        self.app.setOrganizationName("CyberGuard")
        
        # Set application style
        self.app.setStyle('Fusion')
        
        # Windows
        self.login_window = None
        self.dashboard = None
        
        # Initialize components
        self.initialize_database()
        
        system_logger.log_info("CyberGuard Pro application started")
    
    def initialize_database(self):
        """Initialize database and check integrity"""
        try:
            # Database is auto-initialized in db_manager
            system_logger.log_info("Database initialized successfully")
        except Exception as e:
            system_logger.log_error(f"Database initialization error: {e}", exc_info=True)
            QMessageBox.critical(
                None,
                "Database Error",
                f"Failed to initialize database: {e}"
            )
            sys.exit(1)
    
    def show_login(self):
        """Display login window"""
        self.login_window = LoginWindow()
        self.login_window.login_successful.connect(self.on_login_success)
        self.login_window.show()
    
    def on_login_success(self, username: str):
        """Handle successful login"""
        system_logger.log_info(f"User logged in: {username}")
        
        # Close login window
        if self.login_window:
            self.login_window.close()
        
        # Show dashboard
        self.show_dashboard(username)
    
    def show_dashboard(self, username: str):
        """Display main dashboard"""
        self.dashboard = Dashboard(username)
        self.dashboard.show()
        self.dashboard.showMaximized()
    
    def run(self):
        """Run the application"""
        # Show login window
        self.show_login()
        
        # Start event loop
        return self.app.exec_()


def main():
    """Main entry point"""
    print("=" * 60)
    print("CyberGuard Pro - AI-Powered Autonomous Cyber Defense")
    print("=" * 60)
    print()
    
    try:
        app = CyberGuardApp()
        sys.exit(app.run())
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
