"""
Login Window
User authentication interface
"""

import os
import sys
import json
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QCheckBox, QMessageBox, QGraphicsDropShadowEffect
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor
from gui.styles import LOGIN_STYLESHEET, get_icon

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.auth import auth_manager


class LoginWindow(QWidget):
    """
    Login/Registration window
    """
    
    login_successful = pyqtSignal(str)  # Signal emitted on successful login
    
    def __init__(self):
        super().__init__()
        self.credentials_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'credentials.enc')
        self.init_ui()
        self.load_saved_credentials()
    
    def init_ui(self):
        """Initialize user interface with modern design matching HTML template"""
        self.setWindowTitle("CyberGuard Pro - Secure Login")
        self.setFixedSize(650, 850)
        
        # Modern dark theme stylesheet matching HTML design
        self.setStyleSheet("""
            QWidget {
                background-color: #050505;
                color: #ffffff;
                font-family: 'Segoe UI', 'Roboto', sans-serif;
            }
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid #333;
                border-radius: 6px;
                padding: 14px 16px;
                padding-left: 48px;
                color: #ffffff;
                font-size: 14px;
                min-height: 42px;
            }
            QLineEdit:focus {
                border: 1px solid #00f3ff;
                background-color: rgba(0, 243, 255, 0.05);
                outline: none;
            }
            QLineEdit::placeholder {
                color: #666;
            }
            QPushButton#loginButton {
                background-color: #00f3ff;
                color: #000000;
                border: none;
                border-radius: 0px;
                padding: 14px;
                font-size: 15px;
                font-weight: bold;
                min-height: 56px;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            QPushButton#loginButton:hover {
                background-color: #00f3ff;
                color: #000000;

            }
            QPushButton#loginButton:pressed {
                background-color: #00c2cc;
            }
            QPushButton#togglePassword {
                background-color: transparent;
                color: #666;
                border: none;
                padding: 8px;
                font-size: 20px;
            }
            QPushButton#togglePassword:hover {
                color: #00f3ff;
            }
            QPushButton#forgotPassword {
                background-color: transparent;
                color: #00f3ff;
                border: none;
                text-decoration: underline;
                font-size: 13px;
                padding: 4px;
            }
            QPushButton#forgotPassword:hover {
                color: #ffffff;
            }
            QCheckBox {
                color: #aaa;
                font-size: 13px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #444;
                border-radius: 4px;
                background-color: rgba(255, 255, 255, 0.05);
            }
            QCheckBox::indicator:checked {
                background-color: #00f3ff;
                border-color: #00f3ff;
            }
            QCheckBox::indicator:hover {
                border-color: #00f3ff;
            }
        """)
        
        # Main layout with gradient background effect
        main_widget = QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background: qradialgradient(
                    cx:0.5, cy:0.5, radius: 1.0,
                    fx:0.5, fy:0.5,
                    stop:0 rgba(0, 243, 255, 0.05),
                    stop:1 #050505
                );
            }
        """)
        
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Center container
        center_widget = QWidget()
        center_layout = QVBoxLayout(center_widget)
        center_layout.setAlignment(Qt.AlignCenter)
        center_layout.setContentsMargins(32, 32, 32, 32)
        
        # Content container (max-width card)
        content_widget = QWidget()
        content_widget.setMaximumWidth(450)
        content_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(10, 10, 10, 0.8);
                border: 1px solid #333;
                border-radius: 12px;
            }
        """)
        
        # Add glow effect to the card
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 243, 255, 30))
        shadow.setOffset(0, 0)
        content_widget.setGraphicsEffect(shadow)
        
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(24)
        layout.setContentsMargins(32, 32, 32, 32)
        
        # Header section
        header_layout = QVBoxLayout()
        header_layout.setSpacing(16)
        header_layout.setAlignment(Qt.AlignCenter)
        
        # Logo and title row
        logo_row = QHBoxLayout()
        logo_row.setAlignment(Qt.AlignCenter)
        logo_row.setSpacing(12)
        
        # Shield icon
        shield_label = QLabel()
        shield_label.setPixmap(get_icon('shield', '#00f3ff').pixmap(32, 32))
        shield_label.setStyleSheet("background-color: transparent; border: none;")
        logo_row.addWidget(shield_label)
        
        # Title
        title = QLabel("CyberGuard Pro")
        title.setFont(QFont("Segoe UI", 26, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background-color: transparent; border: none; letter-spacing: 1px;")
        logo_row.addWidget(title)
        
        header_layout.addLayout(logo_row)
        
        layout.addLayout(header_layout)
        
        # Login form section
        form_widget = QWidget()
        form_widget.setStyleSheet("background-color: transparent; border: none;")
        form_layout = QVBoxLayout(form_widget)
        form_layout.setSpacing(8)
        form_layout.setContentsMargins(0, 0, 0, 0)
        
        # Section title
        section_title = QLabel("SECURE LOGIN")
        section_title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        section_title.setAlignment(Qt.AlignCenter)
        section_title.setStyleSheet("color: #00f3ff; background-color: transparent; border: none; letter-spacing: 2px;")
        form_layout.addWidget(section_title)
        
        # Subtitle
        subtitle = QLabel("Authenticate to access secure terminal.")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #888; background-color: transparent; border: none;")
        form_layout.addWidget(subtitle)
        
        form_layout.addSpacing(24)
        
        # Username field
        username_label = QLabel("IDENTITY")
        username_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        username_label.setStyleSheet("color: #00f3ff; background-color: transparent; border: none; padding-bottom: 4px;")
        form_layout.addWidget(username_label)
        
        # Username input with icon
        username_container = QWidget()
        username_container.setStyleSheet("background-color: transparent; border: none;")
        username_layout = QHBoxLayout(username_container)
        username_layout.setContentsMargins(0, 0, 0, 0)
        username_layout.setSpacing(0)
        
        username_icon = QLabel()
        username_icon.setPixmap(get_icon('user', '#666').pixmap(20, 20))
        username_icon.setFixedHeight(48)
        username_icon.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid #333;
            border-right: none;
            padding: 12px;
            min-width: 40px;
        """)
        username_icon.setAlignment(Qt.AlignCenter)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setFixedHeight(48)
        self.username_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid #333;
                border-left: none;
                color: #ffffff;
                padding: 0 16px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #00f3ff;
                border-left: none;
                background-color: rgba(0, 243, 255, 0.05);
            }
        """)
        self.username_input.returnPressed.connect(self.handle_login)
        
        username_layout.addWidget(username_icon)
        username_layout.addWidget(self.username_input)
        form_layout.addWidget(username_container)
        
        form_layout.addSpacing(16)
        
        # Password field
        password_label = QLabel("ACCESS CODE")
        password_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        password_label.setStyleSheet("color: #00f3ff; background-color: transparent; border: none; padding-bottom: 4px;")
        form_layout.addWidget(password_label)
        
        # Password input with icon and toggle
        password_container = QWidget()
        password_container.setStyleSheet("background-color: transparent; border: none;")
        password_layout = QHBoxLayout(password_container)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(0)
        
        password_icon = QLabel()
        password_icon.setPixmap(get_icon('lock', '#666').pixmap(20, 20))
        password_icon.setFixedHeight(48)
        password_icon.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid #333;
            border-right: none;
            padding: 12px;
            min-width: 40px;
        """)
        password_icon.setAlignment(Qt.AlignCenter)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setFixedHeight(48)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid #333;
                border-left: none;
                border-right: none;
                color: #ffffff;
                padding: 0 16px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #00f3ff;
                border-left: none;
                border-right: none;
                background-color: rgba(0, 243, 255, 0.05);
            }
        """)
        self.password_input.returnPressed.connect(self.handle_login)
        
        self.toggle_password_btn = QPushButton()
        self.toggle_password_btn.setIcon(get_icon('eye', '#666'))
        self.toggle_password_btn.setIconSize(QSize(20, 20))
        self.toggle_password_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_password_btn.setFixedHeight(48)
        self.toggle_password_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid #333;
                border-left: none;
                padding: 12px;
                min-width: 40px;
            }
            QPushButton:hover {
                background-color: rgba(0, 243, 255, 0.1);
            }
        """)
        self.toggle_password_btn.clicked.connect(self.toggle_password_visibility)
        
        password_layout.addWidget(password_icon)
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.toggle_password_btn)
        form_layout.addWidget(password_container)
        
        form_layout.addSpacing(8)
        
        # Forgot password link (aligned right)
        forgot_password_btn = QPushButton("Forgot Password?")
        forgot_password_btn.setObjectName("forgotPassword")
        forgot_password_btn.setCursor(Qt.PointingHandCursor)
        forgot_password_btn.clicked.connect(self.handle_forgot_password)
        forgot_layout = QHBoxLayout()
        forgot_layout.addStretch()
        forgot_layout.addWidget(forgot_password_btn)
        form_layout.addLayout(forgot_layout)
        
        form_layout.addSpacing(8)
        
        # Remember me checkbox
        self.remember_me_checkbox = QCheckBox("Remember identity")
        self.remember_me_checkbox.setStyleSheet("""
            QCheckBox {
                color: #aaa;
                font-size: 13px;
                spacing: 8px;
                background-color: transparent;
                border: none;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #444;
                border-radius: 4px;
                background-color: rgba(255, 255, 255, 0.05);
            }
            QCheckBox::indicator:checked {
                background-color: #00f3ff;
                border-color: #00f3ff;
            }
            QCheckBox::indicator:hover {
                border-color: #00f3ff;
            }
        """)
        form_layout.addWidget(self.remember_me_checkbox)
        
        form_layout.addSpacing(24)
        
        # Login button
        self.login_btn = QPushButton("AUTHENTICATE")
        self.login_btn.setObjectName("loginButton")
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.setMinimumHeight(56)
        self.login_btn.clicked.connect(self.handle_login)
        form_layout.addWidget(self.login_btn)
        
        layout.addWidget(form_widget)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #ff003c; background-color: transparent; border: none; font-size: 13px; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # Add content to center
        center_layout.addWidget(content_widget)
        
        # Set main layout
        main_layout.addWidget(center_widget)
        
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(main_widget)
        self.setLayout(outer_layout)
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.toggle_password_btn.setIcon(get_icon('eye-slash', '#666'))
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.toggle_password_btn.setIcon(get_icon('eye', '#666'))
    
    def handle_forgot_password(self):
        """Handle forgot password request"""
        QMessageBox.information(
            self,
            "Password Recovery",
            "Password recovery feature is not available in this version.\n\n"
            "Please contact your system administrator or create a new account."
        )
    
    def handle_login(self):
        """Handle login attempt"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.show_error("Please enter username and password")
            return
        
        # Attempt login
        if auth_manager.login(username, password):
            self.status_label.setText("ACCESS GRANTED")
            self.status_label.setStyleSheet("color: #0aff0a; font-weight: bold;")
            
            # Save credentials if remember me is checked
            if self.remember_me_checkbox.isChecked():
                self.save_credentials(username)
            else:
                self.clear_saved_credentials()
            
            self.login_successful.emit(username)
        else:
            self.show_error("ACCESS DENIED: Invalid credentials")
    
    def handle_register(self):
        """Handle registration"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.show_error("Please enter username and password")
            return
        
        # Check if users already exist
        if auth_manager.has_users():
            reply = QMessageBox.question(
                self,
                "Create Account",
                "An account already exists. Only one master account is allowed. Continue?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        # Attempt registration
        if auth_manager.register_user(username, password):
            QMessageBox.information(
                self,
                "Success",
                "Account created successfully! Please login."
            )
            self.status_label.setText("")
        else:
            self.show_error("Registration failed. Password may be too weak.")
    
    def show_error(self, message: str):
        """Display error message"""
        self.status_label.setText(f"{get_icon('error')} {message}")
        self.status_label.setObjectName("errorLabel")
        self.status_label.setStyleSheet("color: #ff003c; font-weight: bold;")
    
    def clear_inputs(self):
        """Clear input fields"""
        self.username_input.clear()
        self.password_input.clear()
        self.status_label.clear()
    
    def save_credentials(self, username: str):
        """Save username to encrypted file for remember me feature"""
        try:
            from security.encryption import encryption_manager
            
            # Ensure data directory exists
            data_dir = os.path.dirname(self.credentials_file)
            os.makedirs(data_dir, exist_ok=True)
            
            # Encrypt username with a static key derived from machine ID
            # This is for convenience, not high security (username is not highly sensitive)
            machine_key = self.get_machine_key()
            encrypted_username = encryption_manager.encrypt(username, machine_key)
            
            # Save encrypted username
            with open(self.credentials_file, 'w') as f:
                json.dump({'username': encrypted_username}, f)
                
        except Exception as e:
            print(f"Error saving credentials: {e}")
    
    def load_saved_credentials(self):
        """Load saved username if remember me was previously enabled"""
        try:
            if not os.path.exists(self.credentials_file):
                return
            
            from security.encryption import encryption_manager
            
            # Load encrypted username
            with open(self.credentials_file, 'r') as f:
                data = json.load(f)
            
            # Decrypt username
            machine_key = self.get_machine_key()
            username = encryption_manager.decrypt(data['username'], machine_key)
            
            # Populate username field and check remember me
            if username:
                self.username_input.setText(username)
                self.remember_me_checkbox.setChecked(True)
                self.password_input.setFocus()  # Focus on password for convenience
                
        except Exception as e:
            print(f"Error loading credentials: {e}")
    
    def clear_saved_credentials(self):
        """Clear saved credentials when remember me is unchecked"""
        try:
            if os.path.exists(self.credentials_file):
                os.remove(self.credentials_file)
        except Exception as e:
            print(f"Error clearing credentials: {e}")
    
    def get_machine_key(self) -> bytes:
        """Generate a machine-specific key for credential encryption"""
        import hashlib
        import platform
        
        # Use machine-specific information to generate a key
        machine_info = f"{platform.node()}-{platform.system()}-CyberGuardPro"
        return hashlib.sha256(machine_info.encode()).digest()
