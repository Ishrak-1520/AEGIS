"""
Dashboard Window
Main application interface with all security features
"""

import os
import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTabWidget, QTextEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QProgressBar, QMessageBox, QFileDialog, QLineEdit,
    QComboBox, QSpinBox, QCheckBox, QDialog, QFormLayout, QDialogButtonBox,
    QScrollArea, QFrame, QStackedWidget, QListWidget, QListWidgetItem, QSplitter,
    QHeaderView
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QFont, QColor
import qtawesome as qta
from gui.styles import MAIN_STYLESHEET, HEADER_STYLESHEET, LOGOUT_BUTTON_STYLESHEET, COLORS, get_color, get_icon

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.monitor import system_monitor
from core.scanner import FileScanner
from core.quarantine import quarantine_manager
from security.password_manager import password_manager
try:
    from ai.nlp_model import get_nlp_detector
    from ai.explainable_ai import explainable_ai
    NLP_AVAILABLE = True
except (ImportError, AttributeError):
    NLP_AVAILABLE = False
from database.db_manager import db_manager
try:
    from core.realtime_protection import realtime_protection
    from gui.popup_alerts import show_realtime_threat_alert, show_compact_threat_notification
    RTP_AVAILABLE = True
except ImportError:
    RTP_AVAILABLE = False


class ScanWorker(QThread):
    """Background worker thread for file scanning to prevent GUI freezing"""
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(dict)
    file_update = pyqtSignal(str, int)
    
    def __init__(self, scanner, scan_type, directory=None):
        super().__init__()
        self.scanner = scanner
        self.scan_type = scan_type
        self.directory = directory
        self.files_scanned = 0
    
    def progress_callback(self, progress_percent, current_file, result):
        """Callback for scan progress updates"""
        self.files_scanned += 1
        self.progress.emit(int(progress_percent))
        self.status.emit(f"Scanning: {os.path.basename(current_file)} ({self.files_scanned} files)")
    
    def run(self):
        """Run scan in background thread"""
        try:
            if self.scan_type == 'quick':
                self.status.emit("Starting quick scan...")
                result = self.scanner.quick_scan(progress_callback=self.progress_callback)
                self.finished.emit(result)
            elif self.scan_type == 'full':
                home_dir = os.path.expanduser("~")
                self.status.emit(f"Starting full scan of {home_dir}...")
                result = self.scanner.scan_directory(
                    home_dir, 
                    recursive=True,
                    progress_callback=self.progress_callback
                )
                self.finished.emit(result)
            elif self.scan_type == 'custom' and self.directory:
                self.status.emit(f"Starting custom scan of {self.directory}...")
                result = self.scanner.scan_directory(
                    self.directory,
                    recursive=True,
                    progress_callback=self.progress_callback
                )
                self.finished.emit(result)
        except Exception as e:
            self.status.emit(f"Scan error: {str(e)}")
            self.finished.emit({
                'files_scanned': self.files_scanned,
                'threats_found': 0,
                'errors': 1,
                'error_message': str(e)
            })


class Dashboard(QMainWindow):
    """
    Main dashboard window with tabs for all features
    """
    
    # Signal for threat alerts (emitted from background thread)
    threat_detected_signal = pyqtSignal(dict)
    
    def __init__(self, username: str):
        super().__init__()
        self.username = username
        
        # Initialize scanner and monitor before UI
        self.file_scanner = FileScanner()
        self.scan_worker = None  # Track active scan worker
        
        # Initialize password_table to None (will be created in view)
        self.password_table = None
        
        # Real-Time Protection
        self.rtp_active = False
        if RTP_AVAILABLE:
            realtime_protection.register_threat_callback(self._on_realtime_threat_detected)
        
        # Connect the signal to the slot
        self.threat_detected_signal.connect(self._show_threat_alert_dialog)
        
        self.init_ui()
        self.start_monitoring()
    
    def init_ui(self):
        """Initialize user interface with modern sidebar design"""
        self.setWindowTitle(f"CyberGuard Pro - Welcome {self.username}")
        self.setStyleSheet(MAIN_STYLESHEET)
        self.setMinimumSize(1200, 800)
        
        # Main widget with horizontal layout (sidebar + content)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Main layout (horizontal for sidebar + main content)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)
        
        # Create main content area with stacked widget for different views
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("""
            QStackedWidget {
                background-color: #101922;
                border: none;
            }
        """)
        
        # Add different views to stack
        self.content_stack.addWidget(self.create_dashboard_view())  # 0: Dashboard
        self.content_stack.addWidget(self.create_scanner_tab())     # 1: Scanner
        self.content_stack.addWidget(self.create_password_view())   # 2: Password Manager
        self.content_stack.addWidget(self.create_nlp_view())        # 3: NLP Analyzer
        self.content_stack.addWidget(self.create_quarantine_view()) # 4: Quarantine
        self.content_stack.addWidget(self.create_reports_view())    # 5: Reports
        self.content_stack.addWidget(self.create_settings_view())   # 6: Settings
        
        main_layout.addWidget(self.content_stack)
        
        main_widget.setLayout(main_layout)
    
    def create_sidebar(self) -> QWidget:
        """Create modern sidebar with Neon Cyber navigation"""
        sidebar = QWidget()
        sidebar.setFixedWidth(260)
        sidebar.setStyleSheet(f"""
            QWidget {{
                background-color: {COLORS['background_dark']};
                color: {COLORS['text_primary']};
                font-family: 'Segoe UI', 'Roboto', sans-serif;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 24, 20, 24)
        layout.setSpacing(20)
        
        # App Logo/Title
        logo_container = QWidget()
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        logo_layout.setSpacing(4)
        
        title_label = QLabel("CYBERGUARD")
        title_label.setStyleSheet(f"""
            font-size: 20px;
            font-weight: 900;
            color: {COLORS['primary']};
            letter-spacing: 2px;
        """)
        logo_layout.addWidget(title_label)
        
        subtitle_label = QLabel("PRO")
        subtitle_label.setStyleSheet(f"""
            font-size: 14px;
            font-weight: 700;
            color: {COLORS['text_secondary']};
            letter-spacing: 3px;
        """)
        logo_layout.addWidget(subtitle_label)
        
        layout.addWidget(logo_container)
        layout.addSpacing(20)
        
        # Navigation Buttons
        self.nav_buttons = []
        nav_items = [
            ("home", "DASHBOARD", 0),
            ("scan", "SCANNER", 1),
            ("password", "PASSWORDS", 2),
            ("analyzer", "AI ANALYZER", 3),
            ("quarantine", "QUARANTINE", 4),
            ("logs", "REPORTS", 5),
            ("settings", "SETTINGS", 6)
        ]
        
        for icon_name, text, index in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setIcon(get_icon(icon_name, COLORS['text_secondary']))
            btn.setIconSize(qta.icon('fa5s.home').actualSize(QSize(20, 20))) # Dummy call to get size
            btn.setIconSize(QSize(20, 20))
            btn.setFixedHeight(48)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked, idx=index: self.switch_view(idx))
            
            if index == 0:  # Dashboard is active by default
                btn.setIcon(get_icon(icon_name, COLORS['primary']))
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0, 243, 255, 0.1);
                        color: {COLORS['primary']};
                        border: 1px solid {COLORS['primary']};
                        border-radius: 6px;
                        padding: 8px 16px;
                        text-align: left;
                        font-size: 12px;
                        font-weight: 700;
                        letter-spacing: 1px;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: transparent;
                        color: {COLORS['text_secondary']};
                        border: 1px solid transparent;
                        border-radius: 6px;
                        padding: 8px 16px;
                        text-align: left;
                        font-size: 12px;
                        font-weight: 700;
                        letter-spacing: 1px;
                    }}
                    QPushButton:hover {{
                        background-color: rgba(0, 243, 255, 0.05);
                        color: {COLORS['primary']};
                        border: 1px solid rgba(0, 243, 255, 0.3);
                    }}
                """)
            
            layout.addWidget(btn)
            self.nav_buttons.append(btn)
        
        layout.addStretch()
        
        # User Profile Card
        profile_card = QFrame()
        profile_card.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(20, 20, 20, 0.6);
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        profile_layout = QHBoxLayout(profile_card)
        profile_layout.setContentsMargins(8, 8, 8, 8)
        profile_layout.setSpacing(10)
        
        avatar = QLabel()
        avatar.setPixmap(get_icon('user', COLORS['text_primary']).pixmap(24, 24))
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet(f"""
            background-color: {COLORS['surface']};
            border-radius: 18px;
            padding: 6px;
        """)
        profile_layout.addWidget(avatar)
        
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        
        name_lbl = QLabel(self.username)
        name_lbl.setStyleSheet(f"font-weight: 700; color: {COLORS['text_primary']}; font-size: 11px;")
        user_info_layout.addWidget(name_lbl)
        
        role_lbl = QLabel("ADMIN")
        role_lbl.setStyleSheet(f"color: {COLORS['primary']}; font-size: 9px; font-weight: 700; letter-spacing: 1px;")
        user_info_layout.addWidget(role_lbl)
        
        profile_layout.addLayout(user_info_layout)
        layout.addWidget(profile_card)
        
        # Logout Button
        logout_btn = QPushButton("  LOGOUT")
        logout_btn.setIcon(get_icon('logout', COLORS['critical']))
        logout_btn.setIconSize(QSize(16, 16))
        logout_btn.setCursor(Qt.PointingHandCursor)
        logout_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(255, 0, 60, 0.1);
                color: {COLORS['critical']};
                border: 1px solid {COLORS['critical']};
                border-radius: 6px;
                height: 42px;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['critical']};
                color: #ffffff;
            }}
        """)
        logout_btn.clicked.connect(self.handle_logout)
        layout.addWidget(logout_btn)
        
        sidebar.setLayout(layout)
        return sidebar
    
    def switch_view(self, index: int):
        """Switch between different views"""
        self.content_stack.setCurrentIndex(index)
        
        # Update button styles
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: rgba(0, 243, 255, 0.1);
                        color: {COLORS['primary']};
                        border: 1px solid {COLORS['primary']};
                        border-radius: 6px;
                        padding: 8px 16px;
                        text-align: left;
                        font-size: 12px;
                        font-weight: 700;
                        letter-spacing: 1px;
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: transparent;
                        color: {COLORS['text_secondary']};
                        border: 1px solid transparent;
                        border-radius: 6px;
                        padding: 8px 16px;
                        text-align: left;
                        font-size: 12px;
                        font-weight: 700;
                        letter-spacing: 1px;
                    }}
                    QPushButton:hover {{
                        background-color: rgba(0, 243, 255, 0.05);
                        color: {COLORS['primary']};
                        border: 1px solid rgba(0, 243, 255, 0.3);
                    }}
                """)
    
    def create_dashboard_view(self) -> QWidget:
        """Create main dashboard view with Neon Cyber theme"""
        view = QWidget()
        view.setStyleSheet(f"background-color: {COLORS['background_light']};")
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background-color: {COLORS['background_light']};
            }}
            QScrollBar:vertical {{
                background-color: {COLORS['background_dark']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['border']};
                border-radius: 5px;
            }}
        """)
        
        content = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)
        
        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(8)
        
        page_title = QLabel("DASHBOARD")
        page_title.setStyleSheet(f"""
            font-size: 36px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        header_layout.addWidget(page_title)
        
        page_subtitle = QLabel(f"Welcome back, {self.username.upper()}! Your system is currently protected.")
        page_subtitle.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['text_secondary']};
            letter-spacing: 1px;
        """)
        header_layout.addWidget(page_subtitle)
        
        layout.addLayout(header_layout)
        
        # Statistics cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        # Create stat cards
        stat_cards = [
            ("THREATS BLOCKED", "0", COLORS['safe']),
            ("FILES SCANNED", "12,450", COLORS['primary']),
            ("VULNERABILITIES", "3", COLORS['medium']),
            ("SECURITY SCORE", "98%", COLORS['safe'])
        ]
        
        for title, value, color in stat_cards:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(20, 20, 20, 0.6);
                    border: 1px solid {COLORS['border']};
                    border-radius: 12px;
                }}
                QFrame:hover {{
                    border: 1px solid {color};
                }}
            """)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(24, 24, 24, 24)
            card_layout.setSpacing(8)
            
            card_title = QLabel(title)
            card_title.setStyleSheet(f"""
                font-size: 11px;
                font-weight: 700;
                color: {COLORS['text_secondary']};
                letter-spacing: 1px;
            """)
            card_layout.addWidget(card_title)
            
            card_value = QLabel(value)
            card_value.setStyleSheet(f"""
                font-size: 32px;
                font-weight: 900;
                color: {color};
            """)
            card_layout.addWidget(card_value)
            
            stats_layout.addWidget(card)
        
        layout.addLayout(stats_layout)
        
        # Quick Actions Section
        actions_section = QFrame()
        actions_section.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(20, 20, 20, 0.6);
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
            }}
        """)
        actions_layout = QVBoxLayout(actions_section)
        actions_layout.setContentsMargins(24, 24, 24, 24)
        actions_layout.setSpacing(16)
        
        actions_title = QLabel("QUICK ACTIONS")
        actions_title.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        actions_layout.addWidget(actions_title)
        
        # Action buttons
        actions_btns_layout = QHBoxLayout()
        actions_btns_layout.setSpacing(16)
        
        scan_btn = QPushButton("  RUN FULL SCAN")
        scan_btn.setIcon(get_icon('scan', '#000000'))
        scan_btn.setIconSize(QSize(18, 18))
        scan_btn.setFixedHeight(50)
        scan_btn.setCursor(Qt.PointingHandCursor)
        scan_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['primary']};
                color: #000000;
                border: none;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 900;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background-color: #33f6ff;
            }}
        """)
        scan_btn.clicked.connect(lambda: self.switch_view(1))
        actions_btns_layout.addWidget(scan_btn)
        
        passwords_btn = QPushButton("  MANAGE PASSWORDS")
        passwords_btn.setIcon(get_icon('password', COLORS['primary']))
        passwords_btn.setIconSize(QSize(18, 18))
        passwords_btn.setFixedHeight(50)
        passwords_btn.setCursor(Qt.PointingHandCursor)
        passwords_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 243, 255, 0.1);
                color: {COLORS['primary']};
                border: 1px solid {COLORS['primary']};
                border-radius: 6px;
                font-size: 13px;
                font-weight: 900;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background-color: rgba(0, 243, 255, 0.2);
            }}
        """)
        passwords_btn.clicked.connect(lambda: self.switch_view(2))
        actions_btns_layout.addWidget(passwords_btn)
        
        nlp_btn = QPushButton("  AI ANALYZER")
        nlp_btn.setIcon(get_icon('analyzer', COLORS['primary']))
        nlp_btn.setIconSize(QSize(18, 18))
        nlp_btn.setFixedHeight(50)
        nlp_btn.setCursor(Qt.PointingHandCursor)
        nlp_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 243, 255, 0.1);
                color: {COLORS['primary']};
                border: 1px solid {COLORS['primary']};
                border-radius: 6px;
                font-size: 13px;
                font-weight: 900;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background-color: rgba(0, 243, 255, 0.2);
            }}
        """)
        nlp_btn.clicked.connect(lambda: self.switch_view(3))
        actions_btns_layout.addWidget(nlp_btn)
        
        actions_layout.addLayout(actions_btns_layout)
        layout.addWidget(actions_section)
        
        # System Monitor Section (Fixing the bug)
        monitor_section = QFrame()
        monitor_section.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(20, 20, 20, 0.6);
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
            }}
        """)
        monitor_layout = QVBoxLayout(monitor_section)
        monitor_layout.setContentsMargins(24, 24, 24, 24)
        monitor_layout.setSpacing(16)
        
        monitor_title = QLabel("SYSTEM MONITOR")
        monitor_title.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        monitor_layout.addWidget(monitor_title)
        
        self.monitor_display = QLabel("Initializing system monitor...")
        self.monitor_display.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['primary']};
            font-family: 'Consolas', 'Courier New', monospace;
        """)
        monitor_layout.addWidget(self.monitor_display)
        
        layout.addWidget(monitor_section)
        
        # Real-Time Protection Section
        if RTP_AVAILABLE:
            rtp_section = QFrame()
            rtp_section.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(20, 20, 20, 0.6);
                    border: 1px solid {COLORS['border']};
                    border-radius: 12px;
                }}
            """)
            rtp_layout = QVBoxLayout(rtp_section)
            rtp_layout.setContentsMargins(24, 24, 24, 24)
            rtp_layout.setSpacing(16)
            
            # Title
            rtp_title = QLabel("REAL-TIME PROTECTION")
            rtp_title.setStyleSheet(f"""
                font-size: 16px;
                font-weight: 900;
                color: {COLORS['text_primary']};
                letter-spacing: 2px;
            """)
            rtp_layout.addWidget(rtp_title)
            
            # Description
            rtp_desc = QLabel("Monitor your screen in real-time for phishing, malware, and cyber threats")
            rtp_desc.setStyleSheet(f"""
                font-size: 13px;
                color: {COLORS['text_secondary']};
                margin-bottom: 8px;
            """)
            rtp_desc.setWordWrap(True)
            rtp_layout.addWidget(rtp_desc)
            
            # Status and Control
            rtp_control_layout = QHBoxLayout()
            rtp_control_layout.setSpacing(16)
            
            # Status label
            self.rtp_status_label = QLabel("Inactive")
            self.rtp_status_label.setStyleSheet(f"""
                font-size: 14px;
                font-weight: 700;
                color: {COLORS['critical']};
                padding: 8px 16px;
                background-color: rgba(239, 68, 68, 0.1);
                border-radius: 6px;
                border: 1px solid {COLORS['critical']};
            """)
            rtp_control_layout.addWidget(self.rtp_status_label)
            
            rtp_control_layout.addStretch()
            
            # Toggle button
            self.rtp_toggle_btn = QPushButton("  START PROTECTION")
            self.rtp_toggle_btn.setIcon(get_icon('play', '#000000'))
            self.rtp_toggle_btn.setIconSize(QSize(18, 18))
            self.rtp_toggle_btn.setFixedHeight(50)
            self.rtp_toggle_btn.setCursor(Qt.PointingHandCursor)
            self.rtp_toggle_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['primary']};
                    color: #000000;
                    border: none;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 900;
                    letter-spacing: 1px;
                    padding: 0 24px;
                }}
                QPushButton:hover {{
                    background-color: #33f6ff;
                }}
            """)
            self.rtp_toggle_btn.clicked.connect(self.toggle_realtime_protection)
            rtp_control_layout.addWidget(self.rtp_toggle_btn)
            
            rtp_layout.addLayout(rtp_control_layout)
            
            # Statistics
            self.rtp_stats_label = QLabel("Scans: 0 | Threats Detected: 0")
            self.rtp_stats_label.setStyleSheet(f"""
                font-size: 12px;
                color: {COLORS['text_secondary']};
                margin-top: 4px;
            """)
            rtp_layout.addWidget(self.rtp_stats_label)
            
            # Configure button
            rtp_config_btn = QPushButton("  CONFIGURE SETTINGS")
            rtp_config_btn.setIcon(get_icon('settings', COLORS['primary']))
            rtp_config_btn.setIconSize(QSize(16, 16))
            rtp_config_btn.setFixedHeight(42)
            rtp_config_btn.setCursor(Qt.PointingHandCursor)
            rtp_config_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: rgba(0, 243, 255, 0.1);
                    color: {COLORS['primary']};
                    border: 1px solid {COLORS['primary']};
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 700;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    background-color: rgba(0, 243, 255, 0.2);
                }}
            """)
            rtp_config_btn.clicked.connect(self.configure_realtime_protection)
            rtp_layout.addWidget(rtp_config_btn)
            
            layout.addWidget(rtp_section)
        
        # Real-time threat feed
        threat_feed = self.create_threat_feed()
        layout.addWidget(threat_feed)
        
        # Recent Activity Section
        activity_section = QFrame()
        activity_section.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(20, 20, 20, 0.6);
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
            }}
        """)
        activity_layout = QVBoxLayout(activity_section)
        activity_layout.setContentsMargins(24, 24, 24, 24)
        activity_layout.setSpacing(16)
        
        activity_title = QLabel("RECENT ACTIVITY")
        activity_title.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        activity_layout.addWidget(activity_title)
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(150)
        self.activity_log.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background_dark']};
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }}
        """)
        activity_layout.addWidget(self.activity_log)
        
        layout.addWidget(activity_section)
        
        content.setLayout(layout)
        scroll.setWidget(content)
        
        view_layout = QVBoxLayout()
        view_layout.setContentsMargins(0, 0, 0, 0)
        view_layout.addWidget(scroll)
        view.setLayout(view_layout)
        
        return view
    
    def create_stat_card(self, title: str, value: str, period: str, change: str, change_color: str) -> QFrame:
        """Create a statistics card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border: 1px solid #324d67;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        card_title = QLabel(title)
        card_title.setStyleSheet("""
            font-size: 16px;
            font-weight: 500;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        layout.addWidget(card_title)
        
        card_value = QLabel(value)
        card_value.setStyleSheet("""
            font-size: 32px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        layout.addWidget(card_value)
        
        # Period and change
        info_layout = QHBoxLayout()
        
        card_period = QLabel(period)
        card_period.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        info_layout.addWidget(card_period)
        
        card_change = QLabel(change)
        card_change.setStyleSheet(f"""
            font-size: 14px;
            font-weight: 500;
            color: {change_color};
            font-family: 'Space Grotesk', sans-serif;
        """)
        info_layout.addWidget(card_change)
        info_layout.addStretch()
        
        layout.addLayout(info_layout)
        card.setLayout(layout)
        
        return card
    
    def create_threat_feed(self) -> QFrame:
        """Create real-time threat feed widget"""
        feed = QFrame()
        feed.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(20, 20, 20, 0.6);
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header
        header_layout = QHBoxLayout()
        
        feed_title = QLabel("REAL-TIME THREAT FEED")
        feed_title.setStyleSheet(f"""
            font-size: 16px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        header_layout.addWidget(feed_title)
        header_layout.addStretch()
        
        view_all_btn = QPushButton("VIEW ALL")
        view_all_btn.setCursor(Qt.PointingHandCursor)
        view_all_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLORS['primary']};
                border: none;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                color: #33f6ff;
            }}
        """)
        header_layout.addWidget(view_all_btn)
        
        layout.addLayout(header_layout)
        
        # Threat items (sample data - will be replaced with real data)
        threats = [
            ("exclamation-triangle", "Phishing Attempt Blocked", "Suspicious phishing site detected and blocked", "2 MINS AGO", COLORS['critical']),
            ("bug", "Malware Signature Found", "Potential malware detected in downloaded file", "1 HOUR AGO", COLORS['high']),
            ("shield", "Real-Time Protection Active", "System monitoring for threats continuously", "4 MINUTES AGO", COLORS['safe'])
        ]
        
        for icon, title, desc, time, color in threats:
            item = self.create_threat_item(icon, title, desc, time, color)
            layout.addWidget(item)
        
        feed.setLayout(layout)
        return feed
    
    def create_threat_item(self, icon_name: str, title: str, description: str, time: str, color: str) -> QFrame:
        """Create a threat feed item"""
        item = QFrame()
        item.setFixedHeight(72)
        item.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 8px;
            }
            QFrame:hover {
                background-color: rgba(35, 54, 72, 0.5);
            }
        """)
        
        layout = QHBoxLayout()
        layout.setSpacing(16)
        
        # Icon
        icon_label = QLabel()
        icon_label.setPixmap(get_icon(icon_name, color).pixmap(24, 24))
        icon_label.setFixedSize(48, 48)
        icon_label.setStyleSheet(f"""
            QLabel {{
                background-color: #233648;
                border-radius: 8px;
                qproperty-alignment: AlignCenter;
            }}
        """)
        layout.addWidget(icon_label)
        
        # Content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)
        
        item_title = QLabel(title)
        item_title.setStyleSheet("""
            font-size: 16px;
            font-weight: 500;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        content_layout.addWidget(item_title)
        
        item_desc = QLabel(description)
        item_desc.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        content_layout.addWidget(item_desc)
        
        layout.addLayout(content_layout)
        layout.addStretch()
        
        # Time
        time_label = QLabel(time)
        time_label.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        layout.addWidget(time_label)
        
        item.setLayout(layout)
        return item
    
    def create_password_view(self) -> QWidget:
        """Create password manager view matching HTML template"""
        view = QWidget()
        view.setStyleSheet("background-color: #101922;")
        
        # Main horizontal layout (sidebar + content)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Left sidebar for password categories
        sidebar = QFrame()
        sidebar.setFixedWidth(256)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #192633;
                border-right: 1px solid #324d67;
            }
        """)
        
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(16, 16, 16, 16)
        sidebar_layout.setSpacing(16)
        
        # Sidebar header
        header_layout = QHBoxLayout()
        shield_icon = QLabel()
        shield_icon.setPixmap(get_icon('shield', '#36B8A5').pixmap(24, 24))
        shield_icon.setStyleSheet("qproperty-alignment: AlignCenter;")
        header_layout.addWidget(shield_icon)
        
        header_title = QLabel("CyberSecure")
        header_title.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        header_layout.addWidget(header_title)
        sidebar_layout.addLayout(header_layout)
        
        # User info
        user_widget = QWidget()
        user_layout = QHBoxLayout()
        user_layout.setSpacing(12)
        
        user_avatar = QLabel()
        user_avatar.setPixmap(get_icon('user', COLORS['text_primary']).pixmap(24, 24))
        user_avatar.setAlignment(Qt.AlignCenter)
        user_avatar.setStyleSheet("""
            QLabel {
                background-color: #233648;
                border-radius: 20px;
                padding: 6px;
            }
        """)
        user_layout.addWidget(user_avatar)
        
        user_info = QWidget()
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        user_info_layout.setContentsMargins(0, 0, 0, 0)
        
        user_name = QLabel(self.username)
        user_name.setStyleSheet("font-size: 14px; font-weight: 500; color: #ffffff;")
        user_info_layout.addWidget(user_name)
        
        user_email = QLabel(f"{self.username}@email.com")
        user_email.setStyleSheet("font-size: 12px; color: #92adc9;")
        user_info_layout.addWidget(user_email)
        
        user_info.setLayout(user_info_layout)
        user_layout.addWidget(user_info)
        
        user_widget.setLayout(user_layout)
        sidebar_layout.addWidget(user_widget)
        
        # Category navigation
        categories = [
            ("lock", "Logins", True),
            ("credit-card", "Credit Cards", False),
            ("file-alt", "Secure Notes", False),
            ("user", "Identities", False),
            ("key", "Password Generator", False),
            ("heart", "Security Health", False)
        ]
        
        for icon_name, text, active in categories:
            btn = QPushButton(f"  {text}")
            btn.setIcon(get_icon(icon_name, '#ffffff'))
            btn.setIconSize(QSize(16, 16))
            btn.setFixedHeight(40)
            if active:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #233648;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                        font-weight: 500;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: rgba(54, 184, 165, 0.2);
                    }
                """)
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()
        
        # Security badge
        security_badge = QFrame()
        security_badge.setStyleSheet("""
            QFrame {
                background-color: #233648;
                border-radius: 8px;
                padding: 16px;
            }
        """)
        
        badge_layout = QVBoxLayout()
        badge_layout.setSpacing(8)
        
        badge_icon = QLabel()
        badge_icon.setPixmap(get_icon('check', '#36B8A5').pixmap(32, 32))
        badge_icon.setAlignment(Qt.AlignCenter)
        badge_layout.addWidget(badge_icon)
        
        badge_title = QLabel("All Secure")
        badge_title.setStyleSheet("""
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
            qproperty-alignment: AlignCenter;
        """)
        badge_layout.addWidget(badge_title)
        
        badge_desc = QLabel("No weak passwords")
        badge_desc.setStyleSheet("""
            font-size: 12px;
            color: #92adc9;
            qproperty-alignment: AlignCenter;
        """)
        badge_layout.addWidget(badge_desc)
        
        security_badge.setLayout(badge_layout)
        sidebar_layout.addWidget(security_badge)
        
        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)
        
        # Main content area
        content_widget = QWidget()
        content_main_layout = QVBoxLayout()
        content_main_layout.setContentsMargins(0, 0, 0, 0)
        content_main_layout.setSpacing(0)
        
        # Header bar
        header_bar = QFrame()
        header_bar.setFixedHeight(72)
        header_bar.setStyleSheet("""
            QFrame {
                background-color: #192633;
                border-bottom: 1px solid #324d67;
            }
        """)
        
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(24, 0, 24, 0)
        
        # Search bar
        search_widget = QWidget()
        search_layout = QHBoxLayout()
        search_layout.setContentsMargins(0, 0, 0, 0)
        search_layout.setSpacing(8)
        
        search_icon = QLabel()
        search_icon.setPixmap(get_icon('search', '#92adc9').pixmap(16, 16))
        search_icon.setFixedSize(16, 16)
        search_layout.addWidget(search_icon)
        
        search_input = QLineEdit()
        search_input.setPlaceholderText("Search passwords...")
        search_input.setStyleSheet("""
            QLineEdit {
                background-color: transparent;
                border: none;
                color: #ffffff;
                font-size: 14px;
                padding: 8px 0;
            }
        """)
        search_layout.addWidget(search_input)
        
        search_widget.setLayout(search_layout)
        header_layout.addWidget(search_widget, 1)
        
        # Add New button
        add_btn = QPushButton("  Add New")
        add_btn.setIcon(get_icon('plus', '#ffffff'))
        add_btn.setIconSize(QSize(16, 16))
        add_btn.setFixedHeight(40)
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #36B8A5;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #2a9985;
            }
        """)
        add_btn.clicked.connect(self.add_password)
        header_layout.addWidget(add_btn)
        
        header_bar.setLayout(header_layout)
        content_main_layout.addWidget(header_bar)
        
        # Main content with splitter (list + details)
        splitter = QSplitter(Qt.Horizontal)
        
        # Password list
        list_widget = QWidget()
        list_layout = QVBoxLayout()
        list_layout.setContentsMargins(16, 16, 8, 16)
        list_layout.setSpacing(8)
        
        self.password_list = QListWidget()
        self.password_list.setStyleSheet("""
            QListWidget {
                background-color: #101922;
                border: none;
                color: #ffffff;
            }
            QListWidget::item {
                background-color: transparent;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 8px;
            }
            QListWidget::item:selected {
                background-color: #233648;
            }
            QListWidget::item:hover {
                background-color: rgba(17, 115, 212, 0.2);
            }
        """)
        
        # Add sample password entries
        passwords = [
            ("Google", "john.doe@gmail.com", "2 days ago"),
            ("Facebook", "johndoe", "1 week ago"),
            ("Amazon", "john.d@email.com", "3 weeks ago"),
            ("Twitter", "j_doe", "1 month ago")
        ]
        
        for site, username, time in passwords:
            item = QListWidgetItem()
            item_widget = self.create_password_list_item(site, username, time)
            item.setSizeHint(item_widget.sizeHint())
            self.password_list.addItem(item)
            self.password_list.setItemWidget(item, item_widget)
        
        list_layout.addWidget(self.password_list)
        list_widget.setLayout(list_layout)
        splitter.addWidget(list_widget)
        
        # Password details panel
        details_widget = self.create_password_details_panel()
        splitter.addWidget(details_widget)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        content_main_layout.addWidget(splitter)
        content_widget.setLayout(content_main_layout)
        main_layout.addWidget(content_widget)
        
        view.setLayout(main_layout)
        return view
    
    def create_password_list_item(self, site: str, username: str, time: str) -> QWidget:
        """Create a password list item widget"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(4)
        layout.setContentsMargins(0, 0, 0, 0)
        
        header_layout = QHBoxLayout()
        
        site_label = QLabel(site)
        site_label.setStyleSheet("""
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        header_layout.addWidget(site_label)
        header_layout.addStretch()
        
        time_label = QLabel(time)
        time_label.setStyleSheet("""
            font-size: 12px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        header_layout.addWidget(time_label)
        
        layout.addLayout(header_layout)
        
        username_label = QLabel(username)
        username_label.setStyleSheet("""
            font-size: 14px;
            color: #b0c7e2;
            font-family: 'Space Grotesk', sans-serif;
        """)
        layout.addWidget(username_label)
        
        widget.setLayout(layout)
        return widget
    
    def create_password_details_panel(self) -> QWidget:
        """Create password details and generator panel"""
        panel = QWidget()
        panel_layout = QVBoxLayout()
        panel_layout.setContentsMargins(8, 16, 16, 16)
        panel_layout.setSpacing(24)
        
        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_layout.setSpacing(24)
        
        # Password details section
        details_header = QHBoxLayout()
        
        site_title = QLabel("Google")
        site_title.setStyleSheet(f"""
            font-size: 24px;
            font-weight: 700;
            color: {COLORS['text_primary']};
            font-family: 'Space Grotesk', sans-serif;
        """)
        details_header.addWidget(site_title)
        details_header.addStretch()
        
        edit_btn = QPushButton()
        edit_btn.setIcon(get_icon('edit', COLORS['primary']))
        edit_btn.setIconSize(QSize(18, 18))
        edit_btn.setFixedSize(36, 36)
        edit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border-radius: 0px;
                border: 1px solid {COLORS['primary']};
                color: {COLORS['primary']};
            }}
            QPushButton:hover {{
                background-color: rgba(0, 243, 255, 0.1);
                color: {COLORS['text_primary']};
            }}
        """)
        details_header.addWidget(edit_btn)
        
        delete_btn = QPushButton()
        delete_btn.setIcon(get_icon('trash', COLORS['critical']))
        delete_btn.setIconSize(QSize(18, 18))
        delete_btn.setFixedSize(36, 36)
        delete_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border-radius: 0px;
                border: 1px solid {COLORS['critical']};
                color: {COLORS['critical']};
            }}
            QPushButton:hover {{
                background-color: rgba(255, 0, 60, 0.2);
                color: {COLORS['text_primary']};
            }}
        """)
        details_header.addWidget(delete_btn)
        
        scroll_layout.addLayout(details_header)
        
        site_url = QLabel("https://www.google.com")
        site_url.setStyleSheet(f"""
            font-size: 14px;
            color: {COLORS['primary']};
            font-family: 'Space Grotesk', sans-serif;
        """)
        scroll_layout.addWidget(site_url)
        
        # Username field
        username_label = QLabel("Username")
        username_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_secondary']}; font-weight: 500;")
        scroll_layout.addWidget(username_label)
        
        username_field = QWidget()
        username_layout = QHBoxLayout()
        username_layout.setContentsMargins(0, 0, 0, 0)
        
        username_value = QLineEdit("john.doe@gmail.com")
        username_value.setReadOnly(True)
        username_value.setStyleSheet(f"""
            QLineEdit {{
                background-color: transparent;
                border: none;
                color: {COLORS['text_primary']};
                font-size: 14px;
                padding: 0;
            }}
        """)
        username_layout.addWidget(username_value)
        
        copy_username_btn = QPushButton()
        copy_username_btn.setIcon(get_icon('copy', COLORS['text_secondary']))
        copy_username_btn.setIconSize(QSize(16, 16))
        copy_username_btn.setFixedSize(32, 32)
        copy_username_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 0px;
            }
            QPushButton:hover {
                background-color: {COLORS['accent_dim']};
            }
        """)
        username_layout.addWidget(copy_username_btn)
        
        username_field.setLayout(username_layout)
        scroll_layout.addWidget(username_field)
        
        # Password field
        password_label = QLabel("Password")
        password_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_secondary']}; font-weight: 500;")
        scroll_layout.addWidget(password_label)
        
        password_field = QWidget()
        password_layout = QHBoxLayout()
        password_layout.setContentsMargins(0, 0, 0, 0)
        
        self.password_value = QLineEdit("SuperSecretPassword123")
        self.password_value.setEchoMode(QLineEdit.Password)
        self.password_value.setReadOnly(True)
        self.password_value.setStyleSheet("""
            QLineEdit {
                background-color: transparent;
                border: none;
                color: #ffffff;
                font-size: 14px;
                padding: 0;
            }
        """)
        password_layout.addWidget(self.password_value)
        
        toggle_password_btn = QPushButton()
        toggle_password_btn.setIcon(get_icon('eye', COLORS['text_secondary']))
        toggle_password_btn.setIconSize(QSize(16, 16))
        toggle_password_btn.setFixedSize(32, 32)
        toggle_password_btn.clicked.connect(lambda: self.toggle_password_field(self.password_value, toggle_password_btn))
        toggle_password_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 0px;
            }
            QPushButton:hover {
                background-color: {COLORS['accent_dim']};
            }
        """)
        password_layout.addWidget(toggle_password_btn)
        
        copy_password_btn = QPushButton()
        copy_password_btn.setIcon(get_icon('copy', COLORS['text_secondary']))
        copy_password_btn.setIconSize(QSize(16, 16))
        copy_password_btn.setFixedSize(32, 32)
        copy_password_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 16px;
            }
            QPushButton:hover {
                background-color: rgba(54, 184, 165, 0.2);
            }
        """)
        password_layout.addWidget(copy_password_btn)
        
        password_field.setLayout(password_layout)
        scroll_layout.addWidget(password_field)
        
        # Password strength
        scroll_layout.addSpacing(16)
        strength_header = QHBoxLayout()
        strength_label = QLabel("Password Strength")
        strength_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_secondary']}; font-weight: 500;")
        strength_header.addWidget(strength_label)
        
        strength_value = QLabel("Strong")
        strength_value.setStyleSheet(f"font-size: 12px; color: {COLORS['safe']}; font-weight: 700;")
        strength_header.addWidget(strength_value)
        strength_header.addStretch()
        scroll_layout.addLayout(strength_header)
        
        strength_bar = QProgressBar()
        strength_bar.setValue(90)
        strength_bar.setTextVisible(False)
        strength_bar.setFixedHeight(8)
        strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS['surface']};
                border-radius: 0px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['safe']};
                border-radius: 0px;
            }}
        """)
        scroll_layout.addWidget(strength_bar)
        
        # Strength criteria
        criteria = [
            ("check", "Includes uppercase and lowercase letters", COLORS['safe']),
            ("check", "Includes numbers", COLORS['safe']),
            ("check", "Is longer than 12 characters", COLORS['safe']),
            ("warning", "Consider adding a symbol (!@#$%)", COLORS['critical'])
        ]
        
        for icon_name, text, color in criteria:
            criterion_widget = QWidget()
            criterion_layout = QHBoxLayout(criterion_widget)
            criterion_layout.setContentsMargins(0, 0, 0, 0)
            criterion_layout.setSpacing(8)
            
            icon_label = QLabel()
            icon_label.setPixmap(get_icon(icon_name, color).pixmap(14, 14))
            icon_label.setFixedSize(16, 16)
            criterion_layout.addWidget(icon_label)
            
            text_label = QLabel(text)
            text_label.setStyleSheet(f"""
                font-size: 12px;
                color: {color};
                font-family: 'Space Grotesk', sans-serif;
            """)
            criterion_layout.addWidget(text_label)
            criterion_layout.addStretch()
            
            scroll_layout.addWidget(criterion_widget)
        
        scroll_layout.addStretch()
        scroll_content.setLayout(scroll_layout)
        scroll.setWidget(scroll_content)
        
        panel_layout.addWidget(scroll)
        
        # Password generator section (bottom panel)
        generator_panel = QFrame()
        generator_panel.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['background_dark']};
                border-top: 1px solid {COLORS['border']};
                padding: 24px;
            }}
        """)
        
        gen_layout = QVBoxLayout()
        gen_layout.setSpacing(16)
        
        gen_title = QLabel("Password Generator")
        gen_title.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        gen_layout.addWidget(gen_title)
        
        # Generated password display
        gen_password_container = QWidget()
        gen_password_layout = QHBoxLayout()
        gen_password_layout.setContentsMargins(0, 0, 0, 0)
        
        self.generated_password = QLineEdit("G3n3r@t3d_P@ssw0rd!_2024")
        self.generated_password.setReadOnly(True)
        self.generated_password.setFixedHeight(40)
        self.generated_password.setStyleSheet("""
            QLineEdit {
                background-color: #233648;
                border: none;
                border-radius: 8px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 14px;
            }
        """)
        gen_password_layout.addWidget(self.generated_password)
        
        refresh_btn = QPushButton()
        refresh_btn.setIcon(get_icon('refresh', '#ffffff'))
        refresh_btn.setIconSize(QSize(20, 20))
        refresh_btn.setFixedSize(40, 40)
        refresh_btn.clicked.connect(self.generate_password)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #233648;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #324d67;
            }
        """)
        gen_password_layout.addWidget(refresh_btn)
        
        gen_password_container.setLayout(gen_password_layout)
        gen_layout.addWidget(gen_password_container)
        
        # Generator options
        options_grid = QWidget()
        options_layout = QVBoxLayout()
        options_layout.setSpacing(12)
        
        # Length
        length_layout = QHBoxLayout()
        length_label = QLabel("Password Length")
        length_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        length_layout.addWidget(length_label)
        length_layout.addStretch()
        
        length_spin = QSpinBox()
        length_spin.setValue(16)
        length_spin.setRange(8, 32)
        length_spin.setFixedWidth(80)
        length_spin.setStyleSheet("""
            QSpinBox {
                background-color: #233648;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                color: #ffffff;
            }
        """)
        length_layout.addWidget(length_spin)
        options_layout.addLayout(length_layout)
        
        # Checkboxes
        checks = [
            ("Uppercase (A-Z)", True),
            ("Lowercase (a-z)", True),
            ("Numbers (0-9)", True),
            ("Symbols (!@#$%^&*)", True)
        ]
        
        for text, checked in checks:
            checkbox = QCheckBox(text)
            checkbox.setChecked(checked)
            checkbox.setStyleSheet("""
                QCheckBox {
                    color: #ffffff;
                    font-size: 14px;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                    border: 2px solid #334155;
                    border-radius: 4px;
                    background-color: #233648;
                }
                QCheckBox::indicator:checked {
                    background-color: #36B8A5;
                    border-color: #36B8A5;
                }
            """)
            options_layout.addWidget(checkbox)
        
        options_grid.setLayout(options_layout)
        gen_layout.addWidget(options_grid)
        
        # Action buttons
        gen_buttons = QHBoxLayout()
        gen_buttons.addStretch()
        
        copy_gen_btn = QPushButton("Copy Password")
        copy_gen_btn.setFixedHeight(40)
        copy_gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #233648;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #324d67;
            }
        """)
        gen_buttons.addWidget(copy_gen_btn)
        
        fill_save_btn = QPushButton("Fill & Save")
        fill_save_btn.setFixedHeight(40)
        fill_save_btn.setStyleSheet("""
            QPushButton {
                background-color: #36B8A5;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #2a9985;
            }
        """)
        gen_buttons.addWidget(fill_save_btn)
        
        gen_layout.addLayout(gen_buttons)
        
        generator_panel.setLayout(gen_layout)
        panel_layout.addWidget(generator_panel)
        
        panel.setLayout(panel_layout)
        return panel
    
    def toggle_password_field(self, field: QLineEdit, btn: QPushButton):
        """Toggle password visibility"""
        if field.echoMode() == QLineEdit.Password:
            field.setEchoMode(QLineEdit.Normal)
            btn.setIcon(get_icon('eye-slash', COLORS['text_secondary']))
        else:
            field.setEchoMode(QLineEdit.Password)
            btn.setIcon(get_icon('eye', COLORS['text_secondary']))
    
    def create_nlp_view(self) -> QWidget:
        """Create NLP threat analyzer view matching HTML template"""
        view = QWidget()
        view.setStyleSheet("background-color: #101922;")
        
        # Main horizontal layout (sidebar + content)
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(256)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                color: #ffffff;
            }
        """)
        
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(16, 16, 16, 16)
        sidebar_layout.setSpacing(24)
        
        # User profile
        profile_layout = QHBoxLayout()
        profile_layout.setSpacing(12)
        
        avatar = QLabel()
        avatar.setPixmap(get_icon('user', COLORS['text_primary']).pixmap(24, 24))
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet("""
            QLabel {
                background-color: #233648;
                border-radius: 20px;
                padding: 6px;
            }
        """)
        profile_layout.addWidget(avatar)
        
        user_info = QWidget()
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        user_info_layout.setContentsMargins(0, 0, 0, 0)
        
        user_name = QLabel(self.username)
        user_name.setStyleSheet("font-size: 14px; font-weight: 500; color: #ffffff;")
        user_info_layout.addWidget(user_name)
        
        user_email = QLabel(f"{self.username}@example.com")
        user_email.setStyleSheet("font-size: 12px; color: #92adc9;")
        user_info_layout.addWidget(user_email)
        
        user_info.setLayout(user_info_layout)
        profile_layout.addWidget(user_info)
        
        sidebar_layout.addLayout(profile_layout)
        
        # Navigation
        nav_items = [
            ("home", "Dashboard"),
            ("analyzer", "NLP Threat Analysis"),
            ("scan", "Scan"),
            ("settings", "Settings"),
            ("user", "Profile")
        ]
        
        for icon_name, text in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setIcon(get_icon(icon_name, '#ffffff'))
            btn.setIconSize(QSize(16, 16))
            btn.setFixedHeight(40)
            active = text == "NLP Threat Analysis"
            
            if active:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #233648;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                        font-weight: 500;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: #233648;
                    }
                """)
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()
        
        # Bottom buttons
        new_scan_btn = QPushButton("New Scan")
        new_scan_btn.setFixedHeight(40)
        new_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #1172d4;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #0d5cb5;
            }
        """)
        sidebar_layout.addWidget(new_scan_btn)
        
        help_btn = QPushButton("  Help")
        help_btn.setIcon(get_icon('info', '#ffffff'))
        help_btn.setIconSize(QSize(16, 16))
        help_btn.setFixedHeight(40)
        help_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 12px;
                text-align: left;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #233648;
            }
        """)
        sidebar_layout.addWidget(help_btn)
        
        logout_btn = QPushButton("  Logout")
        logout_btn.setIcon(get_icon('logout', '#ff003c'))
        logout_btn.setIconSize(QSize(16, 16))
        logout_btn.setFixedHeight(40)
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ff003c;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                text-align: left;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background-color: rgba(255, 0, 60, 0.1);
            }
        """)
        sidebar_layout.addWidget(logout_btn)
        
        sidebar.setLayout(sidebar_layout)
        main_layout.addWidget(sidebar)
        
        # Main content
        content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(32, 32, 32, 32)
        content_layout.setSpacing(24)
        
        # Header
        header = QLabel("NLP Threat Analysis")
        header.setStyleSheet("""
            font-size: 36px;
            font-weight: 900;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        content_layout.addWidget(header)
        
        # Two column layout
        columns = QHBoxLayout()
        columns.setSpacing(32)
        
        # Left column - Input
        left_col = QFrame()
        left_col.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        left_layout = QVBoxLayout()
        left_layout.setSpacing(16)
        
        input_title = QLabel("Content for Analysis")
        input_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        left_layout.addWidget(input_title)
        
        self.nlp_input = QTextEdit()
        self.nlp_input.setPlaceholderText("Paste email body, URL, or any text here...")
        self.nlp_input.setText("""Dear Customer,
We have detected unusual activity on your account. Please verify your identity by clicking the link below to avoid suspension.
http://your-bank-security-update.com/verify
Thank you,
Your Bank Security Team""")
        self.nlp_input.setStyleSheet("""
            QTextEdit {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                color: #ffffff;
                font-size: 14px;
                padding: 12px;
                font-family: 'Space Grotesk', sans-serif;
            }
            QTextEdit:focus {
                border: 2px solid #1172d4;
            }
        """)
        left_layout.addWidget(self.nlp_input)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        upload_btn = QPushButton("  Upload File")
        upload_btn.setIcon(get_icon('file', '#ffffff'))
        upload_btn.setIconSize(QSize(16, 16))
        upload_btn.setFixedHeight(40)
        upload_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: none;
                font-size: 14px;
                font-weight: 500;
            }
            QPushButton:hover {
                color: #1172d4;
            }
        """)
        action_layout.addWidget(upload_btn)
        
        url_btn = QPushButton("  Analyze URL")
        url_btn.setIcon(get_icon('link', '#ffffff'))
        url_btn.setIconSize(QSize(16, 16))
        url_btn.setFixedHeight(40)
        url_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: none;
                font-size: 14px;
                font-weight: 500;
            }
            QPushButton:hover {
                color: #1172d4;
            }
        """)
        action_layout.addWidget(url_btn)
        
        action_layout.addStretch()
        
        analyze_btn = QPushButton("Analyze")
        analyze_btn.setFixedHeight(48)
        analyze_btn.setFixedWidth(120)
        analyze_btn.clicked.connect(self.analyze_text)
        analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #39FF14;
                color: #000000;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 700;
                font-family: 'Space Grotesk', sans-serif;
            }
            QPushButton:hover {
                background-color: #2ee000;
            }
        """)
        action_layout.addWidget(analyze_btn)
        
        left_layout.addLayout(action_layout)
        left_col.setLayout(left_layout)
        columns.addWidget(left_col)
        
        # Right column - Results
        right_col = QFrame()
        right_col.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        right_layout = QVBoxLayout()
        right_layout.setSpacing(24)
        
        results_title = QLabel("FR-NLP-01: Algorithm Analysis")
        results_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        right_layout.addWidget(results_title)
        
        # Threat level indicator
        threat_level_label = QLabel("FR-NLP-04: Overall Threat Level")
        threat_level_label.setStyleSheet("""
            font-size: 16px;
            font-weight: 500;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        right_layout.addWidget(threat_level_label)
        
        # Threat level bar
        threat_bar = QFrame()
        threat_bar.setFixedHeight(40)
        threat_bar.setStyleSheet("""
            QFrame {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22C55E,
                    stop:0.25 #39FF14,
                    stop:0.5 #EAB308,
                    stop:0.75 #F97316,
                    stop:1 #EF4444
                );
                border-radius: 20px;
            }
        """)
        threat_bar_layout = QHBoxLayout()
        threat_bar_layout.setContentsMargins(8, 0, 8, 0)
        
        for label in ["Safe", "Low", "Medium", "High", "Critical"]:
            level_label = QLabel(label)
            level_label.setStyleSheet("""
                font-size: 12px;
                font-weight: 700;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            """)
            threat_bar_layout.addWidget(level_label)
        
        threat_bar.setLayout(threat_bar_layout)
        right_layout.addWidget(threat_bar)
        
        threat_result = QLabel("High")
        threat_result.setAlignment(Qt.AlignRight)
        threat_result.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #F97316;
            font-family: 'Space Grotesk', sans-serif;
        """)
        right_layout.addWidget(threat_result)
        
        # Detection results
        self.nlp_results = QWidget()
        results_layout = QVBoxLayout()
        results_layout.setSpacing(16)
        
        # Phishing patterns
        phishing_section = QLabel("FR-NLP-02: Phishing Patterns Detected")
        phishing_section.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        results_layout.addWidget(phishing_section)
        
        phishing_card = self.create_nlp_detection_card(
            "Suspicious Link",
            "URL mimics a known entity but is not official.",
            "High",
            "95%",
            "#F97316"
        )
        results_layout.addWidget(phishing_card)
        
        # Social engineering
        social_section = QLabel("FR-NLP-03: Social Engineering Attempts")
        social_section.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        results_layout.addWidget(social_section)
        
        urgency_card = self.create_nlp_detection_card(
            "Urgency & Threat",
            '"avoid suspension" creates a sense of urgency.',
            "Medium",
            "88%",
            "#EAB308"
        )
        results_layout.addWidget(urgency_card)
        
        impersonation_card = self.create_nlp_detection_card(
            "Impersonation",
            'Claims to be from "Your Bank Security Team".',
            "Low",
            "70%",
            "#39FF14"
        )
        results_layout.addWidget(impersonation_card)
        
        # Confidence score
        confidence_layout = QHBoxLayout()
        
        confidence_label = QLabel("FR-NLP-05: Overall Confidence Score")
        confidence_label.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        confidence_layout.addWidget(confidence_label)
        
        confidence_bar = QProgressBar()
        confidence_bar.setValue(92)
        confidence_bar.setTextVisible(False)
        confidence_bar.setFixedHeight(8)
        confidence_bar.setStyleSheet("""
            QProgressBar {
                background-color: #192633;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #1173d4;
                border-radius: 4px;
            }
        """)
        confidence_layout.addWidget(confidence_bar)
        
        confidence_value = QLabel("92%")
        confidence_value.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        confidence_layout.addWidget(confidence_value)
        
        results_layout.addLayout(confidence_layout)
        results_layout.addStretch()
        
        self.nlp_results.setLayout(results_layout)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.nlp_results)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        right_layout.addWidget(scroll)
        
        right_col.setLayout(right_layout)
        columns.addWidget(right_col)
        
        content_layout.addLayout(columns)
        content.setLayout(content_layout)
        main_layout.addWidget(content)
        
        view.setLayout(main_layout)
        return view
    
    def create_nlp_detection_card(self, title: str, description: str, severity: str, confidence: str, color: str) -> QFrame:
        """Create NLP detection result card"""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: #192633;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QHBoxLayout()
        
        # Content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        content_layout.addWidget(title_label)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        desc_label.setWordWrap(True)
        content_layout.addWidget(desc_label)
        
        layout.addLayout(content_layout)
        layout.addStretch()
        
        # Severity info
        info_layout = QVBoxLayout()
        info_layout.setAlignment(Qt.AlignRight)
        
        severity_label = QLabel(f"Severity: {severity}")
        severity_label.setStyleSheet(f"""
            font-size: 12px;
            font-weight: 700;
            color: {color};
            font-family: 'Space Grotesk', sans-serif;
        """)
        info_layout.addWidget(severity_label)
        
        confidence_label = QLabel(f"FR-NLP-05: Confidence: {confidence}")
        confidence_label.setStyleSheet("""
            font-size: 12px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        info_layout.addWidget(confidence_label)
        
        layout.addLayout(info_layout)
        card.setLayout(layout)
        
        return card
    
    def create_quarantine_view(self) -> QWidget:
        """Create scan & quarantine view with Neon Cyber theme"""
        view = QWidget()
        view.setStyleSheet(f"background-color: {COLORS['background_light']};")
        
        # Main content (no duplicate sidebar)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background-color: {COLORS['background_light']};
            }}
            QScrollBar:vertical {{
                background-color: {COLORS['background_dark']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['border']};
                border-radius: 5px;
            }}
        """)
        
        scroll_content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(40, 40, 40, 40)
        content_layout.setSpacing(30)
        
        # Header
        header = QLabel("SCAN & QUARANTINE")
        header.setStyleSheet(f"""
            font-size: 36px;
            font-weight: 900;
            color: {COLORS['text_primary']};
            letter-spacing: 2px;
        """)
        content_layout.addWidget(header)
        
        # Start new scan section
        scan_section = QFrame()
        scan_section.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        scan_layout = QVBoxLayout()
        scan_layout.setSpacing(24)
        
        scan_title = QLabel("Start a New Scan")
        scan_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        scan_layout.addWidget(scan_title)
        
        # Scan type cards
        scan_types_layout = QHBoxLayout()
        scan_types_layout.setSpacing(24)
        
        # File scan card
        file_scan_card = self.create_scan_option_card(
            "file",
            "Scan Individual Files",
            "Select one or more files to check for threats.",
            "Select Files",
            self.run_custom_scan
        )
        scan_types_layout.addWidget(file_scan_card)
        
        # Directory scan card
        dir_scan_card = self.create_scan_option_card(
            "folder",
            "Scan a Directory",
            "Choose a folder to scan all its contents.",
            "Select Directory",
            self.run_full_scan,
            False
        )
        scan_types_layout.addWidget(dir_scan_card)
        
        scan_layout.addLayout(scan_types_layout)
        scan_section.setLayout(scan_layout)
        content_layout.addWidget(scan_section)
        
        # Scan progress section
        progress_section = QFrame()
        progress_section.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(16)
        
        progress_title = QLabel("Scan in Progress")
        progress_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        progress_layout.addWidget(progress_title)
        
        # Progress indicator
        progress_row = QHBoxLayout()
        progress_row.setSpacing(24)
        
        # Circular progress (simulated with label)
        progress_circle = QLabel("75%")
        progress_circle.setFixedSize(128, 128)
        progress_circle.setStyleSheet("""
            QLabel {
                background-color: #233648;
                border: 8px solid #1173d4;
                border-radius: 64px;
                font-size: 28px;
                font-weight: 700;
                color: #1173d4;
                font-family: 'Space Grotesk', sans-serif;
                qproperty-alignment: AlignCenter;
            }
        """)
        progress_row.addWidget(progress_circle)
        
        # Progress details
        progress_details = QWidget()
        details_layout = QVBoxLayout()
        details_layout.setSpacing(8)
        
        scan_path_label = QLabel("Scanning Directory: /Users/" + self.username + "/Documents/")
        scan_path_label.setStyleSheet("""
            font-size: 16px;
            font-weight: 500;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        details_layout.addWidget(scan_path_label)
        
        threats_found_label = QLabel("3 threats found")
        threats_found_label.setStyleSheet("""
            font-size: 14px;
            font-weight: 700;
            color: #F97316;
            font-family: 'Space Grotesk', sans-serif;
        """)
        details_layout.addWidget(threats_found_label)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setValue(75)
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setFixedHeight(10)
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                background-color: #324d67;
                border-radius: 5px;
            }
            QProgressBar::chunk {
                background-color: #1173d4;
                border-radius: 5px;
            }
        """)
        details_layout.addWidget(self.scan_progress)
        
        self.scan_status = QLabel("Currently scanning: Q3_financials_draft.docx")
        self.scan_status.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        details_layout.addWidget(self.scan_status)
        
        progress_details.setLayout(details_layout)
        progress_row.addWidget(progress_details, 1)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setFixedHeight(48)
        self.stop_scan_btn.setFixedWidth(120)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #b91c1c;
            }
        """)
        progress_row.addWidget(self.stop_scan_btn)
        
        progress_layout.addLayout(progress_row)
        progress_section.setLayout(progress_layout)
        content_layout.addWidget(progress_section)
        
        # Detected threats table
        threats_section = QFrame()
        threats_section.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        threats_layout = QVBoxLayout()
        threats_layout.setSpacing(16)
        
        threats_header = QHBoxLayout()
        
        threats_title = QLabel("Detected Threats (3)")
        threats_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        threats_header.addWidget(threats_title)
        threats_header.addStretch()
        
        quarantine_all_btn = QPushButton("Quarantine All")
        quarantine_all_btn.setFixedHeight(40)
        quarantine_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #F97316;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #ea580c;
            }
        """)
        threats_header.addWidget(quarantine_all_btn)
        
        remove_all_btn = QPushButton("Remove All")
        remove_all_btn.setFixedHeight(40)
        remove_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #b91c1c;
            }
        """)
        threats_header.addWidget(remove_all_btn)
        
        threats_layout.addLayout(threats_header)
        
        # Threats table
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["File & Path", "Threat Details", "File Hash (SHA-256)", "Actions"])
        self.threats_table.setRowCount(3)
        self.threats_table.setStyleSheet("""
            QTableWidget {
                background-color: transparent;
                border: none;
                color: #ffffff;
                gridline-color: #324d67;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #324d67;
            }
            QHeaderView::section {
                background-color: #233648;
                color: #92adc9;
                padding: 12px;
                border: none;
                font-weight: 700;
                font-size: 12px;
                text-transform: uppercase;
            }
        """)
        
        # Sample threat data
        threats_data = [
            ("installer.exe\nC:/.../Downloads/", "Trojan.Generic.123\nHigh Severity", "e3b0c442...a591e0a2"),
            ("extension.crx\nC:/.../AppData/", "Adware.Browser.Hijacker\nMedium Severity", "a2c4e68e...f2b5a1c3"),
            ("sysclean.exe\nC:/.../Temp/", "PUP.Optional.SystemCleaner\nLow Severity", "f8a9d0b6...d3e4c5f6")
        ]
        
        for row, (file_info, threat_info, hash_val) in enumerate(threats_data):
            self.threats_table.setItem(row, 0, QTableWidgetItem(file_info))
            self.threats_table.setItem(row, 1, QTableWidgetItem(threat_info))
            self.threats_table.setItem(row, 2, QTableWidgetItem(hash_val))
            
            action_btn = QPushButton("Quarantine")
            action_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #1173d4;
                    border: none;
                    font-weight: 500;
                    text-decoration: underline;
                }
                QPushButton:hover {
                    color: #0d5cb5;
                }
            """)
            self.threats_table.setCellWidget(row, 3, action_btn)
        
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threats_table.verticalHeader().setVisible(False)
        threats_layout.addWidget(self.threats_table)
        
        threats_section.setLayout(threats_layout)
        content_layout.addWidget(threats_section)
        
        # Quarantined threats section
        quarantine_section = QFrame()
        quarantine_section.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        quarantine_layout = QVBoxLayout()
        quarantine_layout.setSpacing(16)
        
        quarantine_header = QHBoxLayout()
        
        quarantine_title = QLabel("Quarantined Threats (1)")
        quarantine_title.setStyleSheet("""
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        quarantine_header.addWidget(quarantine_title)
        quarantine_header.addStretch()
        
        restore_all_btn = QPushButton("Restore All")
        restore_all_btn.setFixedHeight(40)
        restore_all_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(17, 115, 212, 0.2);
                color: #1173d4;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: rgba(17, 115, 212, 0.3);
            }
        """)
        quarantine_header.addWidget(restore_all_btn)
        
        delete_perm_btn = QPushButton("Delete All Permanently")
        delete_perm_btn.setFixedHeight(40)
        delete_perm_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #b91c1c;
            }
        """)
        quarantine_header.addWidget(delete_perm_btn)
        
        quarantine_layout.addLayout(quarantine_header)
        
        # Quarantine table
        quarantine_table = QTableWidget()
        quarantine_table.setColumnCount(4)
        quarantine_table.setHorizontalHeaderLabels(["File Name", "Threat Type", "Date Quarantined", "Actions"])
        quarantine_table.setRowCount(1)
        quarantine_table.setStyleSheet(self.threats_table.styleSheet())
        
        quarantine_table.setItem(0, 0, QTableWidgetItem("malicious_script.js"))
        quarantine_table.setItem(0, 1, QTableWidgetItem("High Severity"))
        quarantine_table.setItem(0, 2, QTableWidgetItem("2023-10-27 14:30"))
        
        actions_widget = QWidget()
        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        
        restore_btn = QPushButton("Restore")
        restore_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #1173d4;
                border: none;
                font-weight: 500;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #0d5cb5;
            }
        """)
        actions_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ef4444;
                border: none;
                font-weight: 500;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #dc2626;
            }
        """)
        actions_layout.addWidget(delete_btn)
        
        actions_widget.setLayout(actions_layout)
        quarantine_table.setCellWidget(0, 3, actions_widget)
        
        quarantine_table.horizontalHeader().setStretchLastSection(True)
        quarantine_table.verticalHeader().setVisible(False)
        quarantine_layout.addWidget(quarantine_table)
        
        quarantine_section.setLayout(quarantine_layout)
        content_layout.addWidget(quarantine_section)
        
        
        scroll_content.setLayout(content_layout)
        scroll.setWidget(scroll_content)
        
        view_layout = QVBoxLayout()
        view_layout.setContentsMargins(0, 0, 0, 0)
        view_layout.addWidget(scroll)
        view.setLayout(view_layout)
        return view
    
    def create_scan_option_card(self, icon_name: str, title: str, description: str, button_text: str, callback, primary: bool = True) -> QFrame:
        """Create a scan option card"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #101922;
                border: 1px solid #324d67;
                border-radius: 12px;
                padding: 24px;
            }
            QFrame:hover {
                border-color: #1173d4;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)
        
        icon_label = QLabel()
        icon_label.setPixmap(get_icon(icon_name, '#1173d4').pixmap(56, 56))
        icon_label.setStyleSheet("""
            qproperty-alignment: AlignCenter;
        """)
        layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
            qproperty-alignment: AlignCenter;
        """)
        layout.addWidget(title_label)
        
        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
            qproperty-alignment: AlignCenter;
        """)
        layout.addWidget(desc_label)
        
        btn = QPushButton(button_text)
        btn.setFixedHeight(48)
        btn.clicked.connect(callback)
        
        if primary:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1173d4;
                    color: #ffffff;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 700;
                }
                QPushButton:hover {
                    background-color: #0d5cb5;
                }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #233648;
                    color: #ffffff;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 700;
                }
                QPushButton:hover {
                    background-color: rgba(17, 115, 212, 0.9);
                }
            """)
        
        layout.addWidget(btn)
        card.setLayout(layout)
        
        return card
    
    def create_simple_sidebar(self, active_item: str) -> QFrame:
        """Create a simple sidebar for views"""
        sidebar = QFrame()
        sidebar.setFixedWidth(256)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #111a22;
                color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(24)
        
        # User profile
        profile_layout = QHBoxLayout()
        profile_layout.setSpacing(12)
        
        avatar = QLabel()
        avatar.setPixmap(get_icon('user', COLORS['text_primary']).pixmap(24, 24))
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet("""
            QLabel {
                background-color: #233648;
                border-radius: 20px;
                padding: 6px;
            }
        """)
        profile_layout.addWidget(avatar)
        
        user_info = QWidget()
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        user_info_layout.setContentsMargins(0, 0, 0, 0)
        
        user_name = QLabel(self.username)
        user_name.setStyleSheet("font-size: 14px; font-weight: 500; color: #ffffff;")
        user_info_layout.addWidget(user_name)
        
        user_role = QLabel("Premium User")
        user_role.setStyleSheet("font-size: 12px; color: #92adc9;")
        user_info_layout.addWidget(user_role)
        
        user_info.setLayout(user_info_layout)
        profile_layout.addWidget(user_info)
        
        layout.addLayout(profile_layout)
        
        # Navigation
        nav_items = [
            ("home", "Dashboard"),
            ("shield", "File Security"),
            ("globe", "Network Protection"),
            ("settings", "Settings")
        ]
        
        for icon_name, text in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setIcon(get_icon(icon_name, '#ffffff'))
            btn.setIconSize(QSize(16, 16))
            btn.setFixedHeight(40)
            
            if text == active_item:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #233648;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                        font-weight: 500;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: #233648;
                    }
                """)
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Upgrade button
        upgrade_btn = QPushButton("Upgrade")
        upgrade_btn.setFixedHeight(40)
        upgrade_btn.setStyleSheet("""
            QPushButton {
                background-color: #1173d4;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #0d5cb5;
            }
        """)
        layout.addWidget(upgrade_btn)
        
        sidebar.setLayout(layout)
        return sidebar
    
    def create_reports_view(self) -> QWidget:
        """Create security reports view with Neon Cyber theme"""
        view = QWidget()
        view.setStyleSheet(f"background-color: {COLORS['background_light']};")
        
        # Main content (no duplicate sidebar)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background-color: {COLORS['background_light']};
            }}
            QScrollBar:vertical {{
                background-color: {COLORS['background_dark']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['border']};
                border-radius: 5px;
            }}
        """)
        
        scroll_content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(32, 32, 32, 32)
        content_layout.setSpacing(32)
        
        # Header with actions
        header_layout = QVBoxLayout()
        header_layout.setSpacing(16)
        
        page_title = QLabel("Security Reports")
        page_title.setStyleSheet("""
            font-size: 36px;
            font-weight: 900;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        header_layout.addWidget(page_title)
        
        page_subtitle = QLabel("Monitor security status, generate reports, and view history.")
        page_subtitle.setStyleSheet("""
            font-size: 16px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        header_layout.addWidget(page_subtitle)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        
        generate_btn = QPushButton("  Generate Report")
        generate_btn.setIcon(get_icon('calendar', '#ffffff'))
        generate_btn.setIconSize(QSize(16, 16))
        generate_btn.setFixedHeight(40)
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #2C3E50;
                color: #ffffff;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
        """)
        actions_layout.addWidget(generate_btn)
        
        export_btn = QPushButton("  Export")
        export_btn.setIcon(get_icon('download', '#ffffff'))
        export_btn.setIconSize(QSize(16, 16))
        export_btn.setFixedHeight(40)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498DB;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        actions_layout.addWidget(export_btn)
        
        header_layout.addLayout(actions_layout)
        content_layout.addLayout(header_layout)
        
        # Status card
        status_card = QFrame()
        status_card.setStyleSheet("""
            QFrame {
                background-color: #1A242E;
                border: 1px solid #324d67;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        status_layout = QVBoxLayout()
        status_layout.setAlignment(Qt.AlignCenter)
        status_layout.setSpacing(16)
        
        shield_icon = QLabel()
        shield_icon.setPixmap(get_icon('check', '#22C55E').pixmap(64, 64))
        shield_icon.setStyleSheet("""
            qproperty-alignment: AlignCenter;
        """)
        status_layout.addWidget(shield_icon)
        
        status_title = QLabel("System Secure")
        status_title.setStyleSheet("""
            font-size: 24px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
            qproperty-alignment: AlignCenter;
        """)
        status_layout.addWidget(status_title)
        
        status_desc = QLabel("Real-time protection is active.")
        status_desc.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
            qproperty-alignment: AlignCenter;
        """)
        status_layout.addWidget(status_desc)
        
        last_scan = QLabel("Last scan: 2 hours ago")
        last_scan.setStyleSheet("""
            font-size: 12px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
            qproperty-alignment: AlignCenter;
        """)
        status_layout.addWidget(last_scan)
        
        status_card.setLayout(status_layout)
        content_layout.addWidget(status_card)
        
        # Metrics grid
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(24)
        
        metrics = [
            ("Threats Detected (30d)", "1,234"),
            ("Scans Performed (30d)", "56"),
            ("Files Quarantined", "78"),
            ("Security Score", "92%")
        ]
        
        colors = ["#ffffff", "#ffffff", "#ffffff", "#2ECC71"]
        
        for i, (title, value) in enumerate(metrics):
            metric_card = QFrame()
            metric_card.setStyleSheet("""
                QFrame {
                    background-color: rgba(44, 62, 80, 0.2);
                    border: 1px solid #324d67;
                    border-radius: 8px;
                    padding: 24px;
                }
            """)
            
            metric_layout = QVBoxLayout()
            metric_layout.setSpacing(8)
            
            metric_title = QLabel(title)
            metric_title.setStyleSheet("""
                font-size: 14px;
                font-weight: 500;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            """)
            metric_layout.addWidget(metric_title)
            
            metric_value = QLabel(value)
            metric_value.setStyleSheet(f"""
                font-size: 24px;
                font-weight: 700;
                color: {colors[i]};
                font-family: 'Space Grotesk', sans-serif;
            """)
            metric_layout.addWidget(metric_value)
            
            metric_card.setLayout(metric_layout)
            metrics_layout.addWidget(metric_card)
        
        content_layout.addLayout(metrics_layout)
        
        # Security metrics chart
        chart_section = QFrame()
        chart_section.setStyleSheet("""
            QFrame {
                background-color: rgba(44, 62, 80, 0.2);
                border: 1px solid #324d67;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        chart_layout = QVBoxLayout()
        chart_layout.setSpacing(16)
        
        chart_header = QHBoxLayout()
        chart_title = QLabel("Security Metrics & Trends")
        chart_title.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        chart_header.addWidget(chart_title)
        
        time_filter = QLabel("Last 30 Days")
        time_filter.setStyleSheet("""
            font-size: 14px;
            color: #92adc9;
            font-family: 'Space Grotesk', sans-serif;
        """)
        chart_header.addWidget(time_filter)
        chart_layout.addLayout(chart_header)
        
        # Chart placeholder
        chart_placeholder = QLabel("Security Trends Chart")
        chart_placeholder.setFixedHeight(220)
        chart_placeholder.setStyleSheet("""
            QLabel {
                background-color: #1A242E;
                border-radius: 8px;
                font-size: 24px;
                color: #3498DB;
                qproperty-alignment: AlignCenter;
            }
        """)
        chart_layout.addWidget(chart_placeholder)
        
        chart_section.setLayout(chart_layout)
        content_layout.addWidget(chart_section)
        
        # Threat logs table
        logs_section = QFrame()
        logs_section.setStyleSheet("""
            QFrame {
                background-color: rgba(44, 62, 80, 0.2);
                border: 1px solid #324d67;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        
        logs_layout = QVBoxLayout()
        logs_layout.setSpacing(16)
        
        logs_header = QHBoxLayout()
        logs_title = QLabel("Scan History & Threat Logs")
        logs_title.setStyleSheet("""
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        logs_header.addWidget(logs_title)
        logs_header.addStretch()
        
        # Filter dropdowns
        type_filter = QComboBox()
        type_filter.addItems(["Type: All", "Quick Scan", "Full Scan", "Custom Scan"])
        type_filter.setStyleSheet("""
            QComboBox {
                background-color: #101922;
                border: 1px solid #324d67;
                border-radius: 4px;
                padding: 6px 12px;
                color: #ffffff;
                font-size: 12px;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        logs_header.addWidget(type_filter)
        
        threat_filter = QComboBox()
        threat_filter.addItems(["Threats: All", "High", "Medium", "Low"])
        threat_filter.setStyleSheet(type_filter.styleSheet())
        logs_header.addWidget(threat_filter)
        
        logs_layout.addLayout(logs_header)
        
        # Threat logs table
        self.threat_logs_table = QTableWidget()
        self.threat_logs_table.setColumnCount(5)
        self.threat_logs_table.setHorizontalHeaderLabels(["Date & Time", "Action", "Threat Details", "Risk Level", "Explanation"])
        self.threat_logs_table.setRowCount(4)
        self.threat_logs_table.setStyleSheet("""
            QTableWidget {
                background-color: transparent;
                border: none;
                color: #ffffff;
                gridline-color: #324d67;
            }
            QTableWidget::item {
                padding: 12px;
                border-bottom: 1px solid #324d67;
            }
            QHeaderView::section {
                background-color: rgba(44, 62, 80, 0.2);
                color: #92adc9;
                padding: 12px;
                border: none;
                font-weight: 700;
                font-size: 12px;
                text-transform: uppercase;
            }
        """)
        
        # Sample threat log data
        logs_data = [
            ("2023-10-28 14:30", "File Blocked", "wacatac.b!ml", "High", "X-AI Analysis"),
            ("2023-10-27 10:05", "Process Quarantined", "svchost.exe (PID 1234)", "Medium", "X-AI Analysis"),
            ("2023-10-27 09:00", "Scan Completed", "No threats found", "-", "N/A"),
            ("2023-10-26 18:45", "Phishing Alert", "Email from \"support@micro-soft.io\"", "Low", "X-AI Analysis")
        ]
        
        for row, (date, action, threat, risk, explanation) in enumerate(logs_data):
            self.threat_logs_table.setItem(row, 0, QTableWidgetItem(date))
            self.threat_logs_table.setItem(row, 1, QTableWidgetItem(action))
            self.threat_logs_table.setItem(row, 2, QTableWidgetItem(threat))
            
            # Risk level with color coding
            if risk == "High":
                risk_widget = QLabel("High")
                risk_widget.setStyleSheet("""
                    QLabel {
                        background-color: #E74C3C;
                        color: #ffffff;
                        border-radius: 12px;
                        padding: 4px 8px;
                        font-size: 12px;
                        font-weight: 700;
                    }
                """)
                self.threat_logs_table.setCellWidget(row, 3, risk_widget)
            elif risk == "Medium":
                risk_widget = QLabel("Medium")
                risk_widget.setStyleSheet("""
                    QLabel {
                        background-color: #F1C40F;
                        color: #000000;
                        border-radius: 12px;
                        padding: 4px 8px;
                        font-size: 12px;
                        font-weight: 700;
                    }
                """)
                self.threat_logs_table.setCellWidget(row, 3, risk_widget)
            elif risk == "Low":
                risk_widget = QLabel("Low")
                risk_widget.setStyleSheet("""
                    QLabel {
                        background-color: #2ECC71;
                        color: #000000;
                        border-radius: 12px;
                        padding: 4px 8px;
                        font-size: 12px;
                        font-weight: 700;
                    }
                """)
                self.threat_logs_table.setCellWidget(row, 3, risk_widget)
            elif risk == "-":
                self.threat_logs_table.setItem(row, 3, QTableWidgetItem(risk))
            
            # Explanation column with AI button
            if explanation != "N/A":
                ai_btn = QPushButton("  X-AI Analysis")
                ai_btn.setIcon(get_icon('robot', '#ffffff'))
                ai_btn.setIconSize(QSize(16, 16))
                ai_btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #3498DB;
                        border: none;
                        font-weight: 500;
                        text-decoration: underline;
                    }
                    QPushButton:hover {
                        color: #2980b9;
                    }
                """)
                # Connect to show threat details dialog
                ai_btn.clicked.connect(lambda checked, r=row: self.show_threat_details(r))
                self.threat_logs_table.setCellWidget(row, 4, ai_btn)
            else:
                na_label = QLabel("N/A")
                na_label.setStyleSheet("color: #92adc9;")
                self.threat_logs_table.setCellWidget(row, 4, na_label)
        
        self.threat_logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_logs_table.verticalHeader().setVisible(False)
        logs_layout.addWidget(self.threat_logs_table)
        
        logs_section.setLayout(logs_layout)
        content_layout.addWidget(logs_section)
        
        
        scroll_content.setLayout(content_layout)
        scroll.setWidget(scroll_content)
        
        view_layout = QVBoxLayout()
        view_layout.setContentsMargins(0, 0, 0, 0)
        view_layout.addWidget(scroll)
        view.setLayout(view_layout)
        return view
    
    def create_reports_sidebar(self) -> QFrame:
        """Create sidebar for reports view"""
        sidebar = QFrame()
        sidebar.setFixedWidth(256)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #2C3E50;
                color: #ffffff;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(24)
        
        # User profile
        profile_layout = QHBoxLayout()
        profile_layout.setSpacing(12)
        
        avatar = QLabel()
        avatar.setPixmap(get_icon('user', COLORS['text_primary']).pixmap(24, 24))
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet("""
            QLabel {
                background-color: #233648;
                border-radius: 20px;
                padding: 6px;
            }
        """)
        profile_layout.addWidget(avatar)
        
        user_info = QWidget()
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        user_info_layout.setContentsMargins(0, 0, 0, 0)
        
        user_name = QLabel(self.username)
        user_name.setStyleSheet("font-size: 14px; font-weight: 500; color: #ffffff;")
        user_info_layout.addWidget(user_name)
        
        user_email = QLabel(f"{self.username}@email.com")
        user_email.setStyleSheet("font-size: 12px; color: #92adc9;")
        user_info_layout.addWidget(user_email)
        
        user_info.setLayout(user_info_layout)
        profile_layout.addWidget(user_info)
        
        layout.addLayout(profile_layout)
        
        # Navigation
        nav_items = [
            ("home", "Dashboard"),
            ("scan", "Scan"),
            ("file-alt", "Reports"),
            ("settings", "Settings")
        ]
        
        for icon_name, text in nav_items:
            btn = QPushButton(f"  {text}")
            btn.setIcon(get_icon(icon_name, '#ffffff'))
            btn.setIconSize(QSize(16, 16))
            btn.setFixedHeight(40)
            
            if text == "Reports":
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: rgba(52, 152, 219, 0.2);
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                        font-weight: 500;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #ffffff;
                        border: none;
                        border-radius: 8px;
                        padding: 8px 12px;
                        text-align: left;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: rgba(52, 152, 219, 0.2);
                    }
                """)
            layout.addWidget(btn)
        
        layout.addStretch()
        
        # Upgrade button
        upgrade_btn = QPushButton("Upgrade to Pro")
        upgrade_btn.setFixedHeight(40)
        upgrade_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498DB;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        layout.addWidget(upgrade_btn)
        
        sidebar.setLayout(layout)
        return sidebar
    
    def create_settings_view(self) -> QWidget:
        """Create settings view with Neon Cyber theme"""
        view = QWidget()
        view.setStyleSheet(f"background-color: {COLORS['background_light']};")
        
        # Main content (no duplicate sidebar)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                background-color: {COLORS['background_light']};
            }}
            QScrollBar:vertical {{
                background-color: {COLORS['background_dark']};
                width: 10px;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {COLORS['border']};
                border-radius: 5px;
            }}
        """)
        
        scroll_content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(32, 32, 32, 32)
        content_layout.setSpacing(32)
        
        # Header
        header = QLabel("Settings")
        header.setStyleSheet("""
            font-size: 36px;
            font-weight: 900;
            color: #ffffff;
            font-family: 'Space Grotesk', sans-serif;
        """)
        content_layout.addWidget(header)
        
        # Settings categories
        categories = [
            ("shield", "Real-Time Protection", self.create_realtime_settings),
            ("search", "Scan Settings", self.create_scan_settings),
            ("lock", "Password Manager", self.create_password_settings),
            ("globe", "Network Protection", self.create_network_settings),
            ("user", "Account", self.create_account_settings),
            ("palette", "Appearance", self.create_appearance_settings)
        ]
        
        for icon_name, title, creator_func in categories:
            section = QFrame()
            section.setStyleSheet("""
                QFrame {
                    background-color: #111a22;
                    border: 1px solid #324d67;
                    border-radius: 12px;
                    padding: 24px;
                }
            """)
            
            section_layout = QVBoxLayout()
            section_layout.setSpacing(16)
            
            # Section header with icon
            header_layout = QHBoxLayout()
            header_layout.setSpacing(12)
            
            icon_label = QLabel()
            icon_label.setPixmap(get_icon(icon_name, '#ffffff').pixmap(24, 24))
            icon_label.setFixedSize(24, 24)
            header_layout.addWidget(icon_label)
            
            section_title = QLabel(title)
            section_title.setStyleSheet("""
                font-size: 20px;
                font-weight: 700;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            """)
            header_layout.addWidget(section_title)
            header_layout.addStretch()
            
            section_layout.addLayout(header_layout)
            
            # Add settings content
            settings_widget = creator_func()
            section_layout.addWidget(settings_widget)
            
            section.setLayout(section_layout)
            content_layout.addWidget(section)
        
        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.setFixedHeight(48)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #1173d4;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #0d5cb5;
            }
        """)
        content_layout.addWidget(save_btn, alignment=Qt.AlignRight)
        
        
        scroll_content.setLayout(content_layout)
        scroll.setWidget(scroll_content)
        
        view_layout = QVBoxLayout()
        view_layout.setContentsMargins(0, 0, 0, 0)
        view_layout.addWidget(scroll)
        view.setLayout(view_layout)
        return view
    
    def create_realtime_settings(self) -> QWidget:
        """Create real-time protection settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Toggle switch
        rt_layout = QHBoxLayout()
        rt_label = QLabel("Enable Real-Time Protection")
        rt_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        rt_layout.addWidget(rt_label)
        rt_layout.addStretch()
        
        rt_toggle = QCheckBox()
        rt_toggle.setChecked(True)
        rt_toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #334155;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background-color: #1173d4;
                border-color: #1173d4;
            }
        """)
        rt_layout.addWidget(rt_toggle)
        layout.addLayout(rt_layout)
        
        # File types
        types_layout = QHBoxLayout()
        types_label = QLabel("File Types to Monitor")
        types_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        types_layout.addWidget(types_label)
        types_layout.addStretch()
        
        types_input = QLineEdit(".exe, .dll, .scr, .bat, .cmd")
        types_input.setFixedWidth(200)
        types_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        types_layout.addWidget(types_input)
        layout.addLayout(types_layout)
        
        # Scan frequency
        freq_layout = QHBoxLayout()
        freq_label = QLabel("Scan Frequency")
        freq_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        freq_layout.addWidget(freq_label)
        freq_layout.addStretch()
        
        freq_combo = QComboBox()
        freq_combo.addItems(["High (Every 5 seconds)", "Medium (Every 30 seconds)", "Low (Every minute)"])
        freq_combo.setStyleSheet("""
            QComboBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
                min-width: 150px;
            }
        """)
        freq_layout.addWidget(freq_combo)
        layout.addLayout(freq_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_scan_settings(self) -> QWidget:
        """Create scan settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Exclusions
        excl_layout = QHBoxLayout()
        excl_label = QLabel("Excluded Directories")
        excl_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        excl_layout.addWidget(excl_label)
        excl_layout.addStretch()
        
        excl_input = QLineEdit("C:\\Windows, C:\\Program Files")
        excl_input.setFixedWidth(200)
        excl_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        excl_layout.addWidget(excl_input)
        layout.addLayout(excl_layout)
        
        # Heuristics
        heur_layout = QHBoxLayout()
        heur_label = QLabel("Enable Heuristic Analysis")
        heur_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        heur_layout.addWidget(heur_label)
        heur_layout.addStretch()
        
        heur_toggle = QCheckBox()
        heur_toggle.setChecked(True)
        heur_toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #334155;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background-color: #1173d4;
                border-color: #1173d4;
            }
        """)
        heur_layout.addWidget(heur_toggle)
        layout.addLayout(heur_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_password_settings(self) -> QWidget:
        """Create password manager settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Master password
        master_layout = QHBoxLayout()
        master_label = QLabel("Require Master Password")
        master_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        master_layout.addWidget(master_label)
        master_layout.addStretch()
        
        master_toggle = QCheckBox()
        master_toggle.setChecked(True)
        master_toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #334155;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background-color: #1173d4;
                border-color: #1173d4;
            }
        """)
        master_layout.addWidget(master_toggle)
        layout.addLayout(master_layout)
        
        # Auto-lock
        lock_layout = QHBoxLayout()
        lock_label = QLabel("Auto-Lock After (minutes)")
        lock_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        lock_layout.addWidget(lock_label)
        lock_layout.addStretch()
        
        lock_spin = QSpinBox()
        lock_spin.setValue(10)
        lock_spin.setRange(1, 60)
        lock_spin.setFixedWidth(80)
        lock_spin.setStyleSheet("""
            QSpinBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        lock_layout.addWidget(lock_spin)
        layout.addLayout(lock_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_network_settings(self) -> QWidget:
        """Create network protection settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Firewall
        fw_layout = QHBoxLayout()
        fw_label = QLabel("Enable Firewall")
        fw_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        fw_layout.addWidget(fw_label)
        fw_layout.addStretch()
        
        fw_toggle = QCheckBox()
        fw_toggle.setChecked(True)
        fw_toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #334155;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background-color: #1173d4;
                border-color: #1173d4;
            }
        """)
        fw_layout.addWidget(fw_toggle)
        layout.addLayout(fw_layout)
        
        # VPN
        vpn_layout = QHBoxLayout()
        vpn_label = QLabel("Auto-Connect VPN")
        vpn_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        vpn_layout.addWidget(vpn_label)
        vpn_layout.addStretch()
        
        vpn_toggle = QCheckBox()
        vpn_toggle.setChecked(False)
        vpn_toggle.setStyleSheet("""
            QCheckBox::indicator {
                width: 40px;
                height: 20px;
                border-radius: 10px;
                border: 2px solid #334155;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background-color: #1173d4;
                border-color: #1173d4;
            }
        """)
        vpn_layout.addWidget(vpn_toggle)
        layout.addLayout(vpn_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_account_settings(self) -> QWidget:
        """Create account settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Email
        email_layout = QHBoxLayout()
        email_label = QLabel("Email Address")
        email_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        email_layout.addWidget(email_label)
        email_layout.addStretch()
        
        email_input = QLineEdit(f"{self.username}@cyberguard.pro")
        email_input.setFixedWidth(200)
        email_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
            }
        """)
        email_layout.addWidget(email_input)
        layout.addLayout(email_layout)
        
        # Change password
        pwd_layout = QHBoxLayout()
        pwd_label = QLabel("Change Password")
        pwd_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        pwd_layout.addWidget(pwd_label)
        pwd_layout.addStretch()
        
        pwd_btn = QPushButton("Change Password")
        pwd_btn.setFixedHeight(32)
        pwd_btn.setStyleSheet("""
            QPushButton {
                background-color: #233648;
                color: #ffffff;
                border: none;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #324d67;
            }
        """)
        pwd_layout.addWidget(pwd_btn)
        layout.addLayout(pwd_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_appearance_settings(self) -> QWidget:
        """Create appearance settings"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        # Theme
        theme_layout = QHBoxLayout()
        theme_label = QLabel("Theme")
        theme_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        theme_layout.addWidget(theme_label)
        theme_layout.addStretch()
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Dark", "Light", "System Default"])
        theme_combo.setStyleSheet("""
            QComboBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 6px;
                color: #ffffff;
                font-size: 12px;
                min-width: 150px;
            }
        """)
        theme_layout.addWidget(theme_combo)
        layout.addLayout(theme_layout)
        
        # Font size
        font_layout = QHBoxLayout()
        font_label = QLabel("Font Size")
        font_label.setStyleSheet("font-size: 14px; color: #ffffff;")
        font_layout.addWidget(font_label)
        font_layout.addStretch()
        
        font_combo = QComboBox()
        font_combo.addItems(["Small", "Medium", "Large"])
        font_combo.setStyleSheet(theme_combo.styleSheet())
        font_layout.addWidget(font_combo)
        layout.addLayout(font_layout)
        
        widget.setLayout(layout)
        return widget
    
    # Old tab-based methods (kept for backward compatibility)
    def create_overview_tab(self) -> QWidget:
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Real-Time Protection Control
        if RTP_AVAILABLE:
            rtp_group = QGroupBox("Real-Time Protection")
            rtp_layout = QVBoxLayout()
            
            # Status and control
            rtp_control_layout = QHBoxLayout()
            
            self.rtp_status_label = QLabel("Inactive")
            self.rtp_status_label.setStyleSheet("color: #ef4444;")
            rtp_control_layout.addWidget(self.rtp_status_label)
            
            rtp_control_layout.addStretch()
            
            self.rtp_toggle_btn = QPushButton("Start Real-Time Protection")
            self.rtp_toggle_btn.setIcon(get_icon('play', '#ffffff'))
            self.rtp_toggle_btn.setIconSize(QSize(16, 16))
            self.rtp_toggle_btn.setObjectName("successButton")
            self.rtp_toggle_btn.setMinimumHeight(50)
            self.rtp_toggle_btn.setFont(QFont("Poppins", 13, QFont.Bold))
            self.rtp_toggle_btn.clicked.connect(self.toggle_realtime_protection)
            rtp_control_layout.addWidget(self.rtp_toggle_btn)
            
            rtp_layout.addLayout(rtp_control_layout)
            
            # Statistics
            self.rtp_stats_label = QLabel("Scans: 0 | Threats Detected: 0")
            self.rtp_stats_label.setStyleSheet("color: #92adc9; font-size: 12px; margin-top: 8px;")
            rtp_layout.addWidget(self.rtp_stats_label)
            
            # Configuration button
            rtp_config_btn = QPushButton("  Configure Settings")
            rtp_config_btn.setIcon(get_icon('settings', '#ffffff'))
            rtp_config_btn.setIconSize(QSize(16, 16))
            rtp_config_btn.setObjectName("secondaryButton")
            rtp_config_btn.clicked.connect(self.configure_realtime_protection)
            rtp_layout.addWidget(rtp_config_btn)
            
            rtp_group.setLayout(rtp_layout)
            layout.addWidget(rtp_group)
        
        # Statistics
        stats_group = QGroupBox("System Statistics")
        stats_layout = QHBoxLayout()
        
        # Placeholder stats
        stats_layout.addWidget(QLabel("Threats Blocked: 0"))
        stats_layout.addWidget(QLabel("Files Scanned: 0"))
        stats_layout.addWidget(QLabel("System Health: Good"))
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Activity log
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_log)
        
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_scanner_tab(self) -> QWidget:
        """Create scanner tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Scan controls
        controls_group = QGroupBox("Scan Controls")
        controls_layout = QHBoxLayout()
        
        quick_scan_btn = QPushButton(f"{get_icon('shield')} Quick Scan")
        quick_scan_btn.clicked.connect(self.run_quick_scan)
        controls_layout.addWidget(quick_scan_btn)
        
        full_scan_btn = QPushButton(f"{get_icon('search')} Full Scan")
        full_scan_btn.setObjectName("secondaryButton")
        full_scan_btn.clicked.connect(self.run_full_scan)
        controls_layout.addWidget(full_scan_btn)
        
        custom_scan_btn = QPushButton(f"{get_icon('folder')} Custom Scan...")
        custom_scan_btn.setObjectName("secondaryButton")
        custom_scan_btn.clicked.connect(self.run_custom_scan)
        controls_layout.addWidget(custom_scan_btn)
        
        # Stop scan button
        self.stop_scan_btn = QPushButton(f"{get_icon('close')} Stop Scan")
        self.stop_scan_btn.setObjectName("dangerButton")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setVisible(False)  # Hidden by default
        controls_layout.addWidget(self.stop_scan_btn)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Progress
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.scan_status = QLabel("Ready to scan")
        progress_layout.addWidget(self.scan_status)
        
        self.scan_progress = QProgressBar()
        progress_layout.addWidget(self.scan_progress)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        results_layout.addWidget(self.scan_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_monitor_tab(self) -> QWidget:
        """Create system monitor tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        monitor_group = QGroupBox("System Resources")
        monitor_layout = QVBoxLayout()
        
        self.monitor_display = QTextEdit()
        self.monitor_display.setReadOnly(True)
        monitor_layout.addWidget(self.monitor_display)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_password_tab(self) -> QWidget:
        """Create password manager tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Password")
        add_btn.clicked.connect(self.add_password)
        controls_layout.addWidget(add_btn)
        
        gen_btn = QPushButton("Generate Password")
        gen_btn.clicked.connect(self.generate_password)
        controls_layout.addWidget(gen_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Password table
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(4)
        self.password_table.setHorizontalHeaderLabels(["Website", "Username", "Category", "Actions"])
        layout.addWidget(self.password_table)
        
        self.load_passwords()
        
        tab.setLayout(layout)
        return tab
    
    def create_nlp_tab(self) -> QWidget:
        """Create NLP analyzer tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Input
        input_group = QGroupBox("Text to Analyze")
        input_layout = QVBoxLayout()
        
        self.nlp_input = QTextEdit()
        self.nlp_input.setPlaceholderText("Paste suspicious text, email, or message here...")
        input_layout.addWidget(self.nlp_input)
        
        analyze_btn = QPushButton("  Analyze Text")
        analyze_btn.setIcon(get_icon('robot', '#ffffff'))
        analyze_btn.setIconSize(QSize(16, 16))
        analyze_btn.clicked.connect(self.analyze_text)
        input_layout.addWidget(analyze_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        self.nlp_results = QTextEdit()
        self.nlp_results.setReadOnly(True)
        results_layout.addWidget(self.nlp_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_quarantine_tab(self) -> QWidget:
        """Create quarantine management tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Quarantine table
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(3)
        self.quarantine_table.setHorizontalHeaderLabels(["File Path", "Threat Type", "Quarantined At"])
        layout.addWidget(self.quarantine_table)
        
        self.load_quarantine()
        
        tab.setLayout(layout)
        return tab
    
    def create_logs_tab(self) -> QWidget:
        """Create logs viewer tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Logs table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(4)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Severity", "Message"])
        layout.addWidget(self.logs_table)
        
        self.load_logs()
        
        tab.setLayout(layout)
        return tab
    
    def start_monitoring(self):
        """Start system monitoring"""
        system_monitor.start_monitoring()
        
        # Update timer
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_dashboard)
        self.monitor_timer.start(5000)  # Update every 5 seconds
    
    def update_dashboard(self):
        """Update dashboard with current data"""
        try:
            # Update monitor display
            stats = system_monitor.get_system_stats()
            if stats:
                monitor_text = f"CPU: {stats.get('cpu', {}).get('percent', 0):.1f}%\n"
                monitor_text += f"Memory: {stats.get('memory', {}).get('percent', 0):.1f}%\n"
                monitor_text += f"Disk: {stats.get('disk', {}).get('percent', 0):.1f}%"
                self.monitor_display.setText(monitor_text)
            
            # Update Real-Time Protection stats
            if RTP_AVAILABLE and hasattr(self, 'rtp_stats_label'):
                rtp_stats = realtime_protection.get_statistics()
                scans = rtp_stats.get('scans_performed', 0)
                threats = rtp_stats.get('threats_detected', 0)
                self.rtp_stats_label.setText(f"Scans: {scans} | Threats Detected: {threats}")
        except Exception as e:
            print(f"Dashboard update error: {e}")
    
    def log_activity(self, message: str):
        """Log activity to the activity log widget"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_message = f"[{timestamp}] {message}"
            
            # Add to activity log
            current_text = self.activity_log.toPlainText()
            if current_text:
                self.activity_log.setPlainText(f"{log_message}\n{current_text}")
            else:
                self.activity_log.setPlainText(log_message)
            
            # Also log to database
            db_manager.log_event('USER_ACTION', 'INFO', message)
        except Exception as e:
            print(f"Error logging activity: {e}")
    
    def run_quick_scan(self):
        """Run quick scan in background thread"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
        
        # Reset UI
        self.scan_progress.setValue(0)
        self.scan_results.clear()
        self.scan_status.setText("Initializing quick scan...")
        self.stop_scan_btn.setVisible(True)
        
        # Create and start worker thread
        self.scan_worker = ScanWorker(self.file_scanner, 'quick')
        self.scan_worker.progress.connect(self.update_scan_progress)
        self.scan_worker.status.connect(self.update_scan_status)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()
        
        self.log_activity("Quick scan initiated")
    
    def run_full_scan(self):
        """Run full system scan in background thread"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
        
        # Confirm full scan
        reply = QMessageBox.question(
            self,
            "Full System Scan",
            "Full scan will scan your entire home directory.\nThis may take a long time.\n\nDo you want to continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Reset UI
        self.scan_progress.setValue(0)
        self.scan_results.clear()
        self.scan_status.setText("Initializing full scan...")
        self.stop_scan_btn.setVisible(True)
        
        # Create and start worker thread
        self.scan_worker = ScanWorker(self.file_scanner, 'full')
        self.scan_worker.progress.connect(self.update_scan_progress)
        self.scan_worker.status.connect(self.update_scan_status)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()
        
        self.log_activity("Full system scan initiated")
    
    def run_custom_scan(self):
        """Run custom directory scan in background thread"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running. Please wait for it to complete.")
            return
        
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not directory:
            return
        
        # Reset UI
        self.scan_progress.setValue(0)
        self.scan_results.clear()
        self.scan_status.setText(f"Initializing scan of {directory}...")
        self.stop_scan_btn.setVisible(True)
        
        # Create and start worker thread
        self.scan_worker = ScanWorker(self.file_scanner, 'custom', directory)
        self.scan_worker.progress.connect(self.update_scan_progress)
        self.scan_worker.status.connect(self.update_scan_status)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()
        
        self.log_activity(f"Custom scan initiated: {directory}")
    
    def update_scan_progress(self, value: int):
        """Update scan progress bar"""
        self.scan_progress.setValue(value)
    
    def update_scan_status(self, message: str):
        """Update scan status label"""
        self.scan_status.setText(message)
    
    def on_scan_finished(self, result: dict):
        """Handle scan completion"""
        self.stop_scan_btn.setVisible(False)
        self.scan_progress.setValue(100)
        
        # Format results
        output = "=" * 60 + "\n"
        output += "SCAN COMPLETED\n"
        output += "=" * 60 + "\n\n"
        
        output += f"Files Scanned: {result.get('files_scanned', 0)}\n"
        output += f"Threats Found: {result.get('threats_found', 0)}\n"
        output += f"Clean Files: {result.get('clean_files', 0)}\n"
        output += f"Errors: {result.get('errors', 0)}\n"
        
        if 'scan_time' in result:
            output += f"Scan Time: {result['scan_time']:.2f} seconds\n"
        
        output += "\n"
        
        # List infected/suspicious files
        if result.get('threats_found', 0) > 0:
            output += "=" * 60 + "\n"
            output += "THREATS & SUSPICIOUS FILES DETECTED\n"
            output += "=" * 60 + "\n\n"
            
            for infected in result.get('infected_files', []):
                output += f"File: {infected['path']}\n"
                threat = infected.get('threat', {})
                if isinstance(threat, dict):
                    threat_name = threat.get('name', 'Unknown')
                    level = threat.get('level', 'Unknown')
                    desc = threat.get('description', 'N/A')
                    
                    if 'Heuristic' in threat_name:
                        output += f"  [SUSPICIOUS] {threat_name}\n"
                        output += f"  Level: {level}\n"
                        output += f"  Reason: {desc}\n"
                    else:
                        output += f"  [THREAT] {threat_name}\n"
                        output += f"  Level: {level}\n"
                        output += f"  Description: {desc}\n"
                else:
                    output += f"  Threat: {threat}\n"
                output += "-" * 40 + "\n"
            
            # Show alert
            QMessageBox.warning(
                self,
                "Threats Detected",
                f"{result.get('threats_found', 0)} threat(s) or suspicious file(s) found!\n\nPlease review the scan results."
            )
        else:
            output += "\n✅ No threats detected. Your system is clean!\n"
            self.scan_status.setText("Scan complete - No threats found")
        
        self.scan_results.setText(output)
        self.log_activity(f"Scan completed: {result.get('files_scanned', 0)} files, {result.get('threats_found', 0)} threats")
    
    def stop_scan(self):
        """Stop the currently running scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Stop Scan",
                "Are you sure you want to stop the current scan?\n\nPartial results will be lost.",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Stop scanner
                self.file_scanner.stop_scan()
                
                # Terminate thread
                self.scan_worker.terminate()
                self.scan_worker.wait()
                
                self.scan_status.setText("Scan stopped by user")
                self.scan_results.setText("Scan was cancelled. Partial results not saved.")
                self.scan_progress.setValue(0)
                self.stop_scan_btn.setVisible(False)
                
                self.log_activity("Scan stopped by user")
    
    def load_passwords(self):
        """Load passwords from database"""
        try:
            # Safety check: ensure password_table exists
            if self.password_table is None:
                return
                
            passwords = password_manager.get_all_passwords()
            self.password_table.setRowCount(len(passwords))
            
            for i, pwd in enumerate(passwords):
                self.password_table.setItem(i, 0, QTableWidgetItem(pwd.get('website', '')))
                self.password_table.setItem(i, 1, QTableWidgetItem(pwd.get('username', '')))
                self.password_table.setItem(i, 2, QTableWidgetItem(pwd.get('category', 'General')))
        except Exception as e:
            print(f"Error loading passwords: {e}")
    
    def show_threat_details(self, row_index):
        """Show threat details dialog for a specific threat"""
        try:
            from gui.threat_details import show_threat_details
            show_threat_details(self)
        except ImportError:
            QMessageBox.warning(self, "Error", "Threat details module not found.")
    
    def add_password(self):
        """Show add password dialog (FR-PM-01: AES-256 encryption, FR-PM-04: Organize by website)"""
        from PyQt5.QtWidgets import QDialog, QFormLayout, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{get_icon('password')} Add Password")
        dialog.setMinimumWidth(550)
        dialog.setMinimumHeight(600)
        
        layout = QFormLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Website/Service field
        website_input = QLineEdit()
        website_input.setPlaceholderText("e.g., gmail.com, facebook.com")
        website_input.setMinimumHeight(44)
        layout.addRow("Website/Service:", website_input)
        
        # Username/Email field
        username_input = QLineEdit()
        username_input.setPlaceholderText("e.g., user@example.com")
        username_input.setMinimumHeight(44)
        layout.addRow("Username/Email:", username_input)
        
        # Password field with show/hide toggle and generate button
        password_container = QHBoxLayout()
        password_container.setSpacing(8)
        
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.Password)
        password_input.setPlaceholderText("Enter password")
        password_input.setMinimumHeight(44)
        password_container.addWidget(password_input, 1)
        
        # Show/Hide password button
        show_password_btn = QPushButton()
        show_password_btn.setIcon(get_icon('eye', '#666'))
        show_password_btn.setIconSize(QSize(16, 16))
        show_password_btn.setFixedWidth(44)
        show_password_btn.setFixedHeight(44)
        show_password_btn.setToolTip("Show/Hide Password")
        
        def toggle_password_visibility():
            if password_input.echoMode() == QLineEdit.Password:
                password_input.setEchoMode(QLineEdit.Normal)
                show_password_btn.setIcon(get_icon('eye-slash', '#666'))
            else:
                password_input.setEchoMode(QLineEdit.Password)
                show_password_btn.setIcon(get_icon('eye', '#666'))
        
        show_password_btn.clicked.connect(toggle_password_visibility)
        password_container.addWidget(show_password_btn)
        
        # Generate password button
        generate_btn = QPushButton("  Generate")
        generate_btn.setIcon(get_icon('dice', '#ffffff'))
        generate_btn.setIconSize(QSize(16, 16))
        generate_btn.setFixedHeight(44)
        generate_btn.setMinimumWidth(100)
        
        def generate_and_update():
            generated = password_manager.generate_password(
                length=16,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_special=True
            )
            password_input.setText(generated)
            self.update_password_strength(generated, strength_label)
        
        generate_btn.clicked.connect(generate_and_update)
        password_container.addWidget(generate_btn)
        
        password_widget = QWidget()
        password_widget.setLayout(password_container)
        layout.addRow("Password:", password_widget)
        
        # Password strength indicator (FR-PM-03)
        strength_label = QLabel("")
        strength_label.setMinimumHeight(30)
        strength_label.setStyleSheet("""
            QLabel {
                padding: 6px 12px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
            }
        """)
        layout.addRow("Strength:", strength_label)
        
        # Connect password input to strength checker
        password_input.textChanged.connect(
            lambda: self.update_password_strength(password_input.text(), strength_label)
        )
        
        # Category dropdown (FR-PM-04)
        category_input = QComboBox()
        category_input.addItems([
            "General",
            "Social Media",
            "Email",
            "Banking",
            "Shopping",
            "Work",
            "Entertainment",
            "Other"
        ])
        category_input.setMinimumHeight(44)
        layout.addRow("Category:", category_input)
        
        # Notes field
        notes_input = QTextEdit()
        notes_input.setPlaceholderText("Optional notes or additional information...")
        notes_input.setMinimumHeight(90)
        notes_input.setMaximumHeight(120)
        layout.addRow("Notes:", notes_input)
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addRow("", button_box)
        
        # Apply styling to dialog
        dialog.setStyleSheet("""
            QDialog {
                background-color: #101922;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
                font-weight: 600;
            }
            QLineEdit, QComboBox {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 12px 16px;
                color: #ffffff;
                font-size: 14px;
                min-height: 20px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #1173d4;
            }
            QLineEdit::placeholder {
                color: #92adc9;
            }
            QTextEdit {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 12px 16px;
                color: #ffffff;
                font-size: 14px;
            }
            QTextEdit:focus {
                border: 2px solid #1173d4;
            }
            QPushButton {
                background-color: #1173d4;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 16px;
                font-size: 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #0d5aa7;
            }
            QComboBox {
                min-height: 44px;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid #92adc9;
                margin-right: 10px;
            }
            QDialogButtonBox QPushButton {
                min-width: 100px;
                min-height: 40px;
            }
        """)
        
        dialog.setLayout(layout)
        
        # Show dialog and handle result
        if dialog.exec_() == QDialog.Accepted:
            website = website_input.text().strip()
            username = username_input.text().strip()
            password = password_input.text()
            category = category_input.currentText()
            notes = notes_input.toPlainText().strip()
            
            # Validation
            if not website:
                QMessageBox.warning(self, "Validation Error", "Website/Service name is required")
                return
            
            if not username:
                QMessageBox.warning(self, "Validation Error", "Username/Email is required")
                return
            
            if not password:
                QMessageBox.warning(self, "Validation Error", "Password is required")
                return
            
            # Add password using password manager
            success = password_manager.add_password(
                website=website,
                username=username,
                password=password,
                category=category if category else None,
                notes=notes if notes else None
            )
            
            if success:
                QMessageBox.information(
                    self,
                    "Success",
                    f"Password for {website} has been securely saved!"
                )
                self.load_passwords()  # Refresh password table
                self.log_activity(f"Added password for {website}")
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    "Failed to save password. Please try again."
                )
    
    def update_password_strength(self, password: str, label: QLabel):
        """Update password strength indicator"""
        if not password:
            label.setText("")
            label.setStyleSheet("")
            return
        
        from security.encryption import encryption_manager
        strength = encryption_manager.evaluate_password_strength(password)
        score = strength.get('score', 0)
        
        # Determine strength level and color
        if score >= 80:
            level = "Very Strong"
            color = "#22c55e"  # Safe green
            bg_color = "rgba(34, 197, 94, 0.1)"
        elif score >= 60:
            level = "Strong"
            color = "#39FF14"  # Low green
            bg_color = "rgba(57, 255, 20, 0.1)"
        elif score >= 40:
            level = "Medium"
            color = "#eab308"  # Medium yellow
            bg_color = "rgba(234, 179, 8, 0.1)"
        elif score >= 20:
            level = "Weak"
            color = "#f97316"  # High orange
            bg_color = "rgba(249, 115, 22, 0.1)"
        else:
            level = "Very Weak"
            color = "#ef4444"  # Critical red
            bg_color = "rgba(239, 68, 68, 0.1)"
        
        label.setText(f"{level} ({score}/100)")
        label.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {bg_color};
                padding: 6px 12px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                border: 1px solid {color};
            }}
        """)
    
    def generate_password(self):
        """Generate random password"""
        pwd = password_manager.generate_password()
        QMessageBox.information(self, "Generated Password", f"Your new password:\n\n{pwd}")
    
    def analyze_text(self):
        """Analyze text for threats using NLP"""
        text = self.nlp_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Input", "Please enter text to analyze")
            return
        
        if not NLP_AVAILABLE:
            self.nlp_results.setText("NLP module not available. Please check ai/nlp_model.py implementation.")
            return
        
        try:
            detector = get_nlp_detector()
            result = detector.analyze_text(text)
            
            explanation = explainable_ai.explain_threat_detection(text, result)
            
            output = f"{explanation['explanation']}\n\n"
            output += f"Highlighted Text:\n{explanation['highlighted_text']}"
            
            self.nlp_results.setText(output)
            
        except Exception as e:
            self.nlp_results.setText(f"Analysis error: {e}")
    
    def load_quarantine(self):
        """Load quarantine list"""
        try:
            files = quarantine_manager.get_quarantined_files()
            self.quarantine_table.setRowCount(len(files))
            
            for i, file in enumerate(files):
                self.quarantine_table.setItem(i, 0, QTableWidgetItem(file['original_path']))
                self.quarantine_table.setItem(i, 1, QTableWidgetItem(file['threat_type']))
                self.quarantine_table.setItem(i, 2, QTableWidgetItem(str(file['quarantined_at'])))
        except Exception as e:
            print(f"Error loading quarantine: {e}")
    
    def refresh_quarantine(self):
        """Refresh quarantine list"""
        self.load_quarantine()
    
    def load_logs(self):
        """Load system logs"""
        try:
            events = db_manager.get_system_events(100)
            self.logs_table.setRowCount(len(events))
            
            for i, event in enumerate(events):
                self.logs_table.setItem(i, 0, QTableWidgetItem(str(event['timestamp'])))
                self.logs_table.setItem(i, 1, QTableWidgetItem(event['event_type']))
                self.logs_table.setItem(i, 2, QTableWidgetItem(event['severity']))
                self.logs_table.setItem(i, 3, QTableWidgetItem(event['message']))
        except Exception as e:
            print(f"Error loading logs: {e}")
    
    def refresh_logs(self):
        """Refresh logs table"""
        self.load_logs()
    
    def handle_logout(self):
        """Handle logout"""
        reply = QMessageBox.question(
            self,
            "Logout",
            "Are you sure you want to logout?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Stop Real-Time Protection if active
            if RTP_AVAILABLE and self.rtp_active:
                realtime_protection.stop_protection()
            
            system_monitor.stop_monitoring()
            from security.auth import auth_manager
            auth_manager.logout()
            self.close()
    
    def closeEvent(self, event):
        """Handle window close"""
        # Stop Real-Time Protection if active
        if RTP_AVAILABLE and self.rtp_active:
            realtime_protection.stop_protection()
        
        system_monitor.stop_monitoring()
        event.accept()
    
    # ==================== Real-Time Protection Methods ====================
    
    def toggle_realtime_protection(self):
        """Toggle Real-Time Protection on/off"""
        if not RTP_AVAILABLE:
            QMessageBox.warning(
                self,
                "Feature Unavailable",
                "Real-Time Protection requires additional dependencies (PIL, pytesseract).\n\n"
                "Please install: pip install Pillow pytesseract"
            )
            return
        
        if self.rtp_active:
            # Stop protection
            success = realtime_protection.stop_protection()
            if success:
                self.rtp_active = False
                self.rtp_status_label.setText("Inactive")
                self.rtp_status_label.setStyleSheet("color: #ef4444;")
                self.rtp_toggle_btn.setText("Start Real-Time Protection")
                self.rtp_toggle_btn.setIcon(get_icon('play', '#ffffff'))
                self.rtp_toggle_btn.setObjectName("successButton")
                self.rtp_toggle_btn.setStyleSheet("")  # Reset to default
                self.log_activity("Real-Time Protection stopped")
                
                QMessageBox.information(
                    self,
                    "Protection Stopped",
                    "Real-Time Protection has been deactivated."
                )
        else:
            # Start protection
            success = realtime_protection.start_protection()
            if success:
                self.rtp_active = True
                self.rtp_status_label.setText("Active - Monitoring Screen")
                self.rtp_status_label.setStyleSheet("color: #22c55e;")
                self.rtp_toggle_btn.setText("Stop Real-Time Protection")
                self.rtp_toggle_btn.setIcon(get_icon('pause', '#ffffff'))
                self.rtp_toggle_btn.setObjectName("dangerButton")
                self.rtp_toggle_btn.setStyleSheet("")  # Reset to default
                self.log_activity("Real-Time Protection started")
                
                QMessageBox.information(
                    self,
                    "Protection Active",
                    "Real-Time Protection is now monitoring your screen for threats.\n\n"
                    "You will be alerted if suspicious content is detected."
                )
            else:
                QMessageBox.critical(
                    self,
                    "Startup Failed",
                    "Failed to start Real-Time Protection.\n\n"
                    "Missing dependency: Tesseract OCR\n\n"
                    "Installation steps:\n"
                    "1. Download: https://github.com/UB-Mannheim/tesseract/wiki\n"
                    "2. Run installer (use default path)\n"
                    "3. Restart CyberGuard Pro\n\n"
                    "Check logs/cyberguard.log for details."
                )
    
    def configure_realtime_protection(self):
        """Show Real-Time Protection configuration dialog"""
        if not RTP_AVAILABLE:
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Real-Time Protection Settings")
        dialog.setMinimumWidth(500)
        dialog.setMinimumHeight(400)
        
        layout = QFormLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Scan interval
        interval_label = QLabel("Scan Interval (seconds):")
        interval_spin = QSpinBox()
        interval_spin.setMinimum(1)
        interval_spin.setMaximum(10)
        interval_spin.setValue(int(realtime_protection.scan_interval))
        interval_spin.setToolTip("How often to scan the screen (1-10 seconds)")
        layout.addRow(interval_label, interval_spin)
        
        # Threat sensitivity
        sensitivity_label = QLabel("Threat Sensitivity:")
        sensitivity_combo = QComboBox()
        sensitivity_combo.addItems(["LOW", "MEDIUM", "HIGH"])
        sensitivity_combo.setCurrentText(realtime_protection.threat_sensitivity)
        sensitivity_combo.setToolTip(
            "LOW: Only critical/high threats\n"
            "MEDIUM: Critical, high, and medium threats\n"
            "HIGH: All threat levels including low"
        )
        layout.addRow(sensitivity_label, sensitivity_combo)
        
        # Info label
        info_label = QLabel(
            "Real-Time Protection monitors your screen content and analyzes visible text "
            "for phishing, malware, and social engineering threats.\n\n"
            "Higher sensitivity may result in more alerts."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #92adc9; font-size: 11px; padding: 12px; "
                                "background-color: #192633; border-radius: 6px;")
        layout.addRow(info_label)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addRow("", button_box)
        
        dialog.setLayout(layout)
        
        # Apply dark theme
        dialog.setStyleSheet("""
            QDialog {
                background-color: #101922;
            }
            QLabel {
                color: #ffffff;
                font-size: 13px;
            }
            QSpinBox, QComboBox {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 8px 12px;
                color: #ffffff;
                min-height: 30px;
            }
            QPushButton {
                background-color: #1173d4;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #0d5aa7;
            }
        """)
        
        if dialog.exec_() == QDialog.Accepted:
            # Apply settings
            new_interval = float(interval_spin.value())
            new_sensitivity = sensitivity_combo.currentText()
            
            realtime_protection.set_scan_interval(new_interval)
            realtime_protection.set_threat_sensitivity(new_sensitivity)
            
            self.log_activity(
                f"Real-Time Protection settings updated: "
                f"Interval={new_interval}s, Sensitivity={new_sensitivity}"
            )
            
            QMessageBox.information(
                self,
                "Settings Updated",
                "Real-Time Protection settings have been updated."
            )
    
    def _on_realtime_threat_detected(self, threat_data: dict):
        """Callback when Real-Time Protection detects a threat"""
        # Emit signal to show popup on main GUI thread
        self.threat_detected_signal.emit(threat_data)
    
    def _show_threat_alert_dialog(self, threat_data: dict):
        """Show threat alert dialog (runs on main GUI thread)"""
        if not RTP_AVAILABLE:
            return
        
        try:
            # Step 1: Show compact notification in bottom-right corner
            user_wants_details = show_compact_threat_notification(threat_data, self)
            
            # Step 2: If user clicked the compact notification, show full details
            if user_wants_details:
                action = show_realtime_threat_alert(threat_data, self)
                
                # Log action to activity
                threat_level = threat_data.get('level', 'UNKNOWN')
                self.log_activity(
                    f"Real-Time Threat Detected: {threat_level} - Action: {action}"
                )
                
                # Handle user action
                if action == "BLOCK":
                    # User chose to block/close
                    QMessageBox.information(
                        self,
                        "Threat Blocked",
                        "Please close the suspicious window or application immediately."
                    )
            else:
                # User dismissed compact notification
                threat_level = threat_data.get('level', 'UNKNOWN')
                self.log_activity(
                    f"Real-Time Threat Detected: {threat_level} - Dismissed from notification"
                )
                
        except Exception as e:
            print(f"Error showing threat alert: {e}")
            import traceback
            traceback.print_exc()
