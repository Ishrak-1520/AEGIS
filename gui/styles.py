"""
CyberGuard Pro - Universal Stylesheet
Modern cyber defense theme with Neon Cyber design
"""

# Main application stylesheet
MAIN_STYLESHEET = """
    QMainWindow, QWidget {
        background-color: #050505;
        color: #e0e0e0;
        font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', sans-serif;
        font-size: 14px;
    }
    QTabWidget::pane {
        border: 1px solid #00f3ff;
        background-color: rgba(10, 10, 10, 0.8);
        border-radius: 12px;
        margin-top: -1px;
    }
    QTabBar::tab {
        background-color: #0a0a0a;
        color: #00f3ff;
        padding: 12px 24px;
        margin-right: 4px;
        border: 1px solid #333;
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        font-weight: 600;
        font-size: 13px;
        min-width: 120px;
        min-height: 30px;
        transition: all 0.3s ease;
    }
    QTabBar::tab:selected {
        background-color: rgba(0, 243, 255, 0.1);
        color: #00f3ff;
        border: 1px solid #00f3ff;
        border-bottom: 1px solid #050505;
    }
    QTabBar::tab:hover {
        background-color: rgba(0, 243, 255, 0.05);
        color: #ffffff;
        border-color: #00f3ff;
    }
    QPushButton {
        background-color: rgba(0, 243, 255, 0.1);
        color: #00f3ff;
        border: 1px solid #00f3ff;
        border-radius: 6px;
        padding: 10px 20px;
        font-weight: 600;
        font-size: 14px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    QPushButton:hover {
        background-color: #00f3ff;
        color: #000000;

    }
    QPushButton:pressed {
        background-color: #00c2cc;
        color: #000000;
    }
    QPushButton#secondaryButton {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid #444;
        color: #aaa;
    }
    QPushButton#secondaryButton:hover {
        background-color: rgba(255, 255, 255, 0.1);
        color: #fff;
        border-color: #fff;
    }
    QPushButton#dangerButton {
        background-color: rgba(255, 0, 60, 0.1);
        color: #ff003c;
        border: 1px solid #ff003c;
    }
    QPushButton#dangerButton:hover {
        background-color: #ff003c;
        color: #ffffff;

    }
    QPushButton#successButton {
        background-color: rgba(10, 255, 10, 0.1);
        color: #0aff0a;
        border: 1px solid #0aff0a;
    }
    QPushButton#successButton:hover {
        background-color: #0aff0a;
        color: #000000;

    }
    QGroupBox {
        background-color: rgba(20, 20, 20, 0.6);
        border: 1px solid #333;
        border-radius: 12px;
        margin-top: 24px;
        padding-top: 24px;
        font-weight: 600;
    }
    QGroupBox::title {
        color: #00f3ff;
        subcontrol-origin: margin;
        left: 16px;
        padding: 0 8px;
        font-size: 15px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    QTableWidget {
        background-color: rgba(10, 10, 10, 0.8);
        gridline-color: #333;
        color: #e0e0e0;
        border: 1px solid #333;
        border-radius: 8px;
        selection-background-color: rgba(0, 243, 255, 0.2);
        selection-color: #ffffff;
    }
    QHeaderView::section {
        background-color: #0f0f0f;
        color: #00f3ff;
        padding: 10px;
        border: none;
        border-bottom: 1px solid #00f3ff;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 12px;
    }
    QLineEdit, QTextEdit, QComboBox, QSpinBox {
        background-color: #0a0a0a;
        border: 1px solid #333;
        border-radius: 6px;
        padding: 10px 12px;
        color: #ffffff;
        selection-background-color: #00f3ff;
        selection-color: #000000;
    }
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
        border: 1px solid #00f3ff;
        background-color: #0f0f0f;
    }
    QLineEdit::placeholder, QTextEdit::placeholder {
        color: #555;
    }
    QProgressBar {
        border: 1px solid #333;
        border-radius: 6px;
        text-align: center;
        background-color: #0a0a0a;
        color: #ffffff;
        font-weight: 600;
    }
    QProgressBar::chunk {
        background-color: #00f3ff;
        border-radius: 5px;
    }
    QLabel {
        color: #e0e0e0;
    }
    QLabel#statusGood {
        color: #0aff0a;
        font-weight: bold;
        text-shadow: 0 0 5px #0aff0a;
    }
    QLabel#statusWarning {
        color: #eab308;
        font-weight: bold;
    }
    QLabel#statusDanger {
        color: #ff003c;
        font-weight: bold;
        text-shadow: 0 0 5px #ff003c;
    }
    QLabel#subtitleText {
        color: #888;
    }
    QLabel#errorLabel {
        color: #ff003c;
    }
    QLabel#successLabel {
        color: #0aff0a;
    }
    
    /* Scrollbar Styling */
    QScrollBar:vertical {
        border: none;
        background: #050505;
        width: 10px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:vertical {
        background: #333;
        min-height: 20px;
        border-radius: 5px;
    }
    QScrollBar::handle:vertical:hover {
        background: #00f3ff;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: none;
        background: none;
    }
"""

# Login window stylesheet
LOGIN_STYLESHEET = """
    QWidget {
        background-color: #050505;
        color: #ffffff;
        font-family: 'Segoe UI', 'Roboto', sans-serif;
    }
    QLineEdit {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid #333;
        border-radius: 6px;
        padding: 12px 16px;
        color: #ffffff;
        font-size: 14px;
        min-height: 20px;
    }
    QLineEdit:focus {
        border: 1px solid #00f3ff;
        background-color: rgba(0, 243, 255, 0.05);
    }
    QLineEdit::placeholder {
        color: #666;
        font-size: 13px;
    }
    QPushButton {
        background-color: rgba(0, 243, 255, 0.1);
        color: #00f3ff;
        border: 1px solid #00f3ff;
        border-radius: 6px;
        padding: 14px;
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    QPushButton:hover {
        background-color: #00f3ff;
        color: #000000;

    }
    QPushButton:pressed {
        background-color: #00c2cc;
        color: #000000;
    }
    QPushButton#secondaryButton {
        background-color: transparent;
        border: 1px solid #444;
        color: #aaa;
    }
    QPushButton#secondaryButton:hover {
        border-color: #fff;
        color: #fff;
    }
    QLabel {
        color: #ffffff;
    }
    QLabel#errorLabel {
        color: #ff003c;
    }
    QLabel#successLabel {
        color: #0aff0a;
    }
"""

# Component-specific stylesheets
HEADER_STYLESHEET = "background-color: #0a0a0a; border-bottom: 1px solid #333; padding: 16px;"

LOGOUT_BUTTON_STYLESHEET = """
    QPushButton {
        padding: 8px 20px;
        font-size: 14px;
        background-color: rgba(255, 0, 60, 0.1);
        color: #ff003c;
        border: 1px solid #ff003c;
    }
    QPushButton:hover {
        background-color: #ff003c;
        color: white;
    }
"""

SCAN_BUTTON_PRIMARY_STYLESHEET = """
    QPushButton {
        background-color: rgba(0, 243, 255, 0.1);
        color: #00f3ff;
        border: 1px solid #00f3ff;
        min-height: 44px;
        font-size: 14px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #00f3ff;
        color: black;

    }
"""

SCAN_BUTTON_SECONDARY_STYLESHEET = """
    QPushButton {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid #444;
        color: #aaa;
        min-height: 44px;
        font-size: 14px;
    }
    QPushButton:hover {
        background-color: rgba(255, 255, 255, 0.1);
        color: #ffffff;
        border-color: #ffffff;
    }
"""

NLP_INPUT_STYLESHEET = """
    QTextEdit {
        background-color: #0a0a0a;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 12px;
        font-size: 13px;
        color: #e0e0e0;
    }
    QTextEdit:focus {
        border: 1px solid #00f3ff;
        background-color: #0f0f0f;
    }
"""

NLP_ANALYZE_BUTTON_STYLESHEET = """
    QPushButton {
        background-color: rgba(10, 255, 10, 0.1);
        color: #0aff0a;
        border: 1px solid #0aff0a;
        font-weight: 700;
        font-size: 14px;
    }
    QPushButton:hover {
        background-color: #0aff0a;
        color: #000000;

    }
"""

NLP_GROUPBOX_STYLESHEET = """
    QGroupBox {
        background-color: rgba(20, 20, 20, 0.6);
        border: 1px solid #333;
        border-radius: 12px;
        padding: 16px;
        font-size: 16px;
        font-weight: 700;
    }
"""

NLP_RESULTS_STYLESHEET = """
    QTextEdit {
        background-color: #0a0a0a;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 12px;
        font-size: 13px;
        line-height: 1.6;
        color: #e0e0e0;
    }
"""

STAT_BOX_STYLESHEET = """
    QGroupBox {
        background-color: rgba(20, 20, 20, 0.6);
        border: 1px solid #333;
        border-radius: 12px;
        padding: 24px;
    }
    QGroupBox:hover {
        border: 1px solid #00f3ff;

    }
"""

# Cyber defense color palette (Neon Cyber)
COLORS = {
    'primary': '#00f3ff',
    'background_dark': '#050505',
    'background_light': '#0a0a0a',
    'surface': '#141414',
    'border': '#333333',
    'text_primary': '#ffffff',
    'text_secondary': '#aaaaaa',
    'critical': '#ff003c',
    'high': '#ff8800',
    'medium': '#eab308',
    'low': '#0aff0a',
    'safe': '#0aff0a',
    'accent_dim': 'rgba(0, 243, 255, 0.1)',
}

def get_color(name: str) -> str:
    """Get color value by name"""
    return COLORS.get(name, '#ffffff')

import qtawesome as qta
from PyQt5.QtGui import QIcon, QColor

# Professional icon mapping using FontAwesome
ICON_MAP = {
    'home': 'fa5s.tachometer-alt',
    'scan': 'fa5s.shield-alt',
    'monitor': 'fa5s.desktop',
    'password': 'fa5s.key',
    'analyzer': 'fa5s.brain',
    'quarantine': 'fa5s.exclamation-triangle',
    'logs': 'fa5s.file-alt',
    'shield': 'fa5s.shield-alt',
    'search': 'fa5s.search',
    'folder': 'fa5s.folder-open',
    'lock': 'fa5s.lock',
    'user': 'fa5s.user-circle',
    'logout': 'fa5s.sign-out-alt',
    'settings': 'fa5s.cog',
    'check': 'fa5s.check-circle',
    'close': 'fa5s.times',
    'info': 'fa5s.info-circle',
    'warning': 'fa5s.exclamation-circle',
    'error': 'fa5s.times-circle',
    'success': 'fa5s.check',
    'plus': 'fa5s.plus',
    'edit': 'fa5s.pen',
    'trash': 'fa5s.trash-alt',
    'copy': 'fa5s.copy',
    'eye': 'fa5s.eye',
    'eye-slash': 'fa5s.eye-slash',
    'refresh': 'fa5s.sync-alt',
    'upload': 'fa5s.file-upload',
    'link': 'fa5s.link',
    'chart': 'fa5s.chart-bar',
    'bug': 'fa5s.bug',
    'file': 'fa5s.file',
    'restore': 'fa5s.trash-restore',
}

def get_icon(name: str, color: str = None) -> QIcon:
    """Get QIcon by name using qtawesome"""
    icon_name = ICON_MAP.get(name, 'fa5s.question-circle')
    
    if color:
        return qta.icon(icon_name, color=color)
    else:
        return qta.icon(icon_name, color=COLORS['primary'])

