"""
Popup Alert System
Displays real-time security alerts and notifications
"""

import sys
import os
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QListWidget, QListWidgetItem,
                             QWidget, QApplication)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QFont

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.styles import get_icon


class ThreatAlert(QDialog):
    """
    Popup alert for security threats
    """
    
    def __init__(self, threat_data: dict, parent=None):
        super().__init__(parent)
        self.threat_data = threat_data
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("Security Alert")
        self.setFixedSize(500, 350)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.Dialog)
        
        # Styling
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            }
            QLabel {
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Space Grotesk', sans-serif;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QTextEdit {
                background-color: #3c3c3c;
                border: 2px solid #555555;
                border-radius: 5px;
                padding: 5px;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title_layout = QHBoxLayout()
        
        title_icon = QLabel()
        title_icon.setPixmap(get_icon('exclamation-triangle', '#ff5555').pixmap(24, 24))
        title_layout.addWidget(title_icon)
        
        title = QLabel("THREAT DETECTED")
        title.setFont(QFont("Space Grotesk", 16, QFont.Bold))
        title.setStyleSheet("color: #ff5555;")
        title_layout.addWidget(title, 1)
        
        layout.addLayout(title_layout)
        
        # Threat level
        level = self.threat_data.get('level', 'UNKNOWN')
        level_color = self.get_level_color(level)
        
        level_label = QLabel(f"Severity: {level}")
        level_label.setFont(QFont("Space Grotesk", 12, QFont.Bold))
        level_label.setAlignment(Qt.AlignCenter)
        level_label.setStyleSheet(f"color: {level_color};")
        layout.addWidget(level_label)
        
        # Threat details
        details_label = QLabel("Threat Details:")
        details_label.setFont(QFont("Space Grotesk", 10, QFont.Bold))
        layout.addWidget(details_label)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        details_text.setMaximumHeight(150)
        
        details_str = f"Type: {self.threat_data.get('type', 'Unknown')}\n"
        details_str += f"Source: {self.threat_data.get('source', 'Unknown')}\n\n"
        details_str += f"Details:\n{self.threat_data.get('details', {})}"
        
        details_text.setText(details_str)
        layout.addWidget(details_text)
        
        # Actions taken
        actions = self.threat_data.get('actions_taken', [])
        if actions:
            actions_label = QLabel(f"Actions Taken: {', '.join(actions)}")
            actions_label.setWordWrap(True)
            actions_label.setStyleSheet("color: #4CAF50;")
            layout.addWidget(actions_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        view_details_btn = QPushButton("View Full Details")
        view_details_btn.clicked.connect(self.view_details)
        button_layout.addWidget(view_details_btn)
        
        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.clicked.connect(self.accept)
        button_layout.addWidget(dismiss_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def get_level_color(self, level: str) -> str:
        """Get color for threat level"""
        colors = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff5555',
            'MEDIUM': '#ffaa00',
            'LOW': '#ffff00',
            'SAFE': '#4CAF50'
        }
        return colors.get(level, '#ffffff')
    
    def view_details(self):
        """View detailed threat information"""
        # Could open a more detailed window
        # For now, just show message
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.information(
            self,
            "Threat Details",
            f"Full details:\n\n{self.threat_data}"
        )


class InfoNotification(QDialog):
    """
    Info notification popup
    """
    
    def __init__(self, title: str, message: str, parent=None, auto_close: int = 0):
        super().__init__(parent)
        self.auto_close = auto_close
        self.init_ui(title, message)
        
        if auto_close > 0:
            QTimer.singleShot(auto_close * 1000, self.accept)
    
    def init_ui(self, title: str, message: str):
        """Initialize UI"""
        self.setWindowTitle(title)
        self.setFixedSize(400, 200)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            }
            QLabel {
                color: #ffffff;
                font-family: 'Space Grotesk', sans-serif;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-family: 'Space Grotesk', sans-serif;
                font-weight: bold;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Message
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg_label)
        
        layout.addStretch()
        
        # OK button
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)
        
        self.setLayout(layout)


def show_threat_alert(threat_data: dict):
    """
    Display threat alert popup
    
    Args:
        threat_data: Threat information dictionary
    """
    alert = ThreatAlert(threat_data)
    alert.exec_()


def show_notification(title: str, message: str, auto_close: int = 5):
    """
    Display info notification
    
    Args:
        title: Notification title
        message: Notification message
        auto_close: Auto-close after seconds (0 = manual close)
    """
    notification = InfoNotification(title, message, auto_close=auto_close)
    notification.exec_()


class RealTimeThreatAlert(QDialog):
    """
    Enhanced popup alert for Real-Time Protection threats
    Displays detailed threat information with recommended actions
    """
    
    action_taken = pyqtSignal(str)  # Signal emitted when action button clicked
    
    def __init__(self, threat_data: dict, parent=None):
        super().__init__(parent)
        self.threat_data = threat_data
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("Real-Time Protection Alert")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.Dialog)  # type: ignore
        
        # Modern dark theme styling
        self.setStyleSheet("""
            QDialog {
                background-color: #101922;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QPushButton {
                background-color: #1173d4;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #0d5aa7;
            }
            QPushButton#ignoreButton {
                background-color: #233648;
            }
            QPushButton#ignoreButton:hover {
                background-color: #324d67;
            }
            QPushButton#blockButton {
                background-color: #ef4444;
            }
            QPushButton#blockButton:hover {
                background-color: #dc2626;
            }
            QTextEdit {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 12px;
                color: #ffffff;
                font-size: 13px;
            }
            QListWidget {
                background-color: #192633;
                border: 1px solid #324d67;
                border-radius: 8px;
                padding: 8px;
                color: #ffffff;
                font-size: 13px;
            }
            QListWidget::item {
                padding: 6px;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background-color: #233648;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title with icon
        title_layout = QHBoxLayout()
        
        threat_icon = QLabel()
        threat_icon.setPixmap(get_icon('exclamation-triangle', '#ef4444').pixmap(32, 32))
        title_layout.addWidget(threat_icon)
        
        title_label = QLabel("THREAT DETECTED")
        title_label.setFont(QFont("Poppins", 18, QFont.Bold))
        title_label.setStyleSheet("color: #ef4444;")
        title_layout.addWidget(title_label, 1)
        layout.addLayout(title_layout)
        
        # Threat level badge
        level = self.threat_data.get('level', 'UNKNOWN')
        confidence = self.threat_data.get('confidence', 0)
        
        level_layout = QHBoxLayout()
        level_label = QLabel(f"Threat Level: {level}")
        level_label.setFont(QFont("Poppins", 14, QFont.Bold))
        level_label.setStyleSheet(self._get_level_style(level))
        level_layout.addWidget(level_label)
        
        confidence_label = QLabel(f"Confidence: {confidence:.1f}%")
        confidence_label.setFont(QFont("Poppins", 12))
        confidence_label.setStyleSheet("color: #92adc9;")
        level_layout.addWidget(confidence_label)
        level_layout.addStretch()
        
        layout.addLayout(level_layout)
        
        # Description
        desc_label = QLabel("Threat Description:")
        desc_label.setFont(QFont("Poppins", 11, QFont.Bold))
        desc_label.setStyleSheet("color: #92adc9; margin-top: 8px;")
        layout.addWidget(desc_label)
        
        description = self.threat_data.get('description', 'Unknown threat detected')
        desc_text = QTextEdit()
        desc_text.setReadOnly(True)
        desc_text.setPlainText(description)
        desc_text.setMaximumHeight(80)
        layout.addWidget(desc_text)
        
        # Detected patterns
        patterns = self.threat_data.get('patterns', [])
        if patterns:
            patterns_label = QLabel("Detected Patterns:")
            patterns_label.setFont(QFont("Poppins", 11, QFont.Bold))
            patterns_label.setStyleSheet("color: #92adc9; margin-top: 8px;")
            layout.addWidget(patterns_label)
            
            patterns_text = QLabel("• " + "\n• ".join(patterns))
            patterns_text.setWordWrap(True)
            patterns_text.setStyleSheet("color: #f97316; padding: 8px; font-size: 12px;")
            layout.addWidget(patterns_text)
        
        # Recommended actions
        actions = self.threat_data.get('recommended_actions', [])
        if actions:
            actions_label = QLabel("Recommended Actions:")
            actions_label.setFont(QFont("Poppins", 11, QFont.Bold))
            actions_label.setStyleSheet("color: #92adc9; margin-top: 8px;")
            layout.addWidget(actions_label)
            
            actions_list = QListWidget()
            actions_list.setMaximumHeight(150)
            for action in actions:
                item = QListWidgetItem(action)
                item.setFont(QFont("Segoe UI", 11))
                actions_list.addItem(item)
            layout.addWidget(actions_list)
        
        # Source info (small text)
        source_label = QLabel(f"Source: {self.threat_data.get('source', 'Unknown')}")
        source_label.setStyleSheet("color: #92adc9; font-size: 10px; margin-top: 8px;")
        layout.addWidget(source_label)
        
        layout.addStretch()
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        # Ignore button
        ignore_btn = QPushButton("  Dismiss")
        ignore_btn.setIcon(get_icon('check', '#ffffff'))
        ignore_btn.setIconSize(QSize(16, 16))
        ignore_btn.setObjectName("ignoreButton")
        ignore_btn.setMinimumHeight(44)
        ignore_btn.clicked.connect(lambda: self._handle_action("DISMISS"))
        button_layout.addWidget(ignore_btn)
        
        # View details button
        details_btn = QPushButton("  View Details")
        details_btn.setIcon(get_icon('info-circle', '#ffffff'))
        details_btn.setIconSize(QSize(16, 16))
        details_btn.setMinimumHeight(44)
        details_btn.clicked.connect(self._show_details)
        button_layout.addWidget(details_btn)
        
        # Block action button (if HIGH/CRITICAL)
        if level in ['HIGH', 'CRITICAL']:
            block_btn = QPushButton("  Block & Close")
            block_btn.setIcon(get_icon('ban', '#ffffff'))
            block_btn.setIconSize(QSize(16, 16))
            block_btn.setObjectName("blockButton")
            block_btn.setMinimumHeight(44)
            block_btn.clicked.connect(lambda: self._handle_action("BLOCK"))
            button_layout.addWidget(block_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _get_level_style(self, level: str) -> str:
        """Get CSS style for threat level"""
        styles = {
            'CRITICAL': 'color: #ef4444; background-color: rgba(239, 68, 68, 0.1); padding: 8px 16px; border-radius: 6px; border: 1px solid #ef4444;',
            'HIGH': 'color: #f97316; background-color: rgba(249, 115, 22, 0.1); padding: 8px 16px; border-radius: 6px; border: 1px solid #f97316;',
            'MEDIUM': 'color: #eab308; background-color: rgba(234, 179, 8, 0.1); padding: 8px 16px; border-radius: 6px; border: 1px solid #eab308;',
            'LOW': 'color: #39FF14; background-color: rgba(57, 255, 20, 0.1); padding: 8px 16px; border-radius: 6px; border: 1px solid #39FF14;',
            'SAFE': 'color: #22c55e; background-color: rgba(34, 197, 94, 0.1); padding: 8px 16px; border-radius: 6px; border: 1px solid #22c55e;'
        }
        return styles.get(level, styles['MEDIUM'])
    
    def _handle_action(self, action: str):
        """Handle action button click"""
        self.action_taken.emit(action)
        self.accept()
    
    def _show_details(self):
        """Show detailed threat information"""
        from PyQt5.QtWidgets import QMessageBox
        
        details_text = "Full Threat Analysis\n" + "="*50 + "\n\n"
        details_text += f"Threat Level: {self.threat_data.get('level', 'Unknown')}\n"
        details_text += f"Confidence: {self.threat_data.get('confidence', 0):.1f}%\n"
        details_text += f"Source: {self.threat_data.get('source', 'Unknown')}\n"
        details_text += f"Timestamp: {self.threat_data.get('timestamp', 'Unknown')}\n\n"
        
        patterns = self.threat_data.get('patterns', [])
        if patterns:
            details_text += "Detected Patterns:\n"
            for pattern in patterns:
                details_text += f"  • {pattern}\n"
            details_text += "\n"
        
        keywords = self.threat_data.get('keywords', [])
        if keywords:
            details_text += "Suspicious Keywords:\n"
            for keyword in keywords[:10]:  # Show first 10
                details_text += f"  • {keyword}\n"
            details_text += "\n"
        
        sample = self.threat_data.get('screen_text_sample', '')
        if sample:
            details_text += f"Screen Text Sample:\n{sample}\n"
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Threat Details")
        msg_box.setText(details_text)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.exec_()


def show_realtime_threat_alert(threat_data: dict, parent=None) -> str:
    """
    Display real-time threat alert popup
    
    Args:
        threat_data: Threat information dictionary
        parent: Parent widget
        
    Returns:
        Action taken by user ("DISMISS", "BLOCK", or "")
    """
    alert = RealTimeThreatAlert(threat_data, parent)
    
    action_result = [""]
    
    def on_action(action: str):
        action_result[0] = action
    
    alert.action_taken.connect(on_action)
    alert.exec_()
    
    return action_result[0]


class CompactThreatNotification(QDialog):
    """
    Small notification that appears in bottom-right corner
    Expands to full alert when clicked
    """
    
    clicked = pyqtSignal()
    dismissed = pyqtSignal()
    
    def __init__(self, threat_data: dict, parent=None):
        super().__init__(parent)
        self.threat_data = threat_data
        self.setWindowFlags(
            Qt.WindowStaysOnTopHint |  # type: ignore
            Qt.FramelessWindowHint |  # type: ignore
            Qt.Tool  # type: ignore
        )
        self.setAttribute(Qt.WA_TranslucentBackground)  # type: ignore
        self.init_ui()
        self.position_bottom_right()
        
        # Auto-dismiss timer (30 seconds)
        self.auto_dismiss_timer = QTimer()
        self.auto_dismiss_timer.timeout.connect(self.fade_out)
        self.auto_dismiss_timer.start(30000)
    
    def init_ui(self):
        """Initialize compact notification UI"""
        self.setMinimumWidth(350)
        self.setMaximumWidth(400)
        
        # Main container
        container = QWidget()
        container.setObjectName("notificationContainer")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        
        # Header row: icon + level + close button
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)
        
        # Threat icon
        level = self.threat_data.get('level', 'UNKNOWN')
        icon_name = self._get_threat_icon(level)
        icon_color = self._get_level_color(level)
        
        icon_label = QLabel()
        icon_label.setPixmap(get_icon(icon_name, icon_color).pixmap(20, 20))
        header_layout.addWidget(icon_label)
        
        # Threat level badge
        level_label = QLabel(level)
        level_label.setFont(QFont("Poppins", 11, QFont.Bold))
        level_label.setStyleSheet(f"""color: {self._get_level_color(level)}; padding: 4px 8px; 
                                     background-color: {self._get_level_bg(level)}; border-radius: 4px;""")
        header_layout.addWidget(level_label)
        
        # Confidence
        confidence = self.threat_data.get('confidence', 0)
        conf_label = QLabel(f"{confidence:.0f}%")
        conf_label.setFont(QFont("Poppins", 10))
        conf_label.setStyleSheet("color: #92adc9;")
        header_layout.addWidget(conf_label)
        
        header_layout.addStretch()
        
        # Close button
        close_btn = QPushButton()
        close_btn.setIcon(get_icon('times', '#92adc9'))
        close_btn.setIconSize(QSize(16, 16))
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
            }
            QPushButton:hover {
                background-color: rgba(239, 68, 68, 0.1);
                border-radius: 4px;
            }
        """)
        close_btn.clicked.connect(self.dismiss)
        header_layout.addWidget(close_btn)
        
        layout.addLayout(header_layout)
        
        # Source
        source = self.threat_data.get('source', 'Real-Time Protection')
        source_label = QLabel(f"Source: {source}")
        source_label.setFont(QFont("Segoe UI", 9))
        source_label.setStyleSheet("color: #92adc9;")
        layout.addWidget(source_label)
        
        # Content excerpt (10-15 words)
        excerpt = self._get_content_excerpt()
        if excerpt:
            excerpt_label = QLabel(f'"...{excerpt}..."')
            excerpt_label.setFont(QFont("Segoe UI", 10))
            excerpt_label.setStyleSheet("color: #ffffff; font-style: italic; padding: 6px; "
                                       "background-color: rgba(255, 255, 255, 0.05); border-radius: 4px;")
            excerpt_label.setWordWrap(True)
            layout.addWidget(excerpt_label)
        
        # Click hint
        hint_layout = QHBoxLayout()
        hint_icon = QLabel()
        hint_icon.setPixmap(get_icon('search', '#1173d4').pixmap(12, 12))
        hint_layout.addWidget(hint_icon)
        
        hint_label = QLabel("Click for details")
        hint_label.setFont(QFont("Segoe UI", 9))
        hint_label.setStyleSheet("color: #1173d4; padding-top: 4px;")
        hint_layout.addWidget(hint_label)
        hint_layout.addStretch()
        
        layout.addLayout(hint_layout)
        
        container.setLayout(layout)
        
        # Container styling
        container.setStyleSheet("""
            #notificationContainer {
                background-color: #111a22;
                border: 2px solid #1173d4;
                border-radius: 12px;
            }
        """)
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)
        self.setLayout(main_layout)
        
        # Make entire notification clickable
        container.mousePressEvent = lambda event: self.open_detailed_alert()
    
    def position_bottom_right(self):
        """Position notification in bottom-right corner of screen"""
        from PyQt5.QtWidgets import QApplication
        screen = QApplication.desktop().screenGeometry()
        
        # Position: 40-50px from right, 90px from bottom (moved left and up)
        x = screen.width() - self.width() - 70
        y = screen.height() - self.height() - 250
        
        self.move(x, y)
    
    def _get_threat_icon(self, level: str) -> str:
        """Get icon name for threat level"""
        icons = {
            'CRITICAL': 'exclamation-triangle',
            'HIGH': 'exclamation-triangle',
            'MEDIUM': 'bolt',
            'LOW': 'info-circle',
            'SAFE': 'check-circle'
        }
        return icons.get(level, 'exclamation-triangle')
    
    def _get_level_color(self, level: str) -> str:
        """Get color for threat level"""
        colors = {
            'CRITICAL': '#ef4444',
            'HIGH': '#f97316',
            'MEDIUM': '#eab308',
            'LOW': '#39FF14',
            'SAFE': '#22c55e'
        }
        return colors.get(level, '#eab308')
    
    def _get_level_bg(self, level: str) -> str:
        """Get background color for threat level"""
        bgs = {
            'CRITICAL': 'rgba(239, 68, 68, 0.15)',
            'HIGH': 'rgba(249, 115, 22, 0.15)',
            'MEDIUM': 'rgba(234, 179, 8, 0.15)',
            'LOW': 'rgba(57, 255, 20, 0.15)',
            'SAFE': 'rgba(34, 197, 94, 0.15)'
        }
        return bgs.get(level, 'rgba(234, 179, 8, 0.15)')
    
    def _get_content_excerpt(self) -> str:
        """Get 10-15 word excerpt from detected content"""
        sample = self.threat_data.get('screen_text_sample', '')
        if not sample:
            # Try keywords
            keywords = self.threat_data.get('keywords', [])
            if keywords:
                return ' '.join(keywords[:3])
            return ''
        
        # Get first 15 words
        words = sample.split()
        excerpt_words = words[:15]
        excerpt = ' '.join(excerpt_words)
        
        # Truncate if too long
        if len(excerpt) > 100:
            excerpt = excerpt[:100]
        
        return excerpt
    
    def open_detailed_alert(self):
        """Open the full detailed alert dialog"""
        self.auto_dismiss_timer.stop()
        self.clicked.emit()
        self.accept()
    
    def dismiss(self):
        """Dismiss the notification"""
        self.auto_dismiss_timer.stop()
        self.dismissed.emit()
        self.accept()
    
    def fade_out(self):
        """Fade out and close notification"""
        self.dismiss()


def show_compact_threat_notification(threat_data: dict, parent=None) -> bool:
    """
    Show compact threat notification in bottom-right corner
    
    Args:
        threat_data: Threat information dictionary
        parent: Parent widget
        
    Returns:
        True if user clicked to see details, False if dismissed
    """
    notification = CompactThreatNotification(threat_data, parent)
    
    user_clicked = [False]
    
    def on_clicked():
        user_clicked[0] = True
    
    notification.clicked.connect(on_clicked)
    notification.exec_()
    
    return user_clicked[0]
