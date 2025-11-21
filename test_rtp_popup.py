"""
Test RTP Popup System with Phishing Content Display
"""
import sys
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

class PhishingTestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Banking Portal - Login Required")
        self.setGeometry(100, 100, 800, 600)
        
        # Create widget
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(30)
        
        # Add phishing content that should trigger detection
        phishing_texts = [
            "⚠️ URGENT ACTION REQUIRED",
            "Your account has been suspended!",
            "Click here to verify your account immediately",
            "Update payment method within 24 hours",
            "Enter your password to confirm identity",
            "Verify your credit card details now",
            "Act now or your account will be permanently locked",
            "Send money via wire transfer to reactivate",
            "You have won $10,000! Claim your prize",
            "Limited time offer - expires today!",
        ]
        
        for text in phishing_texts:
            label = QLabel(text)
            label.setFont(QFont("Arial", 18, QFont.Bold))
            label.setAlignment(Qt.AlignCenter)
            label.setWordWrap(True)
            label.setStyleSheet("""
                QLabel {
                    color: red;
                    padding: 20px;
                    background-color: #fff3cd;
                    border: 3px solid #ff0000;
                }
            """)
            layout.addWidget(label)
        
        widget.setLayout(layout)
        self.setCentralWidget(widget)
        
        # Auto-close after 30 seconds
        QTimer.singleShot(30000, self.close)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    print("="*70)
    print("RTP POPUP TEST - PHISHING CONTENT DISPLAY")
    print("="*70)
    print("\nThis window will display phishing content for 30 seconds.")
    print("If Real-Time Protection is active, you should see:")
    print("  1. Compact notification in bottom-right corner")
    print("  2. Click it to see full threat alert")
    print("\nMake sure RTP is STARTED in the CyberGuard Pro dashboard!")
    print("="*70)
    print("\nDisplaying phishing content now...\n")
    
    window = PhishingTestWindow()
    window.show()
    window.raise_()
    window.activateWindow()
    
    sys.exit(app.exec_())
