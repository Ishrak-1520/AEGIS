# 🛡️ AEGIS - AI-Powered Autonomous Cyber Defense

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Status](https://img.shields.io/badge/status-Production%20Ready-success)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![React](https://img.shields.io/badge/react-19.2.0-blue)
![License](https://img.shields.io/badge/license-Educational-orange)

**Next-Generation Cybersecurity Suite with AI-Powered Threat Detection**

*Advanced Endpoint Guard & Intelligence System*

[Features](#-key-features) • [Installation](#-installation) • [Usage](#-usage-guide) • [Documentation](#-documentation) • [Architecture](#️-architecture)

</div>

---

## 📌 Overview

**AEGIS** (Advanced Endpoint Guard & Intelligence System) is a comprehensive desktop cybersecurity application with a modern React-based interface and powerful Python backend. It provides real-time system protection, AI-powered threat detection, advanced malware scanning with YARA integration, secure password management, and explainable AI for transparent security decisions.

### 🎯 Why AEGIS?

- **Modern React Interface**: Premium Neon Cyber theme with glassmorphism design
- **Real-Time Protection (RTP)**: Advanced file system monitoring with YARA rule integration
- **AI-Powered Detection**: Transformer-based NLP models for phishing and social engineering detection
- **Explainable AI**: Transparent security decisions with highlighted threat indicators
- **True Threat Prevention**: Automated quarantine with AES-256 encryption
- **System-Wide Alerts**: Native notifications + in-app popups with Game Mode support
- **PII Detection**: Advanced regex-based personally identifiable information detection
- **Production Ready**: Fully functional with comprehensive testing and documentation

---

## ✨ Key Features

### 🔍 Real-Time Protection (RTP)
- **File System Monitoring**: Watchdog-based real-time file change detection
- **YARA Integration**: Advanced pattern matching for malware signatures
- **Auto-Quarantine**: Instant threat isolation with encryption
- **Game Mode**: Zero-interruption gaming with background protection
- **Native Notifications**: System-wide alerts outside the application

### 🤖 AI-Powered Threat Detection
- **NLP Analysis**: DistilBERT transformer model for content analysis
- **PII Detection**: Regex-based detection of SSN, credit cards, emails, and sensitive data
- **Heuristic Scoring**: Multi-factor threat assessment
- **Keyword Highlighting**: Visual explanations of threat indicators
- **Multi-Category Detection**: Phishing, scams, social engineering, malware links

### 🦠 Advanced Malware Scanning
- **YARA Rules**: Industry-standard pattern matching
- **Multi-Hash Algorithms**: MD5, SHA-1, SHA-256 file verification
- **Recursive Scanning**: Deep directory traversal
- **Scan Types**: Quick scan, full scan, custom directory scan
- **Detailed Reporting**: Comprehensive scan results with threat metadata

### 🔐 Password Management
- **AES-256-GCM Encryption**: Military-grade password storage
- **PBKDF2 Key Derivation**: 100,000 iterations with unique salts
- **Password Generator**: Customizable strength and character sets
- **Strength Evaluation**: Real-time password security assessment
- **Category Organization**: Flexible password categorization

### 📊 System Monitoring
- **Resource Tracking**: Real-time CPU, memory, disk, and network usage
- **Process Analysis**: Top consumers and suspicious process detection
- **Connection Monitoring**: Active network connections with threat detection
- **Anomaly Detection**: Behavioral analysis of system processes

### 🗃️ Secure Quarantine System
- **Encrypted Storage**: AES-256 encrypted threat isolation
- **Metadata Preservation**: Complete threat information retention
- **Restore Capability**: Safe restoration of false positives
- **Permanent Deletion**: Secure file destruction

### 📈 Modern Interface Features
- **Neon Cyber Theme**: Premium glassmorphism design
- **Real-Time Dashboard**: Live threat statistics and system status
- **Interactive Charts**: Recharts-powered data visualization
- **Smooth Animations**: Framer Motion enhanced UX
- **Responsive Design**: Optimized for all screen sizes

---

## 🏗️ Architecture

### Project Structure

```
CGP-2/
├── main.py                     # PyQt5 Application Entry Point
├── main_aegis.py               # AEGIS React Interface Entry Point
├── setup.py                    # Automated Setup Script
├── requirements.txt            # Python Dependencies
├── BUILD.bat                   # Windows Build Script
│
├── core/                       # Core Security Modules
│   ├── realtime_protection.py  # RTP Engine with YARA
│   ├── scanner.py              # Malware Scanner
│   ├── monitor.py              # System Monitor
│   ├── quarantine.py           # Quarantine Manager
│   ├── threat_prevention.py    # Automated Response
│   ├── api_bridge.py           # Python-JS Bridge
│   └── native_notifications.py # System Notifications
│
├── ai/                         # AI/ML Components
│   ├── nlp_model.py            # NLP Threat Detector
│   ├── explainable_ai.py       # XAI Module
│   └── train_nlp.py            # Model Training
│
├── security/                   # Security Layer
│   ├── encryption.py           # AES-256 Encryption
│   ├── auth.py                 # Authentication
│   └── password_manager.py     # Password Vault
│
├── database/                   # Data Persistence
│   ├── db_manager.py           # SQLite Manager
│   └── schema.sql              # Database Schema
│
├── gui/                        # PyQt5 GUI Components
│   ├── login.py                # Login Window
│   ├── dashboard.py            # Dashboard Components
│   ├── popup_alerts.py         # Alert Windows
│   └── styles.py               # Neon Cyber Theme
│
├── ui/                         # React Frontend Interface
│   ├── frontend/               # React/Vite Application
│   │   ├── src/
│   │   │   ├── App.jsx         # Main Application
│   │   │   ├── components/     # React Components
│   │   │   │   ├── Dashboard.jsx
│   │   │   │   ├── RTPMonitor.jsx
│   │   │   │   ├── ThreatAlertManager.jsx
│   │   │   │   ├── PasswordVault.jsx
│   │   │   │   └── ScannerInterface.jsx
│   │   │   └── index.css       # TailwindCSS Styles
│   │   ├── package.json        # Node Dependencies
│   │   └── vite.config.js      # Build Config
│   └── notification.html       # Popup Notifications
│
├── data/                       # Application Data
│   ├── signatures.json         # Malware Signatures
│   └── yara_rules/             # YARA Rules
│
└── docs/                       # Documentation
    ├── README.md               # This File
    ├── QUICK_START.md          # Fast Setup Guide
    ├── QUICK_START_RTP.md      # RTP Setup Guide
    └── SRS Documentation.md    # Technical Specs
```

### Technology Stack

#### Backend (Python)
- **Framework**: PyQt5 + pywebview
- **AI/ML**: PyTorch, Transformers, NLTK, spaCy
- **Security**: cryptography (AES-256-GCM, PBKDF2)
- **File Monitoring**: watchdog
- **Pattern Matching**: yara-python
- **Database**: SQLite with SQLAlchemy
- **System Analysis**: psutil

#### Frontend (AEGIS)
- **Framework**: React 19.2.0
- **Build Tool**: Vite 7.2.4
- **UI Library**: TailwindCSS 3.4.17
- **Animations**: Framer Motion 12.23
- **Charts**: Recharts 3.4.1
- **Icons**: Lucide React 0.554

---

## 🚀 Installation

### Prerequisites

- **Python**: 3.8 or higher
- **Node.js**: 16+ (for AEGIS interface)
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB available disk space
- **OS**: Windows 10+, macOS 10.14+, Ubuntu 18.04+

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd CGP-2

# Run automated setup
python setup.py

# This will:
# - Install all Python dependencies
# - Download NLP models (optional)
# - Initialize the database
# - Setup YARA rules
# - Configure Tesseract OCR (if available)
```

### Option 2: Manual Installation

#### Step 1: Python Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install spaCy model (optional, for enhanced NLP)
python -m spacy download en_core_web_sm
```

#### Step 2: Frontend Setup

```bash
# Navigate to frontend directory
cd ui/frontend

# Install Node dependencies
npm install

# Build production bundle
npm run build

# Go back to project root
cd ../..
```

#### Step 3: YARA Rules (Optional but Recommended)

```bash
# YARA rules are included in data/yara_rules/
# No additional setup required
```

#### Step 4: Tesseract OCR (Optional, for screenshot analysis)

```bash
# Windows (using Chocolatey)
choco install tesseract

# macOS
brew install tesseract

# Ubuntu
sudo apt-get install tesseract-ocr
```

### Verify Installation

```bash
# Run verification script
python verify_project.py

# This will check:
# - All dependencies installed
# - Database initialized
# - YARA rules loaded
# - Frontend built
```

---

## 📖 Usage Guide

### Launching the Application

#### Primary Launch Method

```bash
python main_aegis.py
```

- Modern React-based interface with Neon Cyber theme
- Real-time threat monitoring and alerts
- Glassmorphism design and smooth animations
- System-wide native notifications with Game Mode

#### Alternative: Classic Interface (Legacy)

```bash
python main.py
```

- Traditional desktop GUI
- PyQt5-based dashboard
- Classic tab-based interface
- Legacy support for older systems

### First Launch

1. **Create Master Account**
   - Click "Create Account" on login screen
   - Enter username and strong master password
   - Password requirements:
     - Minimum 12 characters
     - Uppercase + lowercase letters
     - Digits and special characters
     - No common patterns

2. **Login**
   - Enter credentials
   - Session timeout: 30 minutes of inactivity
   - Secure session management with encryption

### Dashboard Features

#### 🏠 Overview Tab
- **Threat Statistics**: 7-day summary with charts
- **System Health**: Real-time protection status
- **Recent Activity**: Latest security events
- **Quick Actions**: One-click scan/protection controls

#### 🔍 Scanner Tab
- **Quick Scan**: Common malware locations (Temp, Downloads, Documents)
- **Full Scan**: Complete system scan with YARA rules
- **Custom Scan**: Select specific directories
- **Results**: Detailed threat information with hashes and scores

#### 📊 System Monitor Tab
- **Resource Usage**: CPU, Memory, Disk, Network
- **Top Processes**: Resource consumption ranking
- **Suspicious Processes**: Anomaly detection
- **Network Connections**: Active connections with threat assessment

#### 🔑 Password Vault Tab
- **Store Passwords**: Encrypted with AES-256
- **Generate Passwords**: Customizable strength (8-64 characters)
- **Categories**: Organize by type (email, banking, social, work)
- **Search**: Quick credential retrieval
- **Strength Meter**: Real-time password evaluation

#### 🤖 Threat Analyzer Tab (NLP)
- **Text Analysis**: Paste emails, messages, or content
- **AI Detection**: Phishing, scams, social engineering
- **PII Detection**: SSN, credit cards, sensitive data
- **Explainable Results**: Highlighted keywords and threat factors
- **Confidence Scoring**: 0-100% threat probability

#### 🗃️ Quarantine Tab
- **View Threats**: Encrypted quarantined files
- **Restore Files**: Recovery for false positives
- **Delete Permanently**: Secure file destruction
- **Threat Details**: Full metadata and detection info

#### 📋 Logs Tab
- **Event Filtering**: By type, severity, date
- **Security Audit**: Complete activity trail
- **Export Logs**: CSV/JSON export capability
- **Search**: Full-text log search

### Real-Time Protection (RTP)

#### Enabling RTP

```python
# Via AEGIS Interface
# Dashboard → Real-Time Protection → Toggle ON

# Via Python
from core.realtime_protection import rtp_engine
rtp_engine.start_monitoring()
```

#### Game Mode

Enables silent protection without interrupting gaming:

```python
# Enable Game Mode
rtp_engine.enable_game_mode()

# Alerts are logged but not displayed
# Protection continues in background
```

#### Monitored Locations

Default monitored directories:
- `C:\Users\<User>\Downloads`
- `C:\Users\<User>\Documents`
- `C:\Users\<User>\Desktop`
- `C:\Temp`
- `C:\Windows\Temp`

Custom directories can be added via the interface.

---

## 🔐 Security Features

### Encryption Standards

#### Password Storage
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Salt**: 256-bit cryptographically secure random
- **Key Length**: 256 bits

#### Data Encryption
- **Algorithm**: AES-256-GCM
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Nonce**: 96-bit unique per encryption
- **Tag**: 128-bit authentication tag

#### Quarantine Encryption
- **Algorithm**: AES-256 with unique keys per file
- **Metadata**: Stored separately with encryption details
- **Integrity**: SHA-256 checksums for verification

### Threat Detection Methods

#### 1. Signature-Based (YARA)
- Industry-standard YARA rules
- Custom signature database
- Pattern matching for known malware
- File hash verification (MD5, SHA-1, SHA-256)

#### 2. Heuristic Analysis
- Behavioral pattern detection
- Anomaly scoring system
- Process relationship analysis
- Resource usage patterns

#### 3. AI/ML Detection
- DistilBERT transformer model
- Keyword pattern matching (fallback)
- Confidence scoring (0-100%)
- Multi-category classification:
  - Phishing attempts
  - Social engineering
  - Financial scams
  - Malware distribution
  - PII exposure risks

#### 4. PII Detection
- Social Security Numbers (SSN)
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- Email addresses
- Phone numbers (US format)
- IP addresses
- Dates of birth
- Custom regex patterns

### Automated Response

When threats are detected:

1. **Immediate Actions**
   - File quarantine (high/critical threats)
   - Process termination (if malicious)
   - Network connection blocking

2. **User Notifications**
   - Native system notifications
   - In-app popup alerts
   - Dashboard updates

3. **Logging**
   - Complete event details
   - Threat metadata
   - User actions
   - System state

4. **Reporting**
   - Daily security summaries
   - Incident reports
   - Trend analysis

---

## 🧪 Testing

### Run Unit Tests

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=. --cov-report=html

# View coverage report
# Open htmlcov/index.html in browser
```

### Test Suites

- **Encryption Tests**: `tests/test_encryption.py`
- **Scanner Tests**: `tests/test_scanner.py`
- **RTP Tests**: `test_realtime_protection.py`
- **NLP Tests**: `test_nlp_pii.py`
- **Quarantine Tests**: `test_quarantine.py`
- **Integration Tests**: `test_aegis_integration.py`

### Manual Testing

```bash
# Test RTP popup
python test_rtp_popup.py

# Test YARA scanning
python test_yara_scan.py

# Test threat prevention
python test_prevention.py

# Inject test threat
python inject_test_threat.py
```

---

## 📊 Performance Benchmarks

### Target Metrics

- ✅ **Application Startup**: <5 seconds
- ✅ **File Scanning**: >1000 files/minute
- ✅ **Memory Usage**: <500MB baseline
- ✅ **CPU Usage (Idle)**: <10%
- ✅ **Database Queries**: <100ms
- ✅ **NLP Analysis**: <5 seconds per 1000 words
- ✅ **RTP Response Time**: <2 seconds from file change to alert

### System Requirements

#### Minimum
- **CPU**: Intel i3 2.0GHz or equivalent
- **RAM**: 4GB
- **Storage**: 2GB free space
- **OS**: Windows 10+, macOS 10.14+, Ubuntu 18.04+

#### Recommended
- **CPU**: Intel i5 2.5GHz or equivalent
- **RAM**: 8GB
- **Storage**: 5GB free space (for logs and quarantine)
- **GPU**: Optional, for faster NLP inference
- **SSD**: Recommended for improved I/O performance

---

## 🔧 Configuration

### Database Location

```
cyberguard.db (SQLite database in project root)
```

### Logs Directory

```
logs/
├── cyberguard.log          # Main application log
├── rtp_*.log               # RTP session logs
└── scan_*.log              # Scan result logs
```

### Quarantine Directory

```
quarantine/
├── threats/                # Encrypted threat files
└── metadata/               # Threat metadata JSON
```

### Custom Settings

Edit via the AEGIS interface or programmatically:

```python
from database.db_manager import db_manager

# Enable auto-quarantine for critical threats
db_manager.set_setting('auto_quarantine_critical', 'true')

# Set RTP scan interval
db_manager.set_setting('rtp_scan_interval', '5')

# Enable game mode by default
db_manager.set_setting('default_game_mode', 'false')
```

---

## 🛠️ Development

### Building from Source

#### Python Application

```bash
# Install development dependencies
pip install -r requirements.txt
pip install pyinstaller

# Build executable
python build_exe.py

# Or use PyInstaller directly
pyinstaller --clean CyberGuardPro.spec
```

#### AEGIS Frontend

```bash
cd ui/frontend

# Development server
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

### Code Quality

```bash
# Linting (Python)
pip install flake8 black
flake8 . --max-line-length=120
black . --check

# Linting (JavaScript/React)
cd ui/frontend
npm run lint
```

### Contributing

This is an educational project. For development:

1. Fork the repository
2. Create a feature branch
3. Commit changes with clear messages
4. Run tests before pushing
5. Submit pull request with description

---

## 🐛 Troubleshooting

### Common Issues

#### 1. "Database initialization error"
```bash
# Solution: Delete and reinitialize database
del cyberguard.db
python main.py
```

#### 2. "NLP model not found"
```bash
# Solution: Install transformer models
pip install transformers torch
python -m transformers-cli download distilbert-base-uncased
```

#### 3. "YARA rules not loading"
```bash
# Solution: Verify YARA installation
pip install yara-python
python check_rtp_dependencies.py
```

#### 4. "Frontend build not found"
```bash
# Solution: Build React frontend
cd ui/frontend
npm install
npm run build
```

#### 5. "Permission denied during scanning"
```bash
# Solution: Run with appropriate permissions
# Windows: Right-click → Run as Administrator (not recommended for daily use)
# Linux/Mac: sudo python main.py (use caution)
```

#### 6. "High CPU usage"
```bash
# Solution: Adjust monitoring interval
# Edit core/monitor.py: update_interval = 10  # Increase from 5
```

#### 7. "RTP alerts not appearing"
```bash
# Solution: Check notification settings
python test_rtp_popup.py
# Verify native_notifications.py is working
```

### Debug Mode

```bash
# Enable detailed logging
export CYBERGUARD_DEBUG=1  # Linux/Mac
set CYBERGUARD_DEBUG=1     # Windows

python main.py
```

### Log Analysis

```bash
# View recent logs
tail -f logs/cyberguard.log

# Search for errors
grep -i "error" logs/cyberguard.log

# Export logs for support
python -c "from core.system_logger import system_logger; system_logger.export_logs('support_logs.zip')"
```

---

## 📈 Roadmap

### Phase 1 (Completed) ✅
- ✅ Core security modules
- ✅ PyQt5 GUI dashboard
- ✅ NLP threat detection
- ✅ Password management
- ✅ Automated threat response
- ✅ Real-time protection (RTP)
- ✅ AEGIS modern interface
- ✅ YARA integration
- ✅ PII detection
- ✅ Native notifications

### Phase 2 (Future)
- [ ] Cloud threat intelligence integration
- [ ] Advanced ML models with custom training
- [ ] Mobile companion app
- [ ] Multi-user support with role-based access
- [ ] Centralized management console
- [ ] Email scanning plugin
- [ ] Browser extension for phishing protection

### Phase 3 (Future)
- [ ] Network firewall integration
- [ ] VPN integration
- [ ] Scheduled automated scans
- [ ] Threat intelligence sharing
- [ ] EDR (Endpoint Detection and Response) capabilities
- [ ] SIEM integration
- [ ] SOC dashboard for enterprise

---

## 📄 License

**Educational Project** - All Rights Reserved

This software is developed as a course project for educational purposes. It is not intended for commercial use or production deployment without proper security auditing.

### Disclaimer

⚠️ **IMPORTANT**: This application handles sensitive data and system-level operations. Use at your own risk. The developers are not responsible for any damage, data loss, or security incidents resulting from the use of this software.

### Third-Party Components

This project uses the following open-source libraries:
- PyQt5 (GPL)
- React (MIT)
- Transformers by Hugging Face (Apache 2.0)
- YARA (BSD 3-Clause)
- And others listed in requirements.txt and package.json

---

## 👥 Team

- **Frontend Developer**: PyQt5 GUI + AEGIS React Interface
- **System Security Developer**: RTP, Scanner, YARA Integration
- **Database Developer**: SQLite Schema, Data Management
- **System Monitor Developer**: Resource Tracking, Process Analysis
- **Password Manager Developer**: Encryption, Vault Implementation
- **Testing & AI Developer**: NLP Models, XAI, Test Suite, PII Detection

---

## 📞 Support

For issues, questions, or feature requests:

### Documentation
- **[README.md](README.md)** - This file (comprehensive guide)
- **[QUICK_START.md](QUICK_START.md)** - Fast 5-minute setup
- **[QUICK_START_RTP.md](QUICK_START_RTP.md)** - RTP-specific guide
- **[REALTIME_PROTECTION_SETUP.md](REALTIME_PROTECTION_SETUP.md)** - Detailed RTP setup
- **[SRS Documentation.md](SRS%20Documentation.md)** - Technical specifications

### Resources
- Code documentation: See module docstrings
- Usage examples: Check `tests/` directory
- Architecture diagrams: In `docs/` folder
- API reference: In-code comments

### Community
- Report bugs: Create an issue on GitHub
- Feature requests: Submit via issue tracker
- Questions: Check documentation first, then ask in discussions

---

## 🔒 Security Notice

**BEST PRACTICES**:

1. ✅ Use a **strong master password** (16+ characters)
2. ✅ Keep the application **updated**
3. ✅ **Backup** `cyberguard.db` regularly
4. ✅ **Never share** your master password
5. ✅ **Review** quarantined files before permanent deletion
6. ✅ **Monitor** logs for suspicious activity
7. ✅ **Test** signature updates in non-production environment
8. ✅ **Verify** PII detection results manually for critical data

**SECURITY INCIDENTS**:

If you discover a security vulnerability:
1. DO NOT disclose publicly
2. Contact the development team immediately
3. Provide detailed reproduction steps
4. Allow time for patch development

---

## 🎯 Quick Start Checklist

- [ ] Python 3.8+ installed
- [ ] Node.js 16+ installed (for AEGIS)
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Frontend built (`cd ui/frontend && npm run build`)
- [ ] AEGIS launches without errors
- [ ] Master account created successfully
- [ ] Password vault tested
- [ ] Quick scan completed
- [ ] NLP analyzer tested with sample text
- [ ] System monitor displays data
- [ ] RTP enabled and monitoring
- [ ] Test threat detected and quarantined

---

## 🌟 Highlights

### Why Choose AEGIS?

1. **🎨 Modern Interface**: Beautiful React-based UI with Neon Cyber theme
2. **🤖 AI-Powered**: Transformer-based NLP for intelligent threat detection
3. **⚡ Real-Time**: Instant threat response with watchdog monitoring
4. **🔐 Military-Grade**: AES-256 encryption throughout
5. **📊 Transparent**: Explainable AI shows why decisions are made
6. **🎮 Game Mode**: Protection without interruption
7. **🧩 Modular**: Clean architecture, easy to extend
8. **📱 Modern**: React + TailwindCSS + Framer Motion

### Technical Excellence

- **Design Patterns**: MVC, Singleton, Observer, Factory, Strategy
- **Security Standards**: NIST, OWASP compliance
- **Performance**: Optimized for low resource usage
- **Scalability**: Multi-threaded, event-driven architecture
- **Maintainability**: Comprehensive documentation and tests

---

## 📚 Additional Documentation

- **[BUILD_INSTRUCTIONS.txt](BUILD_INSTRUCTIONS.txt)** - Detailed build process
- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Complete project overview
- **[RTP_IMPLEMENTATION_SUMMARY.md](RTP_IMPLEMENTATION_SUMMARY.md)** - RTP technical details

---

<div align="center">

**AEGIS** - Protecting Your Digital World with AI 🛡️

*Built with ❤️ for cybersecurity education*

---

**[⬆ Back to Top](#️-aegis---ai-powered-autonomous-cyber-defense)**

</div>
