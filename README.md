# 🛡️ CyberGuard Pro - AI-Powered Autonomous Cyber Defense

**Version:** 1.0.0  
**Status:** Production Ready

## 📌 Overview

CyberGuard Pro is a comprehensive desktop cybersecurity application with AI-powered threat detection, real-time system monitoring, malware scanning, password management, and explainable AI for security decisions.

### ✨ Key Features

- 🔍 **Real-time System Monitoring** - CPU, memory, disk, network, and process monitoring
- 🦠 **Malware Scanner** - Signature-based detection with file integrity checking
- 🔐 **Password Vault** - AES-256 encrypted password storage with PBKDF2 key derivation
- 🤖 **NLP Threat Detection** - AI-powered phishing and social engineering detection
- 💡 **Explainable AI** - Transparent security decisions with highlighted keywords
- 🚫 **Automated Threat Prevention** - Automatic quarantine and blocking
- 📊 **Security Dashboard** - Comprehensive real-time security overview
- 📋 **Detailed Logging** - Complete audit trail and security reports

## 🏗️ Architecture

```
cyberguard_pro/
├── main.py                 # Application entry point
├── gui/                    # PyQt5 GUI components
│   ├── dashboard.py        # Main dashboard
│   ├── login.py            # Authentication UI
│   ├── password_manager_ui.py
│   └── popup_alerts.py
├── core/                   # Core security modules
│   ├── monitor.py          # System monitoring
│   ├── scanner.py          # File security scanner
│   ├── quarantine.py       # Quarantine management
│   ├── threat_prevention.py # Automated responses
│   └── system_logger.py    # Logging system
├── ai/                     # AI/ML components
│   ├── nlp_model.py        # NLP threat detector
│   ├── explainable_ai.py   # XAI module
│   └── train_nlp.py        # Model training
├── security/               # Security utilities
│   ├── encryption.py       # AES-256 encryption
│   ├── auth.py             # Authentication
│   └── password_manager.py # Password operations
├── database/               # Data persistence
│   ├── db_manager.py       # SQLite manager
│   └── schema.sql          # Database schema
├── data/                   # Application data
│   ├── signatures.json     # Malware signatures
│   └── phishing_dataset.csv
├── logs/                   # System logs
├── reports/                # Security reports
└── tests/                  # Unit tests
```

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 2GB available disk space
- Internet connection for initial setup

### Step 1: Install Python Dependencies

```bash
cd CGP-2

# Install all required packages
pip install -r requirements.txt
```

### Step 2: Download NLP Model (Optional)

For full NLP functionality, download the spaCy model:

```bash
python -m spacy download en_core_web_sm
```

### Step 3: Initialize Database

The database will be automatically created on first run. No manual setup required.

### Step 4: Run the Application

```bash
python main.py
```

## 📖 Usage Guide

### First Launch

1. **Create Master Account**
   - Click "Create Account" on login screen
   - Enter a strong master password (12+ characters recommended)
   - Password must include: uppercase, lowercase, digits, and symbols

2. **Login**
   - Enter your username and master password
   - Session lasts 30 minutes of inactivity

### Dashboard Overview

#### 🏠 Overview Tab
- View threat statistics (7-day summary)
- Monitor files scanned count
- Check system health status
- Review recent security activity

#### 🔍 Scanner Tab
- **Quick Scan**: Scans common malware locations (Temp, Downloads)
- **Full Scan**: Complete system scan
- **Custom Scan**: Select specific directories
- View scan results and threat details

#### 📊 System Monitor Tab
- Real-time CPU, memory, and disk usage
- Top processes by resource consumption
- Suspicious process detection
- Network connection monitoring

#### 🔑 Password Vault Tab
- Store encrypted passwords
- Generate strong random passwords
- Organize by category
- Search and retrieve credentials

#### 🤖 Threat Analyzer Tab
- Paste email or message text
- AI analyzes for phishing/scams
- View threat classification
- See highlighted suspicious keywords
- Get explainable AI decisions

#### 🗃️ Quarantine Tab
- View quarantined files
- Restore false positives
- Permanently delete threats
- Review threat details

#### 📋 Logs Tab
- Filter by event type
- Review security events
- Audit user actions
- Export logs

## 🔐 Security Features

### Encryption

- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Salt**: 256-bit cryptographically secure random salt
- **Password Storage**: Salted hash, never plaintext

### Threat Detection

1. **Signature-Based Scanning**
   - MD5/SHA-256 file hashing
   - Malware signature database
   - Regular signature updates

2. **NLP-Based Detection**
   - Transformer model (DistilBERT)
   - Keyword pattern matching
   - Confidence scoring
   - Multiple threat categories:
     - Phishing
     - Social Engineering
     - Scams
     - Malware Links

3. **Behavioral Analysis**
   - Suspicious process detection
   - Abnormal resource usage alerts
   - Network connection monitoring
   - Known malicious port detection

### Automated Response

- **Auto-Quarantine**: High/critical threats
- **Domain Blocking**: Malicious URLs
- **IP Blacklisting**: Suspicious connections
- **User Alerts**: Real-time notifications
- **Audit Logging**: Complete event trail

## 🧪 Testing

### Run Unit Tests

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test module
pytest tests/test_scanner.py -v
```

### Test Coverage Goals

- Unit tests: ≥80% code coverage
- Integration tests: All module interfaces
- Security tests: Encryption, authentication
- GUI tests: Critical user workflows

## 📊 Performance Benchmarks

### Target Metrics

- Application startup: <5 seconds
- File scanning: >1000 files/minute
- Memory usage: <500MB baseline
- CPU usage (idle): <10%
- Database queries: <100ms
- NLP analysis: <5 seconds per 1000 words

### System Requirements

#### Minimum
- CPU: Intel i3 2.0GHz or equivalent
- RAM: 4GB
- Storage: 2GB free space
- OS: Windows 10+, macOS 10.14+, Ubuntu 18.04+

#### Recommended
- CPU: Intel i5 2.5GHz or equivalent
- RAM: 8GB
- Storage: 5GB free space (for logs and quarantine)
- GPU: Optional, for faster NLP inference

## 🔧 Configuration

### Settings Location

- Database: `cyberguard.db` (root directory)
- Logs: `logs/` directory
- Quarantine: `quarantine/` directory
- Signatures: `data/signatures.json`

### Customization

Edit settings via database or GUI (future feature):

```python
from database.db_manager import db_manager

# Set auto-quarantine
db_manager.set_setting('auto_quarantine', 'true')

# Set scan schedule
db_manager.set_setting('scan_schedule', 'daily')
```

## 🐛 Troubleshooting

### Common Issues

**1. "Database initialization error"**
- Solution: Delete `cyberguard.db` and restart application

**2. "NLP model not found"**
- Solution: Run `pip install transformers torch`
- Or use keyword-based detection (automatic fallback)

**3. "Permission denied" during scanning**
- Solution: Run with elevated privileges (not recommended for daily use)
- Or exclude system directories from scans

**4. High CPU usage**
- Solution: Reduce monitoring frequency in `core/monitor.py`
- Adjust `update_interval` parameter

**5. "Session expired"**
- Solution: Login again (sessions timeout after 30 minutes inactivity)

## 📈 Development Roadmap

### Phase 1 (Current) ✅
- Core security modules
- GUI dashboard
- NLP threat detection
- Password management
- Automated responses

### Phase 2 (Future)
- [ ] Real-time file system monitoring
- [ ] Cloud threat intelligence integration
- [ ] Advanced ML models (custom training)
- [ ] Mobile companion app
- [ ] Multi-user support

### Phase 3 (Future)
- [ ] Network firewall integration
- [ ] VPN integration
- [ ] Scheduled scans
- [ ] Email scanning plugin
- [ ] Browser extension

## 🤝 Contributing

This is a course project. For educational purposes only.

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd CGP-2

# Install dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Run in development mode
python main.py
```

## 📄 License

Educational Project - All Rights Reserved

## 👥 Team

- **Person 1**: GUI Developer (Frontend)
- **Person 2**: System Security Developer
- **Person 3**: Database Developer
- **Person 4**: System Monitor Developer
- **Person 5**: Password Manager Developer
- **Person 6**: Testing & Integration + NLP Developer

## 📞 Support

For issues and questions, refer to:
- SRS Documentation
- Code comments and docstrings
- Test files for usage examples

## 🔒 Security Notice

**IMPORTANT**: This application handles sensitive data. Follow these best practices:

1. Use a strong master password
2. Keep the application updated
3. Regular backups of `cyberguard.db`
4. Don't share your master password
5. Review quarantined files before deletion
6. Monitor logs for suspicious activity

## 🎯 Quick Start Checklist

- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Application starts without errors
- [ ] Master account created
- [ ] Password vault tested
- [ ] Quick scan completed
- [ ] NLP analyzer tested
- [ ] System monitor active

## 📚 Documentation

- **SRS Document**: `SRS Documentation.md`
- **API Docs**: See module docstrings
- **Architecture**: See this README
- **Testing Guide**: `tests/README.md` (to be created)

---

**CyberGuard Pro** - Protecting Your Digital World with AI 🛡️
