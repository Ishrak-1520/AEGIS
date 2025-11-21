# 🚀 CyberGuard Pro - Quick Start Guide

## ⚡ 5-Minute Setup

### Prerequisites Check
```bash
# Verify Python 3.8+
python --version

# Should show: Python 3.8.x or higher
```

### Installation (Choose One Method)

#### Method 1: Automated Setup (Recommended)
```bash
cd CGP-2
python setup.py
```

#### Method 2: Manual Setup
```bash
cd CGP-2

# Install dependencies
pip install -r requirements.txt

# Optional: Download NLP model
python -m spacy download en_core_web_sm

# Run application
python main.py
```

## 🎯 First Time Usage

### 1. Launch Application
```bash
python main.py
```

### 2. Create Master Account
- Click **"Create Account"**
- Username: `admin` (or your choice)
- Password: **Strong password required!**
  - Minimum 12 characters
  - Must include: A-Z, a-z, 0-9, symbols (@#$%)
  - Example: `CyberGuard@2024!`

### 3. Login
- Enter username and password
- Click **"Login"**

## 📊 Quick Feature Tour

### Dashboard Overview
After login, you'll see 6 main tabs:

#### 1️⃣ Overview Tab
- **Threats Blocked**: Last 7 days
- **Files Scanned**: Total count
- **System Health**: Current status
- **Recent Activity**: Security log

#### 2️⃣ Scanner Tab
```
Quick Actions:
• Quick Scan    → Scans Downloads, Temp folders
• Full Scan     → Complete system scan
• Custom Scan   → Choose specific directory
```

**Try it now:**
1. Click **"Quick Scan"**
2. Wait for completion
3. Review results

#### 3️⃣ System Monitor Tab
Real-time monitoring:
- 📊 CPU Usage
- 💾 Memory Usage
- 💿 Disk Usage
- 📋 Top Processes

**Auto-updates every 5 seconds**

#### 4️⃣ Password Vault Tab
```
Actions:
• Add Password       → Store credentials
• Generate Password  → Create strong password
• View/Edit          → Manage saved passwords
```

**Try it now:**
1. Click **"Generate Password"**
2. Copy the secure password
3. Click **"Add Password"** to store it

#### 5️⃣ Threat Analyzer Tab (AI-Powered)
```
Test with sample phishing email:

Urgent: Your account has been suspended! 
Click here to verify your identity immediately 
or your account will be permanently deleted.
```

**Steps:**
1. Paste text in input box
2. Click **"🤖 Analyze Text"**
3. View threat classification
4. See highlighted suspicious keywords
5. Read AI explanation

#### 6️⃣ Quarantine Tab
- View quarantined threats
- Restore false positives
- Permanently delete files

## 🔐 Core Features Demo

### Feature 1: Scan a File
```python
# Via GUI: Scanner Tab → Custom Scan → Select folder
# Or use module directly:

from core.scanner import file_scanner

result = file_scanner.scan_file("path/to/file.exe")
print(f"Status: {result['status']}")
print(f"Hash: {result['hash']}")
```

### Feature 2: Analyze Text Threat
```python
from ai.nlp_model import get_nlp_detector

detector = get_nlp_detector()
result = detector.analyze_text("Your suspicious text here")

print(f"Threat: {result['threat_class']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Keywords: {result['keywords_found']}")
```

### Feature 3: Password Management
```python
from security.password_manager import password_manager

# Generate strong password
password = password_manager.generate_password(length=16)
print(f"Generated: {password}")

# Check strength
strength = password_manager.check_password_strength(password)
print(f"Strength: {strength['strength']}")
print(f"Score: {strength['score']}/100")
```

### Feature 4: System Monitoring
```python
from core.monitor import system_monitor

# Start monitoring
system_monitor.start_monitoring()

# Get current stats
stats = system_monitor.get_system_stats()
print(f"CPU: {stats['cpu']['percent']}%")
print(f"Memory: {stats['memory']['percent']}%")

# Get top processes
top_processes = system_monitor.get_top_processes(by='cpu', limit=5)
for proc in top_processes:
    print(f"{proc['name']}: {proc['cpu_percent']}%")
```

## 🧪 Test the System

### Run Unit Tests
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_encryption.py -v

# With coverage
pytest tests/ --cov=. --cov-report=html
```

### Manual Testing Checklist

- [ ] Application starts without errors
- [ ] Can create master account
- [ ] Can login successfully
- [ ] Dashboard loads all tabs
- [ ] Quick scan runs and completes
- [ ] System monitor shows live data
- [ ] Can generate password
- [ ] NLP analyzer detects phishing
- [ ] Logs show activity

## 🎨 Customization

### Change Monitoring Interval
Edit `core/monitor.py`:
```python
# Line ~24
self.update_interval = 5.0  # Change to desired seconds
```

### Add Custom Malware Signature
```python
from core.scanner import file_scanner

file_scanner.add_signature(
    sig_id='custom_001',
    file_hash='your_hash_here',
    name='Custom Malware',
    level='HIGH',
    description='Custom signature'
)
```

### Adjust Security Thresholds
Edit `core/monitor.py`:
```python
# Line ~28-30
self.cpu_threshold = 80.0      # CPU alert %
self.memory_threshold = 50.0   # Memory alert %
```

## 🐛 Common Issues & Solutions

### Issue 1: Import Error
```
Error: No module named 'PyQt5'
```
**Solution:**
```bash
pip install PyQt5
```

### Issue 2: Database Error
```
Error: Database initialization error
```
**Solution:**
```bash
# Delete database and restart
rm cyberguard.db
python main.py
```

### Issue 3: NLP Model Not Found
```
Warning: NLP model not loaded
```
**Solution:**
```bash
pip install torch transformers
# Or system will use keyword detection (works fine!)
```

### Issue 4: Permission Denied
```
Error: Permission denied when scanning
```
**Solution:**
- Scan user directories only
- Or run with elevated privileges (use with caution)

## 📈 Performance Tips

1. **Reduce CPU Usage**
   - Increase monitoring interval (5s → 10s)
   - Reduce concurrent scans

2. **Faster Scans**
   - Exclude large media folders
   - Focus on executable directories

3. **Memory Optimization**
   - Clear old logs regularly
   - Limit quarantine file size

## 🎓 Learning Resources

### Explore the Code
```
Key files to understand:
├── main.py                    # Application entry
├── gui/dashboard.py           # Main UI
├── security/encryption.py     # Crypto operations
├── ai/nlp_model.py           # Threat detection
└── core/scanner.py           # File scanning
```

### API Documentation
All modules have detailed docstrings:
```python
from security.encryption import EncryptionManager

# View documentation
help(EncryptionManager)
help(EncryptionManager.encrypt)
```

### Example Scripts
Check `tests/` folder for usage examples of all modules.

## 🎯 Next Steps

### Beginner
1. ✅ Complete setup
2. ✅ Explore all dashboard tabs
3. ✅ Run quick scan
4. ✅ Test password generator
5. ✅ Analyze sample phishing text

### Intermediate
1. Add custom malware signatures
2. Modify threat detection rules
3. Create scheduled scans
4. Export security reports
5. Customize GUI themes

### Advanced
1. Integrate external threat feeds
2. Train custom NLP model
3. Build browser extension
4. Add network monitoring
5. Develop plugin system

## 🆘 Get Help

**Resources:**
- `README.md` - Complete documentation
- `SRS Documentation.md` - Technical specs
- Code comments - Inline explanations
- Test files - Usage examples

**Contact:**
- Review SRS document for architecture
- Check module docstrings for APIs
- Examine test cases for examples

---

## ✅ Installation Verification

Run this quick check:
```python
# test_installation.py
import sys

modules = [
    'PyQt5.QtWidgets',
    'psutil',
    'cryptography',
    'database.db_manager',
    'security.encryption',
    'core.scanner',
    'ai.nlp_model'
]

print("Checking installation...")
for mod in modules:
    try:
        __import__(mod)
        print(f"✅ {mod}")
    except:
        print(f"❌ {mod}")

print("\nReady to go! Run: python main.py")
```

---

**You're all set! 🎉**

Launch CyberGuard Pro and protect your system with AI-powered security! 🛡️
