# AEGIS - Advanced Endpoint Guard & Intelligence System

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Production%20Ready-success?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge)
![React](https://img.shields.io/badge/react-19.2.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-Educational-orange?style=for-the-badge)

**Next-Generation Cybersecurity Suite with Multi-layered AI-Powered Threat Detection**

[Features](#key-features) • [Installation](#installation) • [Usage](#usage-guide) • [Architecture](#architecture) • [Documentation](#documentation)

</div>

---

## Overview

**AEGIS** is a comprehensive desktop cybersecurity application that combines traditional signature-based detection with state-of-the-art AI and Machine Learning. Featuring a modern React-based interface (powered by pywebview) and a high-performance Python backend, AEGIS provides real-time protection against fileless malware, network intrusions, social engineering, and zero-day threats.

### Why AEGIS?

- **Modern React UI**: Premium Neon Cyber theme with glassmorphism design and live data visualization.
- **Hybrid AI Defense**: Combines scikit-learn ML models (RandomForest), DistilBERT NLP, and Longcat LLMs.
- **Real-Time Protection (RTP)**: OCR-based screen monitoring and Volatile Memory HIDS for fileless malware.
- **Network Intrusion Detection (NIDS)**: ML-powered packet analysis with active IPS (Intrusion Prevention System) and Windows Firewall integration.
- **True Threat Prevention**: Automated AES-256 encrypted quarantine and rogue process termination.
- **Explainable AI (XAI)**: Transparent security decisions with word importance scoring and visual threat highlighting.

---

## Key Features

### Real-Time Protection (RTP) & HIDS
- **Volatile Memory Analysis**: Live memory telemetry classification to detect hidden fileless malware.
- **Screen OCR Monitoring**: Continuous screen analysis for phishing, credential theft, and social engineering.
- **Game Mode**: Zero-interruption background protection.
- **Native Notifications**: OS-level Windows Toast alerts with custom audio escalation.

### Network Intrusion Detection System (NIDS)
- **ML Flow Analysis**: Random Forest classifier evaluating 6-dimensional packet flow features.
- **Heuristic Overrides**: Rule-based detection for web threats, clickjacking, and trackers.
- **Active IPS**: Automatically blocks malicious IPs via Windows Firewall (`netsh`).

### AI-Powered Threat Analysis
- **NLP Text Scanner**: Transformer-based analysis for phishing and scams.
- **SIFT Engine**: LLM-powered code security auditor utilizing the `LongCat-2.0-Preview` API for registry verification and vulnerability analysis.
- **PII Detection**: Regex-based detection of SSN, credit cards, emails, and sensitive data.

### Advanced Malware Scanning
- **YARA Rules**: Industry-standard pattern matching.
- **PE File ML Analyzer**: Extracts Import Address Table (IAT) API calls and classifies via RandomForest.
- **Multi-Hash Verification**: MD5, SHA-1, SHA-256 validation.

### Password Management & Encryption
- **AES-256-GCM Encryption**: Military-grade vault storage.
- **PBKDF2 Key Derivation**: 100,000 iterations with 256-bit unique salts.
- **Secure Password Generator**: Customizable strength with real-time evaluation.

---

## Architecture

AEGIS uses a decoupled architecture where a React frontend communicates with a Python backend via a secure `pywebview` bridge (`AegisAPI`). 

```text
CGP-2/
├── main_aegis.py               # Application Entry Point (pywebview + React)
├── core/                       # Core Security Modules
│   ├── api_bridge.py           # Python <-> JS API bridge
│   ├── scanner.py              # Multi-engine File Scanner
│   ├── realtime_protection.py  # Screen OCR & Memory Monitor
│   ├── hids_analyzer.py        # ML PE Analyzer & Volatile Memory HIDS
│   ├── quarantine.py           # AES-256 Encrypted Quarantine
│   ├── sift_engine.py          # LLM Code Auditor
│   └── network/nids_engine.py  # Network Packet Sniffer & IPS
├── ai/                         # AI/ML Components
│   ├── nlp_model.py            # NLP Threat Detector
│   ├── explainable_ai.py       # XAI Explanations
│   └── models/                 # Pre-trained ML Models (.pkl)
├── security/                   # Data Protection Layer
│   ├── encryption.py           # AES-256 / PBKDF2
│   └── password_manager.py     # Secure Vault
├── database/                   # SQLite Persistence
│   ├── db_manager.py           # Thread-safe SQLite DAL
│   └── schema.sql              # 7-table Schema
└── ui/frontend/                # React 19 + Vite + Tailwind SPA
```

---

## Installation

### Prerequisites

- **OS**: Windows 10/11 (Required for Npcap, Windows Firewall IPS, and Toast notifications)
- **Python**: 3.8 or higher
- **Node.js**: 16+ (for frontend building)
- **Npcap**: Required for `scapy` network sniffing (NIDS)
- **Tesseract OCR**: Required for Screen Monitoring (RTP)

### Automated Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/Ishrak-1520/AEGIS.git
cd CGP-2

# Run automated setup script
python setup.py
```
*This installs Python requirements, downloads NLP models, initializes the SQLite DB, and sets up YARA.*

### Frontend Compilation

```bash
cd ui/frontend
npm install
npm run build
cd ../..
```

---

## Usage Guide

### Launching the Application

Start the modern AEGIS interface with Administrator privileges (required for network sniffing and firewall modifications):

```bash
python main_aegis.py
```

### First Launch
1. **Create Master Account**: Choose a username and a strong master password (min 12 chars). This derives the encryption keys for your password vault.
2. **Dashboard Overview**: Access the live system telemetry, threat statistics, and protection status.
3. **Enable Protections**: Toggle Real-Time Protection (RTP) and Network Defense (NIDS) directly from the dashboard or settings.

### API Keys
To use the **SIFT Engine** (LLM Code Auditor), you must provide a Longcat API key:
1. Copy `.env.example` to `.env`.
2. Add your key: `SIFT_API_KEY=your_api_key_here`.
3. AEGIS currently targets the `LongCat-2.0-Preview` model.

---

## Testing & Development

Run the test suite using `pytest`:

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=. --cov-report=html
```

### Development Server
To work on the React frontend with Hot Module Replacement (HMR):
```bash
cd ui/frontend
npm run dev
```

---

## Performance Benchmarks

- **Application Startup**: < 5 seconds
- **Volatile HIDS Latency**: < 50ms per inference
- **Network ML Inference**: < 10ms per flow
- **Memory Footprint**: < 500MB baseline
- **File Scanning**: > 1000 files/minute

---

## License & Disclaimer

**Educational Project** - All Rights Reserved

This software is developed as a cybersecurity research project. It handles sensitive data and system-level operations (such as firewall modifications and process termination). **Use at your own risk.** The developers are not responsible for any damage, data loss, or security incidents resulting from the use of this software.

---

## Team

Built by cybersecurity students specializing in AI-driven threat intelligence, network security, and encrypted data storage. For detailed architectural specifications, please refer to the `AEGIS_Technical_Documentation.md`.
