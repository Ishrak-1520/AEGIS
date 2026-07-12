# AEGIS - Advanced Endpoint Guard & Intelligence System

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Production%20Ready-success?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge)
![React](https://img.shields.io/badge/react-19.2.0-blue?style=for-the-badge)

**A desktop cybersecurity suite featuring AI-powered threat detection and a modern React interface.**

</div>

---

## Overview

AEGIS provides real-time protection against fileless malware, network intrusions, and social engineering by combining traditional signature-based detection with machine learning.

## Key Features

- **Real-Time Protection (RTP):** Continuous memory and screen monitoring to detect fileless malware and phishing.
- **Network Intrusion Detection (NIDS):** ML-powered packet analysis with an active IPS that blocks malicious IPs.
- **AI Code Auditor:** Uses the `LongCat-2.0-Preview` LLM to verify code security and detect vulnerabilities.
- **Advanced Malware Scanning:** Multi-engine file scanner utilizing YARA rules, hashes, and heuristic analysis.
- **Secure Password Vault:** AES-256-GCM encrypted local password management.
- **Automated Quarantine:** Automatically encrypts and isolates detected threats.

## Installation

### Prerequisites
- **OS:** Windows 10/11
- **Python:** 3.8+
- **Node.js:** 16+
- **Npcap:** Required for network sniffing
- **Tesseract OCR:** Required for screen monitoring

### Setup

Clone the repository and run the automated setup script to install Python dependencies, models, and databases:

```bash
git clone https://github.com/Ishrak-1520/AEGIS.git
cd CGP-2
python setup.py
```

Build the React frontend:

```bash
cd ui/frontend
npm install
npm run build
cd ../..
```

*(Optional)* To use the LLM Code Auditor, add your Longcat API key to a `.env` file:
`SIFT_API_KEY=your_api_key_here`

## Usage

Run the application with Administrator privileges (required for network sniffing and firewall rules):

```bash
python main_aegis.py
```

1. On first launch, create a master account with a strong password.
2. Toggle **Real-Time Protection** and **Network Defense** from the dashboard to activate continuous monitoring.

## Testing

Run the test suite using pytest:

```bash
pip install pytest pytest-cov pytest-mock
pytest tests/ -v
```

## License
Educational Project - All Rights Reserved. Use at your own risk.
