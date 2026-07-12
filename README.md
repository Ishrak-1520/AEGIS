# AEGIS - Advanced Endpoint Guard & Intelligence System

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/Ishrak-1520/AEGIS)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg)](https://github.com/Ishrak-1520/AEGIS)
[![Python](https://img.shields.io/badge/python-3.8+-3776AB.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-19.2.0-20232A.svg)](https://react.dev/)

AEGIS is a Windows desktop cybersecurity suite combining local machine learning intrusion detection, live network packet inspection, automated threat prevention, and code auditing into a unified interface.

## Key Capabilities

* **Host Intrusion Detection (Volatile Guardian):** Inspects Windows Portable Executable (PE) binaries and tracks Import Address Table (IAT) API calls (`VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`) to detect packed or obfuscated executables before execution.
* **Network Intrusion Prevention (RT-XNIDS):** Captures live network traffic via Scapy and Npcap, monitors connection baselines, and automatically blocks malicious external IP addresses using Windows Firewall rules.
* **AI Code Auditor (SIFT):** Scans source code and dependencies for vulnerabilities like SQL injection, command injection, and typosquatting using static AST analysis combined with OpenRouter Gemma 4.
* **Bilingual Scam & Phishing Detection:** Analyzes text from browser sessions and emails in English and Bangla. It detects mobile financial scams targeting bKash, Nagad, and Rocket while highlighting specific threat keywords.
* **Real-Time Screen & Process Protection:** Uses background OCR to detect phishing sites and credential harvesting forms on screen. It applies alert deduplication and cooldown timers so notifications stay accurate without spamming the desktop.
* **Encrypted Vault & Quarantine:** Includes an AES-256-GCM local password manager and an encrypted file quarantine system (`cyberguard.db`) that safely isolates suspicious payloads.

## System Prerequisites

1. **Windows 10 or Windows 11 (64-bit)**
2. **Npcap:** Required for live network packet inspection. Download from [npcap.com](https://npcap.com/) and enable **Install Npcap in WinPcap API-compatible Mode** during installation.
3. **Tesseract OCR:** Required for real-time screen OCR protection. Download from [UB-Mannheim Tesseract](https://github.com/UB-Mannheim/tesseract/wiki) and install to default path (`C:\Program Files\Tesseract-OCR`).

## Download & Installation

### Option 1: Standalone Windows Application (Recommended)

You can run AEGIS as a self-contained Windows desktop application (`AEGIS.exe`) without manually running a Python server.

1. Download the latest `AEGIS.exe` binary from the [GitHub Releases page](https://github.com/Ishrak-1520/AEGIS/releases).
2. Right-click `AEGIS.exe` and select **Run as administrator** (required for network packet inspection and firewall control).

If you want to compile `AEGIS.exe` locally from source:
```cmd
BUILD_AEGIS.bat
```
The compiled executable will be generated in `dist\AEGIS.exe`.

### Option 2: Running from Source (For Developers)

1. Clone the repository and install Python dependencies:
```bash
git clone https://github.com/Ishrak-1520/AEGIS.git
cd CGP-2
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

2. Build the React frontend:
```bash
cd UI/frontend
npm install
npm run build
cd ../..
```

3. Launch the application as Administrator:
```bash
python main_aegis.py
```

## Configuration

To enable optional AI verification for the code auditor, create a `.env` file in the project root folder:
```env
SIFT_API_KEY=your_openrouter_api_key
```
If `.env` is omitted, all local detection engines (HIDS, NIDS, Scanner, Real-Time Protection) continue to run fully offline.

## Command Line Flags

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--rebuild` | Compiles the React frontend bundle before launching the app | `python main_aegis.py --rebuild` |
| `--dev` | Skips static bundle checks when running a Vite development server | `python main_aegis.py --dev` |

## Programmatic API Usage

You can import AEGIS detection modules directly into standalone Python scripts:

### File Scanner
```python
from core.scanner import FileScanner

scanner = FileScanner()
result = scanner.scan_file("C:/Users/Admin/Downloads/sample.exe")

print(result["status"])   # clean or infected
print(result["hash"])
print(result["details"])
```

### Bilingual Phishing & Scam Detection
```python
from ai.nlp_model import get_nlp_detector

detector = get_nlp_detector()
result = detector.analyze_text("Urgent bKash account update required. Verify PIN immediately.")

print(result["threat_class"])
print(result["confidence"])
print(result["keywords_found"])
```

### PE Binary HIDS Inspection
```python
from core.hids_analyzer import hids_analyzer

report = hids_analyzer.analyze_pe_file("C:/Windows/System32/calc.exe")
print(report["prediction"])
print(report["confidence"])
```

## License & Legal Disclaimer

AEGIS is provided for educational, defensive security research, and endpoint protection purposes. Maintainers assume no liability for misuse. Always verify firewall blocking actions and quarantine rules in a testing environment before deploying across production networks.
