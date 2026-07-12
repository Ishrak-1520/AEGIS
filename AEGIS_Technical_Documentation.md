# AEGIS — Advanced Endpoint Guard & Intelligence System
## Complete Technical Documentation v2.0

---

## 1. Executive Summary

**AEGIS** is a comprehensive desktop cybersecurity suite for Windows that provides real-time endpoint protection through a multi-layered defense architecture. It combines traditional signature-based malware detection with AI/ML-powered behavioral analysis, NLP-based screen threat detection, network intrusion detection, and a secure password vault — all managed through a modern React-based dashboard.

| Attribute | Detail |
|---|---|
| **Version** | 2.0.0 |
| **Platform** | Windows 10/11 |
| **Backend** | Python 3.8+ |
| **Frontend** | React 19 + Vite + TailwindCSS |
| **Bridge** | pywebview (Python ↔ JavaScript) |
| **Database** | SQLite (`cyberguard.db`) |
| **AI/ML** | scikit-learn (RandomForest), keyword-based NLP, LLM integration (SiftEngine) |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AEGIS Application                     │
├──────────────┬──────────────────────────────────────────┤
│  React UI    │  Python Backend                          │
│  (Vite SPA)  │                                          │
│              │  ┌─────────────────────────────────────┐ │
│  Dashboard   │  │         AegisAPI Bridge              │ │
│  Scanner     │  │  (core/api_bridge.py — pywebview)   │ │
│  NLP Panel   │  └───────┬─────────────────────────────┘ │
│  HIDS Live   │          │                               │
│  Network     │  ┌───────┴───────────────────────────┐   │
│  Quarantine  │  │        Core Security Engine        │   │
│  Passwords   │  │  Scanner │ RTP │ HIDS │ NIDS │ NLP │   │
│  Settings    │  └───────┬───────────────────────────┘   │
│  Reports     │          │                               │
│              │  ┌───────┴───────────────────────────┐   │
│              │  │    Data & Security Layer           │   │
│              │  │  SQLite DB │ Encryption │ Auth     │   │
│              │  └───────────────────────────────────┘   │
└──────────────┴──────────────────────────────────────────┘
```

### 2.2 Entry Points

| Entry Point | File | Description |
|---|---|---|
| **Modern UI** | `main_aegis.py` | Primary. Launches React frontend via pywebview. Auto-builds frontend if needed. |
| **Legacy UI** | `main.py` | PyQt5-based desktop GUI (deprecated). |

### 2.3 Directory Structure

```
CGP-2/
├── main_aegis.py          # Modern entry point (pywebview + React)
├── main.py                # Legacy entry point (PyQt5)
├── core/                  # Core security modules
│   ├── api_bridge.py      # Python ↔ JS API bridge (AegisAPI class)
│   ├── scanner.py         # File scanner (YARA + hash + heuristic)
│   ├── realtime_protection.py  # RTP: screen OCR + memory HIDS
│   ├── threat_prevention.py    # Automated response (quarantine, block, kill)
│   ├── monitor.py         # System resource monitor (CPU/RAM/Disk/Net)
│   ├── hids_analyzer.py   # PE file ML analyzer + Volatile memory HIDS
│   ├── quarantine.py      # Encrypted quarantine vault
│   ├── sift_engine.py     # LLM-powered code auditor
│   ├── system_logger.py   # Centralized rotating-file logger
│   ├── native_notifications.py  # Windows Toast notifications
│   └── network/
│       ├── nids_engine.py      # ML-based network intrusion detection
│       ├── sniffer_service.py  # Legacy packet sniffer service
│       └── data_adapter.py     # Data standardization for NIDS
├── ai/
│   ├── nlp_model.py       # NLP threat detector (keyword + regex + LLM)
│   ├── explainable_ai.py  # XAI: word importance & threat explanations
│   └── models/            # Serialized ML models (.pkl)
├── security/
│   ├── encryption.py      # AES-256-GCM + PBKDF2 cryptography
│   ├── auth.py            # Authentication & session management
│   └── password_manager.py # Secure password vault
├── database/
│   ├── db_manager.py      # Thread-safe SQLite DAL (singleton)
│   └── schema.sql         # Database schema (7 tables)
├── ui/frontend/           # React 19 + Vite + TailwindCSS
│   └── src/components/    # Dashboard, Scanner, NLP, HIDS, Network, etc.
├── signatures/            # YARA rules & hash databases
├── logs/                  # Rotating log files
├── quarantine/            # Encrypted quarantined files
└── tests/                 # pytest test suite
```

---

## 3. Core Security Modules

### 3.1 File Scanner (`core/scanner.py`)

The `FileScanner` class provides multi-engine malware scanning with three detection methods:

**Detection Engines:**

| Engine | Method | Details |
|---|---|---|
| **YARA** | Pattern matching | Loads `.yar` rule files from `signatures/` directory |
| **Hash Signatures** | MD5/SHA-256 lookup | Compares file hashes against known malware database |
| **Heuristic Analysis** | Pattern detection | Checks for encoded PowerShell, suspicious VBS/JS objects, base64 encoded executables |

**Scan Modes:**
- **Quick Scan** — Scans common threat locations (Desktop, Downloads, Temp, AppData, Startup)
- **Full Scan** — Recursive scan of the entire user home directory
- **Custom Scan** — User-specified file or directory

**Key Features:**
- Progress callback system for real-time UI updates
- Configurable file size limits (default: 100MB max)
- Automatic skip of system/binary files
- Threat results logged to SQLite database
- EICAR test file detection built-in

**Scan Result Format:**
```python
{
    "status": "CLEAN" | "INFECTED" | "SUSPICIOUS" | "ERROR",
    "threat": "Threat name or None",
    "engine": "yara" | "hash" | "heuristic",
    "details": "Additional context"
}
```

### 3.2 Real-Time Protection (`core/realtime_protection.py`)

The `RealTimeProtection` class provides continuous screen monitoring using OCR and NLP analysis, plus volatile memory HIDS.

**Screen Monitoring Pipeline:**
```
Screenshot → Tesseract OCR → Text Extraction → NLP Analysis → Threat Alert
     ↑                                                              │
     └──────────── Continuous loop (configurable interval) ─────────┘
```

**Components:**
1. **Screen Capture** — Takes periodic screenshots using `PIL.ImageGrab`
2. **OCR Processing** — Extracts text via `pytesseract` (Tesseract OCR engine)
3. **NLP Threat Analysis** — Passes extracted text to `NLPThreatDetector` for phishing/scam detection
4. **Volatile Memory HIDS** — Collects live Windows telemetry and feeds to ML classifier

**Threat Callback System:**
- RTP supports registering callback functions via `register_threat_callback()`
- When a threat is detected, all registered callbacks fire with threat data
- The API bridge uses this to push alerts to the React frontend and trigger Windows Toast notifications

**Configuration:**
- Monitoring interval: 5 seconds (default)
- Screen analysis resolution: Configurable
- Sensitivity levels: LOW / MEDIUM / HIGH

### 3.3 HIDS Analyzer (`core/hids_analyzer.py`)

Two independent ML-based analyzers:

#### 3.3.1 MalwareAnalyzer (PE File Analysis)
- Parses Windows PE files using the `pefile` library
- Extracts Import Address Table (IAT) API calls as features
- Maps 80+ common Windows API functions (VirtualAlloc, CreateRemoteThread, etc.) to a 100-dimensional feature vector
- Classifies using a pre-trained RandomForest model (`hids_model.pkl`)
- Returns `is_malware`, `threat_score` (0.0–1.0), and `confidence`

#### 3.3.2 VolatileMemoryHIDS (Live Memory Analysis)
- Analyzes live system memory telemetry in real-time
- Uses 5 features: `svcscan.nservices`, `svcscan.kernel_drivers`, `handles.nmutant`, `dlllist.avg_dlls_per_proc`, `pslist.nprocs64bit`
- **Dynamic Baseline Calibration** — Solves the "Sandbox Paradox" where local telemetry differs from training data (CIC-MalMem-2022)
  - Captures 5 baseline samples on startup
  - Calculates offset between local baseline and training population mean
  - Applies calibration offset to all subsequent predictions
- Adaptive threat threshold: 0.90 (configurable)
- Reports inference latency in milliseconds

### 3.4 NLP Threat Detector (`ai/nlp_model.py`)

The `NLPThreatDetector` performs text-based threat analysis using keyword matching, regex patterns, and optional LLM verification.

**Detection Categories:**

| Category | Weight | Examples |
|---|---|---|
| Critical Keywords | ×30 | malware, ransomware, trojan, keylogger |
| Suspicious URLs | ×20 | IP-based URLs, URL shorteners, free TLD domains |
| Web Threats | ×20 | Clickjacking prompts, fake virus alerts, browser hijacking |
| Scam Indicators | ×18 | Nigerian prince, pyramid scheme, get rich quick |
| Phishing | ×15 | Verify account, suspended account, update payment |
| Social Engineering | ×12 | Congratulations, lottery winner, free money |
| Credential Requests | +25 | Enter password, credit card, CVV |
| Financial Requests | +20 | Send money, wire transfer, bank account |
| Urgency Language | +10 | Act now, urgent, expires today |
| PII Detection | ×25 | Credit cards (regex), SSN, email, phone, IPv4 |

**Bilingual Support:** All keyword categories include both English and Bangla (বাংলা) equivalents.

**LLM Context Verification (SiftEngine):**
- Only MEDIUM-level threats are sent to the LLM for context verification
- HIGH/CRITICAL alerts fire immediately (speed priority)
- The LLM can override a MEDIUM detection to SAFE if the context is benign (reduces false positives)

**Threat Classification Scale:**

| Score Range | Level | Confidence Formula |
|---|---|---|
| ≥80 | CRITICAL | min(95%, 70% + score×0.25) |
| ≥50 | HIGH | min(90%, 60% + score×0.4) |
| ≥30 | MEDIUM | min(85%, 50% + score×0.8) |
| ≥10 | LOW | min(75%, 40% + score×2.0) |
| <10 | SAFE | 100% − score |

### 3.5 Network Intrusion Detection — NIDS (`core/network/nids_engine.py`)

The `NIDSEngine` provides real-time network packet capture and ML-based flow analysis.

**Architecture:**
```
Scapy Packet Capture → Flow Aggregation → Feature Extraction → ML Inference → Alert
         │                                                            │
         └── Background sniffer thread                    Heuristic override ──┘
```

**Flow Features (6-dimensional):**
1. `duration` — Flow duration in seconds
2. `fwd_packets` — Forward packet count
3. `bwd_packets` — Backward packet count
4. `pkt_len_mean` — Mean packet length
5. `pkt_len_std` — Packet length standard deviation
6. `iat_mean` — Mean inter-arrival time

**Dual Detection System:**
- **ML Model** — RandomForest classifier trained on network intrusion datasets
- **Heuristic Engine** — Independent rule-based detection for web threats (clickjacking, ad injection, suspicious redirects, ad trackers, spam bots, suspicious downloads)
- Results are merged: if both flag a flow, the heuristic reason is preferred (more specific)

**Smart Whitelisting:**
- Local/private IP ranges (192.168.x, 10.x, 172.16.x)
- Known safe services (Google, Microsoft, DNS resolvers)
- Cloudflare deliberately excluded from safe list (hosts malicious CDN-proxied content)

**IPS (Intrusion Prevention):**
- Auto-block mode: detected attacker IPs automatically blocked via Windows Firewall
- Uses `ThreatPreventionSystem` for firewall rule management
- Manual block/unblock via API

**Operational Modes:**
- **Learning Mode** — First 30 seconds: captures baseline, no alerts
- **Active Mode** — Full detection with alerting
- Minimum 3 packets required before flow analysis

### 3.6 Threat Prevention (`core/threat_prevention.py`)

The `ThreatPreventionSystem` provides automated response capabilities:

| Action | Method | Implementation |
|---|---|---|
| **File Quarantine** | `quarantine_file()` | AES-256 encrypted isolation to `quarantine/` directory |
| **Process Termination** | `kill_process()` | Terminates malicious processes by PID |
| **Domain Blocking** | `block_domain()` | Adds entries to Windows `hosts` file (127.0.0.1 redirect) |
| **IP Blocking** | `block_ip()` | Creates Windows Firewall outbound block rules via `netsh` |
| **IP Unblocking** | `unblock_ip()` | Removes firewall rules |
| **Network Isolation** | `isolate_network()` | Blocks all outbound traffic except critical services |

> **Note:** Network blocking/firewall operations require Administrator privileges.

### 3.7 SIFT Engine — AI Code Auditor (`core/sift_engine.py`)

The `SiftEngine` is a hybrid AI-static analysis tool for automated code security auditing.

**Capabilities:**
1. **Language Detection** — Uses Pygments to identify programming language
2. **Registry Verification** — Real-time PyPI/npm package verification to detect hallucinated or typosquatted imports ("Slopsquatting")
3. **ReDoS Detection** — Static regex analysis for catastrophic backtracking patterns (CWE-730)
4. **LLM Security Audit** — Full vulnerability analysis via OpenAI-compatible API (Google Gemma 4 via OpenRouter)
5. **Fix Recognition** — Analyzes patched code to verify if vulnerabilities are truly resolved
6. **Screen Text Analysis** — Contextual threat verification for RTP false-positive reduction

**Scoring:**
- 90–100: Safe code
- 70–89: Minor conditional risks
- 40–69: Moderate vulnerabilities
- 0–39: Critical, easily exploitable

### 3.8 Explainable AI (`ai/explainable_ai.py`)

Provides interpretability for NLP threat detection decisions:
- **Keyword Highlighting** — Wraps suspicious keywords in markdown bold markers
- **Word Importance Scoring** — Rates each word 0.0–1.0 based on threat relevance
- **ASCII Visualization** — Color-coded emoji indicators (🔴 High, 🟡 Medium, 🟢 Low, ⚪ None)
- **Decision Factor Extraction** — Structured list of factors that contributed to the detection

---

## 4. Security Infrastructure

### 4.1 Encryption (`security/encryption.py`)

The `EncryptionManager` provides all cryptographic operations:

| Operation | Algorithm | Parameters |
|---|---|---|
| Data Encryption | AES-256-GCM | 12-byte random nonce, 16-byte auth tag |
| Key Derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations, 256-bit salt |
| Password Hashing | PBKDF2 | Same as key derivation |
| Password Verification | Constant-time comparison | `secrets.compare_digest()` |
| File Hashing | SHA-256 / SHA-1 / MD5 | Chunked reading (4KB) for large files |
| Password Generation | CSPRNG | `secrets.choice()` with charset enforcement |
| Secure Memory Wipe | Overwrite + delete | Best-effort for `bytearray` types |

### 4.2 Authentication (`security/auth.py`)

The `AuthenticationManager` handles user sessions:
- Master password registration with strength validation (minimum score: 60)
- Login with PBKDF2 password verification
- Session-based authentication with 30-minute timeout
- Session key derived from master password (used for password vault encryption)
- Thread-safe with `threading.Lock`
- Audit logging of all auth events (login, logout, registration, failures)

### 4.3 Password Vault (`security/password_manager.py`)

The `PasswordManager` provides encrypted credential storage:
- Passwords encrypted with the user's session key (AES-256-GCM)
- Only decrypted on-demand when the user requests to view a password
- CRUD operations: add, retrieve, update, delete, search
- Built-in password generator with configurable charset
- Password strength evaluator (0–100 score with qualitative rating)

### 4.4 Quarantine System (`core/quarantine.py`)

The `QuarantineManager` isolates infected files:
1. Calculates SHA-256 hash of the file for tracking
2. Generates a unique AES-256 encryption key per file
3. Encrypts file contents and writes to `quarantine/` directory
4. Removes the original file from disk
5. Records metadata + encryption key in SQLite database
6. Supports restoration (decrypt + move back) and permanent deletion
7. Automatic cleanup of files older than 30 days

---

## 5. Data Layer

### 5.1 Database (`database/db_manager.py`)

Thread-safe singleton `DatabaseManager` using SQLite with `threading.local()` for per-thread connections.

**Schema (7 tables):**

| Table | Purpose | Key Fields |
|---|---|---|
| `users` | Authentication | username, password_hash, salt, last_login |
| `scan_history` | Scan records | scan_type, scan_path, threats_found, files_scanned, duration |
| `threat_logs` | Detected threats | threat_type, threat_level, source, confidence_score |
| `quarantine` | Quarantined files | original_path, quarantine_path, file_hash, encryption_key |
| `stored_passwords` | Password vault | website, username, encrypted_password, category |
| `system_events` | Audit log | event_type, severity, message, details |
| `network_connections` | Network monitoring | local/remote address, port, protocol, process_name, is_suspicious |
| `settings` | App config | key-value pairs |
| `malware_signatures` | Known malware hashes | signature_hash, signature_name, threat_level |

### 5.2 System Logger (`core/system_logger.py`)

Centralized logging with three rotating file handlers:
- `cyberguard.log` — Application events (10MB max, 5 backups)
- `threats.log` — Security threat events
- `audit.log` — User action audit trail

### 5.3 Native Notifications (`core/native_notifications.py`)

Windows Toast notifications via PowerShell:
- Non-blocking (fires in a daemon thread)
- Audio escalation: default sound for LOW/MEDIUM, alarm for HIGH/CRITICAL
- Input sanitization to prevent PowerShell injection

---

## 6. API Bridge & Frontend

### 6.1 API Bridge (`core/api_bridge.py`)

The `AegisAPI` class is the central bridge between the Python backend and React frontend, exposed to JavaScript via `pywebview`.

**API Surface (35+ methods):**

| Category | Methods |
|---|---|
| System | `get_system_stats()`, `get_version()`, `browse_directory()`, `browse_file()` |
| Scanner | `start_scan()`, `get_scan_progress()`, `stop_scan()` |
| Auth | `check_auth_status()`, `register_master_password()`, `login_master_password()` |
| Passwords | `get_passwords()`, `get_decrypted_password()`, `add_password()`, `delete_password()` |
| Quarantine | `get_quarantined_items()`, `restore_quarantine_item()`, `delete_quarantine_item()` |
| RTP | `get_rtp_status()`, `toggle_rtp()`, `get_pending_threat_alerts()` |
| HIDS | `get_volatile_memory_status()`, `recalibrate_hids()` |
| NLP | `analyze_text()`, `get_nlp_history()`, `clear_nlp_history()` |
| NIDS | `get_network_alerts()`, `get_nids_status()`, `toggle_nids()` |
| IPS | `get_blocked_ips()`, `block_ip()`, `unblock_ip()`, `toggle_auto_block()` |
| SIFT | `sift_detect_language()`, `sift_analyze_code()` |
| Settings | `get_all_settings()`, `save_setting()`, `save_all_settings()` |
| Logs | `get_recent_logs()`, `get_threat_activity_history()` |

**Key Design Patterns:**
- Scans run in background `threading.Thread` with progress callbacks
- NIDS starts/stops with RTP toggle (coordinated lifecycle)
- Threat alerts use a polling queue (frontend polls `get_pending_threat_alerts()`)
- Settings changes apply immediately via `_apply_setting()` side-effects
- AI narrative generation for HIDS status (`_generate_live_narrative()`)

### 6.2 Frontend (`ui/frontend/`)

React 19 SPA built with Vite and styled with TailwindCSS.

**Components:**

| Component | File | Purpose |
|---|---|---|
| Dashboard | `Dashboard.jsx` | System overview, resource charts, threat activity graph |
| Scanner | `Scanner.jsx` | Scan controls, progress bar, threat results |
| NLP Analyzer | `NLPAnalyzer.jsx` | Text input, threat analysis results with keyword highlighting |
| HIDS Live | `HidsLiveDashboard.jsx` | Real-time memory telemetry, AI reasoning narrative |
| Network Monitor | `NetworkMonitor.jsx` | NIDS status, network alerts, IPS controls, blocked IPs |
| Password Manager | `PasswordManager.jsx` | Vault UI with master password auth flow |
| Quarantine | `Quarantine.jsx` | Quarantined file list, restore/delete actions |
| Settings | `Settings.jsx` | Application configuration panel |
| Reports | `Reports.jsx` | Scan/threat reports and log viewer |
| SIFT | `Sift/` | Code security audit interface |
| Threat Alerts | `ThreatAlertDialog.jsx`, `ThreatAlertManager.jsx`, `ThreatNotification.jsx` | Real-time threat notification overlays |

**Frontend ↔ Backend Communication:**
```javascript
// All API calls go through pywebview's JS bridge:
window.pywebview.api.methodName(args)
  .then(result => { /* handle response */ })
```

---

## 7. ML Models & AI

### 7.1 Model Inventory

| Model | File | Algorithm | Features | Purpose |
|---|---|---|---|---|
| HIDS PE Classifier | `ai/models/hids_model.pkl` | RandomForest | 100 (IAT API calls) | PE file malware detection |
| HIDS PE Scaler | `ai/models/hids_scaler.pkl` | StandardScaler | 100 | Feature normalization |
| Volatile Memory HIDS | `ai/models/volatile_hids_model.pkl` | RandomForest | 5 (memory telemetry) | Fileless malware detection |
| NIDS Classifier | `core/network/RT-XNIDS_FInal/model_live.pkl` | RandomForest | 6 (flow features) | Network intrusion detection |
| NIDS Scaler | `core/network/RT-XNIDS_FInal/scaler_live.pkl` | StandardScaler | 6 | Feature normalization |

### 7.2 External AI Integration

The **SiftEngine** connects to an OpenAI-compatible API (`openrouter.ai/api/v1`) using:
- Model: `google/gemma-4-26b-a4b-it:free` (code audit and screen text analysis)
- API key stored in `.env` as `SIFT_API_KEY`
- Used for: code vulnerability analysis, screen text false-positive reduction, fix verification

---

## 8. Configuration & Deployment

### 8.1 Environment Variables

| Variable | Purpose | Required |
|---|---|---|
| `SIFT_API_KEY` | API key for SiftEngine LLM features | Optional (degrades gracefully) |
| `CYBERGUARD_DEBUG` | Enable debug mode logging | Optional |

### 8.2 Application Settings (SQLite)

| Setting | Default | Type |
|---|---|---|
| `realTimeProtection` | true | boolean |
| `autoScan` | true | boolean |
| `notifications` | true | boolean |
| `darkMode` | true | boolean |
| `autoBlockThreats` | true | boolean |
| `scanInterval` | 60 | integer (minutes) |
| `threatSensitivity` | MEDIUM | LOW/MEDIUM/HIGH |

### 8.3 System Requirements

- **OS:** Windows 10/11
- **Python:** 3.8+
- **Node.js:** Required for frontend build
- **Tesseract OCR:** Must be installed and in PATH (for RTP screen monitoring)
- **Npcap:** Required for NIDS packet capture
- **Admin Privileges:** Required for firewall rules, network blocking, and packet capture

### 8.4 Key Dependencies

**Python:** `pywebview`, `psutil`, `yara-python`, `cryptography`, `pytesseract`, `Pillow`, `scikit-learn`, `joblib`, `numpy`, `pefile`, `scapy`, `openai`, `pygments`, `watchdog`, `requests`

**Frontend:** `react`, `react-dom`, `vite`, `tailwindcss`, `recharts`, `framer-motion`

### 8.5 Build & Run

```bash
# Install Python dependencies
pip install -r requirements.txt

# Build frontend (auto-handled by main_aegis.py)
cd ui/frontend && npm install && npm run build

# Run application
python main_aegis.py
```

---

## 9. Data Flow Diagrams

### 9.1 Threat Detection Flow

```
User Activity
     │
     ├─→ File System Change → File Scanner → YARA/Hash/Heuristic → Threat?
     │                                                                  │
     ├─→ Screen Content → OCR → NLP Detector → LLM Verify? → Threat? ─┤
     │                                                                  │
     ├─→ Network Traffic → Scapy Capture → Flow Analysis → ML/Heuristic┤
     │                                                                  │
     └─→ System Memory → Telemetry → Volatile HIDS ML ────────────────┤
                                                                       │
                                                              ┌────────┴────────┐
                                                              │ Threat Response  │
                                                              ├─────────────────┤
                                                              │ • UI Alert       │
                                                              │ • Toast Notify   │
                                                              │ • Quarantine     │
                                                              │ • Process Kill   │
                                                              │ • IP Block       │
                                                              │ • DB Log         │
                                                              └─────────────────┘
```

### 9.2 Authentication & Password Vault Flow

```
User → Master Password → PBKDF2(password, salt) → Derived Key
                                                        │
                                    ┌───────────────────┤
                                    │                   │
                              Verify against        Session Key
                              stored hash           (in memory)
                                    │                   │
                              Auth Success         Encrypt/Decrypt
                                    │              vault passwords
                              Create Session        (AES-256-GCM)
                              (30 min timeout)
```

---

## 10. Security Considerations

| Area | Implementation |
|---|---|
| **Password Storage** | PBKDF2-HMAC-SHA256 with 100K iterations, 256-bit salt |
| **Data Encryption** | AES-256-GCM with random nonces, authenticated encryption |
| **Quarantine Security** | Per-file unique encryption keys, keys stored in DB |
| **Session Security** | 30-minute timeout, memory wipe on logout |
| **Input Sanitization** | PowerShell injection prevention in notifications |
| **SQL Safety** | Parameterized queries throughout (no string concatenation) |
| **Timing Attacks** | `secrets.compare_digest()` for password verification |
| **API Security** | No external network exposure (pywebview local bridge only) |

---

*Document generated from full codebase analysis of 30+ source files across all modules.*
*Last updated: May 14, 2026*
