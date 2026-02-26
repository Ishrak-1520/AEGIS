# AEGIS Network Module Documentation

## Overview

The Network Module provides **real-time Network Intrusion Detection System (NIDS)** and **Intrusion Prevention System (IPS)** capabilities for AEGIS. It captures live network traffic, analyzes it using Machine Learning models, detects cyber threats, and can automatically block malicious IP addresses.

---

## File Structure

```
core/network/
├── __init__.py          # Module exports and initialization
├── nids_engine.py       # Main NIDS engine with ML detection & IPS
├── sniffer_service.py   # Legacy sniffer service (deprecated)
├── data_adapter.py      # Data preprocessing and feature mapping
├── README.md            # This documentation
│
└── RT-XNIDS_FInal/      # ML Model Assets
    ├── model_live.pkl   # Trained Random Forest classifier
    ├── scaler_live.pkl  # Feature scaler (StandardScaler)
    ├── flow_builder_pro.py  # Flow extraction utilities
    ├── live_stats.json  # Runtime statistics
    └── alerts.log       # Threat detection log
```

---

## Core Components

### 1. NIDSEngine (`nids_engine.py`)

The main intrusion detection engine. Runs as a background thread and provides:

| Feature | Description |
|---------|-------------|
| **Packet Capture** | Uses Scapy to sniff live network traffic |
| **Flow Tracking** | Groups packets into bidirectional flows |
| **ML Detection** | Random Forest model trained on CICIDS dataset |
| **XAI Explanations** | Human-readable threat explanations |
| **IPS Integration** | Automatic IP blocking via Windows Firewall |

#### Key Classes

**`NetworkFlow`** - Tracks a network connection over time:
```python
class NetworkFlow:
    def __init__(self, packet):
        self.src_ip       # Source IP address
        self.dst_ip       # Destination IP address
        self.src_port     # Source port
        self.dst_port     # Destination port
        self.protocol     # TCP/UDP/ICMP
        self.packet_sizes # List of packet lengths
        self.inter_arrival_times  # Time between packets
    
    def get_features(self) -> dict:
        # Returns 6 features for ML model
```

**`NIDSEngine`** - Main detection engine:
```python
class NIDSEngine(threading.Thread):
    # Detection settings
    MIN_CONFIDENCE = 0.75      # Alert threshold
    ALERT_COOLDOWN = 5         # Seconds between alerts per IP
    LEARNING_DURATION = 30     # Baseline learning period
    
    # Key methods
    def start_monitoring()     # Begin packet capture
    def stop()                 # Stop monitoring
    def get_stats()            # Get detection statistics
    def set_sensitivity(level) # LOW/MEDIUM/HIGH
    def manual_block_ip(ip)    # IPS: Block specific IP
    def unblock_ip(ip)         # IPS: Remove block
```

---

### 2. SnifferService (`sniffer_service.py`)

⚠️ **DEPRECATED** - Use `NIDSEngine` instead.

Legacy service that provides basic packet sniffing. Kept for backward compatibility.

```python
class SnifferService(threading.Thread):
    def __init__(self, stop_event, alert_queue)
    def run()                  # Start capture
    def stop()                 # Stop capture
    def get_statistics()       # Get stats
```

---

### 3. DataAdapter (`data_adapter.py`)

Handles data preprocessing for the ML model:

- **Column Mapping**: Converts various column names to standardized format
- **Feature Extraction**: Extracts 6 core features needed by the model
- **Data Cleaning**: Handles missing values and normalization

| Internal Name | Common Aliases |
|---------------|----------------|
| Duration | dur, flow_duration, total_duration |
| FwdPkts | fwdpkts, total_fwd_packets, spkts |
| BwdPkts | bwdpkts, total_backward_packets |
| LenMean | lenmean, fwd_packet_length_mean |
| LenStd | lenstd, fwd_packet_length_std |
| IAT | iat, flow_iat_mean |

---

## How Detection Works

### Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        PACKET CAPTURE                            │
│   Scapy sniffs all TCP/UDP/ICMP packets on network interface     │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                        FLOW TRACKING                             │
│   Packets grouped by (src_ip, dst_ip, src_port, dst_port, proto) │
│   NetworkFlow accumulates: packet sizes, IAT, direction          │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                      FEATURE EXTRACTION                          │
│   6 Features: duration, fwd_pkts, bwd_pkts, len_mean, len_std,   │
│               iat_mean                                           │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                      ML INFERENCE                                │
│   StandardScaler → Random Forest → Confidence Score              │
│   Classes: BENIGN, PortScan, DDoS, Bot, etc.                     │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    THREAT CLASSIFICATION                         │
│   Heuristic rules + ML prediction → Final threat determination   │
│   Whitelist checking, confidence thresholding                    │
└──────────────────────────────────┬───────────────────────────────┘
                                   │
                         ┌─────────┴─────────┐
                         │                   │
                      BENIGN              THREAT
                         │                   │
                         ▼                   ▼
                     No Action        ┌─────────────────┐
                                      │  XAI EXPLAINER  │
                                      │  Generate human │
                                      │  -readable info │
                                      └────────┬────────┘
                                               │
                                      ┌────────┴────────┐
                                      │                 │
                                 IPS ENABLED?      ALERT QUEUE
                                      │                 │
                                      ▼                 ▼
                                Block IP via      Push to Frontend
                                Firewall          (NetworkMonitor.jsx)
```

---

## Detected Threat Types

| Threat Type | Description | Risk Level |
|-------------|-------------|------------|
| **PortScan** | Systematic scanning of ports to find vulnerabilities | HIGH |
| **Bot** | Automated attack traffic with very low inter-arrival time | HIGH |
| **DDoS** | Distributed denial of service with high volume traffic | CRITICAL |
| **SpamBot** | Email spam traffic on SMTP ports (25, 465, 587) | MEDIUM |
| **SuspiciousDownload** | Large unexpected downloads (potential malware) | MEDIUM |
| **AdTracker** | Advertising tracker/popup activity | LOW |
| **NoResponse** | One-way traffic (possible reconnaissance) | MEDIUM |
| **Anomaly** | ML-detected abnormal pattern (generic) | MEDIUM |

---

## XAI (Explainable AI) Integration

Each threat comes with human-readable explanations:

```python
xai_explanation = {
    "title": "Port Scanning Attack",
    "simple_explanation": "Someone is checking your computer for open doors (ports) to sneak in.",
    "technical_details": "High packet rate (150 packets in 0.5s) indicates systematic port enumeration.",
    "risk_level": "HIGH",
    "recommended_action": "This IP is scanning your system to find vulnerabilities...",
    "confidence_interpretation": "High Confidence - Very likely a threat",
    "attack_categories": ["PortScan"]
}
```

---

## IPS (Intrusion Prevention System)

When enabled, AEGIS can automatically block detected attackers:

### How It Works

1. Threat detected with confidence ≥ threshold
2. Source IP extracted from malicious flow
3. Windows Firewall rule created to block IP
4. IP logged to blocked list
5. Rule can be removed via `unblock_ip()`

### API Methods

```python
# Enable/Disable auto-blocking
nids_engine.set_auto_block(True)

# Manual block
nids_engine.manual_block_ip("192.168.1.100")

# Unblock
nids_engine.unblock_ip("192.168.1.100")

# Get blocked IPs
blocked = nids_engine.get_blocked_ips()
```

---

## Configuration

### Sensitivity Levels

| Level | Confidence Threshold | Description |
|-------|---------------------|-------------|
| LOW | 0.85 | Fewer alerts, only high-confidence threats |
| MEDIUM | 0.75 | Balanced detection (default) |
| HIGH | 0.60 | More alerts, catches subtle attacks |

### Whitelist Configuration

IPs that are never flagged as threats:

```python
WHITELIST_IPS = [
    "127.0.0.1",      # Localhost
    "192.168.0.1",    # Common gateway
    "192.168.1.1",
]

WHITELIST_RANGES = [
    "192.168.",       # Private Class C
    "10.0.",          # Private Class A
    "172.16.",        # Private Class B
]

SAFE_SERVICE_RANGES = [
    "142.250.",       # Google
    "13.107.",        # Microsoft
    "104.16.",        # Cloudflare
    "8.8.8.8",        # Google DNS
]
```

---

## Requirements

### System Requirements

| Requirement | Purpose |
|-------------|---------|
| **Npcap** | Packet capture on Windows |
| **Administrator Privileges** | Required for packet sniffing |
| **Python 3.8+** | Runtime environment |

### Python Dependencies

```
scapy          # Packet capture and analysis
joblib         # Model serialization
numpy          # Numerical operations
pandas         # Data manipulation (optional)
scikit-learn   # ML model inference
```

---

## Integration with AEGIS

### API Bridge Methods

The following methods are exposed via `api_bridge.py`:

| Method | Description |
|--------|-------------|
| `toggle_nids(enable)` | Start/stop network monitoring |
| `get_nids_status()` | Get NIDS statistics |
| `get_nids_alerts(limit)` | Get recent threat alerts |
| `block_ip(ip)` | Manually block an IP |
| `unblock_ip(ip)` | Remove IP block |
| `get_blocked_ips()` | List blocked IPs |

### Frontend Integration

The React `NetworkMonitor.jsx` component:
- Displays real-time threat feed
- Shows statistics (packets, flows, threats, blocked IPs)
- Online/Offline toggle for NIDS
- Expandable threat cards with XAI explanations
- Manual block/unblock buttons

---

## Model Information

| Property | Value |
|----------|-------|
| **Model Type** | Random Forest Classifier |
| **Training Data** | CICIDS2017 Dataset |
| **Features** | 6 (duration, packets, lengths, IAT) |
| **Classes** | BENIGN + 14 attack types |
| **Location** | `RT-XNIDS_FInal/model_live.pkl` |

---

## Example Usage

```python
from core.network import NIDSEngine, get_nids_engine
import threading
import queue

# Create engine with alert queue
stop_event = threading.Event()
alert_queue = queue.Queue()

engine = NIDSEngine(stop_event=stop_event, alert_queue=alert_queue)

# Configure
engine.set_sensitivity("MEDIUM")
engine.set_auto_block(True)

# Start monitoring (non-blocking)
engine.start()

# Check for alerts
while not alert_queue.empty():
    alert = alert_queue.get()
    print(f"Threat: {alert['threat_type']} from {alert['source_ip']}")

# Stop
engine.stop()
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Npcap not installed" | Download from https://npcap.com |
| "Permission denied" | Run AEGIS as Administrator |
| "Model not found" | Ensure `RT-XNIDS_FInal/*.pkl` files exist |
| No threats detected | Check sensitivity level, verify traffic exists |
| High false positives | Lower sensitivity to LOW |

---

## Version History

| Version | Changes |
|---------|---------|
| 2.0 | Added XAI explanations, IPS integration, new threat types |
| 1.5 | Added learning mode, whitelist configuration |
| 1.0 | Initial ML-based NIDS implementation |

---

*Last Updated: February 2026*
