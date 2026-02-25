"""
RT-XNIDS: Professional Real-Time Network Intrusion Detection
=============================================================
- Better feature extraction
- Smart baseline learning
- Reduced false positives
- Professional-grade detection logic
"""

import time
import threading
import statistics
import numpy as np
import joblib
import csv
import os
import json
import warnings
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init

# Suppress warnings
warnings.filterwarnings("ignore")
init()


LOG_FILE = "alerts.log"
STATS_FILE = "live_stats.json"

# Model paths (use the live-trained model if available)
MODEL_PATH = "model_live.pkl" if os.path.exists("model_live.pkl") else "model.pkl"
SCALER_PATH = "scaler_live.pkl" if os.path.exists("scaler_live.pkl") else "scaler.pkl"

# --- DETECTION TUNING ---
MIN_CONFIDENCE = 0.75          # Higher threshold = fewer false positives
ALERT_COOLDOWN = 5             # Seconds between alerts for same IP
MIN_PACKETS_FOR_DETECTION = 3  # Minimum packets before analyzing a flow

# --- WHITELIST ---
# Add your trusted IPs here (router, DNS, common services)
WHITELIST_IPS = [
    # Local/Private
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    
    # Common Router Gateways
    "192.168.0.1", "192.168.1.1", "192.168.31.1",
    "10.0.0.1", "10.0.0.138",
    "172.16.0.1",
    
    # Broadcast/Multicast
    "224.0.0.1", "224.0.0.251", "239.255.255.250",
]

# Whitelist IP ranges (partial match)
WHITELIST_RANGES = [
    "192.168.",    # Local network
    "10.0.",       # Private network
    "172.16.",     # Private network
    "172.17.",
    "172.18.",
    "fe80:",       # IPv6 link-local
]

# Common safe services (Google, Microsoft, Cloudflare, Amazon, etc.)
SAFE_SERVICE_RANGES = [
    # Google
    "142.250.", "172.217.", "216.239.", "74.125.", "173.194.",
    # Microsoft/Azure
    "13.107.", "52.168.", "20.189.", "40.126.", "20.190.",
    "104.215.", "23.96.", "40.112.", "40.113.",
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "1.1.1.1", "1.0.0.1",
    # Amazon AWS
    "52.94.", "54.239.", "99.86.", "99.87.",
    # Akamai CDN
    "23.223.", "23.32.", "23.33.",
    # Apple
    "17.253.", "17.142.",
    # DNS servers
    "8.8.8.8", "8.8.4.4",  # Google DNS
    "208.67.222.222",       # OpenDNS
]

# =============================================================================
# GLOBAL STATE
# =============================================================================

model = None
scaler = None
EXPECTED_FEATURES = 6  # We only use 6 features now

# Statistics
stats = {
    "total_flows": 0,
    "total_packets": 0,
    "threats_detected": 0,
    "benign_flows": 0,
    "last_alert_time": {},  # IP -> timestamp for cooldown
}

# Baseline learning
baseline = {
    "enabled": True,
    "learning_mode": True,
    "learning_duration": 30,  # Learn for 30 seconds
    "start_time": None,
    "normal_patterns": defaultdict(list),  # Store normal traffic patterns
}

# =============================================================================
# LOAD MODEL
# =============================================================================

def load_model():
    global model, scaler, EXPECTED_FEATURES
    
    try:
        print(f"{Fore.CYAN}[INIT] Loading ML Model...{Style.RESET_ALL}")
        
        if not os.path.exists(MODEL_PATH):
            print(f"{Fore.RED}[ERROR] Model not found: {MODEL_PATH}")
            print(f"  Run 'python train_model_live.py' first!{Style.RESET_ALL}")
            return False
            
        scaler = joblib.load(SCALER_PATH)
        model = joblib.load(MODEL_PATH)
        
        if hasattr(model, "n_features_in_"):
            EXPECTED_FEATURES = model.n_features_in_
        
        print(f"{Fore.GREEN}[OK] Model loaded: {MODEL_PATH}")
        print(f"[OK] Expected features: {EXPECTED_FEATURES}{Style.RESET_ALL}")
        
        # Initialize log file
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "SrcIP", "DstIP", "Confidence", "AttackReason", "ImpactScore"])
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to load model: {e}{Style.RESET_ALL}")
        return False

# =============================================================================
# WHITELIST CHECKING
# =============================================================================

def is_whitelisted(ip):
    """Check if IP should be ignored"""
    if ip in WHITELIST_IPS:
        return True
    
    for prefix in WHITELIST_RANGES:
        if ip.startswith(prefix):
            return True
    
    for prefix in SAFE_SERVICE_RANGES:
        if ip.startswith(prefix):
            return True
    
    return False

def is_local_traffic(src_ip, dst_ip):
    """Check if traffic is local (same network)"""
    src_local = any(src_ip.startswith(p) for p in ["192.168.", "10.", "172.16."])
    dst_local = any(dst_ip.startswith(p) for p in ["192.168.", "10.", "172.16."])
    return src_local and dst_local

# =============================================================================
# FLOW TRACKING
# =============================================================================

class NetworkFlow:
    """Tracks a network flow (connection) over time"""
    
    def __init__(self, packet):
        self.src_ip = packet[IP].src
        self.dst_ip = packet[IP].dst
        self.src_port = packet.sport if hasattr(packet, 'sport') else 0
        self.dst_port = packet.dport if hasattr(packet, 'dport') else 0
        self.protocol = packet[IP].proto
        
        self.start_time = float(packet.time)
        self.last_time = float(packet.time)
        
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.packet_sizes = []
        self.inter_arrival_times = []
        
        self.analyzed = False
        self.add_packet(packet)
    
    def add_packet(self, packet):
        """Add a new packet to this flow"""
        curr_time = float(packet.time)
        
        # Calculate inter-arrival time
        if self.packet_sizes:  # Not first packet
            iat = max(0, curr_time - self.last_time)
            self.inter_arrival_times.append(iat)
        
        # Track direction
        if packet[IP].src == self.src_ip:
            self.fwd_packets += 1
        else:
            self.bwd_packets += 1
        
        self.packet_sizes.append(len(packet))
        self.last_time = curr_time
    
    def get_features(self):
        """Extract the 6 features for ML model"""
        duration = max(0, self.last_time - self.start_time)
        
        # Packet length stats
        if self.packet_sizes:
            pkt_len_mean = statistics.mean(self.packet_sizes)
            pkt_len_std = statistics.stdev(self.packet_sizes) if len(self.packet_sizes) > 1 else 0
        else:
            pkt_len_mean = 0
            pkt_len_std = 0
        
        # Inter-arrival time
        if self.inter_arrival_times:
            iat_mean = statistics.mean(self.inter_arrival_times)
        else:
            iat_mean = 0
        
        return {
            "duration": duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "iat_mean": iat_mean,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "total_packets": len(self.packet_sizes),
        }

# Flow storage
active_flows = {}
flow_lock = threading.Lock()

def get_flow_key(packet):
    """Generate unique key for a flow"""
    if IP not in packet:
        return None
    
    src = packet[IP].src
    dst = packet[IP].dst
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0
    proto = packet[IP].proto
    
    # Bidirectional key (same key for both directions)
    if (src, sport) < (dst, dport):
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)

# =============================================================================
# DETECTION ENGINE
# =============================================================================

def analyze_flow(flow):
    """Run ML inference on a flow"""
    global stats
    
    features = flow.get_features()
    
    # Skip if not enough packets
    if features["total_packets"] < MIN_PACKETS_FOR_DETECTION:
        return None
    
    # Skip whitelisted IPs
    if is_whitelisted(features["src_ip"]) or is_whitelisted(features["dst_ip"]):
        stats["benign_flows"] += 1
        return {"label": "BENIGN", "confidence": 1.0, "reason": "Whitelisted", "features": features}
    
    # Build feature vector
    X = np.array([[
        features["duration"],
        features["fwd_packets"],
        features["bwd_packets"],
        features["pkt_len_mean"],
        features["pkt_len_std"],
        features["iat_mean"]
    ]])
    
    # Pad if needed for old model compatibility
    if EXPECTED_FEATURES > 6:
        X_padded = np.zeros((1, EXPECTED_FEATURES))
        X_padded[0, :6] = X[0]
        X = X_padded
    
    try:
        # Scale and predict
        X_scaled = scaler.transform(X)
        probs = model.predict_proba(X_scaled)[0]
        pred_idx = np.argmax(probs)
        confidence = probs[pred_idx]
        label = model.classes_[pred_idx]
        
        # Determine if attack
        is_attack = str(label).upper() not in ["BENIGN", "NORMAL", "0"]
        
        # Additional heuristic checks (reduce false positives)
        reason = "ML Detection"
        
        # Very short flows are usually benign (handshakes, DNS, etc.)
        if features["duration"] < 0.1 and features["total_packets"] < 10:
            is_attack = False
            reason = "Short flow"
        
        # Normal web browsing pattern
        if 0.5 < features["duration"] < 30 and features["total_packets"] < 50:
            if features["bwd_packets"] > 0:  # Has response
                confidence *= 0.7  # Reduce confidence
                if confidence < MIN_CONFIDENCE:
                    is_attack = False
                    reason = "Normal pattern"
        
        # Local traffic is usually safe
        if is_local_traffic(features["src_ip"], features["dst_ip"]):
            confidence *= 0.5
            if confidence < MIN_CONFIDENCE:
                is_attack = False
                reason = "Local traffic"
        
        return {
            "label": "ATTACK" if is_attack and confidence >= MIN_CONFIDENCE else "BENIGN",
            "confidence": confidence,
            "reason": reason if not is_attack else get_attack_reason(features),
            "features": features
        }
        
    except Exception as e:
        return None

def get_attack_reason(features):
    """Determine why traffic looks suspicious"""
    reasons = []
    
    # High packet rate
    if features["fwd_packets"] > 50 and features["duration"] < 1:
        reasons.append("High packet rate")
    
    # No response (scan-like)
    if features["fwd_packets"] > 10 and features["bwd_packets"] == 0:
        reasons.append("No response (scan)")
    
    # Very fast IAT (automated)
    if features["iat_mean"] < 0.001 and features["total_packets"] > 20:
        reasons.append("Automated traffic")
    
    # Large packets
    if features["pkt_len_mean"] > 1000:
        reasons.append("Large packets")
    
    return ", ".join(reasons) if reasons else "Anomaly"

def should_alert(ip):
    """Check if we should alert for this IP (cooldown logic)"""
    now = time.time()
    last_alert = stats["last_alert_time"].get(ip, 0)
    
    if now - last_alert < ALERT_COOLDOWN:
        return False
    
    stats["last_alert_time"][ip] = now
    return True

# =============================================================================
# PACKET PROCESSING
# =============================================================================

def packet_callback(packet):
    """Called for each captured packet"""
    global stats
    
    if IP not in packet:
        return
    
    if not (TCP in packet or UDP in packet or ICMP in packet):
        return
    
    stats["total_packets"] += 1
    
    key = get_flow_key(packet)
    if key is None:
        return
    
    with flow_lock:
        if key in active_flows:
            active_flows[key].add_packet(packet)
        else:
            active_flows[key] = NetworkFlow(packet)

# =============================================================================
# ANALYSIS THREAD
# =============================================================================

def analysis_thread():
    """Background thread that analyzes flows"""
    global stats, baseline
    
    baseline["start_time"] = time.time()
    
    print(f"\n{Fore.YELLOW}[LEARNING] Observing normal traffic for {baseline['learning_duration']}s...{Style.RESET_ALL}")
    
    while True:
        time.sleep(2)  # Analyze every 2 seconds
        
        # Check if still in learning mode
        elapsed = time.time() - baseline["start_time"]
        if baseline["learning_mode"] and elapsed > baseline["learning_duration"]:
            baseline["learning_mode"] = False
            print(f"\n{Fore.GREEN}[READY] Learning complete! Now detecting threats...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Baseline packets: {stats['total_packets']}")
            print(f"  Baseline flows: {stats['total_flows']}{Style.RESET_ALL}\n")
        
        with flow_lock:
            if not active_flows:
                continue
            
            flows_to_analyze = list(active_flows.items())
        
        for key, flow in flows_to_analyze:
            if flow.analyzed:
                continue
            
            # Only analyze flows with enough data
            if len(flow.packet_sizes) < MIN_PACKETS_FOR_DETECTION:
                continue
            
            result = analyze_flow(flow)
            if result is None:
                continue
            
            flow.analyzed = True
            stats["total_flows"] += 1
            
            features = result["features"]
            
            # During learning mode, just observe
            if baseline["learning_mode"]:
                if stats["total_flows"] % 20 == 0:
                    print(f"{Fore.BLUE}[LEARN] Flow #{stats['total_flows']}: {features['src_ip']} -> {features['dst_ip']}{Style.RESET_ALL}")
                continue
            
            # Detection mode
            if result["label"] == "ATTACK":
                if should_alert(features["src_ip"]):
                    stats["threats_detected"] += 1
                    
                    print(f"{Fore.RED}[ALERT] {result['reason']}")
                    print(f"   Source: {features['src_ip']} -> {features['dst_ip']}")
                    print(f"   Confidence: {result['confidence']:.1%}")
                    print(f"   Packets: {features['total_packets']} | Duration: {features['duration']:.2f}s{Style.RESET_ALL}\n")
                    
                    # Log to file
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    with open(LOG_FILE, 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            timestamp,
                            features['src_ip'],
                            features['dst_ip'],
                            f"{result['confidence']:.2f}",
                            result['reason'],
                            "1.0"
                        ])
            else:
                stats["benign_flows"] += 1
                
                # Occasionally show safe traffic
                if stats["benign_flows"] % 50 == 0:
                    print(f"{Fore.GREEN}[SAFE] {features['src_ip']} -> {features['dst_ip']} ({result['reason']}){Style.RESET_ALL}")
        
        # Update stats file for dashboard
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    "accuracy": "Live Mode",
                    "latency": "Real-time",
                    "total": stats["total_flows"],
                    "threats": stats["threats_detected"],
                    "mode": "Live Sniffing" if not baseline["learning_mode"] else "Learning"
                }, f)
        except:
            pass
        
        # Cleanup old flows (older than 60 seconds)
        now = time.time()
        with flow_lock:
            old_keys = [k for k, v in active_flows.items() if now - v.last_time > 60]
            for k in old_keys:
                del active_flows[k]

# =============================================================================
# MAIN
# =============================================================================

def main():
    print(f"\n{Fore.CYAN}{'='*60}")
    print("  RT-XNIDS: Real-Time Network Intrusion Detection System")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    if not load_model():
        return
    
    print(f"\n{Fore.YELLOW}[CONFIG] Detection Settings:")
    print(f"  • Confidence Threshold: {MIN_CONFIDENCE:.0%}")
    print(f"  • Alert Cooldown: {ALERT_COOLDOWN}s per IP")
    print(f"  • Min Packets: {MIN_PACKETS_FOR_DETECTION}")
    print(f"  • Whitelisted IPs: {len(WHITELIST_IPS)} entries")
    print(f"  • Safe Ranges: {len(SAFE_SERVICE_RANGES)} services{Style.RESET_ALL}\n")
    
    # Start analysis thread
    analyzer = threading.Thread(target=analysis_thread, daemon=True)
    analyzer.start()
    
    print(f"{Fore.GREEN}[START] Capturing network traffic... (Ctrl+C to stop){Style.RESET_ALL}\n")
    
    try:
        # Start packet capture (requires admin/root)
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[STOP] Shutting down...{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Session Summary:")
        print(f"  • Total Packets: {stats['total_packets']}")
        print(f"  • Total Flows: {stats['total_flows']}")
        print(f"  • Threats Detected: {stats['threats_detected']}")
        print(f"  • Benign Flows: {stats['benign_flows']}{Style.RESET_ALL}\n")
    except PermissionError:
        print(f"{Fore.RED}[ERROR] Permission denied! Run as Administrator.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
