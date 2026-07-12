"""
AEGIS NIDS Engine - Network Intrusion Detection System
=======================================================
Real-time network packet capture and ML-based threat detection.
Based on RT-XNIDS with AEGIS integration patterns.

Located in: core/network/nids_engine.py
Models in: core/network/RT-XNIDS_FInal/

Features:
- Real-time packet sniffing using Scapy
- ML-powered threat classification
- Smart whitelisting and baseline learning
- Callback-based threat notifications
- Integration with AEGIS database and logging
"""

import os
import sys
import time
import threading
import statistics
import csv
import json
import queue
import warnings
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

import numpy as np

# Suppress warnings
warnings.filterwarnings("ignore")

# Try to import required libraries
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    # Disable verbose output
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from database.db_manager import db_manager
from core.system_logger import system_logger

# Import threat prevention for IPS functionality
try:
    from core.threat_prevention import threat_prevention
    IPS_AVAILABLE = True
except ImportError:
    threat_prevention = None
    IPS_AVAILABLE = False

# --- Path Configuration ---
# Network folder is current directory
NETWORK_DIR = os.path.dirname(os.path.abspath(__file__))
NIDS_DIR = os.path.join(NETWORK_DIR, "RT-XNIDS_FInal")

# Model paths - use RT-XNIDS models
MODEL_PATH = os.path.join(NIDS_DIR, "model_live.pkl")
SCALER_PATH = os.path.join(NIDS_DIR, "scaler_live.pkl")

# Fallback to ai/models if RT-XNIDS models don't exist
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(PROJECT_ROOT, "ai", "models", "nids_model.pkl")
if not os.path.exists(SCALER_PATH):
    SCALER_PATH = os.path.join(PROJECT_ROOT, "ai", "models", "nids_scaler.pkl")

# Log and stats files
ALERTS_LOG = os.path.join(NIDS_DIR, "alerts.log")
STATS_FILE = os.path.join(NIDS_DIR, "live_stats.json")


class NetworkFlow:
    """
    Tracks a network flow (bidirectional connection) over time.
    Extracts features for ML-based threat detection.
    """
    
    def __init__(self, packet):
        """Initialize flow from first packet."""
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
        """Add a new packet to this flow."""
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
    
    def get_features(self) -> Dict[str, Any]:
        """Extract the 6 features for ML model."""
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
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "total_packets": len(self.packet_sizes),
        }


class NIDSEngine(threading.Thread):
    """
    Network Intrusion Detection System Engine.
    Provides real-time network monitoring with ML-based threat detection.
    
    Can run as a standalone service (threading.Thread) for main_aegis.py
    or be controlled via start()/stop() methods.
    """
    
    # Detection tuning
    MIN_CONFIDENCE = 0.65  # Lowered from 0.75 — catches more real threats with fewer misses
    ALERT_COOLDOWN = 5  # Seconds between alerts per IP
    MIN_PACKETS_FOR_DETECTION = 3
    FLOW_TIMEOUT = 60  # Seconds before flow expires
    ANALYSIS_INTERVAL = 2  # Seconds between analysis cycles
    LEARNING_DURATION = 30  # Seconds for baseline learning
    
    # Whitelist configuration
    WHITELIST_IPS = [
        "127.0.0.1", "0.0.0.0", "255.255.255.255",
        "192.168.0.1", "192.168.1.1", "192.168.31.1",
        "10.0.0.1", "172.16.0.1",
        "224.0.0.1", "224.0.0.251", "239.255.255.250",
    ]
    
    WHITELIST_RANGES = [
        "192.168.", "10.0.", "10.1.",
        "172.16.", "172.17.", "172.18.",
        "fe80:",
    ]
    
    SAFE_SERVICE_RANGES = [
        # Google
        "142.250.", "172.217.", "216.239.", "74.125.", "173.194.",
        # Microsoft/Azure
        "13.107.", "52.168.", "20.189.", "40.126.", "20.190.",
        # DNS
        "8.8.8.8", "8.8.4.4", "208.67.222.222",
        # Note: Cloudflare (104.16-20.x) deliberately excluded —
        # they also host malicious ad networks and CDN-proxied threats.
    ]
    
    def __init__(self, stop_event: threading.Event = None, alert_queue: queue.Queue = None):
        """
        Initialize NIDS Engine.
        
        Args:
            stop_event: Optional threading event for external shutdown control
            alert_queue: Optional queue to push alerts (for main_aegis.py integration)
        """
        super().__init__(daemon=True, name="NIDS-Engine")
        
        self.model = None
        self.scaler = None
        self.expected_features = 6
        
        # External control
        self.external_stop_event = stop_event
        self.alert_queue = alert_queue
        
        # State
        self.is_active = False
        self.is_learning = False
        self.sniffer_thread = None
        self.analysis_thread = None
        self.stop_event = threading.Event()
        
        # Flow tracking
        self.active_flows: Dict[tuple, NetworkFlow] = {}
        self.flow_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "total_flows": 0,
            "threats_detected": 0,
            "benign_flows": 0,
            "last_alert_time": {},
            "start_time": None,
            "error": None,
        }
        
        # Callbacks for threat notifications
        self.threat_callbacks: List[Callable] = []
        
        # Settings
        self.sensitivity = "MEDIUM"  # LOW, MEDIUM, HIGH
        self.auto_block_enabled = True  # IPS: Auto-block detected attackers
        
        # Load model
        self._load_model()
        
        system_logger.log_info(f"NIDS Engine initialized (IPS: {'Available' if IPS_AVAILABLE else 'Not available'})", 'app')
    
    def _load_model(self) -> bool:
        """Load ML model and scaler."""
        if not JOBLIB_AVAILABLE:
            self.stats["error"] = "joblib not available"
            system_logger.log_error("joblib not available for NIDS", 'app')
            return False
        
        try:
            if not os.path.exists(MODEL_PATH):
                self.stats["error"] = f"Model not found: {MODEL_PATH}"
                system_logger.log_warning(f"NIDS model not found: {MODEL_PATH}", 'app')
                return False
            
            if not os.path.exists(SCALER_PATH):
                self.stats["error"] = f"Scaler not found: {SCALER_PATH}"
                system_logger.log_warning(f"NIDS scaler not found: {SCALER_PATH}", 'app')
                return False
            
            self.scaler = joblib.load(SCALER_PATH)
            self.model = joblib.load(MODEL_PATH)
            
            # Silence verbose models
            if hasattr(self.model, "verbose"):
                self.model.verbose = 0
            
            if hasattr(self.model, "n_features_in_"):
                self.expected_features = self.model.n_features_in_
            
            self.stats["error"] = None
            system_logger.log_info(f"NIDS model loaded: {MODEL_PATH}", 'app')
            return True
            
        except Exception as e:
            self.stats["error"] = str(e)
            system_logger.log_error(f"Failed to load NIDS model: {e}", 'app')
            return False
    
    def register_threat_callback(self, callback: Callable):
        """
        Register callback for threat notifications.
        
        Args:
            callback: Function with signature callback(threat_data: dict)
        """
        self.threat_callbacks.append(callback)
    
    def is_available(self) -> bool:
        """Check if NIDS is available (all dependencies loaded)."""
        return SCAPY_AVAILABLE and self.model is not None and self.scaler is not None
    
    def run(self):
        """Thread entry point - starts monitoring."""
        self.start_monitoring()
    
    def start_monitoring(self) -> bool:
        """
        Start network monitoring.
        
        Returns:
            True if started successfully, False otherwise.
        """
        if not self.is_available():
            error_msg = "NIDS not available - missing dependencies"
            self.stats["error"] = error_msg
            system_logger.log_error(error_msg, 'app')
            self._push_error(error_msg)
            return False
        
        if self.is_active:
            system_logger.log_warning("NIDS already active", 'app')
            return False
        
        self.is_active = True
        self.is_learning = True
        self.stop_event.clear()
        self.stats["start_time"] = time.time()
        self.stats["error"] = None
        
        # Initialize alerts log
        self._init_alerts_log()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True,
            name="NIDS-Analysis"
        )
        self.analysis_thread.start()
        
        # Start sniffer (blocking in this thread)
        system_logger.log_info("NIDS Engine started", 'app')
        db_manager.log_event('NIDS_START', 'INFO', 'Network IDS started')
        
        self._sniffer_loop()
        
        return True
    
    def start(self) -> bool:
        """
        Start network monitoring (non-blocking version).
        Starts monitoring in background via the thread start mechanism.
        """
        if not self.is_available():
            system_logger.log_error("NIDS not available - missing dependencies", 'app')
            return False
        
        if self.is_active:
            system_logger.log_warning("NIDS already active", 'app')
            return False
        
        # Start the thread which calls run() -> start_monitoring()
        super().start()
        return True
    
    def stop(self):
        """Stop network monitoring."""
        if not self.is_active:
            return
        
        self.is_active = False
        self.stop_event.set()
        
        # Wait for threads to finish
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=3)
        
        system_logger.log_info("NIDS Engine stopped", 'app')
        db_manager.log_event('NIDS_STOP', 'INFO', 
            f'Network IDS stopped. Threats: {self.stats["threats_detected"]}, Flows: {self.stats["total_flows"]}')
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current NIDS statistics (compatible with SnifferService API)."""
        mode = "Learning" if self.is_learning else ("Active" if self.is_active else "Inactive")
        blocked_ips = self.get_blocked_ips() if IPS_AVAILABLE else []
        
        return {
            "mode": mode,
            "is_active": self.is_active,
            "total_packets": self.stats["total_packets"],
            "total_flows": self.stats["total_flows"],
            "threats_detected": self.stats["threats_detected"],
            "benign_flows": self.stats["benign_flows"],
            "active_flows": len(self.active_flows),
            "error": self.stats.get("error"),
            # IPS status
            "ips_available": IPS_AVAILABLE,
            "ips_enabled": self.auto_block_enabled,
            "blocked_ips_count": len(blocked_ips),
            "blocked_ips": blocked_ips[:10],  # Show first 10
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Alias for get_stats() - for SnifferService API compatibility."""
        return self.get_stats()
    
    def is_active_check(self) -> bool:
        """Check if sniffer is actively running."""
        return self.is_active
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts from log file."""
        alerts = []
        try:
            if os.path.exists(ALERTS_LOG):
                import pandas as pd
                df = pd.read_csv(ALERTS_LOG, keep_default_na=False)
                df = df.tail(limit)
                alerts = df.to_dict('records')
        except Exception:
            pass
        return alerts
    
    def set_sensitivity(self, level: str):
        """
        Set detection sensitivity.
        
        Args:
            level: LOW, MEDIUM, or HIGH
        """
        level = level.upper()
        if level in ["LOW", "MEDIUM", "HIGH"]:
            self.sensitivity = level
            
            # Adjust confidence threshold based on sensitivity
            if level == "LOW":
                self.MIN_CONFIDENCE = 0.85
            elif level == "MEDIUM":
                self.MIN_CONFIDENCE = 0.75
            else:  # HIGH
                self.MIN_CONFIDENCE = 0.60
            
            system_logger.log_info(f"NIDS sensitivity set to {level}", 'app')
    
    def add_whitelist_ip(self, ip: str):
        """Add IP to whitelist."""
        if ip not in self.WHITELIST_IPS:
            self.WHITELIST_IPS.append(ip)
    
    # === IPS (Intrusion Prevention) Control Methods ===
    
    def set_auto_block(self, enabled: bool):
        """
        Enable or disable automatic IP blocking (IPS mode).
        
        Args:
            enabled: If True, detected attackers will be blocked via Windows Firewall
        """
        self.auto_block_enabled = enabled
        mode = "enabled" if enabled else "disabled"
        system_logger.log_info(f"NIDS auto-block (IPS) {mode}", 'app')
    
    def is_ips_available(self) -> bool:
        """Check if IPS (auto-blocking) functionality is available."""
        return IPS_AVAILABLE and threat_prevention is not None
    
    def get_blocked_ips(self) -> list:
        """Get list of IPs currently blocked by IPS."""
        if IPS_AVAILABLE and threat_prevention:
            return threat_prevention.get_blocked_ips()
        return []
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Manually unblock an IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if successfully unblocked
        """
        if IPS_AVAILABLE and threat_prevention:
            threat_prevention.unblock_ip(ip, remove_firewall=True)
            system_logger.log_info(f"Manually unblocked IP: {ip}", 'app')
            return True
        return False
    
    def manual_block_ip(self, ip: str) -> bool:
        """
        Manually block an IP address.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successfully blocked
        """
        if IPS_AVAILABLE and threat_prevention:
            success = threat_prevention.block_ip(ip, use_firewall=True)
            system_logger.log_info(f"Manually blocked IP: {ip}", 'app')
            return success
        return False

    def _init_alerts_log(self):
        """Initialize alerts log file with headers."""
        try:
            if not os.path.exists(ALERTS_LOG):
                os.makedirs(os.path.dirname(ALERTS_LOG), exist_ok=True)
                with open(ALERTS_LOG, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Timestamp", "SrcIP", "DstIP", 
                        "Confidence", "AttackReason", "ImpactScore"
                    ])
        except Exception as e:
            system_logger.log_error(f"Failed to init alerts log: {e}", 'app')
    
    def _push_error(self, message: str):
        """Push a system error message to the alert queue."""
        if self.alert_queue:
            self.alert_queue.put({
                "type": "system_error",
                "source": "NIDS",
                "msg": message,
                "timestamp": datetime.now().isoformat()
            })
    
    def _push_alert(self, alert_data: dict):
        """Push a network threat alert to the queue."""
        if self.alert_queue:
            alert_data["type"] = "network_threat"
            alert_data["timestamp"] = datetime.now().isoformat()
            self.alert_queue.put(alert_data)
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP should be ignored."""
        if ip in self.WHITELIST_IPS:
            return True
        
        for prefix in self.WHITELIST_RANGES:
            if ip.startswith(prefix):
                return True
        
        for prefix in self.SAFE_SERVICE_RANGES:
            if ip.startswith(prefix):
                return True
        
        return False
    
    def _is_local_traffic(self, src_ip: str, dst_ip: str) -> bool:
        """Check if traffic is local (same network)."""
        local_prefixes = ["192.168.", "10.", "172.16."]
        src_local = any(src_ip.startswith(p) for p in local_prefixes)
        dst_local = any(dst_ip.startswith(p) for p in local_prefixes)
        return src_local and dst_local
    
    def _get_flow_key(self, packet) -> Optional[tuple]:
        """Generate unique bidirectional key for a flow."""
        if IP not in packet:
            return None
        
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet.sport if hasattr(packet, 'sport') else 0
        dport = packet.dport if hasattr(packet, 'dport') else 0
        proto = packet[IP].proto
        
        # Bidirectional key
        if (src, sport) < (dst, dport):
            return (src, dst, sport, dport, proto)
        else:
            return (dst, src, dport, sport, proto)
    
    def _packet_callback(self, packet):
        """Process captured packet."""
        if not self.is_active:
            return
        
        # Check external stop event
        if self.external_stop_event and self.external_stop_event.is_set():
            self.stop()
            return
        
        if IP not in packet:
            return
        
        if not (TCP in packet or UDP in packet or ICMP in packet):
            return
        
        self.stats["total_packets"] += 1
        
        key = self._get_flow_key(packet)
        if key is None:
            return
        
        with self.flow_lock:
            if key in self.active_flows:
                self.active_flows[key].add_packet(packet)
            else:
                self.active_flows[key] = NetworkFlow(packet)
    
    def _sniffer_loop(self):
        """Packet capture loop."""
        try:
            def stop_filter(pkt):
                if self.external_stop_event:
                    return self.stop_event.is_set() or self.external_stop_event.is_set()
                return self.stop_event.is_set()
            
            sniff(
                prn=self._packet_callback,
                store=0,
                stop_filter=stop_filter
            )
        except PermissionError:
            error_msg = "NIDS requires administrator privileges"
            self.stats["error"] = error_msg
            system_logger.log_error(error_msg, 'app')
            self._push_error(error_msg)
        except Exception as e:
            error_msg = f"NIDS sniffer error: {e}"
            self.stats["error"] = error_msg
            system_logger.log_error(error_msg, 'app')
            self._push_error(error_msg)
    
    def _analysis_loop(self):
        """Background analysis of flows."""
        while self.is_active and not self.stop_event.is_set():
            # Check external stop event
            if self.external_stop_event and self.external_stop_event.is_set():
                break
            
            try:
                time.sleep(self.ANALYSIS_INTERVAL)
                
                # Check learning mode
                if self.is_learning:
                    elapsed = time.time() - self.stats["start_time"]
                    if elapsed > self.LEARNING_DURATION:
                        self.is_learning = False
                        system_logger.log_info(
                            f"NIDS learning complete. Baseline: {self.stats['total_packets']} packets, "
                            f"{self.stats['total_flows']} flows", 'app'
                        )
                
                # Get flows to analyze
                with self.flow_lock:
                    flows_to_analyze = list(self.active_flows.items())
                
                for key, flow in flows_to_analyze:
                    if flow.analyzed:
                        continue
                    
                    if len(flow.packet_sizes) < self.MIN_PACKETS_FOR_DETECTION:
                        continue
                    
                    result = self._analyze_flow(flow)
                    if result is None:
                        continue
                    
                    flow.analyzed = True
                    self.stats["total_flows"] += 1
                    
                    # Skip during learning
                    if self.is_learning:
                        continue
                    
                    # Handle detection
                    if result["is_threat"]:
                        self._handle_threat(result)
                    else:
                        self.stats["benign_flows"] += 1
                
                # Update stats file
                self._update_stats_file()
                
                # Cleanup old flows
                self._cleanup_flows()
                
            except Exception as e:
                system_logger.log_error(f"NIDS analysis error: {e}", 'app')
    
    def _analyze_flow(self, flow: NetworkFlow) -> Optional[Dict]:
        """Run ML inference on a flow, with an independent heuristic override for web threats."""
        features = flow.get_features()
        
        # Skip pure local traffic (both IPs on the same LAN)
        if self._is_local_traffic(features["src_ip"], features["dst_ip"]):
            return {"is_threat": False, "reason": "Local traffic", "features": features}
        
        # Determine the REMOTE IP (the one that is NOT our local machine).
        # Only whitelist-check the remote side; our own local IP (192.168.x.x)
        # should NOT cause the entire flow to be skipped.
        local_prefixes = ["192.168.", "10.", "172.16."]
        src_is_local = any(features["src_ip"].startswith(p) for p in local_prefixes)
        dst_is_local = any(features["dst_ip"].startswith(p) for p in local_prefixes)
        
        if src_is_local and not dst_is_local:
            remote_ip = features["dst_ip"]
        elif dst_is_local and not src_is_local:
            remote_ip = features["src_ip"]
        else:
            # Both external or both local (local-local already handled above)
            remote_ip = features["dst_ip"]
        
        if self._is_whitelisted(remote_ip):
            return {"is_threat": False, "reason": "Whitelisted", "features": features}
        
        # ── Phase 1: ML Model ──────────────────────────────────────────────────
        ml_is_threat = False
        ml_confidence = 0.0
        ml_reason = "Normal"
        ml_label = "BENIGN"
        
        try:
            X = np.array([[
                features["duration"],
                features["fwd_packets"],
                features["bwd_packets"],
                features["pkt_len_mean"],
                features["pkt_len_std"],
                features["iat_mean"]
            ]])
            
            if self.expected_features > 6:
                X_padded = np.zeros((1, self.expected_features))
                X_padded[0, :6] = X[0]
                X = X_padded
            
            X_scaled = self.scaler.transform(X)
            probs = self.model.predict_proba(X_scaled)[0]
            pred_idx = np.argmax(probs)
            ml_confidence = float(probs[pred_idx])
            ml_label = self.model.classes_[pred_idx]
            
            is_attack = str(ml_label).upper() not in ["BENIGN", "NORMAL", "0"]
            
            if is_attack and ml_confidence >= self.MIN_CONFIDENCE:
                # Very short flows are noise —ignore
                if not (features["duration"] < 0.1 and features["total_packets"] < 10):
                    ml_reason = self._get_attack_reason(features)
                    ml_is_threat = True
                    
        except Exception as e:
            system_logger.log_error(f"NIDS ML inference error: {e}", 'app')
        
        # ── Phase 2: Independent Heuristic Pass ─────────────────────────────────
        # The ML model was trained on DoS/PortScan datasets, not web ad-traffic.
        # We run heuristics unconditionally so web threats are caught even when
        # the ML classifies the flow as BENIGN.
        heuristic_reason = self._get_attack_reason(features)
        
        WEB_THREAT_TYPES = {
            "Clickjacking", "AdInjection", "SuspiciousRedirect",
            "AdTracker", "SpamBot", "SuspiciousDownload"
        }
        
        heuristic_tags = {t.strip() for t in heuristic_reason.split(",")}
        heuristic_matched = heuristic_tags & WEB_THREAT_TYPES  # intersection
        
        heuristic_is_threat = len(heuristic_matched) > 0
        
        # Assign a confidence proxy for heuristic detections
        heuristic_confidence_map = {
            "Clickjacking": 0.82,
            "AdInjection": 0.78,
            "SuspiciousRedirect": 0.72,
            "AdTracker": 0.68,
            "SpamBot": 0.75,
            "SuspiciousDownload": 0.70,
        }
        heuristic_confidence = max(
            (heuristic_confidence_map.get(t, 0.68) for t in heuristic_matched),
            default=0.0
        )
        
        # ── Merge results ────────────────────────────────────────────────────────
        if ml_is_threat and heuristic_is_threat:
            reason = heuristic_reason  # heuristic reason is more specific
            confidence = max(ml_confidence, heuristic_confidence)
            is_threat = True
        elif ml_is_threat:
            reason = ml_reason
            confidence = ml_confidence
            is_threat = True
        elif heuristic_is_threat:
            reason = heuristic_reason
            confidence = heuristic_confidence
            is_threat = True
        else:
            reason = ml_reason
            confidence = ml_confidence
            is_threat = False
        
        return {
            "is_threat": is_threat,
            "confidence": confidence,
            "label": ml_label,
            "reason": reason,
            "features": features,
        }
    
    def _get_attack_reason(self, features: Dict) -> str:
        """Determine why traffic looks suspicious."""
        reasons = []
        
        if features["fwd_packets"] > 50 and features["duration"] < 1:
            reasons.append("PortScan")
        
        if features["fwd_packets"] > 10 and features["bwd_packets"] == 0:
            reasons.append("NoResponse")
        
        if features["iat_mean"] < 0.001 and features["total_packets"] > 20:
            reasons.append("Bot")
        
        if features["pkt_len_mean"] > 1000:
            reasons.append("DDoS")
        
        dst_port = features.get("dst_port", 0)
        
        # Spam/Adware detection
        if dst_port in [25, 465, 587] and features["fwd_packets"] > 20:
            reasons.append("SpamBot")
        
        # Suspicious downloads
        if features["pkt_len_mean"] > 1400 and features["fwd_packets"] > features["bwd_packets"] * 3:
            reasons.append("SuspiciousDownload")
        
        # Clickjacking: rapid HTTP requests with small payloads (iframe overlays)
        if dst_port in [80, 443] and features["total_packets"] > 4 and features["duration"] < 2.0:
            if features["pkt_len_mean"] < 500 and features["iat_mean"] < 0.1:
                reasons.append("Clickjacking")
        
        # Ad injection: short-lived HTTP connections with back-and-forth traffic
        if dst_port in [80, 443] and features["fwd_packets"] > 2 and features["duration"] < 3.0:
            if features["bwd_packets"] > 0 and features["iat_mean"] < 0.1:
                reasons.append("AdInjection")
        
        # Suspicious redirect chains: medium-sized packets, short duration
        if features["pkt_len_mean"] > 200 and features["pkt_len_mean"] < 800:
            if features["duration"] < 1.0 and features["total_packets"] > 3:
                reasons.append("SuspiciousRedirect")
        
        # Pop-up/Ad-related (frequent short connections)
        if features["duration"] < 0.5 and features["total_packets"] < 5 and dst_port in [80, 443]:
            if features["iat_mean"] < 0.01:
                reasons.append("AdTracker")
        
        return ", ".join(reasons) if reasons else "Anomaly"
    
    def _classify_network_threat_level(self, attack_reason: str, confidence: float) -> str:
        """Determine an overall risk level for the attack reason."""
        critical_types = ["DDoS", "Clickjacking"]
        high_types = ["PortScan", "Bot", "AdInjection"]
        medium_types = ["NoResponse", "SpamBot", "SuspiciousDownload", "SuspiciousRedirect", "Anomaly"]
        
        reason_parts = [r.strip() for r in attack_reason.split(",")]
        
        for r in reason_parts:
            if any(c in r for c in critical_types): return "CRITICAL"
        for r in reason_parts:
            if any(c in r for c in high_types): return "HIGH"
        for r in reason_parts:
            if any(c in r for c in medium_types): return "MEDIUM"
        return "LOW"
    
    def _generate_xai_explanation(self, features: Dict, attack_reason: str, confidence: float) -> Dict:
        """Generate human-readable XAI explanation for the threat."""
        explanations = {
            "PortScan": {
                "title": "Port Scanning Attack",
                "simple": "Someone is checking your computer for open doors (ports) to sneak in.",
                "technical": f"High packet rate ({features['fwd_packets']} packets in {features['duration']:.2f}s) indicates systematic port enumeration.",
                "risk": "HIGH",
                "action": "This IP is scanning your system to find vulnerabilities. It's like someone checking all your windows and doors to see which ones are unlocked."
            },
            "NoResponse": {
                "title": "One-Way Traffic Attack",
                "simple": "A computer is repeatedly sending you data but not waiting for replies - this is suspicious behavior.",
                "technical": f"Asymmetric flow: {features['fwd_packets']} incoming, {features['bwd_packets']} outgoing packets.",
                "risk": "MEDIUM",
                "action": "This could be a flood attack or reconnaissance. The attacker is sending data without expecting normal responses."
            },
            "Bot": {
                "title": "Bot/Automated Attack",
                "simple": "An automated program (bot) is rapidly sending requests to your system - much faster than a human could.",
                "technical": f"Very low inter-arrival time ({features['iat_mean']*1000:.2f}ms) indicates automated traffic.",
                "risk": "HIGH",
                "action": "Your system is being targeted by a bot, possibly part of a larger botnet attack. This is like a robot repeatedly knocking on your door."
            },
            "DDoS": {
                "title": "Flood Attack (DDoS)",
                "simple": "Someone is trying to overwhelm your system by sending huge amounts of data.",
                "technical": f"Large average packet size ({features['pkt_len_mean']:.0f} bytes) indicates potential volumetric attack.",
                "risk": "CRITICAL",
                "action": "This is a denial-of-service attack trying to crash or slow down your system by flooding it with traffic."
            },
            "SpamBot": {
                "title": "Spam Activity Detected",
                "simple": "Your network is being used to send spam emails or is receiving spam-related traffic.",
                "technical": f"High volume email traffic detected on port {features.get('dst_port', 'N/A')}.",
                "risk": "MEDIUM",
                "action": "This could indicate a spam campaign. Spam emails often contain malicious links or attachments."
            },
            "SuspiciousDownload": {
                "title": "Suspicious Download",
                "simple": "A large file is being downloaded from a potentially unsafe source.",
                "technical": f"Unusual download pattern: high incoming data ({features['pkt_len_mean']:.0f} bytes avg).",
                "risk": "MEDIUM",
                "action": "An unexpected download was detected. This could be malware, adware, or unwanted software being installed."
            },
            "AdInjection": {
                "title": "Ad Injection Attack",
                "simple": "Malicious code is trying to inject unauthorized advertisements into web pages you're viewing — these ads may contain phishing links or malware.",
                "technical": f"Rapid sequential HTTP connections ({features['total_packets']} packets, {features['iat_mean']*1000:.1f}ms avg IAT) consistent with ad injection framework activity.",
                "risk": "HIGH",
                "action": "A script on the page is hijacking ad slots to display malicious content. Avoid clicking any popup or banner ads on this page and consider using an ad-blocker."
            },
            "Clickjacking": {
                "title": "Clickjacking Attempt",
                "simple": "A website is placing an invisible layer over legitimate content to trick you into clicking something you didn't intend to — possibly authorizing transactions or sharing data.",
                "technical": f"High-frequency micro-requests ({features['total_packets']} pkts, {features['pkt_len_mean']:.0f}B avg, {features['duration']*1000:.1f}ms duration) — classic iframe overlay pattern.",
                "risk": "CRITICAL",
                "action": "Do not click anything on this page. A transparent overlay may be redirecting your clicks to a hidden malicious element. Close this tab immediately."
            },
            "SuspiciousRedirect": {
                "title": "Suspicious Redirect Chain",
                "simple": "This web page is quietly forwarding your browser through multiple hidden destinations — a common tactic used by phishing sites and malvertising networks.",
                "technical": f"Short-lived connections ({features['duration']*1000:.1f}ms) with medium payload ({features['pkt_len_mean']:.0f}B avg) matching redirect chain fingerprint.",
                "risk": "MEDIUM",
                "action": "The page is silently tracking or redirecting you. Do not submit any personal information. Leave the site and clear your browser cookies."
            },
            "AdTracker": {
                "title": "Ad Tracker / Pop-up Activity",
                "simple": "Advertising trackers or pop-up ads are trying to collect your data or show unwanted content.",
                "technical": f"Rapid short-lived connections typical of ad networks.",
                "risk": "LOW",
                "action": "Ad trackers are monitoring your browsing. While not immediately dangerous, they invade your privacy."
            },
            "Anomaly": {
                "title": "Suspicious Network Activity",
                "simple": "This network traffic doesn't look normal and could be a cyber threat.",
                "technical": f"ML model detected abnormal traffic pattern with {confidence*100:.0f}% confidence.",
                "risk": "MEDIUM",
                "action": "Our AI detected unusual behavior. This traffic doesn't match normal patterns and should be monitored."
            }
        }
        
        # Get the primary reason (first one if multiple)
        primary_reason = attack_reason.split(",")[0].strip() if attack_reason else "Anomaly"
        explanation = explanations.get(primary_reason, explanations["Anomaly"])
        
        # Add confidence level interpretation
        if confidence >= 0.95:
            confidence_text = "Very High Confidence - Almost certain this is malicious"
        elif confidence >= 0.85:
            confidence_text = "High Confidence - Very likely a threat"
        elif confidence >= 0.75:
            confidence_text = "Moderate Confidence - Probable threat"
        else:
            confidence_text = "Low Confidence - Possible threat, needs monitoring"
        
        return {
            "title": explanation["title"],
            "simple_explanation": explanation["simple"],
            "technical_details": explanation["technical"],
            "risk_level": explanation["risk"],
            "recommended_action": explanation["action"],
            "confidence_interpretation": confidence_text,
            "attack_categories": attack_reason.split(", ")
        }
    
    def _should_alert(self, ip: str) -> bool:
        """Check cooldown for IP."""
        now = time.time()
        last_alert = self.stats["last_alert_time"].get(ip, 0)
        
        if now - last_alert < self.ALERT_COOLDOWN:
            return False
        
        self.stats["last_alert_time"][ip] = now
        return True
    
    def _handle_threat(self, result: Dict):
        """Handle detected threat and trigger IPS response."""
        features = result["features"]
        
        if not self._should_alert(features["src_ip"]):
            return
        
        self.stats["threats_detected"] += 1
        
        threat_data = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            # Use field names expected by frontend
            "source_ip": features["src_ip"],
            "dest_ip": features["dst_ip"],
            "src_port": features["src_port"],
            "dst_port": features["dst_port"],
            "confidence": result["confidence"],
            "threat_type": result["reason"],  # Frontend expects "threat_type"
            "attack_type": result["reason"],  # Keep for backward compatibility
            "packets": features["total_packets"],
            "duration": features["duration"],
        }
        
        # Generate XAI explanation
        xai_explanation = self._generate_xai_explanation(
            features, result["reason"], result["confidence"]
        )
        threat_data["xai"] = xai_explanation
        
        # Log to file
        self._log_alert(threat_data)
        
        # Log to database
        db_manager.log_event(
            'NIDS_THREAT',
            'WARNING',
            f'Network threat: {result["reason"]}',
            f'{features["src_ip"]} -> {features["dst_ip"]} ({result["confidence"]:.0%})'
        )
        
        # === IPS: Auto-block attacker via ThreatPrevention ===
        if IPS_AVAILABLE and threat_prevention and self.auto_block_enabled:
            try:
                ips_response = threat_prevention.handle_network_threat(
                    threat_data, 
                    auto_block=True
                )
                threat_data["ips_response"] = ips_response
                threat_data["blocked"] = ips_response.get("firewall_blocked", False)
                
                if ips_response.get("firewall_blocked"):
                    system_logger.log_info(
                        f"IPS: Blocked attacker {features['src_ip']} via firewall", 'app'
                    )
            except Exception as e:
                system_logger.log_error(f"IPS response error: {e}", 'app')
        
        # Push to alert queue (for main_aegis.py)
        self._push_alert(threat_data)
        
        # Notify callbacks
        for callback in self.threat_callbacks:
            try:
                callback(threat_data)
            except Exception as e:
                system_logger.log_error(f"NIDS callback error: {e}", 'app')
    
    def _log_alert(self, threat_data: Dict):
        """Log alert to CSV file."""
        try:
            with open(ALERTS_LOG, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    threat_data["timestamp"],
                    threat_data["source_ip"],
                    threat_data["dest_ip"],
                    f"{threat_data['confidence']:.2f}",
                    threat_data["threat_type"],
                    "1.0"
                ])
        except Exception:
            pass
    
    def _update_stats_file(self):
        """Update stats JSON for external monitoring."""
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    "accuracy": "Live Mode",
                    "latency": "Real-time",
                    "total": self.stats["total_flows"],
                    "threats": self.stats["threats_detected"],
                    "mode": "Learning" if self.is_learning else "Live Sniffing"
                }, f)
        except Exception:
            pass
    
    def _cleanup_flows(self):
        """Remove expired flows."""
        now = time.time()
        with self.flow_lock:
            expired = [k for k, v in self.active_flows.items() 
                      if now - v.last_time > self.FLOW_TIMEOUT]
            for k in expired:
                del self.active_flows[k]


# Singleton instance (for simple usage)
_nids_engine_instance = None


def get_nids_engine() -> NIDSEngine:
    """Get or create the NIDS engine singleton (for backward compatibility)."""
    global _nids_engine_instance
    if _nids_engine_instance is None:
        _nids_engine_instance = NIDSEngine()
    return _nids_engine_instance


# Convenience alias
nids_engine = property(lambda self: get_nids_engine())
