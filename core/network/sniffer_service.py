"""
AEGIS NIDS - Sniffer Service
Network Intrusion Detection System running as a background thread.

This module provides real-time network packet sniffing and ML-based
threat detection as a non-blocking service for AEGIS.
"""
import os
import sys
import time
import threading
import statistics
import queue
import warnings
from collections import defaultdict
from datetime import datetime

import numpy as np
import joblib

# Scapy imports (may fail without proper privileges)
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Suppress sklearn feature name warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --- Path Configuration ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "nids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "ai", "models", "nids_scaler.pkl")

# --- Fine-Tuning ---
MIN_CONFIDENCE = 0.60
WHITELIST_IPS = ["127.0.0.1", "192.168.1.1", "192.168.0.1"]


class Flow:
    """Represents a network flow (bidirectional connection)."""
    
    def __init__(self, start_packet):
        self.src_ip = start_packet[IP].src
        self.dst_ip = start_packet[IP].dst
        self.src_port = start_packet.sport
        self.dst_port = start_packet.dport
        self.protocol = start_packet.proto
        
        self.start_time = float(start_packet.time)
        self.last_time = float(start_packet.time)
        
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.flow_lengths = []
        self.flow_iats = []
        
        self.updated = False
        self.update(start_packet)

    def update(self, packet):
        """Update flow statistics with a new packet."""
        curr_time = float(packet.time)
        
        if hasattr(self, 'flow_lengths') and len(self.flow_lengths) > 0:
            iat = curr_time - self.last_time
            if iat < 0:
                iat = 0.0
            self.flow_iats.append(iat)

        if packet[IP].src == self.src_ip:
            self.fwd_pkts += 1
        else:
            self.bwd_pkts += 1
            
        self.flow_lengths.append(len(packet))
        self.last_time = curr_time
        self.updated = True

    def get_features(self):
        """Extract ML features from the flow."""
        duration = self.last_time - self.start_time
        if duration < 0:
            duration = 0.0
        
        if len(self.flow_lengths) > 0:
            pkt_len_mean = statistics.mean(self.flow_lengths)
            pkt_len_std = statistics.stdev(self.flow_lengths) if len(self.flow_lengths) > 1 else 0.0
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            
        if len(self.flow_iats) > 0:
            flow_iat_mean = statistics.mean(self.flow_iats)
        else:
            flow_iat_mean = 0.0
            
        return {
            "flow_duration": duration,
            "total_fwd_packets": self.fwd_pkts,
            "total_bwd_packets": self.bwd_pkts,
            "packet_length_mean": pkt_len_mean,
            "packet_length_std": pkt_len_std,
            "flow_iat_mean": flow_iat_mean,
            "src": self.src_ip,
            "dst": self.dst_ip
        }


class SnifferService(threading.Thread):
    """
    Network Intrusion Detection Service running as a background thread.
    
    Captures network packets, analyzes flows using ML model, and pushes
    alerts to a thread-safe queue for consumption by the API bridge.
    """
    
    def __init__(self, stop_event: threading.Event, alert_queue: queue.Queue):
        """
        Initialize the sniffer service.
        
        Args:
            stop_event: Threading event to signal graceful shutdown
            alert_queue: Thread-safe queue for pushing alerts to frontend
        """
        super().__init__(daemon=True, name="NIDS-SnifferThread")
        
        self.stop_event = stop_event
        self.alert_queue = alert_queue
        
        # Flow tracking
        self.active_flows = {}
        self.flow_lock = threading.Lock()
        
        # Statistics
        self.total_flows = 0
        self.total_packets = 0
        self.threats_detected = 0
        self.is_running = False
        self.error_state = None
        
        # ML artifacts (loaded on start)
        self.model = None
        self.scaler = None
        self.expected_features = 6  # NIDS model uses exactly 6 features
        
    def _load_model(self) -> bool:
        """Load ML model and scaler. Returns True if successful."""
        try:
            if not os.path.exists(MODEL_PATH):
                self._push_error(f"Model file not found: {MODEL_PATH}")
                return False
                
            if not os.path.exists(SCALER_PATH):
                self._push_error(f"Scaler file not found: {SCALER_PATH}")
                return False
            
            self.scaler = joblib.load(SCALER_PATH)
            self.model = joblib.load(MODEL_PATH)

            # --- FIX: SILENCE VERBOSE LOGS ---
            # Force the network model to be quiet
            if hasattr(self.model, "verbose"):
                self.model.verbose = 0
            # ---------------------------------
            
            if hasattr(self.model, "n_features_in_"):
                self.expected_features = self.model.n_features_in_
                
            return True
            
        except Exception as e:
            self._push_error(f"Failed to load NIDS model: {str(e)}")
            return False
    
    def _push_error(self, message: str):
        """Push a system error message to the alert queue."""
        self.error_state = message
        self.alert_queue.put({
            "type": "system_error",
            "source": "NIDS",
            "msg": message,
            "timestamp": datetime.now().isoformat()
        })
    
    def _push_alert(self, alert_data: dict):
        """Push a network threat alert to the queue."""
        alert_data["type"] = "network_threat"
        alert_data["timestamp"] = datetime.now().isoformat()
        self.alert_queue.put(alert_data)
        self.threats_detected += 1
    
    def _get_flow_key(self, pkt):
        """Generate a unique key for a network flow."""
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt.sport
        dport = pkt.dport
        proto = pkt.proto
        return (src, dst, sport, dport, proto)
    
    def _packet_callback(self, pkt):
        """Callback invoked for each captured packet."""
        if IP in pkt and (TCP in pkt or UDP in pkt):
            self.total_packets += 1
            key = self._get_flow_key(pkt)
            with self.flow_lock:
                if key in self.active_flows:
                    self.active_flows[key].update(pkt)
                else:
                    self.active_flows[key] = Flow(pkt)
    
    def _analyze_flows(self):
        """Analyze updated flows and generate alerts for threats."""
        with self.flow_lock:
            if not self.active_flows:
                return
            
            current_flows = list(self.active_flows.items())
            
            for key, flow in current_flows:
                if not flow.updated:
                    continue
                    
                try:
                    f = flow.get_features()
                    
                    # Build 6-feature vector matching training order:
                    # [flow_duration, total_fwd_packets, total_bwd_packets,
                    #  packet_length_mean, packet_length_std, flow_iat_mean]
                    X = np.array([[
                        f["flow_duration"],
                        f["total_fwd_packets"],
                        f["total_bwd_packets"],
                        f["packet_length_mean"],
                        f["packet_length_std"],
                        f["flow_iat_mean"]
                    ]])
                    
                    X_scaled = self.scaler.transform(X)
                    
                    # Model inference
                    probs = self.model.predict_proba(X_scaled)[0]
                    pred_class_idx = np.argmax(probs)
                    confidence = probs[pred_class_idx]
                    pred_label = self.model.classes_[pred_class_idx]
                    
                    self.total_flows += 1
                    
                    # Determine if malicious
                    is_benign = "BENIGN" in str(pred_label).upper()
                    is_malicious = not is_benign
                    
                    # Heuristic: High packet count -> Suspicious
                    if f['total_fwd_packets'] > 100 and is_benign:
                        pred_label = "High Volume (Heuristic)"
                        is_malicious = True
                    
                    # Generate alert if threat detected
                    if is_malicious and confidence >= MIN_CONFIDENCE and f['src'] not in WHITELIST_IPS:
                        # Determine top contributing feature
                        if f['total_fwd_packets'] > 50:
                            top_feature = "High Forward Packets"
                        elif f['flow_iat_mean'] < 0.01:
                            top_feature = "Low Inter-Arrival Time"
                        else:
                            top_feature = str(pred_label)
                        
                        self._push_alert({
                            "threat_type": str(pred_label),
                            "source_ip": f['src'],
                            "dest_ip": f['dst'],
                            "confidence": round(confidence, 2),
                            "reason": top_feature,
                            "fwd_packets": f['total_fwd_packets'],
                            "bwd_packets": f['total_bwd_packets']
                        })
                        
                except Exception:
                    # Silently ignore occasional math/processing errors
                    pass
                    
                flow.updated = False
    
    def run(self):
        """Main thread execution - starts packet capture and analysis."""
        # Check Scapy availability
        if not SCAPY_AVAILABLE:
            self._push_error("NIDS requires Scapy library. Please install: pip install scapy")
            return
        
        # Load ML model
        if not self._load_model():
            return
        
        self.is_running = True
        
        # Start flow analysis in background
        def analyzer_loop():
            while not self.stop_event.is_set():
                time.sleep(1)
                try:
                    self._analyze_flows()
                except Exception:
                    pass
        
        analyzer_thread = threading.Thread(target=analyzer_loop, daemon=True, name="NIDS-AnalyzerThread")
        analyzer_thread.start()
        
        # Start packet capture with graceful error handling
        try:
            # Scapy sniff with stop condition
            sniff(
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except PermissionError:
            self._push_error("NIDS requires Administrator privileges to capture network packets. Please restart AEGIS as Administrator.")
        except OSError as e:
            if "permission" in str(e).lower() or "access" in str(e).lower():
                self._push_error("NIDS requires Administrator privileges to capture network packets. Please restart AEGIS as Administrator.")
            else:
                self._push_error(f"NIDS network error: {str(e)}")
        except Exception as e:
            # Catch Scapy-specific exceptions (e.g., Scapy_Exception)
            error_msg = str(e).lower()
            if "permission" in error_msg or "admin" in error_msg or "root" in error_msg or "access denied" in error_msg:
                self._push_error("NIDS requires Administrator privileges to capture network packets. Please restart AEGIS as Administrator.")
            elif "npcap" in error_msg or "winpcap" in error_msg:
                self._push_error("NIDS requires Npcap to be installed. Please install Npcap from https://npcap.com/")
            else:
                self._push_error(f"NIDS sniffer error: {str(e)}")
        finally:
            self.is_running = False
    
    def stop(self):
        """Signal the sniffer to stop gracefully."""
        self.stop_event.set()
    
    def is_active(self) -> bool:
        """Check if the sniffer is currently running."""
        return self.is_running and self.is_alive()
    
    def get_statistics(self) -> dict:
        """Get current sniffer statistics."""
        return {
            "is_active": self.is_active(),
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "threats_detected": self.threats_detected,
            "error": self.error_state
        }
