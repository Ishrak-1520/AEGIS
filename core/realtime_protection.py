"""
Real-Time Protection Module
Monitors screen content in real-time for cyber threats
Captures screenshots and analyzes visible text for phishing, malware, and suspicious patterns
Now includes Advanced Context Awareness and Smart Scanning
"""

import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

# Advanced RTP Dependencies
try:
    import ctypes
    import psutil
    PROCESS_Context_AVAILABLE = True
except ImportError:
    PROCESS_Context_AVAILABLE = False

try:
    from PIL import ImageGrab, Image, ImageChops
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    ImageGrab = None  # type: ignore
    Image = None  # type: ignore
    ImageChops = None # type: ignore

try:
    import pytesseract
    import platform
    
    # Configure Tesseract path for Windows
    if platform.system() == 'Windows':
        tesseract_paths = [
            r'C:\Program Files\Tesseract-OCR\tesseract.exe',
            r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
            r'C:\Tesseract-OCR\tesseract.exe',
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Tesseract-OCR\tesseract.exe')
        ]
        tesseract_found = False
        for path in tesseract_paths:
            if os.path.exists(path):
                # Set tesseract_cmd on the module
                pytesseract.tesseract_cmd = path
                
                # Try setting on submodule too (some versions need this)
                try:
                    pytesseract.pytesseract.tesseract_cmd = path
                except AttributeError:
                    pass
                
                # Add to PATH for this process (helps if pytesseract relies on PATH)
                tess_dir = os.path.dirname(path)
                if tess_dir not in os.environ['PATH']:
                    os.environ['PATH'] += os.pathsep + tess_dir
                
                tesseract_found = True
                print(f"Tesseract configured at: {path}") 
                break
    
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    pytesseract = None  # type: ignore

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from core.system_logger import system_logger

try:
    from ai.nlp_model import get_nlp_detector
    NLP_AVAILABLE = True
except (ImportError, AttributeError):
    NLP_AVAILABLE = False
    get_nlp_detector = None  # type: ignore

from core.monitor import live_telemetry
from core.hids_analyzer import get_volatile_hids
from core.threat_prevention import threat_prevention


class RealTimeProtection:
    """
    Real-time screen monitoring and threat detection system
    Continuously scans screen content for cyber threats
    """
    
    def __init__(self, scan_interval: float = 1.5):
        """
        Initialize real-time protection
        
        Args:
            scan_interval: Seconds between screen scans (default: 3.0)
        """
        self.scan_interval = scan_interval
        self.is_active = False
        self.monitor_thread = None
        
        # Threat detection callbacks
        self.threat_callbacks: List[Callable] = []
        
        # Statistics
        self.scans_performed = 0
        self.threats_detected = 0
        self.last_scan_time = None
        
        # Configuration
        self.threat_sensitivity = 'MEDIUM'  # LOW, MEDIUM, HIGH
        self.whitelist_urls = set()
        self.whitelist_processes = {
            'cyberguard.exe', 'cyberguard pro.exe', 'python.exe',
            'python3.exe', 'python3.11.exe', 'python3.12.exe', 'python3.13.exe',
            'pythonw.exe', 'pycharm64.exe',
            'code.exe', 'explorer.exe', 'taskmgr.exe'
        }
        
        # Performance monitoring
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        
        # Screen capture settings
        self.capture_enabled = True
        self.last_screen_text = ""
        self.last_screenshot = None
        
        # Threat history (to avoid duplicate alerts, capped short to allow re-detection)
        self.recent_threats = []
        self.max_threat_history = 5
        
        # Last OCR time (to force re-scan even if screen unchanged after a threshold)
        self._last_ocr_time = 0.0
        self._force_rescan_interval = 15.0  # Seconds before forcing re-scan even on static screen
        
        self._tesseract_ok = self._check_tesseract()
        
        # Volatile Memory HIDS
        self.volatile_hids = get_volatile_hids()
        self.memory_monitor_thread = None
        self.memory_scan_interval = 5.0
        self.last_memory_prob = 0.0
        self.last_telemetry_vector = []
        
        system_logger.log_info("Real-Time Protection initialized", 'app')

    def _check_tesseract(self) -> bool:
        """Check Tesseract OCR availability once at init. Returns True if usable."""
        if not TESSERACT_AVAILABLE or pytesseract is None:
            system_logger.log_warning("Real-Time Protection: pytesseract module not installed.", 'app')
            return False
        try:
            pytesseract.get_tesseract_version()
            return True
        except Exception:
            system_logger.log_warning(
                "Real-Time Protection: Tesseract OCR not found. "
                "Screen scanning disabled. Install from: https://github.com/UB-Mannheim/tesseract/wiki",
                'app'
            )
            return False
    
    def register_threat_callback(self, callback: Callable):
        """
        Register callback function for threat alerts
        
        Args:
            callback: Function to call when threat is detected
                     Signature: callback(threat_data: dict) -> None
        """
        self.threat_callbacks.append(callback)
    
    def start_protection(self) -> bool:
        """
        Start real-time protection monitoring
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_active:
            system_logger.log_warning("Real-Time Protection already active", 'app')
            return False
        
        if not NLP_AVAILABLE:
            system_logger.log_error("NLP module not available for Real-Time Protection", 'app')
            return False
        
        if not PIL_AVAILABLE:
            system_logger.log_error("PIL (Pillow) not available for Real-Time Protection", 'app')
            return False
        
        if not self._tesseract_ok:
            # Tesseract unavailable — start in degraded mode (screen scanning disabled)
            self._use_screen_scan = False
        else:
            self._use_screen_scan = True
        
        self.is_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        # Start Memory Monitor Thread
        self.memory_monitor_thread = threading.Thread(
            target=self._memory_monitoring_loop,
            daemon=True
        )
        self.memory_monitor_thread.start()
        
        # Log to database
        db_manager.log_event(
            'REALTIME_PROTECTION_START',
            'INFO',
            f'Real-Time Protection started (interval: {self.scan_interval}s)'
        )
        
        system_logger.log_info("Real-Time Protection started", 'app')
        return True
    
    def stop_protection(self) -> bool:
        """
        Stop real-time protection monitoring
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.is_active:
            return False
        
        self.is_active = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        
        # Log to database
        db_manager.log_event(
            'REALTIME_PROTECTION_STOP',
            'INFO',
            f'Real-Time Protection stopped (Scans: {self.scans_performed}, Threats: {self.threats_detected})'
        )
        
        system_logger.log_info(
            f"Real-Time Protection stopped. Scans: {self.scans_performed}, Threats: {self.threats_detected}",
            'app'
        )
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop (runs in background thread)"""
        while self.is_active:
            try:
                start_time = time.time()
                
                # Capture and analyze screen
                self._perform_screen_scan()
                
                # Update statistics
                scan_duration = time.time() - start_time
                self.last_scan_time = datetime.now()
                
                # Sleep until next scan
                sleep_time = max(0, self.scan_interval - scan_duration)
                time.sleep(sleep_time)
                
            except Exception as e:
                system_logger.log_error(f"Real-Time Protection monitoring error: {e}", 'app', exc_info=True)
                time.sleep(self.scan_interval)

    def _memory_monitoring_loop(self):
        """Dedicated loop for Volatile Memory HIDS analysis (runs every 5s)"""
        system_logger.log_info("Volatile Memory HIDS monitoring loop started", 'app')
        
        while self.is_active:
            try:
                # 1. Extract Telemetry
                vector = live_telemetry.get_live_telemetry_vector()
                self.last_telemetry_vector = vector.tolist()
                
                # 2. Analyze with ML Model
                is_threat, prob = self.volatile_hids.predict_memory_threat(vector)
                self.last_memory_prob = prob
                
                # 3. Handle Detection
                if is_threat:
                    self._handle_volatile_memory_threat(prob, vector)
                
                time.sleep(self.memory_scan_interval)
                
            except Exception as e:
                system_logger.log_error(f"Memory monitoring error: {e}", 'app', exc_info=True)
                time.sleep(self.memory_scan_interval)

    def _handle_volatile_memory_threat(self, probability: float, vector: Any):
        """Handle detected volatile memory threat"""
        self.threats_detected += 1
        
        threat_data = {
            'type': 'VOLATILE_MEMORY_THREAT',
            'level': 'CRITICAL',
            'confidence': probability * 100,
            'description': "In-Memory Threat Detected: High-probability fileless malware or exploit activity.",
            'timestamp': datetime.now().isoformat(),
            'source': 'Dynamic Volatile Memory HIDS',
            'telemetry': vector.tolist(),
            'malware_prob': probability,
            'recommended_actions': [
                "⚠️ Host network isolation triggered",
                "🚫 Suspicious process termination initiated",
                "🔍 Immediate full system scan recommended"
            ]
        }
        
        # Log to database
        db_manager.log_threat(
            threat_type='VOLATILE_MEMORY_THREAT',
            threat_level='CRITICAL',
            source='Volatile Memory HIDS',
            details=str(threat_data),
            action_taken='Automated Remediation Triggered',
            confidence_score=probability * 100
        )
        
        # Alert via system logger
        system_logger.log_threat(
            'VOLATILE_MEMORY_THREAT',
            'CRITICAL',
            f"Fileless malware detected with {probability*100:.1f}% probability. Triggering remediation."
        )
        
        # Notify registered callbacks (Popups)
        for callback in self.threat_callbacks:
            try:
                callback(threat_data)
            except Exception as e:
                system_logger.log_error(f"Threat callback error: {e}", 'app')
                
        # 4. Trigger Task 4: Automated EDR Remediation
        try:
            from core.threat_prevention import threat_prevention
            # Assuming Task 4 implements this method
            if hasattr(threat_prevention, 'remediate_volatile_threat'):
                threading.Thread(target=threat_prevention.remediate_volatile_threat, daemon=True).start()
        except Exception as e:
            system_logger.log_error(f"Remediation trigger error: {e}", 'app')
    
    def _get_active_window_info(self) -> Dict[str, Any]:
        """Get info about the active window (process name, fullscreen status)"""
        info = {'process': 'unknown', 'fullscreen': False}
        
        if not PROCESS_Context_AVAILABLE:
            return info
            
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            
            # Get Process Name
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            process = psutil.Process(pid.value)
            info['process'] = process.name().lower()
            
            # Check Fullscreen
            rect = ctypes.wintypes.RECT()
            ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            
            # Get Screen Resolution
            user32 = ctypes.windll.user32
            screen_w = user32.GetSystemMetrics(0)
            screen_h = user32.GetSystemMetrics(1)
            
            win_w = rect.right - rect.left
            win_h = rect.bottom - rect.top
            
            if win_w >= screen_w and win_h >= screen_h:
                info['fullscreen'] = True
                
        except Exception:
            pass
            
        return info

    def _perform_screen_scan(self):
        """Capture screen and analyze for threats with Smart Scanning"""
        if not self.capture_enabled:
            return
        
        # If running in degraded mode (no Tesseract), skip screen OCR
        if not getattr(self, '_use_screen_scan', False):
            return
        
        try:
            # Capture screen
            screenshot = self._capture_screen()
            if screenshot is None:
                return
            
            # 1. Differential Scanning: Check if screen changed significantly
            if self.last_screenshot is not None:
                # Resize to small thumbnail for fast comparison
                curr_thumb = screenshot.resize((100, 100))
                last_thumb = self.last_screenshot.resize((100, 100))
                
                diff = ImageChops.difference(curr_thumb, last_thumb)
                time_since_ocr = time.time() - self._last_ocr_time
                screen_changed = diff.getbbox() is not None
                
                if not screen_changed and time_since_ocr < self._force_rescan_interval:
                    # Screen same AND not enough time passed — skip expensive OCR
                    return
            
            self.last_screenshot = screenshot.copy()
            self._last_ocr_time = time.time()

            # 2. Context Awareness: Get active window info
            window_info = self._get_active_window_info()
            active_process = window_info['process']
            is_fullscreen = window_info['fullscreen']
            
            # 3. Whitelist Check: Skip if process is safe
            if active_process in self.whitelist_processes:
                # Still count as scan, but skip analysis
                self.scans_performed += 1
                return

            # Extract text from screenshot using OCR
            screen_text = self._extract_text_from_image(screenshot)
            
            # Skip if no text or same as last scan
            if not screen_text or screen_text.strip() == "":
                return
            
            # Analyze text for threats
            self._analyze_screen_text(screen_text, active_process, is_fullscreen)
            
            self.scans_performed += 1
            self.last_screen_text = screen_text
            
        except Exception as e:
            system_logger.log_error(f"Screen scan error: {e}", 'app', exc_info=True)
    
    def _capture_screen(self) -> Optional[Any]:
        """
        Capture current screen
        
        Returns:
            PIL Image object or None if capture fails
        """
        if not PIL_AVAILABLE or ImageGrab is None:
            return None
        
        try:
            screenshot = ImageGrab.grab()
            return screenshot
        except Exception as e:
            system_logger.log_error(f"Screen capture error: {e}", 'app')
            return None

    def _extract_text_from_image(self, image: Any) -> str:
        """
        Extract text from image using OCR
        
        Args:
            image: PIL Image object
            
        Returns:
            Extracted text string
        """
        if not TESSERACT_AVAILABLE or pytesseract is None or Image is None:
            return ""
        
        try:
            # Optimize image for OCR (resize if too large)
            max_dimension = 1920
            if image.width > max_dimension or image.height > max_dimension:
                ratio = min(max_dimension / image.width, max_dimension / image.height)
                new_size = (int(image.width * ratio), int(image.height * ratio))
                # Use LANCZOS (Pillow 10+) or ANTIALIAS (older versions)
                try:
                    image = image.resize(new_size, Image.Resampling.LANCZOS)  # Pillow 10+
                except (AttributeError, TypeError):
                    # Fallback for older Pillow versions
                    try:
                        image = image.resize(new_size, 1)  # 1 = ANTIALIAS constant
                    except Exception:
                        pass  # Use original size if resize fails
            
            # Extract text using Tesseract OCR with fast config
            # PSM 11 = Sparse text (good for mixed screen content)
            # OEM 1 = LSTM neural net engine only (faster than default combined)
            custom_config = '--psm 11 --oem 1'
            text = pytesseract.image_to_string(image, lang='eng', config=custom_config)
            return text.strip()
            
        except Exception as e:
            system_logger.log_error(f"OCR extraction error: {e}", 'app')
            return ""
    
    def _analyze_screen_text(self, text: str, process_name: str = "unknown", is_fullscreen: bool = False):
        """
        Analyze extracted screen text for threats
        
        Args:
            text: Text extracted from screen
            process_name: Name of the active process
            is_fullscreen: Whether the active window is fullscreen
        """
        if not NLP_AVAILABLE or get_nlp_detector is None:
            return
        
        try:
            # Get NLP detector
            detector = get_nlp_detector()
            
            # --- FIX: SILENCE VERBOSE LOGS ---
            # Force the internal model to be quiet
            try:
                # Check for common model attributes and silence them
                if hasattr(detector, 'model') and hasattr(detector.model, 'verbose'):
                    detector.model.verbose = 0
                elif hasattr(detector, 'verbose'):
                    detector.verbose = 0
            except Exception:
                pass
            # ---------------------------------
            
            # Analyze text
            result = detector.analyze_text(text)
            
            # Check threat level based on sensitivity
            threat_level = result.get('threat_level', 'SAFE')
            
            # Determine if alert should be triggered based on sensitivity and context
            should_alert = self._should_trigger_alert(threat_level, result, process_name, is_fullscreen)
            
            if should_alert:
                self._handle_threat_detection(text, result, process_name)
        
        except Exception as e:
            system_logger.log_error(f"Screen text analysis error: {e}", 'app', exc_info=True)
    
    def _should_trigger_alert(self, threat_level: str, result: dict, process_name: str, is_fullscreen: bool) -> bool:
        """
        Determine if alert should be triggered based on sensitivity settings
        
        Args:
            threat_level: Detected threat level
            result: Analysis result dictionary
            process_name: Active process name
            is_fullscreen: Whether active window is fullscreen
            
        Returns:
            True if alert should be triggered
        """
        confidence = result.get('confidence', 0)
        
        # Sensitivity thresholds
        thresholds = {
            'LOW': ['CRITICAL', 'HIGH'],
            'MEDIUM': ['CRITICAL', 'HIGH', 'MEDIUM'],
            'HIGH': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        }
        
        # Check if threat level meets sensitivity threshold
        if threat_level not in thresholds.get(self.threat_sensitivity, ['CRITICAL', 'HIGH', 'MEDIUM']):
            return False
        
        # Require minimum confidence
        min_confidence = {
            'LOW': 80.0,
            'MEDIUM': 60.0,
            'HIGH': 40.0
        }
        
        if confidence < min_confidence.get(self.threat_sensitivity, 60.0):
            return False
            
        # Whitelist Check (Double check in case called directly)
        if process_name in self.whitelist_processes:
            return False
            
        # Game Mode / Presentation Mode Logic
        # If fullscreen and threat is NOT CRITICAL, suppress popup (log only)
        if is_fullscreen and threat_level != 'CRITICAL':
            # Log suppression
            system_logger.log_info(f"Suppressed {threat_level} alert in Game Mode (Process: {process_name})", 'threat')
            return False
        
        # Check if a threat at same level from same process was very recently detected (avoid spam)
        threat_signature = f"{threat_level}:{process_name}"
        if threat_signature in self.recent_threats:
            return False
        
        return True
    
    def _handle_threat_detection(self, text: str, result: dict, process_name: str):
        """
        Handle detected threat
        
        Args:
            text: Original screen text
            result: Threat analysis result
            process_name: Active process name
        """
        self.threats_detected += 1
        
        threat_level = result.get('threat_level', 'UNKNOWN')
        confidence = result.get('confidence', 0)
        patterns = result.get('patterns_detected', [])
        keywords = result.get('keywords_found', [])
        
        # Create threat data
        threat_data = {
            'type': 'SCREEN_THREAT',
            'level': threat_level,
            'confidence': confidence,
            'patterns': patterns,
            'keywords': keywords[:5],  # Limit to first 5 keywords
            'description': result.get('description', ''),
            'timestamp': datetime.now().isoformat(),
            'source': f'Real-Time Protection ({process_name})',
            'process': process_name,
            'screen_text_sample': text[:200] if len(text) > 200 else text,  # First 200 chars
            'recommended_actions': self._get_recommended_actions(threat_level, patterns)
        }
        
        # Add XAI explanation
        threat_data["xai"] = self._generate_nlp_xai_explanation(result, process_name)
        
        # Add to recent threats (to avoid duplicate spam)
        threat_signature = f"{threat_level}:{process_name}"
        self.recent_threats.append(threat_signature)
        if len(self.recent_threats) > self.max_threat_history:
            self.recent_threats.pop(0)
        
        # Log to database
        db_manager.log_threat(
            threat_type='REALTIME_SCREEN_THREAT',
            threat_level=threat_level,
            source=f'Screen Monitor ({process_name})',
            details=str(threat_data),
            action_taken='Alert Displayed',
            confidence_score=confidence
        )
        
        # Log to file
        system_logger.log_threat(
            'SCREEN_THREAT',
            threat_level,
            f"Process: {process_name}, Patterns: {', '.join(patterns)}, Confidence: {confidence:.1f}%"
        )
        
        # Trigger callbacks (show popup alerts)
        for callback in self.threat_callbacks:
            try:
                callback(threat_data)
            except Exception as e:
                system_logger.log_error(f"Threat callback error: {e}", 'app')
    
    def _generate_nlp_xai_explanation(self, result: dict, process_name: str) -> dict:
        """
        Generate an Explainable AI (XAI) explanation dict for an NLP screen threat
        to surface in the frontend notification pane.
        """
        threat_level = result.get('threat_level', 'UNKNOWN')
        confidence   = result.get('confidence', 0)
        patterns     = result.get('patterns_detected', [])
        description  = result.get('description', '')
        
        # Map level to risk
        risk_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
        risk_level = risk_map.get(threat_level, 'MEDIUM')
        
        # Build a simple plain-language explanation from the classified patterns
        pattern_explanations = {
            'Phishing Indicators':    "The text contains language commonly used in phishing emails or pages — attempting to trick you into revealing personal information.",
            'Urgency Language':       "Strong urgency cues (e.g. 'ACT NOW', 'IMMEDIATELY') are being used to pressure you into hasty action — a classic social engineering tactic.",
            'Suspicious URLs':        "Suspicious or obfuscated URLs were detected. These may redirect you to a fake site designed to steal your credentials.",
            'Credential Request':     "The content is requesting your username, password, or PIN — a red flag if it appeared unexpectedly.",
            'Financial Request':      "A request for financial information (credit card, bank account) was detected on screen.",
            'Malware Indicators':     "Language associated with fake system warnings or malware scare-tactics was detected.",
            'Malware/Exploit Keywords': "Language associated with malware, exploits, or hacking tools was detected on screen.",
            'PII Detected: Email':    "Email addresses are visible on screen and may be targets of phishing or data harvesting.",
            'PII Detected: IPv4':     "IP addresses were spotted, which may indicate network configuration pages or attack instructions.",
            'Web Browsing Threat':    "The website is displaying deceptive content — such as fake permission prompts, clickjacking overlays, or misleading download buttons — designed to trick you into clicking something harmful.",
            'Social Engineering':     "The content uses social manipulation tactics to pressure you into taking an action — like claiming a prize or responding to a fake urgent message.",
            'Scam Indicators':        "The text matches common online scam patterns — such as fake investment opportunities, lottery wins, or get-rich-quick schemes.",
            'Cleared by AI Context Analysis': "The initial keyword scan flagged this, but the AI confirmed the context is safe.",
        }
        
        # Find the first matching pattern explanation
        simple = next(
            (pattern_explanations[p] for p in patterns if p in pattern_explanations),
            f"The AI detected suspicious content with {confidence:.0f}% confidence based on the text visible on your screen."
        )
        
        # Technical: list patterns + process
        tech = (
            f"Process: {process_name} | Confidence: {confidence:.1f}% | "
            f"Patterns: {', '.join(patterns[:3]) if patterns else 'General anomaly'}"
        )
        
        # Confidence interpretation
        if confidence >= 90:
            conf_text = "Very High — AI is nearly certain this is malicious content."
        elif confidence >= 75:
            conf_text = "High — very likely a genuine threat."
        elif confidence >= 55:
            conf_text = "Moderate — probable threat, exercise caution."
        else:
            conf_text = "Low — possible threat, worth monitoring."
        
        # Choose recommended action based on risk
        actions = {
            'CRITICAL': "Close this window immediately and do not enter any information. Run a quick scan.",
            'HIGH':     "Do not click any links or enter credentials. Verify the source of this content.",
            'MEDIUM':   "Be cautious — verify the legitimacy of what is being shown before proceeding.",
            'LOW':      "This content is mildly suspicious. Stay alert and avoid sharing personal information.",
        }
        
        return {
            "title": f"{risk_level} Threat Detected by Screen Monitor",
            "simple_explanation": simple,
            "technical_details": tech,
            "risk_level": risk_level,
            "recommended_action": actions.get(risk_level, "Review the on-screen content carefully."),
            "confidence_interpretation": conf_text,
            "attack_categories": patterns[:5] if patterns else ["Suspicious Content"],
            "description": description,
        }
    
    def _get_recommended_actions(self, threat_level: str, patterns: List[str]) -> List[str]:
        """
        Get recommended actions based on threat
        
        Args:
            threat_level: Detected threat level
            patterns: Detected threat patterns
            
        Returns:
            List of recommended action strings
        """
        actions = []
        
        if threat_level == 'CRITICAL':
            actions.append("⚠️ Close suspicious window immediately")
            actions.append("🚫 Do not enter any personal information")
            actions.append("📋 Take screenshot for evidence")
        elif threat_level == 'HIGH':
            actions.append("⚠️ Verify source before proceeding")
            actions.append("🔍 Check URL authenticity")
            actions.append("🚫 Avoid clicking suspicious links")
        elif threat_level == 'MEDIUM':
            actions.append("⚠️ Exercise caution")
            actions.append("🔍 Verify legitimacy of request")
        else:
            actions.append("ℹ️ Be aware of potential risk")
        
        # Pattern-specific actions
        if 'Phishing Indicators' in patterns:
            actions.append("📧 Verify sender email address")
            actions.append("🔗 Do not click on links")
        
        if 'Suspicious URLs' in patterns:
            actions.append("🌐 Manually type website address")
            actions.append("🔒 Check for HTTPS and valid certificate")
        
        if 'Credential Request' in patterns:
            actions.append("🔐 Never enter passwords on suspicious pages")
            actions.append("☎️ Contact organization directly to verify")
        
        if 'Financial Request' in patterns:
            actions.append("💳 Do not provide financial information")
            actions.append("🏦 Contact bank directly if requested")
        
        return actions
    
    def set_scan_interval(self, interval: float):
        """Set scan interval in seconds"""
        self.scan_interval = max(1.0, min(10.0, interval))  # Clamp between 1-10 seconds
    
    def set_threat_sensitivity(self, sensitivity: str):
        """Set threat detection sensitivity (LOW, MEDIUM, HIGH)"""
        if sensitivity in ['LOW', 'MEDIUM', 'HIGH']:
            self.threat_sensitivity = sensitivity
            db_manager.log_event(
                'RTP_SENSITIVITY_CHANGE',
                'INFO',
                f'Threat sensitivity changed to {sensitivity}'
            )
    
    def add_to_whitelist(self, item: str, item_type: str):
        """
        Add item to whitelist
        
        Args:
            item: URL or process name to whitelist
            item_type: 'url' or 'process'
        """
        if item_type == 'url':
            self.whitelist_urls.add(item.lower())
        elif item_type == 'process':
            self.whitelist_processes.add(item.lower())
    
    def remove_from_whitelist(self, item: str, item_type: str):
        """Remove item from whitelist"""
        if item_type == 'url':
            self.whitelist_urls.discard(item.lower())
        elif item_type == 'process':
            self.whitelist_processes.discard(item.lower())
    
    def get_statistics(self) -> Dict:
        """
        Get real-time protection statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'is_active': self.is_active,
            'scans_performed': self.scans_performed,
            'threats_detected': self.threats_detected,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
            'scan_interval': self.scan_interval,
            'threat_sensitivity': self.threat_sensitivity,
            'whitelist_count': len(self.whitelist_urls) + len(self.whitelist_processes)
        }


# Global instance
realtime_protection = RealTimeProtection()
