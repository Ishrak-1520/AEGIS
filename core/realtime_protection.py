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


class RealTimeProtection:
    """
    Real-time screen monitoring and threat detection system
    Continuously scans screen content for cyber threats
    """
    
    def __init__(self, scan_interval: float = 3.0):
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
            'cyberguard.exe', 'cyberguard pro.exe', 'python.exe', 'pycharm64.exe', 
            'code.exe', 'notepad.exe', 'explorer.exe', 'taskmgr.exe'
        }
        
        # Performance monitoring
        self.cpu_usage = 0.0
        self.memory_usage = 0.0
        
        # Screen capture settings
        self.capture_enabled = True
        self.last_screen_text = ""
        self.last_screenshot = None
        
        # Threat history (to avoid duplicate alerts)
        self.recent_threats = []
        self.max_threat_history = 10
        
        system_logger.log_info("Real-Time Protection initialized", 'app')
    
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
        
        if not TESSERACT_AVAILABLE:
            system_logger.log_error("pytesseract module not available for Real-Time Protection", 'app')
            return False
        
        # Test if Tesseract OCR executable is actually accessible
        if pytesseract is not None:
            try:
                pytesseract.get_tesseract_version()
            except Exception as e:
                system_logger.log_error(f"Tesseract OCR executable not found: {e}", 'app')
                system_logger.log_error("Install Tesseract OCR from: https://github.com/UB-Mannheim/tesseract/wiki", 'app')
                return False
        
        self.is_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
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
                if not diff.getbbox():
                    # Screen hasn't changed, skip expensive OCR
                    return
            
            self.last_screenshot = screenshot.copy()

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
            
            # Extract text using Tesseract OCR
            text = pytesseract.image_to_string(image, lang='eng')
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
        
        # Check if similar threat was recently detected (avoid duplicates)
        threat_signature = f"{threat_level}:{','.join(result.get('patterns_detected', []))}:{process_name}"
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
        
        # Add to recent threats (to avoid duplicates)
        threat_signature = f"{threat_level}:{','.join(patterns)}:{process_name}"
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
