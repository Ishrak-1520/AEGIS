"""
AEGIS HIDS Analyzer
Host-based Intrusion Detection using PE file analysis.

This module analyzes Windows PE (Portable Executable) files for malware
by examining their Import Address Table (IAT) and comparing against
a trained ML model.
"""
import os
import sys
import warnings
import numpy as np
import joblib
import time
from datetime import datetime
from core.system_logger import system_logger

# Suppress sklearn warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Try to import pefile
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# --- Path Configuration ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "hids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "ai", "models", "hids_scaler.pkl")
API_MAPPING_PATH = os.path.join(BASE_DIR, "ai", "models", "hids_api_mapping.pkl")
VOLATILE_MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "volatile_hids_model.pkl")

# Number of features expected by the model (t_0 to t_99)
NUM_FEATURES = 100

# Common Windows API functions for mapping
# These are commonly seen in malware analysis
COMMON_API_FUNCTIONS = [
    "VirtualAlloc", "VirtualProtect", "VirtualFree", "VirtualQuery",
    "CreateRemoteThread", "CreateThread", "CreateProcess", "CreateFile",
    "WriteFile", "ReadFile", "DeleteFile", "CopyFile", "MoveFile",
    "RegOpenKey", "RegSetValue", "RegCreateKey", "RegDeleteKey",
    "LoadLibrary", "GetProcAddress", "GetModuleHandle", "FreeLibrary",
    "OpenProcess", "TerminateProcess", "WriteProcessMemory", "ReadProcessMemory",
    "CreateService", "StartService", "ControlService", "DeleteService",
    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
    "URLDownloadToFile", "WSAStartup", "socket", "connect", "send", "recv",
    "GetWindowsDirectory", "GetSystemDirectory", "GetTempPath",
    "ShellExecute", "WinExec", "system", "CreateMutex",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    "NtQuerySystemInformation", "ZwQuerySystemInformation",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
    "GetTickCount", "QueryPerformanceCounter", "Sleep",
    "EnumProcesses", "EnumProcessModules", "GetModuleBaseName",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
    "SetFileAttributes", "GetFileAttributes", "FindFirstFile", "FindNextFile",
    "CreatePipe", "PeekNamedPipe", "CreateMailslot",
    "NetUserAdd", "NetUserDel", "NetLocalGroupAddMembers",
    "ExitProcess", "ExitThread", "ExitWindowsEx",
    "GetComputerName", "GetUserName", "GetVersionEx",
    "MessageBox", "FindWindow", "ShowWindow", "SetWindowText",
    "CloseHandle", "DuplicateHandle", "SetHandleInformation"
]


class MalwareAnalyzer:
    """
    Analyzes PE files for potential malware using ML-based classification.
    
    Uses a trained RandomForest model on API call patterns extracted from
    the PE file's Import Address Table (IAT).
    """
    
    def __init__(self):
        """Initialize the analyzer and load ML artifacts."""
        self.model = None
        self.scaler = None
        self.api_mapping = None
        self.is_loaded = False
        self.error = None
        
        # Build a simple API-to-index mapping for common functions
        self.api_to_index = {api.lower(): idx for idx, api in enumerate(COMMON_API_FUNCTIONS)}
        
        self._load_model()
    
    def _load_model(self):
        """Load the HIDS model and scaler."""
        try:
            if not os.path.exists(MODEL_PATH):
                self.error = f"HIDS model not found: {MODEL_PATH}"
                return
            
            if not os.path.exists(SCALER_PATH):
                self.error = f"HIDS scaler not found: {SCALER_PATH}"
                return
            
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            
            # Load API mapping if available
            if os.path.exists(API_MAPPING_PATH):
                self.api_mapping = joblib.load(API_MAPPING_PATH)
            
            self.is_loaded = True
            
        except Exception as e:
            self.error = f"Failed to load HIDS model: {str(e)}"
    
    def extract_pe_features(self, file_path: str) -> tuple:
        """
        Extract features from a PE file's Import Address Table.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Tuple of (feature_vector, error_message)
            If successful, error_message is None
        """
        if not PEFILE_AVAILABLE:
            return None, "pefile library not installed"
        
        if not os.path.exists(file_path):
            return None, f"File not found: {file_path}"
        
        try:
            # Parse PE file
            pe = pefile.PE(file_path, fast_load=True)
            
            # Parse imports only
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
            
            # Initialize feature vector with zeros
            features = np.zeros(NUM_FEATURES)
            
            # Extract imported functions
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                api_counts = {}
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            func_lower = func_name.lower()
                            
                            # Count API occurrences
                            if func_lower in api_counts:
                                api_counts[func_lower] += 1
                            else:
                                api_counts[func_lower] = 1
                
                # Map API calls to feature indices
                # Strategy: Use common API function mapping for first ~80 slots
                # Then use hash-based mapping for remaining functions
                
                idx = 0
                for api_name, count in api_counts.items():
                    if api_name in self.api_to_index:
                        # Use predefined index for known APIs
                        feat_idx = self.api_to_index[api_name]
                        if feat_idx < NUM_FEATURES:
                            features[feat_idx] = count
                    else:
                        # For unknown APIs, use hash-based distribution
                        # in the remaining feature space
                        hash_idx = hash(api_name) % (NUM_FEATURES - len(COMMON_API_FUNCTIONS))
                        feat_idx = len(COMMON_API_FUNCTIONS) + hash_idx
                        if feat_idx < NUM_FEATURES:
                            features[feat_idx] += count
                
            pe.close()
            return features, None
            
        except pefile.PEFormatError:
            return None, "Not a valid PE file"
        except Exception as e:
            return None, f"PE analysis error: {str(e)}"
    
    def predict_pe_file(self, file_path: str) -> dict:
        """
        Analyze a PE file and return malware prediction.
        
        Args:
            file_path: Path to the PE file to analyze
            
        Returns:
            Dictionary with analysis results:
            {
                "file": str,
                "is_malware": bool,
                "threat_score": float (0.0-1.0),
                "confidence": float,
                "error": str or None
            }
        """
        result = {
            "file": os.path.basename(file_path),
            "path": file_path,
            "is_malware": False,
            "threat_score": 0.0,
            "confidence": 0.0,
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Check if model is loaded
        if not self.is_loaded:
            result["error"] = self.error or "Model not loaded"
            return result
        
        # Check if pefile is available
        if not PEFILE_AVAILABLE:
            result["error"] = "pefile library not installed (pip install pefile)"
            return result
        
        # Extract features
        features, extract_error = self.extract_pe_features(file_path)
        if extract_error:
            result["error"] = extract_error
            return result
        
        try:
            # Reshape and scale features
            X = features.reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            # Get malware probability (class 1)
            malware_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
            
            result["is_malware"] = bool(prediction == 1)
            result["threat_score"] = round(float(malware_prob), 4)
            result["confidence"] = round(float(max(probabilities)), 4)
            
            return result
            
        except Exception as e:
            result["error"] = f"Prediction error: {str(e)}"
            return result
    
    def is_available(self) -> bool:
        """Check if the analyzer is ready to use."""
        return self.is_loaded and PEFILE_AVAILABLE
    
    def get_status(self) -> dict:
        """Get analyzer status information."""
        return {
            "model_loaded": self.is_loaded,
            "pefile_available": PEFILE_AVAILABLE,
            "error": self.error,
            "model_path": MODEL_PATH
        }



class VolatileMemoryHIDS:
    """
    Analyzes live memory telemetry using a pre-trained Random Forest classifier.
    Mitigates the 'Sandbox Paradox' with Dynamic Baseline Calibration.
    """
    
    def __init__(self):
        self.model = None
        self.threshold = 0.90
        self.is_loaded = False
        self.error = None
        
        # --- Sandbox Paradox Mitigation: Calibration State ---
        self.calibration_samples = []
        self.calibration_limit = 5  # Capture 5 samples for a quick baseline
        self.calibration_offset = np.zeros(5)
        self.is_calibrated = False
        
        # Target Training Population Mean (Estimated from CIC-MalMem-2022)
        # Shifting local telemetry to these levels moves them into the model's "Comfort Zone"
        self.target_metrics = np.array([450, 221, 500, 40, 0])
        
        self.last_inference_time = 0.0
        
        self._load_model()
    
    def _load_model(self):
        """Load the volatile memory ML model."""
        try:
            if not os.path.exists(VOLATILE_MODEL_PATH):
                self.error = f"Volatile HIDS model not found: {VOLATILE_MODEL_PATH}"
                return
            
            self.model = joblib.load(VOLATILE_MODEL_PATH)
            self.is_loaded = True
            
        except Exception as e:
            self.error = f"Failed to load Volatile HIDS model: {str(e)}"
    
    def predict_memory_threat(self, features_vector: np.ndarray) -> tuple:
        """
        Predict if the current memory telemetry indicates a threat.
        Applies Dynamic Baseline Calibration to resolve Sandbox Paradox.
        
        Args:
            features_vector: Numpy array of 5 features
            
        Returns:
            Tuple of (is_malware: bool, threat_probability: float)
        """
        if not self.is_loaded:
            return False, 0.0
            
        try:
            # 1. Calibration Phase
            if not self.is_calibrated:
                self.calibration_samples.append(features_vector)
                
                if len(self.calibration_samples) >= self.calibration_limit:
                    # Calculate baseline and offset
                    baseline = np.mean(self.calibration_samples, axis=0)
                    self.calibration_offset = self.target_metrics - baseline
                    # Ensure we don't zero out 64-bit proc checks if they are actually 0
                    self.calibration_offset[4] = 0 
                    self.is_calibrated = True
                    system_logger.log_info(f"HIDS Calibration Complete. Offset: {self.calibration_offset.tolist()}", 'app')
                
                # While calibrating, we return low probability to avoid false positives
                return False, 0.05
            
            # 2. Apply Calibration Offset
            calibrated_X = features_vector + self.calibration_offset
            
            # Ensure no negative values after calibration
            calibrated_X = np.maximum(calibrated_X, 0)
            
            # Reshape features for model prediction
            X_input = calibrated_X.reshape(1, -1)
            
            # 3. Get probability scores
            start_inference = time.perf_counter()
            probabilities = self.model.predict_proba(X_input)[0]
            self.last_inference_time = (time.perf_counter() - start_inference) * 1000
            
            malware_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
            
            # Apply Adaptive Threshold
            is_malware = malware_prob >= self.threshold
            
            return is_malware, round(malware_prob, 4)
            
        except Exception as e:
            system_logger.log_error(f"Volatile HIDS prediction error: {e}", 'app')
            return False, 0.0

    def get_status(self) -> dict:
        """Get volatile analyzer status."""
        return {
            "model_loaded": self.is_loaded,
            "threshold": self.threshold,
            "error": self.error,
            "model_path": VOLATILE_MODEL_PATH
        }


# Singleton instances
_analyzer_instance = None
_volatile_hids_instance = None


def get_malware_analyzer() -> MalwareAnalyzer:
    """Get or create the singleton MalwareAnalyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = MalwareAnalyzer()
    return _analyzer_instance


def get_volatile_hids() -> VolatileMemoryHIDS:
    """Get or create the singleton VolatileMemoryHIDS instance."""
    global _volatile_hids_instance
    if _volatile_hids_instance is None:
        _volatile_hids_instance = VolatileMemoryHIDS()
    return _volatile_hids_instance


# --- CLI for testing ---
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AEGIS HIDS - PE File Analyzer")
    parser.add_argument("file", nargs="?", help="PE file to analyze")
    parser.add_argument("--status", action="store_true", help="Show analyzer status")
    args = parser.parse_args()
    
    analyzer = get_malware_analyzer()
    
    if args.status:
        print("\n=== HIDS Analyzer Status ===")
        status = analyzer.get_status()
        for key, value in status.items():
            print(f"  {key}: {value}")
        print()
    elif args.file:
        print(f"\nAnalyzing: {args.file}")
        result = analyzer.predict_pe_file(args.file)
        print(f"\n=== Analysis Result ===")
        for key, value in result.items():
            print(f"  {key}: {value}")
        print()
        
        if result["is_malware"]:
            print("⚠️  WARNING: File appears to be MALWARE")
        else:
            print("✓ File appears to be SAFE")
    else:
        parser.print_help()
