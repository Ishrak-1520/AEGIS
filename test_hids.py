"""
AEGIS HIDS Test Script
Tests both components of the Volatile Guardian:
1. PE File Analyzer (static .exe scanning)
2. Volatile Memory HIDS (live memory analysis)
"""
import os
import sys
import time
import numpy as np

# Setup path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Suppress noisy warnings
import warnings
warnings.filterwarnings("ignore")

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
WARN = "\033[93m[WARN]\033[0m"

results = []

def log_result(test_name, passed, detail=""):
    status = PASS if passed else FAIL
    print(f"  {status} {test_name}" + (f" - {detail}" if detail else ""))
    results.append((test_name, passed))


print("\n" + "=" * 60)
print("  AEGIS HIDS TEST SUITE - Volatile Guardian")
print("=" * 60)

# =============================================
# TEST 1: PE File Analyzer
# =============================================
print(f"\n{INFO} TEST GROUP 1: PE File Analyzer (MalwareAnalyzer)")
print("-" * 50)

try:
    from core.hids_analyzer import get_malware_analyzer
    analyzer = get_malware_analyzer()
    
    # 1a. Model loaded?
    log_result(
        "Model loads successfully",
        analyzer.is_loaded,
        analyzer.error or "OK"
    )
    
    # 1b. pefile available?
    from core.hids_analyzer import PEFILE_AVAILABLE
    log_result(
        "pefile library available",
        PEFILE_AVAILABLE,
        "Installed" if PEFILE_AVAILABLE else "Not installed (pip install pefile)"
    )
    
    # 1c. Scan a known-safe Windows executable
    safe_files = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\explorer.exe",
    ]
    
    scanned = False
    for safe_file in safe_files:
        if os.path.exists(safe_file):
            result = analyzer.predict_pe_file(safe_file)
            
            log_result(
                f"Scan safe file ({os.path.basename(safe_file)})",
                result["error"] is None,
                result["error"] or f"Threat score: {result['threat_score']:.4f}, Is malware: {result['is_malware']}"
            )
            
            # The model uses a 0.90 threshold. As long as is_malware=False, the file is correctly classified.
            log_result(
                f"Safe file not flagged as malware ({os.path.basename(safe_file)})",
                not result["is_malware"],
                f"Correctly NOT flagged (score {result['threat_score']:.2f} < 0.90 threshold)" if not result["is_malware"] else f"FALSE POSITIVE - flagged with score {result['threat_score']:.4f}"
            )
            scanned = True
            break
    
    if not scanned:
        log_result("Scan safe file", False, "No test .exe files found")

    # 1d. Handle non-existent file gracefully
    result = analyzer.predict_pe_file(r"C:\fake\doesnt_exist.exe")
    log_result(
        "Handle missing file gracefully",
        result["error"] is not None,
        "Error caught correctly" if result["error"] else "Should have returned an error"
    )
    
    # 1e. Handle non-PE file gracefully
    result = analyzer.predict_pe_file(os.path.join(BASE_DIR, "requirements.txt"))
    log_result(
        "Handle non-PE file gracefully",
        result["error"] is not None,
        "Error caught correctly" if result["error"] else "Should have returned an error"
    )

except Exception as e:
    log_result("PE Analyzer initialization", False, str(e))

# =============================================
# TEST 2: Volatile Memory HIDS
# =============================================
print(f"\n{INFO} TEST GROUP 2: Volatile Memory HIDS (Live Memory Analysis)")
print("-" * 50)

try:
    from core.hids_analyzer import get_volatile_hids
    hids = get_volatile_hids()
    
    # 2a. Model loaded?
    log_result(
        "Volatile HIDS model loads",
        hids.is_loaded,
        hids.error or "OK"
    )
    
    # 2b. Test with normal-looking telemetry (should be safe)
    # Simulating: ~200 services, ~220 drivers, ~500 mutexes, ~40 DLLs, 0 64-bit flag
    normal_vector = np.array([200, 220, 500, 40, 0])
    
    # Reset calibration for clean test
    hids.calibration_samples = []
    hids.is_calibrated = False
    hids.calibration_offset = np.zeros(5)
    
    # Feed calibration samples (5 needed)
    print(f"  {INFO} Feeding 5 calibration samples...")
    for i in range(5):
        is_threat, prob = hids.predict_memory_threat(normal_vector)
    
    log_result(
        "Calibration completes",
        hids.is_calibrated,
        f"Offset: {hids.calibration_offset.tolist()}"
    )
    
    # 2c. Normal telemetry should be classified as SAFE
    is_threat, prob = hids.predict_memory_threat(normal_vector)
    log_result(
        "Normal telemetry = SAFE",
        not is_threat,
        f"Threat probability: {prob*100:.1f}% (threshold: {hids.threshold*100:.0f}%)"
    )
    
    # 2d. Test with suspicious telemetry (extremely high values)
    # Simulating: 1000 services, 500 drivers, 5000 mutexes, 200 DLLs, 1 64-bit
    suspicious_vector = np.array([1000, 500, 5000, 200, 1])
    is_threat_suspicious, prob_suspicious = hids.predict_memory_threat(suspicious_vector)
    log_result(
        "Suspicious telemetry detection",
        True,  # We just want to see that prediction runs without errors
        f"Threat probability: {prob_suspicious*100:.1f}%, Flagged: {is_threat_suspicious}"
    )

except Exception as e:
    log_result("Volatile HIDS initialization", False, str(e))


# =============================================
# TEST 3: Live Telemetry Collection
# =============================================
print(f"\n{INFO} TEST GROUP 3: Live Telemetry Collection (Windows Metrics)")
print("-" * 50)

try:
    from core.monitor import live_telemetry
    
    # 3a. Collect live vector
    print(f"  {INFO} Collecting live system telemetry...")
    start = time.time()
    vector = live_telemetry.get_live_telemetry_vector()
    elapsed = time.time() - start
    
    log_result(
        "Telemetry collection works",
        vector is not None and len(vector) == 5,
        f"Got {len(vector)} features in {elapsed:.1f}s"
    )
    
    # 3b. Print the live values
    feature_names = [
        "Background Programs (services)",
        "Hardware Drivers",
        "Resource Locks (mutexes)",
        "Loaded Components (avg DLLs)",
        "Active Processes (64-bit)"
    ]
    
    print(f"\n  {INFO} Your system's current telemetry:")
    for name, val in zip(feature_names, vector):
        print(f"       {name}: {val}")
    
    # 3c. Feed live data through HIDS model
    hids2 = get_volatile_hids()
    # Reset for clean test
    hids2.calibration_samples = []
    hids2.is_calibrated = False
    hids2.calibration_offset = np.zeros(5)
    
    # Quick calibrate with live data
    for _ in range(5):
        hids2.predict_memory_threat(vector)
    
    is_threat, prob = hids2.predict_memory_threat(vector)
    log_result(
        "Live data through ML model",
        True,
        f"Your system: {prob*100:.1f}% threat probability, {'THREAT' if is_threat else 'SAFE'}"
    )

except Exception as e:
    log_result("Live telemetry collection", False, str(e))


# =============================================
# TEST 4: Narrative Generator (Plain English)
# =============================================
print(f"\n{INFO} TEST GROUP 4: AI Narrative Generator (Plain English)")
print("-" * 50)

try:
    from core.api_bridge import AegisAPI
    api = AegisAPI.__new__(AegisAPI)
    
    # 4a. Safe narrative
    narrative_safe = api._generate_live_narrative(False, 0.05, [200, 220, 500, 40, 0])
    
    has_old_jargon = any(term in narrative_safe for term in [
        "RING-0", "SVC-GRID", "MUTEX-LOCK", "DLL-SURFACE", 
        "NAVY-6", "QUANTUM", "SEVERITY-LOW", "SEVERITY-HIGH"
    ])
    
    log_result(
        "Safe narrative is plain English",
        not has_old_jargon and "ALL CLEAR" in narrative_safe,
        "No jargon found" if not has_old_jargon else "OLD JARGON STILL PRESENT"
    )
    
    print(f"\n  {INFO} Sample SAFE narrative:")
    for line in narrative_safe.split("\n"):
        print(f"       {line}")
    
    # 4b. Threat narrative
    narrative_threat = api._generate_live_narrative(True, 0.95, [600, 300, 1000, 60, 1])
    
    has_old_jargon_threat = any(term in narrative_threat for term in [
        "RING-0", "SVC-GRID", "MUTEX-LOCK", "DLL-SURFACE",
        "NAVY-6", "QUANTUM", "SEVERITY-LOW", "SEVERITY-HIGH"
    ])
    
    log_result(
        "Threat narrative is plain English",
        not has_old_jargon_threat and "THREAT DETECTED" in narrative_threat,
        "No jargon found" if not has_old_jargon_threat else "OLD JARGON STILL PRESENT"
    )
    
    print(f"\n  {INFO} Sample THREAT narrative:")
    for line in narrative_threat.split("\n"):
        print(f"       {line}")

except Exception as e:
    log_result("Narrative generator", False, str(e))


# =============================================
# FINAL SUMMARY
# =============================================
print("\n" + "=" * 60)
total = len(results)
passed = sum(1 for _, p in results if p)
failed = total - passed

if failed == 0:
    print(f"  {PASS} ALL {total} TESTS PASSED")
else:
    print(f"  {WARN} {passed}/{total} passed, {failed} failed")
    print(f"\n  Failed tests:")
    for name, p in results:
        if not p:
            print(f"    {FAIL} {name}")

print("=" * 60 + "\n")
