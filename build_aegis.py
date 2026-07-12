#!/usr/bin/env python3
"""
Automated PyInstaller Build Script for AEGIS (v2.0.0)
Compiles the Python engine and built React 19 UI into a single standalone Windows executable (AEGIS.exe).
"""

import os
import sys
import shutil
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "UI", "frontend")
DIST_UI_INDEX = os.path.join(FRONTEND_DIR, "dist", "index.html")


def ensure_frontend_build():
    """Build the React frontend if dist/index.html is missing."""
    if not os.path.exists(DIST_UI_INDEX):
        print("[+] React UI build not found. Compiling frontend...")
        cmd = f'cd /d "{FRONTEND_DIR}" && npm install && npm run build'
        subprocess.run(cmd, shell=True, check=True)
    else:
        print(f"[+] React UI build found at: {DIST_UI_INDEX}")


def build_aegis_exe():
    """Run PyInstaller to create standalone AEGIS.exe."""
    print("=" * 60)
    print("Building Standalone AEGIS Executable (v2.0.0)")
    print("=" * 60)

    ensure_frontend_build()

    # Clean prior PyInstaller build artifacts
    for folder in ("build", "dist"):
        folder_path = os.path.join(PROJECT_ROOT, folder)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)

    pyinstaller_cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=AEGIS",
        "--onefile",
        "--windowed",
        "--add-data=UI/frontend/dist;UI/frontend/dist",
        "--add-data=core/rules;core/rules",
        "--hidden-import=webview",
        "--hidden-import=scapy",
        "--hidden-import=PIL",
        "--hidden-import=pytesseract",
        "--hidden-import=win10toast",
        "--hidden-import=psutil",
        "--hidden-import=cryptography",
        "--hidden-import=dotenv",
        "--hidden-import=requests",
        "--hidden-import=urllib3",
        "--hidden-import=core.api_bridge",
        "--hidden-import=core.network.nids_engine",
        "--hidden-import=core.sift_engine",
        "--hidden-import=ai.nlp_model",
        "--hidden-import=core.realtime_protection",
        "main_aegis.py",
    ]

    print("\n[+] Running PyInstaller packaging...")
    result = subprocess.run(pyinstaller_cmd, cwd=PROJECT_ROOT)

    if result.returncode == 0:
        exe_path = os.path.join(PROJECT_ROOT, "dist", "AEGIS.exe")
        print("\n" + "=" * 60)
        print("BUILD SUCCESSFUL!")
        print("=" * 60)
        print(f"Standalone executable created at:\n  {exe_path}")
        print("=" * 60)
        return True
    else:
        print("\n[-] Build failed.")
        return False


if __name__ == "__main__":
    success = build_aegis_exe()
    sys.exit(0 if success else 1)
