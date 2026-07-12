"""
Build Script for CyberGuard Pro
Creates executable file using PyInstaller
"""

import os
import sys
import subprocess
import shutil

def clean_build_dirs():
    """Remove previous build directories"""
    dirs_to_clean = ['build', 'dist', '__pycache__']
    
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            print(f"Cleaning {dir_name}...")
            shutil.rmtree(dir_name, ignore_errors=True)
    
    # Remove spec file if exists
    if os.path.exists('CyberGuardPro.spec'):
        os.remove('CyberGuardPro.spec')

def build_exe():
    """Build executable using PyInstaller"""
    print("=" * 60)
    print("Building CyberGuard Pro Executable")
    print("=" * 60)
    
    # Clean previous builds
    clean_build_dirs()
    
    # PyInstaller command with options
    cmd = [
        'python',
        '-m',
        'PyInstaller',
        '--name=CyberGuardPro',
        '--onefile',  # Single executable file
        '--windowed',  # No console window (GUI mode)
        '--icon=NONE',  # No icon for now
        '--add-data=database/schema.sql;database',  # Include schema
        '--exclude-module=tensorflow',  # Exclude heavy ML libs
        '--exclude-module=transformers',
        '--exclude-module=nltk',
        '--exclude-module=spacy',
        '--exclude-module=torch',
        '--hidden-import=PyQt5.QtCore',
        '--hidden-import=PyQt5.QtGui',
        '--hidden-import=PyQt5.QtWidgets',
        '--hidden-import=cryptography',
        '--hidden-import=psutil',
        'main.py'
    ]
    
    print("\nRunning PyInstaller...")
    print(f"Command: {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        
        print("\n" + "=" * 60)
        print("✅ Build Successful!")
        print("=" * 60)
        print(f"\nExecutable location: dist\\CyberGuardPro.exe")
        print("\nYou can now run the application by double-clicking:")
        print("  dist\\CyberGuardPro.exe")
        print("\nNote: First run may take longer as it extracts files.")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print("\n" + "=" * 60)
        print("❌ Build Failed!")
        print("=" * 60)
        print(f"\nError: {e}")
        return False

if __name__ == '__main__':
    success = build_exe()
    sys.exit(0 if success else 1)
