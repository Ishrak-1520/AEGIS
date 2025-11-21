import sys
import os
import platform

print(f"Python Executable: {sys.executable}")
print(f"Working Directory: {os.getcwd()}")

try:
    import pytesseract
    # Set path explicitly for testing
    tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    if os.path.exists(tesseract_path):
        pytesseract.tesseract_cmd = tesseract_path
        print(f"Set tesseract_cmd to: {tesseract_path}")
    
    print(f"pytesseract imported successfully. Version: {pytesseract.get_tesseract_version()}")
except ImportError as e:
    print(f"Failed to import pytesseract: {e}")
except Exception as e:
    print(f"Error using pytesseract: {e}")

# Check paths
tesseract_paths = [
    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
    r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
    r'C:\Tesseract-OCR\tesseract.exe'
]

print("\nChecking Tesseract Paths:")
for path in tesseract_paths:
    exists = os.path.exists(path)
    print(f"  {path}: {'FOUND' if exists else 'NOT FOUND'}")

# Check PATH
print("\nChecking PATH for tesseract:")
import shutil
tess_in_path = shutil.which("tesseract")
print(f"  tesseract in PATH: {tess_in_path}")

print("\nTesting subprocess execution:")
import subprocess
tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.path.exists(tesseract_path):
    try:
        result = subprocess.run([tesseract_path, '--version'], capture_output=True, text=True)
        print(f"  Subprocess return code: {result.returncode}")
        print(f"  Subprocess stdout: {result.stdout.strip()}")
        print(f"  Subprocess stderr: {result.stderr.strip()}")
    except Exception as e:
        print(f"  Subprocess failed: {e}")
else:
    print("  Tesseract executable not found for subprocess test.")
