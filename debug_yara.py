import sys
print(f"Python executable: {sys.executable}")
print(f"Python path: {sys.path}")
try:
    import yara
    print("YARA imported successfully")
    print(f"YARA version: {yara.__version__}")
except ImportError as e:
    print(f"Failed to import YARA: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
