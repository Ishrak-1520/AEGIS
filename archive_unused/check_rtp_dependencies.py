"""
Installation Helper for Real-Time Protection
Checks for required dependencies and provides installation guidance
"""

import sys
import os


def check_pil():
    """Check if Pillow (PIL) is installed"""
    try:
        from PIL import Image, ImageGrab
        print("✓ Pillow (PIL) is installed")
        return True
    except ImportError:
        print("✗ Pillow (PIL) is NOT installed")
        print("  Install with: pip install Pillow>=10.0.0")
        return False


def check_pytesseract():
    """Check if pytesseract is installed"""
    try:
        import pytesseract
        print("✓ pytesseract is installed")
        return True
    except ImportError:
        print("✗ pytesseract is NOT installed")
        print("  Install with: pip install pytesseract>=0.3.10")
        return False


def check_tesseract_ocr():
    """Check if Tesseract OCR system package is installed"""
    try:
        import pytesseract
        import platform
        import os
        
        # Configure Tesseract path for Windows
        if platform.system() == 'Windows':
            tesseract_paths = [
                r'C:\Program Files\Tesseract-OCR\tesseract.exe',
                r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
                r'C:\Tesseract-OCR\tesseract.exe'
            ]
            for path in tesseract_paths:
                if os.path.exists(path):
                    pytesseract.pytesseract.tesseract_cmd = path
                    break
        
        version = pytesseract.get_tesseract_version()
        print(f"✓ Tesseract OCR is installed (version {version})")
        return True
    except Exception as e:
        print("✗ Tesseract OCR is NOT installed or not found")
        print()
        print("  Windows Installation:")
        print("  1. Download from: https://github.com/UB-Mannheim/tesseract/wiki")
        print("  2. Run installer: tesseract-ocr-w64-setup-5.3.3.exe")
        print("  3. Default path: C:\\Program Files\\Tesseract-OCR\\")
        print()
        print("  Linux Installation:")
        print("  sudo apt-get install tesseract-ocr")
        print()
        print("  macOS Installation:")
        print("  brew install tesseract")
        print()
        print(f"  Error: {e}")
        return False


def check_nlp_model():
    """Check if NLP model is available"""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ai.nlp_model import get_nlp_detector
        detector = get_nlp_detector()
        print("✓ NLP Threat Detection module is available")
        return True
    except Exception as e:
        print("✗ NLP Threat Detection module is NOT available")
        print(f"  Error: {e}")
        return False


def test_realtime_protection():
    """Test if Real-Time Protection can be initialized"""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from core.realtime_protection import realtime_protection
        print("✓ Real-Time Protection module loaded successfully")
        
        # Show current configuration
        stats = realtime_protection.get_statistics()
        print(f"  Scan Interval: {stats['scan_interval']} seconds")
        print(f"  Threat Sensitivity: {stats['threat_sensitivity']}")
        
        return True
    except Exception as e:
        print("✗ Real-Time Protection module failed to load")
        print(f"  Error: {e}")
        return False


def main():
    """Main installation check"""
    print("=" * 70)
    print("CyberGuard Pro - Real-Time Protection Installation Checker")
    print("=" * 70)
    print()
    
    results = []
    
    print("Checking Python Dependencies...")
    print("-" * 70)
    results.append(("Pillow (PIL)", check_pil()))
    results.append(("pytesseract", check_pytesseract()))
    print()
    
    print("Checking System Dependencies...")
    print("-" * 70)
    results.append(("Tesseract OCR", check_tesseract_ocr()))
    print()
    
    print("Checking CyberGuard Pro Modules...")
    print("-" * 70)
    results.append(("NLP Threat Detection", check_nlp_model()))
    results.append(("Real-Time Protection", test_realtime_protection()))
    print()
    
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    
    all_passed = True
    for name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{name:.<50} {status}")
        if not passed:
            all_passed = False
    
    print()
    
    if all_passed:
        print("🎉 All checks passed! Real-Time Protection is ready to use.")
        print()
        print("To start using:")
        print("1. Run: python main.py")
        print("2. Log into CyberGuard Pro")
        print("3. Go to Overview tab")
        print("4. Click 'Start Real-Time Protection'")
    else:
        print("⚠️  Some checks failed. Please install missing dependencies.")
        print()
        print("Quick Install (Windows):")
        print("  pip install Pillow pytesseract")
        print("  Then download and install Tesseract OCR:")
        print("  https://github.com/UB-Mannheim/tesseract/wiki")
    
    print()
    print("=" * 70)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
