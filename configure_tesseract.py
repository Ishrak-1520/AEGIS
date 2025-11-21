"""
Tesseract OCR Configuration Helper
Automatically detects and configures Tesseract OCR path for Windows
"""

import os
import sys
import platform


def find_tesseract_windows():
    """Find Tesseract OCR installation on Windows"""
    common_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        r"C:\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Tesseract-OCR\tesseract.exe"),
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None


def configure_tesseract():
    """Configure Tesseract OCR path"""
    if platform.system() != 'Windows':
        print("Tesseract configuration only needed for Windows.")
        print("On Linux/macOS, Tesseract should be in PATH after installation.")
        return None
    
    print("Searching for Tesseract OCR installation...")
    
    tesseract_path = find_tesseract_windows()
    
    if tesseract_path:
        print(f"✓ Found Tesseract at: {tesseract_path}")
        
        # Update realtime_protection.py
        rtp_file = os.path.join(os.path.dirname(__file__), 'core', 'realtime_protection.py')
        
        if os.path.exists(rtp_file):
            with open(rtp_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if already configured
            if 'pytesseract.pytesseract.tesseract_cmd' in content:
                print("✓ Tesseract path already configured in realtime_protection.py")
            else:
                # Add configuration after imports
                config_line = f"\n# Tesseract OCR path configuration (Windows)\nimport pytesseract\npytesseract.pytesseract.tesseract_cmd = r'{tesseract_path}'\n\n"
                
                # Find where to insert (after imports)
                insert_pos = content.find('sys.path.append(')
                if insert_pos != -1:
                    # Insert before sys.path.append
                    content = content[:insert_pos] + config_line + content[insert_pos:]
                    
                    with open(rtp_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print("✓ Tesseract path configured in realtime_protection.py")
                else:
                    print("⚠️  Could not auto-configure. Please add manually:")
                    print(f"   pytesseract.pytesseract.tesseract_cmd = r'{tesseract_path}'")
        
        return tesseract_path
    else:
        print("✗ Tesseract OCR not found in common locations.")
        print()
        print("Please install Tesseract OCR:")
        print("1. Download from: https://github.com/UB-Mannheim/tesseract/wiki")
        print("2. Run installer: tesseract-ocr-w64-setup-5.3.3.exe")
        print("3. Run this script again")
        print()
        print("Or manually configure the path in core/realtime_protection.py:")
        print("  pytesseract.pytesseract.tesseract_cmd = r'C:\\Path\\To\\tesseract.exe'")
        
        return None


def test_tesseract():
    """Test if Tesseract is working"""
    try:
        import pytesseract
        from PIL import Image
        
        version = pytesseract.get_tesseract_version()
        print(f"\n✓ Tesseract is working! Version: {version}")
        return True
    except Exception as e:
        print(f"\n✗ Tesseract test failed: {e}")
        return False


def main():
    print("=" * 70)
    print("Tesseract OCR Configuration Helper")
    print("=" * 70)
    print()
    
    tesseract_path = configure_tesseract()
    
    if tesseract_path:
        print()
        print("Testing Tesseract OCR...")
        test_tesseract()
        
        print()
        print("=" * 70)
        print("Configuration complete!")
        print("=" * 70)
        print()
        print("You can now use Real-Time Protection:")
        print("1. Run: python main.py")
        print("2. Go to Overview tab")
        print("3. Click 'Start Real-Time Protection'")
    else:
        print()
        print("=" * 70)
        print("Configuration incomplete")
        print("=" * 70)
        print("Please install Tesseract OCR and run this script again.")
    
    print()


if __name__ == '__main__':
    main()
