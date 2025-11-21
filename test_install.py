"""
Simple Installation Verification Test
Run this to verify CyberGuard Pro is properly set up
"""

import sys
import os

print("=" * 60)
print("CyberGuard Pro - Installation Verification")
print("=" * 60)

# Test 1: Python Version
print("\n1. Checking Python version...")
version = sys.version_info
print(f"   Python {version.major}.{version.minor}.{version.micro}")
if version.major >= 3 and version.minor >= 8:
    print("   ✅ PASS - Python version is compatible")
else:
    print("   ❌ FAIL - Python 3.8+ required")
    sys.exit(1)

# Test 2: Core Modules
print("\n2. Testing core module imports...")
modules = {
    'Database': 'database.db_manager',
    'Encryption': 'security.encryption',
    'Scanner': 'core.scanner',
    'Monitor': 'core.monitor',
    'NLP': 'ai.nlp_model'
}

all_ok = True
for name, module in modules.items():
    try:
        __import__(module)
        print(f"   ✅ {name}")
    except ImportError as e:
        print(f"   ❌ {name} - {e}")
        all_ok = False

if not all_ok:
    print("\n   ⚠️  Some modules failed to import")
    print("   This is normal if dependencies aren't installed yet")
    print("   Run: python setup.py")

# Test 3: File Structure
print("\n3. Checking file structure...")
required_files = [
    'main.py',
    'setup.py',
    'requirements.txt',
    'README.md'
]

for filename in required_files:
    if os.path.exists(filename):
        print(f"   ✅ {filename}")
    else:
        print(f"   ❌ {filename}")

# Test 4: Directories
print("\n4. Checking directories...")
required_dirs = ['gui', 'core', 'ai', 'security', 'database', 'tests']

for dirname in required_dirs:
    if os.path.isdir(dirname):
        print(f"   ✅ {dirname}/")
    else:
        print(f"   ❌ {dirname}/")

# Summary
print("\n" + "=" * 60)
if all_ok:
    print("✅ Installation verification PASSED")
    print("\nReady to run: python main.py")
else:
    print("⚠️  Installation incomplete")
    print("\nNext steps:")
    print("1. Install dependencies: python setup.py")
    print("2. Or manually: pip install -r requirements.txt")
    print("3. Then run: python main.py")
print("=" * 60)
