"""
Setup and Installation Script for CyberGuard Pro
Automates dependency installation and initial configuration
"""

import os
import sys
import subprocess


def print_header(message):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {message}")
    print("=" * 70 + "\n")


def check_python_version():
    """Check if Python version is compatible"""
    print_header("Checking Python Version")
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ ERROR: Python 3.8 or higher is required")
        print("   Please upgrade Python and try again")
        return False
    
    print("✅ Python version is compatible")
    return True


def install_dependencies():
    """Install required Python packages"""
    print_header("Installing Dependencies")
    
    try:
        print("Installing packages from requirements.txt...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("\n✅ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("\n❌ Error installing dependencies")
        print("   Try running manually: pip install -r requirements.txt")
        return False


def download_nlp_model():
    """Download spaCy NLP model"""
    print_header("Downloading NLP Model (Optional)")
    
    response = input("Download spaCy NLP model? (y/n): ").strip().lower()
    
    if response == 'y':
        try:
            print("Downloading en_core_web_sm model...")
            subprocess.check_call([
                sys.executable, "-m", "spacy", "download", "en_core_web_sm"
            ])
            print("\n✅ NLP model downloaded successfully")
            return True
        except subprocess.CalledProcessError:
            print("\n⚠️ Could not download NLP model")
            print("   The system will use keyword-based detection as fallback")
            return False
    else:
        print("⏭️  Skipping NLP model download")
        print("   Keyword-based detection will be used")
        return True


def create_sample_data():
    """Create sample dataset and signatures"""
    print_header("Creating Sample Data")
    
    try:
        # Run training script to create sample data
        from ai.train_nlp import save_sample_dataset
        save_sample_dataset()
        print("✅ Sample phishing dataset created")
        return True
    except Exception as e:
        print(f"⚠️ Error creating sample data: {e}")
        print("   This is optional and won't affect core functionality")
        return True


def verify_installation():
    """Verify installation by importing key modules"""
    print_header("Verifying Installation")
    
    modules_to_check = [
        ('PyQt5', 'PyQt5.QtWidgets'),
        ('psutil', 'psutil'),
        ('cryptography', 'cryptography.fernet'),
        ('transformers', 'transformers'),
        ('torch', 'torch'),
    ]
    
    all_ok = True
    
    for name, module_path in modules_to_check:
        try:
            __import__(module_path)
            print(f"✅ {name} - OK")
        except ImportError:
            print(f"❌ {name} - NOT FOUND")
            all_ok = False
    
    return all_ok


def setup_database():
    """Initialize database"""
    print_header("Initializing Database")
    
    try:
        from database.db_manager import db_manager
        print("✅ Database initialized successfully")
        print(f"   Location: {db_manager.db_path}")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        return False


def display_next_steps():
    """Display next steps for the user"""
    print_header("Installation Complete!")
    
    print("""
🎉 CyberGuard Pro is ready to use!

📝 Next Steps:

1. Start the application:
   
   python main.py

2. Create your master account:
   - Click "Create Account"
   - Use a strong password (12+ characters)
   - Include uppercase, lowercase, digits, and symbols

3. Explore features:
   - Run a quick scan
   - Test the NLP threat analyzer
   - Store passwords in the vault
   - Monitor system resources

📚 Documentation:
   - README.md - Complete user guide
   - SRS Documentation.md - Technical specifications
   - Module docstrings - API documentation

🔒 Security Tips:
   - Never share your master password
   - Regular backups of cyberguard.db
   - Keep the application updated
   - Review logs periodically

💡 Need Help?
   - Check README.md for troubleshooting
   - Review test files for usage examples
   - Examine module docstrings for API details

Enjoy using CyberGuard Pro! 🛡️
    """)


def main():
    """Main setup function"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║            🛡️  CyberGuard Pro - Setup & Installation           ║
║                                                                  ║
║          AI-Powered Autonomous Cyber Defense System              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Step 1: Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Step 2: Install dependencies
    if not install_dependencies():
        print("\n⚠️  Installation incomplete. Please fix errors and try again.")
        sys.exit(1)
    
    # Step 3: Download NLP model (optional)
    download_nlp_model()
    
    # Step 4: Create sample data
    create_sample_data()
    
    # Step 5: Verify installation
    if not verify_installation():
        print("\n⚠️  Some packages are missing. Try running:")
        print("     pip install -r requirements.txt")
    
    # Step 6: Initialize database
    setup_database()
    
    # Step 7: Display next steps
    display_next_steps()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Setup failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
