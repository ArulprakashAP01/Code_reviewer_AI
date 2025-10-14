sd#!/usr/bin/env python3
"""
Quick Start Script for Security Code Reviewer AI
Automates the complete setup process and provides interactive guidance
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path

def print_banner():
    """Print the application banner"""
    print("🔒" + "="*60 + "🔒")
    print("           Security Code Reviewer AI - Quick Start")
    print("🔒" + "="*60 + "🔒")
    print()

def check_python_version():
    """Check Python version compatibility"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected")
    return True

def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True, text=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("   Try running: pip install -r requirements.txt manually")
        return False

def check_security_tools():
    """Check and install security tools"""
    print("\n🔍 Checking security tools...")
    
    tools = {
        'bandit': {
            'check_cmd': ['bandit', '--version'],
            'install_cmd': [sys.executable, '-m', 'pip', 'install', 'bandit'],
            'description': 'Python security linter'
        },
        'eslint': {
            'check_cmd': ['npx', 'eslint', '--version'],
            'install_cmd': ['npm', 'install', '-g', 'eslint'],
            'description': 'JavaScript/TypeScript linter'
        },
        'gosec': {
            'check_cmd': ['gosec', '--version'],
            'install_cmd': ['go', 'install', 'github.com/securecodewarrior/gosec/v2/cmd/gosec@latest'],
            'description': 'Go security scanner'
        },
        'semgrep': {
            'check_cmd': ['semgrep', '--version'],
            'install_cmd': [sys.executable, '-m', 'pip', 'install', 'semgrep'],
            'description': 'Multi-language security scanner'
        }
    }
    
    available_tools = []
    missing_tools = []
    
    for tool_name, tool_info in tools.items():
        print(f"   Checking {tool_name}...", end=" ")
        try:
            result = subprocess.run(tool_info['check_cmd'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Available")
                available_tools.append(tool_name)
            else:
                print("❌ Not found")
                missing_tools.append((tool_name, tool_info))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("❌ Not found")
            missing_tools.append((tool_name, tool_info))
    
    if missing_tools:
        print(f"\n⚠️ Missing security tools ({len(missing_tools)}):")
        for tool_name, tool_info in missing_tools:
            print(f"   - {tool_name}: {tool_info['description']}")
        
        install_missing = input("\n🤔 Would you like to install missing tools? (y/n): ").lower().strip()
        if install_missing in ['y', 'yes']:
            for tool_name, tool_info in missing_tools:
                print(f"\n📦 Installing {tool_name}...")
                try:
                    subprocess.run(tool_info['install_cmd'], check=True, capture_output=True, text=True)
                    print(f"✅ {tool_name} installed successfully")
                    available_tools.append(tool_name)
                except subprocess.CalledProcessError as e:
                    print(f"❌ Failed to install {tool_name}: {e}")
                    print(f"   Try installing manually: {' '.join(tool_info['install_cmd'])}")
    
    print(f"\n📊 Security tools summary: {len(available_tools)}/{len(tools)} available")
    return available_tools

def create_env_file():
    """Create .env file with user input"""
    env_file = Path('.env')
    if env_file.exists():
        print("\n✅ .env file already exists")
        return True
    
    print("\n📝 Creating .env file...")
    print("   You'll need your GitHub App credentials.")
    print("   If you don't have them yet, you can create them later.")
    
    app_id = input("   GitHub App ID (or press Enter to skip): ").strip()
    webhook_secret = input("   GitHub Webhook Secret (or press Enter to skip): ").strip()
    
    env_content = f"""# GitHub App Configuration
# Replace with your actual values

# Your GitHub App ID
GITHUB_APP_ID={app_id or 'your_app_id_here'}

# Your GitHub App webhook secret
GITHUB_WEBHOOK_SECRET={webhook_secret or 'your_webhook_secret_here'}

# Optional: Override default values
# GITHUB_APP_ID=1513443
# GITHUB_WEBHOOK_SECRET=arulprakash01
"""
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully")
        if not app_id or not webhook_secret:
            print("⚠️ Please update .env with your actual GitHub App credentials later")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False

def test_application():
    """Test the application"""
    print("\n🧪 Testing application...")
    try:
        # Test imports
        from app import SecurityScanner, GitHubIssueReporter
        print("✅ Application imports successfully")
        
        # Test scanner initialization
        scanner = SecurityScanner()
        print("✅ Security scanner initialized")
        
        # Test logging setup
        from logging_config import setup_logging
        setup_logging()
        print("✅ Logging system initialized")
        
        return True
    except Exception as e:
        print(f"❌ Application test failed: {e}")
        return False

def run_demo():
    """Run the demo"""
    print("\n🎯 Running demo...")
    try:
        subprocess.run([sys.executable, "demo_enhanced.py"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Demo failed: {e}")
        return False
    except KeyboardInterrupt:
        print("\n⏹️ Demo interrupted by user")
        return False

def show_github_app_instructions():
    """Show GitHub App setup instructions"""
    print("\n📋 GitHub App Setup Instructions")
    print("=" * 50)
    print("1. Go to https://github.com/settings/apps")
    print("2. Click 'New GitHub App'")
    print("3. Fill in the basic information:")
    print("   - App name: Security Code Reviewer AI")
    print("   - Homepage URL: https://github.com/your-username/security-code-reviewer")
    print("   - Webhook URL: https://your-ngrok-url.ngrok.io/webhook")
    print("   - Webhook secret: (generate a secure secret)")
    print("4. Set permissions:")
    print("   - Repository permissions:")
    print("     * Contents: Read")
    print("     * Issues: Write")
    print("     * Pull requests: Write")
    print("5. Subscribe to events:")
    print("   - Pull requests")
    print("   - Installation")
    print("6. Create the app and note the App ID")
    print("7. Generate a private key and save it")
    print("8. Update your .env file with the credentials")
    print()

def show_next_steps():
    """Show next steps"""
    print("\n📋 Next Steps")
    print("=" * 50)
    print("1. 📝 Update .env file with your GitHub App credentials")
    print("2. 🌐 Create a GitHub App (see instructions above)")
    print("3. 🔗 Set webhook URL to your ngrok URL")
    print("4. 🚀 Run the application: python app.py")
    print("5. 🌍 Start ngrok: ngrok http 5000")
    print("6. 📱 Install the app on your repositories")
    print("\n📚 For detailed instructions, see README.md")
    print("🔍 For monitoring logs, use: python log_viewer.py --all")

def main():
    """Main quick start function"""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Check security tools
    available_tools = check_security_tools()
    
    # Create .env file
    if not create_env_file():
        return False
    
    # Test application
    if not test_application():
        return False
    
    print(f"\n✅ Setup completed successfully!")
    print(f"📊 Available security tools: {len(available_tools)}")
    
    # Show GitHub App instructions
    show_github_app_instructions()
    
    # Show next steps
    show_next_steps()
    
    # Offer to run demo
    run_demo_choice = input("\n🎯 Would you like to run the demo? (y/n): ").lower().strip()
    if run_demo_choice in ['y', 'yes']:
        run_demo()
    
    print(f"\n🎉 Quick start completed!")
    print(f"🚀 You're ready to use Security Code Reviewer AI!")
    
    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Setup interrupted by user")
        print("You can run this script again anytime to continue setup")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("Please check the error and try again") 
