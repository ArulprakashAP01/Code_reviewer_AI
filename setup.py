#!/usr/bin/env python3
"""
Setup Script for Security Code Reviewer AI
Helps users quickly configure and test the GitHub App
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_security_tools():
    """Check which security tools are available"""
    print("🔍 Checking security tools availability...")
    
    tools = {
        'bandit': 'pip install bandit',
        'eslint': 'npm install -g eslint',
        'gosec': 'go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest',
        'semgrep': 'pip install semgrep'
    }
    
    available_tools = []
    missing_tools = []
    
    for tool, install_cmd in tools.items():
        try:
            if tool == 'bandit':
                result = subprocess.run(['bandit', '--version'], capture_output=True, text=True, timeout=5)
            elif tool == 'eslint':
                result = subprocess.run(['npx', 'eslint', '--version'], capture_output=True, text=True, timeout=5)
            elif tool == 'gosec':
                result = subprocess.run(['gosec', '--version'], capture_output=True, text=True, timeout=5)
            elif tool == 'semgrep':
                result = subprocess.run(['semgrep', '--version'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                print(f"✅ {tool.upper()} is available")
                available_tools.append(tool)
            else:
                print(f"❌ {tool.upper()} not found")
                missing_tools.append((tool, install_cmd))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"❌ {tool.upper()} not found")
            missing_tools.append((tool, install_cmd))
    
    if missing_tools:
        print(f"\n⚠️ Missing security tools:")
        for tool, install_cmd in missing_tools:
            print(f"  {tool}: {install_cmd}")
        print("\nNote: The app will work without these tools, but with reduced security coverage.")
    
    return available_tools, missing_tools

def create_env_file():
    """Create .env file template"""
    env_file = Path('.env')
    if env_file.exists():
        print("✅ .env file already exists")
        return True
    
    print("📝 Creating .env file template...")
    env_content = """# GitHub App Configuration
# Replace with your actual values

# Your GitHub App ID
GITHUB_APP_ID=your_app_id_here

# Your GitHub App webhook secret
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here

# Optional: Override default values
# GITHUB_APP_ID=1513443
# GITHUB_WEBHOOK_SECRET=arulprakash01
"""
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created successfully")
        print("⚠️ Please update .env with your actual GitHub App credentials")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False

def create_logs_directory():
    """Create logs directory"""
    logs_dir = Path('logs')
    if not logs_dir.exists():
        print("📁 Creating logs directory...")
        logs_dir.mkdir()
        print("✅ Logs directory created")
    else:
        print("✅ Logs directory already exists")

def test_application():
    """Test the application"""
    print("🧪 Testing application...")
    
    try:
        # Test import
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
    """Run the demo if requested"""
    response = input("\n🎯 Would you like to run the demo? (y/n): ").lower().strip()
    if response in ['y', 'yes']:
        print("\n🚀 Running demo...")
        try:
            subprocess.run([sys.executable, "demo_enhanced.py"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Demo failed: {e}")
        except KeyboardInterrupt:
            print("\n⏹️ Demo interrupted by user")

def show_next_steps():
    """Show next steps for setup"""
    print("\n📋 Next Steps:")
    print("=" * 50)
    print("1. 📝 Update .env file with your GitHub App credentials")
    print("2. 🌐 Create a GitHub App in your GitHub account")
    print("3. 🔗 Set webhook URL to your ngrok URL")
    print("4. 🔧 Configure app permissions (Contents: Read, Issues: Write, PRs: Write)")
    print("5. 📡 Subscribe to events (Pull requests, Installation)")
    print("6. 🚀 Run the application: python app.py")
    print("7. 🌍 Start ngrok: ngrok http 5000")
    print("8. 📱 Install the app on your repositories")
    print("\n📚 For detailed instructions, see README.md")
    print("🔍 For monitoring logs, use: python log_viewer.py --all")

def main():
    """Main setup function"""
    print("🔒 Security Code Reviewer AI - Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Check security tools
    available_tools, missing_tools = check_security_tools()
    
    # Create .env file
    if not create_env_file():
        return False
    
    # Create logs directory
    create_logs_directory()
    
    # Test application
    if not test_application():
        return False
    
    print(f"\n✅ Setup completed successfully!")
    print(f"📊 Available security tools: {len(available_tools)}/{len(available_tools) + len(missing_tools)}")
    
    # Show next steps
    show_next_steps()
    
    # Offer to run demo
    run_demo()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🎉 Setup completed! Your Security Code Reviewer AI is ready to use!")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️ Setup interrupted by user")
        sys.exit(1) 