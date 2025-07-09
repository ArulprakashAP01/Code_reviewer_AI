#!/usr/bin/env python3
"""
Test script to verify the Security Code Reviewer AI setup
"""

import subprocess
import sys
import json
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and return success status"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"✅ {description}")
            return True
        else:
            print(f"❌ {description}")
            print(f"   Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"⏰ {description} - Timeout")
        return False
    except FileNotFoundError:
        print(f"❌ {description} - Command not found")
        return False
    except Exception as e:
        print(f"❌ {description} - {str(e)}")
        return False

def test_python_dependencies():
    """Test Python dependencies"""
    print("\n🐍 Testing Python Dependencies:")
    
    dependencies = [
        ("flask", "Flask"),
        ("flask_githubapp", "Flask-GitHubApp"),
        ("github", "PyGithub"),
        ("bandit", "Bandit"),
        ("dotenv", "python-dotenv"),
        ("semgrep", "Semgrep"),
        ("requests", "Requests")
    ]
    
    all_good = True
    for module, name in dependencies:
        try:
            __import__(module)
            print(f"✅ {name}")
        except ImportError:
            print(f"❌ {name} - Not installed")
            all_good = False
    
    return all_good

def test_security_tools():
    """Test security scanning tools"""
    print("\n🔒 Testing Security Tools:")
    
    tools = [
        (["bandit", "--version"], "Bandit (Python security linter)"),
        (["npx", "eslint", "--version"], "ESLint (JavaScript linter)"),
        (["gosec", "--version"], "gosec (Go security scanner)"),
        (["semgrep", "--version"], "Semgrep (Multi-language scanner)")
    ]
    
    all_good = True
    for command, description in tools:
        if not run_command(command, description):
            all_good = False
    
    return all_good

def test_system_tools():
    """Test system tools"""
    print("\n🛠️ Testing System Tools:")
    
    tools = [
        (["git", "--version"], "Git"),
        (["curl", "--version"], "cURL"),
        (["python", "--version"], "Python 3.x")
    ]
    
    all_good = True
    for command, description in tools:
        if not run_command(command, description):
            all_good = False
    
    return all_good

def test_configuration():
    """Test configuration files"""
    print("\n⚙️ Testing Configuration:")
    
    config_files = [
        ("app.py", "Main application"),
        ("config.py", "Configuration settings"),
        ("custom_rules.json", "Custom security rules"),
        ("requirements.txt", "Python dependencies")
    ]
    
    all_good = True
    for filename, description in config_files:
        if Path(filename).exists():
            print(f"✅ {description} ({filename})")
        else:
            print(f"❌ {description} ({filename}) - File not found")
            all_good = False
    
    return all_good

def test_environment():
    """Test environment variables"""
    print("\n🌍 Testing Environment:")
    
    env_vars = [
        ("GITHUB_WEBHOOK_SECRET", "GitHub Webhook Secret"),
        ("GITHUB_APP_ID", "GitHub App ID")
    ]
    
    all_good = True
    for var, description in env_vars:
        value = os.getenv(var)
        if value:
            print(f"✅ {description} (set)")
        else:
            print(f"⚠️ {description} (not set)")
            all_good = False
    
    return all_good

def test_app_functionality():
    """Test basic app functionality"""
    print("\n🧪 Testing App Functionality:")
    
    try:
        # Test importing the main app
        from app import app, SecurityScanner, GitHubIssueReporter
        print("✅ App imports successfully")
        
        # Test scanner initialization
        scanner = SecurityScanner()
        print("✅ SecurityScanner initialized")
        
        # Test configuration loading
        from config import get_all_config
        config = get_all_config()
        print("✅ Configuration loaded")
        
        return True
    except Exception as e:
        print(f"❌ App functionality test failed: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("🔒 Security Code Reviewer AI - Setup Test")
    print("=" * 50)
    
    tests = [
        ("Python Dependencies", test_python_dependencies),
        ("Security Tools", test_security_tools),
        ("System Tools", test_system_tools),
        ("Configuration", test_configuration),
        ("Environment", test_environment),
        ("App Functionality", test_app_functionality)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} - Test failed with exception: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your setup is ready.")
        return 0
    else:
        print("⚠️ Some tests failed. Please check the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 