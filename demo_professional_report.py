#!/usr/bin/env python3
"""
Demo script for Professional Security Reporting
Shows how the enhanced reporting system works
"""

import os
import sys
from datetime import datetime
from app import SecurityScanner, GitHubIssueReporter

def create_demo_vulnerabilities():
    """Create demo files with vulnerabilities for testing"""
    
    # Create a Python file with vulnerabilities
    python_code = '''#!/usr/bin/env python3
"""
Demo file with intentional vulnerabilities for testing
"""

import os
import subprocess
import sqlite3
import pickle
import base64

# HIGH SEVERITY: Command injection vulnerability
def vulnerable_function(user_input):
    # This is intentionally vulnerable
    os.system(f"echo {user_input}")  # HIGH: Command injection
    subprocess.call(f"ls {user_input}", shell=True)  # HIGH: Command injection
    
    # HIGH SEVERITY: SQL injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # HIGH: SQL injection
    
    # MEDIUM SEVERITY: Hardcoded password
    password = "admin123"  # MEDIUM: Hardcoded password
    api_key = "sk-1234567890abcdef"  # MEDIUM: Hardcoded secret
    
    # LOW SEVERITY: Weak crypto
    import hashlib
    hashed = hashlib.md5(password.encode()).hexdigest()  # LOW: Weak hash
    
    # HIGH SEVERITY: Deserialization vulnerability
    data = base64.b64decode(user_input)
    obj = pickle.loads(data)  # HIGH: Unsafe deserialization
    
    return obj

# MEDIUM SEVERITY: Debug mode in production
DEBUG = True  # MEDIUM: Debug mode enabled

if __name__ == "__main__":
    user_input = input("Enter your name: ")
    result = vulnerable_function(user_input)
    print(f"Result: {result}")
'''
    
    # Create a JavaScript file with vulnerabilities
    js_code = '''// Demo JavaScript file with vulnerabilities

// HIGH SEVERITY: XSS vulnerability
function displayUserInput(userInput) {
    // This is intentionally vulnerable
    document.getElementById('output').innerHTML = userInput; // HIGH: XSS
    eval(userInput); // HIGH: Code injection
}

// MEDIUM SEVERITY: Hardcoded credentials
const API_KEY = "sk-1234567890abcdef"; // MEDIUM: Hardcoded secret
const PASSWORD = "admin123"; // MEDIUM: Hardcoded password

// LOW SEVERITY: Weak crypto
function hashPassword(password) {
    // This is intentionally weak
    return btoa(password); // LOW: Weak encoding
}

// HIGH SEVERITY: SQL injection
function queryDatabase(userInput) {
    const query = `SELECT * FROM users WHERE name = '${userInput}'`; // HIGH: SQL injection
    return executeQuery(query);
}

// MEDIUM SEVERITY: Insecure random
function generateToken() {
    return Math.random().toString(36); // MEDIUM: Insecure random
}

// Usage
const userInput = prompt("Enter your name:");
displayUserInput(userInput);
queryDatabase(userInput);
'''
    
    # Create a Go file with vulnerabilities
    go_code = '''package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// HIGH SEVERITY: Command injection
func vulnerableFunction(userInput string) {
    // This is intentionally vulnerable
    cmd := exec.Command("echo", userInput) // HIGH: Command injection
    cmd.Run()
    
    // HIGH SEVERITY: SQL injection
    db, _ := sql.Open("sqlite3", "database.db")
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput) // HIGH: SQL injection
    db.Query(query)
}

// MEDIUM SEVERITY: Hardcoded credentials
const (
    APIKey = "sk-1234567890abcdef" // MEDIUM: Hardcoded secret
    Password = "admin123"           // MEDIUM: Hardcoded password
)

// LOW SEVERITY: Weak crypto
func hashPassword(password string) string {
    // This is intentionally weak
    return strings.ToLower(password) // LOW: Weak hashing
}

func main() {
    userInput := os.Args[1]
    vulnerableFunction(userInput)
}
'''
    
    # Write files
    with open('demo_vulnerable.py', 'w') as f:
        f.write(python_code)
    
    with open('demo_vulnerable.js', 'w') as f:
        f.write(js_code)
    
    with open('demo_vulnerable.go', 'w') as f:
        f.write(go_code)
    
    print("✅ Demo vulnerability files created:")
    print("   - demo_vulnerable.py (Python vulnerabilities)")
    print("   - demo_vulnerable.js (JavaScript vulnerabilities)")
    print("   - demo_vulnerable.go (Go vulnerabilities)")

def run_demo_scan():
    """Run a demo security scan and show results"""
    print("\n" + "="*80)
    print("🔒 PROFESSIONAL SECURITY SCAN DEMO")
    print("="*80)
    
    # Create demo files
    create_demo_vulnerabilities()
    
    # Run security scan
    print("\n🔍 Running comprehensive security scan...")
    scanner = SecurityScanner()
    scan_results = scanner.run_comprehensive_scan()
    
    # Display results
    summary = scan_results['summary']
    findings = scan_results['findings']
    
    print(f"\n📊 SCAN RESULTS SUMMARY:")
    print(f"   Total Issues: {summary['total_issues']}")
    print(f"   High Severity: {summary['high_severity']} 🔴")
    print(f"   Medium Severity: {summary['medium_severity']} 🟡")
    print(f"   Low Severity: {summary['low_severity']} 🟢")
    print(f"   Languages Scanned: {', '.join(summary['languages_scanned'])}")
    
    # Show detailed findings
    if findings:
        print(f"\n🚨 DETAILED FINDINGS:")
        for i, finding in enumerate(findings, 1):
            severity_icon = "🔴" if finding['severity'] == 'HIGH' else "🟡" if finding['severity'] == 'MEDIUM' else "🟢"
            print(f"\n   {i}. {severity_icon} {finding['severity']} - {finding['tool']}")
            print(f"      File: {finding['file']}:{finding['line']}")
            print(f"      Issue: {finding['message']}")
    
    return scan_results

def generate_demo_report(scan_results):
    """Generate a demo professional report"""
    print(f"\n📋 GENERATING PROFESSIONAL REPORT...")
    
    # Create a mock GitHub reporter for demo
    class DemoReporter:
        def _generate_issue_body(self, scan_results, pr_number=None):
            from app import GitHubIssueReporter
            # Create a mock reporter that doesn't need GitHub client
            reporter = GitHubIssueReporter.__new__(GitHubIssueReporter)
            reporter.repo_name = "demo/repo"
            return reporter._generate_issue_body(scan_results, pr_number)
    
    reporter = DemoReporter()
    report_body = reporter._generate_issue_body(scan_results, 123)
    
    # Save report to file
    with open('demo_security_report.md', 'w') as f:
        f.write(report_body)
    
    print("✅ Professional security report generated: demo_security_report.md")
    
    # Show preview
    print(f"\n📄 REPORT PREVIEW (first 20 lines):")
    print("-" * 60)
    lines = report_body.split('\n')[:20]
    for line in lines:
        print(line)
    print("...")
    print("-" * 60)
    
    return report_body

def main():
    """Main demo function"""
    print("🚀 Starting Professional Security Reporting Demo")
    print("="*80)
    
    try:
        # Run demo scan
        scan_results = run_demo_scan()
        
        # Generate professional report
        report = generate_demo_report(scan_results)
        
        print(f"\n🎉 DEMO COMPLETED SUCCESSFULLY!")
        print(f"📁 Generated files:")
        print(f"   - demo_vulnerable.py (test vulnerabilities)")
        print(f"   - demo_vulnerable.js (test vulnerabilities)")
        print(f"   - demo_vulnerable.go (test vulnerabilities)")
        print(f"   - demo_security_report.md (professional report)")
        
        print(f"\n📊 Scan Summary:")
        summary = scan_results['summary']
        print(f"   - Found {summary['total_issues']} security issues")
        print(f"   - Risk Level: {'HIGH' if summary['high_severity'] > 0 else 'MEDIUM' if summary['medium_severity'] > 0 else 'LOW'}")
        
        print(f"\n💡 Next Steps:")
        print(f"   1. Review demo_security_report.md for professional report format")
        print(f"   2. Run 'python view_logs.py --summary' to see backend logs")
        print(f"   3. Test with real PR by creating a pull request")
        
    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 