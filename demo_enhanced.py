#!/usr/bin/env python3
"""
Enhanced Demo Script for Security Code Reviewer AI
Demonstrates the complete workflow with detailed logging and professional reporting
"""

import os
import json
import time
from datetime import datetime
from app import SecurityScanner, GitHubIssueReporter
from logging_config import (
    setup_logging, log_security_scan_start, log_security_scan_complete,
    log_github_issue_created, log_github_comment_posted, log_tool_execution
)

def create_demo_files():
    """Create demo files with various security vulnerabilities"""
    print("🔧 Creating demo files with security vulnerabilities...")
    
    # Create vulnerable Python file
    with open("demo_vulnerable.py", "w") as f:
        f.write("""
import os
import subprocess
import sqlite3

# High severity: Hardcoded password
password = "admin123"

# High severity: SQL injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()

# Medium severity: Command injection
def run_command(command):
    # Vulnerable to command injection
    os.system(command)

# Low severity: Weak crypto
import hashlib
def hash_password(password):
    # Weak hashing
    return hashlib.md5(password.encode()).hexdigest()

# High severity: Unsafe deserialization
import pickle
def load_data(data):
    # Unsafe deserialization
    return pickle.loads(data)

# Medium severity: Debug mode in production
DEBUG = True
if DEBUG:
    print("Debug mode enabled")
""")
    
    # Create vulnerable JavaScript file
    with open("demo_vulnerable.js", "w") as f:
        f.write("""
// High severity: XSS vulnerability
function displayUserInput(userInput) {
    // Vulnerable to XSS
    document.getElementById('output').innerHTML = userInput;
}

// High severity: SQL injection
function getUserData(userId) {
    // Vulnerable to SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return database.execute(query);
}

// Medium severity: Unsafe eval
function processData(data) {
    // Unsafe eval usage
    return eval(data);
}

// Low severity: Console logging in production
console.log('User data:', userData);

// Medium severity: Weak crypto
function hashPassword(password) {
    // Weak hashing
    return btoa(password);
}

// High severity: Prototype pollution
function mergeObjects(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}
""")
    
    # Create vulnerable Go file
    with open("demo_vulnerable.go", "w") as f:
        f.write(`
package main

import (
    "database/sql"
    "fmt"
    "os/exec"
    "crypto/md5"
    _ "github.com/mattn/go-sqlite3"
)

// High severity: SQL injection
func getUserData(db *sql.DB, userID string) {
    // Vulnerable to SQL injection
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
    db.Query(query)
}

// High severity: Command injection
func runCommand(command string) {
    // Vulnerable to command injection
    exec.Command("sh", "-c", command).Run()
}

// Medium severity: Weak crypto
func hashPassword(password string) string {
    // Weak hashing
    hash := md5.Sum([]byte(password))
    return fmt.Sprintf("%x", hash)
}

// Low severity: Debug logging
func debugLog(message string) {
    fmt.Printf("DEBUG: %s\n", message)
}

// High severity: Unsafe file operations
func readFile(path string) {
    // No path validation
    data, _ := os.ReadFile(path)
    fmt.Println(string(data))
}
`)
    
    print("✅ Demo files created successfully")

def run_enhanced_demo():
    """Run the enhanced demo with comprehensive logging"""
    print("🚀 Starting Enhanced Security Code Reviewer AI Demo")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    
    # Create demo files
    create_demo_files()
    
    # Simulate PR number for logging
    demo_pr_number = 999
    demo_repo = "demo/security-test"
    
    print(f"\n📋 Demo Configuration:")
    print(f"  PR Number: #{demo_pr_number}")
    print(f"  Repository: {demo_repo}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    
    # Log scan start
    log_security_scan_start(demo_pr_number, demo_repo)
    
    print(f"\n🔍 Starting comprehensive security scan...")
    
    # Run security scan
    scanner = SecurityScanner()
    scan_results = scanner.run_comprehensive_scan()
    
    # Log scan completion
    log_security_scan_complete(demo_pr_number, scan_results)
    
    print(f"\n📊 Scan Results Summary:")
    summary = scan_results['summary']
    print(f"  Total Issues: {summary['total_issues']}")
    print(f"  High Severity: {summary['high_severity']} 🔴")
    print(f"  Medium Severity: {summary['medium_severity']} 🟡")
    print(f"  Low Severity: {summary['low_severity']} 🟢")
    print(f"  Languages Scanned: {', '.join(summary['languages_scanned'])}")
    
    # Display detailed findings
    if scan_results['findings']:
        print(f"\n🔍 Detailed Findings:")
        print("-" * 40)
        for finding in scan_results['findings']:
            severity_icon = "🔴" if finding['severity'] == 'HIGH' else "🟡" if finding['severity'] == 'MEDIUM' else "🟢"
            print(f"{severity_icon} {finding['tool']}: {finding['severity']} - {finding['message']}")
            print(f"   File: {finding['file']}:{finding['line']}")
            print()
    
    # Simulate GitHub issue creation
    print(f"\n📝 Simulating GitHub issue creation...")
    try:
        # Note: This would normally require a real GitHub client
        print("✅ GitHub issue would be created with detailed report")
        print("✅ PR comment would be posted with summary")
        
        # Log simulated activities
        log_github_issue_created(demo_pr_number, "https://github.com/demo/repo/issues/123")
        log_github_comment_posted(demo_pr_number, summary)
        
    except Exception as e:
        print(f"⚠️ GitHub integration simulation: {e}")
    
    # Display tool execution status
    print(f"\n🛠️ Tool Execution Status:")
    print("-" * 40)
    scan_results_detail = scan_results.get('scan_results', {})
    for tool, result in scan_results_detail.items():
        status = "✅ SUCCESS" if not result.get('error') else f"❌ FAILED: {result['error']}"
        print(f"  {tool.upper()}: {status}")
    
    # Show what the GitHub issue would look like
    print(f"\n📄 Sample GitHub Issue Report:")
    print("=" * 60)
    
    # Calculate risk level
    risk_level = "🔴 CRITICAL" if summary['high_severity'] > 0 else "🟡 MEDIUM" if summary['medium_severity'] > 0 else "🟢 LOW" if summary['low_severity'] > 0 else "✅ SECURE"
    
    issue_body = f"""# 🔒 Security Assessment Report

## 📋 Executive Summary

**Risk Level:** {risk_level}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Total Security Issues:** {summary['total_issues']}  
**Languages Analyzed:** {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None detected'}

**Related Pull Request:** #{demo_pr_number}

---

## 📊 Detailed Findings

### Severity Breakdown
- 🔴 **Critical/High:** {summary['high_severity']} issues
- 🟡 **Medium:** {summary['medium_severity']} issues  
- 🟢 **Low:** {summary['low_severity']} issues

### Security Tools Used
"""
    
    # Add tool status
    tools_used = []
    for tool, result in scan_results_detail.items():
        if result.get('error'):
            issue_body += f"- ❌ **{tool.upper()}:** {result['error']}\n"
        else:
            issue_body += f"- ✅ **{tool.upper()}:** Successfully scanned\n"
            tools_used.append(tool)
    
    issue_body += f"""
**Total Tools Successfully Executed:** {len(tools_used)}

---

## 🔍 Detailed Vulnerability Analysis
"""
    
    if scan_results['findings']:
        issue_body += "| **Tool** | **File** | **Line** | **Severity** | **Vulnerability** | **CWE** |\n"
        issue_body += "|----------|----------|----------|--------------|-------------------|---------|\n"
        
        for finding in scan_results['findings']:
            file_path = finding['file'].replace('\\', '/')
            severity_icon = "🔴" if finding['severity'] == 'HIGH' else "🟡" if finding['severity'] == 'MEDIUM' else "🟢"
            cwe = finding.get('cwe', 'N/A')
            message = finding['message'][:80] + "..." if len(finding['message']) > 80 else finding['message']
            
            issue_body += f"| {finding['tool']} | `{file_path}` | {finding['line']} | {severity_icon} {finding['severity']} | {message} | {cwe} |\n"
    else:
        issue_body += """
### ✅ No Security Vulnerabilities Detected

**Assessment Result:** Your code has passed all security checks!  
**Recommendation:** Continue following security best practices in future development.
"""
    
    issue_body += f"""

---

## 🛡️ Security Recommendations

### General Best Practices
1. **Regular Updates:** Keep dependencies updated to patch known vulnerabilities
2. **Code Review:** Implement mandatory security code reviews
3. **Static Analysis:** Use automated security scanning in CI/CD pipelines
4. **Dependency Scanning:** Regularly scan for vulnerable dependencies
5. **Secrets Management:** Never commit secrets or sensitive data to version control

### Language-Specific Recommendations
"""
    
    if 'python' in summary['languages_scanned']:
        issue_body += """
**Python:**
- Use virtual environments for dependency isolation
- Regularly update pip and packages
- Follow PEP 8 security guidelines
- Use `bandit` for automated security testing
"""
    
    if 'javascript' in summary['languages_scanned']:
        issue_body += """
**JavaScript/TypeScript:**
- Use npm audit for dependency vulnerability scanning
- Implement Content Security Policy (CSP)
- Validate and sanitize all user inputs
- Use HTTPS for all external requests
"""
    
    if 'go' in summary['languages_scanned']:
        issue_body += """
**Go:**
- Use `go mod tidy` to clean dependencies
- Run `gosec` for security analysis
- Validate all user inputs
- Use context for request cancellation
"""
    
    # Add next steps based on risk level
    if summary['high_severity'] > 0:
        issue_body += """
---

## 🚨 Critical Action Required

**Status:** Critical security vulnerabilities detected  
**Priority:** IMMEDIATE - Address before merging  
**Action:** Review detailed report and fix high-severity issues
"""
    elif summary['medium_severity'] > 0:
        issue_body += """
---

## ⚠️ Security Review Required

**Status:** Medium-risk vulnerabilities detected  
**Priority:** HIGH - Address before deployment  
**Action:** Review and address medium-severity issues
"""
    elif summary['low_severity'] > 0:
        issue_body += """
---

## ℹ️ Security Review Recommended

**Status:** Low-risk issues detected  
**Priority:** MEDIUM - Address as part of development cycle  
**Action:** Review low-severity issues for improvement
"""
    else:
        issue_body += """
---

## ✅ Maintain Security Standards

**Status:** No vulnerabilities detected  
**Priority:** Continue best practices  
**Action:** Maintain current security practices
"""
    
    issue_body += f"""

---

*This report was generated automatically by the Security Code Reviewer AI.*

**Report ID:** {datetime.now().strftime('%Y%m%d-%H%M%S')}  
**Generated:** {datetime.now().isoformat()} UTC
"""
    
    print(issue_body)
    
    # Show what the PR comment would look like
    print(f"\n💬 Sample PR Comment:")
    print("=" * 60)
    
    risk_level_comment = "🔴 CRITICAL" if summary['high_severity'] > 0 else "🟡 MEDIUM" if summary['medium_severity'] > 0 else "🟢 LOW" if summary['low_severity'] > 0 else "✅ SECURE"
    
    comment_body = f"""## 🔒 Security Assessment Complete

### 📊 Assessment Summary
- **Risk Level:** {risk_level_comment}
- **Total Issues:** {summary['total_issues']}
- **Critical/High:** {summary['high_severity']} 🔴
- **Medium:** {summary['medium_severity']} 🟡
- **Low:** {summary['low_severity']} 🟢

**Languages Analyzed:** {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None detected'}

### 📋 Detailed Report
**Comprehensive Security Assessment:** [Issue Link]

"""
    
    if summary['total_issues'] == 0:
        comment_body += "### ✅ Assessment Status\n"
        comment_body += "**Result:** No security vulnerabilities detected\n"
        comment_body += "**Action:** Code is ready for review and deployment\n"
        comment_body += "**Compliance:** ✅ Meets security standards"
    elif summary['high_severity'] > 0:
        comment_body += "### 🚨 Critical Action Required\n"
        comment_body += "**Status:** Critical security vulnerabilities detected\n"
        comment_body += "**Priority:** IMMEDIATE - Address before merging\n"
        comment_body += "**Action:** Review detailed report and fix high-severity issues"
    elif summary['medium_severity'] > 0:
        comment_body += "### ⚠️ Security Review Required\n"
        comment_body += "**Status:** Medium-risk vulnerabilities detected\n"
        comment_body += "**Priority:** HIGH - Address before deployment\n"
        comment_body += "**Action:** Review and address medium-severity issues"
    else:
        comment_body += "### ℹ️ Security Review Recommended\n"
        comment_body += "**Status:** Low-risk issues detected\n"
        comment_body += "**Priority:** MEDIUM - Address as part of development cycle\n"
        comment_body += "**Action:** Review low-severity issues for improvement"
    
    comment_body += "\n\n---\n*This assessment was performed by the Security Code Reviewer AI. For questions, contact the security team.*"
    
    print(comment_body)
    
    # Cleanup demo files
    print(f"\n🧹 Cleaning up demo files...")
    for file in ["demo_vulnerable.py", "demo_vulnerable.js", "demo_vulnerable.go"]:
        if os.path.exists(file):
            os.remove(file)
    print("✅ Demo files cleaned up")
    
    print(f"\n🎉 Enhanced Demo Completed Successfully!")
    print("=" * 60)
    print(f"📊 Final Summary:")
    print(f"  Total Issues Found: {summary['total_issues']}")
    print(f"  Risk Level: {risk_level}")
    print(f"  Tools Executed: {len(tools_used)}")
    print(f"  Languages Scanned: {len(summary['languages_scanned'])}")
    print(f"\n📝 Logs generated in 'logs/' directory")
    print(f"🔍 Use 'python log_viewer.py --all' to view all logs")
    print(f"👀 Use 'python log_viewer.py --monitor 60' for real-time monitoring")

if __name__ == "__main__":
    run_enhanced_demo() 