#!/usr/bin/env python3
"""
Enhanced Demo Script for Security Code Reviewer AI
Tests the complete security scanning workflow with various vulnerable code examples
"""

import os
import sys
import json
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import SecurityScanner, GitHubIssueReporter
from logging_config import setup_logging

def create_vulnerable_python_code():
    """Create Python code with various security vulnerabilities"""
    return """
import os
import subprocess
import sqlite3
import pickle
import base64

# High severity - SQL injection
def vulnerable_sql_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)  # SQL injection vulnerability
    return cursor.fetchall()

# High severity - Command injection
def vulnerable_command_execution(command):
    result = subprocess.run(command, shell=True)  # Command injection vulnerability
    return result.stdout

# High severity - Hardcoded password
password = "admin123"  # Hardcoded password
api_key = "sk-1234567890abcdef"  # Hardcoded API key

# Medium severity - Unsafe deserialization
def vulnerable_deserialization(data):
    return pickle.loads(data)  # Unsafe deserialization

# Medium severity - Weak crypto
import hashlib
def weak_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash function

# Low severity - Debug information
DEBUG = True
if DEBUG:
    print("Debug mode enabled")  # Debug information exposure

# Dangerous file operations
def dangerous_file_operation():
    os.remove("/tmp/important_file.txt")  # Dangerous file deletion
    shutil.rmtree("/tmp/important_directory")  # Dangerous directory deletion

# XSS vulnerability simulation
def vulnerable_web_function(user_input):
    html = f"<div>{user_input}</div>"  # XSS vulnerability
    return html

# Test the vulnerable functions
if __name__ == "__main__":
    # Test SQL injection
    result = vulnerable_sql_query("'; DROP TABLE users; --")
    
    # Test command injection
    result = vulnerable_command_execution("ls; rm -rf /")
    
    # Test unsafe deserialization
    malicious_data = base64.b64encode(pickle.dumps({"type": "system", "command": "rm -rf /"}))
    result = vulnerable_deserialization(malicious_data)
"""

def create_vulnerable_javascript_code():
    """Create JavaScript code with various security vulnerabilities"""
    return """
// High severity - XSS vulnerability
function vulnerableXSS(userInput) {
    document.getElementById('output').innerHTML = userInput; // XSS vulnerability
}

// High severity - SQL injection
function vulnerableSQL(userInput) {
    const query = `SELECT * FROM users WHERE name = '${userInput}'`; // SQL injection
    return executeQuery(query);
}

// High severity - Hardcoded secrets
const API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
const PASSWORD = "admin123"; // Hardcoded password

// Medium severity - Eval usage
function vulnerableEval(code) {
    return eval(code); // Dangerous eval usage
}

// Medium severity - InnerHTML usage
function vulnerableInnerHTML(html) {
    document.body.innerHTML = html; // XSS vulnerability
}

// Low severity - Console logging
function debugFunction(data) {
    console.log("Debug data:", data); // Debug information exposure
}

// Dangerous file operations simulation
function dangerousFileOperation() {
    // Simulating dangerous file operations
    const fs = require('fs');
    fs.unlinkSync('/tmp/important_file.txt'); // Dangerous file deletion
}

// Test the vulnerable functions
function testVulnerabilities() {
    // Test XSS
    vulnerableXSS('<script>alert("XSS")</script>');
    
    // Test SQL injection
    vulnerableSQL("'; DROP TABLE users; --");
    
    // Test eval
    vulnerableEval("alert('Eval executed')");
    
    // Test innerHTML
    vulnerableInnerHTML('<img src=x onerror=alert("XSS")>');
}

// Export for testing
module.exports = {
    vulnerableXSS,
    vulnerableSQL,
    vulnerableEval,
    vulnerableInnerHTML,
    testVulnerabilities
};
"""

def create_vulnerable_go_code():
    """Create Go code with various security vulnerabilities"""
    return """
package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
    "strings"
    _ "github.com/mattn/go-sqlite3"
)

// High severity - SQL injection
func vulnerableSQLQuery(db *sql.DB, userInput string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
    rows, err := db.Query(query) // SQL injection vulnerability
    if err != nil {
        fmt.Println(err)
    }
    defer rows.Close()
}

// High severity - Command injection
func vulnerableCommandExecution(command string) {
    cmd := exec.Command("sh", "-c", command) // Command injection vulnerability
    cmd.Run()
}

// High severity - Hardcoded secrets
const (
    APIKey    = "sk-1234567890abcdef" // Hardcoded API key
    Password  = "admin123"            // Hardcoded password
    SecretKey = "my-secret-key-123"   // Hardcoded secret
)

// Medium severity - Weak crypto
import "crypto/md5"
func weakPasswordHash(password string) string {
    hash := md5.Sum([]byte(password)) // Weak hash function
    return fmt.Sprintf("%x", hash)
}

// Medium severity - Unsafe file operations
func dangerousFileOperation() {
    os.Remove("/tmp/important_file.txt") // Dangerous file deletion
    os.RemoveAll("/tmp/important_directory") // Dangerous directory deletion
}

// Low severity - Debug information
const Debug = true
func debugFunction(data string) {
    if Debug {
        fmt.Printf("Debug: %s\\n", data) // Debug information exposure
    }
}

// XSS vulnerability simulation
func vulnerableWebFunction(userInput string) string {
    html := fmt.Sprintf("<div>%s</div>", userInput) // XSS vulnerability
    return html
}

func main() {
    // Test SQL injection
    db, _ := sql.Open("sqlite3", ":memory:")
    vulnerableSQLQuery(db, "'; DROP TABLE users; --")
    
    // Test command injection
    vulnerableCommandExecution("ls; rm -rf /")
    
    // Test weak crypto
    hash := weakPasswordHash("password123")
    fmt.Println("Hash:", hash)
    
    // Test dangerous file operations
    dangerousFileOperation()
    
    // Test XSS
    html := vulnerableWebFunction("<script>alert('XSS')</script>")
    fmt.Println("HTML:", html)
}
"""

def create_vulnerable_java_code():
    """Create Java code with various security vulnerabilities"""
    return """
import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;

public class VulnerableCode {
    
    // High severity - SQL injection
    public static void vulnerableSQLQuery(Connection conn, String userInput) throws SQLException {
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); // SQL injection vulnerability
    }
    
    // High severity - Hardcoded secrets
    private static final String API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
    private static final String PASSWORD = "admin123"; // Hardcoded password
    private static final String SECRET_KEY = "my-secret-key-123"; // Hardcoded secret
    
    // Medium severity - Weak crypto
    public static String weakPasswordHash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak hash function
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    // Medium severity - Unsafe file operations
    public static void dangerousFileOperation() {
        File file = new File("/tmp/important_file.txt");
        file.delete(); // Dangerous file deletion
        
        File dir = new File("/tmp/important_directory");
        deleteDirectory(dir); // Dangerous directory deletion
    }
    
    private static void deleteDirectory(File dir) {
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file);
                }
            }
        }
        dir.delete();
    }
    
    // Low severity - Debug information
    private static final boolean DEBUG = true;
    public static void debugFunction(String data) {
        if (DEBUG) {
            System.out.println("Debug: " + data); // Debug information exposure
        }
    }
    
    // XSS vulnerability simulation
    public static String vulnerableWebFunction(String userInput) {
        String html = "<div>" + userInput + "</div>"; // XSS vulnerability
        return html;
    }
    
    public static void main(String[] args) {
        try {
            // Test weak crypto
            String hash = weakPasswordHash("password123");
            System.out.println("Hash: " + hash);
            
            // Test dangerous file operations
            dangerousFileOperation();
            
            // Test XSS
            String html = vulnerableWebFunction("<script>alert('XSS')</script>");
            System.out.println("HTML: " + html);
            
            // Test debug function
            debugFunction("sensitive data");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
"""

def create_vulnerable_php_code():
    """Create PHP code with various security vulnerabilities"""
    return """
<?php
// High severity - SQL injection
function vulnerableSQLQuery($conn, $userInput) {
    $query = "SELECT * FROM users WHERE name = '$userInput'";
    $result = mysqli_query($conn, $query); // SQL injection vulnerability
    return $result;
}

// High severity - XSS vulnerability
function vulnerableXSS($userInput) {
    echo "<div>$userInput</div>"; // XSS vulnerability
}

// High severity - Hardcoded secrets
$API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
$PASSWORD = "admin123"; // Hardcoded password
$SECRET_KEY = "my-secret-key-123"; // Hardcoded secret

// Medium severity - Weak crypto
function weakPasswordHash($password) {
    return md5($password); // Weak hash function
}

// Medium severity - Unsafe file operations
function dangerousFileOperation() {
    unlink("/tmp/important_file.txt"); // Dangerous file deletion
    rmdir("/tmp/important_directory"); // Dangerous directory deletion
}

// Low severity - Debug information
$DEBUG = true;
function debugFunction($data) {
    global $DEBUG;
    if ($DEBUG) {
        echo "Debug: $data"; // Debug information exposure
    }
}

// Command injection vulnerability
function vulnerableCommandExecution($command) {
    $output = shell_exec($command); // Command injection vulnerability
    return $output;
}

// Test the vulnerable functions
if (isset($_GET['test'])) {
    // Test SQL injection
    $conn = mysqli_connect("localhost", "user", "pass", "db");
    vulnerableSQLQuery($conn, "'; DROP TABLE users; --");
    
    // Test XSS
    vulnerableXSS("<script>alert('XSS')</script>");
    
    // Test command injection
    vulnerableCommandExecution("ls; rm -rf /");
    
    // Test weak crypto
    $hash = weakPasswordHash("password123");
    echo "Hash: $hash";
    
    // Test dangerous file operations
    dangerousFileOperation();
    
    // Test debug function
    debugFunction("sensitive data");
}
?>
"""

def create_test_directory():
    """Create a test directory with vulnerable code files"""
    test_dir = Path("demo_test_repo")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir()
    
    # Create vulnerable Python file
    with open(test_dir / "vulnerable_app.py", "w") as f:
        f.write(create_vulnerable_python_code())
    
    # Create vulnerable JavaScript file
    with open(test_dir / "vulnerable_app.js", "w") as f:
        f.write(create_vulnerable_javascript_code())
    
    # Create vulnerable Go file
    with open(test_dir / "vulnerable_app.go", "w") as f:
        f.write(create_vulnerable_go_code())
    
    # Create vulnerable Java file
    with open(test_dir / "VulnerableCode.java", "w") as f:
        f.write(create_vulnerable_java_code())
    
    # Create vulnerable PHP file
    with open(test_dir / "vulnerable_app.php", "w") as f:
        f.write(create_vulnerable_php_code())
    
    # Create a requirements.txt file
    with open(test_dir / "requirements.txt", "w") as f:
        f.write("flask==2.3.3\nrequests==2.31.0\n")
    
    # Create a package.json file
    with open(test_dir / "package.json", "w") as f:
        f.write('''{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "description": "A vulnerable application for testing",
  "main": "vulnerable_app.js",
  "scripts": {
    "test": "echo \\"Error: no test specified\\" && exit 1"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}''')
    
    # Create a go.mod file
    with open(test_dir / "go.mod", "w") as f:
        f.write("""module vulnerable-app

go 1.21

require github.com/mattn/go-sqlite3 v1.14.17
""")
    
    return test_dir

def run_demo():
    """Run the complete demo"""
    print("🔒 Security Code Reviewer AI - Enhanced Demo")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    
    # Create test directory with vulnerable code
    print("📁 Creating test repository with vulnerable code...")
    test_dir = create_test_directory()
    
    # Change to test directory
    original_dir = os.getcwd()
    os.chdir(test_dir)
    
    try:
        print("🔍 Starting comprehensive security scan...")
        print("-" * 40)
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Run comprehensive scan
        scan_results = scanner.run_comprehensive_scan()
        
        print("\n" + "=" * 60)
        print("📊 SCAN RESULTS SUMMARY")
        print("=" * 60)
        
        summary = scan_results['summary']
        findings = scan_results['findings']
        
        print(f"🎯 Risk Level: {'🔴 CRITICAL' if summary['high_severity'] > 0 else '🟡 MEDIUM' if summary['medium_severity'] > 0 else '🟢 LOW' if summary['low_severity'] > 0 else '✅ SECURE'}")
        print(f"📈 Total Issues: {summary['total_issues']}")
        print(f"🔴 High Severity: {summary['high_severity']}")
        print(f"🟡 Medium Severity: {summary['medium_severity']}")
        print(f"🟢 Low Severity: {summary['low_severity']}")
        print(f"📁 Files Scanned: {summary['files_scanned']}")
        print(f"⏱️ Scan Duration: {summary['scan_duration']:.2f} seconds")
        print(f"🔧 Tools Executed: {', '.join(summary['tools_executed'])}")
        print(f"🌐 Languages Detected: {', '.join(summary['languages_scanned'])}")
        
        if findings:
            print(f"\n🔍 DETAILED FINDINGS ({len(findings)} total)")
            print("-" * 40)
            
            # Group findings by severity
            high_findings = [f for f in findings if f['severity'] == 'high']
            medium_findings = [f for f in findings if f['severity'] == 'medium']
            low_findings = [f for f in findings if f['severity'] == 'low']
            
            if high_findings:
                print(f"\n🔴 CRITICAL & HIGH SEVERITY ({len(high_findings)} issues)")
                for i, finding in enumerate(high_findings, 1):
                    print(f"  {i}. {finding['tool']}: {finding['message']}")
                    print(f"     File: {finding['file']}:{finding['line']}")
                    print(f"     CWE: {finding.get('cwe', 'N/A')}")
                    print()
            
            if medium_findings:
                print(f"\n🟡 MEDIUM SEVERITY ({len(medium_findings)} issues)")
                for i, finding in enumerate(medium_findings, 1):
                    print(f"  {i}. {finding['tool']}: {finding['message']}")
                    print(f"     File: {finding['file']}:{finding['line']}")
                    print(f"     CWE: {finding.get('cwe', 'N/A')}")
                    print()
            
            if low_findings:
                print(f"\n🟢 LOW SEVERITY ({len(low_findings)} issues)")
                for i, finding in enumerate(low_findings, 1):
                    print(f"  {i}. {finding['tool']}: {finding['message']}")
                    print(f"     File: {finding['file']}:{finding['line']}")
                    print(f"     CWE: {finding.get('cwe', 'N/A')}")
                    print()
        else:
            print("\n✅ No security vulnerabilities detected!")
        
        # Show tool execution results
        print(f"\n🛠️ TOOL EXECUTION RESULTS")
        print("-" * 40)
        for tool_name, result in scan_results.get('scan_results', {}).items():
            if result['error']:
                print(f"❌ {tool_name.upper()}: Failed - {result['error']}")
            else:
                print(f"✅ {tool_name.upper()}: Completed successfully")
        
        # Generate sample report
        print(f"\n📝 GENERATING SAMPLE SECURITY REPORT")
        print("-" * 40)
        
        # Create a mock GitHub client for demo
        class MockGitHubClient:
            def get_repo(self, repo_name):
                return MockRepo()
        
        class MockRepo:
            def create_issue(self, title, body, labels=None):
                print(f"📋 Issue Title: {title}")
                print(f"🏷️ Labels: {labels}")
                print(f"📄 Body Length: {len(body)} characters")
                return MockIssue()
        
        class MockIssue:
            @property
            def html_url(self):
                return "https://github.com/demo/repo/issues/1"
        
        # Create reporter and generate report
        mock_github = MockGitHubClient()
        reporter = GitHubIssueReporter(mock_github, "demo/repo")
        
        try:
            issue_url = reporter.create_security_report_issue(scan_results, 123)
            print(f"✅ Sample report generated successfully")
            print(f"🔗 Issue URL: {issue_url}")
        except Exception as e:
            print(f"⚠️ Report generation failed: {e}")
        
        # Save results to file
        results_file = "demo_scan_results.json"
        with open(results_file, "w") as f:
            json.dump(scan_results, f, indent=2, default=str)
        print(f"\n💾 Scan results saved to: {results_file}")
        
        print(f"\n🎉 Demo completed successfully!")
        print(f"📊 Summary: {summary['total_issues']} issues found across {len(summary['languages_scanned'])} languages")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        os.chdir(original_dir)
        print(f"\n🧹 Cleaning up test files...")
        shutil.rmtree(test_dir)
        print(f"✅ Cleanup completed")

if __name__ == "__main__":
    run_demo() 