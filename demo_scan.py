#!/usr/bin/env python3
"""
Demonstration of the Security Code Reviewer AI workflow
"""

import json
from datetime import datetime
from app import SecurityScanner, GitHubIssueReporter

def demo_security_scan():
    """Demonstrate the complete security scanning workflow"""
    
    print("🔒 Security Code Reviewer AI - Demo")
    print("=" * 50)
    
    # Initialize the security scanner
    scanner = SecurityScanner()
    
    print("📊 Running security scan...")
    
    # Run comprehensive security scan
    scan_results = scanner.run_comprehensive_scan()
    
    # Display results
    summary = scan_results['summary']
    findings = scan_results['findings']
    
    print(f"\n📋 Scan Summary:")
    print(f"   Total Issues: {summary['total_issues']}")
    print(f"   High Severity: {summary['high_severity']} 🔴")
    print(f"   Medium Severity: {summary['medium_severity']} 🟡")
    print(f"   Low Severity: {summary['low_severity']} 🟢")
    print(f"   Languages Scanned: {', '.join(summary['languages_scanned'])}")
    
    if findings:
        print(f"\n🚨 Security Vulnerabilities Found:")
        print("-" * 50)
        
        # Group by severity
        high_findings = [f for f in findings if f['severity'] == 'HIGH']
        medium_findings = [f for f in findings if f['severity'] == 'MEDIUM']
        low_findings = [f for f in findings if f['severity'] == 'LOW']
        
        if high_findings:
            print("\n🔴 HIGH SEVERITY ISSUES:")
            for finding in high_findings:
                print(f"   • {finding['tool']}: {finding['message']}")
                print(f"     File: {finding['file']}:{finding['line']}")
                if finding['cwe']:
                    print(f"     CWE: {finding['cwe']}")
                print()
        
        if medium_findings:
            print("\n🟡 MEDIUM SEVERITY ISSUES:")
            for finding in medium_findings:
                print(f"   • {finding['tool']}: {finding['message']}")
                print(f"     File: {finding['file']}:{finding['line']}")
                if finding['cwe']:
                    print(f"     CWE: {finding['cwe']}")
                print()
        
        if low_findings:
            print("\n🟢 LOW SEVERITY ISSUES:")
            for finding in low_findings:
                print(f"   • {finding['tool']}: {finding['message']}")
                print(f"     File: {finding['file']}:{finding['line']}")
                if finding['cwe']:
                    print(f"     CWE: {finding['cwe']}")
                print()
        
        print("\n📋 What happens when you install the GitHub App:")
        print("1. 🔄 User creates a pull request")
        print("2. 📡 GitHub sends webhook to your app")
        print("3. 🔍 App automatically scans the code")
        print("4. 📊 App generates detailed security report")
        print("5. 🏷️ App creates GitHub issue with findings")
        print("6. 💬 App comments on PR with summary")
        print("7. 🚨 Team gets notified of security issues")
        
        print(f"\n📄 Sample GitHub Issue Title:")
        print(f"   🔒 Security Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n📋 Sample PR Comment:")
        print(f"   ## 🔒 Automated Security Scan Complete")
        print(f"   **Scan Results:**")
        print(f"   - Total Issues: {summary['total_issues']}")
        print(f"   - High Severity: {summary['high_severity']} 🔴")
        print(f"   - Medium Severity: {summary['medium_severity']} 🟡")
        print(f"   - Low Severity: {summary['low_severity']} 🟢")
        print(f"   📋 **Detailed Report:** [Link to GitHub Issue]")
        
        if summary['high_severity'] > 0:
            print(f"   🚨 **High severity issues found! Please review immediately.**")
        
    else:
        print("\n✅ No security vulnerabilities detected!")
        print("   Your code follows security best practices.")
    
    print("\n" + "=" * 50)
    print("🎉 Demo completed! Your GitHub App is ready to scan repositories.")

if __name__ == "__main__":
    demo_security_scan() 