from app import SecurityScanner

# Test the scanner
scanner = SecurityScanner()
results = scanner.run_comprehensive_scan()

print(f"🔒 Security Scan Results:")
print(f"Total Issues: {results['summary']['total_issues']}")
print(f"High Severity: {results['summary']['high_severity']}")
print(f"Medium Severity: {results['summary']['medium_severity']}")
print(f"Low Severity: {results['summary']['low_severity']}")

if results['findings']:
    print("\n🚨 Vulnerabilities Found:")
    for finding in results['findings']:
        print(f"  • {finding['tool']}: {finding['message']}")
        print(f"    File: {finding['file']}:{finding['line']}")
else:
    print("\n✅ No vulnerabilities found!") 