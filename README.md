# 🔒 Security Code Reviewer AI - GitHub App

A comprehensive GitHub App that automatically scans pull requests for security vulnerabilities using multiple security tools and generates professional security reports in GitHub issues. The app provides complete code coverage, detailed vulnerability analysis, and actionable security recommendations.

## 🚀 Features

### 🔍 Comprehensive Security Scanning
- **Multi-language Support**: Python, JavaScript/TypeScript, Go, Java, C/C++, PHP, Ruby, Rust
- **Multiple Security Tools**: Bandit, ESLint, gosec, Semgrep
- **Automatic Language Detection**: Scans code based on detected file types
- **Additional Security Checks**: Hardcoded secrets, dangerous file operations, pattern-based scanning
- **Complete Code Coverage**: Scans all relevant files while skipping build artifacts and dependencies

### 📊 Professional Reporting
- **GitHub Issues**: Detailed security reports in issues tab with executive summary
- **PR Comments**: Summary comments with risk assessment and action items
- **Professional Format**: Executive summary, detailed findings, recommendations, compliance info
- **Actionable Insights**: Clear next steps based on risk level and vulnerability type

### 📝 Complete Logging & Monitoring
- **Console Logging**: Real-time logging to console for easy monitoring
- **Webhook Events**: Track all incoming GitHub events
- **Scan Progress**: Monitor security tool execution and results
- **Security Findings**: Log all detected vulnerabilities with details
- **Error Handling**: Comprehensive error logging and recovery

### 🔄 Automatic Workflow
- **PR Triggers**: Automatically scans on PR open/update/reopen
- **Installation Support**: Handles app installation events
- **Real-time Processing**: Immediate scanning and reporting
- **Cleanup**: Automatic temporary file cleanup

## 🛠️ Quick Setup

### 1. Prerequisites
```bash
# Install Python 3.7+
python --version

# Install Node.js (for ESLint)
node --version

# Install Go (for gosec)
go version
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install security tools (optional - app handles missing tools gracefully)
pip install bandit
npm install -g eslint
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
pip install semgrep
```

### 3. Run Setup Script
```bash
# Run the automated setup script
python setup.py
```

### 4. Configure Environment
Create a `.env` file with your GitHub App credentials:
```env
GITHUB_APP_ID=your_app_id
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

### 5. GitHub App Configuration
1. Create a GitHub App in your GitHub account
2. Set the webhook URL to your ngrok URL: `https://your-ngrok-url.ngrok.io/webhook`
3. Configure required permissions:
   - Repository permissions: Contents (Read), Issues (Write), Pull requests (Write)
   - Subscribe to events: Pull requests, Installation

### 6. Run the Application
```bash
# Start the Flask application
python app.py

# In another terminal, start ngrok
ngrok http 5000
```

## 📋 Usage

### Automatic Scanning
Once installed, the app automatically:
1. **Detects PR Events**: Monitors for new/updated pull requests
2. **Clones Repository**: Downloads PR code for analysis
3. **Detects Languages**: Identifies programming languages in the codebase
4. **Runs Security Scans**: Executes appropriate security tools for detected languages
5. **Generates Reports**: Creates detailed GitHub issues with findings
6. **Comments on PR**: Posts summary with risk assessment and action items

### Manual Scanning
You can also trigger manual scans:
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo"}'
```

### Demo and Testing
Run the comprehensive demo to test the scanner:
```bash
python demo_enhanced.py
```

## 🔍 Security Tools & Coverage

### Bandit (Python)
- **Purpose**: Python security linter
- **Detects**: SQL injection, hardcoded passwords, unsafe functions, eval usage
- **Configuration**: Uses default rules with high confidence

### ESLint (JavaScript/TypeScript)
- **Purpose**: JavaScript/TypeScript security analysis
- **Detects**: XSS vulnerabilities, unsafe eval, prototype pollution, SQL injection
- **Configuration**: Security-focused rules and best practices

### gosec (Go)
- **Purpose**: Go security scanner
- **Detects**: SQL injection, command injection, weak crypto, unsafe file operations
- **Configuration**: Comprehensive security rules

### Semgrep (Multi-language)
- **Purpose**: Pattern-based security analysis
- **Detects**: Custom security patterns, OWASP Top 10, language-specific vulnerabilities
- **Configuration**: Auto-configuration with security rules

### Additional Checks
- **Hardcoded Secrets**: API keys, passwords, tokens, private keys
- **Dangerous Operations**: File deletions, directory removals, unsafe commands
- **Pattern Matching**: Custom regex patterns for security issues

## 📊 Report Structure

### Executive Summary
- Risk level assessment (Critical/Medium/Low/Secure)
- Total issues found with severity breakdown
- Languages analyzed and tools executed
- Scan duration and files processed
- Timestamp and PR reference

### Detailed Findings
- **Critical/High Severity**: Immediate attention required
- **Medium Severity**: High priority review needed
- **Low Severity**: Recommended improvements
- Each finding includes: tool, severity, message, file location, line number, CWE reference

### Security Recommendations
- **Immediate Actions**: For critical issues
- **High Priority Actions**: For medium issues
- **Improvement Opportunities**: For low issues
- **Language-Specific**: Best practices for each detected language

### Compliance & Standards
- OWASP Top 10 2021 coverage
- CWE (Common Weakness Enumeration) references
- Industry best practices
- Security standards compliance

## 🚨 Risk Levels

### 🔴 Critical (High Severity)
- **Action**: Immediate attention required
- **Priority**: Fix before merging
- **Examples**: SQL injection, hardcoded secrets, unsafe deserialization, command injection

### 🟡 Medium Severity
- **Action**: High priority review
- **Priority**: Address before deployment
- **Examples**: Weak crypto, unsafe functions, potential XSS, dangerous file operations

### 🟢 Low Severity
- **Action**: Recommended improvements
- **Priority**: Address in development cycle
- **Examples**: Code quality issues, best practice violations, debug information exposure

### ✅ Secure
- **Action**: Maintain standards
- **Priority**: Continue good practices
- **Status**: No vulnerabilities detected

## 📈 Monitoring & Logging

### Console Output
The app provides real-time console logging for easy monitoring:
```
2024-01-15 10:30:15 - webhook - INFO - WEBHOOK EVENT: RECEIVED - PULL_REQUEST - OPENED
2024-01-15 10:30:16 - security - INFO - SECURITY SCAN STARTED - PR #123 - user/repo
2024-01-15 10:30:17 - scan - INFO - TOOL_EXECUTION - BANDIT - started
2024-01-15 10:30:20 - scan - INFO - TOOL_EXECUTION - BANDIT - completed
2024-01-15 10:30:25 - security - INFO - SECURITY SCAN COMPLETED - Issues: 5 (H:2 M:2 L:1)
```

### Log Viewer
Use the included log viewer for detailed monitoring:
```bash
# Show log summary
python log_viewer.py --summary

# Monitor recent activity
python log_viewer.py --recent 24

# Track specific PR
python log_viewer.py --pr 123

# Real-time monitoring
python log_viewer.py --monitor 300
```

## 🔧 Configuration

### Custom Security Rules
You can add custom security patterns by modifying the scanner:
```python
# Add custom patterns in _run_additional_checks method
custom_patterns = [
    (r'your_pattern', 'Your custom message'),
]
```

### Logging Configuration
Modify `logging_config.py` to adjust log levels and output:
```python
# Change log level
logging.basicConfig(level=logging.DEBUG)
```

### Tool Configuration
Each security tool can be configured with custom rules:
```python
# Custom Bandit configuration
result = subprocess.run([
    "bandit", "-r", ".", "-f", "json", "-ll",
    "-c", "custom_bandit_config.yaml"
], capture_output=True, text=True)
```

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run with Docker
docker-compose up -d
```

### Systemd Service
```bash
# Install as system service
sudo cp security-reviewer.service /etc/systemd/system/
sudo systemctl enable security-reviewer
sudo systemctl start security-reviewer
```

### Production Considerations
- Use HTTPS for webhook endpoints
- Implement proper authentication
- Set up monitoring and alerting
- Configure backup and recovery
- Use environment variables for secrets

## 🆘 Troubleshooting

### Common Issues

**Webhook not receiving events:**
- Check ngrok URL is correct and accessible
- Verify webhook secret matches
- Ensure app has proper permissions

**Scan not triggering:**
- Check app is installed on repository
- Verify PR events are subscribed
- Review console logs for errors

**Tools not working:**
- Install missing security tools
- Check tool versions and compatibility
- Review tool-specific error messages

**Authentication errors:**
- Verify GitHub App credentials
- Check private key format
- Ensure proper installation ID

### Debug Mode
Enable debug logging for detailed troubleshooting:
```python
logging.basicConfig(level=logging.DEBUG)
```

### Health Check
Check application status:
```bash
curl http://localhost:5000/health
```

## 📚 Resources

### Documentation
- [GitHub Apps Documentation](https://docs.github.com/en/developers/apps)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)

### Security Tools
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [ESLint Security Rules](https://eslint.org/docs/rules/)
- [gosec Documentation](https://github.com/securecodewarrior/gosec)
- [Semgrep Documentation](https://semgrep.dev/)

### Support
- Check console logs for detailed error information
- Review GitHub App configuration
- Verify security tool installations
- Test with demo script

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🔒 Security Code Reviewer AI** - Making code security accessible and automated for every development team. 


