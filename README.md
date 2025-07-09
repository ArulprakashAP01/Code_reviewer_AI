# 🔒 Security Code Reviewer AI - GitHub App

A comprehensive GitHub App that automatically scans pull requests for security vulnerabilities and generates professional security reports. The app integrates multiple security tools and provides detailed backend logging for complete transparency.

## 🚀 Features

### 🔍 Comprehensive Security Scanning
- **Multi-language Support**: Python, JavaScript/TypeScript, Go, and more
- **Multiple Security Tools**: Bandit, ESLint, gosec, Semgrep
- **Automatic Detection**: Scans code based on file extensions
- **Severity Classification**: High, Medium, Low risk levels

### 📊 Professional Reporting
- **GitHub Issues**: Detailed security reports in issues tab
- **PR Comments**: Summary comments with risk assessment
- **Professional Format**: Executive summary, detailed findings, recommendations
- **Actionable Insights**: Clear next steps based on risk level

### 📝 Complete Backend Logging
- **Webhook Events**: Track all incoming GitHub events
- **Scan Progress**: Monitor security tool execution
- **Security Findings**: Log all detected vulnerabilities
- **Report Generation**: Track issue and comment creation
- **Error Handling**: Comprehensive error logging

### 🔄 Automatic Workflow
- **PR Triggers**: Automatically scans on PR open/update
- **Installation Support**: Handles app installation events
- **Real-time Processing**: Immediate scanning and reporting
- **Cleanup**: Automatic temporary file cleanup

## 🛠️ Setup Instructions

### 1. Prerequisites
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install security tools (optional - app handles missing tools gracefully)
pip install bandit
npm install -g eslint
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
pip install semgrep
```

### 2. Environment Configuration
Create a `.env` file with your GitHub App credentials:
```env
GITHUB_APP_ID=your_app_id
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

### 3. GitHub App Configuration
1. Create a GitHub App in your GitHub account
2. Set the webhook URL to your ngrok URL: `https://your-ngrok-url.ngrok.io/webhook`
3. Configure required permissions:
   - Repository permissions: Contents (Read), Issues (Write), Pull requests (Write)
   - Subscribe to events: Pull requests, Installation

### 4. Run the Application
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
3. **Runs Security Scans**: Executes all available security tools
4. **Generates Reports**: Creates detailed GitHub issues
5. **Comments on PR**: Posts summary with risk assessment

### Manual Scanning
You can also trigger manual scans:
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo"}'
```

## 📊 Logging and Monitoring

### Log Files
The app creates comprehensive logs in the `logs/` directory:
- `security_scanner.log` - Main application logs
- `webhook_events.log` - GitHub webhook events
- `security_findings.log` - Detected vulnerabilities
- `scan_progress.log` - Security tool execution
- `report_generation.log` - Report creation activity

### Log Viewer
Use the included log viewer for monitoring:
```bash
# Show log summary
python log_viewer.py --summary

# Monitor recent activity
python log_viewer.py --recent 24

# Track specific PR
python log_viewer.py --pr 123

# Real-time monitoring
python log_viewer.py --monitor 300

# Show all log types
python log_viewer.py --all
```

## 🔍 Security Tools

### Bandit (Python)
- **Purpose**: Python security linter
- **Detects**: SQL injection, hardcoded passwords, unsafe functions
- **Configuration**: Uses default rules with high confidence

### ESLint (JavaScript/TypeScript)
- **Purpose**: JavaScript/TypeScript security analysis
- **Detects**: XSS vulnerabilities, unsafe eval, prototype pollution
- **Configuration**: Security-focused rules

### gosec (Go)
- **Purpose**: Go security scanner
- **Detects**: SQL injection, command injection, weak crypto
- **Configuration**: Comprehensive security rules

### Semgrep (Multi-language)
- **Purpose**: Pattern-based security analysis
- **Detects**: Custom security patterns, OWASP Top 10
- **Configuration**: Auto-configuration with security rules

## 📈 Report Structure

### Executive Summary
- Risk level assessment
- Total issues found
- Languages analyzed
- Timestamp and PR reference

### Detailed Findings
- Severity breakdown (High/Medium/Low)
- Tool execution status
- Vulnerability details with file locations
- CWE references

### Security Recommendations
- Language-specific best practices
- General security guidelines
- Risk-based action items

### Technical Details
- Scan configuration
- Security standards compliance
- Support resources

## 🚨 Risk Levels

### 🔴 Critical (High Severity)
- **Action**: Immediate attention required
- **Priority**: Fix before merging
- **Examples**: SQL injection, hardcoded secrets, unsafe deserialization

### 🟡 Medium Severity
- **Action**: High priority review
- **Priority**: Address before deployment
- **Examples**: Weak crypto, unsafe functions, potential XSS

### 🟢 Low Severity
- **Action**: Recommended improvements
- **Priority**: Address in development cycle
- **Examples**: Code quality issues, best practice violations

### ✅ Secure
- **Action**: Maintain standards
- **Priority**: Continue good practices
- **Status**: No vulnerabilities detected

## 🔧 Configuration

### Custom Security Rules
You can add custom security patterns by modifying the scanner classes:
```python
# Add custom Bandit rules
def scan_with_bandit(self):
    # Custom configuration
    result = subprocess.run([
        "bandit", "-r", ".", "-f", "json", "-ll",
        "-c", "custom_bandit_config.yaml"
    ], capture_output=True, text=True)
```

### Logging Configuration
Modify `logging_config.py` to adjust log levels and file sizes:
```python
# Adjust log file sizes
maxBytes=10*1024*1024,  # 10MB
backupCount=5
```

## 🐛 Troubleshooting

### Common Issues

1. **Webhook 404 Errors**
   - Verify ngrok URL is correct
   - Check webhook secret configuration
   - Ensure app is running

2. **Security Tools Not Found**
   - App handles missing tools gracefully
   - Install tools for full coverage
   - Check tool availability in logs

3. **Authentication Errors**
   - Verify GitHub App ID and private key
   - Check installation permissions
   - Review webhook secret

4. **Scan Timeouts**
   - Large repositories may timeout
   - Check scan progress logs
   - Consider repository size limits

### Debug Mode
Enable debug logging:
```python
logging.getLogger().setLevel(logging.DEBUG)
```

## 📞 Support

### Health Check
```bash
curl http://localhost:5000/health
```

### Log Analysis
```bash
# Check for errors
python log_viewer.py --findings

# Monitor webhook events
python log_viewer.py --webhooks

# Track scan progress
python log_viewer.py --scan-progress
```

## 🔄 Updates and Maintenance

### Regular Maintenance
- Update security tools regularly
- Monitor log file sizes
- Review and update security rules
- Check GitHub App permissions

### Performance Optimization
- Monitor scan durations
- Optimize repository cloning
- Review tool configurations
- Implement caching if needed

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📚 Resources

- [GitHub Apps Documentation](https://docs.github.com/en/developers/apps)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [ESLint Security Rules](https://eslint.org/docs/rules/)
- [gosec Documentation](https://github.com/securecodewarrior/gosec)
- [Semgrep Documentation](https://semgrep.dev/docs/)

---

**Security Code Reviewer AI** - Making code security accessible and automated! 🔒✨ 