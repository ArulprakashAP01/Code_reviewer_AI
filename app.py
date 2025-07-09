import os
import glob
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_githubapp import GitHubApp
from github import Github, GithubIntegration
import subprocess
from dotenv import load_dotenv
import re
from typing import Dict, List, Any, Optional

# Import logging configuration
from logging_config import (
    setup_logging, log_webhook_event, log_security_scan_start, 
    log_security_scan_complete, log_github_issue_created, 
    log_github_comment_posted, log_error, log_tool_execution,
    log_report_generation_start, log_report_generation_complete
)

# Setup comprehensive logging
setup_logging()
logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
try:
    load_dotenv()
except Exception as e:
    logger.warning(f"Could not load .env file: {e}")
    # Set default values if .env is not available
    try:
        if not os.getenv("GITHUB_WEBHOOK_SECRET"):
            os.environ["GITHUB_WEBHOOK_SECRET"] = "arulprakash01"
        if not os.getenv("GITHUB_APP_ID"):
            os.environ["GITHUB_APP_ID"] = "1513443"
    except Exception as inner_e:
        logger.warning(f"Failed to set default env vars: {inner_e}")

app = Flask(__name__)

PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv5EzTYr2kIdcXNGhDGuXvJx2tfTDYpCuOZkP4afaRxxyNqlK
474pSMwYFpkP5cNgDwbWwmdZ7FTA1vQxnCAHk/aZXafvqtBIw20H0lHj2xfmp2L/
W1edJlcwSEpjAaNZ8NR5ZaZ9tZtxor1phd0B09gf3M7FM+f6Qvvq/DiMycyfNB0y
DRyjiul5xsX6C6fX1Ol3kiMyP1+HkvWAJS5YIf4+qJAIi+RRF0NurSYY7J6XuGCR
ICa8//mdZPOWt114OZo8c2haUYoc9dDpMDeGpDRjXnzYWD/+o7kGkbO36MeMaz1A
FJC01lt/w2U2b0uBaHHKU1eFbOU8MXl9ZQzgxwIDAQABAoIBAF5QlJuW0THzEsw4
ATxmNHyN4/xNl2yNotmEvEbzJwpfvPOggdiCpTzMDwgBL8yFVmPPkCiCTcmHKLIr
48jkFBcLEBMGPX8xsMFWisVHwBD8QXkjymkkR6C6yHCu/vOtgviJA4PCZp3k/BuN
eciIOQAdpgJGYtzdV19nPBgVl2s6Us0Cro/Tz0oQmBuwkfV05B0wrL1AJG3lpIp2
wdb04i2uhlv3FgTw1idqTwtS1ZA2RGVUpgKYRwLBApMgyJSICcWGN77tABR3zusV
Cntp42RNPfZUF68DbzaJmlyd8tURZ5S2EGgf7o4Ocl5M9bWUddy1+K11pteUE/EB
G7wGW4ECgYEA6JbUdTmm6shvqmyINvqMS2DaMcZYs38vn5Zr7aw9MRL57/S6UJyA
PBgHbKmwYLRA60hujEtnc0ET4Z4AReuPFgCZPM26ZuvVDvhCAyyKYFUPCq593Qf/
DV+X/ohcjd+oxnEiluiT8T99ENy2vbsFgMrEg36w1gEQmHVh5mvDESECgYEA0tlZ
VspE7zAwUs0zQpUnuQ7UsC0mkHmfAtmuRczQpUz99bnmnj6U8nM+DRu1DtoIC2Up
pEupE2vHt2V+YsvFANPoiSq6QaWoFFSkg6kI7KCLUA8DhRZftXmxeLbO3JNMNuS3
fgJUtyoqGtN0aPmBLdCZUci/V4SgCmiaDSZ+7OcCgYEAiGa8His7SoFVi1qu3587
25DnJT2vE0VJhovOq8nQ8RCx5xlckp3VTmjBIea5+1x6ngESY9Bs0NifcjcY7ehh
N4QOWexEnss7XdYV0Iq0dB4t/hOq2I8x8oPXPXx22vUJo6cBpAKtkFOtYtAtk0M0
zP0dFgicaESjmOVuDpWwBkECgYAoeRgxFLqOv01HV6RTT5ZEa5hgCQqyCOaBAY/2
Tg5u7IyDMqAWGCU3NO/gTEVBCJEqvsxzgSJ/W90GUzEjfcHfGs40JkOCfm35GRZL
P5M6+MZFI9ylG1pb13Q9m7mxlYS3tMeUJJZmYm2aoKRj0iD9zmDf1g0Em6ys0s9f
XthWWQKBgCzrMwdf/espAgKROSB/QLK24ZKhTNJo10jwNfLhHJpLX0goqtj5WQIE
TBP111fOMBU3rv+GZupO9xT+UJfhJXoYLTxESAXGs5ACxWU45h6GFMItq846AdFl
e6G/ZQNhCSnz73FF1slMP8dfSDO0THdBr/HsnDXiXquKtcLMdbvI
-----END RSA PRIVATE KEY-----'''

# Configure Flask-GitHubApp
app.config['GITHUBAPP_ID'] = os.getenv("GITHUB_APP_ID", "1513443")
app.config['GITHUBAPP_KEY'] = PRIVATE_KEY
app.config['GITHUBAPP_SECRET'] = os.getenv("GITHUB_WEBHOOK_SECRET", "arulprakash01")

github_app = GitHubApp(app)

GITHUB_APP_ID = int(app.config['GITHUBAPP_ID'])
WEBHOOK_SECRET = app.config['GITHUBAPP_SECRET']

class SecurityScanner:
    """Enhanced security scanner with comprehensive vulnerability detection"""
    
    def __init__(self):
        self.findings = []
        self.scan_summary = {
            'total_issues': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'languages_scanned': []
        }
    
    def scan_with_bandit(self) -> Dict[str, Any]:
        """Scan Python code with Bandit"""
        try:
            if not glob.glob("**/*.py", recursive=True):
                return {'output': '', 'error': None}
            
            result = subprocess.run(
                ["bandit", "-r", ".", "-f", "json", "-ll"], 
                capture_output=True, 
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                try:
                    bandit_results = json.loads(result.stdout)
                    self._process_bandit_results(bandit_results)
                    return {'output': result.stdout, 'error': None}
                except json.JSONDecodeError:
                    return {'output': result.stdout, 'error': 'Failed to parse Bandit JSON output'}
            else:
                return {'output': result.stdout, 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'output': '', 'error': 'Bandit scan timed out'}
        except Exception as e:
            return {'output': '', 'error': f'Bandit scan failed: {str(e)}'}
    
    def scan_with_eslint(self) -> Dict[str, Any]:
        """Scan JavaScript/TypeScript code with ESLint"""
        try:
            js_files = glob.glob("**/*.js", recursive=True)
            ts_files = glob.glob("**/*.ts", recursive=True)
            
            if not js_files and not ts_files:
                return {'output': '', 'error': None}
            
            # Check if ESLint is available
            try:
                eslint_check = subprocess.run(["npx", "eslint", "--version"], capture_output=True, timeout=10)
                if eslint_check.returncode != 0:
                    return {'output': '', 'error': 'ESLint not available - Node.js/npm not installed'}
            except FileNotFoundError:
                return {'output': '', 'error': 'ESLint not available - Node.js/npm not installed'}
            
            result = subprocess.run(
                ["npx", "eslint", ".", "--format", "json", "--ext", ".js,.ts,.jsx,.tsx"], 
                capture_output=True, 
                text=True,
                timeout=300
            )
            
            if result.returncode in [0, 1]:  # ESLint returns 1 when issues are found
                try:
                    eslint_results = json.loads(result.stdout)
                    self._process_eslint_results(eslint_results)
                    return {'output': result.stdout, 'error': None}
                except json.JSONDecodeError:
                    return {'output': result.stdout, 'error': 'Failed to parse ESLint JSON output'}
            else:
                return {'output': result.stdout, 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'output': '', 'error': 'ESLint scan timed out'}
        except Exception as e:
            return {'output': '', 'error': f'ESLint scan failed: {str(e)}'}
    
    def scan_with_gosec(self) -> Dict[str, Any]:
        """Scan Go code with gosec"""
        try:
            if not glob.glob("**/*.go", recursive=True):
                return {'output': '', 'error': None}
            
            # Check if gosec is available
            try:
                gosec_check = subprocess.run(["gosec", "--version"], capture_output=True, timeout=10)
                if gosec_check.returncode != 0:
                    return {'output': '', 'error': 'gosec not available - Go not installed'}
            except FileNotFoundError:
                return {'output': '', 'error': 'gosec not available - Go not installed'}
            
            result = subprocess.run(
                ["gosec", "-fmt=json", "./..."], 
                capture_output=True, 
                text=True,
                timeout=300
            )
            
            if result.returncode in [0, 1]:  # gosec returns 1 when issues are found
                try:
                    gosec_results = json.loads(result.stdout)
                    self._process_gosec_results(gosec_results)
                    return {'output': result.stdout, 'error': None}
                except json.JSONDecodeError:
                    return {'output': result.stdout, 'error': 'Failed to parse gosec JSON output'}
            else:
                return {'output': result.stdout, 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'output': '', 'error': 'gosec scan timed out'}
        except Exception as e:
            return {'output': '', 'error': f'gosec scan failed: {str(e)}'}
    
    def scan_with_semgrep(self) -> Dict[str, Any]:
        """Scan with Semgrep for additional security patterns"""
        try:
            result = subprocess.run(
                ["semgrep", "--json", "--config=auto"], 
                capture_output=True, 
                text=True,
                timeout=300
            )
            
            if result.returncode in [0, 1]:
                try:
                    semgrep_results = json.loads(result.stdout)
                    self._process_semgrep_results(semgrep_results)
                    return {'output': result.stdout, 'error': None}
                except json.JSONDecodeError:
                    return {'output': result.stdout, 'error': 'Failed to parse Semgrep JSON output'}
            else:
                return {'output': result.stdout, 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'output': '', 'error': 'Semgrep scan timed out'}
        except Exception as e:
            return {'output': '', 'error': f'Semgrep scan failed: {str(e)}'}
    
    def _process_bandit_results(self, results: Dict[str, Any]):
        """Process Bandit scan results"""
        if 'results' in results:
            for issue in results['results']:
                severity = self._map_bandit_severity(issue.get('issue_severity', 'LOW'))
                self.findings.append({
                    'tool': 'Bandit',
                    'severity': severity,
                    'file': issue.get('filename', 'Unknown'),
                    'line': issue.get('line_number', 0),
                    'message': issue.get('issue_text', 'Unknown issue'),
                    'code': issue.get('code', ''),
                    'cwe': issue.get('issue_cwe', {}).get('id', ''),
                    'description': issue.get('more_info', '')
                })
                self._update_summary(severity)
            self.scan_summary['languages_scanned'].append('Python')
    
    def _process_eslint_results(self, results: List[Dict[str, Any]]):
        """Process ESLint scan results"""
        security_rules = [
            'no-eval', 'no-implied-eval', 'no-new-func', 'no-script-url',
            'no-unsafe-finally', 'no-unsafe-negation', 'no-unsafe-optional-chaining'
        ]
        
        for file_result in results:
            for message in file_result.get('messages', []):
                if message.get('ruleId') in security_rules or 'security' in message.get('message', '').lower():
                    severity = self._map_eslint_severity(message.get('severity', 1))
                    self.findings.append({
                        'tool': 'ESLint',
                        'severity': severity,
                        'file': file_result.get('filePath', 'Unknown'),
                        'line': message.get('line', 0),
                        'message': message.get('message', 'Unknown issue'),
                        'code': message.get('ruleId', ''),
                        'cwe': '',
                        'description': message.get('message', '')
                    })
                    self._update_summary(severity)
        
        if results:
            self.scan_summary['languages_scanned'].append('JavaScript/TypeScript')
    
    def _process_gosec_results(self, results: Dict[str, Any]):
        """Process gosec scan results"""
        if 'Issues' in results:
            for issue in results['Issues']:
                severity = self._map_gosec_severity(issue.get('severity', 'LOW'))
                self.findings.append({
                    'tool': 'gosec',
                    'severity': severity,
                    'file': issue.get('file', 'Unknown'),
                    'line': issue.get('line', 0),
                    'message': issue.get('details', 'Unknown issue'),
                    'code': issue.get('code', ''),
                    'cwe': issue.get('cwe', {}).get('ID', ''),
                    'description': issue.get('details', '')
                })
                self._update_summary(severity)
            self.scan_summary['languages_scanned'].append('Go')
    
    def _process_semgrep_results(self, results: Dict[str, Any]):
        """Process Semgrep scan results"""
        if 'results' in results:
            for issue in results['results']:
                severity = self._map_semgrep_severity(issue.get('extra', {}).get('severity', 'WARNING'))
                self.findings.append({
                    'tool': 'Semgrep',
                    'severity': severity,
                    'file': issue.get('path', 'Unknown'),
                    'line': issue.get('start', {}).get('line', 0),
                    'message': issue.get('extra', {}).get('message', 'Unknown issue'),
                    'code': issue.get('extra', {}).get('rule_id', ''),
                    'cwe': '',
                    'description': issue.get('extra', {}).get('message', '')
                })
                self._update_summary(severity)
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to standard levels"""
        mapping = {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
        return mapping.get(severity.upper(), 'LOW')
    
    def _map_eslint_severity(self, severity: int) -> str:
        """Map ESLint severity to standard levels"""
        mapping = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH'}
        return mapping.get(severity, 'LOW')
    
    def _map_gosec_severity(self, severity: str) -> str:
        """Map gosec severity to standard levels"""
        mapping = {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'}
        return mapping.get(severity.upper(), 'LOW')
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standard levels"""
        mapping = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
        return mapping.get(severity.upper(), 'LOW')
    
    def _update_summary(self, severity: str):
        """Update scan summary with new finding"""
        self.scan_summary['total_issues'] += 1
        if severity == 'HIGH':
            self.scan_summary['high_severity'] += 1
        elif severity == 'MEDIUM':
            self.scan_summary['medium_severity'] += 1
        else:
            self.scan_summary['low_severity'] += 1
    
    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan with detailed logging"""
        logger.info("🔍 Starting comprehensive security scan...")
        
        # Reset findings and summary
        self.findings = []
        self.scan_summary = {
            'total_issues': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'languages_scanned': []
        }
        
        scan_results = {}
        
        # Scan with Bandit (Python)
        logger.info("🐍 Scanning Python code with Bandit...")
        log_tool_execution("bandit", "STARTED")
        bandit_result = self.scan_with_bandit()
        scan_results['bandit'] = bandit_result
        if bandit_result['error']:
            logger.warning(f"⚠️ Bandit scan error: {bandit_result['error']}")
            log_tool_execution("bandit", "FAILED", bandit_result['error'])
        else:
            logger.info("✅ Bandit scan completed")
            log_tool_execution("bandit", "COMPLETED")
            if 'python' not in self.scan_summary['languages_scanned']:
                self.scan_summary['languages_scanned'].append('python')
        
        # Scan with ESLint (JavaScript/TypeScript)
        logger.info("📜 Scanning JavaScript/TypeScript code with ESLint...")
        log_tool_execution("eslint", "STARTED")
        eslint_result = self.scan_with_eslint()
        scan_results['eslint'] = eslint_result
        if eslint_result['error']:
            logger.warning(f"⚠️ ESLint scan error: {eslint_result['error']}")
            log_tool_execution("eslint", "FAILED", eslint_result['error'])
        else:
            logger.info("✅ ESLint scan completed")
            log_tool_execution("eslint", "COMPLETED")
            if 'javascript' not in self.scan_summary['languages_scanned']:
                self.scan_summary['languages_scanned'].append('javascript')
        
        # Scan with gosec (Go)
        logger.info("🐹 Scanning Go code with gosec...")
        log_tool_execution("gosec", "STARTED")
        gosec_result = self.scan_with_gosec()
        scan_results['gosec'] = gosec_result
        if gosec_result['error']:
            logger.warning(f"⚠️ gosec scan error: {gosec_result['error']}")
            log_tool_execution("gosec", "FAILED", gosec_result['error'])
        else:
            logger.info("✅ gosec scan completed")
            log_tool_execution("gosec", "COMPLETED")
            if 'go' not in self.scan_summary['languages_scanned']:
                self.scan_summary['languages_scanned'].append('go')
        
        # Scan with Semgrep (Multi-language)
        logger.info("🔍 Scanning with Semgrep (multi-language)...")
        log_tool_execution("semgrep", "STARTED")
        semgrep_result = self.scan_with_semgrep()
        scan_results['semgrep'] = semgrep_result
        if semgrep_result['error']:
            logger.warning(f"⚠️ Semgrep scan error: {semgrep_result['error']}")
            log_tool_execution("semgrep", "FAILED", semgrep_result['error'])
        else:
            logger.info("✅ Semgrep scan completed")
            log_tool_execution("semgrep", "COMPLETED")
        
        # Log scan summary
        logger.info("📊 Security scan summary:")
        logger.info(f"   Total findings: {len(self.findings)}")
        logger.info(f"   High severity: {self.scan_summary['high_severity']}")
        logger.info(f"   Medium severity: {self.scan_summary['medium_severity']}")
        logger.info(f"   Low severity: {self.scan_summary['low_severity']}")
        logger.info(f"   Languages scanned: {', '.join(self.scan_summary['languages_scanned'])}")
        
        return {
            'findings': self.findings,
            'summary': self.scan_summary,
            'scan_results': scan_results
        }

class GitHubIssueReporter:
    """Handles GitHub issue creation and management"""
    
    def __init__(self, github_client: Github, repo_name: str):
        self.github = github_client
        self.repo = github_client.get_repo(repo_name)
    
    def create_security_report_issue(self, scan_results: Dict[str, Any], pr_number: Optional[int] = None) -> str:
        """Create a comprehensive security report issue"""
        title = f"🔒 Security Vulnerability Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        body = self._generate_issue_body(scan_results, pr_number)
        
        # Create labels for the issue
        labels = ['security', 'automated-scan']
        if scan_results['summary']['high_severity'] > 0:
            labels.append('high-priority')
        if scan_results['summary']['total_issues'] == 0:
            labels.append('no-vulnerabilities')
        
        # Create the issue
        issue = self.repo.create_issue(
            title=title,
            body=body,
            labels=labels
        )
        
        return issue.html_url
    
    def _generate_issue_body(self, scan_results: Dict[str, Any], pr_number: Optional[int] = None) -> str:
        """Generate a professional security report issue body"""
        findings = scan_results['findings']
        summary = scan_results['summary']
        scan_results_detail = scan_results.get('scan_results', {})
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(summary)
        
        # Generate issue body
        body = f"""# 🔒 Security Assessment Report

## 📋 Executive Summary

**Risk Level:** {risk_level}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Total Security Issues:** {summary['total_issues']}  
**Languages Analyzed:** {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None detected'}

{f"**Related Pull Request:** #{pr_number}" if pr_number else ""}

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
                body += f"- ❌ **{tool.upper()}:** {result['error']}\n"
            else:
                body += f"- ✅ **{tool.upper()}:** Successfully scanned\n"
                tools_used.append(tool)
        
        body += f"""
**Total Tools Successfully Executed:** {len(tools_used)}

---

## 🔍 Detailed Vulnerability Analysis
"""
        
        if findings:
            body += self._format_findings_table(findings)
        else:
            body += """
### ✅ No Security Vulnerabilities Detected

**Assessment Result:** Your code has passed all security checks!  
**Recommendation:** Continue following security best practices in future development.

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
                body += """
**Python:**
- Use virtual environments for dependency isolation
- Regularly update pip and packages
- Follow PEP 8 security guidelines
- Use `bandit` for automated security testing
"""
            
            if 'javascript' in summary['languages_scanned']:
                body += """
**JavaScript/TypeScript:**
- Use npm audit for dependency vulnerability scanning
- Implement Content Security Policy (CSP)
- Validate and sanitize all user inputs
- Use HTTPS for all external requests
"""
            
            if 'go' in summary['languages_scanned']:
                body += """
**Go:**
- Use `go mod tidy` to clean dependencies
- Run `gosec` for security analysis
- Validate all user inputs
- Use context for request cancellation
"""

        body += f"""
---

## 📈 Risk Assessment

**Overall Risk Level:** {risk_level}

### Risk Factors Considered
- Number and severity of vulnerabilities
- Types of security issues detected
- Code complexity and attack surface
- Language-specific security considerations

### Next Steps
"""
        
        if summary['high_severity'] > 0:
            body += """
🚨 **IMMEDIATE ACTION REQUIRED**
1. **Address Critical Issues:** Fix all high-severity vulnerabilities before deployment
2. **Security Review:** Conduct thorough security code review
3. **Testing:** Perform additional security testing
4. **Documentation:** Document security fixes and lessons learned
"""
        elif summary['medium_severity'] > 0:
            body += """
⚠️ **HIGH PRIORITY ACTION**
1. **Address Medium Issues:** Fix medium-severity vulnerabilities
2. **Code Review:** Review affected code sections
3. **Testing:** Verify fixes with security testing
4. **Monitoring:** Implement additional security monitoring
"""
        elif summary['low_severity'] > 0:
            body += """
ℹ️ **RECOMMENDED ACTION**
1. **Address Low Issues:** Fix low-severity issues as part of regular development
2. **Code Review:** Review for potential improvements
3. **Documentation:** Document security improvements
"""
        else:
            body += """
✅ **MAINTAIN SECURITY STANDARDS**
1. **Continue Best Practices:** Maintain current security practices
2. **Regular Scanning:** Continue automated security scanning
3. **Team Training:** Keep team updated on security best practices
4. **Monitoring:** Monitor for new security threats
"""

        body += f"""
---

## 🔧 Technical Details

### Scan Configuration
- **Scan Duration:** {datetime.now().strftime('%H:%M:%S')}
- **Tools Executed:** {', '.join(tools_used) if tools_used else 'None'}
- **Scan Coverage:** Full repository analysis
- **Report Format:** GitHub Issue

### Security Standards Compliance
- ✅ **OWASP Top 10:** Checked for common web vulnerabilities
- ✅ **CWE/SANS Top 25:** Analyzed for critical software weaknesses
- ✅ **Language-Specific:** Applied language-specific security rules
- ✅ **Custom Rules:** Applied project-specific security policies

---

## 📞 Support & Resources

**Security Team Contact:** [Contact your security team]  
**Documentation:** [Link to security guidelines]  
**Training Resources:** [Link to security training]  
**Emergency Contact:** [Security incident response contact]

---

*This report was generated automatically by the Security Code Reviewer AI. For questions or concerns, please contact the security team.*

**Report ID:** {datetime.now().strftime('%Y%m%d-%H%M%S')}  
**Generated:** {datetime.now().isoformat()} UTC
"""
        
        return body
    
    def _calculate_risk_level(self, summary: Dict[str, Any]) -> str:
        """Calculate overall risk level based on findings"""
        if summary['high_severity'] > 0:
            return "🔴 **CRITICAL** - Immediate action required"
        elif summary['medium_severity'] > 0:
            return "🟡 **MEDIUM** - Review and address promptly"
        elif summary['low_severity'] > 0:
            return "🟢 **LOW** - Monitor and address as needed"
        else:
            return "✅ **SECURE** - No vulnerabilities detected"

    def _format_findings_table(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings as a professional markdown table"""
        if not findings:
            return "✅ **No security vulnerabilities detected in this assessment.**\n"
        
        table = "| **Tool** | **File** | **Line** | **Severity** | **Vulnerability** | **CWE** |\n"
        table += "|----------|----------|----------|--------------|-------------------|---------|\n"
        
        for finding in findings:
            file_path = finding['file'].replace('\\', '/')
            severity_icon = "🔴" if finding['severity'] == 'HIGH' else "🟡" if finding['severity'] == 'MEDIUM' else "🟢"
            cwe = finding.get('cwe', 'N/A')
            message = finding['message'][:80] + "..." if len(finding['message']) > 80 else finding['message']
            
            table += f"| {finding['tool']} | `{file_path}` | {finding['line']} | {severity_icon} {finding['severity']} | {message} | {cwe} |\n"
        
        return table

def aggregate_findings():
    """Legacy function for backward compatibility"""
    scanner = SecurityScanner()
    results = scanner.run_comprehensive_scan()
    return results

def create_or_update_issue(repo, findings):
    """Legacy function for backward compatibility"""
    reporter = GitHubIssueReporter(Github(), repo.full_name)
    reporter.create_security_report_issue(findings)

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    """Handle incoming webhooks from GitHub"""
    try:
        # Get the webhook payload
        payload = request.get_json()
        event_type = request.headers.get('X-GitHub-Event')
        
        logger.info(f"Received webhook: {event_type}")
        
        # Log webhook event
        log_webhook_event(event_type, payload, "received")
        
        # Handle installation events (when users install your app)
        if event_type == 'installation':
            action = payload.get('action')
            if action == 'created':
                logger.info(f"GitHub App installed in repository: {payload.get('repositories', [])}")
                # You can add logic here to welcome the user or set up initial scans
                return "", 200
        
        # Handle pull request events
        if event_type == 'pull_request':
            action = payload.get('action')
            if action in ['opened', 'synchronize', 'reopened']:
                logger.info(f"Processing PR {action} event")
                return on_pull_request(payload, "webhook")
        
        return "", 200
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        log_error("WEBHOOK_HANDLER", str(e), f"Event: {event_type}")
        return "", 500

@github_app.on("pull_request")
def on_pull_request(data, guid):
    """Enhanced pull request webhook handler with comprehensive security scanning"""
    action = data["action"]
    if action not in ["opened", "synchronize", "reopened"]:
        return "", 204

    try:
        repo_full_name = data["repository"]["full_name"]
        pr_number = data["number"]
        installation_id = data["installation"]["id"]
        pr_title = data["pull_request"]["title"]
        pr_author = data["pull_request"]["user"]["login"]

        logger.info(f"🚀 Starting security scan for PR #{pr_number} in {repo_full_name}")
        logger.info(f"  Title: {pr_title}")
        logger.info(f"  Author: {pr_author}")
        logger.info(f"  Action: {action}")

        # Log scan start with detailed information
        log_security_scan_start(pr_number, repo_full_name)

        # Setup GitHub client with proper authentication
        try:
            logger.info("🔐 Authenticating with GitHub API...")
            integration = GithubIntegration(GITHUB_APP_ID, PRIVATE_KEY)
            access_token = integration.get_access_token(installation_id).token
            g = Github(access_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            logger.info("✅ Successfully authenticated with GitHub API")
        except Exception as auth_error:
            error_msg = f"GitHub authentication failed: {str(auth_error)}"
            logger.error(error_msg)
            log_error("AUTHENTICATION", str(auth_error), f"PR #{pr_number}")
            return "", 500

        # Clone and checkout PR
        try:
            logger.info(f"📥 Cloning repository for PR #{pr_number}...")
            os.system("rm -rf repo && mkdir repo")
            clone_result = os.system(f"git clone {pr.head.repo.clone_url} repo")
            if clone_result != 0:
                raise Exception("Failed to clone repository")
            os.chdir("repo")
            fetch_result = os.system(f"git fetch origin pull/{pr_number}/head:pr_branch")
            if fetch_result != 0:
                raise Exception("Failed to fetch PR branch")
            checkout_result = os.system("git checkout pr_branch")
            if checkout_result != 0:
                raise Exception("Failed to checkout PR branch")
            logger.info(f"✅ Repository cloned and checked out successfully")
            # Log repository information
            logger.info(f"📁 Repository structure:")
            for root, dirs, files in os.walk(".", topdown=True):
                level = root.replace(".", "").count(os.sep)
                indent = " " * 2 * level
                logger.info(f"{indent}{os.path.basename(root)}/")
                subindent = " " * 2 * (level + 1)
                for file in files[:10]:  # Limit to first 10 files per directory
                    logger.info(f"{subindent}{file}")
                if len(files) > 10:
                    logger.info(f"{subindent}... and {len(files) - 10} more files")
        except Exception as clone_error:
            error_msg = f"Repository cloning failed: {str(clone_error)}"
            logger.error(error_msg)
            log_error("REPOSITORY_CLONE", str(clone_error), f"PR #{pr_number}")
            return "", 500

        # Run comprehensive security scan
        try:
            logger.info(f"🔍 Starting comprehensive security scan for PR #{pr_number}...")
            scanner = SecurityScanner()
            scan_results = scanner.run_comprehensive_scan()
            # Log scan completion with detailed results
            log_security_scan_complete(pr_number, scan_results)
            logger.info(f"✅ Scan completed successfully")
            logger.info(f"📊 Scan Results Summary:")
            logger.info(f"   Total Issues: {scan_results['summary']['total_issues']}")
            logger.info(f"   High Severity: {scan_results['summary']['high_severity']}")
            logger.info(f"   Medium Severity: {scan_results['summary']['medium_severity']}")
            logger.info(f"   Low Severity: {scan_results['summary']['low_severity']}")
            logger.info(f"   Languages Scanned: {', '.join(scan_results['summary']['languages_scanned'])}")
        except Exception as scan_error:
            error_msg = f"Security scan failed: {str(scan_error)}"
            logger.error(error_msg)
            log_error("SECURITY_SCAN", str(scan_error), f"PR #{pr_number}")
            return "", 500

        # Create GitHub issue reporter and generate report
        try:
            logger.info(f"📝 Creating security report issue for PR #{pr_number}...")
            log_report_generation_start(pr_number)
            reporter = GitHubIssueReporter(g, repo_full_name)
            # Create security report issue
            issue_url = reporter.create_security_report_issue(scan_results, pr_number)
            logger.info(f"✅ Security report issue created: {issue_url}")
            # Log issue creation
            log_github_issue_created(pr_number, issue_url)
            log_report_generation_complete(pr_number, "github_issue")
        except Exception as report_error:
            error_msg = f"Report generation failed: {str(report_error)}"
            logger.error(error_msg)
            log_error("REPORT_GENERATION", str(report_error), f"PR #{pr_number}")
            return "", 500

        # Comment on PR with summary
        try:
            logger.info(f"💬 Posting summary comment on PR #{pr_number}...")
            summary = scan_results['summary']
            risk_level = "🔴 CRITICAL" if summary['high_severity'] > 0 else "🟡 MEDIUM" if summary['medium_severity'] > 0 else "🟢 LOW" if summary['low_severity'] > 0 else "✅ SECURE"
            comment_body = f"""## 🔒 Security Assessment Complete

### 📊 Assessment Summary
- **Risk Level:** {risk_level}
- **Total Issues:** {summary['total_issues']}
- **Critical/High:** {summary['high_severity']} 🔴
- **Medium:** {summary['medium_severity']} 🟡
- **Low:** {summary['low_severity']} 🟢

**Languages Analyzed:** {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None detected'}

### 📋 Detailed Report
**Comprehensive Security Assessment:** {issue_url}

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
            pr.create_issue_comment(comment_body)
            # Log comment posting
            log_github_comment_posted(pr_number, summary)
            logger.info(f"✅ Summary comment posted successfully")
        except Exception as comment_error:
            error_msg = f"PR comment posting failed: {str(comment_error)}"
            logger.error(error_msg)
            log_error("PR_COMMENT", str(comment_error), f"PR #{pr_number}")

        # Cleanup
        try:
            logger.info(f"🧹 Cleaning up temporary files...")
            os.chdir("..")
            cleanup_result = os.system("rm -rf repo")
            if cleanup_result == 0:
                logger.info(f"✅ Cleanup completed successfully")
            else:
                logger.warning(f"⚠️ Cleanup had issues (exit code: {cleanup_result})")
        except Exception as cleanup_error:
            logger.warning(f"⚠️ Cleanup failed: {str(cleanup_error)}")
        logger.info(f"🎉 Successfully completed security assessment for PR #{pr_number}")
        return "", 200

    except Exception as e:
        error_msg = f"Error processing PR: {str(e)}"
        logger.error(error_msg)
        log_error("PR_PROCESSING", str(e), f"PR #{pr_number}")
        try:
            os.chdir("..")
            os.system("rm -rf repo")
        except Exception:
            pass
        return "", 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/scan', methods=['POST'])
def manual_scan():
    """Manual scan endpoint for testing"""
    try:
        data = request.get_json()
        repo_url = data.get('repo_url')
        
        if not repo_url:
            return jsonify({'error': 'repo_url is required'}), 400
        
        # Clone repo
        os.system("rm -rf manual_scan && mkdir manual_scan")
        os.chdir("manual_scan")
        os.system(f"git clone {repo_url} .")
        
        # Run scan
        scanner = SecurityScanner()
        results = scanner.run_comprehensive_scan()
        
        # Cleanup
        os.chdir("..")
        os.system("rm -rf manual_scan")
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    # Run on all interfaces for ngrok
    app.run(host='0.0.0.0', port=5000, debug=True)