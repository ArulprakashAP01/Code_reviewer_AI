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

PRIVATE_KEY = 
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
        """Run comprehensive security scan with all available tools"""
        logger.info("🔍 Starting comprehensive security scan...")
        
        # Reset findings and summary
        self.findings = []
        self.scan_summary = {
            'total_issues': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'languages_scanned': [],
            'tools_executed': [],
            'scan_duration': 0,
            'files_scanned': 0
        }
        
        start_time = datetime.now()
        
        # Detect languages and files to scan
        detected_languages = self._detect_languages()
        self.scan_summary['languages_scanned'] = detected_languages
        
        logger.info(f"📁 Detected languages: {', '.join(detected_languages)}")
        
        # Count files for each language
        file_counts = self._count_files_by_language()
        total_files = sum(file_counts.values())
        self.scan_summary['files_scanned'] = total_files
        
        logger.info(f"📊 Files to scan: {total_files}")
        for lang, count in file_counts.items():
            if count > 0:
                logger.info(f"  {lang}: {count} files")
        
        # Run security scans based on detected languages
        scan_results = {}
        
        # Python scanning with Bandit
        if 'Python' in detected_languages:
            logger.info("🐍 Scanning Python code with Bandit...")
            log_tool_execution("bandit", "started")
            bandit_result = self.scan_with_bandit()
            scan_results['bandit'] = bandit_result
            self.scan_summary['tools_executed'].append('bandit')
            if bandit_result['error']:
                log_tool_execution("bandit", "failed", bandit_result['error'])
                logger.warning(f"⚠️ Bandit scan failed: {bandit_result['error']}")
            else:
                log_tool_execution("bandit", "completed")
                logger.info("✅ Bandit scan completed")
        
        # JavaScript/TypeScript scanning with ESLint
        if 'JavaScript' in detected_languages or 'TypeScript' in detected_languages:
            logger.info("🟨 Scanning JavaScript/TypeScript code with ESLint...")
            log_tool_execution("eslint", "started")
            eslint_result = self.scan_with_eslint()
            scan_results['eslint'] = eslint_result
            self.scan_summary['tools_executed'].append('eslint')
            if eslint_result['error']:
                log_tool_execution("eslint", "failed", eslint_result['error'])
                logger.warning(f"⚠️ ESLint scan failed: {eslint_result['error']}")
            else:
                log_tool_execution("eslint", "completed")
                logger.info("✅ ESLint scan completed")
        
        # Go scanning with gosec
        if 'Go' in detected_languages:
            logger.info("🔵 Scanning Go code with gosec...")
            log_tool_execution("gosec", "started")
            gosec_result = self.scan_with_gosec()
            scan_results['gosec'] = gosec_result
            self.scan_summary['tools_executed'].append('gosec')
            if gosec_result['error']:
                log_tool_execution("gosec", "failed", gosec_result['error'])
                logger.warning(f"⚠️ gosec scan failed: {gosec_result['error']}")
            else:
                log_tool_execution("gosec", "completed")
                logger.info("✅ gosec scan completed")
        
        # Universal scanning with Semgrep
        logger.info("🔍 Running universal security scan with Semgrep...")
        log_tool_execution("semgrep", "started")
        semgrep_result = self.scan_with_semgrep()
        scan_results['semgrep'] = semgrep_result
        self.scan_summary['tools_executed'].append('semgrep')
        if semgrep_result['error']:
            log_tool_execution("semgrep", "failed", semgrep_result['error'])
            logger.warning(f"⚠️ Semgrep scan failed: {semgrep_result['error']}")
        else:
            log_tool_execution("semgrep", "completed")
            logger.info("✅ Semgrep scan completed")
        
        # Additional security checks
        logger.info("🔒 Running additional security checks...")
        additional_findings = self._run_additional_checks()
        if additional_findings:
            self.findings.extend(additional_findings)
            logger.info(f"✅ Additional checks found {len(additional_findings)} issues")
        
        # Calculate scan duration
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        self.scan_summary['scan_duration'] = scan_duration
        
        # Update summary counts
        for finding in self.findings:
            self._update_summary(finding['severity'])
        
        logger.info(f"🎉 Comprehensive scan completed in {scan_duration:.2f} seconds")
        logger.info(f"📊 Scan Summary:")
        logger.info(f"   Total Issues: {self.scan_summary['total_issues']}")
        logger.info(f"   High Severity: {self.scan_summary['high_severity']}")
        logger.info(f"   Medium Severity: {self.scan_summary['medium_severity']}")
        logger.info(f"   Low Severity: {self.scan_summary['low_severity']}")
        logger.info(f"   Tools Executed: {', '.join(self.scan_summary['tools_executed'])}")
        logger.info(f"   Files Scanned: {self.scan_summary['files_scanned']}")
        
        return {
            'summary': self.scan_summary,
            'findings': self.findings,
            'scan_results': scan_results,
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_languages(self) -> List[str]:
        """Detect programming languages in the codebase"""
        languages = []
        
        # Check for Python files
        if glob.glob("**/*.py", recursive=True):
            languages.append("Python")
        
        # Check for JavaScript files
        if glob.glob("**/*.js", recursive=True) or glob.glob("**/*.jsx", recursive=True):
            languages.append("JavaScript")
        
        # Check for TypeScript files
        if glob.glob("**/*.ts", recursive=True) or glob.glob("**/*.tsx", recursive=True):
            languages.append("TypeScript")
        
        # Check for Go files
        if glob.glob("**/*.go", recursive=True):
            languages.append("Go")
        
        # Check for Java files
        if glob.glob("**/*.java", recursive=True):
            languages.append("Java")
        
        # Check for C/C++ files
        if glob.glob("**/*.c", recursive=True) or glob.glob("**/*.cpp", recursive=True) or glob.glob("**/*.h", recursive=True):
            languages.append("C/C++")
        
        # Check for PHP files
        if glob.glob("**/*.php", recursive=True):
            languages.append("PHP")
        
        # Check for Ruby files
        if glob.glob("**/*.rb", recursive=True):
            languages.append("Ruby")
        
        # Check for Rust files
        if glob.glob("**/*.rs", recursive=True):
            languages.append("Rust")
        
        return languages
    
    def _count_files_by_language(self) -> Dict[str, int]:
        """Count files by programming language"""
        counts = {}
        
        # Python files
        counts['Python'] = len(glob.glob("**/*.py", recursive=True))
        
        # JavaScript files
        counts['JavaScript'] = len(glob.glob("**/*.js", recursive=True)) + len(glob.glob("**/*.jsx", recursive=True))
        
        # TypeScript files
        counts['TypeScript'] = len(glob.glob("**/*.ts", recursive=True)) + len(glob.glob("**/*.tsx", recursive=True))
        
        # Go files
        counts['Go'] = len(glob.glob("**/*.go", recursive=True))
        
        # Java files
        counts['Java'] = len(glob.glob("**/*.java", recursive=True))
        
        # C/C++ files
        counts['C/C++'] = len(glob.glob("**/*.c", recursive=True)) + len(glob.glob("**/*.cpp", recursive=True)) + len(glob.glob("**/*.h", recursive=True))
        
        # PHP files
        counts['PHP'] = len(glob.glob("**/*.php", recursive=True))
        
        # Ruby files
        counts['Ruby'] = len(glob.glob("**/*.rb", recursive=True))
        
        # Rust files
        counts['Rust'] = len(glob.glob("**/*.rs", recursive=True))
        
        return counts
    
    def _run_additional_checks(self) -> List[Dict[str, Any]]:
        """Run additional security checks beyond tool-based scanning"""
        additional_findings = []
        
        # Check for hardcoded secrets
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password detected'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key detected'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret detected'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token detected'),
            (r'private_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded private key detected'),
            (r'-----BEGIN\s+PRIVATE\s+KEY-----', 'Private key in code detected'),
            (r'-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----', 'RSA private key in code detected'),
            (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', 'SSH private key in code detected'),
        ]
        
        for pattern, message in secret_patterns:
            for file_path in glob.glob("**/*", recursive=True):
                if os.path.isfile(file_path) and not self._should_skip_file(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                additional_findings.append({
                                    'tool': 'Manual Check',
                                    'severity': 'high',
                                    'message': message,
                                    'file': file_path,
                                    'line': line_number,
                                    'code': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0),
                                    'cwe': 'CWE-259'
                                })
                    except Exception:
                        continue
        
        # Check for dangerous file operations
        dangerous_patterns = [
            (r'os\.remove\(', 'Dangerous file deletion operation'),
            (r'os\.unlink\(', 'Dangerous file deletion operation'),
            (r'shutil\.rmtree\(', 'Dangerous directory deletion operation'),
            (r'rm\s+-rf', 'Dangerous recursive deletion command'),
            (r'del\s+/s\s+/q', 'Dangerous recursive deletion command'),
        ]
        
        for pattern, message in dangerous_patterns:
            for file_path in glob.glob("**/*", recursive=True):
                if os.path.isfile(file_path) and not self._should_skip_file(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                additional_findings.append({
                                    'tool': 'Manual Check',
                                    'severity': 'medium',
                                    'message': message,
                                    'file': file_path,
                                    'line': line_number,
                                    'code': match.group(0)[:100] + '...' if len(match.group(0)) > 100 else match.group(0),
                                    'cwe': 'CWE-73'
                                })
                    except Exception:
                        continue
        
        return additional_findings
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped during scanning"""
        skip_patterns = [
            r'\.git/',
            r'node_modules/',
            r'__pycache__/',
            r'\.pyc$',
            r'\.log$',
            r'\.tmp$',
            r'\.cache/',
            r'\.vscode/',
            r'\.idea/',
            r'\.DS_Store$',
            r'\.env$',
            r'\.env\.',
            r'package-lock\.json$',
            r'yarn\.lock$',
            r'\.min\.js$',
            r'\.min\.css$',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, file_path):
                return True
        
        return False

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
        """Generate comprehensive security report issue body"""
        summary = scan_results['summary']
        findings = scan_results['findings']
        scan_results_detail = scan_results.get('scan_results', {})
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(summary)
        
        # Generate issue body
        body = f"""# 🔒 Security Assessment Report

## 📊 Executive Summary

**Risk Level:** {risk_level}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Total Issues Found:** {summary['total_issues']}  
**Files Scanned:** {summary['files_scanned']}  
**Scan Duration:** {summary['scan_duration']:.2f} seconds  

{f"**Related PR:** #{pr_number}" if pr_number else ""}

### 🎯 Risk Assessment
- **🔴 Critical/High Severity:** {summary['high_severity']} issues
- **🟡 Medium Severity:** {summary['medium_severity']} issues  
- **🟢 Low Severity:** {summary['low_severity']} issues

### 🔍 Languages & Tools
**Languages Analyzed:** {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None detected'}  
**Security Tools Executed:** {', '.join(summary['tools_executed']) if summary['tools_executed'] else 'None'}

---

## 📋 Detailed Findings

"""
        
        if findings:
            # Group findings by severity
            high_findings = [f for f in findings if f['severity'] == 'high']
            medium_findings = [f for f in findings if f['severity'] == 'medium']
            low_findings = [f for f in findings if f['severity'] == 'low']
            
            # High severity findings
            if high_findings:
                body += "### 🔴 Critical & High Severity Issues\n\n"
                body += self._format_findings_table(high_findings)
                body += "\n"
            
            # Medium severity findings
            if medium_findings:
                body += "### 🟡 Medium Severity Issues\n\n"
                body += self._format_findings_table(medium_findings)
                body += "\n"
            
            # Low severity findings
            if low_findings:
                body += "### 🟢 Low Severity Issues\n\n"
                body += self._format_findings_table(low_findings)
                body += "\n"
        else:
            body += "### ✅ No Security Issues Detected\n\n"
            body += "**Status:** Code appears to be secure based on current security standards.\n\n"
            body += "**Recommendation:** Continue following security best practices and maintain regular security reviews.\n\n"
        
        # Add tool-specific results
        body += "## 🛠️ Tool Execution Results\n\n"
        
        for tool_name, result in scan_results_detail.items():
            if result['error']:
                body += f"### {tool_name.upper()}\n"
                body += f"**Status:** ❌ Failed\n"
                body += f"**Error:** {result['error']}\n\n"
            else:
                body += f"### {tool_name.upper()}\n"
                body += f"**Status:** ✅ Completed\n"
                if result['output']:
                    body += f"**Output:** {len(result['output'])} characters of results\n\n"
                else:
                    body += f"**Output:** No issues found\n\n"
        
        # Add recommendations section
        body += "## 🎯 Security Recommendations\n\n"
        
        if summary['high_severity'] > 0:
            body += "### 🚨 Immediate Actions Required\n"
            body += "1. **Address Critical Issues First:** Fix all high-severity vulnerabilities before deployment\n"
            body += "2. **Security Review:** Conduct thorough code review focusing on security aspects\n"
            body += "3. **Testing:** Implement additional security testing before production deployment\n"
            body += "4. **Documentation:** Update security documentation with findings and fixes\n\n"
        
        if summary['medium_severity'] > 0:
            body += "### ⚠️ High Priority Actions\n"
            body += "1. **Review Medium Issues:** Address medium-severity issues before next release\n"
            body += "2. **Code Review:** Enhance code review process to catch similar issues\n"
            body += "3. **Training:** Consider security training for development team\n\n"
        
        if summary['low_severity'] > 0:
            body += "### ℹ️ Improvement Opportunities\n"
            body += "1. **Code Quality:** Address low-severity issues during regular development cycles\n"
            body += "2. **Best Practices:** Implement coding standards to prevent similar issues\n"
            body += "3. **Automation:** Consider additional automated security checks\n\n"
        
        # Add language-specific recommendations
        if summary['languages_scanned']:
            body += "### 🔧 Language-Specific Recommendations\n\n"
            
            if 'Python' in summary['languages_scanned']:
                body += "**Python:**\n"
                body += "- Use `bandit` in CI/CD pipeline\n"
                body += "- Implement dependency scanning with `safety`\n"
                body += "- Use virtual environments and requirements.txt\n"
                body += "- Follow OWASP Python security guidelines\n\n"
            
            if 'JavaScript' in summary['languages_scanned'] or 'TypeScript' in summary['languages_scanned']:
                body += "**JavaScript/TypeScript:**\n"
                body += "- Use `npm audit` for dependency vulnerabilities\n"
                body += "- Implement Content Security Policy (CSP)\n"
                body += "- Use HTTPS for all external requests\n"
                body += "- Validate and sanitize all user inputs\n\n"
            
            if 'Go' in summary['languages_scanned']:
                body += "**Go:**\n"
                body += "- Use `gosec` in CI/CD pipeline\n"
                body += "- Implement proper error handling\n"
                body += "- Use Go modules for dependency management\n"
                body += "- Follow Go security best practices\n\n"
        
        # Add compliance and standards section
        body += "## 📚 Security Standards & Compliance\n\n"
        body += "### OWASP Top 10 Coverage\n"
        body += "This assessment covers common web application security risks including:\n"
        body += "- Injection attacks (SQL, NoSQL, LDAP, etc.)\n"
        body += "- Broken authentication and session management\n"
        body += "- Sensitive data exposure\n"
        body += "- XML external entity (XXE) attacks\n"
        body += "- Broken access control\n"
        body += "- Security misconfiguration\n"
        body += "- Cross-site scripting (XSS)\n"
        body += "- Insecure deserialization\n"
        body += "- Using components with known vulnerabilities\n"
        body += "- Insufficient logging and monitoring\n\n"
        
        # Add technical details
        body += "## 🔧 Technical Details\n\n"
        body += f"**Scan Configuration:**\n"
        body += f"- Tools: {', '.join(summary['tools_executed']) if summary['tools_executed'] else 'None'}\n"
        body += f"- Languages: {', '.join(summary['languages_scanned']) if summary['languages_scanned'] else 'None'}\n"
        body += f"- Files: {summary['files_scanned']}\n"
        body += f"- Duration: {summary['scan_duration']:.2f} seconds\n\n"
        
        body += "**Security Standards:**\n"
        body += "- OWASP Top 10 2021\n"
        body += "- CWE (Common Weakness Enumeration)\n"
        body += "- Industry best practices\n\n"
        
        # Add support and resources
        body += "## 📞 Support & Resources\n\n"
        body += "### Documentation\n"
        body += "- [OWASP Top 10](https://owasp.org/www-project-top-ten/)\n"
        body += "- [CWE Database](https://cwe.mitre.org/)\n"
        body += "- [Security Best Practices](https://owasp.org/www-project-cheat-sheets/)\n\n"
        
        body += "### Tools Used\n"
        for tool in summary['tools_executed']:
            if tool == 'bandit':
                body += f"- **Bandit:** Python security linter - [Documentation](https://bandit.readthedocs.io/)\n"
            elif tool == 'eslint':
                body += f"- **ESLint:** JavaScript/TypeScript linter - [Documentation](https://eslint.org/)\n"
            elif tool == 'gosec':
                body += f"- **gosec:** Go security scanner - [Documentation](https://github.com/securecodewarrior/gosec)\n"
            elif tool == 'semgrep':
                body += f"- **Semgrep:** Multi-language security scanner - [Documentation](https://semgrep.dev/)\n"
        
        body += "\n---\n"
        body += "*This security assessment was performed by the Security Code Reviewer AI. For questions or concerns, please contact the security team.*\n\n"
        body += f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        body += f"**Report ID:** {datetime.now().strftime('%Y%m%d%H%M%S')}"
        
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
        """Format findings as a professional markdown table, including vulnerability type"""
        if not findings:
            return "✅ **No security vulnerabilities detected in this assessment.**\n"
        
        table = "| **Tool** | **File** | **Line** | **Severity** | **Vulnerability Type** | **Description** | **CWE** |\n"
        table += "|----------|----------|----------|--------------|-----------------------|-----------------|---------|\n"
        
        for finding in findings:
            file_path = finding['file'].replace('\\', '/')
            severity_icon = "🔴" if finding['severity'].lower() == 'high' else "🟡" if finding['severity'].lower() == 'medium' else "🟢"
            cwe = finding.get('cwe', 'N/A')
            vuln_type = "Other"
            msg = finding.get('message', '').lower()
            code = finding.get('code', '').lower()
            # Map vulnerability type based on message or code
            if "sql injection" in msg or "sql_injection" in code:
                vuln_type = "SQL Injection"
            elif "xss" in msg or "cross-site scripting" in msg or "xss" in code:
                vuln_type = "Cross-Site Scripting (XSS)"
            elif "path traversal" in msg or "directory traversal" in msg or "path_traversal" in code:
                vuln_type = "Path Traversal"
            elif "dangerous file deletion" in msg or "rmtree" in code or "remove" in code or "unlink" in code:
                vuln_type = "Dangerous File Operation"
            elif "hardcoded password" in msg or "hardcoded secret" in msg or "api key" in msg or "token" in msg or "private key" in msg:
                vuln_type = "Hardcoded Secret"
            elif "private key" in msg or "rsa private key" in msg or "ssh private key" in msg:
                vuln_type = "Private Key Exposure"
            elif "eval" in msg or "no-eval" in code:
                vuln_type = "Use of eval"
            elif "command injection" in msg or "os.system" in code or "subprocess" in code:
                vuln_type = "Command Injection"
            elif "insecure deserialization" in msg or "pickle" in code:
                vuln_type = "Insecure Deserialization"
            elif "broken authentication" in msg:
                vuln_type = "Broken Authentication"
            elif "sensitive data exposure" in msg:
                vuln_type = "Sensitive Data Exposure"
            elif "security misconfiguration" in msg:
                vuln_type = "Security Misconfiguration"
            elif "broken access control" in msg:
                vuln_type = "Broken Access Control"
            elif "xml external entity" in msg or "xxe" in code:
                vuln_type = "XML External Entity (XXE)"
            elif "insecure dependencies" in msg or "dependency" in code:
                vuln_type = "Insecure Dependency"
            # Add more mappings as needed
            
            description = finding['message'][:80] + "..." if len(finding['message']) > 80 else finding['message']
            
            table += f"| {finding['tool']} | `{file_path}` | {finding['line']} | {severity_icon} {finding['severity'].upper()} | {vuln_type} | {description} | {cwe} |\n"
        
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
