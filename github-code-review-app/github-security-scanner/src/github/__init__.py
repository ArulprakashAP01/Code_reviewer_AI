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