# src/types/index.py

from typing import Dict, Any, List, Optional

# Define custom types for security findings
class SecurityFinding:
    def __init__(self, tool: str, severity: str, file: str, line: int, message: str, code: str, cwe: Optional[str] = None):
        self.tool = tool
        self.severity = severity
        self.file = file
        self.line = line
        self.message = message
        self.code = code
        self.cwe = cwe

# Define a type for the scan summary
class ScanSummary:
    def __init__(self, total_issues: int, high_severity: int, medium_severity: int, low_severity: int, languages_scanned: List[str]):
        self.total_issues = total_issues
        self.high_severity = high_severity
        self.medium_severity = medium_severity
        self.low_severity = low_severity
        self.languages_scanned = languages_scanned

# Define a type for the scan results
class ScanResults:
    def __init__(self, summary: ScanSummary, findings: List[SecurityFinding], scan_results: Dict[str, Any]):
        self.summary = summary
        self.findings = findings
        self.scan_results = scan_results