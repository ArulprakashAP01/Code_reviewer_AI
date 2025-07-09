"""
Comprehensive logging configuration for Security Code Reviewer AI
"""

import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging():
    """Setup logging to only output to the console (stdout)"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()  # Only log to console
        ]
    )
    # Create specific loggers as before
    webhook_logger = logging.getLogger('webhook')
    webhook_logger.setLevel(logging.INFO)
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    github_logger = logging.getLogger('github')
    github_logger.setLevel(logging.INFO)
    scan_logger = logging.getLogger('scan')
    scan_logger.setLevel(logging.INFO)
    report_logger = logging.getLogger('report')
    report_logger.setLevel(logging.INFO)
    return {
        'webhook': webhook_logger,
        'security': security_logger,
        'github': github_logger,
        'scan': scan_logger,
        'report': report_logger
    }

def log_webhook_event(event_type, data, status="received"):
    """Log webhook events with details"""
    logger = logging.getLogger('webhook')
    
    if event_type == 'pull_request':
        action = data.get('action', 'unknown')
        pr_number = data.get('number', 'unknown')
        repo = data.get('repository', {}).get('full_name', 'unknown')
        pr_title = data.get('pull_request', {}).get('title', 'unknown')
        pr_author = data.get('pull_request', {}).get('user', {}).get('login', 'unknown')
        
        logger.info(f"WEBHOOK EVENT: {status.upper()} - {event_type.upper()} - {action.upper()}")
        logger.info(f"  Repository: {repo}")
        logger.info(f"  PR Number: #{pr_number}")
        logger.info(f"  PR Title: {pr_title}")
        logger.info(f"  PR Author: {pr_author}")
        logger.info(f"  Action: {action}")
        logger.info(f"  Timestamp: {datetime.now().isoformat()}")
        
        if 'installation' in data:
            logger.info(f"  Installation ID: {data['installation']['id']}")
    
    elif event_type == 'installation':
        action = data.get('action', 'unknown')
        installation_id = data.get('installation', {}).get('id', 'unknown')
        repositories = data.get('repositories', [])
        
        logger.info(f"WEBHOOK EVENT: {status.upper()} - {event_type.upper()} - {action.upper()}")
        logger.info(f"  Installation ID: {installation_id}")
        logger.info(f"  Action: {action}")
        logger.info(f"  Repositories: {[repo['full_name'] for repo in repositories]}")
        logger.info(f"  Timestamp: {datetime.now().isoformat()}")

def log_security_scan_start(pr_number, repo_name):
    """Log the start of a security scan"""
    logger = logging.getLogger('security')
    scan_logger = logging.getLogger('scan')
    
    logger.info("=" * 80)
    logger.info(f"SECURITY SCAN STARTED")
    logger.info(f"  PR Number: #{pr_number}")
    logger.info(f"  Repository: {repo_name}")
    logger.info(f"  Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 80)
    
    scan_logger.info(f"SCAN_START - PR #{pr_number} - {repo_name}")

def log_security_scan_complete(pr_number, scan_results):
    """Log the completion of a security scan"""
    logger = logging.getLogger('security')
    scan_logger = logging.getLogger('scan')
    summary = scan_results['summary']
    
    logger.info("=" * 80)
    logger.info(f"SECURITY SCAN COMPLETED")
    logger.info(f"  PR Number: #{pr_number}")
    logger.info(f"  Total Issues: {summary['total_issues']}")
    logger.info(f"  High Severity: {summary['high_severity']}")
    logger.info(f"  Medium Severity: {summary['medium_severity']}")
    logger.info(f"  Low Severity: {summary['low_severity']}")
    logger.info(f"  Languages Scanned: {', '.join(summary['languages_scanned'])}")
    logger.info(f"  Timestamp: {datetime.now().isoformat()}")
    
    # Log individual findings
    if scan_results['findings']:
        logger.info("  DETAILED FINDINGS:")
        for finding in scan_results['findings']:
            logger.info(f"    - {finding['tool']}: {finding['severity']} - {finding['message']}")
            logger.info(f"      File: {finding['file']}:{finding['line']}")
    
    logger.info("=" * 80)
    
    scan_logger.info(f"SCAN_COMPLETE - PR #{pr_number} - Issues: {summary['total_issues']} (H:{summary['high_severity']} M:{summary['medium_severity']} L:{summary['low_severity']})")

def log_tool_execution(tool_name, status, details=None):
    """Log individual tool execution status"""
    scan_logger = logging.getLogger('scan')
    scan_logger.info(f"TOOL_EXECUTION - {tool_name.upper()} - {status}")
    if details:
        scan_logger.info(f"  Details: {details}")

def log_github_issue_created(pr_number, issue_url):
    """Log when a GitHub issue is created"""
    logger = logging.getLogger('github')
    report_logger = logging.getLogger('report')
    
    logger.info(f"GITHUB ISSUE CREATED")
    logger.info(f"  PR Number: #{pr_number}")
    logger.info(f"  Issue URL: {issue_url}")
    logger.info(f"  Timestamp: {datetime.now().isoformat()}")
    
    report_logger.info(f"ISSUE_CREATED - PR #{pr_number} - {issue_url}")

def log_github_comment_posted(pr_number, summary):
    """Log when a comment is posted on PR"""
    logger = logging.getLogger('github')
    report_logger = logging.getLogger('report')
    
    logger.info(f"GITHUB COMMENT POSTED")
    logger.info(f"  PR Number: #{pr_number}")
    logger.info(f"  Total Issues: {summary['total_issues']}")
    logger.info(f"  Risk Level: {'HIGH' if summary['high_severity'] > 0 else 'MEDIUM' if summary['medium_severity'] > 0 else 'LOW'}")
    logger.info(f"  Timestamp: {datetime.now().isoformat()}")
    
    report_logger.info(f"COMMENT_POSTED - PR #{pr_number} - Issues: {summary['total_issues']}")

def log_report_generation_start(pr_number):
    """Log when report generation starts"""
    report_logger = logging.getLogger('report')
    report_logger.info(f"REPORT_GENERATION_START - PR #{pr_number}")

def log_report_generation_complete(pr_number, report_type):
    """Log when report generation completes"""
    report_logger = logging.getLogger('report')
    report_logger.info(f"REPORT_GENERATION_COMPLETE - PR #{pr_number} - Type: {report_type}")

def log_error(error_type, error_message, context=None):
    """Log errors with context"""
    logger = logging.getLogger('error')
    logger.error(f"ERROR: {error_type.upper()}")
    logger.error(f"  Message: {error_message}")
    if context:
        logger.error(f"  Context: {context}")
    logger.error(f"  Timestamp: {datetime.now().isoformat()}")

def get_log_summary():
    """Get a summary of recent logs"""
    try:
        with open('logs/security_scanner.log', 'r') as f:
            lines = f.readlines()
            return {
                'total_lines': len(lines),
                'recent_events': lines[-10:] if len(lines) > 10 else lines
            }
    except FileNotFoundError:
        return {'total_lines': 0, 'recent_events': []}

def get_scan_logs(pr_number=None):
    """Get scan-specific logs"""
    try:
        with open('logs/scan_progress.log', 'r') as f:
            lines = f.readlines()
            if pr_number:
                # Filter logs for specific PR
                filtered_lines = [line for line in lines if f"PR #{pr_number}" in line]
                return filtered_lines
            return lines[-20:] if len(lines) > 20 else lines
    except FileNotFoundError:
        return []

def get_report_logs(pr_number=None):
    """Get report generation logs"""
    try:
        with open('logs/report_generation.log', 'r') as f:
            lines = f.readlines()
            if pr_number:
                # Filter logs for specific PR
                filtered_lines = [line for line in lines if f"PR #{pr_number}" in line]
                return filtered_lines
            return lines[-20:] if len(lines) > 20 else lines
    except FileNotFoundError:
        return [] 