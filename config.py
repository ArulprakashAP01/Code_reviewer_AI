"""
Configuration file for the Security Code Reviewer AI
"""

import os
from typing import Dict, List, Any

# GitHub App Configuration
GITHUB_APP_ID = 1513443
WEBHOOK_SECRET = os.getenv("arulprakash01")

# Security Scanner Configuration
SCANNER_CONFIG = {
    'timeout_seconds': 300,  # 5 minutes timeout for each scanner
    'max_file_size_mb': 10,  # Skip files larger than 10MB
    'exclude_patterns': [
        'node_modules/**',
        'venv/**',
        '.git/**',
        '__pycache__/**',
        '*.pyc',
        '*.pyo',
        '*.pyd',
        '.pytest_cache/**',
        'dist/**',
        'build/**',
        '*.egg-info/**',
        'coverage/**',
        '.coverage',
        '*.log',
        '*.tmp',
        '*.temp'
    ],
    'include_patterns': [
        '**/*.py',
        '**/*.js',
        '**/*.ts',
        '**/*.jsx',
        '**/*.tsx',
        '**/*.go',
        '**/*.java',
        '**/*.php',
        '**/*.rb',
        '**/*.cs',
        '**/*.cpp',
        '**/*.c',
        '**/*.h',
        '**/*.hpp'
    ]
}

# Scanner-specific configurations
BANDIT_CONFIG = {
    'enabled': True,
    'severity_levels': ['LOW', 'MEDIUM', 'HIGH'],
    'confidence_levels': ['LOW', 'MEDIUM', 'HIGH'],
    'exclude_dirs': ['tests', 'test', 'tests_*', 'test_*'],
    'skips': ['B101', 'B601']  # Skip specific bandit tests if needed
}

ESLINT_CONFIG = {
    'enabled': True,
    'security_rules': [
        'no-eval',
        'no-implied-eval', 
        'no-new-func',
        'no-script-url',
        'no-unsafe-finally',
        'no-unsafe-negation',
        'no-unsafe-optional-chaining',
        'no-unsafe-unary-negation',
        'security/detect-object-injection',
        'security/detect-non-literal-regexp',
        'security/detect-unsafe-regex'
    ],
    'config_file': '.eslintrc.json'
}

GOSEC_CONFIG = {
    'enabled': True,
    'severity_levels': ['LOW', 'MEDIUM', 'HIGH'],
    'exclude_rules': [],  # Exclude specific gosec rules if needed
    'include_rules': []   # Include only specific rules
}

SEMGREP_CONFIG = {
    'enabled': True,
    'config': 'auto',  # Use auto config for security rules
    'severity_levels': ['INFO', 'WARNING', 'ERROR'],
    'exclude_patterns': [
        'tests/**',
        'test/**',
        '**/*_test.py',
        '**/*_test.js',
        '**/*.test.js',
        '**/*.spec.js'
    ]
}

# Issue Reporting Configuration
ISSUE_CONFIG = {
    'create_issues': True,
    'update_existing': True,
    'labels': {
        'security': '🔒',
        'automated-scan': '🤖',
        'high-priority': '🚨',
        'medium-priority': '⚠️',
        'low-priority': 'ℹ️',
        'no-vulnerabilities': '✅'
    },
    'issue_template': {
        'title_template': '🔒 Security Vulnerability Report - {timestamp}',
        'include_summary': True,
        'include_details': True,
        'include_recommendations': True,
        'include_tools_info': True
    }
}

# Notification Configuration
NOTIFICATION_CONFIG = {
    'pr_comment': True,
    'issue_creation': True,
    'email_notifications': False,  # Future feature
    'slack_notifications': False,  # Future feature
    'teams_notifications': False   # Future feature
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'security_scanner.log',
    'max_size_mb': 10,
    'backup_count': 5
}

# API Configuration
API_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': False,
    'threaded': True,
    'ssl_context': None  # Set to ('cert.pem', 'key.pem') for HTTPS
}

# Security Headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'"
}

# Rate Limiting
RATE_LIMIT_CONFIG = {
    'enabled': True,
    'requests_per_minute': 60,
    'burst_size': 10
}

# Caching Configuration
CACHE_CONFIG = {
    'enabled': True,
    'ttl_seconds': 3600,  # 1 hour
    'max_size': 1000
}

# Error Handling
ERROR_CONFIG = {
    'max_retries': 3,
    'retry_delay_seconds': 5,
    'graceful_degradation': True,
    'fallback_scanners': ['bandit']  # Use these if others fail
}

# Custom Security Rules
CUSTOM_RULES = {
    'enabled': True,
    'rules_file': 'custom_rules.json',
    'patterns': [
        {
            'name': 'hardcoded_password',
            'pattern': r'password\s*=\s*["\'][^"\']+["\']',
            'severity': 'HIGH',
            'description': 'Hardcoded password detected'
        },
        {
            'name': 'sql_injection_risk',
            'pattern': r'execute\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
            'severity': 'HIGH',
            'description': 'Potential SQL injection risk'
        },
        {
            'name': 'debug_code',
            'pattern': r'(console\.log|print\s*\(|debugger\s*;)',
            'severity': 'LOW',
            'description': 'Debug code found in production'
        }
    ]
}

# Export all configurations
def get_all_config() -> Dict[str, Any]:
    """Get all configuration settings"""
    return {
        'scanner': SCANNER_CONFIG,
        'bandit': BANDIT_CONFIG,
        'eslint': ESLINT_CONFIG,
        'gosec': GOSEC_CONFIG,
        'semgrep': SEMGREP_CONFIG,
        'issue': ISSUE_CONFIG,
        'notification': NOTIFICATION_CONFIG,
        'logging': LOGGING_CONFIG,
        'api': API_CONFIG,
        'security_headers': SECURITY_HEADERS,
        'rate_limit': RATE_LIMIT_CONFIG,
        'cache': CACHE_CONFIG,
        'error': ERROR_CONFIG,
        'custom_rules': CUSTOM_RULES
    } 