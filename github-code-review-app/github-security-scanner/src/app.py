from datetime import datetime
import os
import glob
import re
import subprocess
import json
import logging
from flask import Flask, request, jsonify
from flask_githubapp import GitHubApp
from github import Github, GithubIntegration
from dotenv import load_dotenv
from scanner import SecurityScanner
from github import GitHubIssueReporter

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
load_dotenv()

app = Flask(__name__)

# Configure Flask-GitHubApp
app.config['GITHUBAPP_ID'] = os.getenv("GITHUB_APP_ID")
app.config['GITHUBAPP_KEY'] = os.getenv("GITHUB_APP_KEY")
app.config['GITHUBAPP_SECRET'] = os.getenv("GITHUB_WEBHOOK_SECRET")

github_app = GitHubApp(app)

@app.route('/webhook', methods=['POST'])
def webhook_handler():
    """Handle incoming webhooks from GitHub"""
    try:
        payload = request.get_json()
        event_type = request.headers.get('X-GitHub-Event')
        
        logger.info(f"Received webhook: {event_type}")
        
        if event_type == 'pull_request':
            return on_pull_request(payload)
        
        return "", 200
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return "", 500

@github_app.on("pull_request")
def on_pull_request(data):
    """Handle pull request events"""
    action = data["action"]
    if action not in ["opened", "synchronize", "reopened"]:
        return "", 204

    try:
        repo_full_name = data["repository"]["full_name"]
        pr_number = data["number"]
        installation_id = data["installation"]["id"]

        logger.info(f"Starting security scan for PR #{pr_number} in {repo_full_name}")

        # Setup GitHub client
        integration = GithubIntegration(os.getenv("GITHUB_APP_ID"), os.getenv("GITHUB_APP_KEY"))
        access_token = integration.get_access_token(installation_id).token
        g = Github(access_token)
        repo = g.get_repo(repo_full_name)

        # Clone and checkout PR
        # (Implementation for cloning and checking out the PR goes here)

        # Run comprehensive security scan
        scanner = SecurityScanner()
        scan_results = scanner.run_comprehensive_scan()

        # Create GitHub issue with scan results
        reporter = GitHubIssueReporter(g, repo_full_name)
        issue_url = reporter.create_security_report_issue(scan_results, pr_number)
        logger.info(f"Security report issue created: {issue_url}")

    except Exception as e:
        logger.error(f"Error processing pull request: {str(e)}")
        return "", 500

    return "", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))