#!/usr/bin/env python3
"""
Comprehensive Log Viewer for Security Code Reviewer AI
Provides real-time monitoring of all log types and filtering capabilities
"""

import os
import sys
import time
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json

def get_log_files():
    """Get all available log files"""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        print("❌ Logs directory not found. Run the app first to generate logs.")
        return {}
    
    log_files = {
        'security_scanner': 'logs/security_scanner.log',
        'webhook_events': 'logs/webhook_events.log',
        'security_findings': 'logs/security_findings.log',
        'scan_progress': 'logs/scan_progress.log',
        'report_generation': 'logs/report_generation.log'
    }
    
    # Check which files exist
    existing_files = {}
    for name, path in log_files.items():
        if os.path.exists(path):
            existing_files[name] = path
    
    return existing_files

def read_log_file(file_path: str, lines: int = 50) -> List[str]:
    """Read the last N lines from a log file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            return all_lines[-lines:] if len(all_lines) > lines else all_lines
    except Exception as e:
        return [f"Error reading log file: {str(e)}"]

def filter_logs_by_pr(log_lines: List[str], pr_number: int) -> List[str]:
    """Filter log lines by PR number"""
    return [line for line in log_lines if f"PR #{pr_number}" in line]

def filter_logs_by_time(log_lines: List[str], hours: int) -> List[str]:
    """Filter log lines by time (last N hours)"""
    cutoff_time = datetime.now() - timedelta(hours=hours)
    filtered_lines = []
    
    for line in log_lines:
        try:
            # Extract timestamp from log line (assuming format: YYYY-MM-DD HH:MM:SS)
            timestamp_str = line.split(' - ')[0]
            log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
            if log_time >= cutoff_time:
                filtered_lines.append(line)
        except:
            # If we can't parse the timestamp, include the line
            filtered_lines.append(line)
    
    return filtered_lines

def get_log_statistics(log_files: Dict[str, str]) -> Dict[str, Any]:
    """Get statistics about log files"""
    stats = {}
    
    for name, path in log_files.items():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                stats[name] = {
                    'total_lines': len(lines),
                    'file_size': os.path.getsize(path),
                    'last_modified': datetime.fromtimestamp(os.path.getmtime(path))
                }
        except Exception as e:
            stats[name] = {'error': str(e)}
    
    return stats

def display_log_summary(log_files: Dict[str, str]):
    """Display a summary of all log files"""
    print("📊 LOG SUMMARY")
    print("=" * 60)
    
    stats = get_log_statistics(log_files)
    
    for name, stat in stats.items():
        if 'error' in stat:
            print(f"❌ {name.upper()}: {stat['error']}")
        else:
            print(f"📄 {name.upper()}:")
            print(f"   Lines: {stat['total_lines']:,}")
            print(f"   Size: {stat['file_size'] / 1024:.1f} KB")
            print(f"   Last Modified: {stat['last_modified'].strftime('%Y-%m-%d %H:%M:%S')}")
        print()

def display_recent_activity(log_files: Dict[str, str], hours: int = 24):
    """Display recent activity across all logs"""
    print(f"🕒 RECENT ACTIVITY (Last {hours} hours)")
    print("=" * 60)
    
    cutoff_time = datetime.now() - timedelta(hours=hours)
    
    for name, path in log_files.items():
        print(f"\n📋 {name.upper()}:")
        print("-" * 40)
        
        lines = read_log_file(path, 100)
        recent_lines = filter_logs_by_time(lines, hours)
        
        if recent_lines:
            for line in recent_lines[-10:]:  # Show last 10 recent lines
                print(line.rstrip())
        else:
            print("No recent activity")

def display_pr_activity(pr_number: int, log_files: Dict[str, str]):
    """Display all activity for a specific PR"""
    print(f"🔍 PR #{pr_number} ACTIVITY")
    print("=" * 60)
    
    for name, path in log_files.items():
        print(f"\n📋 {name.upper()}:")
        print("-" * 40)
        
        lines = read_log_file(path, 200)
        pr_lines = filter_logs_by_pr(lines, pr_number)
        
        if pr_lines:
            for line in pr_lines:
                print(line.rstrip())
        else:
            print("No activity found for this PR")

def display_scan_progress(log_files: Dict[str, str]):
    """Display current scan progress"""
    print("🔍 SCAN PROGRESS")
    print("=" * 60)
    
    if 'scan_progress' in log_files:
        lines = read_log_file(log_files['scan_progress'], 50)
        for line in lines:
            print(line.rstrip())
    else:
        print("No scan progress logs found")

def display_webhook_events(log_files: Dict[str, str]):
    """Display recent webhook events"""
    print("🌐 WEBHOOK EVENTS")
    print("=" * 60)
    
    if 'webhook_events' in log_files:
        lines = read_log_file(log_files['webhook_events'], 30)
        for line in lines:
            print(line.rstrip())
    else:
        print("No webhook event logs found")

def display_security_findings(log_files: Dict[str, str]):
    """Display recent security findings"""
    print("🔒 SECURITY FINDINGS")
    print("=" * 60)
    
    if 'security_findings' in log_files:
        lines = read_log_file(log_files['security_findings'], 50)
        for line in lines:
            print(line.rstrip())
    else:
        print("No security findings logs found")

def display_report_generation(log_files: Dict[str, str]):
    """Display recent report generation activity"""
    print("📝 REPORT GENERATION")
    print("=" * 60)
    
    if 'report_generation' in log_files:
        lines = read_log_file(log_files['report_generation'], 30)
        for line in lines:
            print(line.rstrip())
    else:
        print("No report generation logs found")

def real_time_monitoring(log_files: Dict[str, str], duration: int = 300):
    """Real-time log monitoring"""
    print(f"👀 REAL-TIME MONITORING (Duration: {duration} seconds)")
    print("=" * 60)
    print("Press Ctrl+C to stop monitoring")
    print()
    
    # Store initial file sizes
    initial_sizes = {}
    for name, path in log_files.items():
        try:
            initial_sizes[name] = os.path.getsize(path)
        except:
            initial_sizes[name] = 0
    
    start_time = time.time()
    
    try:
        while time.time() - start_time < duration:
            for name, path in log_files.items():
                try:
                    current_size = os.path.getsize(path)
                    if current_size > initial_sizes[name]:
                        # New content added
                        with open(path, 'r', encoding='utf-8') as f:
                            f.seek(initial_sizes[name])
                            new_content = f.read()
                            if new_content.strip():
                                print(f"[{datetime.now().strftime('%H:%M:%S')}] {name.upper()}:")
                                for line in new_content.strip().split('\n'):
                                    if line.strip():
                                        print(f"  {line}")
                                print()
                        
                        initial_sizes[name] = current_size
                except Exception as e:
                    print(f"Error monitoring {name}: {e}")
            
            time.sleep(1)  # Check every second
            
    except KeyboardInterrupt:
        print("\n⏹️ Monitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(description='Security Code Reviewer AI Log Viewer')
    parser.add_argument('--summary', action='store_true', help='Show log summary')
    parser.add_argument('--recent', type=int, metavar='HOURS', default=24, help='Show recent activity (default: 24 hours)')
    parser.add_argument('--pr', type=int, metavar='NUMBER', help='Show activity for specific PR number')
    parser.add_argument('--scan-progress', action='store_true', help='Show scan progress')
    parser.add_argument('--webhooks', action='store_true', help='Show webhook events')
    parser.add_argument('--findings', action='store_true', help='Show security findings')
    parser.add_argument('--reports', action='store_true', help='Show report generation')
    parser.add_argument('--monitor', type=int, metavar='SECONDS', default=300, help='Real-time monitoring (default: 300 seconds)')
    parser.add_argument('--all', action='store_true', help='Show all log types')
    
    args = parser.parse_args()
    
    log_files = get_log_files()
    
    if not log_files:
        return
    
    if args.summary:
        display_log_summary(log_files)
    
    if args.pr:
        display_pr_activity(args.pr, log_files)
    
    if args.scan_progress:
        display_scan_progress(log_files)
    
    if args.webhooks:
        display_webhook_events(log_files)
    
    if args.findings:
        display_security_findings(log_files)
    
    if args.reports:
        display_report_generation(log_files)
    
    if args.all:
        display_log_summary(log_files)
        display_recent_activity(log_files, args.recent)
        display_scan_progress(log_files)
        display_webhook_events(log_files)
        display_security_findings(log_files)
        display_report_generation(log_files)
    
    if args.monitor:
        real_time_monitoring(log_files, args.monitor)
    
    # Default behavior if no specific option is provided
    if not any([args.summary, args.pr, args.scan_progress, args.webhooks, 
                args.findings, args.reports, args.all, args.monitor]):
        display_log_summary(log_files)
        print("\n" + "=" * 60)
        display_recent_activity(log_files, args.recent)

if __name__ == "__main__":
    main() 