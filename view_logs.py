#!/usr/bin/env python3
"""
Log Viewer for Security Code Reviewer AI
Displays backend logs in a user-friendly format
"""

import os
import sys
from datetime import datetime
import argparse
from typing import List, Dict

def read_log_file(filename: str, lines: int = 50) -> List[str]:
    """Read the last N lines from a log file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            return all_lines[-lines:] if len(all_lines) > lines else all_lines
    except FileNotFoundError:
        return [f"Log file {filename} not found."]
    except Exception as e:
        return [f"Error reading {filename}: {str(e)}"]

def display_logs(log_type: str = "all", lines: int = 50, follow: bool = False):
    """Display logs based on type"""
    
    log_files = {
        "all": "logs/security_scanner.log",
        "webhook": "logs/webhook_events.log", 
        "security": "logs/security_findings.log",
        "main": "logs/security_scanner.log"
    }
    
    if log_type not in log_files:
        print(f"Invalid log type: {log_type}")
        print(f"Available types: {', '.join(log_files.keys())}")
        return
    
    filename = log_files[log_type]
    
    if not os.path.exists(filename):
        print(f"Log file {filename} does not exist.")
        print("Make sure the application has been run at least once.")
        return
    
    print(f"\n{'='*80}")
    print(f"🔍 SECURITY CODE REVIEWER AI - LOG VIEWER")
    print(f"{'='*80}")
    print(f"📁 Log Type: {log_type.upper()}")
    print(f"📄 File: {filename}")
    print(f"📊 Lines: {lines}")
    print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")
    
    if follow:
        print("🔄 Following logs (Press Ctrl+C to stop)...\n")
        try:
            import time
            while True:
                current_lines = read_log_file(filename, lines)
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"\n{'='*80}")
                print(f"🔍 SECURITY CODE REVIEWER AI - LOG VIEWER (FOLLOWING)")
                print(f"{'='*80}")
                print(f"📁 Log Type: {log_type.upper()}")
                print(f"📄 File: {filename}")
                print(f"⏰ Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'='*80}\n")
                
                for line in current_lines:
                    print(line.rstrip())
                
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n\n🛑 Stopped following logs.")
            return
    else:
        log_lines = read_log_file(filename, lines)
        for line in log_lines:
            print(line.rstrip())

def show_summary():
    """Show a summary of all log files"""
    print(f"\n{'='*80}")
    print(f"📊 SECURITY CODE REVIEWER AI - LOG SUMMARY")
    print(f"{'='*80}")
    
    log_files = [
        ("Main Log", "logs/security_scanner.log"),
        ("Webhook Events", "logs/webhook_events.log"),
        ("Security Findings", "logs/security_findings.log")
    ]
    
    for name, filename in log_files:
        if os.path.exists(filename):
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    size = os.path.getsize(filename)
                    last_modified = datetime.fromtimestamp(os.path.getmtime(filename))
                    
                    print(f"\n📁 {name}:")
                    print(f"   📄 File: {filename}")
                    print(f"   📊 Lines: {len(lines)}")
                    print(f"   💾 Size: {size:,} bytes")
                    print(f"   ⏰ Last Modified: {last_modified.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if lines:
                        print(f"   📝 Last Entry: {lines[-1].strip()}")
            except Exception as e:
                print(f"   ❌ Error reading {filename}: {str(e)}")
        else:
            print(f"\n📁 {name}:")
            print(f"   ❌ File not found: {filename}")
    
    print(f"\n{'='*80}")

def main():
    parser = argparse.ArgumentParser(description="View Security Code Reviewer AI logs")
    parser.add_argument("--type", "-t", choices=["all", "webhook", "security", "main"], 
                       default="all", help="Type of logs to display")
    parser.add_argument("--lines", "-n", type=int, default=50, 
                       help="Number of lines to display")
    parser.add_argument("--follow", "-f", action="store_true", 
                       help="Follow logs in real-time")
    parser.add_argument("--summary", "-s", action="store_true", 
                       help="Show summary of all log files")
    
    args = parser.parse_args()
    
    if args.summary:
        show_summary()
    else:
        display_logs(args.type, args.lines, args.follow)

if __name__ == "__main__":
    main() 