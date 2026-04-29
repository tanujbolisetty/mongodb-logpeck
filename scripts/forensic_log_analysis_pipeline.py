#!/usr/bin/env python3
"""
================================================================================
Forensic Log Analysis Pipeline Wrapper
================================================================================

This script serves as the top-level orchestrator for the LogPeck forensic suite.
It seamlessly chains the download of MongoDB Atlas logs, the generation of 
analytical HTML dashboards, lifecycle management (purging old data), and email 
notifications into a single, cohesive workflow.

USAGE EXAMPLES:
---------------
1. Basic execution with default 7-day retention and AUTO discovery mode:
   $ python3 scripts/forensic_log_analysis_pipeline.py --mode AUTO

2. Fetch logs from PRIMARY nodes with 3-day retention and send a completion email:
   $ python3 scripts/forensic_log_analysis_pipeline.py \\
         --mode AUTO \\
         --role PRIMARY \\
         --retention-days 3 \\
         --email-to "tanuj.bolisetty@macys.com"

3. Manually fetch logs for specific projects/clusters with custom latency:
   $ python3 scripts/forensic_log_analysis_pipeline.py \\
         --mode MANUAL \\
         --manual-targets '{"ProjectName": ["ClusterName"]}' \\
         --latency 0
         
Note: Any argument not explicitly defined in this wrapper is automatically 
passed downstream to the `download_atlas_logs_v2.py` script.
"""

import os
import sys
import argparse
import subprocess
import shutil
import time
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def run_command(cmd: list) -> None:
    """
    Executes a shell command and streams its output to the console.
    If the command exits with a non-zero code, it immediately halts the pipeline
    to prevent cascading failures (e.g., trying to analyze logs that failed to download).
    """
    print(f"\n🚀 Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"❌ Command failed with exit code {result.returncode}")
        sys.exit(result.returncode)

def purge_old_directories(base_dir: str, retention_days: int) -> None:
    """
    Scans the provided base directory (e.g., forensic_data/logs) and securely 
    deletes any subdirectories whose modification time is older than the specified 
    retention_days threshold. This ensures the disk does not fill up over time.
    """
    if not os.path.exists(base_dir):
        return  # Nothing to purge if the directory hasn't been created yet.
    
    now = time.time()
    cutoff_time = now - (retention_days * 86400) # 86400 seconds = 1 day
    
    # Iterate through all run folders in the base directory
    for item in os.listdir(base_dir):
        # SAFETY CHECK: Only touch folders that follow our 'run_' naming convention
        if not item.startswith("run_"):
            continue
            
        item_path = os.path.join(base_dir, item)
        if os.path.isdir(item_path):
            # Check the last modification time of the directory
            mtime = os.path.getmtime(item_path)
            if mtime < cutoff_time:
                print(f"🧹 Purging old data: {item_path} (older than {retention_days} days)")
                try:
                    # Securely wipe the directory and its contents
                    shutil.rmtree(item_path)
                except Exception as e:
                    print(f"⚠️ Failed to delete {item_path}: {e}")

def send_email_notification(to_addr: str, from_addr: str, smtp_server: str, smtp_port: int, run_id: str, report_dir: str) -> None:
    """
    Sends a summary email listing the generated reports. We do not attach the 
    HTML reports directly as they can be several megabytes in size, which 
    often violates corporate SMTP attachment limits.
    """
    if not to_addr:
        return
        
    print(f"\n📧 Sending email notification to {to_addr}...")
    
    # Gather generated reports from the output directory
    reports = []
    if os.path.exists(report_dir):
        reports = [f for f in os.listdir(report_dir) if f.endswith(".html")]
        
    subject = f"✅ logpeck Forensic Pipeline Complete (Run: {run_id})"
    
    # Construct the plain-text email body
    body = f"""Hello,

The logpeck Forensic Pipeline has successfully completed its run.

Run ID: {run_id}
Local Report Directory: {os.path.abspath(report_dir)}

Generated Reports ({len(reports)}):
"""
    # Append each report file name to the email body
    for r in sorted(reports):
        body += f"- {r}\n"
        
    body += "\nNote: Reports are not attached due to size limits. Please access them via the directory path above.\n"
    
    # Construct the MIME multipart message
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Standard local/internal relay attempt
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.send_message(msg)
            print("✅ Email sent successfully.")
    except Exception as e:
        print(f"⚠️ Failed to send email via {smtp_server}:{smtp_port}: {e}")

def main():
    # Setup argument parser for the wrapper script
    parser = argparse.ArgumentParser(
        description="End-to-End Forensic Log Analysis Pipeline",
        epilog="Note: All remaining arguments are passed directly to the download_atlas_logs_v2.py script."
    )
    
    # Core Pipeline Arguments
    parser.add_argument("--retention-days", type=int, default=7, 
                        help="Number of days to keep logs and reports before purging (default: 7)")
    parser.add_argument("--latency", type=int, default=0, 
                        help="Minimum latency (ms) for forensic capture passed to logpeck (default: 0)")
    
    # Email Notification Arguments
    parser.add_argument("--email-to", type=str, help="Email address to send completion notification to")
    parser.add_argument("--email-from", type=str, default="logpeck@localhost", help="Sender email address")
    parser.add_argument("--smtp-server", type=str, default="localhost", help="SMTP server address")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP server port")
    
    # Parse our wrapper args, and collect the rest to pass to the downloader
    args, unknown_args = parser.parse_known_args()
    
    # -------------------------------------------------------------------------
    # Phase 0: Naming Convention & Directory Scaffolding
    # -------------------------------------------------------------------------
    # Generate a unique run ID based on the current timestamp
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Define the root forensic storage location
    base_dir = os.path.abspath("forensic_data")
    logs_dir = os.path.join(base_dir, "logs")
    reports_dir = os.path.join(base_dir, "reports")
    
    # Define dynamic outputs specifically for this current execution run
    run_log_dir = os.path.join(logs_dir, f"run_{run_id}")
    run_report_dir = os.path.join(reports_dir, f"run_{run_id}")
    
    # Ensure the directories exist before we attempt to write to them
    os.makedirs(run_log_dir, exist_ok=True)
    os.makedirs(run_report_dir, exist_ok=True)
    
    print("==================================================")
    print(f"🕵️  STARTING FORENSIC PIPELINE | RUN: {run_id}")
    print("==================================================")
    
    # -------------------------------------------------------------------------
    # Phase 1: Log Download Phase
    # -------------------------------------------------------------------------
    print("\n[1/3] Initiating Atlas Log Download Phase...")
    download_script = os.path.join("scripts", "download_atlas_logs_v2.py")
    
    # Sanity check to ensure the script is running from the correct root directory
    if not os.path.exists(download_script):
        print(f"❌ Error: Download script not found at {download_script}")
        sys.exit(1)
        
    # Build and execute the download command. We append `unknown_args` so that 
    # things like `--mode AUTO` flow directly into the downloader.
    download_cmd = [sys.executable, download_script, "--output-path", run_log_dir] + unknown_args
    run_command(download_cmd)
    
    # -------------------------------------------------------------------------
    # Phase 2: Forensic Analysis Phase
    # -------------------------------------------------------------------------
    print("\n[2/3] Initiating Forensic Engine Analysis Phase...")
    dashboard_html = os.path.join(run_report_dir, "dashboard.html")
    
    # Execute the logpeck engine. It will sweep the `run_log_dir` and generate
    # the HTML reports in the `run_report_dir`.
    analyze_cmd = [
        sys.executable, "-m", "logpeck", "dashboard", 
        "--folder", run_log_dir, 
        "--latency", str(args.latency), 
        "--html", dashboard_html
    ]
    run_command(analyze_cmd)
    
    # -------------------------------------------------------------------------
    # Phase 3: Lifecycle Purge Phase
    # -------------------------------------------------------------------------
    print(f"\n[3/3] Initiating Lifecycle Purge ({args.retention_days} Days Retention)...")
    
    # Clean up both the raw logs and the generated reports that have expired
    purge_old_directories(logs_dir, args.retention_days)
    purge_old_directories(reports_dir, args.retention_days)
    
    print("\n==================================================")
    print(f"✅ Pipeline Complete!")
    print(f"📂 Logs saved to:    {run_log_dir}")
    print(f"📊 Reports saved to: {run_report_dir}")
    print("==================================================")
    
    # -------------------------------------------------------------------------
    # Phase 4: Notification Phase
    # -------------------------------------------------------------------------
    if args.email_to:
        send_email_notification(args.email_to, args.email_from, args.smtp_server, args.smtp_port, run_id, run_report_dir)

if __name__ == "__main__":
    main()
