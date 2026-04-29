#!/usr/bin/env python3
"""
MongoDB Atlas Log Downloader
---------------------------------------
Purpose: Automate log downloading for all production projects and clusters.
Usage:   Update the configuration variables below and run the script.

Examples:
1. Auto-Discovery (ALL Production Clusters):
   python3 scripts/download_atlas_logs_v2.py --mode AUTO --org-id "623e..."

2. Manual Selection with Timezone Offsets (MANDATORY):
   python3 scripts/download_atlas_logs_v2.py \
     --mode MANUAL \
     --manual-targets '{"Proj-A": ["Cluster-1"]}' \
     --start-time "2026-04-12T10:00:00-04:00" \
     --end-time "2026-04-12T22:00:00-04:00"

3. UTC Time (Safest for Forensic Analysis):
   python3 scripts/download_atlas_logs_v2.py \
     --start-time "2026-04-12T14:00:00Z" \
     --end-time "2026-04-13T02:00:00Z"

Operational Modes:
1. AUTO:   Scans all projects for names containing 'prod', 'production', or 'prd'.
2. MANUAL: Uses the provided MANUAL_TARGETS dictionary mapping Projects to Clusters.

Target Node Roles:
- ALL (Default): Downloads logs from all nodes in the cluster (Primary + Secondaries).
- PRIMARY: Downloads logs only from the current Primary node.
"""

import os
import time
import json
import logging
import requests
import argparse
from datetime import datetime, timedelta, timezone
from requests.auth import HTTPDigestAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_env_file(filepath=".env"):
    """
    Simple zero-dependency .env parser to maintain script self-sufficiency.
    Loads variables into os.environ.
    """
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")
    except Exception as e:
        print(f"[!] Warning: Could not parse {filepath}: {e}")

# Load environment variables from .env if present
load_env_file()

# =============================================================================
# 0. LOGGING SETUP
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("atlas_downloader")

# =============================================================================
# 1. CONFIGURATION (REQUIRED)
# =============================================================================
# Set your Atlas API Credentials here
# Priority: 1. CLI Args, 2. .env file
# NOTE: No hardcoded fallbacks are allowed for security reasons.
ATLAS_PUBLIC_KEY = os.getenv("ATLAS_PUBLIC_KEY") # Mandatory
ATLAS_PRIVATE_KEY = os.getenv("ATLAS_PRIVATE_KEY") # Mandatory
ATLAS_ORG_ID = os.getenv("ATLAS_ORG_ID")  # Mandatory for auto-discovery

# Operational Mode: 'AUTO' or 'MANUAL'
MODE = "AUTO"

# Manual Targets (Used only if MODE="MANUAL")
# Format: {"Project-Name": ["Cluster-1", "Cluster-2"], "Project-B": ["Cluster-X"]}
MANUAL_TARGETS = {
    "mtech-host-hs1-prod": ["preference-plus-prod-global"]
}

# Log Files to download (e.g., ["mongodb.gz", "mongos.gz", "mongodb-audit-log.gz"])
LOG_FILES = ["mongodb.gz"]

# Time Window (ISO 8601 Recommended)
# Examples: 
#   "2026-04-12T10:00:00-04:00" (EDT Offset)
#   "2026-04-12T10:00:00Z"      (UTC)
# Leave as None for default (Last 24 Hours)
START_TIME = None  
END_TIME = None    

# Target Node Role: 'ALL' (default) or 'PRIMARY'
TARGET_NODE_ROLE = "ALL"

# Parallelization
MAX_CONCURRENCY = 3

# Download Destination
BASE_DOWNLOAD_PATH = "./logs_dump"

import certifi

# SSL Configuration (Required for HTTPS with internal proxy/certs)
# Use 'custom_bundle.pem' for local production API calls
BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "custom_bundle.pem")
ATLAS_CA_BUNDLE = BUNDLE_PATH if os.path.exists(BUNDLE_PATH) else certifi.where()

# Global Session for Retries
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))

# Stats for the final report
stats = {"success": 0, "fail": 0, "skip": 0, "errors": []}

def get_utc_now():
    return datetime.now(timezone.utc)

def parse_timestamp(date_str):
    """
    Converts ISO 8601 strings to UNIX epoch.
    STRICT REQUIREMENT: All time strings MUST include a timezone offset (e.g., -04:00 or Z).
    """
    if not date_str:
        return None
    try:
        # Normalize 'Z' to '+00:00' for compatible parsing
        clean_str = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        
        # Validation: Ensure the datetime is offset-aware
        if dt.tzinfo is None:
            print(f"\n[!] VALIDATION ERROR: Timezone offset is required for '{date_str}'.")
            print(f"    Please use ISO 8601 format with offset (e.g., '2026-04-12T10:00:00-04:00' or '...Z').")
            return None
            
        return int(dt.timestamp())
    except Exception as e:
        print(f"\n[!] ERROR parsing date '{date_str}': {e}")
        return None

def make_atlas_request(method, endpoint, params=None):
    """
    Makes an authenticated GET/POST request to the Atlas Admin API v2.
    
    Args:
        method (str): HTTP method (GET, POST).
        endpoint (str): API endpoint path starting with '/'.
        params (dict, optional): Query parameters for the request.
        
    Returns:
        dict: Parsed JSON response from the API.
        
    Note:
        Uses the 'application/vnd.atlas.2025-03-12+json' header to ensure 
        compatibility with the latest Atlas API versioning.
    """
    url = f"https://cloud.mongodb.com/api/atlas/v2{endpoint}"
    auth = HTTPDigestAuth(ATLAS_PUBLIC_KEY, ATLAS_PRIVATE_KEY)
    headers = {"Accept": "application/vnd.atlas.2025-03-12+json"}
    
    try:
        response = session.request(method, url, auth=auth, params=params, headers=headers, verify=ATLAS_CA_BUNDLE, timeout=30)
        
        if response.status_code == 401:
            logger.error("AUTHENTICATION ERROR: Verify ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY.")
            exit(1)
        if response.status_code == 403:
            logger.error(f"PERMISSION ERROR: IP check or permissions lack. Details: {response.text}")
            exit(1)
        if response.status_code >= 400:
            logger.error(f"API Error ({response.status_code}): {response.text}")
            response.raise_for_status()
            
        return response.json()
    except Exception as e:
        logger.error(f"Network error: {e}")
        exit(1)

def download_log_file(group_id, hostname, log_name, start_epoch, end_epoch, save_path, p_name, c_name):
    """
    Downloads a specific binary log file (.gz) from a target host.
    
    This function is designed to be thread-safe and is executed within
    the ThreadPoolExecutor for parallel performance.
    
    Args:
        group_id (str): Atlas Project ID.
        hostname (str): The node hostname (e.g. shard-00-00.x.mongodb.net).
        log_name (str): Type of log (mongodb.gz, mongos.gz, etc.).
        start_epoch/end_epoch (int): Unix timestamps for the time window.
        save_path (str): Full local path to save the binary file.
        p_name/c_name (str): Project and Cluster names for logging/metadata.
    """
    url = f"https://cloud.mongodb.com/api/atlas/v2/groups/{group_id}/clusters/{hostname}/logs/{log_name}"
    auth = HTTPDigestAuth(ATLAS_PUBLIC_KEY, ATLAS_PRIVATE_KEY)
    headers = {"Accept": "application/vnd.atlas.2025-03-12+gzip"}
    
    params = {}
    if start_epoch: params["startDate"] = start_epoch
    if end_epoch: params["endDate"] = end_epoch
    
    try:
        response = session.get(url, auth=auth, params=params, stream=True, headers=headers, verify=ATLAS_CA_BUNDLE, timeout=60)
        
        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"    [OK] {p_name} | {c_name} | {hostname} | {log_name}")
            stats["success"] += 1
            return True
        elif response.status_code == 404:
            logger.warning(f"  [SKIP] {log_name} not found on {hostname}")
            stats["skip"] += 1
        else:
            logger.error(f" [ERROR] {hostname}:{log_name} -> {response.status_code}")
            stats["fail"] += 1
            stats["errors"].append(f"{hostname}:{log_name} -> {response.status_code}")
    except Exception as e:
        logger.error(f" [FETCH FAILED] {hostname}:{log_name} -> {e}")
        stats["fail"] += 1
        stats["errors"].append(f"{hostname}:{log_name} -> {e}")
    return False

def get_production_targets():
    """
    Identifies the specific projects and clusters to be processed.
    Returns a list of matching targets, each with its ProjectID, Name, and Clusters.
    """
    targets = []
    
    if MODE == "MANUAL":
        # MANUAL Mode: Uses the hardcoded or CLI-provided dictionary
        print(f"Running in MANUAL mode for {len(MANUAL_TARGETS)} projects...")
        for p_name, clusters in MANUAL_TARGETS.items():
            try:
                # Need the Atlas Project ID (Group ID) for further API calls
                resp = make_atlas_request("GET", f"/groups/byName/{p_name}")
                group_id = resp["id"]
                targets.append({"project_id": group_id, "project_name": p_name, "clusters": clusters})
            except Exception as e:
                print(f"\n[!] ERROR: Could not find project '{p_name}'. Please check the name in MANUAL_TARGETS.")
        return targets

    # AUTO Mode: Discovers projects matching keywords in the Organization
    print(f"Running in AUTO mode for Org: {ATLAS_ORG_ID}...")
    try:
        # 1. Fetch all projects linked to this Organization
        resp = make_atlas_request("GET", f"/orgs/{ATLAS_ORG_ID}/groups")
        all_projects = resp.get("results", [])
        
        # 2. Filter projects for production-related keywords
        prod_keywords = ["prod", "production", "prd"]
        for project in all_projects:
            p_name = project["name"].lower()
            # Explicitly exclude 'nonprod', 'staging', 'dev', etc.
            if "nonprod" in p_name or "stg" in p_name or "dev" in p_name:
                continue
                
            # Check if the project name matches any production keyword
            if any(key in p_name.lower() for key in prod_keywords):
                group_id = project["id"]
                
                # 3. For each production project, identify all its clusters
                print(f"  Scanning Production Project: {project['name']} ({group_id})")
                try:
                    c_resp = make_atlas_request("GET", f"/groups/{group_id}/clusters")
                    clusters_data = c_resp.get("results", [])
                    
                    cluster_names = [c["name"] for c in clusters_data]
                    if cluster_names:
                        targets.append({"project_id": group_id, "project_name": p_name, "clusters": cluster_names})
                except Exception as e:
                    print(f"  [!] Failed to fetch clusters for project {p_name}: {e}")
        
    except Exception as e:
        # Most common errors: Invalid Org ID or API keys lacking Org-level permissions
        print(f"\n[!] DISCOVERY FAILED: Likely an invalid ATLAS_ORG_ID or permission issue.")
        print(f"    Check if '{ATLAS_ORG_ID}' is correct and your keys have Org Read access.")
        exit(1)
        
    return targets

def main():
    parser = argparse.ArgumentParser(
        description="MongoDB Atlas Forensic Log Downloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Operational Modes:
  AUTO:   Scans the Organization for all projects containing 'prod', 'production', or 'prd'.
  MANUAL: Uses the MANUAL_TARGETS dictionary defined in the script.

Time Windowing (ISO 8601 MANDATORY):
  Strictly requires offsets to avoid forensic ambiguity.
  Example: "2026-04-12T10:00:00-04:00" (EDT) or "2026-04-12T14:00:00Z" (UTC).
  If no times are provided, the script defaults to the last 24 hours in UTC.

Notes:
  Command-line arguments override any variables hardcoded at the top of the script.
        """
    )
    parser.add_argument("--public-key", help="Atlas API Public Key (Overrides script default)")
    parser.add_argument("--private-key", help="Atlas API Private Key (Overrides script default)")
    parser.add_argument("--org-id", help="Atlas Organization ID (Required for AUTO mode discovery)")
    parser.add_argument("--mode", choices=["AUTO", "MANUAL"], help="Switch between auto-discovery and manual targets")
    parser.add_argument("--start-time", help="Start time (ISO 8601 with offset, e.g. '2026-04-12T10:00:00-04:00')")
    parser.add_argument("--end-time", help="End time (ISO 8601 with offset, e.g. '2026-04-12T10:00:00Z')")
    parser.add_argument("--role", choices=["ALL", "PRIMARY"], help="Fetch logs from 'ALL' nodes or 'PRIMARY' only")
    parser.add_argument("--output-path", help="Local directory to store the .gz log bundles")
    parser.add_argument("--logs", help="Comma-separated log names to fetch (e.g. 'mongodb.gz,mongos.gz')")
    parser.add_argument("--manual-targets", help="JSON string for project-to-cluster mapping (MANUAL mode only)")
    parser.add_argument("--concurrency", type=int, default=3, help="Max parallel downloads (default: 3)")
    
    args = parser.parse_args()

    # Override globals with args
    global ATLAS_PUBLIC_KEY, ATLAS_PRIVATE_KEY, ATLAS_ORG_ID, MODE, START_TIME, END_TIME
    global TARGET_NODE_ROLE, BASE_DOWNLOAD_PATH, LOG_FILES, MANUAL_TARGETS, MAX_CONCURRENCY

    if args.public_key: ATLAS_PUBLIC_KEY = args.public_key
    if args.private_key: ATLAS_PRIVATE_KEY = args.private_key
    if args.org_id: ATLAS_ORG_ID = args.org_id
    if args.mode: MODE = args.mode
    if args.start_time: START_TIME = args.start_time
    if args.end_time: END_TIME = args.end_time
    if args.role: TARGET_NODE_ROLE = args.role
    if args.output_path: BASE_DOWNLOAD_PATH = args.output_path
    if args.logs: LOG_FILES = [log.strip() for log in args.logs.split(",")]
    if args.concurrency: MAX_CONCURRENCY = args.concurrency
    if args.manual_targets:
        try:
            MANUAL_TARGETS = json.loads(args.manual_targets)
        except Exception as e:
            print(f"ERROR: Failed to parse --manual-targets JSON: {e}")
            return

    if not all([ATLAS_PUBLIC_KEY, ATLAS_PRIVATE_KEY, ATLAS_ORG_ID]):
        print("\n[!] CONFIGURATION ERROR: Missing required Atlas credentials.")
        print("    You must provide them via:")
        print("    1. Command line args (--public-key, --private-key, --org-id)")
        print("    2. Environment variables or a local .env file.")
        sys.exit(1)

    # 1. Setup Time Window (Strict Validation for user-provided strings)
    # The Atlas API expects numeric Unix timestamps for log boundaries.
    # Forensic context: We mandate timezone offsets to ensure there is zero ambiguity
    # when comparing Atlas server logs (usually UTC) with local incident times.
    now_epoch = int(time.time())
    
    if START_TIME:
        start_epoch = parse_timestamp(START_TIME)
        if start_epoch is None:
            return  # Exit on validation failure
    else:
        # Default fallback logic: Process the most recent 24-hour cycle
        start_epoch = now_epoch - (24 * 3600)
        
    if END_TIME:
        end_epoch = parse_timestamp(END_TIME)
        if end_epoch is None:
            return  # Exit on validation failure
    else:
        # Default fallback logic: Stop at the current system time
        end_epoch = now_epoch

    print(f"Time Range: {time.ctime(start_epoch)} to {time.ctime(end_epoch)}")

    # 2. Setup Output Directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_folder = f"atlaslogs_{timestamp}"
    full_output_path = os.path.join(BASE_DOWNLOAD_PATH, report_folder)
    os.makedirs(full_output_path, exist_ok=True)
    print(f"Output directory: {full_output_path}")

    # 3. Identify Targets
    targets = get_production_targets()
    if not targets:
        print("No matching projects or clusters found.")
        return

    print(f"Starting download for {len(targets)} projects...")

    # 4. Main Processing Cycle (Parallelized)
    download_tasks = []
    
    for target in targets:
        p_id = target["project_id"]
        p_name = target["project_name"]
        
        for c_name in target["clusters"]:
            logger.info(f"Scanning Nodes for Cluster: {c_name} in Project: {p_name}")
            try:
                proc_resp = make_atlas_request("GET", f"/groups/{p_id}/processes", params={"itemsPerPage": 500})
                all_processes = proc_resp.get("results", [])
                c_name_clean = c_name.strip().lower()
                
                for proc in all_processes:
                    hostname = (proc.get("hostname") or "").lower()
                    alias = (proc.get("userAlias") or "").lower()
                    
                    # Node Matching Logic:
                    # Atlas process hostnames and userAliases often differ or contain project-specific prefixes.
                    # We use a multi-stage fallback matching strategy:
                    # 1. Direct prefix match (Cluster Name == Hostname Start).
                    # 2. Alias match (Cluster Name is part of the User Alias).
                    # 3. Base Shard match (Handles -shard-00-00 naming conventions).
                    is_match = (c_name_clean == hostname.split(":")[0]) or (c_name_clean == alias.split(":")[0])
                    if not is_match and alias:
                        # Extract the base cluster name from a complex shard/config alias
                        alias_base = alias.split("-shard-")[0].split("-config-")[0].split("-mongos-")[0]
                        is_match = (c_name_clean in alias) or (c_name_clean in hostname) or \
                                   (alias_base in c_name_clean and len(alias_base) > 5) or \
                                   (c_name_clean.startswith(alias_base) or alias_base.startswith(c_name_clean))

                    if is_match:
                        if TARGET_NODE_ROLE == "PRIMARY" and proc.get("typeName") != "REPLICA_PRIMARY":
                            continue
                        
                        hostname_clean = hostname.split(":")[0]
                        for log_type in LOG_FILES:
                            file_name = f"{p_name}_{c_name}_{hostname_clean}_{log_type}"
                            save_path = os.path.join(full_output_path, file_name)
                            
                            # Add to thread pool queue
                            download_tasks.append({
                                "group_id": p_id,
                                "hostname": hostname_clean,
                                "log_name": log_type,
                                "start_epoch": start_epoch,
                                "end_epoch": end_epoch,
                                "save_path": save_path,
                                "p_name": p_name,
                                "c_name": c_name
                            })
            except Exception as e:
                logger.error(f"Failed to scan cluster {c_name}: {e}")

    # Step 5: Execute Downloads in Parallel
    if not download_tasks:
        logger.warning("No nodes found for the selected criteria.")
        return

    logger.info(f"Executing {len(download_tasks)} parallel downloads (Concurrency: {MAX_CONCURRENCY})...")
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as executor:
        futures = [executor.submit(download_log_file, **task) for task in download_tasks]
        try:
            for future in as_completed(futures):
                future.result() # Propagate exceptions if any
        except KeyboardInterrupt:
            logger.warning("\n[!] Execution interrupted by user. Stopping...")
            executor.shutdown(wait=False)
            exit(1)

    # Step 6: Final Summary
    logger.info("=" * 60)
    logger.info("DOWNLOAD SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  SUCCESS: {stats['success']}")
    logger.info(f"  SKIPPED: {stats['skip']}")
    logger.info(f"  FAILED:  {stats['fail']}")
    
    if stats["errors"]:
        logger.info("-" * 60)
        logger.info("  FAILED TASKS:")
        for err in stats["errors"]:
            logger.info(f"    - {err}")
    logger.info("=" * 60)
    logger.info(f"Artifacts saved in: {full_output_path}")

if __name__ == "__main__":
    main()
