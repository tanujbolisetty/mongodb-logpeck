import sys
import logging
from typing import List, Optional, Dict, Any, Union
from .analyzer import read_logs_chunked, build_forensic_context, normalize_conn_id
from .parser import extract_log_metrics, get_nested_value, detect_op_and_ns

logger = logging.getLogger(__name__)

def search_logs(
    log_file_path: str, 
    keyword: str, 
    limit: int = 10, 
    count_only: bool = False
) -> Union[List[Dict[str, Any]], int]:
    """
    High-fidelity stateful keyword search across JSON logs.
    Implements 2-pass forensic reconstruction for absolute accuracy.
    """
    # 🕵️ Forensic Pass 1: Global Multi-Context Sweep (MCS)
    # Builds the high-speed connection registry and namespace cache for the entire trace.
    # Essential for attributing collections to lean timeout events in v2.0.0.
    context_cache = build_forensic_context(log_file_path)
    
    results = []
    count = 0
    keyword_lower = keyword.lower()
    
    print(f"🔎 Forensic Pass 2: Discovery & Backfilling for '{keyword}'...", file=sys.stderr)
    
    for entry in read_logs_chunked(log_file_path):
        attr = entry.get("attr", {})
        if not isinstance(attr, dict): attr = {}
        
        ctx = normalize_conn_id(entry.get("ctx", ""))
        msg = str(entry.get("msg", ""))
        
        # Build discovery search space
        err_hint = ""
        if isinstance(attr.get("error"), dict):
            err_hint = str(attr["error"].get("errmsg", ""))
        else:
            err_hint = str(attr.get("error", ""))
        
        search_space = (msg + " " + str(entry.get("ctx", "")) + " " + err_hint + " " + str(attr.get("errmsg", ""))).lower()
        command_space = str(attr.get("command", "")).lower() + " " + str(attr.get("originatingCommand", "")).lower()
        
        found = False
        if keyword_lower in search_space or keyword_lower in command_space:
            found = True
        elif keyword_lower in str(attr.get("queryHash", "")).lower():
            found = True
        elif keyword_lower in str(attr.get("queryShapeHash", "")).lower():
            found = True
        
        if found:
            count += 1
            if not count_only:
                # 🦷 Forensic Backfilling: Extract metrics and merge reconstructed state
                metrics = extract_log_metrics(entry) or {}
                res_ns = metrics.get("ns")
                if (not res_ns or res_ns in ["unknown", "$cmd", "None"]):
                    metrics["ns"] = context_cache.get(ctx, "unknown")
                
                if not metrics.get("ns"): metrics["ns"] = "unknown"
                
                entry["metrics"] = metrics
                results.append(entry)
                if len(results) >= limit: break
            
    return count if count_only else results

def filter_logs(
    log_file_path: str, 
    filters: Dict[str, Any], 
    limit: int = 10, 
    count_only: bool = False
) -> Union[List[Dict[str, Any]], int]:
    """
    Complex multidimensional filtering (Duration, Namespace, Severity).
    Implements 2-pass forensic reconstruction for absolute accuracy.
    """
    # 🕵️ Forensic Pass 1: Global Multi-Context Sweep (MCS)
    context_cache = build_forensic_context(log_file_path)
    
    results = []
    count = 0
    
    print(f"🔎 Forensic Pass 2: Discovery & Backfilling for Filter {filters}...", file=sys.stderr)
    
    for entry in read_logs_chunked(log_file_path):
        ctx = normalize_conn_id(entry.get("ctx", ""))
        metrics = extract_log_metrics(entry, include_full_command=True) or {}
        
        # 🦷 Forensic Backfilling
        if (not metrics.get("ns") or metrics.get("ns") in ["unknown", "$cmd", "None"]):
            metrics["ns"] = context_cache.get(ctx, "unknown")
        
        if not metrics.get("ns"): metrics["ns"] = "unknown"

        match = True
        for key, val in filters.items():
            # Deep Metric Lookup (v2.5.0)
            actual = metrics.get(key)
            if actual is None:
                # Check forensic sub-dict (e.g. keysExamined, keysInserted)
                actual = metrics.get("forensic", {}).get(key)
            if actual is None:
                # Check wait metrics (e.g. storage_wait, lock_wait)
                actual = metrics.get("waits_ms", {}).get(key)
            if actual is None:
                actual = get_nested_value(entry, key)
            
            if actual is None:
                match = False; break
                
            if isinstance(val, dict):
                for op, expected in val.items():
                    if not _compare(actual, op, expected):
                        match = False; break
                if not match: break
            else:
                if not _compare(actual, "eq", val):
                    match = False; break
                
        if match:
            count += 1
            if not count_only:
                entry["metrics"] = metrics
                results.append(entry)
                if len(results) >= limit: break
            
    return count if count_only else results

def _compare(actual, op, expected):
    """Forensic comparator for multidimensional filtering."""
    try:
        if op == "eq": return str(actual).lower() == str(expected).lower()
        if op == "gt": return float(actual) > float(expected)
        if op == "lt": return float(actual) < float(expected)
        if op == "contains": return str(expected).lower() in str(actual).lower()
    except: pass
    return False
