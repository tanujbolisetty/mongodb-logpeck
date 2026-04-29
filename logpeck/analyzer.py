# ==============================================================================
# logpeck: analyzer.py
# The High-Performance Forensic Engine for MongoDB Atlas logs.
# ==============================================================================
# This module implements a distributed-aware, two-pass analysis architecture
# designed to synthesize high-resolution forensic insights from massive log datasets.
#
# ARCHITECTURE OVERVIEW:
# ----------------------
# 1. Pass 1 (Sweep): 
#    - Purpose: High-speed linear scan to build "Identity Registries".
#    - Tasks: Stitch Connection-to-App mappings, recover Primary node identity, 
#      and capture slow query "Witness" objects for deep inspection.
#
# 2. Pass 2 (Synthesis):
#    - Purpose: Hierarchical Aggregation & Diagnostic Evaluation.
#    - Tasks: Hash queries into "Shapes", elevate background noise (Gossip), 
#      attribute bottlenecks (I/O, CPU, Queue), and run the Diagnostic Rule Engine.
# ==============================================================================

import os
import re
import json
import time
import gzip
import sys
from collections import Counter
from typing import List, Optional, Dict, Any, Tuple
from .parser import (
    parse_log_line, extract_log_metrics, is_system_query, heuristic_extract_ns, 
    detect_op_and_ns, normalize_conn_id, induce_log_schema, get_nested_value
)
from .specification import (
    SYSTEM_EVENT_IDENTIFIERS, SIMPLIFIED_OPS, LIFECYCLE_EVENT_IDENTIFIERS, 
    GOSSIP_EVENT_IDENTIFIERS, ERROR_CODE_MAP
)
from .version import __version__
from .utils import format_duration

EXCLUDED_EVENT_IDS = {"51800", "21530", "18", "22943", "22944", "5286306", "51801", "4651401", "20478", "20526", "23799"}


RE_OBJECT_ID = re.compile(r'ObjectId\([^)]+\)')
RE_TIMESTAMP = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*')
SEVERITY_MAP = {"I": "INFO", "W": "WARN", "E": "ERROR", "F": "FATAL", "D": "DEBUG", "D1": "DEBUG", "D2": "DEBUG"}
LATENCY_BUCKETS = [100, 250, 500, 1000, 2000, 5000, 10000]

def load_diagnostic_rules() -> List[dict]:
    """
    Loads the authoritative forensic audit rules from the internal rules.json.
    """
    path = os.path.join(os.path.dirname(__file__), "rules.json")
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f: return json.load(f).get("rules", [])
        except: pass
    return []

def evaluate_rule(rule: dict, data: dict) -> Tuple[bool, Optional[float]]:
    """
    Evaluates a forensic diagnostic rule against extracted metrics.
    Supports thresholds, ratios, and pattern-based logic.
    """
    op = str(data.get("op", ""))
    if "exclude_ops" in rule and op in rule["exclude_ops"]: return False, None
    if "include_ops" in rule and op not in rule["include_ops"]: return False, None
    r_type = rule.get("type")
    try:
        if r_type == "pattern":
            val = data.get(rule["field"], "")
            if rule["op"] == "contains" and str(rule["value"]) in str(val): return True, None
        elif r_type == "logic":
            if rule["id"] == "UNINDEXED_SORT":
                plan = str(data.get("plan_summary", ""))
                if "SORT" in plan and "IXSCAN" not in plan: return True, None
        elif r_type == "threshold":
            val = data.get(rule["field"], 0)
            if rule["op"] == "gt" and val > rule["value"]: return True, float(val)
            if rule["op"] == "eq" and val == rule["value"]: return True, float(val)
            if rule["op"] == "in" and val in rule["value"]: return True, float(val)
        elif r_type == "ratio":
            num = data.get(rule["numerator"], 0)
            den = data.get(rule["denominator"], 1) or 1
            if num < rule.get("min_numerator", 0): return False, None
            if data.get("count", 0) < rule.get("min_count", 0): return False, None
            ratio = num / den
            if ratio > rule["threshold"]: return True, ratio
    except: pass
    return False, None

def harvest_error_code(attr: dict, is_timeout: bool = False) -> Optional[int]:
    """
    Surgically extracts the numerical error code from potentially nested blocks.
    Priority: 1. Top-level errCode, 2. Top-level code, 3. Nested error.code
    """
    if not isinstance(attr, dict): return 50 if is_timeout else None
    
    # 1. Direct Extraction
    code = attr.get("errCode") or attr.get("code")
    
    # 2. Deep Harvesting (Nested Error Objects)
    if code is None and isinstance(attr.get("error"), dict):
        e_obj = attr["error"]
        code = e_obj.get("code") or e_obj.get("value")
        
    # 3. Timeout Defaulting
    if code is None and is_timeout:
        return 50
        
    # 4. Type Normalization (ensure int if it looks like one)
    try:
        if code is not None:
            return int(code)
    except (ValueError, TypeError):
        pass
        
    return code

def read_logs_chunked(file_path: str):
    is_gz = file_path.lower().endswith(".gz")
    opener = gzip.open(file_path, 'rt', encoding='utf-8') if is_gz else open(file_path, 'r', encoding='utf-8')
    with opener as f:
        for line in f:
            entry = parse_log_line(line)
            if entry: yield entry


def build_forensic_context(log_file_path: str) -> Dict[str, Dict[str, str]]:
    """
    The Pre-Scan Discovery Layer (v5.0.1).
    
    Performs a high-speed context sweep of the log file to build a map 
    of Connection ID -> {Namespace, AppName}.
    
    WHY: In many failure logs (e.g., Timeouts), the namespace or app identity 
    is missing. By pre-sweeping, we can correctly attribute 'conn123' to 
    'Compass' or the 'inventory.items' collection.
    """
    ctx_registry = {}  # { ctx: { "ns": "...", "app": "..." } }
    total_parsed = 0
    import sys
    print(f"🔬 Forensic Context Sweep (v{__version__})...", file=sys.stderr)
    
    try:
        f_opener = gzip.open(log_file_path, 'rt', encoding='utf-8') if log_file_path.endswith('.gz') else open(log_file_path, 'r', encoding='utf-8')
        with f_opener as f:
            for entry in f:
                total_parsed += 1
                try:
                    # 🕵️ Surgical JSON Extraction (v4.1.3): 
                    # Many logs have a plaintext timestamp prefix before the '{' JSON block.
                    j_idx = entry.find('{')
                    if j_idx == -1: continue
                    obj = json.loads(entry[j_idx:])
                    if total_parsed % 500000 == 0: print(f"  ↳ {total_parsed:,} lines swept...")
                    
                    ctx = normalize_conn_id(obj.get("ctx", ""))
                    attr = obj.get("attr", {})
                    if not isinstance(attr, dict): continue
                    
                    if ctx not in ctx_registry:
                        ctx_registry[ctx] = {"ns": "unknown", "app": "unknown"}

                    # Capture Identity (from metadata handshake 22944)
                    app = str(attr.get("appName") or attr.get("doc", {}).get("application", {}).get("name") or "unknown")
                    if app != "unknown":
                        ctx_registry[ctx]["app"] = app

                    # Identify the namespace (db.collection) active on this context
                    p_cmd = attr.get("command") or attr.get("originatingCommand") or attr.get("doc", {}).get("q")
                    raw_ns = attr.get("ns")
                    if raw_ns and raw_ns != "unknown":
                        _, res_ns, _ = detect_op_and_ns(attr, p_cmd or {}, str(obj.get("msg", "")), raw_ns)
                        ctx_registry[ctx]["ns"] = str(res_ns)
                except: continue
    except Exception as e:
        print(f"  ⚠️ Context sweep partially interrupted: {e}")
    
    return ctx_registry

def analyze_slow_queries(log_file_path: str, threshold_ms: int = 0) -> Dict[str, Any]:
    """
    The Orchestration Hub for Forensic Analysis.
    
    This function coordinates the Two-Pass analysis workflow:
    1. Pass 1 (Sweep): Linear scan to capture raw telemetry, stitch sessions, 
       and filter noise.
    2. Pass 2 (Synthesis): Semantic aggregation into shapes and rule-based 
       bottleneck attribution.
    
    Returns: A nested dictionary containing global stats, connection metadata, 
             and synthesized shape summaries (Workload, System, Timeouts).
    """
    start_time = time.time(); rules = load_diagnostic_rules()
    
    # 📑 Core Analytics Registries
    severity_stats = Counter(); component_stats = Counter(); namespace_stats = Counter()
    message_registry = {} # Unique log message snippets
    conn_registry = {}    # Connection state (IP, User, App)
    auth_fail_count = 0; timeout_count = 0; identified_error_count = 0; timeout_patterns = {}
    system_error_patterns = {} # 🛠️ Capture network/system errors without query hashes
    error_namespace_stats = Counter(); error_code_agg = {}
    global_latency_dist = Counter()
    
    # 📑 Shape & Clinical Registries
    session_ns_map = {}; session_app_map = {}; shape_stats = {}
    gh_counts = Counter(); global_bottlenecks = Counter()
    system_shape_stats = {} # 🏥 System-level events (Replica Set, TTL, etc.)
    timeout_shape_stats = {} # 🚨 Critical Timeouts (Wait, ExceededLimit)
    last_op_cache = {}      # 🔄 Stateful Operation Correlation
    last_ns_cache = {}      # 🔄 Stateful Namespace Tracking
    
    # 📑 Identity Registries (MSH Matrix)
    app_registry = Counter(); user_registry = Counter(); ip_registry = Counter(); op_registry = Counter()
    global_forensic_sums = Counter() # Sum of all forensic markers (keysExamined, etc.)
    global_app_driver_map = {}
    conn_metadata = {}  # 🔑 MSH Matrix: {ctx: {"app": str, "user": str, "ip": str, "driver": str}}
    engine_errors = [] 
    cursor_hash_map = {}
    op_id_hash_map = {}  # 🔄 Stateful Operation Mapping
    
    total_parsed = 0; total_filtered = 0; total_slow_count = 0; total_accepted = 0; total_closed = 0
    start_ts = None; end_ts = None

    # 🕵️ PASS 1: Light-Speed Forensic Sweep
    # Purpose: Capture every slow query, stitch sessions/ips, and map cursors.
    print(f"\n🔬 Pass 1: Light-Speed Forensic Sweep (v{__version__})...", file=sys.stderr)

    last_known_ts = None
    try:
        f_opener = gzip.open(log_file_path, 'rt', encoding='utf-8') if log_file_path.endswith('.gz') else open(log_file_path, 'r', encoding='utf-8')
        with f_opener as f:
            for entry in f:
                total_parsed += 1
                try:
                    # 🕵️ Surgical JSON Extraction (v4.1.3): Skip plaintext timestamp prefixes
                    j_idx = entry.find('{')
                    if j_idx == -1: continue
                    obj = json.loads(entry[j_idx:])
                    
                    # 🧪 Unified Schema Induction (v3.2.12)
                    header = induce_log_schema(obj, last_known_ts)
                    ts = header["t"]
                    if ts:
                        if not start_ts: start_ts = str(ts)
                        end_ts = str(ts)
                        last_known_ts = ts
                    
                    if total_parsed % 500000 == 0: print(f"  ↳ {total_parsed:,} lines processed...", file=sys.stderr)
                    
                    s = header.get("s", "I"); sev = str(SEVERITY_MAP.get(s, s)); severity_stats[sev] += 1
                    c = header.get("c", "unknown"); component_stats[c] += 1
                    msg = header.get("msg", "unknown"); norm_msg = RE_OBJECT_ID.sub('...', msg) if "ObjectId(" in msg else msg
                    ctx = header.get("ctx", "unknown")
                    
                    # 💡 Context-Aware Error Tracking (v1.3.4)
                    m_key = (sev, str(norm_msg[:80]))
                    if m_key not in message_registry:
                        message_registry[m_key] = {"count": 0, "preview": "N/A"}
                    message_registry[m_key]["count"] += 1
                    
                    # 🧪 Early Forensic Matrix Extraction (v3.2.4)
                    metrics = extract_log_metrics(obj, include_full_command=True, last_ts=last_known_ts)
                    attr = metrics.get("attr") or obj.get("attr", {})
                    op = metrics.get("op") or "unknown"
                    log_id = str(obj.get("id", "")) or op
                    
                    # 🏺 Forensic Injection into MSH Matrix (v2.6.22: Metadata Priority)
                    if log_id in EXCLUDED_EVENT_IDS:
                        if log_id == "22943": total_accepted += 1
                        if log_id == "22944": total_closed += 1
                        user = str(attr.get("user") or "unknown")
                        app = str(attr.get("appName") or attr.get("doc", {}).get("application", {}).get("name") or "unknown")
                        ip_raw = str(attr.get("remote", attr.get("client", "unknown")))
                        ip = str(ip_raw.split(":")[0] if ":" in ip_raw else ip_raw)
                        md = {}
                        cm_obj = attr.get("clientMetadata")
                        d_obj = attr.get("doc", {}).get("driver")
                        if isinstance(cm_obj, dict): md = cm_obj.get("driver", {})
                        if not md and isinstance(d_obj, dict): md = d_obj
                        
                        d_str = "unknown"
                        if md and isinstance(md, dict):
                            m_n = str(md.get('name', 'unknown'))
                            m_v = str(md.get('version', 'unknown'))
                            if m_n != "unknown":
                                d_str = f"{m_n} v{m_v}" if m_v != "unknown" else m_n
                                if app != "unknown": global_app_driver_map[app] = d_str
                        
                        if ctx not in conn_metadata: conn_metadata[ctx] = {"app": "unknown", "user": "unknown", "ip": "unknown", "driver": "unknown"}
                        if app != "unknown": conn_metadata[ctx]["app"] = app
                        if user != "unknown": conn_metadata[ctx]["user"] = user
                        if ip != "unknown": conn_metadata[ctx]["ip"] = ip
                        if d_str != "unknown": conn_metadata[ctx]["driver"] = d_str
                        if d_str != "unknown":
                            if ctx not in conn_registry: conn_registry[ctx] = {}
                            conn_registry[ctx]["driver"] = d_str
                        continue

                    # 🚦 Deep-Scan Diagnostic Triage (v1.3.14)
                    attr_safe = (attr or {})
                    err_hint = str(attr_safe.get("error", obj.get("error", "")))
                    if isinstance(attr_safe.get("error") or obj.get("error"), dict):
                        e_obj = attr_safe.get("error") or obj.get("error")
                        err_hint = str(e_obj.get("errmsg", e_obj.get("errMsg", "")))
                    attr_err = str(attr_safe.get("errmsg", attr_safe.get("errMsg", obj.get("errmsg", obj.get("errMsg", "")))))
                    attr_name = str(attr_safe.get("errName", obj.get("errName", "")))
                    search_space = (msg + " " + err_hint + " " + attr_err + " " + attr_name).lower()
                    
                    timeout_sigs = [
                        "exceeded time limit", "exceededtimelimit", "timed out", 
                        "deadline exceeded", "code: 50", "code: 202", 
                        "networkinterfaceexceededtimelimit",
                        "operation timed out while waiting to acquire connection"
                    ]
                    
                    # 🧪 Early Failure Detection (v2.7.8): Capture FATAL/ERROR logs even if attr is missing
                    # 🕵️ Senior Logic: Expand error search space to include common network and lifecycle failures.
                    # 🧪 Early Failure Detection (v5.0.4): Hardened Severity Triage
                    # 🕵️ Senior Logic: We ignore Severity 'I' (Informational) logs as failures UNLESS:
                    # 1. They are an explicit Timeout Signature (e.g., Code 50).
                    # 2. They contain an explicit error 'code' or 'errCode' field.
                    # This prevents high-volume infrastructure noise (like heartbeat disconnects) from clogging forensics.
                    
                    FAILURE_SIGNATURES = [
                        "error", "failed", "failure", "socketexception", "clientdisconnect", "interrupted", 
                        "exceededtimelimit", "networkinterface", "steppeddown", "primarysteppeddown",
                        "notyetinitialized", "invalidsyncsource", "terminated", "connection closed",
                        "infrastructure failure"
                    ]
                    
                    is_timeout_op = any(sig in search_space for sig in timeout_sigs) or "planexecutor error" in search_space
                    has_error_code = any(k in (attr or {}) or k in obj for k in ["errCode", "code"])
                    
                    # Core Predicate: Real errors are Warning/Error/Fatal OR (Info + Explicit Code/Timeout)
                    is_error_op_base = (sev in ["ERROR", "FATAL", "WARN", "E", "F", "W"]) or \
                                      ((is_timeout_op or has_error_code) and sev in ["INFO", "I"]) or \
                                      (any(sig in search_space for sig in FAILURE_SIGNATURES) and sev not in ["INFO", "I"])
                    
                    if not isinstance(attr, dict):
                        # 🧪 Lean Log Induction (v3.2.13): Allow logs without 'attr' if they have durations or are errors.
                        if is_error_op_base or is_timeout_op or metrics.get("ms", 0) > 0:
                            attr = {} 
                        else:
                            continue

                    # 🧬 Soundness Correction (v5.0.6): Unified Distinct Error Triage
                    # Ensure each problematic log line is counted exactly once in the global error registry.
                    # We prioritize explicit failures (ok:0, error codes) even if logged as 'INFO'.
                    is_error_op = is_error_op_base
                    
                    # 🕵️ Noise Suppression Blacklist: Skip known heartbeat/access noise
                    NOISE_BLACKLIST = ["reauthenticate", "JWK Set", "certificate expiration", "heartbeat"]
                    is_noise = any(n.lower() in msg.lower() for n in NOISE_BLACKLIST)
                    
                    if not is_noise:
                        if any(k in (attr or {}) or k in obj for k in ["error", "errCode", "code"]) or str((attr or {}).get("ok", obj.get("ok"))) == "0":
                            is_error_op = True
                        if "errorMessage" in obj or "errmsg" in obj:
                            is_error_op = True
                        if header.get("msg") == "Infrastructure Failure":
                            is_error_op = True
                    else:
                        # If it's identified as noise, we explicitly downgrade it
                        is_error_op = False
                    
                    if is_error_op:
                        identified_error_count += 1
                    
                    if is_timeout_op:
                        timeout_count += 1
                        # 🕵️ Smart Namespace Discovery for Timeouts (v1.3.21)
                        ns_guess = attr.get("ns")
                        if not ns_guess or str(ns_guess).endswith(".$cmd"):
                            p_cmd = attr.get("command") or attr.get("originatingCommand") or {}
                            _, res_ns, _ = detect_op_and_ns(attr, p_cmd, msg, ns_guess or "unknown")
                            ns_guess = res_ns
                        
                        # 🧪 Heuristic Fallback (v2.7.11): Try to extract NS from the message text if still missing
                        if not ns_guess or ns_guess == "unknown" or ns_guess == "N/A":
                            ns_guess = str(heuristic_extract_ns(search_space) or last_ns_cache.get(ctx) or "N/A")
                        else:
                            ns_guess = str(ns_guess)

                        
                        # 🏮 High-Resolution Error Signature (v4.3.5)
                        # Identify timeout signatures without forcing a default error code.
                        e_code = attr.get("errCode") or attr.get("code") or p_cmd.get("code")
                        
                        # 🧪 Deep Error Extraction (v4.5.4): Support nested asio/system error objects
                        if not e_code and isinstance(attr.get("error"), dict):
                            e_code = attr["error"].get("value") or attr["error"].get("code")
                        
                        e_name = attr.get("errName") or attr.get("errorName") or p_cmd.get("errName")
                        if not e_name and e_code in ERROR_CODE_MAP:
                            e_name = ERROR_CODE_MAP[e_code]
                        
                        e_msg = attr.get("errMsg") or attr.get("errorMsg") or attr.get("error") or p_cmd.get("error")
                        if isinstance(e_msg, dict):
                            e_msg = e_msg.get("message") or e_msg.get("what") or str(e_msg)

                        # 🧪 Context-Aware Labeling (v4.5.4)
                        if "asio.system" in search_space or "set_option" in search_space:
                            display_err = f"System: {e_msg or msg}"
                        elif "maxtimemsexpired" in search_space or "exceeded time limit" in search_space or e_code == 50:
                            display_err = "MaxTimeMSExpired: operation exceeded time limit"
                        else:
                            display_err = msg
                            # Extract error components from both attr and cmd_obj
                            if e_name and e_msg:
                                display_err = f"{e_name}: {e_msg}"
                            elif e_name:
                                display_err = str(e_name)
                            elif e_msg:
                                display_err = str(e_msg)
                        
                        key = (ns_guess, str(display_err[:100]))
                        dur_ms = attr.get("durationMillis", 0) or 0
                        if key not in timeout_patterns:
                            preview = str((attr.get("command", {}) or {}).get("filter") or (attr.get("command", {}) or {}).get("pipeline") or "N/A")
                            if preview == "N/A": 
                                preview = last_op_cache.get(ctx, "N/A")
                            timeout_patterns[key] = {
                                "count": 0, "ts": str(ts), "msg": str(display_err[:120]), "ns": ns_guess, "op": "unknown",
                                "preview": preview,
                                "remote": str(attr.get("remote", "-")), "ctx": str(obj.get("ctx", "-")),
                                "error_code": e_code,
                                "total_ms": 0, "max_ms": 0,
                                "app_name": str(attr.get("appName") or conn_registry.get(ctx, {}).get("app") or "unknown")
                            }
                        timeout_patterns[key]["count"] += 1
                        timeout_patterns[key]["total_ms"] += dur_ms
                        timeout_patterns[key]["max_ms"] = max(timeout_patterns[key]["max_ms"], dur_ms)

                        error_namespace_stats[ns_guess] += 1
                    
                    if is_error_op and not is_timeout_op:
                        # 🧬 High-Resolution Systemic Error Extraction (v4.6.3)
                        # Extract the most meaningful label for the summary, but keep the payload raw.
                        e_cat = attr.get("category") or header.get("c") or "SYSTEM"
                        
                        # Preferred extraction order for the "Summary" column
                        raw_err = attr.get("error") or attr.get("errmsg") or attr.get("message") or msg
                        if isinstance(raw_err, dict):
                            e_msg = raw_err.get("errmsg") or raw_err.get("message") or raw_err.get("codeName") or str(raw_err)
                        else:
                            e_msg = str(raw_err)
                            
                        e_note = attr.get("note", "N/A")
                        
                        # 🧪 Technical Forensic Payload: Deeply harvest codes from nested blocks
                        err_payload = {k: v for k, v in attr.items() if k in ["what", "message", "category", "value", "code", "codeName", "errmsg", "note", "error", "reason"]}
                        
                        # Promote numerical codes from nested error objects if present
                        sys_code = harvest_error_code(attr, is_timeout=False)
                        
                        # Promote specific names for high-frequency errors
                        if sys_code == 11000 or "E11000" in str(e_msg):
                            e_msg = f"DuplicateKey: {e_msg}"
                        elif sys_code == 13 or "Unauthorized" in str(e_msg):
                            e_msg = f"Unauthorized: {e_msg}"
                        elif "ConnectionPoolExpired" in str(e_msg):
                            e_msg = f"ConnectionPoolExpired: {e_msg}"

                        # Hardened Payload Guard: Skip if empty forensic evidence exists for informational logs
                        if not err_payload and (sev in ["INFO", "I"] or not is_error_op):
                            continue
                        
                        # Ensure we don't have empty messages
                        if not e_msg or e_msg.strip() == "":
                            e_msg = msg or "Unknown System Error"

                        key = (str(e_cat), str(e_msg)[:120], str(e_note)[:50])
                        if key not in system_error_patterns:
                            system_error_patterns[key] = {
                                "ts": str(ts),
                                "category": str(e_cat).upper(),
                                "msg": str(e_msg)[:150],
                                "note": str(e_note)[:120],
                                "code": str(sys_code) if sys_code is not None else "N/A",
                                "count": 0,
                                "payload": json.dumps(err_payload, indent=2) if err_payload else "N/A"
                            }
                        system_error_patterns[key]["count"] += 1

                    if not isinstance(attr, dict): continue

                    if "Authentication failed" in msg: auth_fail_count += 1
                    if msg == "Slow query": total_slow_count += 1
                    
                    # 🕵️ Identity & Bottleneck Discovery (v2.7.4)
                    curr_op = metrics.get("op", "unknown")
                    curr_ns = metrics.get("ns", "unknown")
                    
                    duration = metrics.get("ms", 0)
                    waits = metrics.get("waits_ms", {})
                    io_ms = waits.get("storage_wait", 0)
                    cpu_ms = waits.get("cpu_time", 0) or (duration - sum(waits.values()) if duration > sum(waits.values()) else 0)
                    
                    # 📊 High-Fidelity Bottleneck Aggregation (v3.3.3)
                    # Distinguish between Tickets (Admission), Locks (Contention), and Repl (Throttling)
                    f_data = metrics.get("forensic", {})
                    op_ms = f_data.get("totalOplogSlotDurationMicros", 0) / 1000.0
                    repl_ms = f_data.get("flowControlMillis", 0)
                    q_ms = f_data.get("totalTimeQueuedMicros", 0) / 1000.0
                    l_ms = waits.get("lock_wait", 0)
                    
                    global_bottlenecks["storage_ms"] += max(0, io_ms - op_ms)
                    global_bottlenecks["cpu_ms"] += cpu_ms
                    global_bottlenecks["oplog_ms"] += op_ms
                    global_bottlenecks["queue_ms"] += q_ms
                    global_bottlenecks["lock_ms"] += l_ms
                    global_bottlenecks["repl_ms"] += repl_ms
                    global_bottlenecks["planning_ms"] += waits.get("planning", 0)
                    
                    # 📊 Full Portfolio Instrumentation (v2.2.0)
                    op_registry[str(metrics.get("op", "unknown"))] += 1
                    for fk, fv in metrics.get("forensic", {}).items():
                        if isinstance(fv, (int, float)):
                            global_forensic_sums[fk] += fv
                    
                    # 🔗 Stateful Session Discovery (v2.7.2 Fix)
                    # Check top-level attr and nested parameters block for session ID.
                    lsid_obj = attr.get("lsid") or attr.get("parameters", {}).get("lsid") or {}
                    lsid = str(lsid_obj.get("id", ""))
                    
                    # 🔗 Stateful Session Reconstruction (v1.1.49)
                    if lsid:
                        ns_val = str(metrics.get("ns", "unknown"))
                        app_val = str(metrics.get("app_name", "unknown"))
                        # 🔗 Stateful Session Reconstruction (v2.7.3 Hardening)
                        # Remove the "not in" guard to allow the MOST RECENT business collection to be the anchor.
                        if ns_val != "unknown" and not ns_val.endswith(".$cmd"): 
                            session_ns_map[lsid] = ns_val
                        if app_val != "unknown": 
                            session_app_map[lsid] = app_val
                    
                    is_inferred = False
                    
                    # 🔗 Stateful Cursor Grouping (v1.1.49)
                    cursor_id = attr.get("cursorid") or metrics.get("command", {}).get("getMore")
                    if cursor_id:
                        c_id_str = str(cursor_id)
                        q_hash = metrics.get("query_shape_hash")
                        if q_hash and q_hash != "N/A":
                            cursor_hash_map[c_id_str] = q_hash
                        elif metrics.get("op") == "getmore" and c_id_str in cursor_hash_map:
                            metrics["query_shape_hash"] = cursor_hash_map[c_id_str]
                    if lsid:
                        if (str(metrics.get("ns", "unknown")) == "unknown" or str(metrics.get("ns", "")).endswith(".$cmd")) and lsid in session_ns_map:
                            metrics["ns"] = session_ns_map[lsid]; is_inferred = True
                        
                        # 🔗 Stateful Operation Reconstruction (v4.5.2)
                        op_id = metrics.get("op_id")
                        if op_id and op_id != "N/A":
                            q_hash = metrics.get("query_shape_hash")
                            if q_hash and q_hash != "N/A":
                                op_id_hash_map[str(op_id)] = q_hash
                            elif str(op_id) in op_id_hash_map:
                                metrics["query_shape_hash"] = op_id_hash_map[str(op_id)]
                        
                        # 🏮 Identity Propagation (v2.7.3): Fallback to Session Map -> Then Connection Metadata
                        if str(metrics.get("app_name", "unknown")) == "unknown":
                            if lsid in session_app_map:
                                metrics["app_name"] = str(session_app_map[lsid])
                            elif ctx in conn_metadata and conn_metadata[ctx]["app"] != "unknown":
                                metrics["app_name"] = conn_metadata[ctx]["app"]
                        
                        if str(metrics.get("user", "unknown")) == "unknown":
                            if ctx in conn_metadata and conn_metadata[ctx]["user"] != "unknown":
                                metrics["user"] = conn_metadata[ctx]["user"]

                    # 🏮 Identity Discovery (v1.2.6)
                    if ctx not in conn_metadata: 
                        conn_metadata[ctx] = {"app": "unknown", "user": "unknown", "ip": "unknown", "driver": "unknown"}
                    
                    m_ip = str(metrics.get("client_ip", "unknown"))
                    if m_ip != "unknown": conn_metadata[ctx]["ip"] = m_ip
                    
                    m_app = str(metrics.get("app_name", "unknown"))
                    if m_app != "unknown": 
                        conn_metadata[ctx]["app"] = m_app
                    
                    m_user = str(metrics.get("user", "unknown"))
                    if m_user != "unknown": 
                        conn_metadata[ctx]["user"] = m_user

                    # 🧬 MSH Identity Back-filling (v1.2.5)
                    if ctx in conn_metadata:
                        msh = conn_metadata[ctx]
                        if str(metrics.get("app_name", "unknown")) == "unknown" and msh["app"] != "unknown":
                            metrics["app_name"] = msh["app"]
                        if str(metrics.get("user", "unknown")) == "unknown" and msh["user"] != "unknown":
                            metrics["user"] = msh["user"]
                        if str(metrics.get("client_ip", "unknown")) == "unknown" and msh["ip"] != "unknown":
                            metrics["client_ip"] = msh["ip"]

                    ns = str(metrics.get("ns", "unknown"))
                    
                    # 🧬 Forensic Context Back-filling (v4.4.0)
                    # Cache the most recent valid namespace for this connection to help 
                    # attribute anonymous failure events later in the trace.
                    if ns != "unknown" and not ns.endswith(".$cmd"):
                        last_ns_cache[ctx] = ns
                        
                    namespace_stats[ns] += 1
                    a_n = str(metrics.get("app_name", "unknown"))
                    app_registry[a_n] += 1
                    u_n = str(metrics.get("user", "unknown"))
                    user_registry[u_n] += 1
                    i_n = str(metrics.get("client_ip", "unknown"))
                    ip_registry[i_n] += 1

                    # 🏥 System Health Event Discovery (NEW v2.1.0)
                    # We isolate 'Interesting' system events (TTL, Replication, etc.) into a 
                    # separate summary for the System Health tab.
                    # 🛡️ Broadened Search Space (v2.2.0): Use case-insensitive search across msg and attributes.
                    is_system_op = any(id_pattern in search_space for id_pattern in SYSTEM_EVENT_IDENTIFIERS)
                    is_lifecycle_op = any(id_pattern in search_space for id_pattern in LIFECYCLE_EVENT_IDENTIFIERS)
                    is_gossip_op = any(id_pattern in search_space for id_pattern in GOSSIP_EVENT_IDENTIFIERS)
                    
                    # 🦷 Surgical Lifecycle & Gossip De-noising (v2.7.4)
                    # Suppress pure 0ms successful connection/lifecycle/gossip noise.
                    if (is_lifecycle_op or is_gossip_op) and duration == 0 and not is_error_op and not is_timeout_op:
                        continue
                    
                    # 🧬 Diagnostic Routing (v2.7.5): 
                    # 1. Identify noise (System namespaces, components, or internal apps)
                    # Recovery: In v4.4.0, we pass 'has_crud' to prevent misclassification of transactions as noise.
                    is_noise = is_system_query(ns, app=a_n, component=c, op=curr_op, has_crud=metrics.get("has_crud", False))
                    
                    # 2. Hard Suppression check: 0ms Noise is Silenced
                    if is_noise and duration == 0 and not is_error_op and not is_timeout_op:
                        continue
                    
                    # 3. Diagnostic Routing Decision (v2.7.6): 
                    # Housekeeping -> System Health (if slow/error) or Silence.
                    # Business -> Workload/Slow Query Forensics.
                    if is_noise and not is_error_op and not is_timeout_op:
                        is_system_op = True # Force promotion to System Health tab
                    
                    # 🚀 Soft Noise Elevation Policy: Standard system components (FTDC, REPL) bypass noise filter if slow.
                    if duration >= threshold_ms or is_system_op or is_timeout_op or is_error_op:
                        op = str(metrics.get("op", "unknown"))
                        
                        # 🏷️ Apply Simplified Op/App Names for System Events
                        if is_system_op:
                            # Search for the exact pattern to find the simplified name
                            for pattern, simple_name in SIMPLIFIED_OPS.items():
                                if pattern in search_space:
                                    op = simple_name
                                    metrics["op"] = simple_name
                                    # Request: Simplify TTL index app name too
                                    if simple_name == "TTL Index":
                                        metrics["app_name"] = "TTL Index"
                                        a_n = "TTL Index" # Ensure aggregated shape uses the same label
                                    break
                        
                        # 🏷️ Namespace Normalization (v2.7.6)
                        # We only use "N/A" for truly anonymous platform events.
                        # For System Query Forensics (admin, config, local), we PRESERVE the namespace.
                        if not ns or ns == "unknown":
                            ns = "N/A"
                            metrics["ns"] = "N/A"
                        
                        h_b = str(metrics.get("query_shape_hash") or "N/A")
                        
                        # 🧪 Failure Granularity (v4.5.2): Split failures by Error Code
                        err_c = None
                        if is_timeout_op or is_error_op:
                            err_c = attr.get("errCode") or attr.get("code") or (50 if is_timeout_op else "unknown")
                            h = str(f"{op}-{ns}-{h_b}-{err_c}")
                        else:
                            h = str(f"{op}-{ns}-{h_b}")
                        
                        # Route to appropriate bucket (v3.2.1 Failure Primacy)
                        # Priority: 🚨 Failure Forensics (Error/Timeout) > 🛠️ System Health > 🐢 Business Workload
                        if is_timeout_op or is_error_op:
                            # 🧪 Type-Safe Error resolution (v4.3.5)
                            h_err = metrics.get("harvested_error", {})
                            if h_err:
                                from .specification import resolve_error_code
                                resolve_error_code(h_err)
                                
                            # 🧪 FAILURES ALWAYS WIN: Even network interrupts belong in the Failure tab
                            target_stats = timeout_shape_stats 
                        elif is_system_op:
                            # Benign system telemetry (Heartbeats, TTL, etc.)
                            target_stats = system_shape_stats
                        else:
                            # Standard business workload
                            # 🛡️ Dual-Layer Extraction Protection (v2.6.24)
                            if duration == 0 and op not in ["find", "aggregate", "insert", "update", "delete", "getmore"]:
                                target_stats = system_shape_stats
                            else:
                                target_stats = shape_stats
                        
                        if is_error_op or is_timeout_op:
                            # 🧪 Executive Failure Aggregation (v2.7.16)
                            # Pull code and name, and track hotspots by error code
                            err_c = harvest_error_code(attr, is_timeout=is_timeout_op) or "N/A"
                            err_n = attr.get("errName") or (ERROR_CODE_MAP.get(err_c) if isinstance(err_c, int) else "N/A")
                            
                            # Standardize description: if we have a name, use it.
                            err_desc = str(err_n) if err_n != "N/A" else str(err_c)
                            
                            if err_c not in error_code_agg:
                                error_code_agg[err_c] = {
                                    "code": err_c, "name": err_desc, "count": 0, "total_ms": 0,
                                    "namespaces": Counter(), "apps": Counter(),
                                    "max_ms": 0, "max_metrics": None, "max_peek_attr": None, "max_example_raw": None,
                                    "last_ts": None
                                }
                            ec_o = error_code_agg[err_c]
                            ec_o["count"] += 1; ec_o["total_ms"] += duration
                            ec_o["namespaces"][ns] += 1
                            ec_o["apps"][a_n] += 1
                            if ts: ec_o["last_ts"] = ts
                            
                            # 🧪 Witness Harvesting: Capture the most 'impactful' (slowest) occurrence as a representative sample
                            if ec_o["max_metrics"] is None or duration >= ec_o["max_ms"]:
                                ec_o["max_ms"] = duration
                                ec_o["max_metrics"] = metrics
                                ec_o["max_peek_attr"] = attr
                                ec_o["max_example_raw"] = str(entry).strip()

                        if h not in target_stats:
                            target_stats[h] = {
                                "count":0, "total_ms":0, "max_ms":0, "min_ms":float('inf'), "ns":str(ns), "inferred_ns": is_inferred, "op":str(op), "query_shape_hash":h_b, "has_regex": False, "has_lookup": False,
                                "is_system": is_system_op or is_noise,
                                "total_active_ms":0, "total_io_ms":0, "total_app_wait_ms":0, "total_oplog_wait_ms":0, "total_queue_wait_ms":0, "total_lock_wait_ms":0, "total_replication_wait_ms":0, "total_search_wait_ms":0, "timeout_count":0, "total_planning_ms":0, "total_yields":0, "total_write_conflicts":0, 
                                "total_keys_examined":0, "total_docs_examined":0, "total_nreturned":0,
                                "total_ninserted":0, "total_nModified":0, "total_ndeleted":0, "total_nMatched":0, "total_upserted": 0,
                                "total_keysInserted":0, "total_keysUpdated":0, "total_keysDeleted":0,
                                "total_txn_bytes_dirty":0, "total_mongot_wait_ms":0, "total_storage_read_micros":0,
                                "histogram":{b:0 for b in LATENCY_BUCKETS}, "max_example_raw":None, "min_example_raw":None, 
                                "max_metrics": None, "min_metrics": None, "last_ts": str(ts),
                                "max_peek_attr": {}, "min_peek_attr": {}, "max_wait_metrics":{}, "min_wait_metrics":{}, "query_fields": set(), "app_names": set(),
                                "query_hash": "N/A", "plan_cache_key": "N/A"
                            }
                        
                        s_o = target_stats[h]; s_o["count"] += 1; s_o["total_ms"] += duration
                        s_o["last_ts"] = str(ts)

                        
                        # 🧪 Transaction Metric Extraction (v2.7.1 Fix)
                        # Extract forensic data before calculating app_ms to ensure idle time is captured.
                        f_data = metrics.get("forensic", {})
                        app_ms = f_data.get("timeInactiveMicros", 0) / 1000.0
                        
                        s_o["total_io_ms"] += io_ms; s_o["total_app_wait_ms"] += app_ms; s_o["total_active_ms"] += (duration - app_ms)
                        s_o["total_planning_ms"] += waits.get("planning", 0)
                        s_o["total_yields"] += f_data.get("numYields", 0)
                        s_o["total_write_conflicts"] += f_data.get("writeConflicts", 0)
                        s_o["total_oplog_wait_ms"] += f_data.get("totalOplogSlotDurationMicros", 0) / 1000.0
                        s_o["total_queue_wait_ms"] += waits.get("queued", 0)
                        s_o["total_lock_wait_ms"] += waits.get("lock_wait", 0)
                        s_o["total_replication_wait_ms"] += waits.get("replication_wait", 0)
                        
                        # 🧬 Clinical Insight Accumulation (v3.3.4)
                        s_o["total_keys_examined"] += f_data.get("keysExamined", 0)
                        s_o["total_docs_examined"] += f_data.get("docsExamined", 0)
                        s_o["total_nreturned"] += f_data.get("nreturned", 0)
                        
                        s_o["total_ninserted"] += f_data.get("ninserted", 0)
                        s_o["total_nModified"] += f_data.get("nModified", 0)
                        s_o["total_ndeleted"] += f_data.get("ndeleted", 0)
                        s_o["total_nMatched"] += f_data.get("nMatched", 0)
                        s_o["total_upserted"] += f_data.get("upserted", 0)
                        
                        s_o["total_keysInserted"] += f_data.get("keysInserted", 0)
                        s_o["total_keysUpdated"] += f_data.get("keysUpdated", 0)
                        s_o["total_keysDeleted"] += f_data.get("keysDeleted", 0)
                        
                        # 🧬 Full-Stack Storage & Search Metrics (v4.0.0)
                        s_o["total_txn_bytes_dirty"] += f_data.get("txnBytesDirty", 0)
                        s_o["total_mongot_wait_ms"] += f_data.get("mongot_wait", 0)
                        s_o["total_storage_read_micros"] += (get_nested_value(entry, "attr.storage.data.timeReadingMicros") or 0) + (get_nested_value(entry, "attr.storage.index.timeReadingMicros") or 0)
                        
                        # 🧪 Search & Timeout Detection (v2.6.5)
                        is_search_op = "$search" in metrics.get("query_schema", [])
                        if is_search_op:
                            s_o["total_search_wait_ms"] += f_data.get("workingMillis", 0)
                        
                        if f_data.get("errCode") == 50 or f_data.get("errName") == "MaxTimeMSExpired":
                            s_o["timeout_count"] += 1
                        
                        if metrics.get("has_regex"):
                            s_o["has_regex"] = True
                        
                        if metrics.get("has_lookup"):
                            s_o["has_lookup"] = True
                        
                        if metrics.get("query_schema"):
                            s_o["query_fields"].update([str(f) for f in metrics["query_schema"]])
                        
                        s_o["app_names"].add(str(a_n))
                        
                        # 🧪 Persistence: Maintain system bit across aggregation
                        if is_system_op or is_noise:
                            s_o["is_system"] = True
                        
                        # 🧬 Final Persistence: Save samples and fingerprints
                        for b in reversed(LATENCY_BUCKETS):
                            if duration >= b: 
                                s_o["histogram"][b] += 1
                                global_latency_dist[b] += 1
                                break
                        
                        # 🧬 Metric Peak Caching (v4.4.0)
                        # We cache the full forensic metrics for the peak (max) and valley (min) 
                        # examples during Pass 1. This eliminates the redundant JSON parsing 
                        # loop in finalize_forensic_summary.
                        if s_o["max_example_raw"] is None or duration > s_o["max_ms"]:
                            s_o["max_ms"] = duration
                            s_o["max_example_raw"] = str(entry).strip()
                            s_o["max_metrics"] = metrics
                            s_o["max_peek_attr"] = attr
                            s_o["query_hash"] = metrics.get("query_hash", "N/A")
                            s_o["plan_cache_key"] = metrics.get("plan_cache_key", "N/A")
                            s_o["max_wait_metrics"] = {
                                "Planning": waits.get("planning", 0), 
                                "Storage": io_ms, 
                                "Locks": waits.get("lock_wait", 0), 
                                "Queued": waits.get("queued", 0), 
                                "Execution": waits.get("execution", 0),
                                "Transactions": (f_data.get("timeActiveMicros", 0) / 1000.0) if f_data.get("timeActiveMicros") else 0
                            }
                        
                        if s_o["min_example_raw"] is None or duration < s_o["min_ms"]:
                            s_o["min_ms"] = duration
                            s_o["min_example_raw"] = str(entry).strip()
                            s_o["min_metrics"] = metrics
                            s_o["min_peek_attr"] = attr

                except Exception as e:
                    if len(engine_errors) < 100: 
                        engine_errors.append(f"Pass 1 Line {total_parsed}: {str(e)[:120]}")
                    continue

        print(f"  ↳ Captured {len(shape_stats)} slow, {len(system_shape_stats)} system, {len(timeout_shape_stats)} timeout shapes from {total_parsed:,} lines.", file=sys.stderr)

        log_dur_sec = 1
        if start_ts and end_ts:
            from dateutil import parser as dp
            try: log_dur_sec = max((dp.isoparse(end_ts) - dp.isoparse(start_ts)).total_seconds(), 1)
            except: pass

        # 🧠 PASS 2: Expert Synthesis (Unified v2.6.0)
        # Purpose: Aggregate raw Pass 1 data into logical shapes and identify bottlenecks.
        
        # Calculate global denominator for cross-tab AAS synchronization (v3.2.14)
        # This ensures that 'Load %' in the report is relative to the entire server workload.
        global_active_ms = (
            sum(s["total_active_ms"] for s in shape_stats.values()) +
            sum(s["total_active_ms"] for s in system_shape_stats.values()) +
            sum(s["total_active_ms"] for s in timeout_shape_stats.values())
        )

        # 🧬 Synthesize Business Workload Tab
        final_results = finalize_forensic_summary(
            shape_stats=shape_stats,
            log_dur_sec=log_dur_sec,
            rules=rules,
            global_total_active=global_active_ms
        )
        
        # 🧬 Synthesize System Health Tab
        system_summary = finalize_forensic_summary(
            shape_stats=system_shape_stats,
            log_dur_sec=log_dur_sec,
            rules=rules, 
            global_total_active=global_active_ms
        )
        system_summary = [s for s in system_summary if s["total_ms"] > 0]
        
        # 🧬 Synthesize Failure Forensics Tab
        # 🧪 STRICT FILTERING (v4.5.1): Only show failures tied to identified query shapes
        filtered_timeout_stats = {
            h: s for h, s in timeout_shape_stats.items() 
            if s.get("query_shape_hash") not in ["N/A", "unknown", "N/D"]
        }
        timeout_summary = finalize_forensic_summary(
            shape_stats=filtered_timeout_stats,
            log_dur_sec=log_dur_sec,
            rules=rules,
            global_total_active=global_active_ms
        )

        global_total_ms = sum(s["total_ms"] for s in shape_stats.values())
        
        # 🏮 Post-Synthesis Identity Back-filling (v1.3.16)
        # (Note: Identity back-filling is now handled within the aggregator or pre-pass)

        avg_slow_ms = global_total_ms / total_slow_count if total_slow_count > 0 else 0
        # 📈 Senior Stat Sync (v4.3.0): Use unified error count directly for soundness
        log_error_count = identified_error_count

        res = {
            "stats": {
                "total_parsed": total_parsed, "total_filtered": total_filtered, "unique_shapes": len(shape_stats), 
                "start_ts": str(start_ts), "end_ts": str(end_ts), "total_slow_count": total_slow_count,
                "avg_slow_ms": avg_slow_ms, "log_error_count": log_error_count,
                "timeout_count": timeout_count,
                "total_accepted": total_accepted, "total_closed": total_closed,
                "engine_errors": engine_errors,
                "analysis_duration": round(time.time()-start_time, 2), 
                "op_distribution": dict(op_registry.most_common(12)),
                "global_efficiency": {str(k): v for k, v in global_forensic_sums.items()},
                "global_health": {str(k): v for k, v in gh_counts.items()}, "global_bottlenecks": {str(k): v for k, v in global_bottlenecks.items()}, 
                "time_window": {"start": str(start_ts), "end": str(end_ts)}, "severities": {str(k): v for k, v in severity_stats.items()}, 
                "components": {str(k): v for k, v in component_stats.most_common(12)}, 
                "top_messages": [
                    {"severity": str(sk[0]), "msg": str(sk[1]), "count": sv["count"], "preview": sv["preview"]} 
                    for sk, sv in sorted(message_registry.items(), key=lambda x: x[1]["count"], reverse=True)
                    if sk[0] not in ["INFO", "I"]
                ][:12], 
                "timeout_patterns": sorted(timeout_patterns.values(), key=lambda x: x["count"], reverse=True)[:8], 
                "namespaces": {str(k): v for k, v in namespace_stats.most_common(12) if k != "unknown" and ".$cmd" not in k},
                "error_namespaces": {str(k): v for k, v in error_namespace_stats.most_common(16) if k != "unknown" and ".$cmd" not in k},
                "error_code_summary": [
                    {
                        "code": k,
                        "name": v["name"],
                        "count": v["count"],
                        "avg_ms": v["total_ms"] / v["count"] if v["count"] > 0 else 0,
                        "max_ms": v["max_ms"],
                        "top_ns": v["namespaces"].most_common(1)[0][0] if v["namespaces"] else "N/A",
                        "top_app": v["apps"].most_common(1)[0][0] if v["apps"] else "N/A",
                        "max_metrics": v["max_metrics"],
                        "max_peek_attr": v["max_peek_attr"],
                        "max_example_raw": v["max_example_raw"],
                        "diagnostic_tags": [{"label": "ERROR", "severity": "error"}]
                    }
                    for k, v in sorted(error_code_agg.items(), key=lambda x: x[1]["count"], reverse=True)
                ],
                "system_error_patterns": sorted(system_error_patterns.values(), key=lambda x: x["count"], reverse=True)[:10],
                "active_latency_tiers": sorted([int(k) for k, v in global_latency_dist.items() if v > 0]),
            }, 
            "connections": {
                "total_connections": max(len(conn_registry), len(namespace_stats.keys())),
                "top_apps": {str(k): v for k, v in Counter([str(c.get("app", "unknown")) for c in conn_registry.values()] + list(app_registry.elements())).most_common(10) if k != "unknown"},
                "top_ips": {str(k): v for k, v in Counter([str(c.get("ip", "unknown")) for c in conn_registry.values()] + list(ip_registry.elements())).most_common(10) if k != "unknown"},
                "top_users": {str(k): v for k, v in Counter([str(c.get("user", "unknown")) for c in conn_registry.values()] + list(user_registry.elements())).most_common(10) if k != "unknown"},
                "app_driver_mapping": [
                    {"app": str(app), "driver": str(global_app_driver_map.get(app, "unknown")), "count": count}
                    for app, count in app_registry.items() if app != "unknown"
                ],
                "churn_rate": round(len(conn_registry)/max(log_dur_sec, 1), 2) if log_dur_sec > 0 else 0,
                "auth_fail_count": auth_fail_count,
                "duration_sec": log_dur_sec
            },
            "summary": final_results,
            "system_summary": system_summary,
            "timeout_summary": timeout_summary,
            "threshold": threshold_ms
        }
        return res

    except Exception as ge:
        print(f"!!! [CRITICAL v1.3.2] Global Engine Failure: {ge}")
        import traceback; traceback.print_exc()
        return { "stats": {}, "connections": {}, "summary": [] }

def group_by_shape(entries: List[Dict]) -> Dict[str, Dict]:
    """
    Groups raw log entries into query shapes.
    """
    from .parser import extract_log_metrics
    shape_stats = {}
    
    for entry in entries:
        metrics = entry.get("metrics") or extract_log_metrics(entry)
        if not metrics: continue
        
        op = str(metrics.get("op", "unknown"))
        ns = str(metrics.get("ns", "unknown"))
        h_b = str(metrics.get("query_shape_hash") or metrics.get("query_hash") or "unknown")
        duration = metrics.get("ms", 0)
        waits = metrics.get("waits_ms", {})
        
        h = f"{op}-{ns}-{h_b}"
        if h not in shape_stats:
            shape_stats[h] = {
                "count":0, "total_ms":0, "max_ms":0, "min_ms":float('inf'), 
                "ns":ns, "op":op, "query_shape_hash":h_b, "total_active_ms":0, 
                "total_io_ms":0, "total_app_wait_ms":0, "total_oplog_wait_ms":0,
                "total_queue_wait_ms": 0, "total_lock_wait_ms": 0, "total_replication_wait_ms": 0,
                "total_cpu_ms": 0,
                "app_names": set(), "max_example_raw": None, 
                "histogram": {b:0 for b in LATENCY_BUCKETS}
            }
        
        s = shape_stats[h]
        s["count"] += 1
        s["total_ms"] += duration
        s["max_ms"] = max(s["max_ms"], duration)
        s["min_ms"] = min(s["min_ms"], duration)
        s["total_io_ms"] += waits.get("storage_wait", 0)
        # 🧪 Transaction Fix: Pull from forensic block
        app_ms = metrics.get("forensic", {}).get("timeInactiveMicros", 0) / 1000.0
        s["total_app_wait_ms"] += app_ms
        s["total_active_ms"] += max(0, duration - app_ms)
        s["total_oplog_wait_ms"] += (metrics.get("forensic", {}).get("totalOplogSlotDurationMicros", 0) / 1000.0)
        s["total_queue_wait_ms"] += waits.get("queued", 0)
        s["total_lock_wait_ms"] += waits.get("lock_wait", 0)
        s["total_replication_wait_ms"] += waits.get("replication_wait", 0)
        s["total_cpu_ms"] += (metrics.get("forensic", {}).get("cpuNanos", 0) / 1000000.0)
        
        app = metrics.get("app_name", "unknown")
        if app != "unknown": s["app_names"].add(app)
        
        if s["max_example_raw"] is None or duration >= s["max_ms"]:
            s["max_example_raw"] = entry
            
        for b in sorted(LATENCY_BUCKETS, reverse=True):
            if duration >= b:
                s["histogram"][b] += 1; break
    return shape_stats

def finalize_forensic_summary(shape_stats: Dict[str, Dict], log_dur_sec: float = 1.0, rules: List = None, global_total_active: float = None) -> List[Dict]:
    """
    The Post-Synthesis Aggregator.
    
    This function takes raw shape data and calculates the full Clinical Insight 
    Suite (Latency Cliff, AAS, Storage Intensity). 
    
    It serves as the Single Source of Truth for both the CLI output and 
    the final HTML dashboard.
    """
    from .parser import extract_log_metrics
    final_results = []
    rules = rules or []
    top_shapes = sorted(shape_stats.values(), key=lambda x: x["total_ms"], reverse=True)
    
    # Use global active time if provided, otherwise fall back to local tab total
    sum_total_active = global_total_active if global_total_active else (sum(s["total_active_ms"] for s in shape_stats.values()) or 1)
    if sum_total_active == 0: sum_total_active = 1
    
    for i, q in enumerate(top_shapes):
        tags = []
        # 🧪 High-Fidelity Extraction (Max & Min)
        max_entry = q.get("max_example_raw")
        min_entry = q.get("min_example_raw") or max_entry
        
        # 🧬 Cached Metric Retrieval (v4.4.0)
        # We use the metrics extracted during Pass 1 to avoid redundant JSON parsing.
        max_d = q.get("max_metrics") or {}
        min_d = q.get("min_metrics") or max_d
        
        # 🕒 Timestamp & Attribute Extraction
        # 🕒 Timestamp & Attribute Retrieval
        # Recovery: In v4.4.0, we use the cached attributes from Pass 1.
        max_attr = q.get("max_peek_attr", {})
        min_attr = q.get("min_peek_attr", {})
        
        # Extract timestamps from raw logs if possible, otherwise use unknown
        def _extract_ts(entry_raw):
            if not entry_raw: return "unknown"
            try:
                raw_str = str(entry_raw)
                j_idx = raw_str.find('{')
                if j_idx != -1:
                    obj = json.loads(raw_str[j_idx:])
                    t = obj.get("t", {}).get("$date") if isinstance(obj.get("t"), dict) else obj.get("t")
                    return str(t) if t else "unknown"
            except: pass
            return "unknown"

        max_ts = _extract_ts(max_entry)
        min_ts = _extract_ts(min_entry)

        # 🧪 Hybrid Clinical Insights (v3.3.7)
        # Decision: Anchor Efficiency to the Slowest-Case Sample, but Mutation to the Shape-wide Aggregate.
        
        # 1. Sample Forensics (Slowest Case)
        sample_f = max_d.get("forensic", {})
        s_nret = sample_f.get("nreturned", 0)
        s_docs_ex = sample_f.get("docsExamined", 0)
        s_keys_ex = sample_f.get("keysExamined", 0)
        s_n_ins = sample_f.get("ninserted", 0)
        s_n_match = sample_f.get("nMatched", 0)
        s_n_del = sample_f.get("ndeleted", 0)
        s_n_ups = sample_f.get("upserted", 0)
        
        s_impact = s_nret + s_n_match + s_n_ins + s_n_del + s_n_ups
        s_denom = s_impact if s_impact > 0 else 1 # Per-operation normalization for single sample
        
        # 2. Shape Aggregates (Economic Overhead)
        n_ins = q.get("total_ninserted", 0)
        n_mod = q.get("total_nModified", 0)
        n_del = q.get("total_ndeleted", 0)
        n_upsert = q.get("total_upserted", 0)
        doc_mut = n_ins + n_mod + n_del + n_upsert
        
        k_ins = q.get("total_keysInserted", 0)
        k_upd = q.get("total_keysUpdated", 0)
        k_del = q.get("total_keysDeleted", 0)
        key_mut = k_ins + k_upd + k_del

        avg_ms = round(q["total_ms"] / q["count"], 2)
        stats = {
            "load_pct": round(q["total_active_ms"] / sum_total_active * 100, 1),
            "avg_ms": avg_ms,
            "aas": round(q["total_active_ms"] / (max(log_dur_sec, 1) * 1000), 3),
            # Efficiency anchored to Slowest-Case Sample (The Forensic Smoking Gun)
            "scan_efficiency": round(s_docs_ex / s_denom, 1),
            "index_selectivity": round(s_keys_ex / s_denom, 1),
            "fetch_amplification": round(s_docs_ex / s_keys_ex, 1) if s_keys_ex > 0 else (s_docs_ex if s_docs_ex > 0 else 0),
            # Workload Amplification anchored to Shape Aggregate (The Economic Tax)
            "workload_amplification": round(key_mut / doc_mut, 1) if doc_mut > 0 else 0,
            "ins_amp": round(k_ins / n_ins, 1) if n_ins > 0 else 0,
            "upd_amp": round(k_upd / n_mod, 1) if n_mod > 0 else 0,
            "del_amp": round(k_del / n_del, 1) if n_del > 0 else 0,
            # ✨ Advanced Clinical Suite v4.0.0 (The Full Stack)
            "cache_pressure": round(max_d.get("forensic", {}).get("txnBytesDirty", 0) / (1024 * 1024), 1),
            "replication_backpressure": max(max_d.get("forensic", {}).get("flowControlMillis", 0), max_d.get("max_peek_attr", {}).get("waitForWriteConcernDurationMillis", 0)),
            "storage_intensity": min(100.0, round((max_d.get("waits_ms", {}).get("storage_wait", 0) / max(max_d.get("ms", 1), 1)) * 100, 1)),
            "search_latency": max_d.get("forensic", {}).get("mongot_wait", 0),
            "cache_stall": round(max_d.get("forensic", {}).get("timeWaitingMicros_cache", 0) / 1000.0, 1)
        }

        eval_data = {
            **q, "avg_ms": q["total_ms"]/q["count"], 
            "keysExamined": max_d.get("forensic", {}).get("keysExamined", 0),
            "docsExamined": max_d.get("forensic", {}).get("docsExamined", 0),
            "nreturned": max_d.get("forensic", {}).get("nreturned", 1),
            "plan_summary": max_d.get("plan_summary", "N/A"),
            "has_regex": 1 if q.get("has_regex") else 0,
            "has_lookup": 1 if q.get("has_lookup") else 0,
            "error_code": max_d.get("forensic", {}).get("errCode") or max_d.get("forensic", {}).get("code"),
            "error_name": max_d.get("forensic", {}).get("errName") or max_d.get("forensic", {}).get("codeName"),
            "clinical_stats": stats,
            "cache_pressure": stats["cache_pressure"],
            "cache_stall": stats["cache_stall"],
            "ins_amp": stats["ins_amp"],
            "doc_mut": doc_mut,
            "has_read_forensics": 1 if (s_docs_ex > 0 or s_keys_ex > 0) else 0,
            "has_write_forensics": 1 if doc_mut > 0 else 0,
            "is_system": q.get("is_system", 0),
            "query_hash": q.get("query_hash", "N/A"),
            "plan_cache_key": q.get("plan_cache_key", "N/A")
        }
        
        for rule in rules:
            try:
                triggered, val = evaluate_rule(rule, eval_data)
                if triggered: 
                    label = str(rule["label"])
                    if "{" in label and val is not None:
                        display_val = val * 100 if "%" in label else val
                        if "{value_duration}" in label:
                            label = label.format(value=display_val, value_duration=format_duration(val))
                        else:
                            label = label.format(value=display_val)
                    tags.append({"label": label, "severity": rule.get("severity", "warning")})
            except: continue
            
        final_results.append({
            "row": i+1, 
            "category": q["op"], 
            "namespace": q["ns"],
            "avg_time": int(q["total_ms"]/q["count"]),
            "max_time": q["max_ms"], 
            "min_time": int(q["min_ms"]) if q["min_ms"] != float('inf') else 0,
            "count": q["count"], 
            "total_ms": q["total_ms"],
            "load_pct": stats["load_pct"],
            "aas_load": stats["aas"],
            # Forensic Metadata for Reporter Visibility
            "docsExamined": eval_data.get("docsExamined", 0),
            "keysExamined": eval_data.get("keysExamined", 0),
            "doc_mut": doc_mut,
            "is_system": q.get("is_system", 0),
            # Hybrid Clinical Ratios
            "scan_efficiency": stats["scan_efficiency"],
            "index_selectivity": stats["index_selectivity"],
            "fetch_amplification": stats["fetch_amplification"],
            "workload_amplification": stats["workload_amplification"],
            "ins_amp": stats["ins_amp"],
            "upd_amp": stats["upd_amp"],
            "del_amp": stats["del_amp"],
            "cache_pressure": stats["cache_pressure"],
            "replication_backpressure": stats["replication_backpressure"],
            "storage_intensity": stats["storage_intensity"],
            "search_latency": stats["search_latency"],
            "diagnostic_tags": tags if tags else [{"label": "BALANCED", "severity": "success"}],
            "app_name": ", ".join(list(q["app_names"])[:3]) if q["app_names"] else "unknown",
            "plan_summary": str(max_d.get("plan_summary", "N/A")),
            # 🏺 Web Drill-Down Metadata (Mandatory Contract)
            "query_shape_hash": str(q.get("query_shape_hash", "N/A")),
            "query_hash": str(q.get("query_hash", "N/A")),
            "plan_cache_key": str(q.get("plan_cache_key", "N/A")),
            "query_schema": max_d.get("query_schema", []),
            "max_ts": max_ts,
            "min_ts": min_ts,
            "max_peek_attr": max_attr,
            "min_peek_attr": min_attr,
            "max_forensic": max_d.get("forensic", {}),
            "min_forensic": min_d.get("forensic", {}),
            "max_waits": max_d.get("waits_ms", {}),
            "min_waits": min_d.get("waits_ms", {}),
            "max_query_params": max_d.get("query_params", {}),
            "min_query_params": min_d.get("query_params", {}),
            "latency_distribution": q.get("histogram", {}),
            "last_ts": q.get("last_ts", max_ts),
            "error_code": eval_data.get("error_code"),
            "error_name": eval_data.get("error_name"),
            "max_example_raw": max_entry if isinstance(max_entry, str) else json.dumps(max_entry),
            "min_example_raw": min_entry if isinstance(min_entry, str) else json.dumps(min_entry)
        })
    return final_results

def aggregate_forensic_results(entries: List[Dict], log_dur_sec: float = 1.0, rules: List = None) -> List[Dict]:
    """🌪️ Unified Forensic Entry Point (v2.6.0)"""
    shape_stats = group_by_shape(entries)
    return finalize_forensic_summary(shape_stats, log_dur_sec, rules)
