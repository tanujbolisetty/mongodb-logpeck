import os
import re
import json
import time
import gzip
import sys
from collections import Counter
from typing import List, Optional, Dict, Any, Tuple
from .parser import parse_log_line, extract_log_metrics, is_system_query, heuristic_extract_ns, detect_op_and_ns, normalize_conn_id, induce_log_schema
from .specification import SYSTEM_EVENT_IDENTIFIERS, SIMPLIFIED_OPS, LIFECYCLE_EVENT_IDENTIFIERS, GOSSIP_EVENT_IDENTIFIERS, ERROR_CODE_MAP
from .version import __version__

"""
logpeck: analyzer.py
The core analytical engine for LogPeck.

Architecture:
1. Pass 1 (Sweep): High-speed linear scan of logs to build metadata registries
   (connections, sessions, cursor hashes) and capture slow query samples.
2. Pass 2 (Synthesis): Aggregation of shapes, rule evaluation, and bottleneck attribution.
"""

EXCLUDED_EVENT_IDS = {"51800", "21530", "18", "22943", "22944", "5286306", "51801"}


RE_OBJECT_ID = re.compile(r'ObjectId\([^)]+\)')
RE_TIMESTAMP = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*')
SEVERITY_MAP = {"I": "INFO", "W": "WARN", "E": "ERROR", "F": "FATAL", "D": "DEBUG", "D1": "DEBUG", "D2": "DEBUG"}
LATENCY_BUCKETS = [100, 250, 500, 1000, 2000, 5000, 10000]

def load_diagnostic_rules(custom_path: Optional[str] = None) -> List[dict]:
    default_path = os.path.join(os.path.dirname(__file__), "rules.json")
    path = custom_path if custom_path and os.path.exists(custom_path) else default_path
    if os.path.exists(path):
        try:
            with open(path, 'r') as f: return json.load(f).get("rules", [])
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

def read_logs_chunked(file_path: str):
    is_gz = file_path.lower().endswith(".gz")
    opener = gzip.open(file_path, 'rt', encoding='utf-8') if is_gz else open(file_path, 'r', encoding='utf-8')
    with opener as f:
        for line in f:
            entry = parse_log_line(line)
            if entry: yield entry


def build_forensic_context(log_file_path: str) -> Dict[str, str]:
    """
    Performs a high-speed context sweep of the log file to build a connection-to-namespace map.
    This is used by discovery tools (Search/Filter) to attribute namespaces to lean error logs.
    """
    last_ns_cache = {}
    total_parsed = 0
    import sys
    print(f"🔬 Forensic Context Sweep (v{__version__})...", file=sys.stderr)
    
    try:
        f_opener = gzip.open(log_file_path, 'rt', encoding='utf-8') if log_file_path.endswith('.gz') else open(log_file_path, 'r', encoding='utf-8')
        with f_opener as f:
            for entry in f:
                total_parsed += 1
                try:
                    obj = json.loads(entry)
                    if total_parsed % 500000 == 0: print(f"  ↳ {total_parsed:,} lines swept...")
                    
                    ctx = normalize_conn_id(obj.get("ctx", ""))
                    attr = obj.get("attr", {})
                    if not isinstance(attr, dict): continue
                    
                    p_cmd = attr.get("command") or attr.get("originatingCommand") or attr.get("doc", {}).get("q")
                    raw_ns = attr.get("ns")
                    if raw_ns and raw_ns != "unknown":
                        _, res_ns = detect_op_and_ns(attr, p_cmd or {}, str(obj.get("msg", "")), raw_ns)
                        last_ns_cache[ctx] = str(res_ns)
                except: continue
    except Exception as e:
        print(f"  ⚠️ Context sweep partially interrupted: {e}")
    
    return last_ns_cache

def analyze_slow_queries(log_file_path: str, threshold_ms: int = 0, limit: int = 20, rules_path: Optional[str] = None) -> Dict[str, Any]:
    start_time = time.time(); rules = load_diagnostic_rules(rules_path)
    severity_stats = Counter(); component_stats = Counter(); namespace_stats = Counter(); message_registry = {}
    conn_registry = {}; auth_fail_count = 0; timeout_count = 0; identified_error_count = 0; timeout_patterns = {}
    error_namespace_stats = Counter(); error_code_agg = {}
    global_latency_dist = Counter()
    session_ns_map = {}; session_app_map = {}; shape_stats = {}; gh_counts = Counter(); global_bottlenecks = Counter()
    system_shape_stats = {} # 🏥 System-level events (Replica Set, TTL, etc.)
    timeout_shape_stats = {} # 🚨 Critical Timeouts (Wait, ExceededLimit)
    last_op_cache = {} # 🔄 Stateful Operation Correlation: {ctx: last_known_op_preview}
    last_ns_cache = {} # 🔄 Stateful Namespace Tracking: {ctx: last_known_ns}
    app_registry = Counter() 
    user_registry = Counter() 
    ip_registry = Counter() 
    op_registry = Counter() 
    global_forensic_sums = Counter() # 📑 Global Efficiency: {marker: sum}
    global_app_driver_map = {}
    conn_metadata = {}  # 🔑 MSH Matrix: {ctx: {"app": str, "user": str, "ip": str, "driver": str}}
    engine_errors = [] 
    cursor_hash_map = {}
    total_parsed = 0; total_filtered = 0; total_slow_count = 0; total_accepted = 0; total_closed = 0
    start_ts = None; end_ts = None

    # 🕵️ Pass 1: Light-Speed Forensic Sweep
    # Purpose: Capture every slow query, stitch sessions/ips, and map cursors.
    print(f"\n🔬 Pass 1: Light-Speed Forensic Sweep (v{__version__})...", file=sys.stderr)

    last_known_ts = None
    try:
        f_opener = gzip.open(log_file_path, 'rt', encoding='utf-8') if log_file_path.endswith('.gz') else open(log_file_path, 'r', encoding='utf-8')
        with f_opener as f:
            for entry in f:
                total_parsed += 1
                try:
                    obj = json.loads(entry)
                    
                    # 🧪 Unified Schema Induction (v3.2.12)
                    header = induce_log_schema(obj, last_known_ts)
                    ts = header["t"]
                    if ts:
                        if not start_ts: start_ts = str(ts)
                        end_ts = str(ts)
                        last_known_ts = ts
                    
                    if total_parsed % 500000 == 0: print(f"  ↳ {total_parsed:,} lines processed...", file=sys.stderr)
                    
                    s = header["s"]; sev = str(SEVERITY_MAP.get(s, s)); severity_stats[sev] += 1
                    c = header["c"]; component_stats[c] += 1
                    msg = header["msg"]; norm_msg = RE_OBJECT_ID.sub('...', msg) if "ObjectId(" in msg else msg
                    ctx = header["ctx"]
                    
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
                    FAILURE_SIGNATURES = [
                        "error", "failed", "failure", "socketexception", "clientdisconnect", "interrupted", 
                        "exceededtimelimit", "networkinterface", "steppeddown", "primarysteppeddown",
                        "notyetinitialized", "invalidsyncsource", "terminated", "connection closed",
                        "infrastructure failure"
                    ]
                    is_error_op_base = sev in ["ERROR", "FATAL", "E", "F"] or any(sig in search_space for sig in FAILURE_SIGNATURES)
                    is_timeout_op = any(sig in search_space for sig in timeout_sigs) or "planexecutor error" in search_space
                    
                    if not isinstance(attr, dict):
                        # 🧪 Lean Log Induction (v3.2.13): Allow logs without 'attr' if they have durations or are errors.
                        if is_error_op_base or is_timeout_op or metrics.get("ms", 0) > 0:
                            attr = {} 
                        else:
                            continue

                    # 🕵️ Senior Failure Detection (v2.7.7): Promote command errors even if severity is 'I'
                    is_error_op = is_error_op_base or any(k in (attr or {}) or k in obj for k in ["error", "errCode", "code"]) or str((attr or {}).get("ok", obj.get("ok"))) == "0"
                    if "errorMessage" in obj or "errmsg" in obj: is_error_op = True
                    if header.get("msg") == "Infrastructure Failure": is_error_op = True
                    
                    if is_error_op:
                        identified_error_count += 1
                    
                    if is_timeout_op:
                        timeout_count += 1
                        # 🕵️ Smart Namespace Discovery for Timeouts (v1.3.21)
                        ns_guess = attr.get("ns")
                        if not ns_guess or str(ns_guess).endswith(".$cmd"):
                            p_cmd = attr.get("command") or attr.get("originatingCommand") or {}
                            _, res_ns = detect_op_and_ns(attr, p_cmd, msg, ns_guess or "unknown")
                            ns_guess = res_ns
                        
                        # 🧪 Heuristic Fallback (v2.7.11): Try to extract NS from the message text if still missing
                        if not ns_guess or ns_guess == "unknown" or ns_guess == "N/A":
                            ns_guess = str(heuristic_extract_ns(search_space) or last_ns_cache.get(ctx) or "N/A")
                        else:
                            ns_guess = str(ns_guess)

                        
                        # 🏮 High-Resolution Error Signature (v2.6.21)
                        # Aggressively prioritize 'MaxTimeMSExpired' and lethal error signatures.
                        if "maxtimemsexpired" in search_space or "exceeded time limit" in search_space:
                            display_err = "MaxTimeMSExpired: operation exceeded time limit"
                        else:
                            display_err = msg
                            # Extract error components from both attr and cmd_obj
                            e_code = attr.get("errCode") or attr.get("code") or p_cmd.get("code")
                            e_name = attr.get("errName") or attr.get("errorName") or p_cmd.get("errName")
                            if not e_name and e_code in ERROR_CODE_MAP:
                                e_name = ERROR_CODE_MAP[e_code]
                                
                            e_msg = attr.get("errMsg") or attr.get("errorMsg") or attr.get("error") or p_cmd.get("error")
                            
                            if e_name and e_msg:
                                display_err = f"{e_name}: {e_msg}"
                            elif e_name:
                                display_err = str(e_name)
                            elif e_msg:
                                display_err = str(e_msg)
                        
                        key = (ns_guess, str(display_err[:100]))
                        if key not in timeout_patterns:
                            preview = str((attr.get("command", {}) or {}).get("filter") or (attr.get("command", {}) or {}).get("pipeline") or "N/A")
                            if preview == "N/A": 
                                preview = last_op_cache.get(ctx, "N/A")
                            timeout_patterns[key] = {
                                "count": 0, "ts": str(ts), "msg": str(display_err[:120]), "ns": ns_guess, "op": "unknown",
                                "preview": preview,
                                "remote": str(attr.get("remote", "-")), "ctx": str(obj.get("ctx", "-"))
                            }
                        timeout_patterns[key]["count"] += 1
                        error_namespace_stats[ns_guess] += 1

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
                    
                    # 📊 High-Fidelity Bottleneck Aggregation (v3.2.14)
                    # Deduct Oplog from Storage to ensure disjoint categories for the visual Radar
                    f_data = metrics.get("forensic", {})
                    op_ms = f_data.get("totalOplogSlotDurationMicros", 0)
                    global_bottlenecks["storage_ms"] += max(0, io_ms - op_ms)
                    global_bottlenecks["cpu_ms"] += cpu_ms
                    global_bottlenecks["oplog_ms"] += op_ms
                    global_bottlenecks["queue_ms"] += f_data.get("totalTimeQueuedMicros", 0)
                    global_bottlenecks["planning_ms"] += waits.get("planning", 0)
                    global_bottlenecks["lock_ms"] += waits.get("lock_wait", 0)
                    
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
                    is_noise = is_system_query(ns, app=a_n, component=c, op=curr_op)
                    
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
                        
                        h_b = str(metrics.get("query_shape_hash") or metrics.get("query_hash") or "")
                        if not h_b:
                            schema = metrics.get("query_schema", [])
                            if schema:
                                # 🧪 UI Density Protection (v2.6.17): Cap schema hash display to 5 fields
                                if len(schema) > 5:
                                    h_b = "SCHEMA-" + "-".join([str(x) for x in schema[:5]]) + f"-({len(schema)-5}_others)"
                                else:
                                    h_b = "SCHEMA-" + "-".join([str(x) for x in schema])
                            else:
                                h_b = "GENERIC"
                        
                        h = str(f"{op}-{ns}-{h_b}")
                        
                        # Route to appropriate bucket (v3.2.1 Failure Primacy)
                        # Priority: 🚨 Failure Forensics (Error/Timeout) > 🛠️ System Health > 🐢 Business Workload
                        if is_timeout_op or is_error_op:
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
                            err_c = attr.get("errCode") or attr.get("code") or (50 if is_timeout_op else "unknown")
                            err_n = attr.get("errName") or (ERROR_CODE_MAP.get(err_c) if isinstance(err_c, int) else "unknown")
                            
                            # Standardize description: if we have a name, use it.
                            err_desc = str(err_n) if err_n != "unknown" else str(err_c)
                            
                            if err_c not in error_code_agg:
                                error_code_agg[err_c] = {
                                    "code": err_c, "name": err_desc, "count": 0, "total_ms": 0,
                                    "namespaces": Counter(), "apps": Counter()
                                }
                            ec_o = error_code_agg[err_c]
                            ec_o["count"] += 1; ec_o["total_ms"] += duration
                            ec_o["namespaces"][ns] += 1
                            ec_o["apps"][a_n] += 1

                        if h not in target_stats:
                            target_stats[h] = {"count":0, "total_ms":0, "max_ms":0, "min_ms":float('inf'), "ns":str(ns), "inferred_ns": is_inferred, "op":str(op), "query_shape_hash":h_b, "has_regex": False, "total_active_ms":0, "total_io_ms":0, "total_app_wait_ms":0, "total_oplog_wait_ms":0, "total_queue_wait_ms":0, "total_search_wait_ms":0, "timeout_count":0, "total_planning_ms":0, "total_yields":0, "total_write_conflicts":0, "histogram":{b:0 for b in LATENCY_BUCKETS}, "max_example_raw":None, "min_example_raw":None, "max_peek_attr": {}, "min_peek_attr": {}, "max_wait_metrics":{}, "min_wait_metrics":{}, "query_fields": set(), "app_names": set()}
                        
                        s_o = target_stats[h]; s_o["count"] += 1; s_o["total_ms"] += duration
                        
                        # 🧪 Transaction Metric Extraction (v2.7.1 Fix)
                        # Extract forensic data before calculating app_ms to ensure idle time is captured.
                        f_data = metrics.get("forensic", {})
                        app_ms = f_data.get("timeInactiveMicros", 0) / 1000.0
                        
                        s_o["total_io_ms"] += io_ms; s_o["total_app_wait_ms"] += app_ms; s_o["total_active_ms"] += (duration - app_ms)
                        s_o["total_planning_ms"] += waits.get("planning", 0)
                        s_o["total_yields"] += f_data.get("numYields", 0)
                        s_o["total_write_conflicts"] += f_data.get("writeConflicts", 0)
                        s_o["total_oplog_wait_ms"] += f_data.get("totalOplogSlotDurationMicros", 0)
                        s_o["total_queue_wait_ms"] += f_data.get("totalTimeQueuedMicros", 0)
                        
                        # 🧪 Search & Timeout Detection (v2.6.5)
                        is_search_op = "$search" in metrics.get("query_schema", [])
                        if is_search_op:
                            s_o["total_search_wait_ms"] += f_data.get("workingMillis", 0)
                        
                        if f_data.get("errCode") == 50 or f_data.get("errName") == "MaxTimeMSExpired":
                            s_o["timeout_count"] += 1
                        
                        if metrics.get("has_regex"):
                            s_o["has_regex"] = True
                        
                        if metrics.get("query_schema"):
                            s_o["query_fields"].update([str(f) for f in metrics["query_schema"]])
                        
                        s_o["app_names"].add(str(a_n))
                        
                        for b in reversed(LATENCY_BUCKETS):
                            if duration >= b: 
                                s_o["histogram"][b] += 1
                                global_latency_dist[b] += 1
                                break
                        if s_o["max_example_raw"] is None or duration > s_o["max_ms"]:
                            s_o["max_ms"] = duration; s_o["max_example_raw"] = entry; s_o["max_peek_attr"] = attr
                            s_o["max_wait_metrics"] = {
                                "Planning": waits.get("planning", 0), 
                                "Storage": io_ms, 
                                "Locks": waits.get("lock_wait", 0), 
                                "Queued": waits.get("queued", 0), 
                                "Execution": waits.get("execution", 0),
                                "Transactions": (f_data.get("timeActiveMicros", 0) / 1000.0) if f_data.get("timeActiveMicros") else 0
                            }
                        if s_o["min_example_raw"] is None or duration < s_o["min_ms"]:
                            s_o["min_ms"] = duration; s_o["min_example_raw"] = entry; s_o["min_peek_attr"] = attr

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

        # 🧠 Pass 2: Expert Synthesis (Unified v2.6.0)
        # We now use the dedicated synthesis logic for the full sweep results.
        final_results = finalize_forensic_summary(
            shape_stats=shape_stats,
            log_dur_sec=log_dur_sec,
            rules=rules
        )
        
        system_summary = finalize_forensic_summary(
            shape_stats=system_shape_stats,
            log_dur_sec=log_dur_sec,
            rules=[] # No diagnostic rules for system ops yet
        )
        system_summary = [s for s in system_summary if s["total_ms"] > 0]
        
        timeout_summary = finalize_forensic_summary(
            shape_stats=timeout_shape_stats,
            log_dur_sec=log_dur_sec,
            rules=rules 
        )

        global_total_ms = sum(s["total_ms"] for s in shape_stats.values())
        
        # 🏮 Post-Synthesis Identity Back-filling (v1.3.16)
        # (Note: Identity back-filling is now handled within the aggregator or pre-pass)

        avg_slow_ms = global_total_ms / total_slow_count if total_slow_count > 0 else 0
        # 📈 Senior Stat Sync (v2.7.7): Count both severity errors and identified command failures
        log_error_count = max(severity_stats.get('E', 0) + severity_stats.get('ERROR', 0), identified_error_count)

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
                    for sk, sv in sorted(message_registry.items(), key=lambda x: x[1]["count"], reverse=True)[:12]
                ], 
                "timeout_patterns": sorted(timeout_patterns.values(), key=lambda x: x["count"], reverse=True)[:8], 
                "namespaces": {str(k): v for k, v in namespace_stats.most_common(12) if k != "unknown" and ".$cmd" not in k},
                "error_namespaces": {str(k): v for k, v in error_namespace_stats.most_common(16) if k != "unknown" and ".$cmd" not in k},
                "error_code_summary": [
                    {
                        "code": k,
                        "name": v["name"],
                        "count": v["count"],
                        "avg_ms": v["total_ms"] / v["count"] if v["count"] > 0 else 0,
                        "top_ns": v["namespaces"].most_common(1)[0][0] if v["namespaces"] else "N/A",
                        "top_app": v["apps"].most_common(1)[0][0] if v["apps"] else "N/A"
                    }
                    for k, v in sorted(error_code_agg.items(), key=lambda x: x[1]["count"], reverse=True)
                ],
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
            "timeout_summary": timeout_summary
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
                "total_queue_wait_ms": 0, "total_cpu_ms": 0,
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
        s["total_cpu_ms"] += (metrics.get("forensic", {}).get("cpuNanos", 0) / 1000000.0)
        
        app = metrics.get("app_name", "unknown")
        if app != "unknown": s["app_names"].add(app)
        
        if s["max_example_raw"] is None or duration >= s["max_ms"]:
            s["max_example_raw"] = entry
            
        for b in sorted(LATENCY_BUCKETS, reverse=True):
            if duration >= b:
                s["histogram"][b] += 1; break
    return shape_stats

def finalize_forensic_summary(shape_stats: Dict[str, Dict], log_dur_sec: float = 1.0, rules: List = None) -> List[Dict]:
    """
    Synthesizes the Complete Forensic Data Contract (v2.6.2).
    This function is the Single Source of Truth for both CLI and Web views.
    """
    from .parser import extract_log_metrics
    final_results = []
    rules = rules or []
    top_shapes = sorted(shape_stats.values(), key=lambda x: x["total_ms"], reverse=True)
    sum_total_active = sum(s["total_active_ms"] for s in shape_stats.values()) or 1
    
    for i, q in enumerate(top_shapes):
        tags = []
        # 🧪 High-Fidelity Extraction (Max & Min)
        max_entry = q["max_example_raw"]
        min_entry = q.get("min_example_raw") or max_entry
        
        def _get_metrics(entry):
            if not entry: return {}
            if isinstance(entry, str):
                try: return extract_log_metrics(json.loads(entry), include_full_command=True) or {}
                except: return {}
            return entry.get("metrics") or extract_log_metrics(entry, include_full_command=True) or {}

        max_d = _get_metrics(max_entry)
        min_d = _get_metrics(min_entry)
        
        # 🕒 Timestamp & Attribute Extraction
        def _get_ts_and_attr(entry):
            if not entry: return "unknown", {}
            if isinstance(entry, str):
                try: obj = json.loads(entry)
                except: return "unknown", {}
            else: obj = entry or {}
            
            t = obj.get("t", {}).get("$date") if isinstance(obj.get("t"), dict) else obj.get("t")
            return (str(t) if t else "unknown"), obj.get("attr", {})

        max_ts, max_attr = _get_ts_and_attr(max_entry)
        min_ts, min_attr = _get_ts_and_attr(min_entry)

        eval_data = {
            **q, "avg_ms": q["total_ms"]/q["count"], 
            "keysExamined": max_d.get("forensic", {}).get("keysExamined", 0),
            "docsExamined": max_d.get("forensic", {}).get("docsExamined", 0),
            "nreturned": max_d.get("forensic", {}).get("nreturned", 1),
            "plan_summary": max_d.get("plan_summary", "N/A"),
            "has_regex": 1 if q.get("has_regex") else 0,
            "error_code": max_d.get("forensic", {}).get("errCode") or max_d.get("forensic", {}).get("code"),
            "error_name": max_d.get("forensic", {}).get("errName") or max_d.get("forensic", {}).get("codeName")
        }
        
        for rule in rules:
            try:
                triggered, val = evaluate_rule(rule, eval_data)
                if triggered: 
                    label = str(rule["label"])
                    if "{value" in label and val is not None:
                        display_val = val * 100 if "%" in label else val
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
            "load_pct": round((q["total_active_ms"]/sum_total_active)*100, 1),
            "aas_load": round(q["total_active_ms"]/(max(log_dur_sec, 1)*1000), 2),
            "diagnostic_tags": tags if tags else [{"label": "BALANCED", "severity": "success"}],
            "app_name": ", ".join(list(q["app_names"])[:3]) if q["app_names"] else "unknown",
            "plan_summary": str(max_d.get("plan_summary", "N/A")),
            # 🏺 Web Drill-Down Metadata (Mandatory Contract)
            "query_shape_hash": str(q.get("query_shape_hash", "N/A")),
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
