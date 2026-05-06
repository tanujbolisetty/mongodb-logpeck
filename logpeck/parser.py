# ==============================================================================
# logpeck: parser.py
# The surgical extraction layer for MongoDB forensic telemetry.
# ==============================================================================
# This module is responsible for the 'Pass 1' ingestion phase:
# 1. JSON Parsing & Line-by-Line Attribute Recovery.
# 2. Heuristic Namespace Recovery (for obscured or truncated logs).
# 3. Recursive Query Parameter Harvesting (Schema Induction).
# 4. Operation Identity Detection (Find vs Update vs TTL Index).
# ==============================================================================

import json
import re
import hashlib
from typing import Dict, Any, List, Optional, Set
from .specification import (
    ERROR_CODE_MAP, FIELD_DISPLAY, METRIC_MARKERS,
    RE_HEURISTIC_NS_PATTERNS, COMMON_COMMAND_KEYS, CRUD_OP_MAP,
    SEARCH_PROBES, NESTED_METRIC_MAPPING,
    SYSTEM_COMPONENTS, SYSTEM_NAMESPACES, SYSTEM_APP_NAMES,
    EXCLUDED_SYSTEM_FIELDS, SEARCH_STRUCTURAL_FIELDS
)

# 🕵️ Heuristic Forensic Patterns
# Compiled at module load from specification.py patterns.
RE_HEURISTIC_NS = [re.compile(p) for p in RE_HEURISTIC_NS_PATTERNS]

def heuristic_extract_ns(text: str) -> Optional[str]:
    """
    Scans raw message text for db.collection patterns using heuristic regex.
    
    This is critical for Atlas logs where the namespace might be buried in a 
    text message rather than a structured field (e.g., secondary elections).
    """
    if not text: return None
    for pattern in RE_HEURISTIC_NS:
        match = pattern.search(text)
        if match: return match.group(1)
    return None


def _harvest_params(obj: Any, params_found: Dict[str, Any], depth=0):
    """
    Recursively audits a query object to extract field paths and literal values.
    
    This function implements a "Priority Predicate" harvesting policy:
    1. If a key is 'path', its value is treated as a schema field.
    2. If a key is in SEARCH_STRUCTURAL_FIELDS, we recurse into its value.
    3. All other keys are treated as business-level fields and harvested.
    
    Logic Note: We prioritize "Rich Values" (dicts/lists) over simple booleans 
    to ensure we capture actually meaningful filter samples for the forensic report.
    """
    # 🧪 Depth Boost: Standard MongoDB is 8-10, but complex 
    # Atlas Search / $facet pipelines can exceed 20 levels.
    if depth > 32 or not obj: return  
    
    if isinstance(obj, dict):
        # 🧪 Atlas Search Path Extraction
        # Search pipelines often use { "path": "myField" } inside operators.
        if "path" in obj and isinstance(obj["path"], (str, list)):
            paths = [obj["path"]] if isinstance(obj["path"], str) else obj["path"]
            for field_name in paths:
                if not isinstance(field_name, str): continue
                # Ignore structural fields like 'analyzer' or 'score'
                if field_name not in SEARCH_STRUCTURAL_FIELDS:
                    # 🧪 Intelligent Value Harvesting
                    # Try to capture a sample value to show in the "Sample Values" tooltip.
                    val = obj.get("query") or obj.get("value")
                    if val is None:
                        # Look for range bounds for numeric fields
                        val_keys = ["gte", "lte", "gt", "lt", "origin", "pivot"]
                        found_vals = {vk: obj[vk] for vk in val_keys if vk in obj}
                        val = found_vals if found_vals else True
                    
                    # Overwrite protection: If we already have a dict (complex filter),
                    # don't overwrite it with a simple 'True' marker.
                    if field_name in params_found:
                        old_v = params_found[field_name]
                        if isinstance(old_v, (dict, list)) and not isinstance(val, (dict, list)):
                            pass # Keep the "richer" filter value
                        else:
                            params_found[field_name] = val
                    else:
                        params_found[field_name] = val
             
        # Standard Key-Value Harvesting
        for k, v in obj.items():
            if k.startswith("$"):
                # Always recurse into operators (e.g. $match, $and, $elemMatch)
                _harvest_params(v, params_found, depth + 1)
            elif k not in EXCLUDED_SYSTEM_FIELDS:
                # Recurse into potential object payloads (e.g. sub-documents)
                _harvest_params(v, params_found, depth + 1)
                
                # Only harvest the key 'k' as a parameter if it's NOT system noise
                if k not in SEARCH_STRUCTURAL_FIELDS:
                    can_assign = True
                    if k in params_found:
                        old_v = params_found[k]
                        # Don't overwrite complex logic (e.g. {$gt: 5}) with plain values (e.g. 5)
                        if isinstance(old_v, (dict, list)) and not isinstance(v, (dict, list)):
                            can_assign = False
                    
                    if can_assign:
                        if not isinstance(v, (dict, list)):
                            params_found[k] = v
                        elif isinstance(v, dict) and any(str(sk).startswith("$") for sk in v.keys()):
                            # Preserve MongoDB value objects (e.g. {$date: ...}, {$oid: ...})
                            params_found[k] = v
    elif isinstance(obj, list):
        # Recurse through all elements in an array (e.g. $in: [1, 2, 3])
        for item in obj: _harvest_params(item, params_found, depth + 1)


def extract_query_schema(cmd_obj: dict, op: str) -> List[str]:
    """
    Induces the business-level schema from a query command.
    
    🛡️ Dual-Layer Hygiene: 
    1. The recursive harvester collects everything non-system.
    2. This wrapper ensures that structural keywords (like 'analyzer', 'search', 'index') 
       never leak into the final 'Schema' column of the dashboard.
    """
    params = extract_query_params(cmd_obj, op)
    schema = [k for k in params.keys() if k not in SEARCH_STRUCTURAL_FIELDS]
    return sorted(list(set(schema)))

def extract_query_params(cmd_obj: dict, op: str) -> Dict[str, Any]:
    params = {}
    if not cmd_obj: return {}
    
    # Standard op routing
    if op in ["find", "tx-find"]: _harvest_params(cmd_obj.get("filter"), params)
    elif op in ["aggregate", "tx-aggregate"]:
        pipe = cmd_obj.get("pipeline", [])
        for stage in pipe:
            if isinstance(stage, dict):
                _harvest_params(stage.get("$match"), params)
                _harvest_params(stage.get("$search"), params)
    elif op in ["update", "tx-update", "u"]:
        # 🧬 CRUD Coarsening: Only fingerprint the LOOKUP part, skip payload data
        for field in ["filter", "q"]:
            val = cmd_obj.get(field)
            if val: _harvest_params(val, params)
            
        for u in cmd_obj.get("updates", []):
            _harvest_params(u.get("q"), params)
            
    elif op in ["delete", "tx-delete", "d"]:
        for field in ["filter", "q"]:
            val = cmd_obj.get(field)
            if val: _harvest_params(val, params)
    elif op in ["insert", "tx-insert", "i"]:
        # Inserts have no query filter — return empty (no schema to extract)
        pass
    elif op in ["count", "distinct", "findAndModify", "tx-findandmodify"]:
        _harvest_params(cmd_obj.get("query") or cmd_obj.get("filter"), params)
    elif op == "search": _harvest_params(cmd_obj, params)
    
    return params

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(line)
    except:
        return None

def detect_op_and_ns(attr: Dict[str, Any], cmd_obj: Dict, msg: str, ns: str):
    """
    The Forensic Identity Probe.
    
    Surgically identifies the operation type and namespace, even when 
    the log is obscured due to:
    - Timeouts (where only the error message remains)
    - Transactions (where the namespace is hidden in a '$cmd' command)
    - Background Maintenance (TTL Index, Shard Balancing)
    
    Returns: (op_name, namespace)
    """
    msg = msg or ""
    attr_type = attr.get("type")
    
    crud = attr.get("CRUD")
    if attr_type and attr_type != "command":
        raw_op = attr_type
    elif isinstance(crud, dict):
        raw_op = crud.get("op")
        ns = crud.get("ns") or ns
        # Map abbreviations to standard ops
        if raw_op in CRUD_OP_MAP: raw_op = CRUD_OP_MAP[raw_op]
        # Infer op if missing but fields are present
        if not raw_op:
            if "diff" in crud or "o2" in crud: raw_op = "update"
            elif "o" in crud: raw_op = "insert"
    else:
        # 🧪 Op Triage: Fallback to message for system events (Elections, Network, Heartbeats)
        if cmd_obj:
            # 🕵️ Error Priority: If the command failed, the error is the event.
            err = cmd_obj.get("error") or attr.get("error")
            if err and isinstance(err, str) and ("MaxTimeMS" in err or "exceeded time limit" in err):
                raw_op = "MaxTimeMSExpired"
            else:
                raw_op = next(iter(cmd_obj))
        elif msg:
            # Sanitize/Crop if it is a system event to maintain high resolution
            raw_op = msg
        else:
            raw_op = "N/A"
    
    # 🕵️ Special System Event Harvesting
    # Target: Connection Metadata & Authentication lines to recover Identity Anchors
    if msg == "client metadata":
        raw_op = "client metadata"
        app_info = get_nested_value({"attr": attr}, "attr.doc.application.name")
        if app_info: attr["appName"] = str(app_info)
    elif msg == "Successfully authenticated":
        raw_op = "authentication"
        # Database in auth line is the target of the auth (often admin), but user is the key anchor
        if "user" in attr: attr["user"] = attr["user"]
    
    # 🕵️ Forensic Attribute Recovery
    # Recover namespace from attributes (common in housekeeping logs like TTL index)
    if not ns or ns == "N/A" or str(ns).endswith(".$cmd"):
        ns = attr.get("namespace") or ns

    # 🧬 Recovery Anchor
    # Signal if this entry has high-confidence data blocks (CRUD)
    has_crud = isinstance(attr.get("CRUD"), dict)

    # 🕵️ Transaction & Command Namespace Resolution
    params = attr.get("parameters", {})
    #: Strengthened detection to include Logical Sessions and Autocommit markers
    is_tx = (str(ns).endswith(".$cmd") or 
             "txnNumber" in attr or 
             "autocommit" in attr or
             "lsid" in attr or
             has_crud or 
             "txnNumber" in params)
    
    if is_tx or ns == "N/A" or not ns:
        coll = None
        for k in COMMON_COMMAND_KEYS:
            if k in cmd_obj and isinstance(cmd_obj[k], str):
                coll = cmd_obj[k]
                break
        
        if not coll and str(raw_op).lower() == "getmore" and "collection" in cmd_obj:
            coll = cmd_obj["collection"]
            if coll == "oplog.rs":
                raw_op = "OplogFetcher"
        
        if isinstance(coll, str):
            # Resolve DB: Check cmd_obj, top-level attr, or fallback to the prefix of the $cmd namespace
            db_fallback = str(ns).split(".")[0] if ns and "." in str(ns) else "admin"
            db = attr.get("db") or attr.get("$db") or cmd_obj.get("$db") or attr.get("dbName") or db_fallback
            ns = f"{db}.{coll}" if "." not in str(coll) else coll

    from .specification import SIMPLIFIED_OPS
    op = str(raw_op).lower() # Default to raw op

    for pattern, simple_name in SIMPLIFIED_OPS.items():
        if pattern.lower() in str(raw_op).lower() or (msg and pattern.lower() in msg.lower()):
            op = simple_name # Preserve case from specification

    # 🕵️ TTL Index Discovery
    # Refined: Move override after loop to ensure background deletions aren't masked by 'delete' pattern.
    if ("numDeleted" in attr or "ndeleted" in attr) and "index" in attr and "lsid" not in attr:
        op = "TTL Index"

    # Final Normalization and Transaction Enrichment
    if is_tx and op.lower() in ["update", "insert", "delete", "remove", "deletes", "findandmodify", "find"]:
        if not op.lower().startswith("tx-"):
            # Normalize 'remove' or 'deletes' to 'delete' when prefixing
            tx_op = "delete" if op.lower() in ["remove", "deletes"] else op
            op = f"tx-{tx_op}"

    if not ns or ns == "N/A" or str(ns).endswith(".$cmd"):
        h_ns = heuristic_extract_ns(msg)
        if not h_ns and "error" in attr:
            h_ns = heuristic_extract_ns(str(attr["error"]))
        if h_ns: ns = h_ns
        
    return op, ns, has_crud

def normalize_conn_id(ctx: str) -> str:
    """
    Standardizes connection IDs for stateful reconstruction .
    
    MongoDB uses varying formats like '[conn123]', 'conn123', or just '123'. 
    This normalizes everything to 'conn123' to allow consistent lookup 
    across different log entries in the same session.
    """
    if not ctx: return "N/A"
    # Clean brackets and prefix
    raw = str(ctx).strip("[]").replace("conn", "").strip()
    return f"conn{raw}" if raw else "N/A"

def induce_log_schema(entry: Dict[str, Any], last_ts: Optional[str] = None) -> Dict[str, Any]:
    """
    The Universal JSON Adaptor.
    
    Standardizes varied log formats (Standard, Flat, Lean) into a canonical 
    header view used for initial triage. 
    
    Features:
    - Ghost Timestamping: Anchors lean logs (missing 't' field) to the 
      last known event timestamp to maintain chronological integrity.
    - Severity Mapping: Infers severity from presence of error fields if missing.
    """
    canonical = {}
    
    # 1. Timestamp Induction (Ghost Stitching)
    # Extracts the date from MongoDB's ISODate object or raw string.
    raw_t = entry.get("t")
    ts = raw_t.get("$date") if isinstance(raw_t, dict) else raw_t
    
    # 🧬 Normalization: Ensure we have a string representation
    ts_str = str(ts) if ts else None
    
    canonical["t"] = ts_str or entry.get("time") or entry.get("ts") or last_ts
    
    # 2. Severity Induction (I=Info, D=Debug, E=Error, W=Warning)
    s = entry.get("s") or entry.get("severity") or entry.get("level")
    if not s:
        # Infer severity if the engine finds a surgical error block
        s = "E" if "error" in entry or "errorMessage" in entry else "I"
    canonical["s"] = str(s)
    
    # 3. Message/Identity Induction
    msg = entry.get("msg")
    if not msg:
        if entry.get("type") == "command": msg = "Slow query"
        elif "error" in entry: msg = "Infrastructure Failure"
        else: msg = "N/A"
    canonical["msg"] = msg
    
    # 4. Context Induction (Connection / Thread / Host)
    ctx = entry.get("ctx") or entry.get("host") or entry.get("target") or entry.get("connectionId") or "N/A"
    canonical["ctx"] = normalize_conn_id(str(ctx))
    
    # 5. Component/Category Induction (COMMAND, ACCESS, NETWORK, etc.)
    canonical["c"] = entry.get("c") or entry.get("component") or entry.get("category") or "N/A"
    
    return canonical

def extract_log_metrics(entry: Dict[str, Any], include_full_command: bool = False, last_ts: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Surgically extracts forensic metrics from a raw MongoDB log entry.
    
    Handles:
    - Workload Duration (ms)
    - Wait Time Normalization (Storage, Locks, Queue, Replication)
    - Forensic Counters (keysExamined, docsExamined, etc.)
    - Query Schema & Shape Hashing
    """
    # 🧪 Unified Schema Induction
    # Standardize headers (Timestamp, Severity, Msg, Context) across all formats.
    header = induce_log_schema(entry, last_ts)
    
    # 🧬 Timestamp Persistence: Inject the normalized timestamp back into the entry 
    # to ensure all downstream forensic samples (and reports) have valid attribution.
    if header.get("t"): entry["t"] = header["t"]
    
    attr = entry.get("attr")
    
    if not isinstance(attr, dict):
        attr = synthesize_flat_attr(entry)
        entry["attr"] = attr
            
    # Handle both standard command logs and transactional CRUD blocks
    cmd_obj = attr.get("command") or attr.get("CRUD") or entry.get("command") or {}
    msg = header["msg"]
    ns_raw = attr.get("ns") or entry.get("ns") or "N/A"
    
    op, ns, has_crud = detect_op_and_ns(attr, cmd_obj, msg, ns_raw)
    
    # 🆔 Identity Extraction
    identity = extract_identity(attr, entry, op)

    # 🧬 Shape & Hash Extraction
    q_hash = extract_query_hash(attr, entry, op)
    
    # ⏱️ Duration Discovery ( Hardening)
    # Support multiple formats: durationMillis, durationMS, or flat 'ms' field.
    ms = attr.get("durationMillis") or attr.get("durationMS") or attr.get("ms") or \
         entry.get("durationMillis") or entry.get("durationMS") or entry.get("ms") or 0
    if not ms and "parameters" in attr: 
        ms = attr["parameters"].get("durationMillis", 0)

    # 🕵️ Forensic Stats Extraction
    forensic = extract_forensic_stats(attr, entry)
    
    # 🚦 Wait Hierarchy Calculation
    waits_ms = calculate_waits(attr, entry, forensic, ms, op)

    schema_cmd = attr.get("originatingCommand") or cmd_obj
    schema_op = op if op.startswith("tx-") or op in ["update", "insert", "delete"] else (next(iter(schema_cmd)) if schema_cmd else op)
    
    # 🕵️ Surgical Pattern Grep
    cmd_str = str(cmd_obj)
    has_regex = "$regex" in cmd_str or "$regularExpression" in cmd_str
    has_lookup = "$lookup" in cmd_str

    # 🔍 Search & AI Intent Extraction
    plan_summary = extract_search_metadata(attr, entry, cmd_obj, op)

    # 🕵️ System Classification
    is_sys = is_system_query(ns, identity["appName"], header.get("c", ""), op, has_crud)

    metrics = {
        "ms": ms, "ns": ns, "op": op, "query_shape_hash": q_hash,
        "query_hash": attr.get("queryHash") or entry.get("queryHash") or "N/A",
        "plan_cache_key": attr.get("planCacheKey") or entry.get("planCacheKey") or "N/A",
        "query_schema": extract_query_schema(schema_cmd, schema_op),
        "query_params": extract_query_params(schema_cmd, schema_op),
        "has_regex": has_regex,
        "has_lookup": has_lookup,
        "has_crud": has_crud,
        "is_system": is_sys,
        "plan_summary": plan_summary, 
        "app_name": identity["appName"],
        "user": identity["user"],
        "client_ip": identity["client_ip"],
        "op_id": identity["op_id"],
        "forensic": forensic, "waits_ms": waits_ms
    }
    if include_full_command: metrics["attr"] = attr
    return metrics

def is_system_query(ns: str, app: str = "", component: str = "", op: str = "", has_crud: bool = False) -> bool:
    """
    Surgically identifies if an event is internal system noise .
    Filters by Namespace, App Name, OR Component.
    """
    # 1. Explicit System Namespace check (Priority 1)
    if ns and ns != "N/A":
        if any(ns.startswith(p) for p in SYSTEM_NAMESPACES) or ".system." in ns or ns == "oplog.rs":
            return True

    # 2. Transaction & Management Immunity ( Fix)
    # Never filter transactions or destructive admin commands as noise.
    #: Explicitly protect CRUD operations and tx-prefixed commands.
    if has_crud or str(op).startswith("tx-") or op == "transaction" or "drop" in str(op).lower() or "rename" in str(op).lower():
        return False
            
    # 2. System Identity check (Priority 2: Identity > Business Namespace)
    # This captures background tasks even if they target business namespaces (e.g. TTL, mongot)
    if str(component).upper() in SYSTEM_COMPONENTS:
        return True
    if any(str(app).startswith(s) for s in SYSTEM_APP_NAMES):
        return True
    
    # Explicitly route infrastructure-driven operations to System
    if op in ["Wire Spec Update", "Replica Set Change", "TTL Index", "Oplog Processing", "Oplog Truncation", "OplogFetcher"]:
        return True

    # 3. Business Namespace check (Priority 3)
    if ns and ns != "N/A":
        return False
        
    return False

def synthesize_flat_attr(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    🧪 Flat-Block Hybrid Induction .
    Synthesizes a temporary attr block from top-level fields for lean logs.
    """
    attr = {}
    attr = {}
    for k in SEARCH_PROBES:
        if k in entry: attr[k] = entry[k]
        
    err_obj = entry.get("error")
    if isinstance(err_obj, dict):
        for k, v in err_obj.items():
            if k not in attr: attr[k] = v
    elif isinstance(err_obj, str) and "error" not in attr:
        attr["error"] = err_obj
    return attr

def extract_identity(attr: Dict[str, Any], entry: Dict[str, Any], op: str) -> Dict[str, str]:
    """Identifies the application, user, IP, and operation ID anchors."""
    orig_cmd = attr.get("originatingCommand", {})
    ip_raw = str(attr.get("remote") or attr.get("client") or "N/A")
    
    # 🧪 Atlas Identity Restoration: 
    # Check for appName in multiple locations including nested doc.application.name
    app_nested = get_nested_value({"attr": attr}, "attr.doc.application.name")
    app_name = str(attr.get("appName") or entry.get("appName") or orig_cmd.get("appName") or app_nested or "N/A")

    return {
        "appName": app_name,
        "user": str(attr.get("user") or entry.get("user") or orig_cmd.get("user") or "N/A"),
        "client_ip": str(ip_raw.split(":")[0] if ":" in ip_raw else ip_raw),
        "op_id": str(attr.get("opId") or entry.get("opId") or "N/A")
    }

def extract_query_hash(attr: Dict[str, Any], entry: Dict[str, Any], op: str) -> str:
    """Surgically extracts the structural fingerprint (8.0 aware)."""
    shape_hash = attr.get("queryShapeHash") or attr.get("planCacheShapeHash") or attr.get("queryHash")
    if not shape_hash:
        shape_hash = entry.get("queryShapeHash") or entry.get("planCacheShapeHash") or entry.get("queryHash")
    
    if not shape_hash and op == "getmore" and "originatingCommand" in attr:
        orig = attr["originatingCommand"]
        shape_hash = orig.get("queryShapeHash") or orig.get("planCacheShapeHash") or orig.get("queryHash")
    
    return shape_hash or "N/A"

def extract_forensic_stats(attr: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
    """Harvests performance counters and storage metrics recursively."""
    # 🕵️ BFS Discovery
    forensic = discovery_harvest(attr, METRIC_MARKERS)
    
    # Error metadata extraction
    err_obj = attr.get("error") or entry.get("error")
    harvested_error = {}
    if isinstance(err_obj, dict):
        harvested_error["errCode"] = err_obj.get("code") or err_obj.get("errCode")
        harvested_error["errName"] = err_obj.get("codeName") or err_obj.get("errName")
        harvested_error["errMsg"] = err_obj.get("errmsg") or err_obj.get("errMsg")
    elif isinstance(err_obj, str):
        harvested_error["errMsg"] = err_obj

    # Promote metadata
    for k in ["errCode", "errName", "errMsg", "ok"]:
        if k in harvested_error and k not in forensic: forensic[k] = harvested_error[k]
        elif k in attr and k not in forensic: forensic[k] = attr[k]

    # Resolve names
    if ("errCode" in forensic or "errMsg" in forensic) and "errName" not in forensic:
        code = forensic.get("errCode")
        forensic["errName"] = ERROR_CODE_MAP.get(int(code) if str(code).isdigit() else 0) or str(code or "DirectError")

    # Storage specials
    if "shardNames" in attr: forensic["shards"] = len(attr["shardNames"])
    
    # Map dots to canonical metric IDs
    for path, metric_id in NESTED_METRIC_MAPPING.items():
        val = get_nested_value(entry, path)
        if val is not None: forensic[metric_id] = val
        
    return forensic

def calculate_waits(attr: Dict[str, Any], entry: Dict[str, Any], forensic: Dict[str, Any], ms: float, op: str) -> Dict[str, float]:
    """Constructs the diagnostic wait-hierarchy (ms)."""
    waits = {}
    
    # 1. Locks
    lock_micros = 0
    for res, counts in attr.get("locks", {}).items():
        if isinstance(counts, dict):
            w = counts.get("timeAcquiringMicros", 0)
            lock_micros += sum(w.values()) if isinstance(w, dict) else (w if isinstance(w, (int, float)) else 0)
    if lock_micros > 0: waits["lock_wait"] = round(lock_micros / 1000.0, 2)

    # 2. Storage (Unified)
    s_read = (get_nested_value(entry, "attr.storage.data.timeReadingMicros") or 0) + (get_nested_value(entry, "attr.storage.index.timeReadingMicros") or 0)
    s_write = (get_nested_value(entry, "attr.storage.data.timeWritingMicros") or 0) + (attr.get("waitForWriteConcernDurationMillis") or 0) * 1000
    s_cache = forensic.get("timeWaitingMicros_cache", 0)
    oplog_micros = (attr.get("totalOplogSlotDurationMicros") or 0)
    oplog_wait = oplog_micros if (oplog_micros > 1000 and ms > 100) else 0
    
    s_total = (s_read + s_write + s_cache + oplog_wait) / 1000.0
    if s_total > 0: waits["storage_wait"] = round(s_total, 2)

    # 3. Queue / Planning / Repl
    q_micros = get_nested_value(entry, "attr.queues.execution.totalTimeQueuedMicros") or 0
    if q_micros > 0: waits["queue_wait"] = round(q_micros / 1000.0, 2)
    
    p_micros = attr.get("planningTimeMicros") or 0
    if p_micros > 0: waits["planning"] = round(p_micros / 1000.0, 2)
    
    flow = attr.get("flowControlMillis") or 0
    if flow > 0: waits["replication_wait"] = flow

    # 3.5 Atlas Search
    mongot = forensic.get("mongot_wait", 0)
    if mongot > 0: waits["mongot_wait"] = mongot

    # 4. Pure Execution
    work = attr.get("workingMillis")
    if work is not None: waits["execution"] = work

    # 🧪 Wall-Clock Hardening: Cap components at total latency
    if ms > 0:
        for k in waits: waits[k] = min(waits[k], ms)
        
    return waits

def extract_search_metadata(attr: Dict[str, Any], entry: Dict[str, Any], cmd_obj: Dict[str, Any], op: str) -> str:
    """
    Modular Intent Extractor for Atlas Search & Vector Search.
    Identifies index names and surfaces them to the Plan Summary.
    """
    plan_summary = attr.get("planSummary") or entry.get("planSummary") or "N/A"
    
    # Trace target (handle getMore originations)
    target = cmd_obj
    if op == "getMore" and isinstance(attr.get("originatingCommand"), dict):
        target = attr["originatingCommand"]
        
    if not isinstance(target, dict): return plan_summary

    pipeline = target.get("pipeline") or []
    if not isinstance(pipeline, list):
        # Handle cases where $search might be the top-level command (rare but possible in some versions)
        if "$search" in target:
            idx = target["$search"].get("index", "default")
            return f"🔍 SEARCH [{idx}]"
        return plan_summary

    # Recursively scan for search stages
    for stage in pipeline:
        if not isinstance(stage, dict): continue
        
        # Atlas Search ($search)
        if "$search" in stage:
            idx = stage["$search"].get("index", "default")
            return f"🔍 SEARCH [{idx}]"
            
        # Vector Search ($vectorSearch)
        elif "$vectorSearch" in stage:
            idx = stage["$vectorSearch"].get("index", "default")
            return f"🧬 VECTOR [{idx}]"
            
        # Also check for nested search (e.g. inside $facet)
        for k, v in stage.items():
            if isinstance(v, list):
                for sub in v:
                    if isinstance(sub, dict) and ("$search" in sub or "$vectorSearch" in sub):
                        s_type = "SEARCH" if "$search" in sub else "VECTOR"
                        icon = "🔍" if s_type == "SEARCH" else "🧬"
                        idx = sub.get("$search", sub.get("$vectorSearch")).get("index", "default")
                        return f"{icon} {s_type} [{idx}]"
            
    return plan_summary

def discovery_harvest(obj: Any, marker_map: Dict[str, str], result: Optional[Dict[str, Any]] = None, depth: int = 0) -> Dict[str, Any]:
    """
    The Universal Discovery Harvester .
    Performs a Breadth-First Search (BFS) for keys listed in METRIC_MARKERS.
    """
    if result is None: result = {}
    if depth > 10 or not isinstance(obj, dict): return result
    
    for k, v in obj.items():
        if k in marker_map:
            std_id = marker_map[k]
            if std_id not in result:
                result[std_id] = v
        if isinstance(v, dict):
            discovery_harvest(v, marker_map, result, depth + 1)
    return result

def get_nested_value(obj: Any, path: str) -> Any:
    try:
        for part in path.split('.'):
            if isinstance(obj, dict): obj = obj.get(part)
            else: return None
        return obj
    except: return None
