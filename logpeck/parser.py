import json
import re
import hashlib
from typing import Dict, Any, List, Optional, Set
from .specification import ERROR_CODE_MAP, FIELD_DISPLAY, METRIC_MARKERS

# 🕵️ Heuristic Forensic Patterns (v1.3.5)
RE_HEURISTIC_NS = [
    re.compile(r'on ([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)'),
    re.compile(r'ns: ["\']?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)'),
    re.compile(r'namespace: ([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)'),
    re.compile(r'for ns: ([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)'),
    re.compile(r'collection: ([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)'),
    re.compile(r'target: ([a-zA-Z0-9_-]+\.[a-zA-Z0-9_\.-]+)')
]

def heuristic_extract_ns(text: str) -> Optional[str]:
    """Scans raw message text for db.collection patterns using heuristic regex."""
    if not text: return None
    for pattern in RE_HEURISTIC_NS:
        match = pattern.search(text)
        if match: return match.group(1)
    return None

from .specification import (
    SYSTEM_COMPONENTS, SYSTEM_NAMESPACES, SYSTEM_APP_NAMES,
    EXCLUDED_SYSTEM_FIELDS, SEARCH_STRUCTURAL_FIELDS
)


def _harvest_params(obj: Any, params_found: Dict[str, Any], depth=0):
    """
    Recursively audits a query object to extract field paths and literal values.
    
    This function implements a "Priority Predicate" harvesting policy:
    1. If a key is 'path', its value is treated as a schema field.
    2. If a key is in SEARCH_STRUCTURAL_FIELDS, we recurse into its value.
    3. All other keys are treated as business-level fields and harvested.
    """
    if depth > 32 or not obj: return  # 🧪 Depth Boost (v2.7.10): For complex Atlas Search
    if isinstance(obj, dict):
        # 🧪 Atlas Search Path Extraction (v1.1.50)
        # If we find a "path" field, its value is the actual business field name we want to harvest.
        if "path" in obj and isinstance(obj["path"], (str, list)):
            paths = [obj["path"]] if isinstance(obj["path"], str) else obj["path"]
            for field_name in paths:
                if not isinstance(field_name, str): continue
                if field_name not in SEARCH_STRUCTURAL_FIELDS:
                    # 🧪 Intelligent Value Harvesting (v1.1.53)
                    val = obj.get("query") or obj.get("value")
                    if val is None:
                        # Look for range bounds or common operator keys
                        val_keys = ["gte", "lte", "gt", "lt", "origin", "pivot"]
                        found_vals = {vk: obj[vk] for vk in val_keys if vk in obj}
                        val = found_vals if found_vals else True
                    
                    # Overwrite protection: Don't let meta-values (like sorts) overwrite sample values
                    if field_name in params_found:
                        old_v = params_found[field_name]
                        if isinstance(old_v, (dict, list)) and not isinstance(val, (dict, list)):
                            pass # Keep the "richer" filter value
                        else:
                            params_found[field_name] = val
                    else:
                        params_found[field_name] = val
             
        for k, v in obj.items():
            if k.startswith("$"):
                _harvest_params(v, params_found, depth + 1)
            elif k not in EXCLUDED_SYSTEM_FIELDS:
                # Always recurse to find nested paths or predicates
                _harvest_params(v, params_found, depth + 1)
                
                # Only harvest 'k' as a parameter if it's NOT a structural/system key
                if k not in SEARCH_STRUCTURAL_FIELDS:
                    # Overwrite protection
                    can_assign = True
                    if k in params_found:
                        old_v = params_found[k]
                        if isinstance(old_v, (dict, list)) and not isinstance(v, (dict, list)):
                            can_assign = False
                    
                    if can_assign:
                        if not isinstance(v, (dict, list)):
                            params_found[k] = v
                        elif isinstance(v, dict) and any(str(sk).startswith("$") for sk in v.keys()):
                            # Preserve MongoDB value objects (e.g. {$date: ...}, {$oid: ...})
                            params_found[k] = v
    elif isinstance(obj, list):
        for item in obj: _harvest_params(item, params_found, depth + 1)


def extract_query_schema(cmd_obj: dict, op: str) -> List[str]:
    params = extract_query_params(cmd_obj, op)
    # 🛡️ Dual-Layer Hygiene: Ensure NO structural keywords leak into the schema display
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
        # 🧬 CRUD Coarsening (v2.6.16): Only fingerprint the LOOKUP part, skip payload data
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
        # 🧬 CRUD Coarsening (v2.6.16): Inserts have no query shape, using fixed _id anchor
        params = {"_id": True}
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
    Surgically identifies the operation type and namespace, even for obscured 
    commands (e.g. timeouts, transactions, or generic $cmd calls).
    """
    msg = msg or ""
    attr_type = attr.get("type")
    
    # 🏺 Common Command Keys Probe (v1.3.17)
    # Registry of keys that carry the target collection name in the command object.
    COMMON_COMMAND_KEYS = ["find", "update", "delete", "insert", "aggregate", "count", "distinct", "findAndModify", "getMore", "$search"]
    
    crud = attr.get("CRUD")
    if attr_type and attr_type != "command":
        raw_op = attr_type
    elif isinstance(crud, dict):
        raw_op = crud.get("op")
        ns = crud.get("ns") or ns
        # Map abbreviations to standard ops (v2.3.5)
        OP_MAP = {"u": "update", "i": "insert", "d": "delete"}
        if raw_op in OP_MAP: raw_op = OP_MAP[raw_op]
        # Infer op if missing but fields are present (v2.3.6)
        if not raw_op:
            if "diff" in crud or "o2" in crud: raw_op = "update"
            elif "o" in crud: raw_op = "insert"
    else:
        # 🧪 Op Triage (v2.0.2): Fallback to message for system events (Elections, Network, Heartbeats)
        if cmd_obj:
            # 🕵️ Error Priority (v2.6.19): If the command failed, the error is the event.
            err = cmd_obj.get("error") or attr.get("error")
            if err and isinstance(err, str) and ("MaxTimeMS" in err or "exceeded time limit" in err):
                raw_op = "MaxTimeMSExpired"
            else:
                raw_op = next(iter(cmd_obj))
        elif msg:
            # Sanitize/Crop if it is a system event to maintain high resolution
            raw_op = msg
        else:
            raw_op = "unknown"
    
    # 🕵️ Special System Event Harvesting (v2.7.3)
    # Target: Connection Metadata & Authentication lines to recover Identity Anchors
    if msg == "client metadata":
        raw_op = "client metadata"
        app_info = get_nested_value({"attr": attr}, "attr.doc.application.name")
        if app_info: attr["appName"] = str(app_info)
    elif msg == "Successfully authenticated":
        raw_op = "authentication"
        # Database in auth line is the target of the auth (often admin), but user is the key anchor
        if "user" in attr: attr["user"] = attr["user"]
    
    # 🕵️ Forensic Attribute Recovery (v2.7.5)
    # Recover namespace from attributes (common in housekeeping logs like TTL index)
    if not ns or ns == "unknown" or str(ns).endswith(".$cmd"):
        ns = attr.get("namespace") or ns

    # 🕵️ Transaction & Command Namespace Resolution (v2.7.6)
    params = attr.get("parameters", {})
    is_tx = str(ns).endswith(".$cmd") or "txnNumber" in attr or (isinstance(crud, dict) and "txnNumber" in crud) or "txnNumber" in params
    
    if is_tx or ns == "unknown" or not ns:
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
    # Final Normalization and Transaction Enrichment
    if is_tx and op.lower() in ["update", "insert", "delete", "findandmodify", "find"]:
        if not op.lower().startswith("tx-"):
            op = f"tx-{op}"

    if not ns or ns == "unknown" or str(ns).endswith(".$cmd"):
        h_ns = heuristic_extract_ns(msg)
        if not h_ns and "error" in attr:
            h_ns = heuristic_extract_ns(str(attr["error"]))
        if h_ns: ns = h_ns
        
    return op, ns

def normalize_conn_id(ctx: str) -> str:
    """Standardizes connection IDs for stateful reconstruction (v2.0.0)."""
    if not ctx: return "unknown"
    # Clean brackets and prefix
    raw = str(ctx).strip("[]").replace("conn", "").strip()
    return f"conn{raw}" if raw else "unknown"

def induce_log_schema(entry: Dict[str, Any], last_ts: Optional[str] = None) -> Dict[str, Any]:
    """
    Standardizes varied log formats (Standard, Flat, Lean) into a canonical header view.
    Utilizes Ghost Timestamping to anchor lean logs to the previous known event.
    """
    canonical = {}
    
    # 1. Timestamp Induction (Ghost Stitching v3.2.7)
    ts = entry.get("t", {}).get("$date") if isinstance(entry.get("t"), dict) else entry.get("t")
    canonical["t"] = ts or entry.get("time") or entry.get("ts") or last_ts
    
    # 2. Severity Induction
    s = entry.get("s") or entry.get("severity") or entry.get("level")
    if not s:
        s = "E" if "error" in entry or "errorMessage" in entry else "I"
    canonical["s"] = str(s)
    
    # 3. Message/Identity Induction
    msg = entry.get("msg")
    if not msg:
        if entry.get("type") == "command": msg = "Slow query"
        elif "error" in entry: msg = "Infrastructure Failure"
        else: msg = "unknown"
    canonical["msg"] = msg
    
    # 4. Context Induction
    ctx = entry.get("ctx") or entry.get("host") or entry.get("target") or entry.get("connectionId") or "unknown"
    canonical["ctx"] = normalize_conn_id(str(ctx))
    
    # 5. Component/Category Induction
    canonical["c"] = entry.get("c") or entry.get("component") or entry.get("category") or "unknown"
    
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
    # 🧪 Unified Schema Induction (v3.2.8)
    # Standardize headers (Timestamp, Severity, Msg, Context) across all formats.
    header = induce_log_schema(entry, last_ts)
    attr = entry.get("attr")
    
    if not isinstance(attr, dict):
        # 🧪 Flat-Block Hybrid Induction (v3.2.5)
        # If the 'attr' block is missing, the log is likely 'flat'.
        # We synthesize a temporary attr block from top-level fields.
        attr = {}
        # Registry of top-level keys that may carry forensic metadata in flat/lean logs.
        # We also look into 'error' and 'outcome' blocks for secondary discovery.
        SEARCH_PROBES = [
            "errCode", "code", "errName", "codeName", "ok", "errMsg", "errmsg", 
            "durationMillis", "durationMS", "ns", "appName", "user", "client", "remote", 
            "queryHash", "queryShapeHash", "planCacheShapeHash", "target", "host",
            "totalOplogSlotDurationMicros", "totalTimeQueuedMicros", "planningTimeMicros",
            "workingMillis", "cpuNanos", "writeConflicts", "keysExamined", "docsExamined", 
            "nreturned", "reslen", "ninserted", "nModified", "ndeleted",
            "storage", "locks", "queues", "mongot", "command", "originatingCommand",
            "waitForWriteConcernDurationMillis", "numYields", "flowControlMillis", "flowControl"
        ]
        for k in SEARCH_PROBES:
            if k in entry: attr[k] = entry[k]
        entry["attr"] = attr
        
        # 🕵️ Nested Error Extraction (v3.2.6): Flatten 'error' dict if present
        err_obj = entry.get("error")
        if isinstance(err_obj, dict):
            for k, v in err_obj.items():
                if k not in attr: attr[k] = v
        elif isinstance(err_obj, str) and "error" not in attr:
            attr["error"] = err_obj
            
    # Handle both standard command logs and transactional CRUD blocks (v2.3.5)
    cmd_obj = attr.get("command") or attr.get("CRUD") or entry.get("command") or {}
    msg = header["msg"]
    ns_raw = attr.get("ns") or entry.get("ns") or "unknown"
    
    op, ns = detect_op_and_ns(attr, cmd_obj, msg, ns_raw)
    
    # Deep Identity Harvesting (v1.3.16)
    # Prefer top-level attr, but fallback to entry (flat) or originatingCommand
    orig_cmd = attr.get("originatingCommand", {})
    app_name = str(attr.get("appName") or entry.get("appName") or orig_cmd.get("appName") or "unknown")
    user_id = str(attr.get("user") or entry.get("user") or orig_cmd.get("user") or "unknown")

    # Shape Hash Hardening (v1.1.49)
    # Prefer MongoDB 8.0 queryShapeHash > planCacheShapeHash > queryHash
    shape_hash = attr.get("queryShapeHash") or attr.get("planCacheShapeHash") or attr.get("queryHash")
    if not shape_hash:
        shape_hash = entry.get("queryShapeHash") or entry.get("planCacheShapeHash") or entry.get("queryHash")
    
    if not shape_hash and op == "getmore" and "originatingCommand" in attr:
        orig = attr["originatingCommand"]
        shape_hash = orig.get("queryShapeHash") or orig.get("planCacheShapeHash") or orig.get("queryHash")
    
    q_hash = shape_hash or "N/A"
    
    # Hybrid Duration Discovery
    ms = attr.get("durationMillis") or attr.get("durationMS") or entry.get("durationMillis") or entry.get("durationMS") or 0
    if not ms and "parameters" in attr: ms = attr["parameters"].get("durationMillis", 0)

    # 🕵️ Senior Forensic Error Harvesting (v3.2.9)
    # Recursively harvest error metadata with Dynamic Name Resolution from ERROR_CODE_MAP.
    forensic = {}
    harvested_error = {}
    err_obj = attr.get("error") or entry.get("error")
    if isinstance(err_obj, dict):
        harvested_error["errCode"] = err_obj.get("code") or err_obj.get("errCode")
        harvested_error["errName"] = err_obj.get("codeName") or err_obj.get("errName")
        harvested_error["errMsg"] = err_obj.get("errmsg") or err_obj.get("errMsg")
    elif isinstance(err_obj, str):
        # 🧪 String-Format Extract (v3.2.10): NotYetInitialized: Replication...
        if ":" in err_obj:
            p_name = err_obj.split(":")[0].strip()
            # If the prefix looks like a primary code name, harvest it
            for code, name in ERROR_CODE_MAP.items():
                if p_name == name:
                    harvested_error["errCode"] = code
                    harvested_error["errName"] = name
                    break
        harvested_error["errMsg"] = err_obj
        
    # 🧬 Dynamic Error Name Resolution (v3.2.11)
    if harvested_error.get("errCode") and not harvested_error.get("errName"):
        code = harvested_error["errCode"]
        if code in ERROR_CODE_MAP:
            harvested_error["errName"] = ERROR_CODE_MAP[code]
            if not harvested_error.get("errMsg"):
                harvested_error["errMsg"] = f"{ERROR_CODE_MAP[code]} (Code: {code})"

    # 🕵️ Universal Discovery Harvester (v3.2.0): Breadth-First Search for markers
    def discovery_harvest(obj, marker_map, result=None, depth=0):
        if result is None: result = {}
        if depth > 10 or not isinstance(obj, dict): return result
        for k, v in obj.items():
            # If marker matched and not already harvested (prioritize top-level)
            if k in marker_map:
                std_id = marker_map[k]
                if std_id not in result:
                    # 🧬 Inline Normalization (v3.2.2)
                    if isinstance(v, (int, float)):
                        if k.endswith("Micros") or k in ["timeAcquiringMicros", "planningTimeMicros"]:
                            v = round(v / 1000.0, 3)
                        elif k.endswith("Nanos") or k == "cpuNanos":
                            v = round(v / 1000000.0, 3)
                    result[std_id] = v
            if isinstance(v, dict):
                discovery_harvest(v, marker_map, result, depth + 1)
        return result

    # Perform discovery on 'attr' and 'harvested_error'
    forensic = discovery_harvest(attr, METRIC_MARKERS)
    
    # Check harvested_error as well (flattened)
    for k, v in harvested_error.items():
        if k in METRIC_MARKERS:
            std_id = METRIC_MARKERS[k]
            if std_id not in forensic:
                # Normalization for error fields
                if isinstance(v, (int, float)):
                    if k.endswith("Micros"): v = round(v / 1000.0, 3)
                    elif k.endswith("Nanos"): v = round(v / 1000000.0, 3)
                forensic[std_id] = v
    
    # 🧪 Metadata Promotion (v3.2.5): Ensure critical metadata is always in forensic dict
    for meta_key in ["errCode", "errName", "errMsg", "ok"]:
        if meta_key in harvested_error and meta_key not in forensic:
            forensic[meta_key] = harvested_error[meta_key]
        elif meta_key in attr and meta_key not in forensic:
            forensic[meta_key] = attr[meta_key]

    # Validation Fallback (v2.7.0): If we have a failure but no errName, use ERROR_CODE_MAP or errMsg
    if ("errCode" in forensic or "errMsg" in forensic) and "errName" not in forensic:
        code = forensic.get("errCode")
        if code and code in ERROR_CODE_MAP:
            forensic["errName"] = ERROR_CODE_MAP[code]
        else:
            forensic["errName"] = str(code or forensic.get("errMsg", "DirectError"))


    if "shardNames" in attr: forensic["shards"] = len(attr["shardNames"])
    mongot_wait = get_nested_value(entry, "attr.mongot.timeWaitingMillis")

    if mongot_wait: forensic["mongot_wait"] = mongot_wait
    
    # 🧼 Cache Pressure Harvesting (v2.7.14)
    # Prefer nested path, fallback to top-level or extracted forensic dict
    txn_bytes_dirty = get_nested_value(entry, "attr.storage.data.txnBytesDirty") or attr.get("txnBytesDirty") or forensic.get("txnBytesDirty")
    if txn_bytes_dirty is not None: forensic["txnBytesDirty"] = txn_bytes_dirty

    waits_ms = {}
    lock_micros = 0
    if "locks" in attr:
        for res, counts in attr.get("locks", {}).items():
            if isinstance(counts, dict):
                wait_obj = counts.get("timeAcquiringMicros", 0)
                if isinstance(wait_obj, dict):
                    lock_micros += sum(wait_obj.values())
                elif isinstance(wait_obj, (int, float)):
                    lock_micros += wait_obj
    
    if lock_micros > 0:
        val = round(lock_micros / 1000.0, 2)
        waits_ms["lock_wait"] = min(val, ms) if ms > 0 else val

    # 🕵️ Metric Consolidation (v2.3.1)
    # Removing redundant 'oplog_wait' to resolve Oplog Slot Wait duplication.
    # The source 'totalOplogSlotDurationMicros' is already captured in the forensic dict.

    s_read = (get_nested_value(entry, "attr.storage.data.timeReadingMicros") or 0) + (get_nested_value(entry, "attr.storage.index.timeReadingMicros") or 0)
    s_write = (get_nested_value(entry, "attr.storage.data.timeWritingMicros") or 0) + (attr.get("waitForWriteConcernDurationMillis") or 0) * 1000
    
    # 🧪 Write Bottleneck Unification (v2.7.13)
    # Include Oplog Slot Duration in storage wait for mutation ops (update, findAndModify, delete, insert)
    # This aligns the 'I/O Bound' diagnostic with realistic write-path concurrency pressure.
    oplog_wait = (attr.get("totalOplogSlotDurationMicros") or 0)
    
    if s_read > 0 or s_write > 0 or oplog_wait > 0: 
        val = round((s_read + s_write + oplog_wait) / 1000.0, 2)
        # 🧪 Wall-Clock Hardening (v2.3.1)
        # Cap visual components at total duration if they represent cumulative parallel effort.
        waits_ms["storage_wait"] = min(val, ms) if ms > 0 else val

    plan_ms = (attr.get("planningTimeMicros") or 0) / 1000.0
    if plan_ms > 0: waits_ms["planning"] = round(plan_ms, 2)
    
    queue_micros = get_nested_value(entry, "attr.queues.execution.totalTimeQueuedMicros") or 0
    if queue_micros > 0: 
        val = round(queue_micros / 1000.0, 2)
        waits_ms["queued"] = min(val, ms) if ms > 0 else val

    # 🚦 Replication Backpressure (v3.3.3)
    flow_control = attr.get("flowControlMillis") or 0
    if flow_control > 0:
        waits_ms["replication_wait"] = flow_control

    working_ms = attr.get("workingMillis")
    if working_ms is not None: waits_ms["execution"] = working_ms

    schema_cmd = attr.get("originatingCommand") or cmd_obj
    # 🧪 Unified Schema Routing (v2.3.5)
    # If the op is already resolved (e.g. tx-update), use it; Otherwise probe schema_cmd
    schema_op = op if op.startswith("tx-") or op in ["update", "insert", "delete"] else (next(iter(schema_cmd)) if schema_cmd else op)
    
    # 🕵️ Surgical Regex Grep (v2.7.4)
    # Catch $regex at any level of nesting within the command object via string audit
    cmd_str = str(cmd_obj)
    has_regex = "$regex" in cmd_str or "$regularExpression" in cmd_str

    # Forensic IP Extraction (v1.2.6)
    ip_raw = str(attr.get("remote") or attr.get("client") or "unknown")
    client_ip = str(ip_raw.split(":")[0] if ":" in ip_raw else ip_raw)

    metrics = {
        "ms": ms, "ns": ns, "op": op, "query_shape_hash": q_hash,
        "query_schema": extract_query_schema(schema_cmd, schema_op),
        "query_params": extract_query_params(schema_cmd, schema_op),
        "has_regex": has_regex,
        "plan_summary": attr.get("planSummary", "N/A"), "app_name": app_name,
        "user": user_id,
        "client_ip": client_ip,  # 🏺 Recovered from the current line
        "forensic": forensic, "waits_ms": waits_ms
    }
    if include_full_command: metrics["attr"] = attr
    return metrics

def is_system_query(ns: str, app: str = "", component: str = "", op: str = "") -> bool:
    """
    Surgically identifies if an event is internal system noise (v2.0.1 Refinement).
    Filters by Namespace, App Name, OR Component.
    """
    # 0. Transaction & Management Immunity (v2.7.4 Fix)
    # Never filter transactions or destructive admin commands as noise.
    if op == "transaction" or "drop" in str(op).lower() or "rename" in str(op).lower():
        return False

    # 1. Explicit System Namespace check (Priority 1)
    if ns and ns != "unknown":
        if any(ns.startswith(p) for p in SYSTEM_NAMESPACES) or ".system." in ns or ns == "oplog.rs":
            return True
            
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
    if ns and ns != "unknown":
        return False
        
    return False

def get_nested_value(obj: Any, path: str) -> Any:
    try:
        for part in path.split('.'):
            if isinstance(obj, dict): obj = obj.get(part)
            else: return None
        return obj
    except: return None
