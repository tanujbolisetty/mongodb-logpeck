import json
import re
import hashlib
from typing import Dict, Any, List, Optional, Set

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
    if depth > 15 or not obj: return
    if isinstance(obj, dict):
        # 🧪 Atlas Search Path Extraction (v1.1.50)
        # If we find a "path" field, its value is the actual business field name we want to harvest.
        if "path" in obj and isinstance(obj["path"], str):
            field_name = obj["path"]
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
    COMMON_COMMAND_KEYS = ["find", "update", "delete", "insert", "aggregate", "count", "distinct", "findAndModify", "getMore"]
    
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
    
    from .specification import SIMPLIFIED_OPS
    for pattern, simple_name in SIMPLIFIED_OPS.items():
        if pattern.lower() in str(raw_op).lower() or (msg and pattern.lower() in msg.lower()):
            op = simple_name # Preserve case from specification
            # 🕵️ Transaction Detection (v2.3.5)
            # Check top-level attr, CRUD block, and nested parameters (v2.7.2 Fix)
            params = attr.get("parameters", {})
            is_tx = str(ns).endswith(".$cmd") or "txnNumber" in attr or (isinstance(crud, dict) and "txnNumber" in crud) or "txnNumber" in params
            # Ensure namespace is resolved for the result set (v1.3.16)
            if (is_tx or not ns or ns == "unknown") and cmd_obj:
               for k in COMMON_COMMAND_KEYS:
                   if k in cmd_obj and isinstance(cmd_obj[k], str):
                       db_f = str(ns).split(".")[0] if ns and "." in str(ns) else "admin"
                       db = attr.get("db") or attr.get("$db") or cmd_obj.get("$db") or attr.get("dbName") or db_f
                       ns = f"{db}.{cmd_obj[k]}" if "." not in str(cmd_obj[k]) else cmd_obj[k]
                       break
            return op, ns

    op = str(raw_op).lower()
    # 🕵️ Transaction Detection: Check for $cmd namespace OR presence of transaction metadata (v2.3.5)
    # Check top-level attr, CRUD block, and nested parameters (v2.7.2 Fix)
    params = attr.get("parameters", {})
    is_tx = str(ns).endswith(".$cmd") or "txnNumber" in attr or (isinstance(crud, dict) and "txnNumber" in crud) or "txnNumber" in params

    if is_tx or ns == "unknown" or not ns:
        coll = None
        for k in COMMON_COMMAND_KEYS:
            if k in cmd_obj and isinstance(cmd_obj[k], str):
                coll = cmd_obj[k]
                break
        
        if not coll and op == "getmore" and "collection" in cmd_obj:
            coll = cmd_obj["collection"]
        
        if isinstance(coll, str):
            # Resolve DB: Check cmd_obj, top-level attr, or fallback to the prefix of the $cmd namespace
            db_fallback = str(ns).split(".")[0] if ns and "." in str(ns) else "admin"
            db = attr.get("db") or attr.get("$db") or cmd_obj.get("$db") or attr.get("dbName") or db_fallback
            ns = f"{db}.{coll}" if "." not in str(coll) else coll
    
    if is_tx and op in ["update", "insert", "delete", "findandmodify"]:
        op = f"tx-{op}"
    
    # 🕵️ Heuristic Fallback for Errors/Timeouts (v1.3.5)
    if not ns or ns == "unknown" or str(ns).endswith(".$cmd"):
        # Check attr for 'namespace' (common in system health logs like TTL)
        ns = attr.get("namespace") or ns
        
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

def extract_log_metrics(entry: Dict[str, Any], include_full_command: bool = False) -> Optional[Dict[str, Any]]:
    """
    Surgically extracts forensic metrics from a raw MongoDB log entry.
    
    Handles:
    - Workload Duration (ms)
    - Wait Time Normalization (Storage, Locks, Queue, Replication)
    - Forensic Counters (keysExamined, docsExamined, etc.)
    - Query Schema & Shape Hashing
    """
    attr = entry.get("attr")
    if not isinstance(attr, dict):
        return None
    # Handle both standard command logs and transactional CRUD blocks (v2.3.5)
    cmd_obj = attr.get("command") or attr.get("CRUD") or {}
    msg = entry.get("msg", "unknown")
    ns_raw = attr.get("ns") or entry.get("ns") or "unknown"
    
    op, ns = detect_op_and_ns(attr, cmd_obj, msg, ns_raw)
    
    # Deep Identity Harvesting (v1.3.16)
    # Prefer top-level attr, but fallback to originatingCommand for cursors
    orig_cmd = attr.get("originatingCommand", {})
    app_name = str(attr.get("appName") or orig_cmd.get("appName") or "unknown")
    user_id = str(attr.get("user") or orig_cmd.get("user") or "unknown")

    # Shape Hash Hardening (v1.1.49)
    # Prefer MongoDB 8.0 queryShapeHash > planCacheShapeHash > queryHash
    # For getMore, pivot to originatingCommand if top-level hash is missing
    shape_hash = attr.get("queryShapeHash") or attr.get("planCacheShapeHash") or attr.get("queryHash")
    if not shape_hash and op == "getmore" and "originatingCommand" in attr:
        orig = attr["originatingCommand"]
        shape_hash = orig.get("queryShapeHash") or orig.get("planCacheShapeHash") or orig.get("queryHash")
    
    q_hash = shape_hash or "N/A"
    ms = attr.get("durationMillis") or attr.get("durationMS") or 0
    if not ms and "parameters" in attr: ms = attr["parameters"].get("durationMillis", 0)

    # 🕵️ Senior Forensic Error Harvesting (v2.7.0)
    # Recursively harvest error metadata from nested objects (e.g. attr.error)
    forensic = {}
    harvested_error = {}
    err_obj = attr.get("error")
    if isinstance(err_obj, dict):
        harvested_error["errCode"] = err_obj.get("code")
        harvested_error["errName"] = err_obj.get("codeName")
        harvested_error["errMsg"] = err_obj.get("errmsg")
    elif isinstance(err_obj, str):
        harvested_error["errMsg"] = err_obj

    clinical_fields = [
        "keysExamined", "docsExamined", "nreturned", "ninserted", "keysInserted", "ndeleted", "keysDeleted",
        "nMatched", "nModified", "keysUpdated", "upserted", 
        "numYields", "reslen", "timeActiveMicros", "timeInactiveMicros", "totalReturnedUnits", 
        "nStages", "writeConflicts", "prepareReadConflictMillis", "flowControlMillis", "remoteOpWaitMillis",
        "cpuNanos", "waitForWriteConcernDurationMillis", "totalOplogSlotDurationMicros", "totalTimeQueuedMicros",
        "errCode", "errName", "errMsg", "ok", "workingMillis"
    ]
    for k in clinical_fields:
        val = attr.get(k) or harvested_error.get(k)
        if val is not None: forensic[k] = val
    
    # Validation Fallback (v2.7.0): If we have a failure but no errName, use errMsg as the anchor.
    if ("errCode" in forensic or "errMsg" in forensic) and "errName" not in forensic:
        forensic["errName"] = str(forensic.get("errCode") or forensic.get("errMsg", "DirectError"))
    
    # 🕵️ Deep Queue Harvesting (v2.6.11): Extract nested execution metrics if missing from top-level attr
    if "totalTimeQueuedMicros" not in forensic:
        q_wait = get_nested_value(entry, "attr.queues.execution.totalTimeQueuedMicros")
        if q_wait is not None: forensic["totalTimeQueuedMicros"] = q_wait
    
    if "shardNames" in attr: forensic["shards"] = len(attr["shardNames"])
    mongot_wait = get_nested_value(entry, "attr.mongot.timeWaitingMillis")
    if mongot_wait: forensic["mongot_wait"] = mongot_wait
    
    txn_bytes_dirty = get_nested_value(entry, "attr.storage.data.txnBytesDirty")
    if txn_bytes_dirty is not None: forensic["txnBytesDirty"] = txn_bytes_dirty

    waits_ms = {}
    lock_micros = 0
    locks = attr.get("locks", {})
    if isinstance(locks, dict):
        for resource, counts in locks.items():
            if isinstance(counts, dict):
                wait_obj = counts.get("timeAcquiringMicros", {})
                if isinstance(wait_obj, dict): lock_micros += sum(wait_obj.values())
    if lock_micros > 0:
        val = round(lock_micros / 1000.0, 2)
        waits_ms["lock_wait"] = min(val, ms) if ms > 0 else val

    # 🕵️ Metric Consolidation (v2.3.1)
    # Removing redundant 'oplog_wait' to resolve Oplog Slot Wait duplication.
    # The source 'totalOplogSlotDurationMicros' is already captured in the forensic dict.

    s_read = (get_nested_value(entry, "attr.storage.data.timeReadingMicros") or 0) + (get_nested_value(entry, "attr.storage.index.timeReadingMicros") or 0)
    s_write = (get_nested_value(entry, "attr.storage.data.timeWritingMicros") or 0) + (attr.get("waitForWriteConcernDurationMillis") or 0) * 1000
    if s_read > 0 or s_write > 0: 
        val = round((s_read + s_write) / 1000.0, 2)
        # 🧪 Wall-Clock Hardening (v2.3.1)
        # Cap visual components at total duration if they represent cumulative parallel effort.
        waits_ms["storage_wait"] = min(val, ms) if ms > 0 else val

    plan_ms = (attr.get("planningTimeMicros") or 0) / 1000.0
    if plan_ms > 0: waits_ms["planning"] = round(plan_ms, 2)
    
    queue_micros = get_nested_value(entry, "attr.queues.execution.totalTimeQueuedMicros") or 0
    if queue_micros > 0: 
        val = round(queue_micros / 1000.0, 2)
        waits_ms["queued"] = min(val, ms) if ms > 0 else val

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

    # 1. Component check
    if str(component).upper() in SYSTEM_COMPONENTS:
        return True
    
    # 2. App Name check
    if any(str(app).startswith(s) for s in SYSTEM_APP_NAMES):
        return True
    
    # 3. Namespace check
    if not ns or ns == "unknown":
        return False # Forensic default: preserve unknown for Pass 2 context stitching
        
    return any(ns.startswith(p) for p in SYSTEM_NAMESPACES)

def get_nested_value(obj: Any, path: str) -> Any:
    try:
        for part in path.split('.'):
            if isinstance(obj, dict): obj = obj.get(part)
            else: return None
        return obj
    except: return None
