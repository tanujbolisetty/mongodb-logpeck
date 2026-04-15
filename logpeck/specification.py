"""
logpeck: specification.py
The centralized 'Truth Engine' for MongoDB forensic mapping.

This module serves as the authoritative source of truth for the entire LogPeck pipeline.
It defines the deterministic conversion of raw BSON/JSON attributes into standardized 
forensic metrics, ensuring parity between the CLI and the HTML Dashboard.
"""

# 🏛️ 1. Metric Display & Naming Contract
# ==============================================================================
# The human-readable labels used in both CLI and HTML reports.
# Modifying these keys requires an update to the SPECIFICATION.md.
FIELD_DISPLAY = {
    "keysExamined": "Keys Examined", 
    "docsExamined": "Docs Examined", 
    "nreturned": "Docs Returned",
    "totalReturnedUnits": "Total Returned Units",
    "reslen": "Result Size (Bytes)",
    "nMatched": "Docs Matched",
    "nModified": "Docs Modified",
    "ninserted": "Docs Inserted",
    "ndeleted": "Docs Deleted",
    "upserted": "Docs Upserted",
    "numYields": "Lock Yields",
    "workingMillis": "Execution (ms)",
    "planning": "Planning Time (µs)",
    "lock_wait": "Lock Acquisition (ms)",
    "storage_wait": "Storage I/O (ms)",
    "queued": "Execution Queue (ms)",
    "writeConflicts": "Write Conflicts",
    "flowControlMillis": "Flow Control Wait",
    "remoteOpWaitMillis": "Remote Op Wait",
    "prepareReadConflictMillis": "Read Conflict Wait",
    "timeActiveMicros": "Time Active (µs)",
    "timeInactiveMicros": "Time Inactive (µs)",
    "cpuNanos": "CPU Time (ns)",
    "waitForWriteConcernDurationMillis": "Write Concern Wait",
    "totalOplogSlotDurationMicros": "Oplog Slot Wait",
    "totalTimeQueuedMicros": "Global Queue Wait",
    "txnBytesDirty": "Cache Dirty (Bytes)",
    "shards": "Shards Involved",
    "mongot_wait": "Atlas Search Wait (ms)"
}

# 🧪 2. Metrology Standard (Units & Normalization)
# ==============================================================================
# Defines the canonical unit for each metric to ensure unambiguous dashboard display.
# The analyzer is responsible for scaling raw values to these target units.
METRIC_TYPE = {
    # Time Metrics (Standardized to ms/us/ns)
    "timeActiveMicros": "us", "timeInactiveMicros": "us", 
    "totalTimeQueuedMicros": "us", "totalOplogSlotDurationMicros": "us", 
    "lock_wait": "ms", "storage_wait": "ms", "planning": "ms", "execution": "ms", "queued": "ms",
    "cpuNanos": "ns",
    "ms": "ms", "durationMillis": "ms", "workingMillis": "ms",
    "waitForWriteConcernDurationMillis": "ms",
    "prepareReadConflictMillis": "ms", "flowControlMillis": "ms", "remoteOpWaitMillis": "ms",
    "mongot_wait": "ms",
    
    # Storage Metrics (Bytes)
    "reslen": "bytes", "txnBytesDirty": "bytes"
}

# 🕵️ 3. Forensic Source Mapping
# ==============================================================================
# Maps internal metrics back to their raw MongoDB BSON paths. 
# Used for 'Forensic Info' tooltips and architectural auditability.
METRIC_SOURCES = {
    "keysExamined": "attr.keysExamined",
    "docsExamined": "attr.docsExamined",
    "nreturned": "attr.nreturned",
    "totalReturnedUnits": "attr.nreturned (Alias for Docs Returned)",
    "nMatched": "attr.nMatched",
    "nModified": "attr.nModified",
    "ninserted": "attr.ninserted",
    "ndeleted": "attr.ndeleted",
    "upserted": "attr.upserted",
    "workingMillis": "attr.workingMillis (Raw execution time)",
    "numYields": "attr.numYields (Locks yielded during execution)",
    "planning": "attr.planningTimeMicros",
    "lock_wait": "attr.locks.timeAcquiringMicros",
    "storage_wait": "Cumulative I/O Effort (Total timeReading/timeWriting across all threads) + attr.waitForWriteConcernDurationMillis",
    "writeConflicts": "attr.writeConflicts",
    "flowControlMillis": "attr.flowControlMillis",
    "remoteOpWaitMillis": "attr.remoteOpWaitMillis",
    "prepareReadConflictMillis": "attr.prepareReadConflictMillis",
    "timeActiveMicros": "attr.timeActiveMicros",
    "timeInactiveMicros": "attr.timeInactiveMicros",
    "cpuNanos": "attr.cpuNanos",
    "waitForWriteConcernDurationMillis": "attr.waitForWriteConcernDurationMillis",
    "totalOplogSlotDurationMicros": "attr.totalOplogSlotDurationMicros",
    "totalTimeQueuedMicros": "attr.queues.execution.totalTimeQueuedMicros",
    "txnBytesDirty": "attr.storage.data.txnBytesDirty",
    "shards": "attr.shardNames (Length)",
    "mongot_wait": "attr.mongot.timeWaitingMillis"
}


# 🏺 4. System Governance (Exclusions & Denoising)
# ==============================================================================
# Registries used to filter internal MongoDB maintenance noise from performance reports.
SYSTEM_COMPONENTS = {
    "FTDC", "REPL_HB", "SHARD_HE", "NETWORK", "STORAGE", 
    "REPL", "RECOVERY", "INDEX", "SHARDING",
    "ACCESS", "CONTROL", "BALANCER", "JOURNAL", "ELECTION"
}

SYSTEM_NAMESPACES = {"admin.", "config.", "local.", "system."}

SYSTEM_APP_NAMES = {
    "Automation Agent", "Monitoring Agent", "CPS Module",
    "MongoDB Internal", "mongotune", "OplogFetcher",
    "MongoDB Automation Agent", "MongoDB Monitoring Module"
}

# ✂️ 5. Query Hygiene (Structural Pruning)
# ==============================================================================
# Fields removed during query normalization to isolate unique business logic patterns.
EXCLUDED_SYSTEM_FIELDS = {
    "lsid", "clusterTime", "signature", "txnNumber", "stmtId", "readConcern", 
    "writeConcern", "dbName", "config", "ordered", "autocommit", "$clusterTime",
    "help", "comment", "maxTimeMS", "hint", "shardNames", "allowDiskUse", 
    "needsMerge", "fromMongos", "mayContinue", "appName", "driver", "version",
    "os", "platform", "compression"
}

# Atlas Search keywords to prune to isolate business-level field names (e.g., 'orderId').
SEARCH_STRUCTURAL_FIELDS = {
    "must", "should", "filter", "mustNot", "range", "compound", "text", "query", "path", 
    "wildcard", "exists", "near", "geoWithin", "geoIntersects", "equals", "in", 
    "regex", "autocomplete", "moreLikeThis", "phrase", "queryString", "search",
    "index", "facet", "operator", "analyzer", "score", "fuzzy", "prefix", "term",
    "span", "highlight", "synonyms", "tokenOrder", "multi", "queryVector", "filter",
    "gte", "lte", "gt", "lt", "constant", "geoShape", "embeddedDocument",
    "o", "o2", "u", "i", "d", "diff", "upsert", "multi", "updates", "deletes", "CRUD"
}


# 🕵️ 6. System Health Routing (v2.7.0)
# ==============================================================================
# Patterns that trigger event promotion to the System Health tab.
SYSTEM_EVENT_IDENTIFIERS = [
    "replica set primary server change detected",
    "operation timed out while waiting to acquire connection",
    "deleted expired documents using index",
    "wiredtiger record store oplog processing finished",
    "dns resolution while connecting to peer was slow",
    "task finished",
    "ingress tls handshake complete",
    "wiredtiger record store oplog truncation finished",
    "wiredtiger opened",
    "wiredtiger closed",
    "wiredtiger message",
    "interrupted operation as its client disconnected",
    "logging invocation",
    "terminating via shutdown command",
    "rsm received error response",
    "dropping all pooled connections",
    "ending connection due to bad connection status",
    "connecting",
    "network interface redundant shutdown",
    "interrupted all currently",
    "socketexception",
    "connection timed out",
    "not writable primary",
    "interrupted due to step down",
    "interrupted at shutdown"
]

# 🧬 6.5 Lifecycle & Gossip Diagnostics (v2.7.4)
# ==============================================================================
# Patterns for high-velocity system events to be de-noised during sweep.
LIFECYCLE_EVENT_IDENTIFIERS = [
    "connection accepted",
    "connection ended",
    "session started",
    "session ended",
    "connection closed",
    "ending idle connection",
    "dropping unhealthy pooled connection"
]

GOSSIP_EVENT_IDENTIFIERS = [
    "wiredtiger message",
    "rsm monitoring host in expedited mode",
    "rescheduling the next replica set monitoring request",
    "rsm host was added to the topology",
    "failed to gather storage statistics",
    "initial creation method for pre-images",
    "clearing serverless operation lock registry",
    "completed initialization of pre-image",
    "rsm not processing response",
    "failed to handle request",
    "failed to refresh key cache",
    "pool reset",
    "rsm error"
]

# 🧬 7. Simplified Event Logic
# ==============================================================================
# Normalizes verbose system logs into clean, diagnostic categories.
SIMPLIFIED_OPS = {
    "deleted expired documents using index": "TTL Index",
    "wiredtiger record store oplog processing finished": "Oplog Processing",
    "wiredtiger record store oplog truncation finished": "Oplog Truncation",
    "replica set primary server change detected": "Replica Set Change",
    "dns resolution while connecting to peer was slow": "DNS Delay",
    "ingress tls handshake complete": "TLS Handshake",
    "operation timed out while waiting to acquire connection": "Conn Wait Timeout",
    "MaxTimeMSExpired": "MaxTimeMS Timeout",
    "operation exceeded time limit": "MaxTimeMS Timeout",
    "client's executor exceeded time limit": "MaxTimeMS Timeout",
    "deadline exceeded": "MaxTimeMS Timeout",
    "wiredtiger opened": "Storage Engine Open",
    "wiredtiger closed": "Storage Engine Close",
    "wiredtiger message": "Storage Engine Message",
    "interrupted operation as its client disconnected": "Conn Disconnected",
    "logging invocation": "Diagnostic Audit",
    "terminating via shutdown command": "Shutdown Process",
    "rsm received error response": "RSM Error",
    "dropping all pooled connections": "Pool Reset",
    "ending connection due to bad connection status": "Conn Status Error",
    "connecting": "Conn Initiation",
    "network interface redundant shutdown": "Network Shutdown",
    "interrupted all currently": "Force Disconnect",
    "socketexception": "Network Interrupt",
    "connection timed out": "Network Timeout",
    "not writable primary": "Replication Shift",
    "interrupted due to step down": "Step Down Interrupt",
    "interrupted at shutdown": "Shutdown Interrupt"
}

# 🐢 8. Performance Efficiency Thresholds
# ==============================================================================
THRESHOLD_SCAN_RATIO = 10.0  # Normalized limit for 'SCAN_REDUCTION' tag.
THRESHOLD_SLOW_MS = 100      # Baseline for performance profiling.
