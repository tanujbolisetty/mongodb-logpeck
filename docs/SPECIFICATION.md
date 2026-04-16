# 🐦 LogPeck — Core Technical Specification (v3.0.0)

> **Status**: Production Blueprint (High-Fidelity)  
> **Source of Truth**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py) & [analyzer.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/analyzer.py)  
> **Objective**: This document defines the deterministic machinery for MongoDB forensic log analysis. It provides the architectural parity required to reconstruct the engine from a black box.

---

## 🏗️ 1. Forensic Pipeline Architecture

LogPeck implements a **2-Pass Analytical Engine** designed to handle the temporal and structural fragmentation of MongoDB logs.

### 1.1 Pass 1: Light-Speed Context Sweep
Before analysis, the engine performs a linear scan to build the **MSH Matrix** (Metadata-Session-Hostname):
- **Identity Synthesis**: Captures event IDs `22943` (Accepted) and `22944` (Closed) to map `ctx` (Connection ID) to `appName`, `user`, `clientIP`, and `driver`.
- **Session Mapping**: Harvests `lsid` (Logical Session ID) to map transient operations to their originating business namespaces.
- **Cursor Registration**: Maps `cursorId` to its original `queryShapeHash` to ensure `getMore` operations inherit the forensic context of the parent query.

### 1.2 Pass 2: Operational Synthesis
The core engine iterates through the logs, leveraging the MSH Matrix for attribution:
- **Fingerprinting**: Operations are grouped by "Query Shapes" using the hierarchy: `queryShapeHash` > `planCacheShapeHash` > `queryHash`.
- **Identity Propagation**: If a log entry (e.g., a timeout) is missing context, the engine back-fills from the MSH Matrix using the connection ID fallback: `Session Map` → `Connection Registry` → `Heuristic Scan`.

---

## 🏛️ 2. The Forensic Metric Registry

Every metric harvested by LogPeck is bound to a deterministic source path in the MongoDB BSON log.

### 2.1 Primary Metric-to-Source Mapping

| Metric Identifier | BSON Source Path | User-Facing Label | Unit |
| :--- | :--- | :--- | :--- |
| `keysExamined` | `attr.keysExamined` | Keys Examined | count |
| `docsExamined` | `attr.docsExamined` | Docs Examined | count |
| `nreturned` | `attr.nreturned` | Docs Returned | count |
| `reslen` | `attr.reslen` | Result Size | bytes |
| `workingMillis` | `attr.workingMillis` | Execution Time | ms |
| `planning` | `attr.planningTimeMicros` | Planning Time | µs |
| `lock_wait` | `attr.locks.timeAcquiringMicros` | Lock Acquisition | ms |
| `storage_wait` | `timeReading` + `timeWriting` + `oplogSlot` | Unified Storage I/O | ms |
| `cpuNanos` | `attr.cpuNanos` | CPU Time | ns |
| `oplogSlot` | `attr.totalOplogSlotDurationMicros`| Oplog Slot Wait | µs |
| `globalQueue` | `attr.queues.execution.totalTimeQueuedMicros` | Global Queue Wait| µs |
| `txnBytesDirty` | `attr.storage.data.txnBytesDirty` | Cache Dirty | bytes |
| `mongot_wait` | `attr.mongot.timeWaitingMillis` | Atlas Search Wait | ms |

---

## 🚦 3. Diagnostic Routing & Filtering

The engine implements surgical logic to differentiate between business workloads and infrastructure noise.

### 🧬 Hierarchical Diagnostic Routing (v2.7.6)
LogPeck implements a **Hierarchy-First** routing policy to ensure high-fidelity analytical partitioning. Events are bucketed based on the following priority:

1.  **System Namespace**: Any event on `admin.*`, `config.*`, `local.*`, or `oplog.rs` is routed to **System Query Forensics**.
2.  **System Identity**: Any event originating from a known system application (e.g., `mongot`, `MongoDB Automation Agent`, `TTL Index`) or infrastructure operation (e.g., `Wire Spec Update`) is routed to **System Query Forensics**, even if it targets a business namespace.
3.  **Business Workload**: All other events (CRUD, Aggregations) targeting user-level namespaces are routed to **Slow Query Forensics** (Performance) or **Failure Forensics** (Errors).

---

### 🧬 CRUD Normalization (v2.7.6)
All business workload operations are normalized into a standard forensic vocabulary:
*   **Abbreviation Expansion**: `u`, `i`, `d` are expanded to `update`, `insert`, `delete`.
*   **Transaction Prefixing**: Operations part of a multi-document transaction (tagged with `txnNumber`) are prefixed with `tx-` (e.g., `tx-update`).
*   **Infrastructure Ops**: Background maintenance tasks are standardized (e.g., `OplogFetcher`).
 with 0ms duration are silenced entirely.
- **Event ID Blacklist**: Explicitly excludes redundant markers such as `51800` (Metadata), `21530` (Ping), and `51801` (System Stats) from slow query reports.

---

## 🔎 4. Specialized Forensic Harvesting

To handle complex operations, the engine implements targeted extraction logic and standardization for high-impact diagnostic categories.

### 4.0 Operation Normalization (v2.7.6)
To ensure analytical consistency across raw log formats (Command vs CRUD blocks):
- **Abbreviation Expansion**: Raw operations like `u`, `i`, and `d` are automatically expanded to `update`, `insert`, and `delete`.
- **Transactional Enrichment**: All CRUD and command operations occurring within a session context (identified by `txnNumber`) are prefixed with `tx-` (e.g., `tx-update`, `tx-find`).
- **Standardized Diagnostic Names**: Verbose internal signatures are simplified into diagnostic anchors (e.g., `MaxTimeMSExpired` -> `MaxTimeMS Timeout`).

### 4.1 Transaction Logic & Idle Forensic
- **Metric**: `timeInactiveMicros` is harvested from multi-statement transaction logs.
- **Normalization**: Normalized to `app_wait` (Application/Identity wait). This surfaces temporal gaps where the cluster was waiting for the application driver to send the next statement, differentiating application latency from database execution.

### 4.2 TTL Index Lifecycle
- **Discovery**: Detected via `PeriodicTask` identifiers and `TTL` maintenance markers.
- **Simplification**: Background cleanup tasks are unified under the "TTL Index" operation name and attributed to the "TTL Index" application identity, ensuring infrastructure maintenance noise is clearly partitioned.

### 4.3 getMore Continuity (Cursor Stitching)
- **Stitching**: Each `getmore` operation is stitched to its parent query via `cursorId`.
- **Forensic Inheritance**: By mapping the cursor ID to the original `queryShapeHash` in Pass 1, the engine ensures that paged results inherit the diagnostic tags (e.g., `🚨 COLLSCAN`) and metadata of the originating query.

### 4.4 Index Maintenance & Pressure
- **Pressure Markers**: The engine harvests `numYields` and `writeConflicts` for background and foreground index tasks.
- **Wait-Time Attribution**: `lock_wait` and `planning` time are aggressively attributed to index shapes to surface resource contention caused by index builds or schema mutations.

---

## 📈 5. Automated Forensic Heuristics

The engine evaluates query shapes against these clinical diagnostic rules:

| Rule ID | Threshold / Logic | Forensic Tag |
| :--- | :--- | :--- |
| **COLLSCAN** | `planSummary contains "COLLSCAN"` | `🚨 COLLSCAN` |
| **IO_BOUND** | `storage_wait > 0.3 * duration` | `💾 IO_BOUND` |
| **OPLOG_WAIT**| `oplog_wait > 0.3 * duration` | `🚨 OPLOG WAIT` |
| **CPU_BOUND** | `cpu_ns / 1M > 0.8 * duration` | `⚡ CPU_BOUND` |
| **UNINDEXED_SORT**| `plan contains "SORT" AND NOT "IXSCAN"` | `⚠️ UNINDEXED_SORT` |
| **LATENCY_CLIFF** | `max_ms > 10 * avg_ms` | `🚨 LATENCY_CLIFF` |
| **WRITE_CONFLICTS**| `writeConflicts > 0` | `🚨 Write Conflicts` |
| **SCAN_REDUCTION**| `keysExamined / nreturned > 10.0` | `⚠️ SCAN_REDUCTION` |

---

---

## 🚦 7. Error Resolution Engine (Truth Engine) (v2.7.8)

LogPeck implements an autonomous resolution layer to transform numeric MongoDB codes into human-readable diagnostics.

### 7.1 The ERROR_CODE_MAP
- **Inventory**: Contains 488 official MongoDB error codes (1 to 13436065).
- **Back-filling**: If a log entry contains an `errCode` but lacks an `errName`, the engine automatically populates the name from the internal registry during Pass 2 synthesis.

### 7.2 Severity-Based Forensic Promotion
To ensure 100% visibility into system instability:
- **Lethal Promotion**: Any log line with severity `F` (Fatal) or `E` (Error) is automatically promoted to the **Failure Forensics** tab.
- **Infrastructure Fallback**: Logs tagged with critical severity that lack a structured `attr` dictionary (e.g., startup crashes or invariant failures) are still captured. The engine injects an empty attribute block to ensure the failure is groupable and visible.

---

## 📊 8. Forensic UI Specification (v2.7.8)

The Failure Forensics dashboard is designed for rapid diagnostic triage.

### 8.1 High-Resolution Error Grid
To eliminate redundancy, error information is split into distinct columns:
- **CODE**: The numeric MongoDB error code (e.g., `50`).
- **DESCRIPTION**: The human-readable name (e.g., `MaxTimeMSExpired`) prepended with an icon (🚨 for Timeouts, ☢️ for Errors).

### 8.2 Redundancy Elimination
The UI automatically scrubs numeric suffixes from descriptions (e.g., `Operation Exceeded (50)` becomes `Operation Exceeded`) when the Code column is present, providing a concise, industrial-grade view.

---

## 📑 9. Documentation Lifecycle
- **Authoritative Registry**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py)
- **Synchronicity Gate**: All architectural modifications to the stitching, routing, or error resolution logic in `analyzer.py` **MUST** be reflected in this specification prior to version release.
