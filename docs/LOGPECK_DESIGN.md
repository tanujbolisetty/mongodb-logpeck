# 🐦 LogPeck — Core Design Specification (v4.1.5)

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
| `lock_wait` | `SUM(attr.locks.*.timeAcquiringMicros)` | Lock Contention | ms |
| `storage_wait` | `read` + `write` + `oplogSlot` | Storage Effort | ms |
| `cpuNanos` | `attr.cpuNanos` | CPU Time | ns |
| `queue_wait` | `attr.totalTimeQueuedMicros` | Ticket Queue | ms |
| `replication_wait`| `attr.flowControlMillis` | Replication Throttling | ms |
| `txnBytesDirty` | `attr.storage.data.txnBytesDirty` | Cache Dirty | bytes |
| `writeConflicts` | `attr.writeConflicts` | Write Conflicts | count |

---

## 🚦 3. Diagnostic Routing & Filtering

The engine implements surgical logic to differentiate between business workloads and infrastructure noise.

### 3.1 Tab Partitioning Strategy (v3.3.4 Final Release)
LogPeck partitions query shapes into three dedicated diagnostic channels based on a strict priority hierarchy:

| Priority | Tab Category | Routing Criteria |
| :--- | :--- | :--- |
| **1 (Peak)** | **🚨 Failure Forensics** | Any operation containing `errCode`, `code`, or `MaxTimeMSExpired`. **Failures always win**; infrastructure errors are routed here, never buried in System. |
| **2 (High)** | **🐢 Business Workload** | All successful user-level operations targeting business namespaces. This is the 2nd tab for primary developer visibility. |
| **3 (Med)** | **🛠️ System Query** | Operations targeting internal namespaces (`admin`, `local`, `config`) or identified as system maintenance (TTL, Heartbeats). |

### 3.2 AAS Load % Math (Global Synchronization)
To ensure proportionality, the **AAS Load %** (green progress bar) is calculated via a global denominator:
- **Formula**: `(Shape_Active_MS / Global_Active_MS) * 100`
- **Denominator**: `Global_Active_MS = SUM(Active_Time_Business) + SUM(Active_Time_System) + SUM(Active_Time_Failures)`.
- **Result**: A 10% load bar in "Business" represents the same physical weight as a 10% bar in "System".

### 3.2 Hierarchical Diagnostic Routing (v2.7.6)
Events are bucketed using the priority defined in Section 3.1 to ensure that infrastructure noise never masks workload performance issues or critical failures.

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

## 🎨 6. Clinical Intelligence & Color Philosophy (v4.3.0)

LogPeck implements a visual diagnostic language to differentiate between structural query pathogens and environmental resource victims.

### 6.1 The Forensic Color Philosophy
Colors have context-specific meanings to prevent "False Health" interpretations:

| Context | Green (🟢) | Red (🔴) |
| :--- | :--- | :--- |
| **Metric Cards** | **True Health**. Optimal values (e.g., Scan Efficiency = 1.1). | **Pathogens**. Structural waste (e.g., COLLSCAN). |
| **Latency Tiers** | **Fastest of the Slow**. Queries between 100ms - 500ms. | **Latency Cliff**. Queries exceeding 5s - 10s. |
| **Clinical Status**| **OPTIMAL**. Structurally perfect query shape. | **POISONED**. Critical logic failure detected. |

### 6.2 Clinical Threshold Matrix
The engine uses these deterministic guardrails to assign severity tiers to clinical insights:

| Metric | Healthy (🟢) | Warning (🟡) | Critical (🔴) |
| :--- | :--- | :--- | :--- |
| **Scan Efficiency** | `< 20.0` | `20 - 500` | `> 500` |
| **Index Selectivity** | `< 5.0` | `5 - 50` | `> 50` |
| **Fetch Amplif.** | `≤ 1.1` | `1.1 - 3.0` | `> 3.0` |
| **Storage Intensity** | `< 30%` | `30% - 70%` | `> 70%` |
| **Index Amplif.** | `< 5.0` | `5.0 - 10.0` | `> 10.0` |
| **Cache Pressure** | `< 100MB` | `100MB - 500MB` | `> 500MB` |
| **Repl. Backpressure**| `< 50ms` | `50ms - 200ms` | `> 200ms` |

### 6.3 Diagnostic Taxonomy (Symptom Prefixing)
To align Developers and SREs, diagnostic tags are prefixed based on their domain of influence:
- **`[TRACE]` (Structural)**: Pathogens rooted in code, schema, or indexing. (e.g., `[TRACE] COLLSCAN`). **Focus: Developer/DBA.**
- **`[WORKLOAD]` (Environmental)**: Pathogens rooted in resource saturation or cluster health. (e.g., `[WORKLOAD] OPLOG_WAIT`). **Focus: SRE/Platform.**

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
- **Synchronicity Gate**: All architectural modifications to the stitching, routing, or error resolution logic in `analyzer.py` **MUST** be reflected in this design documentation (LOGPECK_DESIGN.md) prior to version release.

---

## 🧪 10. Forensic Hybrid Model (v3.3.7)
The engine utilizes a **Hybrid Anchor** philosophy to maximize forensic signal:
- **Efficiency Metrics (Sample-based)**: Scan Efficiency, Index Selectivity, and Fetch Amplification are calculated from the **Slowest Payload** (Worst-case scenario) to explain why a specific query took the maximum time.
- **Economic Metrics (Shape-based)**: Workload Amplification is calculated as an **Aggregate Average** across the entire query shape to represent the total I/O tax of the indexing strategy.

### 10.1 Workload-Agnostic Denominator (Forensic Impact)
All ratios use a **Success Index (Impact Sum)** as the denominator tailored to the anchor:
- **Sample Impact**: `nreturned + nMatched + ninserted + ndeleted + upserted` (Worst Sample run).
- **Shape Impact**: `Total(nreturned) + Total(nMatched) + ...` (Aggregated workload).

### 10.2 Adaptive Visibility Logic
To reduce noise, the dashboard dynamically hides tiles that are irrelevant to the specific operation's workload:
- **Scan/Selectivity/Fetch**: Only visible if `docsExamined` or `keysExamined` > 0 (Read signal).
- **Workload Amplification**: Only visible if `doc_mutations` > 0 (Write signal).
- **Healthy Fallback**: Business queries with zero overhead show a **✅ CLINICAL STATUS: OPTIMAL** badge.

| Metric | Anchor | Formula | Clinical Signal (Interpretation) |
| :--- | :--- | :--- | :--- |
| **Scan Efficiency** | Worst Sample | `docsExamined / Impact` | Values > 1000 signal a critical collection scan on the slow sample. |
| **Index Selectivity** | Worst Sample | `keysExamined / Impact` | Measures index specificity of the bottleneck sample. |
| **Fetch Amplification** | Worst Sample | `docsExamined / keysExamined` | Values > 2 indicate 'Document Bloat' in the slow run. |
| **Workload Amplification**| Shape Aggregate | `Sum(Key_Mutations) / Sum(Doc_Mutations)` | Measures total index overhead / over-indexing for the shape. |
| **Cache Pressure** | Worst Sample | `txnBytesDirty` | Measures WiredTiger cache bloat (>500MB is high risk). |
| **Replication Backpressure**| Worst Sample | `FlowControl + WriteConcernWait` | Flags minority-ack lag or secondary saturation. |
| **Storage Intensity** | Worst Sample | `(timeReading / totalTime) * 100` | Percentage of time spent on disk I/O. |
| **Search Latency** | Worst Sample | `mongot_wait` | Measures Atlas Search backend (Lucene) bottleneck. |

---

## 🚦 11. Clinical Wait Latency Hierarchy (v3.3.2)
To prevent misdiagnosis, the engine distinguishes between three distinct "wait" concepts that occur at different stages of the operation lifecycle.

### 11.1 The Diagnostic Boundaries
| Concept | Technical Boundary | Clinical Signal |
| :--- | :--- | :--- |
| **🎫 Ticket Queue** | Admission Control | Waiting for an execution ticket. Signal: Global concurrency saturation. |
| **🔐 Lock Contention** | Resource Acquisition | Waiting for a collection or document lock. Signal: Logical/Physical resource contention. |
| **🚦 Replication Throttling** | Flow Control | Primary is waiting for secondaries to catch up. Signal: Replica lag / Write backpressure. |

### 11.2 Storage Effort Derivation
The `Storage Effort` metric is a synthetic derivation designed to summarize physical storage pressure.
- **Formula**: `read + write + oplog/cache stalls`
- **Definition**: Time spent interacting with the physical disk subsystem or waiting for cache space.

---

## 🚦 12. Diagnostic Attribution Strategy (v4.1.6)

LogPeck implements a **Hybrid Rule Engine** to ensure that diagnostic badges provide accurate forensic signals without infrastructure noise. This strategy differentiates between transient environmental pressures and permanent structural pathologies.

### 12.1 Evaluation Domains

| Domain | Label Prefix | Evaluation Anchor | Metrics | Clinical Signal |
| :--- | :--- | :--- | :--- | :--- |
| **Environmental** | None | **Shape Aggregate** | I/O Bound, Queue Wait, Lock Wait | Chronic workload saturation. |
| **Structural** | `[TRACE]` | **Worst-Case Sample** | Cache Poisoning, Index Amplification, Inefficient Index | Pathological code payload. |

### 12.2 Architectural Rationale: Victim vs. Pathogen
The fundamental purpose of this split is to distinguish between high-latency events caused by the cluster environment and those caused by the application logic itself.

1.  **Workload-Centric (Environmental)**: These metrics are often victims of "noisy neighbor" effects or global resource contention. By evaluating these against the **Shape Aggregate**, we ensure a badge only triggers if the query pattern is *consistently* causing pressure. This prevents a well-tuned query from being incorrectly flagged because it was unlucky enough to be running during a backup.
2.  **Trace-Centric (Structural)**: These metrics represent architectural failures (e.g., a single document update generating 132,000 index keys). These are **Diseased Payloads**. If the application is structurally capable of this behavior once, it is dangerous. Evaluating these against the **Worst-Case Sample [WC]** ensures these "cache nukes" are flagged even if they occur intermittently.

### 12.3 Implementation Gate
The [analyzer.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/analyzer.py) must explicitly map these metrics to the correct evaluation domain before the Rules Engine executes.
