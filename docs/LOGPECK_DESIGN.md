# 🐦 LogPeck — Core Design Specification

> **Status**: Production Blueprint (High-Fidelity)  
> **Source of Truth**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py) & [analyzer.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/analyzer.py)  
> **Objective**: This document defines the deterministic machinery for MongoDB forensic log analysis. It provides the architectural parity required to reconstruct the engine from a black box.

---


## 🏗️ 1. Forensic Pipeline Architecture

LogPeck implements a **2-Pass Analytical Engine** designed to handle the temporal and structural fragmentation of MongoDB logs.

### 1.1 Pass 1: Light-Speed Context Sweep
Before analysis, the engine performs a linear scan to build the **MSH Matrix** (Metadata-Session-Hostname):
- **Identity Synthesis**: Captures lifecycle markers (e.g., `Connection accepted`, `client metadata`) to map `ctx` (Connection ID) to `appName`, `user`, `clientIP`, and `driver`.
- **Session Mapping**: Harvests `lsid` (Logical Session ID) to map transient operations to their originating business namespaces.
- **Cursor Registration**: Maps `cursorId` to its original `queryShapeHash` to ensure `getMore` operations inherit the forensic context of the parent query.

### 1.2 Pass 2: Operational Synthesis
The core engine iterates through the logs, leveraging the MSH Matrix for attribution:
- **Fingerprinting**: Operations are grouped by "Query Shapes" using the hierarchy: `queryShapeHash` > `planCacheShapeHash` > `queryHash`.
- **Identity Propagation**: If a log entry (e.g., a timeout) is missing context, the engine back-fills from the MSH Matrix using the connection ID fallback: `Session Map` → `Connection Registry` → `Heuristic Scan`.

---

## 🔬 2. The Log Parsing Engine (The Minute Details)

LogPeck utilizes a multi-layered regex and JSON parser to handle the structural evolution of MongoDB logs (v4.2 to v7.0+).

### 2.1 The Core Regex Matrix
While the engine prefers the `BSON` attribute parser, it utilizes these surgical regexes for high-volume identity harvesting:

| Target | Regex Pattern | Purpose |
| :--- | :--- | :--- |
| **Connection ID** | `conn(\d+)` | Extracts the numeric `ctx` from unstructured string headers. |
| **Namespace** | `([\w.-]+\.\$?\w+)` | Extracts the `DB.Collection` anchor when the `ns` attribute is missing. |
| **Duration** | `(\d+)ms` | Captures wall-clock latency for non-standard log events. |
| **Join Pattern** | `$lookup` | Blind search for relational join stages in the command block. |
| **Oplog Source** | `oplog.rs` | Special handling for high-volume replication gossip. |

### 2.2 Attribute Sanitization Hierarchy
To prevent "Pathological Attribute Bloat," the engine sanitizes the `attr` dictionary in this exact priority order:
1. **Extraction**: Pulls numeric metrics into the `stats` bucket.
2. **Standardization**: Forces all durations into milliseconds (ms)..
3. **Blacklisting**: Removes high-volume, low-signal keys (e.g., `appName` in every line) before storing forensic payloads.
4. **Key Flattening**: Collapses `attr.locks` sub-trees into the flat `lock_wait` summary.

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
| `queryHash` | `attr.queryHash` | Query Hash | hex |
| `planCacheKey` | `attr.planCacheKey` | Plan Cache Key | hex |

---

## 🚦 3. Diagnostic Routing & Filtering

The engine implements surgical logic to differentiate between business workloads and infrastructure noise.

### 3.1 Tab Partitioning Strategy
LogPeck partitions query shapes into three dedicated diagnostic channels based on a strict priority hierarchy:

| Priority | Tab Category | Routing Criteria |
| :--- | :--- | :--- |
| **1 (Peak)** | **🚨 Failure Forensics** | Any operation containing `errCode`, `code`, or `MaxTimeMSExpired`. Also promotes any log with Severity `WARN`, `ERROR`, or `FATAL`. **Failures always win**; infrastructure errors are routed here. Includes a dedicated table for headless/orphan network anomalies with deep-harvested numerical codes. **Mandatory 'LAST SEEN' column added for temporal context.** |
| **2 (High)** | **🐢 Business Workload** | All successful user-level operations targeting business namespaces. This is the 2nd tab for primary developer visibility. **Mandatory 'LAST SEEN' column and join detection tagging.** |
| **3 (Med)** | **🛠️ System Query** | Operations targeting internal namespaces (`admin`, `local`, `config`) or identified as system maintenance (TTL, Heartbeats). **Mandatory 'LAST SEEN' column.** |

### 3.2 AAS Load % Math (Global Synchronization)
To ensure proportionality, the **AAS Load %** (green progress bar) is calculated via a global denominator:
- **Formula**: `(Shape_Active_MS / Global_Active_MS) * 100`
- **Denominator**: `Global_Active_MS = SUM(Active_Time_Business) + SUM(Active_Time_System) + SUM(Active_Time_Failures)`.
- **Result**: A 10% load bar in "Business" represents the same physical weight as a 10% bar in "System".

### 3.2 Hierarchical Diagnostic Routing
Events are bucketed using the priority defined in Section 3.1 to ensure that infrastructure noise never masks workload performance issues or critical failures.

---

### 🧬 CRUD Normalization
All business workload operations are normalized into a standard forensic vocabulary:
*   **Abbreviation Expansion**: `u`, `i`, `d` are expanded to `update`, `insert`, `delete`.
*   **Transaction Prefixing**: Operations part of a multi-document transaction (tagged with `txnNumber`) are prefixed with `tx-` (e.g., `tx-update`).
*   **Infrastructure Ops**: Background maintenance tasks are standardized (e.g., `OplogFetcher`).
 with 0ms duration are silenced entirely.
- **Event ID Blacklist**: Explicitly excludes redundant markers such as `51800` (Metadata), `21530` (Ping), and `51801` (System Stats) from slow query reports.

---

## 🔎 4. Specialized Forensic Harvesting

To handle complex operations, the engine implements targeted extraction logic and standardization for high-impact diagnostic categories.

### 4.0 Operation Normalization
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

## 🧬 5. The MSH Matrix State Machine (Identity Stitching)

The **Metadata-Session-Hostname (MSH)** matrix is the "Memory" of the forensic engine. It allows LogPeck to attribute a slow query occurring at 12:00:00 to an application connection that was established at 09:00:00.

### 5.1 State Transitions
The matrix tracks three distinct life-stages of a connection:

1. **STAGE 1: Accepted (`Connection accepted`)**
   - Registers the `ctx` (e.g., `conn123`) and maps it to the `remote` client IP.
   - Status: *Anonymous Connection*.

2. **STAGE 2: Authentication (`Successfully authenticated`)**
   - Overlays the `user` and `mechanisms` onto the `ctx`.
   - Status: *Identified Principal*.

3. **STAGE 3: Metadata Handshake (`client metadata`)**
   - Attaches the `appName` and `driver` version strings.
   - Status: *Full Forensic Identity*.

### 5.2 Inheritance Logic
When a "Business Query" (Pass 2) arrives with only a `ctx`, the engine recursively crawls the MSH Matrix:
- **Direct Match**: Returns the cached identity.
- **Session Fallback**: If `lsid` is present, it attempts to bridge the identity from other active connections in the same session.
- **Global Inferred**: If all else fails, it tags the operation as `unknown` but preserves the `remote` IP harvested in Stage 1.

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

## 🎨 6. Clinical Intelligence & Color Philosophy

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

## 🚦 7. Error Resolution Engine (Truth Engine)

LogPeck implements an autonomous resolution layer to transform numeric MongoDB codes into human-readable diagnostics.

### 7.1 The ERROR_CODE_MAP
- **Inventory**: Contains 488 official MongoDB error codes (1 to 13436065).
- **Back-filling**: If a log entry contains an `errCode` but lacks an `errName`, the engine automatically populates the name from the internal registry during Pass 2 synthesis.

### 7.3 Surgical Error Triage (Hardened)
To maintain a high signal-to-noise ratio in the **Failure Forensics** dashboard, the engine implements a surgical promotion protocol:
- **Default Promotion**: Events with Severity `W` (Warning), `E` (Error), or `F` (Fatal) are automatically promoted.
- **Operational Failure Recovery**: Logs with `ok: 0` or explicit error codes (e.g., `E11000`) are promoted even if logged at Severity `I` (Informational).
- **Noise Suppression Blacklist**: Known infrastructure patterns (e.g., "reauthenticate", "JWK Set", "certificate expiration") are explicitly silenced to prevent forensic clutter.
- **Forensic Payload Guard**: System Error Patterns are only captured if they contain valid diagnostic metadata (`attr` fields) or are non-informational. This prevents "empty forensics" entries in the UI.
- **Result**: High-volume infrastructure noise is suppressed while ensuring 100% visibility into genuine application failures and authorization errors.

---

## 📊 8. Forensic UI Specification

The Failure Forensics dashboard is designed for rapid diagnostic triage.

### 13.1 Failure Forensic Columns
The "Failure Forensics" tab is optimized for signal-to-noise ratio by consolidating multiple views into a three-part diagnostic hierarchy:

1.  **Executive Failure Summary**: Aggregated by `Error Code`.
2.  **Query Shape Failure Analysis**: Aggregated by `Query Shape` + `Error Code`.
3.  **System & Network Errors**: Raw infrastructure anomalies.

The "Error Event Timeline" (previously Section 2) has been deprecated in to prevent UI clutter. Its critical chronological signal has been merged into the Query Shape table.

#### 13.1.1 Query Shape Failure Analysis Table
| Column | Width | Description |
| :--- | :--- | :--- |
| **CODE** | 80px | MongoDB Error Code (e.g., 50, 11000). |
| **ERROR / DESCRIPTION** | 250px | Human-readable error name or pattern. |
| **COUNT** | 70px | Total occurrences of this shape/error pair. |
| **SHAPE HASH** | 150px | Fingerprint of the query structure. |
| **NAMESPACE** | 220px | Database and Collection target. |
| **CONTEXT / APP** | 200px | Originating application or client context. |
| **LAST SEEN** | 100px | HH:MM:SS of the most recent occurrence. |

### 8.2 Redundancy Elimination
The UI automatically scrubs numeric suffixes from descriptions (e.g., `Operation Exceeded (50)` becomes `Operation Exceeded`) when the Code column is present, providing a concise, industrial-grade view.

---

## 📑 9. Documentation Lifecycle
- **Authoritative Registry**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py)
- **Synchronicity Gate**: All architectural modifications to the stitching, routing, or error resolution logic in `analyzer.py` **MUST** be reflected in this design documentation (LOGPECK_DESIGN.md) prior to version release.

---

## 🧪 10. Forensic Hybrid Model
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

## 🚦 11. Clinical Wait Latency Hierarchy
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

## 🚦 12. Diagnostic Attribution Strategy

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

---

## 🖥️ 13. Dashboard UI Specification

> **Source of Truth**: [reporter.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/reporter.py)
> **Purpose**: This section defines every visual element of the HTML dashboard. Any modification to the UI **MUST** be reflected here. Any future change **MUST NOT** remove or restructure existing elements — only add to them surgically.

### 13.0 Defensive Layout Constraints (CSS Safety)
To prevent extreme data payloads (e.g., massive JSON documents, gigabyte string sizes, or Base64 hashes) from destroying the dashboard grid, the UI is bound by strict, non-negotiable CSS constraints:
1. **Table Integrity**: All `.forensic-table` elements **MUST** use `table-layout: fixed`.
2. **Text Wrapping**: Table cells (`td`) **MUST** use `word-break: break-all` and `overflow-wrap: break-word` to force brutal word-wrapping of unstructured keys.
3. **Payload Boundaries**: All `<pre>` blocks displaying JSON payloads **MUST** be strictly constrained within grid boundaries using `max-width: 100%`, `box-sizing: border-box`, and `white-space: pre-wrap !important`.

### 13.1 Global Layout

| Element | Description |
| :--- | :--- |
| **Header** | Logo (🐦 logpeck), version badge, log file source path |
| **Tab Bar** | 6 tabs, horizontal, uppercase labels. Active tab has green underline. |
| **Design Tokens** | Dark mode (`--bg: #0b111a`), MongoDB emerald accent (`--accent: #00ed64`), Inter + Outfit + JetBrains Mono fonts |

### 13.2 Tab Structure (6 Tabs)

| # | Tab ID | Label | Default Active | Description |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `health` | 🏥 Health Overview | ✅ Yes | Global cluster health cards, bottleneck radar, severity/component waves |
| 2 | `slow` | 🐢 Business Workload Forensics | No | User-level slow query shapes with full drill-down |
| 3 | `system` | 🛠️ System Query Forensics | No | Infrastructure/system query shapes (TTL, Heartbeats, admin ops) |
| 4 | `timeouts` | 🚨 Failure Forensics | No | Error/timeout shapes with error code + description columns |
| 5 | `connections` | 🔌 Connection Analytics | No | Connection churn, app/IP/user waves, driver stitching |
| 6 | `reference` | 📚 Reference | No | Auto-synced diagnostic decoder from `rules.json` + metric registry |

---

### 13.3 Tab 1: Health Overview

| Section | Content |
| :--- | :--- |
| **Health Summary Cards** (7 cards, grid) | Total Logs Parsed · Time Window · Slow Queries · Avg Slow Duration · Max Slow Duration · Workload Failures · Log Errors |
| **Forensic Bottleneck Radar** | Horizontal stacked bar: CPU (green) · Storage (amber) · Oplog (blue) · Replication (red) · Queue (pink) · Lock (purple) · Planning (indigo). Legend below. |
| **Master Forensic Insight** | Executive summary card identifying the primary bottleneck |
| **Platform Health Profile** | Two side-by-side panels: Severity Wave (color-coded bars) + Component Wave |
| **Namespace Grid** | Table: Namespace × Parsed Lines (admin/local/config filtered out) |
| **System Health Trace** | Top Messages table: Severity · Message Pattern · Count |
| **System Error Patterns** | Table with expandable payload rows |

---

### 13.4 Tab 2 & 3: Workload / System Forensics

Both tabs share the same structure. System tab wraps the table in a card with a gold-accented label.

#### 13.4.1 Controls Bar
| Element | Description |
| :--- | :--- |
| **Search Input** | Full-text filter across namespace, op, app, hash. Green left-border (Business) or Gold (System). |
| **Tier Filter Buttons** | Up to 3 latency tier buttons (e.g., `500ms+`, `1s+`, `5s+`) + `ALL` reset button |
| **Collapse All** | Closes all expanded drill-down rows |

#### 13.4.2 Collapsed Row (Table Columns)

| # | Column | Width | Content |
| :--- | :--- | :--- | :--- |
| 1 | `#` | 40px | Row number (with hidden query_hash + plan_cache_key for search) |
| 2 | `OP` | 80px | Operation badge (find, aggregate, update, tx-find, etc.) |
| 3 | `AVG` | 80px | Average latency (formatted duration) |
| 4 | `MAX` | 80px | Maximum latency (bold, formatted duration) |
| 5 | `COUNT` | 80px | Occurrence count |
| 6 | `AAS LOAD` | 110px | Active Average Sessions load bar + percentage |
| 7 | `TOTAL MS` | 100px | Cumulative wall-clock time |
| 8 | `NAMESPACE` | 220px | Collection namespace (with "(Inferred)" italic tag if applicable) |
| 9 | `DIAGNOSTIC` | 350px | Stacked diagnostic badges (severity-colored chips from rules engine) |
| 10 | `APPLICATION` | 180px | Client app name |
| 11 | `PLAN` | auto | Plan summary text or **Plan Badge** (styled pill for SEARCH/VECTOR indexes) |

#### 13.4.3 Expanded Drill-Down (Full Row Detail)

When a row is clicked, a `details-row` expands below it with a 6px green left-border. The drill-down contains the following sections **in exact order**:

**Section A: Identity Header**
| Field | Description |
| :--- | :--- |
| QUERY SHAPE HASH | Full 64-char hex hash (green if present, gray if N/A) |
| QUERY HASH | Short 8-char hash |
| PLAN CACHE KEY | Short 8-char key |
| DISCOVERED QUERY SCHEMA | Colored pill tags for each extracted field name (right-aligned) |

**Section B: Latency Fingerprint (Workload Wave)**
- Horizontal stacked bar showing latency distribution across 7 tiers: 100ms, 250ms, 500ms, 1s, 2s, 5s, 10s
- Color gradient from green (tier1) through amber to red (tier7)
- Legend dots below the bar

**Section C: 🧪 Clinical Insights**
- Grid of diagnostic cards (auto-fit, min 200px). Each card has:
  - Left border color (green/amber/red based on severity)
  - Label (uppercase, 0.6rem)
  - Value (1.3rem, bold, colored)
  - Sublabel (0.6rem, gray)
- Cards rendered (in order, only when metric > 0):

| # | Card | Metric Key | Thresholds (Green / Amber / Red) |
| :--- | :--- | :--- | :--- |
| 1 | Scan Efficiency | `scan_efficiency` | < 20 / 20-500 / > 500 |
| 2 | Index Selectivity | `index_selectivity` | < 5 / 5-50 / > 50 |
| 3 | Fetch Amplification | `fetch_amplification` | ≤ 1.1 / 1.1-3.0 / > 3.0 |
| 4 | Index Amplification | `ins_amp` | < 5 / 5-10 / > 10 |
| 5 | Cache Pressure | `cache_pressure` | < 100MB / 100-500MB / > 500MB |
| 6 | Replication Backpressure | `replication_backpressure` | < 50ms / 50-200ms / > 200ms |
| 7 | Storage Intensity | `storage_intensity` | < 30% / 30-70% / > 70% |
| 8 | Search Latency | `search_latency` | < 100ms / 100-500ms / > 500ms |
| 9 | WT Cache Stall | `cache_stall` | < 1ms / 1-10ms / > 10ms |

- **Fallback States**:
  - If all metrics are healthy → `✅ CLINICAL STATUS: OPTIMAL` (green border card)
  - If no forensic data available → `⏳ CLINICAL STATUS: N/A` (gray card)

**Section D: Forensic Execution Metrics (Left Panel)**
- Two-column comparison table: `🥊 FASTEST SAMPLE` vs `🐢 SLOWEST SAMPLE`
- First row is always `Wall-Clock Latency` (min_time vs max_time)
- Remaining rows are organized by category headers:

| Category | Metrics |
| :--- | :--- |
| 📊 READ FORENSICS | keysExamined, docsExamined |
| LATENCY | storage_wait, queue_wait |
| 🖋️ WRITE CHURN | keysInserted, nModified, nMatched, txnBytesDirty |
| 💾 STORAGE WAIT | timeReadingMicros, timeWritingMicros, timeWaitingMicros_cache, totalOplogSlotDurationMicros |
| 🧭 PLANNING | planning |
| ⚙️ PURE EXECUTION | workingMillis, cpuNanos |

- **Zero-Value Suppression**: Rows where both fastest and slowest values are 0 are hidden
- **Dual-Labeling**: Each metric shows the human label AND the raw log key in small gray text

**Section E: Extracted Query Parameters (Right Panel)**
- Two-column comparison table: `🥊 VALUE` vs `🐢 VALUE`
- **Layout Integrity**: The table utilizes a `fixed` table layout with forced text-wrap constraints (`word-break: break-all`, `overflow-wrap: break-word`) to guarantee that exceptionally long query variables (e.g., massive ObjectIDs, JWT tokens, or SHA hashes) stack correctly and never expand beyond the grid boundary.
- Shows extracted filter/query fields (e.g., `id`, `type`, `xrefIds`)
- For `insert` operations: this panel is empty (no query filter exists)

**Section F: Fastest & Slowest Payloads (Side-by-Side)**
- Grid displays the raw JSON payloads (`max_peek_attr`, `min_peek_attr`)
- Includes "TS: [timestamp]" pills and a "COPY JSON" button
- **Responsive Constraints**: JSON container blocks are rigorously scoped to exactly 50% max capacity (`max-width: 100%` inside a `1fr` column) with strict `white-space: pre-wrap` overrides. This ensures unbroken scalar strings (like Base64 encoded blobs) wrap natively instead of introducing layout-breaking horizontal scrollbars on the parent container.
- Dark background (#000000), monospace font, max-height 450px with scroll

---

### 13.5 Tab 4: Failure Forensics

#### 13.5.1 Executive Summary
- **Failure Summary Grid**: Table with CODE · ERROR/DESCRIPTION · OCCURRENCES · AVG DELAY · PRIMARY NAMESPACE · MOST IMPACTED APP
- **Timeout Pattern Grid**: Table with Last Seen · Code · Count · Avg · Max · Namespace · Op Preview · Error Pattern · App · Context (IP + Ctx)

#### 13.5.2 Forensic Drill-Down Table
- Same column structure as Tab 2 but with timeout-specific columns:

| # | Column | Content |
| :--- | :--- | :--- |
| 1 | `#` | Row number |
| 2 | `CODE` | Error code (JetBrains Mono, bold red: `hsl(0, 84%, 60%)`) |
| 3 | `DESCRIPTION` | Error name with 🚨 (timeout) or ☢️ (error) prefix |
| 4 | `OCCURRENCES` | Total count of this failure shape |
| 5 | `HASH` | Short query shape hash (12 chars) |
| 6 | `NAMESPACE` | Target namespace |
| 7 | `APPLICATION` | Client application name |

- Expanded drill-down follows the same Section A–F structure as Tab 2

---

### 13.6 Tab 5: Connection Analytics

| Section | Content |
| :--- | :--- |
| **Connection Summary Cards** (4 cards) | Total Connections · Churn Rate · Auth Failures · Log Trace Duration |
| **Application Wave** | Top 10 apps by connection count (horizontal bars) |
| **IP Wave** | Top 10 IPs by connection count |
| **User Wave** | Top 10 users by connection count |
| **Driver Stitching Table** | CLIENT APPLICATION · DRIVER STITCHING · COUNT |

---

### 13.7 Tab 6: Reference

| Section | Content |
| :--- | :--- |
| **Diagnostic Decoder** | Auto-synced from `rules.json`. Grid cards with: Rule label, severity badge, technical path, description |
| **Metric Registry** | Grid cards organized by category (Read, Write, Storage, etc.) with: Label, BSON source path, description |

---

### 13.8 Plan Badge System

The PLAN column uses styled pill badges to visually distinguish Search and Vector operations:

| Plan Type | Badge Style | Color |
| :--- | :--- | :--- |
| Standard (IXSCAN, COLLSCAN, etc.) | Plain monospace text | Gray (opacity: 0.7) |
| Atlas Search (`$search`) | Rounded pill with border | Green (`var(--accent)`) |
| Vector Search (`$vectorSearch`) | Rounded pill with border | Purple (`#a855f7`) |

---

### 13.9 Interactive Behaviors

| Behavior | Implementation |
| :--- | :--- |
| **Row Expand/Collapse** | `toggleDetails(id)` — toggles `display: table-row` on the details-row |
| **Tab Switching** | `openTab(tabId, el)` — hides all `.tab-content`, shows target, updates `.active` |
| **Search Filter** | `filterRows(inputId, tableId)` — filters `.row-main` + next sibling by text content |
| **Tier Filter** | `filterByTier(threshold, tableId)` — shows only rows where `data-tier >= threshold` |
| **Collapse All** | `collapseAll()` — hides all `.details-row` elements |
| **Copy JSON** | `copyToClipboard(elementId, button)` — copies `<pre>` text content, button text changes to "✓ Copied" |

---

## 🛠️ 14. Core Utility Tooling (`utils.py`)
LogPeck adheres strictly to DRY (Don't Repeat Yourself) principles. All UI presentation scaling and unit math is centrally managed in `utils.py`.

### 14.1 Duration Formatting (`format_duration`)
Scales raw milliseconds gracefully across magnitudes:
- **Pico/Nano**: Tracks fractions down to `0.000001ms`
- **Micro**: `0.001ms` to `<1ms` -> `µs`
- **Milli**: `1ms` to `<1000ms` -> `ms`
- **Seconds/Minutes**: `>1000ms` -> `s` and `m s` format

### 14.2 Byte Formatting (`format_bytes`)
Scales raw bytes into IEC-standard magnitudes: `B`, `KB`, `MB`, `GB`, `TB`, `PB`.

This centralized utility ensures that the CLI output, dynamic Rule Engine tags (e.g. `{value_duration}`), and HTML Dashboard generation all perfectly align without redundant formatting logic.

---

## 📑 15. Documentation Lifecycle
- **Authoritative Registry**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py)
- **Synchronicity Gate**: All architectural modifications to the stitching, routing, or error resolution logic in `analyzer.py` **MUST** be reflected in this design documentation (LOGPECK_DESIGN.md) prior to version release.
- **UI Gate**: All modifications to `reporter.py` layout, tab structure, or drill-down anatomy **MUST** be reflected in Section 13 of this document.

---

## 🔍 16. Forensic Search Engine & Discovery Architecture

LogPeck implements a dual-mode search engine to balance diagnostic power with surgical precision.

### **16.1 Stateful Mode (Default Forensic Mode)**
*   **Mechanism**: Performs a 2-pass analysis. Pass 1 builds the **MSH Identity Registry** (mapping Connection IDs to Application Names and IPs). Pass 2 executes keyword matching.
*   **Identity Injection**: Keyword matches are performed against a virtual string that combines the raw log message with the backfilled identity from Pass 1.
*   **Impact**: Enables "Identity-Aware" searching (e.g., searching for "Compass" finds queries that don't have the word "Compass" on the line).

### **16.2 Stateless Mode (High-Precision `--grep` Mode)**
*   **Mechanism**: Single-pass, raw string matching.
*   **Search Space**: The entire raw JSON entry is treated as a single string.
*   **Speed**: Optimized for raw performance and high-precision matching of literal strings.
*   **Constraint**: No identity reconstruction or namespace backfilling is performed.

### **16.3 The Search Index Pattern (UI Integration)**
To ensure search parity between the CLI and the Dashboard, LogPeck uses a **Search Index Pattern** in the generated HTML. 

Because the search engine matches against the `textContent` of a table row (`row-main`), any forensic signal that is visually hidden must be explicitly "pinned" to the DOM using a hidden search index span.

**Technical Implementation:**
```html
<tr class="row-main">
  <td>
    [Visible Value]
    <span style="display:none"> [Hidden Forensic Anchor 1] [Hidden Forensic Anchor 2] </span>
  </td>
</tr>
```

### 16.2 Search Index Matrix

| Dashboard Tab | Visual Search Fields | Forensic Search Anchors (Hidden) |
| :--- | :--- | :--- |
| **Business Workload** | Namespace, Operation, App Name, Diagnostic Tags | Query Shape Hash, Plan Cache Key |
| **System Workload** | Background Task Name, Component, Diagnostic Tags | Internal Thread ID |
| **Failure Forensics** | Error Code, Error Pattern, Namespace, App Name | **Client IP**, Connection Context ID, Shape Hash, Full Error Description |
| **Connection Analytics**| App Name, Driver Version | **Client IP**, Username |

### 16.3 Developer Checklist for Searchable Fields
When adding a new forensic metric or metadata field to `reporter.py`:
1. **Visual Column**: If the field is critical for triage (e.g. `App Name`), add it as a visible `<td>`.
2. **Search Anchor**: If the field is for deep forensics only (e.g. `Connection Context`), append it to the hidden `<span>` inside the first `<td>` of the `row-main`.
3. **Case Sensitivity**: The engine uses `.toLowerCase()`. All anchors should be string-cast and space-separated within the index span.

---

## 🎨 17. UI Token System & Design Architecture

LogPeck v5.0 implements a rigid, high-fidelity design system to ensure diagnostic clarity across extreme datasets.

### 17.1 Color Foundation (HSL Philosophy)
We avoid standard hex codes to maintain "Vibrancy Parity" across the dashboard:
- **Background**: `hsl(215, 41%, 7%)` — Deep slate for zero eye-strain.
- **Accent (Emerald)**: `hsl(145, 100%, 46%)` — The MongoDB "Success" anchor.
- **Error (Red)**: `hsl(0, 84%, 60%)` — High-intensity alert.
- **Warning (Gold)**: `hsl(45, 93%, 47%)` — Performance cliff anchor.

### 17.2 Typography & Rhythm
- **Primary Interface**: `Inter, sans-serif` (Optimal legibility).
- **Executive Headers**: `Outfit, sans-serif` (Premium weight).
- **Forensic Payloads**: `'JetBrains Mono', monospace` (Standard for code alignment).
- **Vertical Rhythm**: Every card and table row is bound by a `1.5rem` padding constant to ensure visual balance even when 1,000+ rows are rendered.

### 17.3 Performance Optimization
The dashboard is a **Single-File Zero-Dependency** application:
1. **Zero External CSS**: All styles are inlined in the `<head>`.
2. **O(n) Search**: Live filtering is achieved via a single linear DOM traversal (O(n)), ensuring that searching through 5,000 query shapes remains sub-10ms.
3. **Memory Management**: Expanded rows use `details-content` wrapping to ensure that the layout engine only calculates the geometry of visible forensic cards.

---

## 💾 4. Cross-Platform Integrity & Encoding

To ensure forensic reliability across Windows, macOS, and Linux, LogPeck enforces a strict UTF-8 encoding contract for all file operations.

### 4.1 Strict Encoding Policy
All interactions with JSON configuration files (`metrics.json`, `rules.json`) and the generation of HTML reports utilize `encoding='utf-8'`. This prevents "Charmap" decode errors on Windows systems where the local code page (e.g., CP1252) would otherwise fail on high-bit characters (e.g., emojis 🐦, or non-ASCII log attributes).

### 4.2 Forensic Provenance
Batch reports generated using the `--folder` mode inject a `SOURCE LOG AUDIT` context into the dashboard. This allows SREs to maintain forensic lineage when auditing logs from multiple shards or nodes simultaneously.

---

## 🏗️ 18. Frontend Implementation Rules (Developer Mandate)

To maintain the production-grade integrity of the LogPeck dashboard, all frontend modifications MUST adhere to these strict mandates:

### 18.1 JavaScript Hardening (The JS_BLOCK Policy)
- **Decoupled Scripting**: To prevent Python f-string `SyntaxError` regressions, all significant JavaScript blocks MUST be defined as literal strings (e.g., `JS_BLOCK = """..."""`) outside the main `final_html` f-string.
- **Brace Integrity**: Decoupling allows JS to use standard single braces `{}` without doubling, making the code maintainable and preventing the Python parser from attempting to evaluate JS logic as Python expressions.
- **Placeholder Injection**: The JS block is injected into the final template using a single `{JS_BLOCK}` placeholder.

### 18.2 CSS Class Synchronization & Search Indexing
- **Search Dependency**: The frontend search engine (`filterTable`, `filterRows`) relies on strict CSS class naming to correlate parent rows with their forensic detail cards.
- **Mandatory Class Naming**: 
    - **Main Rows**: MUST use `class="row-main"`.
    - **Detail Rows**: MUST use `class="details-row"`.
- **Search Visibility Logic**: When a `row-main` is hidden by a search filter, its corresponding `details-row` MUST also be hidden automatically by the search logic to prevent orphaned forensic data from cluttering the UI.

### 18.3 Table Alignment & Column Integrity
- **Mandatory 6-Column Failure Summary**: The `Executive Failure Summary` MUST always have 6 columns (CODE, ERROR / DESCRIPTION, OCCURRENCES, AVG DELAY, PRIMARY NAMESPACE, MOST IMPACTED APP).
- **No Index Column in Summaries**: The `#` column is reserved for forensic drill-down tables only. It MUST NOT be present in executive summary tables.
- **Header Naming**: Use `OCCURRENCES` instead of `COUNT` for failure patterns to align with forensic terminology.

### 18.2 Visual Language & Styling
- **Error Codes**: All numeric MongoDB error codes MUST be styled in **bold high-contrast red** (`hsl(0, 84%, 60%)`) using the `JetBrains Mono` font.
- **Diagnostic Icons**: Timeouts MUST be prefixed with 🚨; general Errors MUST be prefixed with ☢️.
- **Hover Transitions**: All `row-main` elements MUST implement a subtle scale and background shift on hover to provide interactive feedback.

### 18.3 Forensic Expansion Protocol
- **Unified ID Mapping**: Every `row-main` MUST have a unique `id` (e.g., `row-fast-{idx}`) that corresponds to its sibling `details-row` (e.g., `details-fast-{idx}`).
- **State Preservation**: The `toggleDetails(id)` function MUST manage the visibility of the expansion row without affecting the scroll position or search filter state.
- **Colspan Matching**: When modifying table headers, the `colspan` value in the corresponding `details-row` MUST be updated immediately to prevent layout fragmentation.

### 18.4 Search Indexing (The Hidden Layer)
- **Deep Discovery**: Every `row-main` MUST include a hidden `<span>` inside the first column containing forensic anchors (Hashes, IPs, Context IDs).
- **Searchable Payloads**: In the Failure Forensics tab, the full string representation of the error pattern MUST be included in the hidden search index to enable searching by partial error messages.
- **Consistency**: All search anchors MUST be space-separated and cast to lowercase to match the linear O(n) search traversal.

---

## 💻 19. CLI Forensic Visualization Contract

To ensure visual parity with the dashboard while optimizing for terminal constraints, the LogPeck CLI adheres to the following layout contract:

### 19.1 Table Structural Guardrails
- **Grid Separation**: All forensic tables MUST use `show_lines=True` to provide clear row boundaries in high-density terminal environments.
- **Header Styling**: Business/System tables use `bold magenta`; Failure tables use `bold red`.

### 19.2 The "Fingerprint" Anchor
- **Placement**: To save horizontal space, a composite fingerprint including the `queryShapeHash` (truncated to 8 chars), `queryHash`, and `planCacheKey` MUST be displayed on a new line directly below the Operation name in the first column.
- **Format**: `S:[Shape] Q:[Query] P:[Plan]`
- **Formatting**: The fingerprint MUST be styled as `dim` (gray) to maintain visual hierarchy, keeping the Operation name as the primary focus.

### 19.3 Dynamic Column Wrapping
- **App Column**: MUST use `overflow="fold"` to stack multiple client applications vertically, preventing horizontal table expansion.
- **Diagnostic Column**: MUST use `overflow="fold"` to ensure all forensic badges (e.g., `Latency Cliff`, `IO Bound`) are visible without truncation.

### 19.4 Failure Workload Parity
The `failure-workload` command MUST prioritize error metadata over performance metrics, utilizing the following column order:
1. **Code**: Bold high-contrast red.
2. **Error**: Bold description.
3. **Count**: Right-justified.
4. **Query Shape Hash**: The full 64-char fingerprint (folded).
5. **Namespace**: Target collection.
6. **App**: Originating client.
7. **Last Seen**: Dimmed timestamp.
