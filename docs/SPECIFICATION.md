# 🐦 LogPeck — Forensic Engine Core Specification (v2.7.0)

> **Status**: Production Blueprint (Restored & Verified)  
> **Source of Truth**: [specification.py](file:///Users/Tanuj.Bolisetty/Documents/Agentic_learning/log-peck/logpeck/specification.py)
> **Objective**: This document defines the deterministic mapping from raw MongoDB JSON logs to high-fidelity forensic metrics. It serves as the master blueprint for recreating the analytical engine.

---

## 🏛️ 1. The "Truth Engine" Contract

LogPeck implements a centralized mapping system to ensure absolute parity between the CLI (`logpeck stats`) and the HTML Dashboard.

### 1.1 Forensic Metrology Standard
All internal counters and time-series data are harvested using a 1:1 path-to-metric mapping.

| Metric Identifier | BSON Source Path | Human-Readable Label | Unit |
| :--- | :--- | :--- | :--- |
| `keysExamined` | `attr.keysExamined` | Keys Examined | count |
| `docsExamined` | `attr.docsExamined` | Docs Examined | count |
| `nreturned` | `attr.nreturned` | Docs Returned | count |
| `reslen` | `attr.reslen` | Result Size | Bytes |
| `cpuNanos` | `attr.cpuNanos` | CPU Time | ns |
| `timeInactiveMicros`| `attr.timeInactiveMicros`| Transaction Idle | µs |
| `workingMillis` | `attr.workingMillis` | Execution Time | ms |
| `txnBytesDirty` | `attr.storage.data.txnBytesDirty` | Cache Dirty | Bytes |
| `mongot_wait` | `attr.mongot.timeWaitingMillis` | Atlas Search Wait | ms |

### 1.2 Wait-Time Reconstruction
Wait times are normalized to **Milliseconds (ms)** across all interfaces.

| Metric Identifier | Source Components | Standard Unit |
| :--- | :--- | :--- |
| `lock_wait` | `attr.locks.timeAcquiringMicros` | ms |
| `storage_wait` | `attr.storage.data.timeReadingMicros` + `attr.storage.index.timeReadingMicros` | ms |
| `planning` | `attr.planningTimeMicros` | ms |
| `queued` | `attr.queues.execution.totalTimeQueuedMicros` | ms |

---

## 🕵️ 2. Forensic Logic Directives

### 2.1 Pass 1: Global Multi-Context Sweep (MCS)
LogPeck initializes a global state matrix (**MSH Matrix**) during the first pass to resolve transient identifiers:
- **Connection Alignment**: `ctx` (e.g., `[conn123]`) is normalized to a stable integer key `conn123`.
- **Identity Stitching**: Events `22943` (Authentication) and `51800` (Metadata) are used to bind context IDs to `appName`, `user`, and `client_IP`.
- **Transaction Stitching (v2.7.2)**: Multi-statement transactions are stitched to their originating namespaces by harvesting `lsid` (Session ID) and `txnNumber` from the nested `parameters` block.

### 2.2 Pass 2: Analysis & Shape Fingerprinting
Raw entries are synthesized into **Query Shapes**:
1.  **Fingerprinting**: Hashes are generated using MongoDB 8.0 `queryShapeHash` > `planCacheShapeHash` > `queryHash`.
2.  **Back-filling**: If a log entry lacks an identity (e.g., a lean timeout error), the engine stitches state from the MSH Matrix using the connection ID as the lookup key.

### 2.3 Forensic Flattening (v2.7.0)
To handle the complexity of MongoDB error payloads, the engine implements a **Recursive Flattening Strategy**:
- **BSON Depth**: The engine traverses nested `error` and `stats` documents to find the root `errmsg`.
- **Payload Integrity**: The original raw JSON is preserved alongside the flattened metrics for 100% forensic auditability.

### 2.4 Infrastructure Recovery Logic
When standard MongoDB `codeName` fields are missing (typical in network-level interrupts), the engine applies the **Message-First Fallback**:
- **Identifier**: `SocketException`, `Broken pipe`, and `Connection timed out` are treated as primary event types.
- **Routing**: These events are automatically promoted to the **System Health** tab to prevent diagnostic noise in the Slow Query tab.

---

## 🛡️ 3. Noise Suppression & Hygiene

Internal MongoDB maintenance events are excluded from performance analysis but preserved for connection state stitching.

### 3.1 Systematic Exclusions
- **Namespaces**: `admin.*`, `config.*`, `local.*`, `*.system.*` (Note: `transaction` operations are exempted from this filter to preserve forensic anchors).
- **Components**: `FTDC`, `REPL_HB`, `SHARD_HE`, `NETWORK`, `STORAGE`, `REPL`, `RECOVERY`, `INDEX`, `SHARDING`.
- **App Names**: `Automation Agent`, `Monitoring Agent`, `CPS Module`, `OplogFetcher`.
- **Lifecycle Events**: Connection pool maintenance and heartbeat noise identified via `LIFECYCLE_EVENT_IDENTIFIERS`.

### 3.2 Schema Hygiene
During query schema discovery, the following "Structural Keywords" are pruned to isolate business-level fields (e.g., `orderId`):
`must`, `should`, `filter`, `range`, `path`, `index`, `score`, `near`, `geoWithin`, etc.

---

## 📉 4. Diagnostic Heuristics

The engine evaluates query shapes against the following efficiency thresholds:

| Logic Rule | Threshold | Tag |
| :--- | :--- | :--- |
| **Index Efficiency** | `keysExamined / nreturned > 10.0` | `⚠️ SCAN_REDUCTION` |
| **Latency Variance** | `max_ms > 10 * avg_ms` | `🚨 LATENCY_CLIFF` |
| **I/O Saturation** | `storage_wait > 0.3 * duration` | `💾 IO_BOUND` |
| **CPU Saturation** | `cpu_ns / 1M > 0.8 * duration` | `⚡ CPU_BOUND` |
| **Idle Transaction**| `app_wait > 0.5 * active_time` | `🐌 IDLE_TRANSACTION` |

---

## 📚 5. Dynamic Metadata Synchronization

As of v2.7.0, the dashboard no longer relies on hardcoded diagnostic glossaries. 
- **The "Rules Sync" Protocol**: The `Reference` tab in the HTML dashboard is generated dynamically by traversing `rules.json`.
- **Consistency Gate**: Any change to `rules.json` (categories, thresholds, or technical descriptions) will be reflected in the next generated report without requiring code modifications to the `reporter` module.

---

## 🏆 Documentation Standard
- Reference File: `logpeck/specification.py`
- All architectural changes **MUST** update both the code registry and this specification.
