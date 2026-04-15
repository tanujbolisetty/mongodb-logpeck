# 🪵 Changelog - mongodb-logpeck

All notable changes to the `mongodb-logpeck` project will be documented in this file.

---

## [2.7.0] - 2026-04-14

### 🚀 Major Milestone: Forensic Engine Stabilization
This release hardens the core analytical engine to resolve critical regressions and ensure production-grade reliability across high-velocity Atlas shard logs.

### 🏛️ Added: Dynamic Metadata Synchronization
- **Dynamic Reference Glossary**: The dashboard's Reference Tab is now synchronized directly with `rules.json`, ensuring technical descriptions and diagnostic rules are always up-to-date without dashboard redeployment.
- **Network Failure Registry**: Expanded system event identifiers to include `SocketException`, `Broken pipe`, and `Connection timed out`, ensuring these critical infrastructure events are correctly routed to System Health.

### 🐢 Improved: Deep Forensic Harvesting
- **Recursive Error Flattening**: Implemented a robust strategy for extracting and flattening nested MongoDB error objects within the log stream.
- **Infrastructure Fallback**: Introduced a logic gate to use `errmsg` as a primary forensic identifier when traditional `codeName` is absent (critical for low-level socket failures).

### 🛠️ Fixed: Critical Analytical Regressions
- **Empty Dashboard Syndrome**: Resolved a `NameError` in `parser.py` where the forensic dictionary was accessed before initialization, restoring telemetry capture for all log streams.
- **Data Integrity**: Optimized the transition between Discovery and Forensic passes to eliminate silent drops in high-concurrency environments.


## [2.0.0] - 2026-04-11

### 🚀 Major Milestone: The Forensic Reconstruction Era
This major release marks the transition from greedy log archaeology to stateful, multi-pass forensic reconstruction. V2.0.0 consolidates the rapid evolution of the engine's core intelligence, enabling deterministic identity stitching for all MongoDB log events.

### 🏛️ Added: Stateful Forensic Intelligence
- **MSH Identity Matrix**: Implemented a stateful multi-pass architecture that binds transient connection IDs (`connX`) to persistent service identities (App Name, Driver, User, IP).
- **Forensic Reconstruction**: The engine can now reconstruct missing collection names for lean timeout events (e.g., `Client's executor exceeded time limit`) by stitching them back to the last known valid operation on that connection.
- **Validation Suite**: Integrated a new `tests/` directory with Unit, E2E, and Report Integrity verification to ensure v2.0.0 stability.
- **Unified OP/NS Probe**: Synchronized namespace attribution logic across the entire pipeline, ensuring 100% data consistency between the Slow Query and System Health dashboards.

### 🎨 Added: Industrial Dashboard v2.0
- **Redesigned Forensic Cards**: Improved visual hierarchy with "Fastest vs. Slowest" payload comparison.
- **Enhanced Accessibility**: Overhauled "COPY JSON" button with industrial styling, high-contrast borders, and interactive hover states.
- **Latency Workload Waves**: 7-tier latency profiling for instant visual identification of performance cliffs.
- **Automatic Forensic Tags**: Automated detection of `COLLSCAN`, `PIPELINE_COLLAPSE`, and `IDLE_TRANSACTION` anti-patterns.

### 🛠️ Fixed: Reliability & Hygiene
- **Atlas standard compatibility**: Enhanced GZip stream decompression and Atlas Search operator extraction.
- **Zero-Noise attribution**: Fixed generic `.$cmd` noise in forensic reports by aggressive database-prefix extraction.
- **Packaging Integrity**: Standardized PEP 517 build system and finalized the `peck` CLI entry point.

---

## [0.6.1] - 2026-04-08

### 🚀 Added: Native Production Support
- **Native GZip**: Added stream-decompression support for `.log.gz` files (Atlas standard).
- **Light-Speed Mode**: Optimized discovery pass by bypassing deep JSON archaeology for million-line traces.
- **Analysis Telemetry**: Added total synthesis duration reporting to the CLI for performance auditability.

## [0.6.0] - 2026-04-08

### 🚀 Added: Surgical Customization
- **Diagnostic Engine**: Ported hardcoded forensic logic to an extensible `rules.json` framework.
- **Lazy Normalization**: Resolved 10-minute bottleneck by deferring RegEx overhead via 'Fast-Path' token checks.
- **Theme-Aware UI**: Grouped forensic metrics into logical clusters (Read vs. Write Churn) for surgical clarity.



