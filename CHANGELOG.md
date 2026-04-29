# 🪵 Changelog - mongodb-logpeck

All notable changes to the `mongodb-logpeck` project will be documented in this file.

## [5.0.1] - 2026-04-29
### Fixed
- **Identity-Aware Search**: Resolved issue where `appName` wasn't searchable in the CLI. The engine now correlates application identities from the MSH Matrix during the discovery pass.

## [5.0.0] - 2026-04-28
### Added
- **Truth Engine**: Surgical identification and aggregation of systemic/infrastructure errors (Tab 1 & Tab 4).
- **Forensic Search Index**: Universal full-text search parity across all tabs including hidden metadata (IPs, Hashes, Drivers).
- **Unified Expansion UI**: Standardized "Click-to-Expand" drill-down logic across Business, System, and Failure tabs.
- **Searchable Hashes**: Enabled forensic fingerprint search in Failure Forensics.
- **Diagnostics Matrix**: New technical specification for searchable fields.

## [4.6.1] - 2026-04-28
### Added
- **Standardized Volumetrics**: Re-introduced the `--limit` flag with an absolute default of **10** results across all `search` and `filter` operations. This ensures a consistent, lightweight experience while still allowing for high-volume overrides (e.g., `--limit 500` or `--limit 0` for unlimited).

## [4.6.0] - 2026-04-28
### Added
- **Failure Workload CLI**: Introduced the `failure-workload` command to the CLI, providing terminal-based parity with the HTML "Failure Forensics" tab for systemic timeout and error analysis.
- **Surgical Match Counting**: Added the `--count` flag to `search` and `filter` commands, enabling rapid identification of matching log volume without generating full reports.
- **Forensic Pipeline Orchestrator**: Created `scripts/forensic_log_analysis_pipeline.py` to automate end-to-end Atlas log downloads, lifecycle management (retention), and automated email notifications.
- **Scenario Runner Coverage**: Expanded `tests/scenario_runner.py` to include systemic failure validation and CLI parity tests.

### Hardened
- **Pipeline Safety Guards**: Implemented a `run_` prefix validation in the lifecycle purge engine to prevent accidental deletion of manual or unrelated directories.
- **Node Filtering**: Added support for `--role PRIMARY` in the forensic pipeline to allow targeted analysis of primary cluster nodes.

## [4.5.9] - 2026-04-27
### Fixed
- **Forensic Scaling**: Corrected unit conversion in the Storage Intensity engine to ensure sub-millisecond metrics are accurately represented in the dashboard.
- **Cache Wait Extraction**: Fixed a regression in `parser.py` that caused `cache_wait` durations to be dropped during high-load throughput, restoring visibility into lock contention.

## [4.5.8] - 2026-04-27
### Fixed
- **Query Categorization**: Fixed a bug where system namespaces (e.g., `system.sessions`, `config.availability`) were incorrectly promoted to the Business Workload tab when part of a transaction. System namespaces now have priority over transaction immunity.

## [4.5.7] - 2026-04-27
### Added
- **System & Network Errors (Forensic Visibility)**: Introduced a dedicated telemetry section for "headless" infrastructure anomalies (e.g., `asio.system`, TCP timeouts) that lack query hashes. These are now isolated in a new table within the "Failure Forensics" tab to maintain workload signal while ensuring critical network events are not silenced.
- **Note Probe**: Expanded `parser.py` to capture the `note` attribute from MongoDB system logs.

### Fixed
- **Module Resolution (Editable Mode)**: Updated `README.md` and installation procedures to enforce editable mode (`pip3 install -e .`), resolving a critical issue where background `multiprocessing` workers imported stale global modules instead of local forensic logic.
- **Directory Hygiene**: Conducted a full sweep to align repository with `logpeck-maintenance` standards, migrating stray artifacts and test scripts to their governed locations.

## [4.5.6] - 2026-04-27
### Hardened
- **Transaction Consistency (tx-delete)**: Standardized forensic labeling for all mutation types. Operations arriving via `CRUD` blocks or with `lsid`/`txnNumber` metadata are now consistently prefixed with `tx-` (e.g., `tx-delete`) to align with `insert` and `update` behavior.
- **Batch Forensics**: Improved `cli.py` to support multi-report generation when using `--folder` mode, enabling cluster-wide primary node sweeps.
- **Dataset Guard (v4.5.6)**: Fixed a critical `ZeroDivisionError` in the forensic synthesis engine that occurred when processing log windows with zero active workload (0ms total time).

## [4.5.2] - 2026-04-27
### Hardened
- **Dual-Labeling (Forensic UX)**: Implemented technical sub-labels for the Forensic Execution Metrics table, showing the raw MongoDB log key (e.g., `nreturned`) beneath business-friendly names to bridge the gap between Executive and DBA views.
- **Hash Discovery (Flat Logs)**: Added `planCacheKey` to the search probes to resolve "N/A" reporting in Business Workload forensics for non-Atlas-Search queries.
- **Granular Failure Forensics**: Updated the grouping logic in `analyzer.py` to include `err_c` (Error Code) in the hash key, ensuring unique query shapes with different failure modes (e.g., Timeout vs. Network) appear as distinct actionable rows.
- **Forensic Honesty (Filtering)**: Implemented a strict pre-synthesis filter to hide anonymous or network-level failures (those lacking a `query_hash`) from the Query Shape Failure Analysis table, keeping the view focused on structural code issues.
- **Executive Standardization**: Standardized "N/A" labeling across all failure summaries, replacing inconsistent "unknown" markers for improved professional reporting.

---

## [4.3.4] - 2026-04-18
### Hardened
- **System Normalization (TTL Index)**: Implemented surgical heuristic for background maintenance detections. Deletions containing `numDeleted` metrics without session context are now correctly categorized as `TTL Index`.
- **CLI Streamlining**: Removed the redundant `--limit` field from all CLI sub-commands to simplify parameter passing and improve forensic discovery defaults.
- **Terminology Update**: Rebalanced "Worst Sample" to "Slowest Sample" in Clinical Insights for improved forensic clarity.

## [4.3.3] - 2026-04-17
### Added
- **Searchable Metadata**: Injected `QUERY HASH` and `PLAN CACHE KEY` as hidden searchable elements in the forensic dashboard to enable direct UI-based filtering.


## [4.3.2] - 2026-04-17
### Fixed
- **Forensic Unit Alignment**: Resolved a 1000x discrepancy in 'Storage Intensity' by unifying wait-time normalization and correcting the MS-to-MS percentage ratio.
- **Diagnostic Transparency**: Explicitly labeled all clinical insights in the HTML dashboard as either '(Worst Sample)' or '(Workload Aggregate)' for forensic clarity.

## [4.3.1] - 2026-04-17
### Fixed
- **Forensic Honesty**: Restricted the `OPTIMAL` clinical status to only apply when measurable forensic data (Read/Write metrics) is present, preventing false positives for indeterminate or sparse query shapes.

## [4.3.0] - 2026-04-17
### Hardened
- **Error Soundness**: Implemented Unified Error Triage in `analyzer.py` to provide a distinct union of system and application failures, preventing double-counting while capturing infrastructure anomalies.
- **Clinical Intelligence**: Formalized the `OPTIMAL` status for healthy query shapes with peak performance metrics (Efficiency < 1.1, Storage < 10%).
- **Taxonomy Refinement**: Optimized diagnostic labeling in `rules.json` by treating "Workload" as the implicit default and reserving `[TRACE]` for max-sample deep-dives.
- **Documentation**: Integrated the Forensic Color Philosophy and Clinical Threshold Matrix into the dashboard Reference tab and design specification.

## [4.2.0] - 2026-04-17
### Hardened
- **Forensic Storage Engine**: Implemented cumulative storage intensity calculation including Reads, Writes, Cache waits, and Oplog slot duration.
- **Diagnostic Logic**: Resolved "False Optimal" reporting for highly I/O bound queries by ensuring full telemetry harvesting from modern logs.
- **Standardized Prefixes**: Applied `[TRACE]` (Structural/Pathogen) and `[WORKLOAD]` (Environmental/Victim) prefixes to all diagnostic rules for cleaner forensic triage.
- **Clinical Reporting**: Updated clinical status fallback from "OPTIMAL" to "N/A" to accurately reflect diagnostic coverage limits.
- **Regression Suite**: Added `tests/io_bound_regression.log` and automated verification script to maintain diagnostic integrity.

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



