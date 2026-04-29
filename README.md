# 🐦 logpeck — Forensic MongoDB Log Analytics

**High-fidelity, single-pass forensic engine for surgical MongoDB performance discovery.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

`logpeck` is a modern forensic assistant designed for high-velocity analysis of both plain-text and natively gzipped (`.gz`) MongoDB logs. It identifies architectural anti-patterns, wait-time bottlenecks, and "Latency Cliffs" that standard monitoring tools often miss.

---

## 🚀 Key Features

- **⚡ Light-Speed 2-Pass Architecture**: Optimized for million-line scans, identifying outliers in seconds before deep forensic archaeology.
- **📦 Native GZip Streaming**: Direct analysis of `.log.gz` traces with zero disk overhead.
- **💎 Master Forensic Insight**: An executive summary card that identifies the primary bottleneck (I/O, CPU, Indexing) across the entire dataset.
- **🛡️ Surgical Latency Histograms**: Visualizes query distribution across 12 geometric buckets (1ms to 60s+).
- **🚨 Dynamic Latency Cliffs**: Automatically flags performance cliffs (e.g. Max > 10x Avg) for every query shape.
- **🔌 Connection Analysis**: Aggregates client metadata (App, IP, User, Driver) to identify connection churn and noisy neighbors.
- **🏥 Platform Health Profile**: Cluster-wide severity distribution and component-level workload mapping.
- **🧬 Identity Stitching & Correlation (v5.0.0)**: Guaranteed identity attribution for context-lean logs by reconstructing state via the connection-based **MSH Matrix**.
- **🔍 Universal Search Index (v5.0.0)**: Live, multi-dimensional search across hashes, IPs, apps, and diagnostics.
- **🛡️ Truth Engine (v5.0.0)**: Surgical aggregation of systemic infrastructure errors and "orphan" network pathologies.
- **🔍 Custom Rules Engine**: Decoupled diagnostic logic in `rules.json` for tunable bottleneck thresholds.
- **💓 Real-time Pulse**: Integrated progress tracking for high-volume log processing.

---

## 📦 Installation

#### **Option A: Stable Version (Main Branch)**
Use this for standard production auditing:
```bash
pip3 install git+https://github.com/tanujbolisetty/mongodb-logpeck.git
```

#### **Option B: Beta Version (v5.0.0 Hardening Branch)**
Use this to access the new **Truth Engine** and **Universal Search Index**:
```bash
pip3 install git+https://github.com/tanujbolisetty/mongodb-logpeck.git@fix/forensic-engine-hardening
```

> [!TIP]
> If the `peck` command is not found after installation, ensure your Python binary directory is in your `PATH`. For example, on macOS:
> `export PATH=$PATH:$(python3 -m site --user-base)/bin`

---

## 🛠️ Surgical CLI Usage

The `peck` command provides multiple forensic lenses into your cluster data.

### 1. Interactive 6-Tab Forensic Dashboard
The flagship feature of **logpeck**. Generates a professional six-tab surgical report for exhaustive diagnostic review.
```bash
# Standard Production Analysis (GZip Support)
# Defaults to --latency 0 (Full forensic capture)
peck dashboard --file mongod.log.gz --html output/dashboard.html

# Custom Diagnostic Sizing (Optional: filter for queries > 100ms)
peck dashboard --file mongod.log.gz --latency 100
```

### 2. Workload Forensics (Business Hotspots)
Deep-dive into business-level performance hotspots while excluding system noise.
```bash
# Analyze business workload (Defaults to --latency 0)
peck workload --file mongod.log.gz

# Analyze business workload with a 500ms filter
peck workload --file mongod.log.gz --latency 500
```

### 3. System Query Forensics (Infrastructure)
Analyze background diagnostics and infrastructure telemetry (TTL cleanup, Oplog truncation, Index builds).
```bash
# Analyze infrastructure task performance
peck system-workload --file mongod.log.gz
```

### 4. Failure & Timeout Forensics
Analyze systemic failures, timeouts, and error hotspots.
```bash
# Analyze all failures and timeouts
peck failure-workload --file mongod.log.gz
```

### 5. Forensic Search (Stateful vs. Stateless)
LogPeck offers two powerful ways to discover information:

- **Forensic Search (Default)**: Reconstructs identity. Searching for "Compass" finds every slow query run by Compass, even if "Compass" isn't on that specific log line.
- **High-Precision Search (`--grep`)**: A stateless, full-text match. Mimics standard `grep` speed and precision by searching the entire raw JSON entry.

```bash
# Forensic: Find everything connected to the identity
peck search --file mongod.log --keyword "compass"

# High-Precision: Find only literal matches
peck search --file mongod.log --keyword "compass" --grep
```

### 6. Connection Portfolio & Client Analysis
Identify connection churn, authentication failures, and app attribution.
```bash
peck connections --file mongod.log.gz
```

### 7. Surgical Filtering & Search
- **`peck search`**: Professional keyword search (IPs, Hash, User, Driver) across the entire log.
- **`peck filter`**: Structured multi-dimensional forensics using logical `AND` chaining.
- **`--count`**: Add this flag to `search` or `filter` to rapidly get the total match volume without a full report.
- **`--limit`**: Control results processed (default: 10).

---

## 🗺️ CLI vs Dashboard Mapping
Use the table below to find the surgical CLI command equivalent for each professional dashboard tab.

| Dashboard Tab | CLI Command | Purpose | Key Options |
| :--- | :--- | :--- | :--- |
| **1. Global Health** | `peck health` | High-level summary of severity levels and components. | `--json` |
| **2. Business Workload** | `peck workload` | Analyzes application-level slow queries. | `--latency`, `--json` |
| **3. System Workload** | `peck system-workload` | Analyzes infrastructure tasks (TTL, Oplog). | `--latency`, `--json` |
| **4. Failure Forensics** | `peck failure-workload` | **(New)** Analyzes systemic timeouts and error codes. | `--latency`, `--json` |
| **5. Connection Analytics** | `peck connections` | Profiles client apps and connection churn. | `--json` |
| **6. Reference** | (Automatic) | Registry of metrics and rules. | N/A |
| **-** | `peck search` | Surgical keyword forensic search. | `--keyword`, `--grep`, `--full`, `--limit`, `--count` |
| **-** | `peck filter` | Multi-dimensional forensic filtering. | `--filters`, `--full`, `--limit`, `--count` |
| **-** | `peck dashboard` | Generates the full 6-tab HTML dashboard. | `--file`, `--folder`, `--latency`, `--html` |

---

## 🧬 Forensic Matrix (6-Tab Dashboard)

The HTML report is organized into six professional focus areas:

| Tab | Focus | Key Diagnostics |
| :--- | :--- | :--- |
| **🏥 Health Overview** | Global Fleet Pulse | Cluster-wide severities, components, and primary bottleneck. |
| **🛠️ System Query Forensics** | Infrastructure Ops | TTL Cleanup, Oplog, Background Index Builds, and Admin tasks. |
| **🐢 Business Workload** | Performance Hotspots | Detailed analysis of user-level query shapes and latency cliffs. |
| **🚨 Failure Forensics** | Workload Interruptions | Consolidated Workload Errors (Lethal) and Timeouts (MaxTimeMS). |
| **🔌 Connection Analytics** | Application Hygiene | Identity attribution, connection churn, and driver fingerprinting. |
| **📚 Reference** | Diagnostic Glossary | Dynamic rule definitions, thresholds, and technical descriptions. |

---

## 👤 Author

**Tanuj Kumar Bolisetty**  
GitHub: [@tanujbolisetty](https://github.com/tanujbolisetty)

---

## 📄 License
MIT © 2026
Distributed under the **MIT License**. See `LICENSE` for more information.
