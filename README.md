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
- **🧬 Identity Stitching & Correlation (v2.7.6)**: Guaranteed identity attribution for context-lean logs by reconstructing state via the connection-based **MSH Matrix**.
- **🔍 Custom Rules Engine**: Decoupled diagnostic logic in `rules.json` for tunable bottleneck thresholds.
- **💓 Real-time Pulse**: Integrated progress tracking for high-volume log processing.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/tanujbolisetty/mongodb-logpeck.git
cd mongodb-logpeck

# Install logpeck in editable mode
pip install -e .
```

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

### 4. Global Platform Health
Quickly assess the overall distribution of severity levels and component-level workload.
```bash
peck health --file mongod.log.gz
```

### 5. Connection Portfolio & Client Analysis
Identify connection churn, authentication failures, and app attribution.
```bash
peck connections --file mongod.log.gz
```

### 6. Surgical Filtering & Search
- **`peck search`**: Professional keyword search (IPs, Hash, User, Driver) across the entire log.
- **`peck filter`**: Structured multi-dimensional forensics using logical `AND` chaining.

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

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.
