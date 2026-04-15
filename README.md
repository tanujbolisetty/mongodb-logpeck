# 🐦 logpeck — Forensic MongoDB Log Analytics

**High-fidelity, single-pass forensic engine for surgical MongoDB performance discovery.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

`logpeck` is a modern forensic assistant designed for single-pass analysis of both plain-text and natively gzipped (`.gz`) MongoDB logs. It identifies architectural anti-patterns, wait-time bottlenecks, and "Latency Cliffs" that standard monitoring tools often miss.

---

## 🚀 Key Features

- **⚡ Light-Speed 2-Pass Architecture**: Optimized for million-line scans, identifying outliers in seconds before deep forensic archaeology.
- **📦 Native GZip Streaming**: Direct analysis of `.log.gz` traces with zero disk overhead.
- **💎 Master Forensic Insight**: An executive summary card that identifies the primary bottleneck (I/O, CPU, Indexing) across the entire dataset.
- **🛡️ Surgical Latency Histograms**: Visualizes query distribution across 12 geometric buckets (1ms to 60s+).
- **🚨 Dynamic Latency Cliffs**: Automatically flags performance cliffs (e.g. Max > 10x Avg) for every query shape.
- **🔌 Connection Analysis**: Aggregates client metadata (App, IP, User, Driver) to identify connection churn and noisy neighbors.
- **🏥 Platform Health Profile**: Cluster-wide severity distribution and component-level workload mapping.
- **🧬 Absolute Reconstructability (v2.7.0)**: Guaranteed connection stitching for sparse logs (e.g. failures) by reconstructing connection-level state via multi-pass discovery.
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

### 1. Interactive Forensic Dashboard
The flagship feature of **logpeck**. Generates a professional three-tab surgical report for exhaustive diagnostic review.
```bash
# Standard Production Analysis (GZip Support)
peck dashboard --file mongod.log.gz --html output/dashboard.html

# Custom Diagnostic Sizing (Including failures regardless of threshold)
peck dashboard --file mongod.log.gz --latency 500
```

### 2. Global Platform Health
Quickly assess the overall distribution of severity levels and component-level workload.
```bash
peck health --file mongod.log.gz
```

### 3. Workload Forensics (Terminal Summary)
Deep-dive into performance hotspots and failures directly from your terminal.
```bash
# Analyze 100% of workload (Full Discovery + Failures)
peck workload --file mongod.log.gz --latency 0
```

### 4. Connection Portfolio & Client Analysis
Identify connection churn, authentication failures, and app attribution.
```bash
peck connections --file mongod.log.gz
```

### 5. Surgical Filtering & Search
`logpeck` provides two specialized lenses for discovery:
- **`peck search`**: Professional global keyword search (IPs, Hash, User, Driver) across 100% of the log.
- **`peck filter`**: Structured multi-dimensional forensics using logical `AND` chaining.

```bash
# Global Forensic Search (Keyword discovery)
peck search --file mongod.log.gz --keyword IXSCAN --full

# Filter by multiple surgical criteria (Unified JSON Syntax)
# Complex operators like gt, gte, lt, lte, and eq are supported.
peck filter --file mongod.log.gz --filters '{"ms": {"gte": 500}}'

# Granular Multi-Filter Deep-Dive (Chained Criteria)
# Supports both top-level aliases (ms, ns) and nested raw paths.
peck filter --file mongod.log.gz \
  --filters '{"ms": {"gte": 1000}, "attr.keysExamined": {"gte": 100000}}' \
  --full
```

---

---

## 🧬 Forensic Matrix (3-Tab Dashboard)

The HTML report is organized into three professional focus areas:

| Tab | Focus | Key Diagnostics |
| :--- | :--- | :--- |
| **🏥 Platform & System** | Infrastructure Integrity | RSM topology, engine messages, and system-level operations. |
| **🚨 Failure Forensics** | Workload Interruptions | Consolidated Workload Errors and Timeouts (🚨/☢️). |
| **🔌 Connection Portfolio** | Application Hygiene | Identity attribution, connection churn, and auth forensic signal. |

---

---

## 👤 Author

**Tanuj Kumar Bolisetty**  
GitHub: [@tanujbolisetty](https://github.com/tanujbolisetty)

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.
