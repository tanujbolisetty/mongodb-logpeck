# 🐦 logpeck — Forensic MongoDB Log Analytics

**Surgical performance discovery for MongoDB. Reconstruct the "Why" behind latency, failures, and architectural bottlenecks.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 What you get from LogPeck

Standard monitoring tells you *when* things are slow. **LogPeck tells you why.** It transforms raw MongoDB logs into actionable forensic insights:

*   **🐢 Latency Cliff Discovery**: Identifies query shapes where the slowest samples are significantly slower than the average—revealing intermittent resource blocking.
*   **🚨 Architectural Anti-Patterns**: Automatically flags `COLLSCAN` events, in-memory sorts, and inefficient index usage.
*   **🔗 Join & Regex Visibility**: Surface non-standard `$lookup` stages and CPU-intensive regex scans that impact cluster stability.
*   **🛡️ Infrastructure Truth**: Isolates systemic network errors (timeouts, disconnects) from business workload performance.
*   **🔌 Application Attribution**: Correlates every slow query to a specific Application, IP, and User, even in logs where that context is missing.
*   **📉 Volumetric AAS Load**: Visualizes the physical "weight" of every operation relative to the total cluster load.

---

## 📦 Installation
```bash
pip3 install git+https://github.com/tanujbolisetty/mongodb-logpeck.git
```

> [!TIP]
> If the `peck` command is not found after installation, ensure your Python binary directory is in your `PATH`. For example, on macOS:
> `export PATH=$PATH:$(python3 -m site --user-base)/bin`

---

## ⚡ Quick Start (How to use)

Generate a professional, six-tab forensic report in seconds:

```bash
# Analyze a log and generate an interactive dashboard
peck dashboard --file mongod.log --html forensic_report.html
```

Or perform surgical analysis directly in your terminal:

```bash
# Analyze business workload hotspots
peck workload --file mongod.log

# Analyze all systemic errors and timeouts
peck failure-workload --file mongod.log
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

### 4. Failure & Timeout Forensics
Analyze systemic failures, timeouts, and error hotspots.
```bash
# Analyze all failures and timeouts
peck failure-workload --file mongod.log.gz
```

### 5. Connection Portfolio & Client Analysis
Identify connection churn, authentication failures, and app attribution.
```bash
peck connections --file mongod.log.gz
```

### 6. Surgical Filtering
Structured multi-dimensional forensics using logical `AND` chaining.
```bash
# Filter by latency (> 500ms)
peck filter --file mongod.log --filters '{"ms": {"gt": 500}}'

# Filter by namespace and operation
peck filter --file mongod.log --filters '{"ns": "production.orders", "op": "update"}'

# Filter by plan (COLLSCAN)
peck filter --file mongod.log --filters '{"plan": "COLLSCAN"}' --cards

# Rapid volume check (Count only)
peck filter --file mongod.log --filters '{"ms": {"gt": 1000}}' --count

# Control display volume (Top 5 results)
peck filter --file mongod.log --filters '{"ms": {"gt": 500}}' --limit 5

# Deep-path filtering (For non-standard or nested fields)
peck filter --file mongod.log --filters '{"attr.storage.data.txnBytesDirty": {"gt": 536045710}}' --cards
```

### 7. Forensic Search (Stateful vs. Stateless)
LogPeck offers two powerful ways to discover information:

- **Forensic Search (Default)**: Reconstructs identity. Searching for "Compass" finds every slow query run by Compass, even if "Compass" isn't on that specific log line.
- **High-Precision Search (`--grep`)**: A stateless, full-text match. Mimics standard `grep` speed and precision by searching the entire raw JSON entry.

```bash
# Forensic: Find everything connected to the identity
peck search --file mongod.log --keyword "compass"

# Forensic: Find top 5 results connected to identity
peck search --file mongod.log --keyword "compass" --limit 5

# High-Precision: Find only literal matches
peck search --file mongod.log --keyword "compass" --grep
```

---

## 🗺️ CLI vs Dashboard Mapping
Use the table below to find the surgical CLI command equivalent for each professional dashboard tab.

| Dashboard Tab | CLI Command | Purpose | Key Options |
| :--- | :--- | :--- | :--- |
| **1. Global Health** | `peck health` | High-level summary of severity levels and components. | `--json` |
| **2. Business Workload** | `peck workload` | Analyzes application-level slow queries. | `--latency`, `--json` |
| **3. System Workload** | `peck system-workload` | Analyzes infrastructure tasks (TTL, Oplog). | `--latency`, `--json` |
| **4. Failure Forensics** | `peck failure-workload` | Analyzes systemic timeouts and error codes. | `--latency`, `--json` |
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
