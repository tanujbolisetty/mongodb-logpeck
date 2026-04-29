# 🐦 LogPeck: Forensic CLI Reference

This document provides a comprehensive technical guide to all command-line flags available in the `logpeck` forensic suite (v5.0.0).

---

## 🛠️ Global Commands

| Command | Focus Area | Dashboard Equivalent |
| :--- | :--- | :--- |
| `health` | Global cluster vitals & background noise. | **1. Global Health** |
| `workload` | Application query shapes & latency. | **2. Business Workload** |
| `system-workload` | Infrastructure tasks (TTL, Oplog, Admin). | **3. System Workload** |
| `failure-workload` | Systemic errors & timeouts. | **4. Failure Forensics** |
| `connections` | Client identity & driver profiling. | **5. Connection Analytics** |
| `search` | Surgical keyword extraction. | N/A |
| `filter` | Multi-dimensional logical filtering. | N/A |
| `dashboard` | HTML Report Generation. | N/A |

---

## 🚩 Command-Line Flags

### 1. Fundamental Flags
*   **`--file <path>`**: (Required for most) The path to the `mongod.log` or `.gz` file to analyze.
*   **`--latency <ms>`**: Filters queries taking longer than the specified milliseconds. 
    *   *Forensic Impact*: Setting this to `500` ignores the "noise" and only captures operations causing visible application delays.
*   **`--json`**: Switches the output from a pretty-printed terminal table to a raw JSON object.
    *   *Usage*: Essential for piping to `jq` or integrating with other automation scripts.

### 2. Search & Filter Flags
*   **`--keyword <term>`**: (Search only) The literal string to find.
*   **`--grep`**: (Search only) Stateless search. Searches the **raw JSON string** of every entry and skips identity reconstruction. Use this for high-precision matching where you only want rows that literally contain the keyword.
*   **`--filters <json>`**: (Filter only) A JSON query object for complex matching.
    *   *Example*: `'{"ms": {"gt": 1000}, "ns": "orders.v1"}'`

#### **Search Modes Comparison**

| Feature | **Default (Forensic)** | **`--grep` (Stateless)** |
| :--- | :--- | :--- |
| **Search Space** | Optimized Space + **Injected Identity** | **Entire Raw JSON String** |
| **Discovery** | Finds all operations for a connection. | Finds only literal matches. |
| **Speed** | 2-Pass (Slower for very large logs) | 1-Pass (Grep-like speed) |
| **Reconstruction**| Yes (Fills in missing Namespaces/Apps) | No (Shows only what is on the line) |
| **Use Case** | Deep Diagnostics & Root Cause Analysis. | Quick, high-precision text finding. |

*   **`--limit <int>`**: Controls the maximum number of results displayed.
    *   **Absolute Default: 10**. 
    *   Use `0` for unlimited output (Caution: can flood terminal).
*   **`--count`**: Bypasses the results table entirely. 
    *   *Forensic Impact*: Rapidly calculates the total volume of matches in the log without processing full forensic cards.
*   **`--full`**: Expands the result to show the **Full Query Fingerprint**.
    *   *Forensic Impact*: Use this when you need the exact JSON query body to reproduce an issue in a test environment.
*   **`--cards`**: Switches the display from a summary table to individual "Forensic Cards" (one per log entry).

### 3. Dashboard Orchestration
*   **`--folder <path>`**: Enables batch processing. Every log in the folder will be analyzed and converted to an HTML dashboard.
*   **`--html <path>`**: Specifies the destination for the generated HTML report.
*   **`--filter <substring>`**: When using `--folder`, only processes files containing this substring (e.g., `--filter "shard-01"`).

---

## 🧪 Forensic Triage Patterns

### Pattern A: "The Quick Sweep"
Find out if there are any `COLLSCAN` events and how many.
```bash
peck search --file mongod.log --keyword "COLLSCAN" --count
```

### Pattern B: "The Latency Cliff"
Find the 10 slowest queries in a specific namespace that took over 2 seconds.
```bash
peck filter --file mongod.log --filters '{"ns": "finance.orders", "ms": {"gt": 2000}}' --full
```

### Pattern C: "The Connection Storm"
Check if a specific IP is churning connections.
```bash
peck search --file mongod.log --keyword "172.31.24.5" --count
```

### Pattern D: "The System Drain"
Check if background Oplog truncation is slowing down the engine.
```bash
peck system-workload --file mongod.log --latency 100
```
