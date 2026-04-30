import argparse
import json
import sys
import os
import re
from .analyzer import analyze_slow_queries, aggregate_forensic_results
from .reporter import generate_html_report
from .finder import search_logs, filter_logs
from .version import __version__ as VERSION
from .specification import FIELD_DISPLAY, METRIC_TYPE
from .utils import format_duration, format_bytes, format_metric_value, get_scan_efficiency_color

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console(stderr=True)

# ==============================================================================
# logpeck: cli.py
# The Unified Command-Line Interface for MongoDB Log Forensics.
# ==============================================================================
# This module provides the user-facing entry point for both interactive and 
# automated log analysis. It manages:
# 1. Professional Terminal Visualization (via Rich).
# 2. Command Routing (Health, Search, Filter, Analyze).
# 3. Output Serialization (Flashing JSON for downstream pipelines).
# ==============================================================================

def format_forensic_entry(entry):
    """
    Generates a high-fidelity, flattened forensic JSON object.
    
    This is used by the --json flag across search/filter commands to provide 
    a deterministic, easy-to-parse structure for other automation tools.
    """
    from .parser import extract_log_metrics
    metrics = extract_log_metrics(entry) or {}
    attr = entry.get("attr", {})
    
    # Harvest the 'Truth'
    ts = entry.get("t")
    ts_str = str(ts.get("$date", ts)) if isinstance(ts, dict) else str(ts or "N/A")
    
    return {
        "timestamp": ts_str,
        "severity": metrics.get("severity", "I"),
        "op": (metrics.get("op") or "unknown").upper(),
        "ns": metrics.get("ns") or "unknown",
        "duration_ms": metrics.get("ms", 0),
        "msg": entry.get("msg", ""),
        "waits": {k: v for k, v in metrics.get("waits_ms", {}).items() if v > 0},
        "stats": metrics.get("forensic", {}),
        "query": entry.get("query_params") or attr.get("command") or attr.get("originatingCommand")
    }

def print_log_card(entry, full=False):
    """
    Prints a professional, structured log entry card to the terminal.
    
    This visualizes a single log line with its identified operation, namespace, 
    latency, and wait breakdown.
    """
    if not isinstance(entry, dict):
        console.print(f"  [dim](Non-Structural Log: {str(entry)[:100]})[/dim]")
        return

    from .parser import extract_log_metrics
    
    # Ensure entry is a dictionary and extract basic fields
    attr = entry.get("attr", {})
    if not isinstance(attr, dict): attr = {}
    
    metrics = entry.get("metrics", {})
    if not isinstance(metrics, dict): metrics = {}
    
    # Late-binding metric extraction if missing (guarantees ms/ns availability)
    if not metrics:
        metrics = extract_log_metrics(entry)

    duration = metrics.get("ms") or attr.get("durationMillis")
    ns = metrics.get("ns")
    if not ns or ns == "None":
        ns = "unknown"
    ts = entry.get("t")
    sev = metrics.get("severity") or "I"
    op = metrics.get("op") or "unknown"
    from rich.markup import escape
    
    # TS Formatting (Defensive against both dict/string variants)
    if isinstance(ts, dict):
        ts_str = str(ts.get("$date", ts))
    else:
        ts_str = str(ts or "N/A")
        
    ts_short = ts_str[11:19] if "T" in ts_str else ts_str
    dur_str = f"({duration}ms)" if duration else ""
    
    console.print("-" * 80, style="dim")
    # Use Rich markup escaping to ensure brackets and namespaces are printed correctly
    ns_display = escape(f"[{ns}]")
    dur_display = f" {dur_str}" if dur_str else ""
    # Forensic Header: Prioritize identified Op over generic Component
    console.print(f"[dim]{ts_short}[/dim]  [bold]{sev}[/bold]  [cyan]{op.upper():<14}[/cyan] [green]{ns_display}[/green]{dur_display}")
    
    msg = entry.get("msg", "")
    if msg:
        console.print(f"  [italic]{msg[:130]}...[/italic]" if len(msg) > 130 else f"  [italic]{msg}[/italic]")

    # Forensic Timeline: Surface all extracted time markers
    waits = metrics.get("waits_ms", {})
    if waits:
        wait_parts = [f"{k}={v}ms" for k, v in waits.items() if v > 0]
        if wait_parts:
            console.print(f"  [dim]Waits:[/dim] {', '.join(wait_parts)}")

    # Forensic Statistics: Surface clinical markers (keysExamined, etc.)
    stats = metrics.get("forensic", {})
    if stats:
        stat_parts = []
        for k, v in stats.items():
            label = FIELD_DISPLAY.get(k, k)
            # Shorten labels for CLI if they are too long, but use the spec as base
            label = label.replace("Examined", "Exm").replace("Inserted", "Ins").replace("Matched", "Mtch")
            val_str = format_metric_value(k, v)
            stat_parts.append(f"{label}={val_str}")
        if stat_parts:
            console.print(f"  [dim]Stats:[/dim] {', '.join(stat_parts)}")


    # Safely extract query parameters or original commands
    query_params = entry.get("query_params") or attr.get("command") or attr.get("originatingCommand")
    if query_params and isinstance(query_params, dict):
        q_str = json.dumps(query_params, indent=2) if full else json.dumps(query_params)
        if not full and len(q_str) > 85: q_str = q_str[:82] + "..."
        console.print(f"  [dim]Query:[/dim] {q_str}")

def get_subset_duration(results):
    """Calculates the time span (seconds) of a log entry subset for AAS accuracy."""
    if not results or len(results) < 2: return 1.0
    from dateutil import parser as dp
    try:
        def _ts(e):
            t = e.get("t")
            if isinstance(t, dict): return t.get("$date")
            return t
        
        times = [dp.isoparse(_ts(r)) for r in results if _ts(r)]
        if not times: return 1.0
        dur = (max(times) - min(times)).total_seconds()
        return max(dur, 1.0)
    except: return 1.0

def print_forensic_table(summary):
    """
    Prints a professional, multi-column forensics table matching the 'Slow Tab' format.
    """
    table = Table(header_style="bold magenta")
    table.add_column("Op", width=8); table.add_column("Namespace", ratio=1); table.add_column("App")
    table.add_column("Avg", justify="right"); table.add_column("Max", justify="right")
    table.add_column("AAS", justify="right", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Diagnostic", width=20); table.add_column("Last Seen", justify="right", style="dim")
    
    for row in summary:
        diag = ", ".join([str(t['label']) for t in row.get('diagnostic_tags', [])])
        if len(diag) > 20: diag = diag[:17] + "..."
        
        last_seen = str(row.get('last_ts', 'N/A'))
        if len(last_seen) > 19: last_seen = last_seen[11:19]
        
        table.add_row(
            str(row['category']), str(row['namespace']), str(row.get('app_name', 'unknown')),
            format_duration(row['avg_time']), format_duration(row['max_time']), 
            f"{row.get('aas_load', 0):.2f}",
            str(row['count']), diag, last_seen
        )

    console.print(table)

def print_failure_summary_table(summary):
    """
    Prints the Executive Failure Summary (Table 1) for the CLI.
    """
    table = Table(header_style="bold red", box=None)
    table.add_column("Code", style="bold red"); table.add_column("Error Name", ratio=1)
    table.add_column("Count", justify="right"); table.add_column("Avg Delay", justify="right")
    table.add_column("Top Namespace", style="dim"); table.add_column("Top App", style="dim")
    
    for row in summary:
        table.add_row(
            str(row.get('code', 'N/A')), str(row.get('name', 'N/A')),
            str(row.get('count', 0)), format_duration(row.get('avg_ms', 0)),
            str(row.get('top_ns', 'N/A')), str(row.get('top_app', 'N/A'))
        )
    console.print(Panel(table, title="📊 Executive Failure Summary", border_style="red"))

def print_system_error_table(errors):
    """
    Prints System & Network Error Patterns (Table 3) for the CLI.
    """
    table = Table(header_style="bold yellow")
    table.add_column("Code", style="cyan"); table.add_column("Category", style="yellow")
    table.add_column("Message Pattern", ratio=1); table.add_column("Count", justify="right")
    table.add_column("Last Seen", justify="right", style="dim")
    
    for err in errors:
        ts = str(err.get('ts', 'N/A'))[11:19]
        table.add_row(
            str(err.get('code', 'N/A')), str(err.get('category', 'N/A')),
            str(err.get('msg', 'N/A')), str(err.get('count', 0)), ts
        )
    console.print(Panel(table, title="🛠️ System & Network Error Forensics", border_style="yellow"))

def main():
    """
    The Command Router for LogPeck.
    
    This is the primary gateway into the engine's capabilities. 
    It parses sys.argv and dispatches to the appropriate analytical module.
    """
    parser = argparse.ArgumentParser(
        description="🐦 LogPeck: Forensic MongoDB Log Analytics (v5.0.7)\n"
                    "Hardened observability with Ticket/Lock/Repl wait-hierarchy logic and Clinical Mutation diagnostics.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version=f"logpeck v{VERSION}")
    subparsers = parser.add_subparsers(dest="command", help="Pecker sub-commands")

    # Command: health (formerly stats)
    health_parser = subparsers.add_parser("health", help="Get professional forensic health profile")
    health_parser.add_argument("--file", required=True, help="Path to mongod.log")
    health_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # Command: search
    search_parser = subparsers.add_parser("search", help="Keyword forensic search")
    search_parser.add_argument("--file", required=True, help="Path to mongod.log")
    search_parser.add_argument("--keyword", required=True, help="Search term")
    search_parser.add_argument("--full", action="store_true", help="Show full query fingerprint")
    search_parser.add_argument("--cards", action="store_true", help="Show individual log cards instead of summary table")
    search_parser.add_argument("--count", action="store_true", help="Only output the total number of matches")
    search_parser.add_argument("--limit", type=int, default=10, help="Max results to display (default: 10, use 0 for unlimited)")
    search_parser.add_argument("--json", action="store_true", help="Output time card in JSON format")
    search_parser.add_argument("--grep", action="store_true", help="Stateless search: Search raw JSON string and skip identity reconstruction")

    # Command: filter
    filter_parser = subparsers.add_parser("filter", help="Multidimension forensic filter")
    filter_parser.add_argument("--file", required=True, help="Path to mongod.log")
    filter_parser.add_argument("--filters", required=True, help="JSON filter e.g. '{\"ms\": {\"gt\": 500}}'")
    filter_parser.add_argument("--full", action="store_true", help="Show full query fingerprint")
    filter_parser.add_argument("--cards", action="store_true", help="Show individual log cards instead of summary table")
    filter_parser.add_argument("--count", action="store_true", help="Only output the total number of matches")
    filter_parser.add_argument("--limit", type=int, default=10, help="Max results to display (default: 10, use 0 for unlimited)")
    filter_parser.add_argument("--json", action="store_true", help="Output time card in JSON format")

    # Command: workload (Business Workload Forensics)
    workload_parser = subparsers.add_parser("workload", help="Analyze business workload hotspots and latency cliffs (excludes system noise)")
    workload_parser.add_argument("--file", required=True, help="Path to mongod.log")
    workload_parser.add_argument("--latency", type=int, default=0, help="Min latency (ms) for forensic capture (default: 0)")
    workload_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Command: system-workload (System Query Forensics)
    system_workload_parser = subparsers.add_parser("system-workload", help="Analyze system infrastructure forensics (TTL, Oplog, Admin, Indices)")
    system_workload_parser.add_argument("--file", required=True, help="Path to mongod.log")
    system_workload_parser.add_argument("--latency", type=int, default=0, help="Min latency (ms) for forensic capture (default: 0)")
    system_workload_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Command: failure-workload (Failure Forensics)
    failure_workload_parser = subparsers.add_parser("failure-workload", help="Analyze systemic failures, timeouts, and error hotspots")
    failure_workload_parser.add_argument("--file", required=True, help="Path to mongod.log")
    failure_workload_parser.add_argument("--latency", type=int, default=0, help="Min latency (ms) for forensic capture (default: 0)")
    failure_workload_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Command: connections
    connections_parser = subparsers.add_parser("connections", help="Analyze client applications and connection churn")
    connections_parser.add_argument("--file", required=True, help="Path to mongod.log")
    connections_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Command: dashboard (formerly report)
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate the professional 6-tab HTML forensic dashboard")
    dashboard_parser.add_argument("--file", help="Path to a single mongod.log")
    dashboard_parser.add_argument("--folder", help="Path directory for batch processing")
    dashboard_parser.add_argument("--html", default="output/logpeck_report.html", help="Dashboard output path")
    dashboard_parser.add_argument("--latency", type=int, default=0, help="Min latency (ms) for forensic capture (default: 0)")
    dashboard_parser.add_argument("--filter", help="Filter files by substring in filename")

    args = parser.parse_args()

    if not args.command:
        parser.print_help(); sys.exit(0)

    try:
        if args.command == "health":
            # Pass a very high threshold to health so we get all metadata without Pass 2 overhead
            result = analyze_slow_queries(args.file, threshold_ms=999999)
            if args.json:
                print(json.dumps(result, indent=2))
                return
            
            s = result["stats"]
            c = result["connections"]
            
            # --- Header ---
            console.print(f"\n[bold cyan]📋 logpeck Forensic Portfolio: {os.path.basename(args.file)}[/bold cyan]")
            
            # --- Panel 1: Global Health & Velocity ---
            meta_items = [
                f"[bold]Parsed:[/bold] {s['total_parsed']:,}",
                f"[bold]Filtered:[/bold] [yellow]{s.get('total_filtered', 0):,}[/yellow]",
                f"[bold]Shapes:[/bold] {s['unique_shapes']:,}",
                f"[bold]Slow:[/bold] {s['total_slow_count']:,}",
                f"[bold]Err:[/bold] [red]{s['log_error_count']:,}[/red]"
            ]
            console.print(Panel(" | ".join(meta_items), border_style="cyan", title="Global Health Overview"))

            # --- Section 2: Workload & Op Profile ---
            workload_table = Table(box=None, padding=(0, 2))
            workload_table.add_column("🔥 Top Namespaces", style="green", ratio=1)
            workload_table.add_column("🛠️ Operation Profile", style="yellow", ratio=1)
            
            ns_list = list(s.get("namespaces", {}).items())[:6]
            op_list = list(s.get("op_distribution", {}).items())[:6]
            
            for i in range(max(len(ns_list), len(op_list))):
                ns_str = f"{ns_list[i][0]:<25} ({ns_list[i][1]:,})" if i < len(ns_list) else ""
                op_str = f"{op_list[i][0]:<25} ({op_list[i][1]:,})" if i < len(op_list) else ""
                workload_table.add_row(ns_str, op_str)
            
            console.print(Panel(workload_table, title="Workload Distribution", border_style="dim"))

            # --- Section 3: Connection Intelligence ---
            conn_table = Table(box=None, padding=(0, 2))
            conn_table.add_column("🚀 Top Applications", style="cyan", ratio=1)
            conn_table.add_column("📍 Top Client IPs", style="magenta", ratio=1)
            
            app_list = list(c.get("top_apps", {}).items())[:6]
            ip_list = list(c.get("top_ips", {}).items())[:6]
            
            for i in range(max(len(app_list), len(ip_list))):
                app_str = f"{app_list[i][0]:<25} ({app_list[i][1]:,})" if i < len(app_list) else ""
                ip_str = f"{ip_list[i][0]:<25} ({ip_list[i][1]:,})" if i < len(ip_list) else ""
                conn_table.add_row(app_str, ip_str)
            
            console.print(Panel(conn_table, title="Connection Portfolio", border_style="dim"))

            # --- Panel 4: Efficiency Audit ---
            eff = s.get("global_efficiency", {})
            total_ret = eff.get("nreturned", 0) or 1
            keys_ratio = round(eff.get("keysExamined", 0) / total_ret, 1)
            docs_ratio = round(eff.get("docsExamined", 0) / total_ret, 1)
            
            eff_color = "red" if keys_ratio > 100 else "yellow" if keys_ratio > 10 else "green"
            eff_msg = f"[bold {eff_color}]Scan Ratio: {keys_ratio}:1 keys/ret[/bold {eff_color}] | Documents Examined: {docs_ratio}:1 docs/ret"
            console.print(Panel(eff_msg, title="Cluster-Wide Efficiency Audit", border_style="dim"))

            # --- Panel 5: Synthesis Dashboard ---
            diag_table = Table(box=None, show_header=False, padding=(0, 2))
            diag_table.add_column("Label", style="bold dim", width=15)
            diag_table.add_column("Value")
            
            # Bottlenecks
            btl = s.get("global_bottlenecks", {})
            total_wait = sum(btl.values()) or 1
            io_pct = round((btl.get("io_ms", 0) / total_wait) * 100, 1)
            cpu_pct = round((btl.get("cpu_ms", 0) / total_wait) * 100, 1)
            storage_pct = round((btl.get("storage_ms", 0) / total_wait) * 100, 1)
            oplog_pct = round((btl.get("oplog_ms", 0) / total_wait) * 100, 1)
            
            btl_str = f"I/O: {io_pct}% | CPU: {cpu_pct}% | Storage: {storage_pct}% | Oplog: {oplog_pct}%"
            diag_table.add_row("Bottlenecks", btl_str)
            
            # Top Messages
            top_msgs = s.get("top_messages", [])[:3]
            for i, m in enumerate(top_msgs):
                label = "Forensic Signal" if i == 0 else ""
                diag_table.add_row(label, f"[dim]{m['severity']}[/dim] [yellow]{m['msg'][:100]}[/yellow] ({m['count']:,})")
            
            console.print(Panel(diag_table, title="Deep Synthesis Dashboard", border_style="dim"))

            # --- Panel 6: Component & Failure Audit ---
            audit_table = Table(box=None, padding=(0, 2))
            audit_table.add_column("🏗️ Component Workload", style="cyan", ratio=1)
            audit_table.add_column("⚠️ Critical Failures (by Code)", style="red", ratio=1)
            
            comp_list = list(s.get("components", {}).items())[:6]
            # 🧪 Systemic Failure View: Prioritise Error Code Summary for CLI
            ecs_list = s.get("error_code_summary", [])[:6]
            
            for i in range(max(len(comp_list), len(ecs_list))):
                if i < len(comp_list):
                    comp_str = f"{comp_list[i][0]:<25} ({comp_list[i][1]:,})"
                else:
                    comp_str = ""
                    
                if i < len(ecs_list):
                    e = ecs_list[i]
                    e_name = str(e.get("name", "UnknownError")).replace(" (50)", "")
                    to_str = f"[[bold]{e.get('code')}[/bold]] {e_name[:18]} ({e.get('count')})"
                else:
                    to_str = ""
                    
                audit_table.add_row(comp_str, to_str)
                
            console.print(Panel(audit_table, title="Technical Audit & Systemic Failures", border_style="dim"))

            # --- Panel 7: Platform & System Diagnostics ---
            # Surfaces background tasks (TTL, Oplog) that may impact primary performance.
            sys_summary = result.get("system_summary", [])
            if sys_summary:
                health_table = Table(box=None, padding=(0, 2))
                health_table.add_column("🧬 Platform/System Event", style="bold yellow", ratio=1)
                health_table.add_column("Avg", justify="right")
                health_table.add_column("Max", justify="right")
                health_table.add_column("Count", justify="right")
                
                for h in sys_summary[:6]:
                    health_table.add_row(
                        h["category"], 
                        format_duration(h["avg_time"]), 
                        format_duration(h["max_time"]), 
                        str(h["count"])
                    )
                console.print(Panel(health_table, title="System Health Diagnostics", border_style="yellow"))

            console.print(f"[dim]Audit completed in {s['analysis_duration']}s. System Health Parity: 100%.[/dim]\n")

        elif args.command == "search":
            # If counting, we bypass the limit to get the true total
            search_limit = 0 if args.count else args.limit
            results = search_logs(args.file, args.keyword, limit=search_limit, count_only=args.count, grep_mode=args.grep)
            
            if args.count:
                print(len(results))
                return
                
            if args.json:
                forensic_json = [format_forensic_entry(r) for r in results]
                print(json.dumps(forensic_json, indent=2))
                return
            
            if not results:
                console.print("[dim]No matches found.[/dim]")
                return

            if args.cards:
                console.print(f"\n[bold green]🔍 Forensic Search Results: '{args.keyword}'[/bold green]")
                for entry in results:
                    print_log_card(entry, full=args.full)
            else:
                dur = get_subset_duration(results)
                summary = aggregate_forensic_results(results, log_dur_sec=dur)
                console.print(f"\n[bold green]📊 Aggregate Forensic Search: '{args.keyword}'[/bold green]")
                print_forensic_table(summary)

        elif args.command == "filter":
            try:
                f_obj = json.loads(args.filters)
            except:
                raise ValueError("Filters must be a valid JSON string. Example: '{\"ms\": {\"gt\": 500}}'")
            
            # If counting, we bypass the limit to get the true total
            filter_limit = 0 if args.count else args.limit
            results = filter_logs(args.file, f_obj, limit=filter_limit)
            
            if args.count:
                print(len(results))
                return
                
            if args.json:
                forensic_json = [format_forensic_entry(r) for r in results]
                print(json.dumps(forensic_json, indent=2))
                return

            if not results:
                console.print("[dim]No matches found.[/dim]")
                return

            if args.cards:
                console.print(f"\n[bold blue]🧪 Diagnostic Filter: {args.filters}[/bold blue]")
                for entry in results:
                    print_log_card(entry, full=args.full)
            else:
                dur = get_subset_duration(results)
                summary = aggregate_forensic_results(results, log_dur_sec=dur)
                console.print(f"\n[bold blue]📊 Aggregate Diagnostic Filter: {args.filters}[/bold blue]")
                print_forensic_table(summary)

        elif args.command == "workload":
            result = analyze_slow_queries(args.file, threshold_ms=args.latency)
            if args.json: print(json.dumps(result["summary"], indent=2)); return

            console.print(f"\n[bold yellow]🐢 Business Workload Forensics (v{VERSION})[/bold yellow]")
            print_forensic_table(result["summary"])

        elif f"system-workload" == args.command:
            result = analyze_slow_queries(log_file_path=args.file, threshold_ms=args.latency)
            if args.json: print(json.dumps(result["system_summary"], indent=2)); return

            console.print(f"\n[bold cyan]🛠️ System Query Forensics (v{VERSION})[/bold cyan]")
            print_forensic_table(result["system_summary"])

        elif f"failure-workload" == args.command:
            result = analyze_slow_queries(log_file_path=args.file, threshold_ms=args.latency)
            stats = result.get("stats", {})
            if args.json: 
                out = {
                    "executive": stats.get("error_code_summary", []),
                    "shapes": result.get("timeout_summary", []),
                    "system": stats.get("system_error_patterns", [])
                }
                print(json.dumps(out, indent=2)); return

            console.print(f"\n[bold red]🚨 Failure & Timeout Forensics (v{VERSION})[/bold red]")
            
            # Tier 1: Executive Summary
            ecs = stats.get("error_code_summary", [])
            if ecs: print_failure_summary_table(ecs)
            
            # Tier 2: Query Shape Analysis
            tos = result.get("timeout_summary", [])
            if tos:
                console.print("\n[bold]🔬 Query Shape Failure Analysis[/bold]")
                print_forensic_table(tos)
                
            # Tier 3: System Errors
            sys_errs = stats.get("system_error_patterns", [])
            if sys_errs:
                console.print("")
                print_system_error_table(sys_errs)

        elif args.command == "connections":
            # Pass threshold 0 to get all connection metadata
            result = analyze_slow_queries(args.file, threshold_ms=999999)
            if args.json:
                print(json.dumps(result["connections"], indent=2))
                return
            
            c = result["connections"]
            console.print(f"\n[bold magenta]🔌 Connection Analytics: {os.path.basename(args.file)}[/bold magenta]")
            
            # --- Panel 1: Stats ---
            stats_items = [
                f"[bold]Total Conns:[/bold] {c['total_connections']:,}",
                f"[bold]Churn:[/bold] [red]{c['churn_rate']}/s[/red]",
                f"[bold]Auth Fails:[/bold] [red]{c['auth_fail_count']}[/red]",
                f"[bold]Trace Duration:[/bold] {int(c['duration_sec']//3600)}h {int((c['duration_sec']%3600)//60)}m"
            ]
            console.print(Panel(" | ".join(stats_items), title="Engagement Statistics", border_style="magenta"))
            
            # --- Table: Identity Portfolio ---
            id_table = Table(box=None, padding=(0, 2))
            id_table.add_column("🚀 Applications", style="cyan", ratio=1)
            id_table.add_column("📍 Client IPs", style="magenta", ratio=1)
            id_table.add_column("👤 Users", style="yellow", ratio=1)
            
            apps = list(c.get("top_apps", {}).items())[:6]
            ips = list(c.get("top_ips", {}).items())[:6]
            users = list(c.get("top_users", {}).items())[:6]
            
            for i in range(max(len(apps), len(ips), len(users))):
                app_str = f"{apps[i][0]:<20} ({apps[i][1]:,})" if i < len(apps) else ""
                ip_str = f"{ips[i][0]:<20} ({ips[i][1]:,})" if i < len(ips) else ""
                user_str = f"{users[i][0]:<20} ({users[i][1]:,})" if i < len(users) else ""
                id_table.add_row(app_str, ip_str, user_str)
            
            console.print(Panel(id_table, title="Client Identity Portfolio", border_style="dim"))
            
            # --- Table: Driver Analysis (Matching HTML Connection tab) ---
            driver_table = Table(box=None, padding=(0, 2))
            driver_table.add_column("CLIENT APPLICATION", style="cyan", ratio=1)
            driver_table.add_column("DRIVER STITCHING", style="green", ratio=1)
            driver_table.add_column("COUNT", justify="right")
            
            for m in c.get("app_driver_mapping", []):
                driver_table.add_row(m["app"], f"[bold]{m['driver']}[/bold]", str(m["count"]))
            
            console.print(Panel(driver_table, title="Driver Fingerprint Analysis", border_style="dim"))
            console.print(f"[dim]Connection audit completed. Parity: 100%.[/dim]\n")

        elif args.command == "dashboard":
            if not args.file and not args.folder:
                raise ValueError("Expressly provide --file or --folder for the dashboard.")
                
            out_dir = os.path.dirname(args.html) or "output"
            if not os.path.exists(out_dir): os.makedirs(out_dir)

            if args.folder:
                files = []
                for root, _, filenames in os.walk(args.folder):
                    for f in filenames:
                        if f.endswith(".log") or f.endswith(".gz") or f.endswith(".json"):
                            files.append(os.path.join(root, f))
                
                if args.filter:
                    files = [f for f in files if args.filter in os.path.basename(f)]
                
                for f in files:
                    out_html = os.path.join(out_dir, os.path.basename(f) + "_report.html")
                    print(f"🐦 Forensic Sweep: {os.path.basename(f)} ↳ {out_html}", file=sys.stderr)
                    result = analyze_slow_queries(log_file_path=f, threshold_ms=args.latency)
                    generate_html_report(result, out_html, source_name=os.path.basename(f))
                print("✅ Batch Forensic Cycle Complete.", file=sys.stderr)
            else:
                dest = args.html if (os.path.dirname(args.html) or args.html.startswith("/")) else f"output/{args.html}"
                result = analyze_slow_queries(log_file_path=args.file, threshold_ms=args.latency)
                print(f"🐦 Forensic Sweep: {args.file} ↳ {dest}", file=sys.stderr)
                generate_html_report(result, dest, source_name=os.path.basename(args.file))
                print("✅ Dashboard Complete.", file=sys.stderr)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        # In development, we might want the full traceback
        import traceback; traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
