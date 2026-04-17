import os
import json
from typing import List, Dict, Any
from .version import __version__ as VERSION
from .specification import FIELD_DISPLAY, METRIC_TYPE, METRIC_SOURCES, ERROR_CODE_MAP, METRIC_REGISTRY, METRIC_CATEGORIES
from .utils import format_duration, format_bytes

"""
logpeck: reporter.py
Engine for generating high-fidelity forensic HTML reports.
"""

# 🧠 Diagnostic Documentation Loader (v3.1.0)
# Pulls forensic explanations directly from rules.json to ensure the dashboard remains a live 'Truth Engine'.
def load_glossary_rules() -> List[Dict[str, Any]]:
    default_path = os.path.join(os.path.dirname(__file__), "rules.json")
    if os.path.exists(default_path):
        try:
            with open(default_path, 'r') as f: return json.load(f).get("rules", [])
        except: pass
    return []

def generate_html_report(results: Dict[str, Any], output_path: str):
    stats = results.get("stats", {}); conn = results.get("connections", {}); summary = results.get("summary", [])
    system_summary = results.get("system_summary", []); timeout_summary = results.get("timeout_summary", []); threshold = results.get("threshold", 100)
    
    # 🧬 Dynamic Rule Synchronization
    rules_glossary = load_glossary_rules()
    
    latency_max = format_duration(max([s.get('max_time', 0) for s in summary] + [0]))
    time_start = str(stats.get('time_window', {}).get('start', 'N/A'))[:19]
    time_end = str(stats.get('time_window', {}).get('end', 'N/A'))[:19]

    err_color = "var(--error)" if stats.get("log_error_count", 0) > 0 else "var(--text-primary)"
    health_summary_html = f'''
        <div class="card"><div class="card-label">Total Logs Parsed</div><div class="card-value">{stats.get("total_parsed", 0):,}</div></div>
        <div class="card"><div class="card-label">Time Window</div><div class="card-value" style="font-size:0.9rem">{time_start} → {time_end}</div></div>
        <div class="card"><div class="card-label">Slow Queries</div><div class="card-value">{stats.get("total_slow_count", 0)}</div></div>
        <div class="card"><div class="card-label">Avg Slow Duration</div><div class="card-value">{format_duration(stats.get("avg_slow_ms", 0))}</div></div>
        <div class="card"><div class="card-label">Max Slow Duration</div><div class="card-value" style="color:var(--error)">{latency_max}</div></div>
        <div class="card"><div class="card-label">Workload Failures</div><div class="card-value">{stats.get("timeout_count", 0)}</div></div>
        <div class="card"><div class="card-label">Log Errors</div><div class="card-value" style="color:{err_color}">{stats.get("log_error_count", 0)}</div></div>
    '''
    
    # 🧬 Forensic Bottleneck Radar (v2.6.10)
    btl = stats.get("global_bottlenecks", {})
    t_wait = sum(btl.values()) or 1
    def _pct(k): return (btl.get(k, 0) / t_wait) * 100
    
    bottleneck_radar_html = f'''
        <div class="card" style="border-left: 4px solid var(--accent)">
            <div class="card-label" style="display:flex; justify-content:space-between; align-items:center">
                <span>🧬 FORENSIC BOTTLENECK RADAR (GLOBAL CLUSTER WAIT RATIO)</span>
                <span style="font-size:0.6rem; color:var(--text-secondary)">TOTAL AUDIT WAIT: {format_duration(t_wait)}</span>
            </div>
            <div style="display:flex; height:24px; border-radius:6px; overflow:hidden; margin:1.2rem 0; background:rgba(255,255,255,0.05)">
                <div style="width:{_pct('io_ms') or 2}%; background:#3B82F6; height:100%" title="I/O Wait"></div>
                <div style="width:{_pct('cpu_ms') or 2}%; background:#10B981; height:100%" title="CPU Time"></div>
                <div style="width:{_pct('storage_ms') or 2}%; background:#F59E0B; height:100%" title="Storage Wait"></div>
                <div style="width:{_pct('oplog_ms') or 2}%; background:#EF4444; height:100%" title="Oplog Slot Wait"></div>
                <div style="width:{_pct('queue_ms') or 2}%; background:#EC4899; height:100%" title="Queue Wait"></div>
                <div style="width:{_pct('lock_ms') or 2}%; background:#8B5CF6; height:100%" title="Lock Wait"></div>
            </div>
            <div style="display:flex; gap:20px; flex-wrap:wrap">
                <div class="legend-item"><div class="legend-dot" style="background:#3B82F6"></div> I/O Wait ({_pct('io_ms'):.1f}%)</div>
                <div class="legend-item"><div class="legend-dot" style="background:#10B981"></div> CPU Time ({_pct('cpu_ms'):.1f}%)</div>
                <div class="legend-item"><div class="legend-dot" style="background:#F59E0B"></div> Storage Wait ({_pct('storage_ms'):.1f}%)</div>
                <div class="legend-item"><div class="legend-dot" style="background:#EF4444"></div> Oplog Slot Wait ({_pct('oplog_ms'):.1f}%)</div>
                <div class="legend-item"><div class="legend-dot" style="background:#EC4899"></div> Queue Wait ({_pct('queue_ms'):.1f}%)</div>
                <div class="legend-item"><div class="legend-dot" style="background:#8B5CF6"></div> Lock Wait ({_pct('lock_ms'):.1f}%)</div>
            </div>
        </div>
    '''
    
    def render_wave(counts: Dict[str, int], color_map: Dict[str, str] = None) -> str:
        total = sum(counts.values()) or 1
        html = ""
        for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            pct = (v / total) * 100; color = color_map.get(k, "var(--accent)") if color_map else "var(--accent)"
            html += f'<div style="margin-bottom:18px"><div style="display:flex;justify-content:space-between;font-size:0.8rem;color:var(--text-secondary);margin-bottom:6px"><span>{k}</span><span>{v:,} ({pct:.1f}%)</span></div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:{pct}%;background:{color}"></div></div></div>'
        return html

    severity_wave_html = render_wave(stats.get("severities", {}), {"ERROR": "var(--error)", "WARN": "var(--warn)", "INFO": "var(--accent)"})
    component_wave_html = render_wave(stats.get("components", {}))
    # 🕵️ Forensic Suppression (v1.3.14): Filter out admin, local, config, and system namespaces to resolve signal-to-noise issues.
    ns_grid_html = f"<table><thead><tr><th>Namespace</th><th>Parsed Lines</th></tr></thead><tbody>" + "".join([f"<tr><td>{ns}</td><td style='font-family:monospace'>{cnt:,}</td></tr>" for ns, cnt in stats.get("namespaces", {}).items() if ns != "unknown" and ".$cmd" not in ns and not any(ns.startswith(p) for p in ["admin.", "local.", "config.", "system."])]) + "</tbody></table>"
    msg_grid_html = f"<table><thead><tr><th>Severity</th><th>Message Pattern</th><th>Count</th></tr></thead><tbody>" + "".join([f"<tr><td style='color:var(--accent)'>{m.get('severity', 'I')}</td><td style='font-size:0.75rem'>{m.get('msg', 'N/A')}</td><td>{m.get('count', 0):,}</td></tr>" for m in stats.get('top_messages', [])]) + "</tbody></table>"
    
    timeout_table_html = "<table><thead><tr><th>Last Seen</th><th>Count</th><th>Namespace</th><th>Op Preview</th><th>Error Pattern</th><th>Context</th></tr></thead><tbody>"
    for t in stats.get("timeout_patterns", []):
        t_ts = str(t.get('ts', 'N/A'))[11:19]
        t_preview = str(t.get('preview', 'N/A'))[:60]
        timeout_table_html += f"<tr><td style='font-size:0.75rem;font-family:monospace'>{t_ts}</td><td><span class='tag-critical'>{t.get('count', 0)}</span></td><td style='font-size:0.75rem'>{t.get('ns', 'N/A')}</td><td style='font-size:0.72rem;font-family:monospace;color:var(--accent)'>{t_preview}</td><td style='font-size:0.72rem;color:var(--error)'>{t.get('msg', 'N/A')}</td><td style='font-size:0.7rem;color:var(--text-secondary)'>IP: {t.get('remote', 'N/A')}<br>Ctx: {t.get('ctx', 'N/A')}</td></tr>"
    timeout_table_html += "</tbody></table>"
    
    tier_buttons_html = '<button class="badge" style="cursor:pointer; border:1px solid var(--border); background:#1e293b" onclick="filterByTier(0)">ALL</button>'
    active_tiers = stats.get("active_latency_tiers", [])
    # Only show up to 3 most relevant tiers to avoid clutter
    for t in active_tiers[-3:]:
        label = format_duration(t) + "+"
        color = "var(--warn)" if t < 1000 else ("#EA580C" if t < 5000 else "var(--error)")
        tier_buttons_html += f'<button class="badge" style="cursor:pointer; border:1px solid {color}44; color:{color}" onclick="filterByTier({t})">{label}</button>'

    conn_summary_html = f'''
        <div class="card"><div class="card-label">Total Connections</div><div class="card-value">{conn.get('total_connections', 0):,}</div></div>
        <div class="card"><div class="card-label">Conn Churn Rate</div><div class="card-value" style="color:var(--error)">{conn.get('churn_rate', 0)}/sec</div></div>
        <div class="card"><div class="card-label">Auth Failures</div><div class="card-value">{conn.get('auth_fail_count', 0)}</div></div>
        <div class="card"><div class="card-label">Log Trace Duration</div><div class="card-value" style="font-size:0.9rem">{int(conn.get('duration_sec', 0)//3600)}h {int((conn.get('duration_sec', 0)%3600)//60)}m</div></div>
    '''
    app_wave_html = render_wave(conn.get("top_apps", {}))
    ip_wave_html = render_wave(conn.get("top_ips", {}))
    user_wave_html = render_wave(conn.get("top_users", {}))
    driver_mapping_html = "<table style='margin-top:1rem'><thead><tr><th>CLIENT APPLICATION</th><th>DRIVER STITCHING</th><th>COUNT</th></tr></thead><tbody>" + "".join([f"<tr><td style='font-size:0.85rem;color:var(--text-secondary)'>{m.get('app', 'N/A')}</td><td style='font-size:0.82rem;color:var(--accent);font-weight:700'>{m.get('driver', 'N/A')}</td><td style='font-family:monospace'>{m.get('count', 0):,}</td></tr>" for m in conn.get("app_driver_mapping", [])]) + "</tbody></table>"

    # 🧬 Executive Failure Summary (v2.7.16)
    failure_summary_html = "<table><thead><tr><th>CODE</th><th>ERROR / DESCRIPTION</th><th>OCCURRENCES</th><th>AVG DELAY</th><th>PRIMARY NAMESPACE</th><th>MOST IMPACTED APP</th></tr></thead><tbody>"
    ecs = stats.get("error_code_summary", [])
    if not ecs:
        failure_summary_html += "<tr><td colspan='6' style='text-align:center;color:var(--text-secondary);padding:2rem'>No workload failures detected in this trace window</td></tr>"
    for e in ecs:
        e_code = e.get("code", "N/A")
        e_name = e.get("name", "UnknownError")
        e_desc = e_name.replace(f" ({e_code})", "").replace(f" {e_code}", "")
        failure_summary_html += f"""
            <tr>
                <td><span style="font-family:'JetBrains Mono'; font-weight:700; color:var(--tier6)">{e_code}</span></td>
                <td><strong style="color:var(--text-primary)">{e_desc}</strong></td>
                <td><span class="tag-critical">{e.get("count", 0):,}</span></td>
                <td>{format_duration(e.get("avg_ms", 0))}</td>
                <td style="font-size:0.75rem">{e.get("top_ns", "N/A")}</td>
                <td style="font-size:0.75rem; color:var(--text-secondary)">{e.get("top_app", "N/A")}</td>
            </tr>
        """
    failure_summary_html += "</tbody></table>"

    def render_summary_rows(data_list, start_idx=0, is_system_view=False, is_timeout_view=False):
        rows = ""
        for i, row in enumerate(data_list):
            did = f"sys_{start_idx + i}" if is_system_view else (f"to_{start_idx + i}" if is_timeout_view else f"d_{start_idx + i}")
            l_pct = row.get("load_pct", 0); l_wid = min(l_pct * 1.5, 100)
            tags = row.get("diagnostic_tags", [])
            chip_list = [f"<span class='tag-{str(t.get('severity', 'info')).lower()}'>{t.get('label', 'UNKNOWN')}</span>" for t in tags]
            chips = f'<div style="display:flex; flex-direction:column; gap:4px; align-items:flex-start;">{" ".join(chip_list)}</div>'
            ns_display = row.get('namespace', 'unknown')
            if row.get("inferred_ns"): ns_display += ' <span style="opacity:0.6;font-style:italic">(Inferred)</span>'
            
            dist = row.get("latency_distribution", {}); tiers = [100, 250, 500, 1000, 2000, 5000, 10000]; t_colors = ["var(--tier1)", "var(--tier2)", "var(--tier3)", "var(--tier4)", "var(--tier5)", "var(--tier6)", "var(--tier7)"]; total_d = sum(dist.values()) or 1
            wave_html = "".join([f'<div style="width:{(dist.get(t, 0)/total_d)*100}%; background:{t_colors[j]}; height:100%"></div>' for j, t in enumerate(tiers) if (dist.get(t, 0)/total_d)*100 > 0])
            legend_html = "".join([f'<div class="legend-item"><div class="legend-dot" style="background:{t_colors[j]}"></div>{t}ms+</div>' for j, t in enumerate(tiers) if dist.get(t, 0) > 0])
            
            def render_clinical_insights(row_data):
                insights = []
                
                # Formula thresholds per clinical feedback
                # SE: docsExamined / nreturned (> 1000 is critical)
                se = row_data.get("scan_efficiency", 0)
                se_clr = "var(--tier1)" if se < 20 else ("#fbbf24" if se < 500 else "var(--error)")
                insights.append(f'<div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:10px; border-left:3px solid {se_clr}"><div class="card-label" style="font-size:0.6rem; opacity:0.6">SCAN EFFICIENCY</div><div style="font-size:1.3rem; font-weight:800; color:{se_clr}; margin:0.3rem 0">{se:,.1f}</div><div style="font-size:0.6rem; color:var(--text-secondary)">DOCS / RETURNED</div></div>')

                # IS: keysExamined / nreturned (> 10 indicates poor selectivity)
                is_sel = row_data.get("index_selectivity", 0)
                is_clr = "var(--tier1)" if is_sel < 5 else ("#fbbf24" if is_sel < 50 else "var(--error)")
                insights.append(f'<div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:10px; border-left:3px solid {is_clr}"><div class="card-label" style="font-size:0.6rem; opacity:0.6">INDEX SELECTIVITY</div><div style="font-size:1.3rem; font-weight:800; color:{is_clr}; margin:0.3rem 0">{is_sel:,.1f}</div><div style="font-size:0.6rem; color:var(--text-secondary)">KEYS / RETURNED</div></div>')

                # FA: docsExamined / keysExamined (> 2 indicates document bloat vs index coverage)
                fa = row_data.get("fetch_amplification", 0)
                fa_clr = "var(--tier1)" if fa <= 1.1 else ("#fbbf24" if fa < 3 else "var(--error)")
                insights.append(f'<div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:10px; border-left:3px solid {fa_clr}"><div class="card-label" style="font-size:0.6rem; opacity:0.6">FETCH AMPLIFICATION</div><div style="font-size:1.3rem; font-weight:800; color:{fa_clr}; margin:0.3rem 0">{fa:,.1f}</div><div style="font-size:0.6rem; color:var(--text-secondary)">DOCS / KEYS</div></div>')

                # WA: Mutated Keys / Total Doc Mutations (> 10 indicates index heavy workload)
                wa = row_data.get("workload_amplification", 0)
                wa_clr = "var(--tier1)" if wa < 5 else ("#fbbf24" if wa < 10 else "var(--error)")
                ins_a, upd_a, del_a = row_data.get("ins_amp", 0), row_data.get("upd_amp", 0), row_data.get("del_amp", 0)
                
                insights.append(f'''
                <div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:10px; border-left:3px solid {wa_clr}">
                    <div class="card-label" style="font-size:0.6rem; opacity:0.6">WORKLOAD AMPLIFICATION</div>
                    <div style="font-size:1.3rem; font-weight:800; color:{wa_clr}; margin:0.3rem 0">{wa:,.1f}</div>
                    <div style="font-size:0.6rem; color:var(--text-secondary); display:flex; gap:8px">
                        <span>ins:{ins_a:,.1f}</span>
                        <span>upd:{upd_a:,.1f}</span>
                        <span>del:{del_a:,.1f}</span>
                    </div>
                </div>''')

                return f'<div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:1rem; margin-top:2rem">{"".join(insights)}</div>'

            insights_html = render_clinical_insights(row)
            
            def render_f_row(k, d1, d2, force_show=False):
                v1, v2 = d1.get(k, 0), d2.get(k, 0)
                
                # 🧪 Zero-Value Suppression (v3.2.0)
                # If neither sample has a value, hide the row unless force_show is set.
                if not force_show:
                    def is_falsy(v):
                        return not v or v == 0 or str(v).lower() in ["0", "0ms", "0.0ms", "0 b"]
                    if is_falsy(v1) and is_falsy(v2): return ""

                def apply_format(val, key):
                    if not isinstance(val, (int, float)): return val
                    m_type = METRIC_TYPE.get(key)
                    if not m_type:
                        if 'Micros' in key: m_type = 'us'
                        elif 'Millis' in key: m_type = 'ms'
                        elif 'bytes' in key or 'Bytes' in key: m_type = 'bytes'
                        else: return f"{val:,}" if isinstance(val, int) else f"{val:.2f}"
                    if m_type == 'ns': return format_duration(val / 1000000.0)
                    if m_type == 'us': return format_duration(val / 1000.0)
                    if m_type == 'ms': return format_duration(val)
                    if m_type == 'bytes': return format_bytes(val)
                    return f"{val:,}"
                f1, f2 = apply_format(v1, k), apply_format(v2, k)
                c1, c2 = ("f-val-fast", "") if str(v1) != str(v2) else ("", "f-val-slow")
                label = FIELD_DISPLAY.get(k, k)
                source = METRIC_SOURCES.get(k, k)
                return f'<tr><td class="f-label" title="Source: {source}">{label}</td><td class="f-val {c1}">{f1}</td><td class="f-val {c2}">{f2}</td></tr>'

            def render_category(label, fields, row_data):
                content = f'<tr class="cat-header"><td colspan="3">{label}</td></tr>'
                count = 0
                for k in fields:
                    line = render_f_row(k, row_data.get('min_forensic', {}), row_data.get('max_forensic', {}))
                    if not line: line = render_f_row(k, row_data.get('min_waits', {}), row_data.get('max_waits', {}))
                    if line: content += line; count += 1
                return content if count > 0 else ""

            # 🧪 Surgical Visibility Guards (v3.1.0)
            # 🧪 Surgical Visibility Guards (v3.2.0): Dynamic categories from registry
            metrics_content = ""
            for cat in METRIC_CATEGORIES:
                fields = [m["id"] for m in METRIC_REGISTRY if m["category"] == cat]
                metrics_content += render_category(cat, fields, row)
            
            # 🧪 Surgical Visibility Guard Refinement (v3.2.0)
            # Only show forensic card if there is non-zero content OR wall-clock latency > 0
            has_metrics = len(metrics_content) > 0 or row.get("max_time", 0) > 0
            l_panel = ""
            if has_metrics:
                l_panel = f'<table class="forensic-table"><thead><tr><th>INDUSTRIAL DIAGNOSTIC</th><th>🥊 FASTEST SAMPLE</th><th>🐢 SLOWEST SAMPLE</th></tr></thead><tbody>'
                l_panel += f'<tr><td class="f-label" title="Wall-Clock duration of the operation">Wall-Clock Latency</td><td class="f-val-fast" style="color:var(--tier1)">{format_duration(row.get("min_time", 0))}</td><td class="f-val-slow" style="color:var(--error)">{format_duration(row.get("max_time", 0))}</td></tr>'
                l_panel += metrics_content
                l_panel += "</tbody></table>"
            
            pm1, pm2 = row.get("min_query_params", {}), row.get("max_query_params", {})
            has_params = len(pm1) > 0 or len(pm2) > 0
            r_panel = ""
            if has_params:
                r_panel = f'<table class="forensic-table"><thead><tr><th>EXTRACTED FIELD</th><th>🥊 VALUE</th><th>🐢 VALUE</th></tr></thead><tbody>'
                # For query parameters, always force show even if value is "0" as it is structural identity
                for k in sorted(list(set(pm1.keys()) | set(pm2.keys()))): r_panel += render_f_row(k, pm1, pm2, force_show=True)
                r_panel += "</tbody></table>"
            
            schema_tags = "".join([f'<span class="tag-info" style="margin-left:8px; margin-bottom:4px">{f}</span>' for f in row.get("query_schema", [])])
            fast_json = json.dumps(row.get('min_peek_attr') or {}, indent=2)
            slow_json = json.dumps(row.get('max_peek_attr') or {}, indent=2)

            # Build optional columns based on view type
            if is_system_view:
                extra_cols = f"""<td>{chips}</td><td style="font-size:0.75rem;color:var(--text-secondary)">{row.get('app_name', 'unknown')}</td><td style="font-family:monospace;font-size:0.75rem;opacity:0.7">{row.get('plan_summary', 'N/A')}</td>"""
                colspan_val = "11"
                aas_load_col = f"""<td class="impact-container"><div class="card-label" style="font-size:0.7rem;margin-bottom:2px">{row.get('aas_load', 0)} load</div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:{l_wid}%"></div></div><div style="font-size:0.7rem;color:var(--accent);font-weight:700;margin-top:2px">{l_pct}%</div></td>"""
            elif is_timeout_view:
                hash_val = row.get('query_shape_hash', 'N/A')
                short_hash = hash_val[:12] + '...' if len(hash_val) > 12 else hash_val
                extra_cols = f"""<td style="font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:var(--accent)">{short_hash}</td><td style="font-size:0.75rem;color:var(--accent)">{ns_display}</td><td style="font-size:0.75rem;color:var(--text-secondary)">{row.get('app_name', 'unknown')}</td>"""
                colspan_val = "7"
                aas_load_col = ""
            else:
                extra_cols = f"""<td>{chips}</td><td style="font-size:0.75rem;color:var(--text-secondary)">{row.get('app_name', 'unknown')}</td><td style="font-family:monospace;font-size:0.75rem;opacity:0.7">{row.get('plan_summary', 'N/A')}</td>"""
                colspan_val = "11"
                aas_load_col = f"""<td class="impact-container"><div class="card-label" style="font-size:0.7rem;margin-bottom:2px">{row.get('aas_load', 0)} load</div><div class="stat-bar-bg"><div class="stat-bar-fill" style="width:{l_wid}%"></div></div><div style="font-size:0.7rem;color:var(--accent);font-weight:700;margin-top:2px">{l_pct}%</div></td>"""

            if is_timeout_view:
                t_cnt = row.get('count', 0)
                e_cnt = row.get('error_count', 0)
                e_code = row.get("error_code") or (row.get("max_forensic", {}).get("errCode")) or ("50" if t_cnt > 0 else "N/A")
                e_name = row.get("error_name") or (row.get("max_forensic", {}).get("errName")) or ("MaxTimeMSExpired" if t_cnt > 0 else "UnknownError")
                if e_name == "UnknownError" and isinstance(e_code, int) and e_code in ERROR_CODE_MAP:
                    e_name = ERROR_CODE_MAP[e_code]
                
                e_desc = e_name.replace(f" ({e_code})", "").replace(f" {e_code}", "")
                code_html = f'<span style="font-family:\'JetBrains Mono\'; font-weight:700; color:{ "var(--tier6)" if t_cnt > 0 else "var(--tier4)" }">{e_code}</span>'
                desc_html = f'<span style="font-weight:700; color:var(--text-primary)">{e_desc}</span>'
                if t_cnt > 0: desc_html = f'🚨 {desc_html}'
                elif e_cnt > 0: desc_html = f'☢️ {desc_html}'

                rows += f'''<tr class="row-main" onclick="toggleDetails('{did}')"><td>{row.get('row', i+1)}</td><td>{code_html}</td><td>{desc_html}</td><td>{row.get('count', 0):,}</td>{extra_cols}</tr>\n'''
            else:
                rows += f'''<tr class="row-main" onclick="toggleDetails('{did}')"><td>{row.get('row', i+1)}</td><td><span class="badge" style="background:#1e293b;border:1px solid var(--border);color:var(--accent);padding:0.2rem 0.5rem;border-radius:4px;font-size:0.72rem;font-weight:700">{row.get('category', 'N/A')}</span></td><td>{format_duration(row.get('avg_time', 0))}</td><td><strong>{format_duration(row.get('max_time', 0))}</strong></td><td>{row.get('count', 0):,}</td>{aas_load_col}<td>{format_duration(row.get('total_ms', 0))}</td><td style="color:var(--text-secondary);font-weight:600">{ns_display}</td>{extra_cols}</tr>\n'''
            
            schema_col = ""
            if schema_tags:
                schema_col = f"""
                    <div style="flex:1; text-align:right">
                        <div class="card-label" style="font-size:0.65rem; color:var(--text-secondary); letter-spacing:0.1em">DISCOVERED QUERY SCHEMA</div>
                        <div style="display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end; margin-top:0.4rem">{schema_tags}</div>
                    </div>"""

            forensic_grid = ""
            if has_metrics or has_params:
                grid_style = "grid-template-columns: 1.2fr 1fr;"
                if not has_metrics or not has_params: grid_style = "grid-template-columns: 1fr;"
                
                l_col = f"""<div><div class="card-label" style="color:var(--text-primary); display:flex; align-items:center; gap:8px; font-size:0.75rem"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> FORENSIC EXECUTION METRICS</div>{l_panel}</div>""" if has_metrics else ""
                r_col = f"""<div><div class="card-label" style="color:var(--text-primary); display:flex; align-items:center; gap:8px; font-size:0.75rem"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg> EXTRACTED QUERY PARAMETERS</div>{r_panel}</div>""" if has_params else ""
                
                forensic_grid = f"""<div class="comparison-grid" style="margin-top:3rem; {grid_style}">{l_col}{r_col}</div>"""

            rows += f'''<tr id="{did}" class="details-row"><td colspan="{colspan_val}"><div class="details-content">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:2.5rem; border-bottom:1px solid rgba(255,255,255,0.05); padding-bottom:1.5rem;">
                    <div style="flex:1">
                        <div class="card-label" style="font-size:0.65rem; color:var(--text-secondary); letter-spacing:0.1em">QUERY SHAPE HASH</div>
                        <div style="color:{'var(--text-secondary)' if row.get('query_shape_hash') == 'N/A' else 'var(--accent)'}; font-family:'JetBrains Mono'; font-size:0.85rem; margin-top:0.4rem">{row.get('query_shape_hash', 'N/A')}</div>
                    </div>
                    {schema_col}
                </div>
                <div class="card-label" style="font-size:0.65rem; color:var(--text-secondary); letter-spacing:0.1em; margin-bottom:1rem">LATENCY FINGERPRINT (WORKLOAD WAVE)</div>
                <div class="dist-bar" style="height:26px">{wave_html}</div>
                <div class="legend-grid" style="margin-top:0.8rem">{legend_html}</div>
                
                <div class="card-label" style="color:var(--text-primary); display:flex; align-items:center; gap:8px; font-size:0.75rem; margin-top:3rem"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg> 🧪 CLINICAL INSIGHTS</div>
                {insights_html}

                {forensic_grid}
                <div class="comparison-grid" style="margin-top:3rem; grid-template-columns: 1fr 1fr;">
                    <div>
                        <div class="card-label" style="display:flex; align-items:center; gap:20px;">
                            <span>💨 Fastest Payload</span>
                            <div style="display:flex; align-items:center; gap:12px">
                                <div style="font-family:'JetBrains Mono'; font-size:0.65rem; color:var(--text-secondary); background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:4px">TS: {row.get('min_ts', 'unknown')}</div>
                                <button class="btn-copy" onclick="copyToClipboard('payload-fast-{start_idx + i}', this)">COPY JSON</button>
                            </div>
                        </div>
                        <pre id="payload-fast-{start_idx + i}" class="payload-pre" style="background:#000000; padding:1.5rem; border-radius:12px; font-size:0.72rem; overflow:auto; max-height:450px; border:1px solid var(--border); color:#a1a1aa; margin-top:0.5rem">{fast_json}</pre>
                    </div>
                    <div>
                        <div class="card-label" style="display:flex; align-items:center; gap:20px;">
                            <span>🐢 Slowest Payload</span>
                            <div style="display:flex; align-items:center; gap:12px">
                                <div style="font-family:'JetBrains Mono'; font-size:0.65rem; color:var(--text-secondary); background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:4px">TS: {row.get('max_ts', 'unknown')}</div>
                                <button class="btn-copy" onclick="copyToClipboard('payload-slow-{start_idx + i}', this)">COPY JSON</button>
                            </div>
                        </div>
                        <pre id="payload-slow-{start_idx + i}" class="payload-pre" style="background:#000000; padding:1.5rem; border-radius:12px; font-size:0.72rem; overflow:auto; max-height:450px; border:1px solid var(--border); color:#a1a1aa; margin-top:0.5rem">{slow_json}</pre>
                    </div>
                </div>
            </div></td></tr>'''
        return rows

    rows_html = render_summary_rows(summary, 0)
    system_rows_html = render_summary_rows(system_summary, 1000, is_system_view=True)
    timeout_forensic_rows_html = render_summary_rows(timeout_summary, 2000, is_timeout_view=True)

    # 📚 Forensic Knowledge Base: Diagnostic Decoder (v2.7.0)
    diag_rows = []
    for r in rules_glossary:
        # 🕵️ Senior Logic: Extract the best 'Internal Trigger' description
        trigger = r.get('technical_path') or r.get('condition') or "Complex Logic"
        diag_rows.append(f"""
            <tr>
                <td style="color:var(--accent); font-weight:700">🔍 {r['id']}</td>
                <td style="font-family:'JetBrains Mono'; font-size:0.75rem">{trigger}</td>
                <td style="color:var(--text-secondary)">{r.get('description', 'Expert diagnostic rule.')}</td>
            </tr>
        """)

    # 📐 Metric Source Registry (v3.2.0): Fully Dynamic Reference Grid
    metric_rows = []
    # Group registry by category for the reference tab
    for cat in METRIC_CATEGORIES:
        cat_metrics = [m for m in METRIC_REGISTRY if m["category"] == cat]
        if not cat_metrics: continue
        
        metric_rows.append(f'<div style="grid-column: 1 / -1; margin-top: 1.5rem; color:var(--accent); font-weight:700; font-size:0.8rem">{cat} Metrics</div>')
        for m in cat_metrics:
            m_label = m["label"]
            m_src = m["source"]
            m_desc = m.get("description", "Primary telemetry field for resource bottleneck analysis.")
            metric_rows.append(f"""
                <div style="padding:1rem; border:1px solid var(--border); border-radius:8px; background:rgba(255,255,255,0.02)">
                    <h4 style="color:var(--text-primary); margin-bottom:0.4rem; font-size:0.9rem">{m_label}</h4>
                    <div style="font-family:'JetBrains Mono'; font-size:0.7rem; color:var(--accent); margin-bottom:0.5rem">{m_src}</div>
                    <p style="color:var(--text-secondary); font-size:0.8rem">{m_desc}</p>
                </div>
            """)

    final_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🐦 logpeck Forensic MongoDB Log Analytics</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Outfit:wght@600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            /* 🎨 Industrial Design Tokens (v1.1.5)
               High-contrast dark mode with MongoDB-native emerald accent. */
            --bg: #0b111a; --card-bg: #151e29; --text-primary: #e1e7ef; --text-secondary: #94a3b8;
            --accent: #00ed64; --border: #1e293b; --header-bg: #112028;
            --error: #ef4444; --warn: #ff9900; --success: #00ed64;
            --info: #38bdf8; --warning: #f97316; --critical: #f87171;
            --tier1: #00ed64; --tier2: #00684A; --tier3: #84CC16; --tier4: #FEC20B; --tier5: #EA580C; --tier6: #991B1B; --tier7: #EF4444;
        }}
        body {{ font-family: 'Inter', sans-serif; background-color: var(--bg); color: var(--text-primary); margin: 0; padding: 2rem; line-height: 1.5; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
        h1 {{ font-family: 'Outfit', sans-serif; font-size: 2rem; margin: 0; display: flex; align-items: center; gap: 10px; }}
        .badge {{ background: var(--accent); color: var(--bg); padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.8rem; font-weight: 700; }}
        
        .tabs {{ display: flex; gap: 0.5rem; margin-bottom: 2rem; border-bottom: 1px solid var(--border); }}
        .tab {{ padding: 1rem 2rem; cursor: pointer; font-weight: 600; color: var(--text-secondary); border-bottom: 3px solid transparent; transition: all 0.2s; border-top-left-radius: 8px; border-top-right-radius: 8px; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        .tab:hover {{ color: var(--text-primary); background: #ffffff05; }}
        .tab.active {{ color: var(--accent); border-bottom-color: var(--accent); background: #00ed640a; }}
        .tab-content {{ display: none; }} .tab-content.active {{ display: block; }}

        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: var(--card-bg); border: 1px solid var(--border); padding: 1.5rem; border-radius: 12px; }}
        .card-label {{ color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.8rem; font-weight: 700; }}
        .card-value {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); font-family: 'Outfit'; }}

        table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 12px; overflow: hidden; border: 1px solid var(--border); table-layout: auto; }}
        th {{ background: #0f172a; text-align: left; padding: 1rem; font-size: 0.65rem; text-transform: uppercase; color: var(--text-secondary); border-bottom: 2px solid var(--border); letter-spacing: 0.1em; }}
        td {{ padding: 1rem; border-bottom: 1px solid var(--border); font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; }}
        
        .row-main:hover {{ background: rgba(255,255,255,0.02); cursor: pointer; }}
        .details-row {{ display: none; background: #0c121d; }}
        .details-content {{ padding: 2.5rem; border-left: 6px solid var(--accent); }}

        .dist-bar {{ width: 100%; display: flex; border-radius: 6px; overflow: hidden; margin: 1rem 0; background: #1e293b; }}
        .stat-bar-bg {{ width: 100%; height: 10px; background: #1e293b; border-radius: 5px; overflow: hidden; }}
        .stat-bar-fill {{ height: 100%; background: var(--accent); border-radius: 5px; }}
        
        .legend-grid {{ display: flex; gap: 18px; margin-bottom: 2rem; flex-wrap: wrap; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 0.7rem; color: var(--text-secondary); font-weight: 600; }}
        .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}

        .forensic-table {{ background: transparent; border: none; width: 100%; margin-top: 1rem; table-layout: auto; }}
        .forensic-table th {{ background: transparent; border-bottom: 1px solid rgba(255,255,255,0.05); padding: 0.8rem 0; font-size:0.6rem; color:var(--text-secondary); letter-spacing:0.05em; }}
        .forensic-table td {{ border: none; padding: 0.8rem 0; font-size: 0.82rem; }}
        .f-label {{ color: var(--text-secondary); font-weight: 600; }}
        .f-val {{ font-family: 'JetBrains Mono'; }}
        .f-val-fast {{ font-weight: 700; color: var(--accent); }}
        .f-val-slow {{ font-weight: 700; color: var(--text-primary); }}
        .cat-header td {{ color: var(--accent); font-weight: 800; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.12em; padding-top: 2rem; border-bottom: 1px solid rgba(0,237,100,0.1); }}

        .impact-container {{ width: 100px; display: flex; flex-direction: column; }}
        .comparison-grid {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 4rem; }}
        .comparison-grid > div {{ min-width: 0; }}
        .payload-pre {{ white-space: pre-wrap !important; word-break: break-all !important; overflow-wrap: break-word !important; }}
        .tag-info {{ background: #1e293b; color: var(--accent); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; border: 1px solid var(--border); }}
        .btn-copy {{ 
            cursor: pointer; 
            border: 1px solid var(--border); 
            background: #111827; 
            color: var(--text-secondary); 
            font-size: 0.6rem; 
            padding: 0.3rem 0.8rem; 
            border-radius: 6px; 
            font-weight: 700; 
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }}
        .btn-copy:hover {{ 
            background: #1f2937; 
            border-color: var(--accent); 
            color: var(--accent); 
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        .footer {{ margin-top: 5rem; text-align: center; color: var(--text-secondary); font-size: 0.8rem; padding-bottom: 3rem; opacity: 0.6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🐦 logpeck <span class="badge">Forensic Analytics {VERSION}</span></h1>
        <div style="text-align: right">
            <div class="card-label">Forensic Filter</div>
            <div style="font-weight: 700; color: var(--accent)">Latency >{threshold}ms</div>
        </div>
    </div>

    <div class="tabs">
        <div class="tab active" onclick="openTab('health', this)">🏥 Health Overview</div>
        <div class="tab" onclick="openTab('system', this)">🛠️ System Query Forensics</div>
        <div class="tab" onclick="openTab('slow', this)">🐢 Business Workload Forensics</div>
        <div class="tab" onclick="openTab('timeouts', this)">🚨 Failure Forensics</div>
        <div class="tab" onclick="openTab('connections', this)">🔌 Connection Analytics</div>
        <div class="tab" onclick="openTab('reference', this)">📚 Reference</div>
    </div>

    <div id="health" class="tab-content active">
        <div class="grid">
            {health_summary_html}
        </div>
        <div style="margin-bottom: 2rem">
            {bottleneck_radar_html}
        </div>
        <div style="margin-bottom:1.5rem">
            <input type="text" id="healthSearch" onkeyup="filterRows('healthSearch', 'healthContent')" placeholder="🔍 Filter hotspots, error patterns, or component workloads..." style="width:100%; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none; border-left:4px solid var(--accent)">
        </div>
        <div id="healthContent">
            <div class="comparison-grid">
                <div class="card"><div class="card-label">Severity Distribution</div><div style="margin-top:1.2rem">{severity_wave_html}</div></div>
                <div class="card"><div class="card-label">Component Workload</div><div style="margin-top:1.2rem">{component_wave_html}</div></div>
            </div>
            <div class="comparison-grid" style="margin-top:1.5rem">
                <div class="card"><div class="card-label">Top Active Namespaces</div><div style="margin-top:1.2rem">{ns_grid_html}</div></div>
                <div class="card"><div class="card-label">Top Message Patterns</div><div style="margin-top:1.2rem">{msg_grid_html}</div></div>
            </div>
        </div>
    </div>

    <div id="system" class="tab-content">
        <div style="margin-bottom:1.5rem; display:flex; gap:1rem; flex-wrap:wrap; align-items:center">
            <input type="text" id="systemSearch" onkeyup="filterRows('systemSearch', 'systemTable')" placeholder="🔍 Forensic search of background tasks, heartbeats, and admin commands..." style="flex:1; min-width:300px; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none; border-left:4px solid var(--warn)">
            <button class="badge" style="cursor:pointer; border:none; padding:0 1.5rem; height:42px" onclick="collapseAll()">COLLAPSE ALL</button>
        </div>
        <div id="systemContent">
            <div class="card" style="margin-top:1.5rem">
                <div class="card-label" style="color:var(--warn)">🧬 System Query Forensics (Infrastructure Telemetry)</div>
                <table id="systemTable">
                    <thead>
                        <tr>
                            <th style="width:40px">#</th>
                            <th style="width:80px">OP</th>
                            <th style="width:80px">Avg</th>
                            <th style="width:80px">Max</th>
                            <th style="width:80px">Count</th>
                            <th style="width:110px">AAS Load</th>
                            <th style="width:100px">Total MS</th>
                            <th style="width:220px">Namespace</th>
                            <th style="width:350px">Diagnostic</th>
                            <th style="width:180px">Component/App</th>
                            <th>Plan</th>
                        </tr>
                    </thead>
                    <tbody>
                        {system_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="timeouts" class="tab-content">
        <div style="margin-bottom:1.5rem; display:flex; gap:1rem; flex-wrap:wrap; align-items:center">
            <input type="text" id="timeoutSearch" onkeyup="filterRows('timeoutSearch', 'timeoutContent')" placeholder="🔍 Search connection timeouts and execution limits..." style="flex:1; min-width:300px; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none; border-left:4px solid var(--error)">
            <button class="badge" style="cursor:pointer; border:none; padding:0 1.5rem; height:42px" onclick="collapseAll()">COLLAPSE ALL</button>
        </div>
        <div id="timeoutContent">
            <div class="card">
                <div class="card-label" style="color:var(--warn)">📊 Executive Failure Summary (Error Code Distribution)</div>
                <p style="color:var(--text-secondary); font-size:0.8rem; margin-bottom:1.5rem">Systemic view of errors across all query shapes. Use this to identify global infrastructure bottlenecks.</p>
                {failure_summary_html}
            </div>

            <div class="card" style="margin-top:1.5rem">
                <div class="card-label" style="color:var(--error)">⚠️ Critical Timeout & Execution Limit Patterns (Pass 1)</div>
                {timeout_table_html}
            </div>
            <div class="card" style="margin-top:1.5rem">
                <div class="card-label" style="color:var(--error)">🚨 Detailed Timeout Forensics (Pass 2 Analysis)</div>
                <table id="timeoutTable">
                    <thead>
                        <tr>
                            <th style="width:40px">#</th>
                            <th style="width:80px">CODE</th>
                            <th style="width:250px">ERROR / DESCRIPTION</th>
                            <th style="width:70px">COUNT</th>
                            <th style="width:150px">SHAPE HASH</th>
                            <th style="width:220px">NAMESPACE</th>
                            <th style="width:200px">CONTEXT / APP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {timeout_forensic_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="slow" class="tab-content">
        <div style="margin-bottom:1.5rem; display:flex; gap:1rem; flex-wrap:wrap; align-items:center">
            <input type="text" id="slowSearch" onkeyup="filterRows('slowSearch', 'slowTable')" placeholder="🔍 Search by namespace, op, app, or hash..." style="flex:1; min-width:300px; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none; border-left:4px solid var(--accent)">
            <div style="display:flex; gap:0.5rem">
                {tier_buttons_html}
            </div>
            <button class="badge" style="cursor:pointer; border:none; padding:0 1.5rem; height:42px" onclick="collapseAll()">COLLAPSE ALL</button>
        </div>
        <table id="slowTable">
            <thead>
                <tr>
                    <th style="width:40px">#</th>
                    <th style="width:80px">OP</th>
                    <th style="width:80px">AVG</th>
                    <th style="width:80px">MAX</th>
                    <th style="width:80px">COUNT</th>
                    <th style="width:110px">AAS LOAD</th>
                    <th style="width:100px">TOTAL MS</th>
                    <th style="width:220px">NAMESPACE</th>
                    <th style="width:350px">DIAGNOSTIC</th>
                    <th style="width:180px">APPLICATION</th>
                    <th>PLAN</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <div id="connections" class="tab-content">
        <div style="margin-bottom:1.5rem">
            <input type="text" id="connSearch" onkeyup="filterRows('connSearch', 'connTable')" placeholder="🔍 Search connection metadata..." style="width:100%; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none;">
        </div>
        <div class="grid">{conn_summary_html}</div>
        <div class="comparison-grid">
            <div class="card"><div class="card-label">Top Client Applications</div><div style="margin-top:1.2rem">{app_wave_html}</div></div>
            <div class="card"><div class="card-label">Top Client IPs</div><div style="margin-top:1.2rem">{ip_wave_html}</div></div>
        </div>
        <div class="comparison-grid" style="margin-top:1.5rem">
            <div class="card"><div class="card-label">Top DB Users</div><div style="margin-top:1.2rem">{user_wave_html}</div></div>
            <div class="card"><div class="card-label">App → Driver Mapping</div><div style="margin-top:1.2rem">{driver_mapping_html}</div></div>
        </div>
    </div>

    <div id="reference" class="tab-content">
        <div style="margin-bottom:1.5rem">
            <input type="text" id="refSearch" onkeyup="filterRows('refSearch', 'referenceContent')" placeholder="🔍 Search diagnostic rules or metric sources..." style="width:100%; padding:1rem; border-radius:12px; border:1px solid var(--border); background:var(--card-bg); color:var(--text-primary); outline:none; border-left:4px solid var(--accent)">
        </div>
        
        <div id="referenceContent">
            <div class="card" style="margin-bottom:2rem; border-left: 4px solid #00ED64">
                <div class="card-label" style="color:#00ED64">🌐 External Documentation</div>
                <div style="margin-top:1rem; font-size:0.9rem">
                    For a complete list of all MongoDB error codes and their internal meanings, refer to the official 
                    <a href="https://www.mongodb.com/docs/manual/reference/error-codes/" target="_blank" style="color:var(--accent); text-decoration:none; font-weight:700">MongoDB Error Code Reference</a>.
                </div>
            </div>

            <div class="card">
                <div class="card-label" style="color:var(--accent)">🚦 Forensic Diagnostic Decoder (v1.3.10)</div>
                <p style="color:var(--text-secondary); margin-top:1rem; font-size:0.9rem">Expert-curated conditions and forensic significance for every query tag the engine generates.</p>
                <table style="margin-top:1.5rem; width:100%; table-layout: auto">
                    <thead><tr><th style="width:180px">TAG</th><th>INTERNAL TRIGGER CONDITION</th><th>FORENSIC SIGNIFICANCE</th></tr></thead>
                    <tbody>
                        {"".join(diag_rows)}
                    </tbody>
                </table>
            </div>

            <div class="card" style="margin-top:2rem">
                <div class="card-label" style="color:#00ED64">📊 Impact Metrics</div>
                <table style="margin-top:1.5rem; width:100%; table-layout: auto">
                    <thead><tr><th style="width:120px">METRIC</th><th>DEFINITION & DERIVATION</th></tr></thead>
                    <tbody>
                        <tr><td style="font-weight:700">Load<br><span style="color:var(--text-secondary);font-weight:normal;font-size:0.85rem">(AAS)</span></td><td><strong style="color:var(--text-primary)">Average Active Sessions.</strong> Derived as <code style="font-family:'JetBrains Mono', monospace;background:rgba(0,0,0,0.2);padding:0.2rem 0.4rem;border-radius:4px">Shape Latency / Wall-Clock Duration</code>.<br><span style="color:var(--text-secondary);font-size:0.85rem;display:block;margin-top:0.6rem">Describes the 'resource pressure'. A load of 1.0 means this query type occupies 1 full CPU core's capacity on average during the log window.</span></td></tr>
                        <tr><td style="font-weight:700">Impact<br><span style="color:var(--text-secondary);font-weight:normal;font-size:0.85rem">(%)</span></td><td><strong style="color:var(--text-primary)">Global Cluster Impact.</strong> Derived as <code style="font-family:\'JetBrains Mono\', monospace;background:rgba(0,0,0,0.2);padding:0.2rem 0.4rem;border-radius:4px">(Query Active Time / Global Cluster Active Time) * 100</code>.<br><span style="color:var(--text-secondary);font-size:0.85rem;display:block;margin-top:0.6rem">Provides a unified view of resource consumption. Higher % = the query is a dominant contributor to total cluster load across ALL tabs (Business + System + Failure).</span></td></tr>
                        <tr><td style="font-weight:700">Scan<br>Efficiency</td><td><strong style="color:var(--text-primary)">Inspection Ratio.</strong> Derived as <code style="font-family:\'JetBrains Mono\', monospace;background:rgba(0,0,0,0.2);padding:0.2rem 0.4rem;border-radius:4px">docsExamined / nreturned</code>.<br><span style="color:var(--text-secondary);font-size:0.85rem;display:block;margin-top:0.6rem">Ideally close to 1.0. High ratios (> 1000) confirm the query is performing expensive collections scans rather than targeted index lookups.</span></td></tr>
                        <tr><td style="font-weight:700">Workload<br>Amplification</td><td><strong style="color:var(--text-primary)">Mutation Overhead.</strong> Derived as <code style="font-family:\'JetBrains Mono\', monospace;background:rgba(0,0,0,0.2);padding:0.2rem 0.4rem;border-radius:4px">(Index Mutations) / (Document Mutations)</code>.<br><span style="color:var(--text-secondary);font-size:0.85rem;display:block;margin-top:0.6rem">Measures the I/O cost of each write. Calculated using (keysInserted+Deleted+Updated) vs (ninserted+Modified+deleted+upserted). Ratios > 10.0 signal the collection is over-indexed for the write workload.</span></td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card" style="margin-top:2rem">
                <div class="card-label" style="color:var(--accent)">📐 Metric Source Matrix</div>
                <p style="color:var(--text-secondary); margin-top:1rem; font-size:0.9rem">Total transparency: Mapping dashboard metrics back to raw MongoDB documentation paths.</p>
                <div style="margin-top:1.5rem; display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:1rem">
                    {"".join(metric_rows)}
                </div>
            </div>

            <div class="card" style="margin-top:2rem">
                <div class="card-label" style="color:var(--accent)">🧬 Forensic Bottleneck Radar Methodology (v2.6.12)</div>
                <p style="color:var(--text-secondary); margin-top:1rem; font-size:0.9rem">The Radar provides a <strong>weighted distribution</strong> of cluster-wide wait times across all analyzed operations. It is designed to identify the primary resource bottleneck (e.g., are we CPU-bound or Concurrency-bound?).</p>
                <table style="margin-top:1.5rem; width:100%; table-layout: auto">
                    <thead><tr><th style="width:160px">RADAR SEGMENT</th><th style="width:250px">RAW LOG FIELD(S)</th><th>TECHNICAL BOTTLENECK CONTEXT</th></tr></thead>
                    <tbody>
                        <tr><td style="font-weight:700; color:#3B82F6">I/O Wait</td><td><code>attr.locks.StorageWait</code></td><td>Time spent waiting for the physical disk subsystem (paging, journal commits, or cold-cache reads).</td></tr>
                        <tr><td style="font-weight:700; color:#10B981">CPU Time</td><td><code>Derived Delta</code></td><td>The <em>True Execution Time</em> where the thread was active. Calculated as <code style="font-size:0.75rem">Duration - (Sum of all wait components)</code>.</td></tr>
                        <tr><td style="font-weight:700; color:#F59E0B">Storage Wait</td><td><code>Cumulative Storage wait</code></td><td>High-level storage engine throttling, flow control, or metadata synchronization delays.</td></tr>
                        <tr><td style="font-weight:700; color:#EF4444">Oplog Slot Wait</td><td><code>totalOplogSlotDurationMicros</code></td><td>A <strong>write-concurrency bottleneck</strong>. Occurs during high-throughput writes as operations wait for a slot in the oplog.</td></tr>
                        <tr><td style="font-weight:700; color:#EC4899">Queue Wait</td><td><code>totalTimeQueuedMicros</code></td><td><strong>Admission Control Bottleneck</strong>. Time spent in the global execution queue waiting for an available execution ticket.</td></tr>
                        <tr><td style="font-weight:700; color:#8B5CF6">Lock Wait</td><td><code>timeAcquiringMicros</code></td><td>Contention for database, collection, or document-level locks.</td></tr>
                    </tbody>
                </table>
                <div style="margin-top:1rem; padding:1rem; background:rgba(255,255,255,0.03); border-radius:8px; border-left:4px solid var(--accent)">
                    <div class="card-label" style="font-size:0.7rem; color:var(--text-secondary)">CALCULATION ENGINE</div>
                    <div style="font-size:0.85rem; color:var(--text-primary); margin-top:0.4rem">Percentage = <code>(Σ Component_Value / Σ Total_Cluster_Wait) * 100</code></div>
                    <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.4rem">Historical wait fields are harvested from the <code>attr</code> and <code>attr.locks</code> BSON segments of each log line.</div>
                </div>
            </div>

            <div class="card" style="margin-top:2rem">
                <div class="card-label" style="color:var(--accent)">⏱️ Latency Workload Wave (7-Tier Tiers)</div>
                <table style="margin-top:1.5rem; width:100%; table-layout: auto">
                    <thead><tr><th>TIER</th><th>RANGE</th><th>HEX</th><th>VISUAL</th></tr></thead>
                    <tbody>
                        <tr><td>Tier 1</td><td>100ms+</td><td><code>#00ED64</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#00ED64"></div></td></tr>
                        <tr><td>Tier 2</td><td>250ms+</td><td><code>#00684A</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#00684A"></div></td></tr>
                        <tr><td>Tier 3</td><td>500ms+</td><td><code>#84CC16</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#84CC16"></div></td></tr>
                        <tr><td>Tier 4</td><td>1000ms+</td><td><code>#FEC20B</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#FEC20B"></div></td></tr>
                        <tr><td>Tier 5</td><td>2000ms+</td><td><code>#EA580C</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#EA580C"></div></td></tr>
                        <tr><td>Tier 6</td><td>5000ms+</td><td><code>#991B1B</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#991B1B"></div></td></tr>
                        <tr><td>Tier 7</td><td>10000ms+</td><td><code>#EF4444</code></td><td><div style="width:80px; height:8px; border-radius:4px; background:#EF4444"></div></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>


    <script>
        function toggleDetails(id) {{ const el = document.getElementById(id); if(!el) return; el.style.display = (el.style.display === 'table-row' || el.style.display === 'block') ? 'none' : (el.tagName === 'TR' ? 'table-row' : 'block'); }}
        function openTab(name, el) {{ document.querySelectorAll('.tab-content').forEach(t => {{ t.classList.remove('active'); t.style.display = 'none'; }}); document.querySelectorAll('.tab').forEach(t => t.classList.remove('active')); var target = document.getElementById(name); if(target) {{ target.classList.add('active'); target.style.display = 'block'; }} el.classList.add('active'); }}
        function filterRows(inputId, containerId) {{
            const input = document.getElementById(inputId), filter = input.value.toLowerCase(), container = document.getElementById(containerId);
            if(!container) return;
            const trs = container.getElementsByTagName("tr");
            for (let i = 0; i < trs.length; i++) {{
                const row = trs[i];
                if (row.classList.contains('cat-header') || row.parentElement.tagName === 'THEAD' || row.classList.contains('details-row')) continue;
                row.style.display = row.textContent.toLowerCase().includes(filter) ? "" : "none";
            }}
        }}
        function filterByTier(minMs) {{
            document.querySelectorAll('#slowTable .row-main').forEach(row => {{
                const maxMsText = row.cells[3].textContent;
                const ms = parseFloat(maxMsText) * (maxMsText.includes('s') && !maxMsText.includes('ms') ? 1000 : 1);
                const matches = ms >= minMs;
                row.style.display = matches ? "" : "none";
                if (!matches) {{
                    const dId = row.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
                    if (dId && document.getElementById(dId)) document.getElementById(dId).style.display = 'none';
                }}
            }});
        }}
        function collapseAll() {{ document.querySelectorAll('.details-row').forEach(r => r.style.display = 'none'); }}
        function copyToClipboard(id, btn) {{
            const text = document.getElementById(id).textContent;
            navigator.clipboard.writeText(text).then(() => {{
                const original = btn.textContent;
                btn.textContent = 'COPIED!'; btn.style.background = '#059669';
                setTimeout(() => {{ btn.textContent = original; btn.style.background = ''; }}, 2000);
            }});
        }}
    </script>
    <div class="footer">Generated by <strong>logpeck v{VERSION}</strong> | Forensic MongoDB Log Analytics</div>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f: f.write(final_html)
