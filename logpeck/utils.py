# ==============================================================================
# logpeck: utils.py
# Shared Forensic Utilities & Precision Formatters.
# ==============================================================================
# This module provides the infrastructure for consistent data presentation 
# across the CLI and HTML reports. It manages:
# 1. High-Precision Duration Formatting (Microsecond & Nanosecond support).
# 2. IEC Metric Byte Formatting.
# 3. Clinical Severity Indicators (Scan Efficiency logic).
# ==============================================================================

from typing import Any

def format_duration(ms: float) -> str:
    """
    Standardized duration formatter with ultra-high resolution.
    
    In MongoDB forensics, events can span from Pico-seconds (rare) to Minutes.
    This function automatically scales the unit to provide the most 
    human-readable context while preserving technical accuracy.
    """
    if ms == 0: return "0ms"
    # Pico / Nano / Micro / Milli scaling ( Support)
    if ms < 0.000001: return f"{int(ms * 1000000000)}ps"
    if ms < 0.001: return f"{int(ms * 1000000)}ns"
    if ms < 1: return f"{int(ms * 1000)}µs"
    if ms < 1000: return f"{ms:.1f}ms"
    
    sec = ms / 1000
    if sec < 60: return f"{sec:.1f}s"
    return f"{int(sec // 60)}m {int(sec % 60)}s"

def format_bytes(b: float) -> str:
    """
    Standardized IEC Byte Formatter.
    Scales from Bytes to Petabytes based on magnitude.
    """
    if not isinstance(b, (int, float)) or b == 0: return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def format_metric_value(key: str, val: Any) -> str:
    """
    The Unified Metric Valuation Engine.
    
    Dispatches raw forensic numbers to the appropriate unit formatter
    based on the METRIC_TYPE registry defined in specification.py.
    """
    from .specification import METRIC_TYPE
    m_type = METRIC_TYPE.get(key)
    
    if val is None: return "N/A"
    
    # Surgical Unit Mapping
    if m_type == "ms":
        return format_duration(val)
    elif m_type == "us":
        return format_duration(val / 1000.0) # Scale micro to milli for formatter
    elif m_type == "ns":
        return format_duration(val / 1000000.0) # Scale nano to milli for formatter
    elif m_type == "bytes":
        return format_bytes(val)
    
    # Defaults for counts/integers (Standardized thousands separator)
    if isinstance(val, int):
        return f"{val:,}"
    return str(val)

def get_scan_efficiency_color(keys: int, returned: int) -> str:
    """
    The Clinical Severity Profiler for Scan Efficiency.
    
    Calculates the 'Gossip Ratio' (Examined vs Returned) and assigns a 
    color code based on industry-standard MongoDB performance thresholds.
    """
    from .specification import THRESHOLD_SCAN_RATIO
    
    # Edge Case: Scan with 0 results is a 'Critical Blind Scan' if many keys were hit.
    if returned == 0: 
        return "red" if keys > 0 else "green"
    
    ratio = keys / returned
    
    # Severity Tiers:
    # Yellow (T)   : Marginal inefficiency (e.g., IXSCAN on non-prefix fields).
    # Red (T * 10) : Critical inefficiency (e.g., COLLSCAN or highly non-selective IXSCAN).
    if ratio > THRESHOLD_SCAN_RATIO * 10: return "red"
    if ratio > THRESHOLD_SCAN_RATIO: return "yellow"
    return "green"
