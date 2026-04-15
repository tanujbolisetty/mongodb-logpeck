"""
logpeck: utils.py
Shared forensic utilities and human-readable formatters.
"""

from typing import Any


def format_duration(ms: float) -> str:
    """Standardized duration formatter with micro/nano resolution."""
    if ms == 0: return "0ms"
    if ms < 0.000001: return f"{int(ms * 1000000000)}ps"
    if ms < 0.001: return f"{int(ms * 1000000)}ns"
    if ms < 1: return f"{int(ms * 1000)}µs"
    if ms < 1000: return f"{ms:.1f}ms"
    sec = ms / 1000
    if sec < 60: return f"{sec:.1f}s"
    return f"{int(sec // 60)}m {int(sec % 60)}s"

def format_bytes(b: float) -> str:
    """Standardized byte formatter (IEC units)."""
    if not isinstance(b, (int, float)) or b == 0: return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def format_metric_value(key: str, val: Any) -> str:
    """
    Applies the standardized unit formatting based on the metric type registry.
    """
    from .specification import METRIC_TYPE
    m_type = METRIC_TYPE.get(key)
    
    if val is None: return "N/A"
    
    if m_type == "ms":
        return format_duration(val)
    elif m_type == "us":
        return format_duration(val / 1000.0)
    elif m_type == "ns":
        return format_duration(val / 1000000.0)
    elif m_type == "bytes":
        return format_bytes(val)
    
    # Defaults for counts/integers
    if isinstance(val, int):
        return f"{val:,}"
    return str(val)

def get_scan_efficiency_color(keys: int, returned: int) -> str:
    """
    Returns a severity color based on the scan efficiency (Examined vs Returned).
    """
    from .specification import THRESHOLD_SCAN_RATIO
    if returned == 0: 
        return "red" if keys > 0 else "green"
    ratio = keys / returned
    if ratio > THRESHOLD_SCAN_RATIO * 10: return "red"
    if ratio > THRESHOLD_SCAN_RATIO: return "yellow"
    return "green"
