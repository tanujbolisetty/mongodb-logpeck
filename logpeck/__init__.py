"""
logpeck: Forensic MongoDB Log Analytics.
Structural log analysis for performance troubleshooting and security audits.
"""

from .version import __version__
from .parser import parse_log_line, extract_log_metrics, is_system_query
from .analyzer import analyze_slow_queries
from .finder import search_logs, filter_logs

__author__ = "Logpeck Team"
