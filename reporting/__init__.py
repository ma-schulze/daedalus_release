"""
HTML Reporting Module for Symbolic Execution Results

This module provides functionality to generate HTML reports for symbolic execution
analysis, including detected bugs, constraints, and solved input values.
"""

from .report_generator import init_report, add_detected_bug, finalize_report, update_stats, add_syscall_stats, add_function_coverage, update_block_coverage, add_stub_function
from .symbol_resolver import resolve_backtrace_with_symbols

__all__ = ['init_report', 'add_detected_bug', 'finalize_report', 'update_stats', 'add_syscall_stats', 'add_function_coverage', 'update_block_coverage', 'add_stub_function', 'resolve_backtrace_with_symbols']

