"""
Memory module for Trusted Application memory management.

This module provides utilities for managing TA memory operations during symbolic execution.
"""

from .ta_memory_mixin import TAMemoryMixin
from .ta_memory import TAMemory
from .ta_memory_filler import TAMemoryFillerMixin
from .ta_taint import get_trusted_mem_bits
from .ta_taint import get_tainted_mem_bits
from .ta_taint import is_tainted
from .ta_taint import is_trusted


__all__ = [
    'TAMemoryMixin',
    'TAMemory',
    'TAMemoryFillerMixin',
    'get_tainted_mem_bits',
    'get_trusted_mem_bits',
    'is_tainted',
    'is_trusted',
]

