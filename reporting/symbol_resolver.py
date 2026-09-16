"""
Symbol Resolver Module

Resolves addresses to function names using the control flow graph (CFG) from
symbolic execution. Uses angr's CFG and knowledge base functions instead of
ELF symbol tables.
"""

import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# Add project root to path for standalone/subprocess execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logging_config import get_logger

logger = get_logger(__name__)


def get_function_for_addr(cfg: Any, addr: int) -> str:
    """
    Resolve an address to a function name using the CFG's knowledge base.

    Args:
        cfg: angr CFG object (CFGFast or CFGEmulated) with kb.functions
        addr: Binary offset / address (same space as CFG, typically base 0)

    Returns:
        Function name if the address falls within a known function, else "<unknown>"
    """
    if cfg is None or not getattr(cfg, "kb", None) or not getattr(cfg.kb, "functions", None):
        return "<unknown>"
    
    # First try to get the function by start address
    func = cfg.kb.functions.function(addr)
    if func is not None:
        return func.name or f"sub_{hex(func.addr)}"
    
    # dirty hack for thumb mode 
    func = cfg.kb.functions.function(addr | 1)
    if func is not None:
        return func.name or f"sub_{hex(func.addr)}"

    # Try to loop through all functions and find the one that contains the address
    for _func_addr, func in cfg.kb.functions.items():
        try:
            size = func.size
        except (TypeError, AttributeError):
            size = 0
        if size is None:
            size = 0
        if func.addr <= addr < func.addr + size:
            return func.name or f"sub_{hex(func.addr)}"

    return "<unknown>"


class CFGSymbolResolver:
    """
    Resolves addresses to function names using an angr CFG (control flow graph).
    """

    def __init__(self, cfg: Any):
        """
        Initialize the resolver with a CFG.

        Args:
            cfg: angr CFG object (from project.analyses.CFGFast or CFGEmulated)
        """
        self.cfg = cfg

    def resolve_address(self, address: int) -> Optional[str]:
        """
        Resolve an address (binary offset) to a function name.

        Args:
            address: The address to resolve (binary offset, same as CFG address space)

        Returns:
            Function name if found, None otherwise
        """
        name = get_function_for_addr(self.cfg, address)
        return name if name != "<unknown>" else None

    def resolve_backtrace(
        self, backtrace_addrs: List[int], mem_base: int
    ) -> List[Tuple[str, str]]:
        """
        Resolve a list of addresses to (address, function_name) tuples.

        Args:
            backtrace_addrs: List of addresses (as loaded in memory with mem_base)
            mem_base: The base address where the binary is loaded

        Returns:
            List of (hex_address, function_name) tuples
        """
        result = []
        for addr in backtrace_addrs:
            offset = addr - mem_base
            func_name = get_function_for_addr(self.cfg, offset)
            result.append((hex(addr), func_name))
        return result


def resolve_backtrace_with_symbols(
    backtrace_hex: List[str],
    binary_path: str,
    mem_base: int,
    cfg: Optional[Any] = None,
) -> List[Dict[str, str]]:
    """
    Resolve a backtrace to (address, function) entries using the CFG when available.

    Args:
        backtrace_hex: List of hex address strings
        binary_path: Path to the binary (used for report metadata; resolution uses cfg when provided)
        mem_base: The base address where the binary is loaded
        cfg: Optional angr CFG; when provided, addresses are resolved to function names via CFG

    Returns:
        List of dicts with 'address' and 'function' keys
    """
    if cfg is None:
        logger.debug("No CFG provided for symbol resolution; all addresses will show as <unknown>")
        return [{"address": addr, "function": "<unknown>"} for addr in backtrace_hex]

    try:
        backtrace_addrs = [int(addr, 16) for addr in backtrace_hex]
    except (ValueError, TypeError):
        return [{"address": addr, "function": "<unknown>"} for addr in backtrace_hex]

    resolver = CFGSymbolResolver(cfg)
    resolved = resolver.resolve_backtrace(backtrace_addrs, mem_base)
    return [{"address": addr, "function": func} for addr, func in resolved]
