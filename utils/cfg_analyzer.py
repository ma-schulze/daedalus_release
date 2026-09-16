#!/usr/bin/env python3
"""
CFG Analyzer Utility

Uses angr's CFGFast to create a Control Flow Graph and count reachable basic blocks
from a specified start address. Falls back to CFGEmulated if CFGFast fails.

Usage:
    python utils/cfg_analyzer.py <binary> <start_address> [options]

Examples:
    python utils/cfg_analyzer.py ./my_ta.elf 0x1000
    python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --list-blocks
    python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --list-functions --base 0x40000
"""

import argparse
import sys
from pathlib import Path
from collections import deque
from typing import Set, Dict, List, Tuple, Optional
import logging
import json

import angr
import networkx as nx

# Module-level logger - will use the project's logging config when imported
logger = logging.getLogger(__name__)


def parse_address(addr_str: str) -> int:
    """Parse an address string (hex or decimal) to int."""
    addr_str = addr_str.strip()
    if addr_str.startswith('0x') or addr_str.startswith('0X'):
        return int(addr_str, 16)
    return int(addr_str)

def find_reachable_blocks_from_file(cfg_path: str, start_addr: int) -> Set[int]:
    """
    Read a pre-computed list of basic block addresses from a JSON file.

    Expected file format (e.g. test_binaries/taemu/beanpod/tas/bbs/bb_<uuid>.ta.json):
    - Top-level object keyed by function entry address (e.g. "0x93ac")
    - Each value has "nodes": [ { "name", "start", "end", "calls", "svc", "edges" }, ... ]
    - Block address is taken from each node's "start" field (hex string, e.g. "000093ac")

    Args:
        cfg_path: Path to the JSON file containing basic block information.
        start_addr: Starting address (reserved for future use, e.g. filtering by entry).

    Returns:
        Set of basic block start addresses (as int) found in the file.
    """
    reachable_blocks: Set[int] = set()
    cfg_path_p = Path(cfg_path)
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg_data = json.load(f)

    # Collect function entry addresses too (helps infer rebasing delta)
    func_entries: Set[int] = set()
    for k in cfg_data.keys():
        try:
            func_entries.add(int(str(k), 16))
        except Exception:
            continue

    # Format: root is { "<func_addr>": { "function", "nodes": [ { "start", ... }, ... ] }, ... }
    raw_block_addrs: List[int] = []
    for _func_entry, func_data in cfg_data.items():
        nodes = func_data.get("nodes") if isinstance(func_data, dict) else []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            start_str = node.get("start")
            if start_str is None:
                continue
            try:
                raw_block_addrs.append(int(start_str, 16))
            except (TypeError, ValueError):
                logger.debug("Skipping invalid block start in %s: %s", cfg_path, start_str)

    if not raw_block_addrs:
        return set()

    mn_addr = min(raw_block_addrs)
    mx_addr = max(raw_block_addrs)
    start_norm = start_addr & ~1

    def _invoke_likely_same_space_as_bb_file() -> bool:
        """True if analysis invoke lies in the same address range as bb JSON (typical T6 / aligned TA)."""
        if start_addr <= 0:
            return False
        return mn_addr <= start_addr <= mx_addr or mn_addr <= start_norm <= mx_addr

    # Heuristic: some bb files store addresses in a different base than our analysis uses.
    # If start_addr is not present, try to infer a constant delta using the TA metadata JSON
    # (it contains TA_*EntryPoint_start values in the analysis address space).
    def _load_entrypoints_from_metadata() -> List[int]:
        # cfg_path often looks like .../tas/bbs/bb_<uuid>.ta.json
        uuid = cfg_path_p.name
        if uuid.startswith("bb_") and uuid.endswith(".ta.json"):
            uuid = uuid[len("bb_") : -len(".ta.json")]
        else:
            return []

        candidates = [
            cfg_path_p.parent.parent / f"{uuid}.json",  # .../tas/<uuid>.json
            cfg_path_p.parent.parent.parent / "vuln_tas" / f"{uuid}.json",  # .../vuln_tas/<uuid>.json
        ]
        for meta in candidates:
            try:
                with open(meta, "r", encoding="utf-8") as mf:
                    meta_data = json.load(mf)
                eps = []
                for key, val in meta_data.items():
                    if isinstance(key, str) and key.endswith("_start") and isinstance(val, int) and val > 0:
                        eps.append(val)
                if eps:
                    return eps
            except Exception:
                continue
        return []

    entrypoints = _load_entrypoints_from_metadata()
    raw_set = set(raw_block_addrs)
    # Invoke is often inside a basic block, so it may not equal any node's "start" even when
    # the bb file is in the correct address space. Only run the Teegris-style rebase when the
    # invoke address is *outside* the span of bb addresses (different coordinate system).
    if (
        start_addr > 0
        and start_addr not in raw_set
        and start_norm not in raw_set
        and not _invoke_likely_same_space_as_bb_file()
        and entrypoints
    ):
        # Infer delta by matching multiple entrypoints against bb function-entry keys.
        # Score candidate deltas by how many entrypoints land on an existing bb function entry.
        invoke = start_addr
        sample_entries = list(func_entries)
        if len(sample_entries) > 2000:
            sample_entries = sample_entries[:2000]

        best_delta = None
        best_score = 0
        entry_set = set(func_entries)
        for bb_entry in sample_entries:
            delta = bb_entry - invoke
            score = 0
            for ep in entrypoints:
                if (ep + delta) in entry_set:
                    score += 1
            if score > best_score:
                best_score = score
                best_delta = delta
                if best_score >= min(3, len(entrypoints)):
                    break

        if best_delta is not None and best_score >= 2:
            rebased = [a - best_delta for a in raw_block_addrs]
            rmn, rmx = min(rebased), max(rebased)
            if (
                start_addr in rebased
                or start_norm in rebased
                or rmn <= start_addr <= rmx
                or rmn <= start_norm <= rmx
            ):
                logger.info(
                    "Rebasing CFG bb addresses from file %s by delta 0x%x (score=%d) to match analysis start %s",
                    cfg_path,
                    best_delta,
                    best_score,
                    hex(start_addr),
                )
                raw_block_addrs = rebased
            else:
                logger.warning(
                    "CFG bb rebase for %s rejected: start %s not in rebased span [%s, %s]. Using raw bb addresses.",
                    cfg_path,
                    hex(start_addr),
                    hex(rmn),
                    hex(rmx),
                )
        else:
            logger.warning(
                "CFG bb addresses from %s do not include start %s and rebase inference failed (entrypoints=%d). "
                "Block coverage may be inaccurate.",
                cfg_path,
                hex(start_addr),
                len(entrypoints),
            )

    for a in raw_block_addrs:
        reachable_blocks.add(a)
    return reachable_blocks


def find_reachable_blocks(cfg, start_addr: int) -> Set[int]:
    """
    Find all basic blocks reachable from a start address using BFS.
    
    Args:
        cfg: angr CFG object (CFGFast or CFGEmulated)
        start_addr: Starting address
        
    Returns:
        Set of reachable basic block addresses
    """
    # Get the CFG model and graph
    model = cfg.model
    graph = cfg.graph
    
    # Find the node at the start address
    start_node = model.get_any_node(start_addr)
    if start_node is None:
        # Try to find closest node (the start address might be inside a basic block)
        logger.debug(f"No exact node at {hex(start_addr)}, searching for containing block...")
        for node in graph.nodes():
            if hasattr(node, 'addr') and hasattr(node, 'size'):
                if node.addr <= start_addr < node.addr + (node.size or 1):
                    start_node = node
                    logger.debug(f"Found containing block at {hex(node.addr)}")
                    break
    
    if start_node is None:
        logger.warning(f"Could not find any CFG node at or containing {hex(start_addr)}")
        return set()
    
    logger.debug(f"Starting BFS from block at {hex(start_node.addr)}")
    
    # BFS to find all reachable nodes
    visited = set()
    queue = deque([start_node])
    
    while queue:
        node = queue.popleft()
        if node.addr in visited:
            continue
        visited.add(node.addr)
        
        # Add successors to queue
        for succ in graph.successors(node):
            if succ.addr not in visited:
                queue.append(succ)
    
    return visited


def get_function_for_addr(cfg, addr: int) -> str:
    """Get function name for an address."""
    if cfg.kb.functions:
        for func_addr, func in cfg.kb.functions.items():
            if func.addr <= addr < func.addr + func.size:
                return func.name or f"sub_{hex(func.addr)}"
    return "<unknown>"

def generate_cfg(project, try_fast_first: bool = True, preset_starts: int = None):
    cfg = None
    cfg_method = None
    
    # Try CFGFast first (faster but may fail for some binaries)
    if try_fast_first:
        try:
            logger.debug(f"Attempting CFGFast analysis starting...")
            cfg = project.analyses.CFGFast(
                force_complete_scan=False,
                resolve_indirect_jumps=True,
                symbols=True,
                data_references=True,
                normalize=True
            )
            logger.info(f"CFGFast succeeded: {len(cfg.graph)} nodes")
            if len(cfg.graph) == 0:
                logger.warning("CFGFast found 0 nodes, will fall back to CFGEmulated")
                cfg = None
        except Exception as e:
            logger.warning(f"CFGFast failed ({type(e).__name__}): {e}")
            cfg = None
    
    # Fallback to CFGEmulated if CFGFast failed or found no nodes
    if cfg is None or len(cfg.graph) == 0:
        try:
            logger.info("CFGFast unavailable, falling back to CFGEmulated...")
            starts = [func.addr for func in project.kb.functions.values()]
            if preset_starts is not None:
                starts.append(preset_starts)
            cfg = project.analyses.CFGEmulated(
                starts=starts,
                call_depth=50,  # Increased call depth to explore more functions
                max_steps=100000,  # Increased max steps to recover more basic blocks
                resolve_indirect_jumps=True,
                context_sensitivity_level=1,
                normalize=True
            )
            logger.debug(f"CFGEmulated succeeded: {len(cfg.graph)} nodes")
        except Exception as e:
            logger.warning(f"CFGEmulated also failed ({type(e).__name__}): {e}")
            logger.warning("Unable to compute reachable blocks - coverage percentage will be unavailable")

    # Ultimate fallback to circument a bug in angr: Do not resolve indirect jumps
    if cfg is None or len(cfg.graph) == 0:
        try:
            logger.info("CFGEmulated failed due to a bug in angr, falling back to incomplete CFGFast...")
            starts = [func.addr for func in project.kb.functions.values()]
            cfg = project.analyses.CFGFast(
                function_starts=starts,
                force_complete_scan=True,
                force_smart_scan=False,
                resolve_indirect_jumps=False,
                symbols=True,
                data_references=True,
            )
        except Exception as e:
            logger.warning(f"CFGEmulated also failed ({type(e).__name__}): {e}")
            logger.warning("Unable to compute reachable blocks - coverage percentage will be unavailable")
            cfg = None

    return cfg

def get_reachable_blocks_from_project(cfg, start_addr: int) -> Set[int]:
    """
    Get all reachable basic blocks from a start address using an existing angr project.
    
    This is intended to be called from the explorer to compute coverage metrics.
    Tries CFGFast first, falls back to CFGEmulated if CFGFast fails (e.g., for binaries
    loaded at base address 0 with low entry points).
    
    Args:
        project: An existing angr.Project instance
        start_addr: Starting address for reachability analysis
        try_fast_first: Whether to try CFGFast first (default True)
    Returns:
        Set of reachable basic block addresses
    """
    
    # Find reachable blocks using BFS
    reachable = find_reachable_blocks(cfg, start_addr)
    logger.info(f"CFG analysis: {len(reachable)} reachable blocks from {hex(start_addr)}")
    
    # Log some diagnostic information if very few blocks found
    if len(reachable) < 10:
        logger.warning(f"Only {len(reachable)} reachable blocks found - this seems low.")
        logger.debug(f"CFG has {len(cfg.graph)} total nodes")
        # Check if start address is in the CFG
        model = cfg.model
        start_node = model.get_any_node(start_addr)
        if start_node:
            logger.debug(f"Start node found at {hex(start_node.addr)}, has {len(list(cfg.graph.successors(start_node)))} successors")
        else:
            logger.warning(f"Start address {hex(start_addr)} not found in CFG nodes")
    
    return reachable 


def analyze_cfg(binary_path: str, start_addr: int, base_addr: int = None,
                list_blocks: bool = False, list_functions: bool = False) -> Dict:
    """
    Analyze CFG and count reachable basic blocks.
    
    Args:
        binary_path: Path to the binary
        start_addr: Start address for reachability analysis
        base_addr: Optional base address for loading the binary
        list_blocks: Whether to list all reachable blocks
        list_functions: Whether to list reachable functions
        
    Returns:
        Dictionary with analysis results
    """
    print(f"Loading binary: {binary_path}")
    
    # Create angr project
    load_options = {'auto_load_libs': False}

    main_opts={
        "backend": "blob", 
        "arch": "aarch64", 
        "entry_point": start_addr, 
        "base_addr": 0
    }

    if base_addr is not None:
        load_options['main_opts'] = {'base_addr': base_addr}
    
    proj = angr.Project(binary_path, load_options=load_options, main_opts=main_opts)
    
    print(f"Binary loaded at base: {hex(proj.loader.main_object.mapped_base)}")
    print(f"Entry point: {hex(proj.entry)}")
    print(f"Start address for analysis: {hex(start_addr)}")
    print()
    
    # Build CFGFast
    print("Building CFGFast... (this may take a moment)")
    cfg = proj.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        function_starts=[start_addr],
        resolve_indirect_jumps=True,
        symbols=True,
        data_references=True,
    )
    
    print(f"CFG built: {len(cfg.graph)} total nodes")
    print(f"Functions discovered: {len(cfg.kb.functions)}")
    print()
    
    # Find reachable blocks
    print(f"Finding reachable blocks from {hex(start_addr)}...")
    reachable = find_reachable_blocks(cfg, start_addr)
    
    results = {
        'binary': binary_path,
        'start_addr': start_addr,
        'total_cfg_nodes': len(cfg.graph),
        'reachable_blocks': len(reachable),
        'total_functions': len(cfg.kb.functions),
    }
    
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Total CFG nodes:      {results['total_cfg_nodes']}")
    print(f"Reachable blocks:     {results['reachable_blocks']}")
    print(f"Total functions:      {results['total_functions']}")
    print("=" * 60)
    
    # List reachable functions
    if list_functions and reachable:
        print()
        print("REACHABLE FUNCTIONS:")
        print("-" * 60)
        
        # Group blocks by function
        func_blocks: Dict[str, List[int]] = {}
        for addr in sorted(reachable):
            func_name = get_function_for_addr(cfg, addr)
            if func_name not in func_blocks:
                func_blocks[func_name] = []
            func_blocks[func_name].append(addr)
        
        # Sort by number of blocks
        for func_name, blocks in sorted(func_blocks.items(), key=lambda x: -len(x[1])):
            print(f"  {func_name}: {len(blocks)} blocks")
        
        results['reachable_functions'] = list(func_blocks.keys())
        print()
        print(f"Total reachable functions: {len(func_blocks)}")
    
    # List all reachable blocks
    if list_blocks and reachable:
        print()
        print("REACHABLE BASIC BLOCKS:")
        print("-" * 60)
        for addr in sorted(reachable):
            node = cfg.model.get_any_node(addr)
            size = node.size if node else 0
            func = get_function_for_addr(cfg, addr)
            print(f"  {hex(addr):12s}  size={size:4d}  func={func}")
        
        results['block_addresses'] = sorted(reachable)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Analyze CFG and count reachable basic blocks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage - count reachable blocks from address
  python utils/cfg_analyzer.py ./my_ta.elf 0x1000

  # With custom base address
  python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --base 0x40000

  # List all reachable blocks
  python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --list-blocks

  # List reachable functions
  python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --list-functions

  # Both lists
  python utils/cfg_analyzer.py ./my_ta.elf 0x1000 --list-blocks --list-functions
        """
    )
    
    parser.add_argument(
        'binary',
        help='Path to the binary file'
    )
    
    parser.add_argument(
        'start_address',
        help='Start address for reachability analysis (hex or decimal)'
    )
    
    parser.add_argument(
        '--base', '-b',
        type=str,
        default=None,
        help='Base address to load the binary at (hex or decimal)'
    )
    
    parser.add_argument(
        '--list-blocks', '-l',
        action='store_true',
        help='List all reachable basic blocks'
    )
    
    parser.add_argument(
        '--list-functions', '-f',
        action='store_true',
        help='List reachable functions with block counts'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='Output results to JSON file'
    )
    
    args = parser.parse_args()
    
    # Validate binary exists
    if not Path(args.binary).exists():
        print(f"Error: Binary not found: {args.binary}")
        sys.exit(1)
    
    # Parse addresses
    try:
        start_addr = parse_address(args.start_address)
    except ValueError:
        print(f"Error: Invalid start address: {args.start_address}")
        sys.exit(1)
    
    base_addr = None
    if args.base:
        try:
            base_addr = parse_address(args.base)
        except ValueError:
            print(f"Error: Invalid base address: {args.base}")
            sys.exit(1)
    
    # Run analysis
    results = analyze_cfg(
        args.binary,
        start_addr,
        base_addr=base_addr,
        list_blocks=args.list_blocks,
        list_functions=args.list_functions
    )
    
    # Save to JSON if requested
    if args.output:
        import json
        # Convert addresses to hex strings for JSON
        output_data = {
            'binary': results['binary'],
            'start_addr': hex(results['start_addr']),
            'total_cfg_nodes': results['total_cfg_nodes'],
            'total_cfg_edges': results['total_cfg_edges'],
            'reachable_blocks': results['reachable_blocks'],
            'total_functions': results['total_functions'],
        }
        if 'block_addresses' in results:
            output_data['block_addresses'] = [hex(a) for a in results['block_addresses']]
        if 'reachable_functions' in results:
            output_data['reachable_functions'] = results['reachable_functions']
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
