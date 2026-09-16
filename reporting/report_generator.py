import os
import sys
import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import pathlib
import time

import angr
from angr.sim_state import SimState


# Add project root to path for standalone/subprocess execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from .symbol_resolver import resolve_backtrace_with_symbols
from utils.logging_config import get_logger

logger = get_logger(__name__)

# Global report state
_report_data = None
_mem_base = None  # Memory base address for the binary
_cfg = None  # angr CFG for symbol resolution (set by init_report when provided by explorer)


class ReportData:
    """Container for all report data"""
    def __init__(self):
        self.binary_name = ""
        self.binary_path = ""
        self.execution_time = ""
        self.start_addr = ""
        self.target_addr = ""
        self.mem_base = 0  # Memory base address
        self.run_id = ""  # Optional identifier for this run (e.g., init function name)
        self.stats = {
            'states_explored': 0,
            'targets_found': 0,
            'bugs_found': 0,
            'max_depth': 0,
            'functions_covered': 0,
            'unique_addresses': 0,
            'blocks_hit': 0,
            'blocks_reachable': 0,
            'block_coverage_pct': 0.0
        }
        self.bugs = []
        self.stub_functions = []  # List of {"name": str, "address": str} for called stub SimProcedures
        self.syscall_stats = {}
        self.function_coverage = []  # List of visited functions
        self.visited_blocks = []  # List of visited block addresses (for merging)
        # Persistence (set by init_report)
        self._output_dir: Path | None = None
        self._output_html_path: Path | None = None
        self._output_json_path: Path | None = None
        self._output_filename: str | None = None
        # Incremental persistence tracking
        self._max_blocks_hit_persisted: int = -1
        self._bugs_persisted: int = 0
        self._stubs_persisted: int = 0
        self._last_html_persist_ts: float = 0.0


def _compute_report_output_paths(output_filename: str) -> tuple[Path, Path]:
    """
    Compute output paths for HTML+JSON report files.
    Uses the same folder layout as finalize_report used to.
    """
    if _report_data is None:
        raise RuntimeError("Report not initialized")

    current_dir = pathlib.Path(__file__).parent
    project_root = current_dir.parent
    reports_base = project_root / "reports"

    binary_path_resolved = pathlib.Path(_report_data.binary_path).resolve()
    try:
        rel_path = binary_path_resolved.relative_to(project_root.resolve())
    except ValueError:
        rel_path = pathlib.Path(_report_data.binary_path)

    parent = rel_path.parent
    if parent.name in ("tas", "vuln_tas"):
        ta_root = parent.parent
        subfolder = parent.name
    else:
        ta_root = parent
        subfolder = parent.name if parent.name else "other"

    output_dir = reports_base / "others" / ta_root / subfolder / _report_data.binary_name
    output_dir.mkdir(parents=True, exist_ok=True)

    html_path = output_dir / output_filename
    json_path = output_dir / output_filename.replace(".html", ".json")
    return html_path, json_path


def _render_report_dict(*, minimal: bool = False) -> dict:
    if _report_data is None:
        raise RuntimeError("Report not initialized")
    base = {
        "binary_name": _report_data.binary_name,
        "binary_path": _report_data.binary_path,
        "execution_time": _report_data.execution_time,
        "start_addr": _report_data.start_addr,
        "target_addr": _report_data.target_addr,
        "mem_base": _report_data.mem_base,
        "run_id": _report_data.run_id,
        "stats": _report_data.stats,
        "bugs": _report_data.bugs,
        "stub_functions": _report_data.stub_functions,
        # Needed for merging block coverage across parallel runs
        "visited_blocks": _report_data.visited_blocks,
    }
    if minimal:
        # Keep coverage/bugs/stubs durable with minimal I/O.
        # Large fields (coverage lists, syscall stats) are only written on bug/stub/finalize.
        return base
    base["syscall_stats"] = _report_data.syscall_stats
    base["function_coverage"] = _report_data.function_coverage
    return base


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _atomic_write_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=str)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _persist_report(reason: str, *, force_html: bool = False) -> None:
    """
    Persist the current report to disk so partial results survive OOM/timeouts.
    Always writes JSON. HTML is throttled to avoid heavy work on frequent coverage updates.
    """
    global _report_data
    if _report_data is None:
        return

    if _report_data._output_html_path is None or _report_data._output_json_path is None:
        # init_report should set these, but be defensive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        if _report_data.run_id:
            output_filename = f"report_{_report_data.binary_name}_{_report_data.run_id}_{timestamp}.html"
        else:
            output_filename = f"report_{_report_data.binary_name}_{timestamp}.html"
        html_path, json_path = _compute_report_output_paths(output_filename)
        _report_data._output_filename = output_filename
        _report_data._output_html_path = html_path
        _report_data._output_json_path = json_path
        _report_data._output_dir = html_path.parent

    # JSON (always). For frequent "coverage" updates, write a minimal JSON to reduce I/O,
    # so we don't lose progress due to slow filesystem writes on HPC/NFS.
    minimal_json = (reason == "coverage")
    try:
        _atomic_write_json(_report_data._output_json_path, _render_report_dict(minimal=minimal_json))
    except Exception as e:
        logger.warning(f"Failed to persist JSON report ({reason}): {e}")
        return

    # HTML (throttled unless forced). For coverage updates, throttle much less so the
    # HTML reflects recent progress even if the process dies quickly after an update.
    now = time.time()
    html_throttle_sec = 1.0 if reason == "coverage" else 10.0
    should_write_html = force_html or (now - _report_data._last_html_persist_ts) >= html_throttle_sec
    if not should_write_html:
        return

    try:
        current_dir = pathlib.Path(__file__).parent
        env = Environment(loader=FileSystemLoader(str(current_dir)), autoescape=True)
        template = env.get_template("report_template.html")
        html_content = template.render(
            binary_name=_report_data.binary_name,
            binary_path=_report_data.binary_path,
            execution_time=_report_data.execution_time,
            start_addr=_report_data.start_addr,
            target_addr=_report_data.target_addr,
            stats=_report_data.stats,
            bugs=_report_data.bugs,
            stub_functions=_report_data.stub_functions,
            syscall_stats=_report_data.syscall_stats,
            function_coverage=_report_data.function_coverage,
        )
        _atomic_write_text(_report_data._output_html_path, html_content)
        _report_data._last_html_persist_ts = now
    except Exception as e:
        logger.warning(f"Failed to persist HTML report ({reason}): {e}")


def init_report(binary_path, start_addr, target_addr, mem_base=0, run_id=None, cfg=None):
    """
    Initialize a new report with metadata.
    
    Args:
        binary_path: Path to the binary being analyzed
        start_addr: Starting address for symbolic execution (hex string or int)
        target_addr: Target address for symbolic execution (hex string or int)
        mem_base: Base address where the binary is loaded in memory (int)
        run_id: Optional identifier for this run (e.g., init function name).
                Used to distinguish reports from parallel runs.
        cfg: Optional angr CFG (from generate_cfg(project)) for resolving addresses to function names.
    
    Returns:
        ReportData object for this report
    """
    global _report_data, _mem_base, _cfg
    
    _report_data = ReportData()
    _cfg = cfg
    _report_data.binary_path = binary_path
    _report_data.binary_name = os.path.basename(binary_path)
    _report_data.execution_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _report_data.start_addr = start_addr if isinstance(start_addr, str) else hex(start_addr)
    _report_data.target_addr = target_addr if isinstance(target_addr, str) else hex(target_addr)
    _report_data.run_id = run_id or ""
    
    # Store memory base for backtrace resolution
    if isinstance(mem_base, str):
        _mem_base = int(mem_base, 16)
    else:
        _mem_base = mem_base
    _report_data.mem_base = _mem_base
    
    run_id_str = f" (run: {run_id})" if run_id else ""
    logger.info(f"Initialized report for {_report_data.binary_name}{run_id_str}")
    logger.debug(f"Memory base: {hex(_mem_base)}")

    # Compute stable output path for this run immediately (so we can persist incrementally).
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    if _report_data.run_id:
        output_filename = f"report_{_report_data.binary_name}_{_report_data.run_id}_{timestamp}.html"
    else:
        output_filename = f"report_{_report_data.binary_name}_{timestamp}.html"
    html_path, json_path = _compute_report_output_paths(output_filename)
    _report_data._output_filename = output_filename
    _report_data._output_html_path = html_path
    _report_data._output_json_path = json_path
    _report_data._output_dir = html_path.parent

    # Write an initial report skeleton so that even very early termination leaves artifacts.
    _persist_report("init", force_html=True)
    
    return _report_data



def _extract_symbolic_variables(state: SimState) -> list[dict]:
    """
    Helper function to extract symbolic variables from state for reporting.
    Args:
        state: The state to extract the variables from.
    Returns:
        List of variable information dicts.
    """
    variables_list = []
    symbolic_vars = state.solver.get_variables()
    
    for var in symbolic_vars:
        if not hasattr(var, 'args') or len(var.args) == 0:
            continue
        
        var_name = var.args[0]
        var_info = {
            'name': var_name,
            'size': var.size(),
            'hex_value': '',
            'bytes_value': '',
            'ascii_value': ''
        }
        
        try:
            # Get a concrete value (just one solution, not all)
            concrete_value = state.solver.eval_one(var, default=0)
            bits = var.size()
            bytes_len = bits // 8
            
            if bytes_len > 1:
                concrete_bytes = concrete_value.to_bytes(bytes_len, byteorder='big')
                hex_str = f"0x{concrete_value:0{bytes_len*2}x}"
                var_info['hex_value'] = hex_str
                var_info['bytes_value'] = str(concrete_bytes)
                
                try:
                    ascii_repr = concrete_bytes.decode('ascii', errors='replace')
                    if any(c.isprintable() for c in ascii_repr):
                        var_info['ascii_value'] = ascii_repr
                except Exception:
                    pass
            else:
                hex_str = hex(concrete_value)
                var_info['hex_value'] = f"{hex_str} ({concrete_value})"
        except Exception:
            pass
        
        variables_list.append(var_info)
    
    return variables_list



def add_detected_bug(state, bug_type, address, criticality="WARNING"):
    """
    Add a detected bug to the report.
    
    Args:
        bug_type: Type of bug (e.g., "PANIC Reached!")
        address: Address where bug was detected (int or hex string)
        criticality: Severity level - "INFO", "WARNING", or "CRITICAL"
    """
    global _report_data, _mem_base
    
    if _report_data is None:
        logger.warning("Report not initialized. Call init_report() first.")
        return
    
    # Format address as hex string if it's an integer

    try: 
        concrete_address = state.solver.eval_one(state.addr)
    except Exception as e:
        logger.warning(f"Failed to evaluate address: {e}")
        return 

    if isinstance(address, int):
        address = hex(address)


    if state.project.is_hooked(state.addr):
        hook = state.project.hooked_by(state.addr)
        if hook:
            name = ""
            # Avoid a hard dependency on explorer.* here (prevents circular imports).
            try:
                from explorer.hooks.function_hooks import _HookRecordingWrapper  # type: ignore
            except Exception:
                _HookRecordingWrapper = None  # type: ignore
            if _HookRecordingWrapper is not None and isinstance(hook, _HookRecordingWrapper):  # type: ignore[arg-type]
                name = getattr(hook, "_hook_name", "") or "unknown"
            else:
                name = getattr(hook, "_hook_name", None) or getattr(hook, "display_name", None) or getattr(hook, "__name__", "unknown")
            logger.info(f"Adding bug for hooked function: {name} at {address}")
            if "printf" in name:
                logger.warning(f"Skipping bug {bug_type} at {address} because it is a print function and something is wrong with their angr implementation")
                return


    satisfiable = state.solver.satisfiable()
    if not satisfiable:
        logger.warning(f"Bug {bug_type} at {address} is not satisfiable")
        return

    variables = _extract_symbolic_variables(state)
    constraints = [str(c) for c in state.solver.constraints]

    backtrace = [hex(a) for a in getattr(state.history, "bbl_addrs", []) if isinstance(a, int)]
    if concrete_address is not None:
        backtrace = [hex(concrete_address)] + backtrace

    # Enhance backtrace with function names (using CFG when available)
    enhanced_backtrace = []
    if backtrace:
        try:
            enhanced_backtrace = resolve_backtrace_with_symbols(
                backtrace,
                _report_data.binary_path,
                _mem_base,
                cfg=_cfg,
            )
            logger.debug(f"Enhanced backtrace with {len(enhanced_backtrace)} function names")
        except Exception as e:
            logger.warning(f"Failed to enhance backtrace: {e}")
            # Fall back to simple format
            enhanced_backtrace = [{'address': addr, 'function': '<unknown>'} for addr in backtrace]
    
    # Validate criticality
    valid_criticalities = {"INFO", "WARNING", "CRITICAL"}
    if criticality not in valid_criticalities:
        logger.warning(f"Invalid criticality '{criticality}', defaulting to WARNING")
        criticality = "WARNING"
    
    bug_entry = {
        'type': bug_type,
        'address': address,
        'constraints': constraints,
        'variables': variables,
        'satisfiable': satisfiable,
        'backtrace': enhanced_backtrace,
        'criticality': criticality
    }
    
    _report_data.bugs.append(bug_entry)
    _report_data.stats['bugs_found'] = len(_report_data.bugs)
    
    logger.info(f"Added bug [{criticality}]: {bug_type} at {address}")
    # Persist immediately so bugs survive OOM/timeout kills.
    _persist_report("bug", force_html=True)


def add_stub_function(name: str, address=None):
    """
    Record that execution hit a hooked-but-stub SimProcedure (e.g. placeholder).
    Deduplicates by name so the same stub is only listed once per report.

    Args:
        name: Display name of the stub procedure (e.g. from hook.display_name or class __name__).
        address: Optional address (int or hex str) where the stub was called.
    """
    global _report_data

    if _report_data is None:
        logger.warning("Report not initialized. Call init_report() first.")
        return

    addr_str = hex(address) if isinstance(address, int) else (address or "")
    for entry in _report_data.stub_functions:
        if entry.get("name") == name:
            return
    _report_data.stub_functions.append({"name": name, "address": addr_str})
    logger.info(f"Stub function called: {name} at {addr_str}")
    # Persist so stub info survives abrupt termination (also affects CSV export).
    _persist_report("stub", force_html=True)


def update_stats(states_explored=None, targets_found=None, max_depth=None):
    """
    Update exploration statistics in the report.
    
    Args:
        states_explored: Number of states explored
        targets_found: Number of target addresses found
        max_depth: Maximum exploration depth reached
    """
    global _report_data
    
    if _report_data is None:
        logger.warning("Report not initialized.")
        return
    
    if states_explored is not None:
        _report_data.stats['states_explored'] = states_explored
    if targets_found is not None:
        _report_data.stats['targets_found'] = targets_found
    if max_depth is not None:
        _report_data.stats['max_depth'] = max_depth


def add_syscall_stats(syscall_stats):
    """
    Add syscall statistics to the report.
    
    Args:
        syscall_stats: Dictionary mapping syscall names to call counts
    """
    global _report_data
    
    if _report_data is None:
        logger.warning("Report not initialized.")
        return
    
    _report_data.syscall_stats = syscall_stats
    logger.debug(f"Added syscall statistics ({len(syscall_stats)} unique syscalls)")


def update_block_coverage(blocks_hit, blocks_reachable, visited_block_addrs=None):
    """
    Update basic block coverage statistics in the report.
    
    Args:
        blocks_hit: Number of unique basic blocks visited during exploration
        blocks_reachable: Total number of reachable basic blocks (from CFG analysis)
        visited_block_addrs: Optional list of visited block addresses (for merging)
    """
    global _report_data
    
    if _report_data is None:
        logger.warning("Report not initialized.")
        return
    
    _report_data.stats['blocks_hit'] = blocks_hit
    _report_data.stats['blocks_reachable'] = blocks_reachable
    
    # Calculate coverage percentage
    if blocks_reachable > 0:
        _report_data.stats['block_coverage_pct'] = round((blocks_hit / blocks_reachable) * 100, 1)
    else:
        _report_data.stats['block_coverage_pct'] = 0.0
    
    # Store visited block addresses for potential merging
    if visited_block_addrs:
        _report_data.visited_blocks = visited_block_addrs
    
    logger.debug(f"Block coverage: {blocks_hit}/{blocks_reachable} ({_report_data.stats['block_coverage_pct']}%)")
    # Persist when we reach a new max coverage so progress survives OOM/timeouts.
    # Special case: first time we learn blocks_reachable, we may still have blocks_hit == 0.
    # Persist a full snapshot once so the JSON doesn't get overwritten by a minimal coverage write.
    if _report_data._max_blocks_hit_persisted < 0 and isinstance(blocks_reachable, int) and blocks_reachable > 0:
        _report_data._max_blocks_hit_persisted = 0
        _persist_report("coverage_init", force_html=True)
        return

    if isinstance(blocks_hit, int) and blocks_hit > _report_data._max_blocks_hit_persisted and blocks_hit > 0:
        _report_data._max_blocks_hit_persisted = blocks_hit
        _persist_report("coverage")


def add_function_coverage(visited_addresses, hook_call_counts=None):
    """
    Add function coverage information to the report.

    Includes both addresses resolved via CFG and hooked functions (SimProcedures)
    that were called during exploration.

    Args:
        visited_addresses: List of addresses visited during symbolic execution
        hook_call_counts: Optional dict mapping hooked function names to call counts
                          (e.g. from GLOBAL_TA_STATE['hook_call_counts'])
    """
    global _report_data, _mem_base, _cfg

    if _report_data is None:
        logger.warning("Report not initialized.")
        return

    function_map = {}

    # Resolve addresses to function names (CFG) and count
    if visited_addresses:
        logger.debug(f"Processing {len(visited_addresses)} visited addresses for function coverage...")
        hex_addresses = [hex(addr) for addr in visited_addresses]
        from .symbol_resolver import resolve_backtrace_with_symbols

        try:
            resolved = resolve_backtrace_with_symbols(
                hex_addresses,
                _report_data.binary_path,
                _mem_base,
                cfg=_cfg,
            )
            for entry in resolved:
                func_name = entry['function']
                if func_name not in function_map:
                    function_map[func_name] = {
                        'name': func_name,
                        'addresses': [],
                        'hit_count': 0
                    }
                function_map[func_name]['addresses'].append(entry['address'])
                function_map[func_name]['hit_count'] += 1
        except Exception as e:
            logger.error(f"Error resolving addresses for function coverage: {e}")
            import traceback
            traceback.print_exc()

    # Merge hooked function call counts (e.g. TEE_Malloc, SLog) into coverage
    if hook_call_counts:
        for name, count in hook_call_counts.items():
            if name not in function_map:
                function_map[name] = {
                    'name': name,
                    'addresses': [],
                    'hit_count': 0
                }
            function_map[name]['hit_count'] += count

    if not function_map:
        logger.debug("No addresses or hook calls to process for coverage")
        return

    # Convert to sorted list (by hit count, then name)
    coverage_list = sorted(
        function_map.values(),
        key=lambda x: (-x['hit_count'], x['name'])
    )

    _report_data.function_coverage = coverage_list
    _report_data.stats['functions_covered'] = len([f for f in coverage_list if f['name'] != '<unknown>'])
    _report_data.stats['unique_addresses'] = len(visited_addresses) if visited_addresses else 0

    logger.debug(f"Function coverage processed:")
    logger.debug(f"  - Unique addresses: {len(visited_addresses) if visited_addresses else 0}")
    logger.debug(f"  - Unique functions: {_report_data.stats['functions_covered']}")
    logger.debug(f"  - Hook calls included: {bool(hook_call_counts)}")


def finalize_report(output_filename=None):
    """
    Generate the final HTML report file and accompanying JSON data file.
    
    The JSON file can be used for merging multiple reports from parallel runs.
    
    Args:
        output_filename: Name for the output HTML file (default: auto-generated)
    
    Returns:
        Path to the generated HTML file
    """
    global _report_data
    
    if _report_data is None:
        logger.error("No report data to finalize.")
        return None
    
    # Sort bugs by criticality (CRITICAL → WARNING → INFO), then by confidence within each level
    if _report_data.bugs:
        criticality_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        _report_data.bugs.sort(
            key=lambda b: (
                criticality_order.get(b.get('criticality', 'WARNING'), 1),  # Primary: criticality
                -b.get('confidence', 50)  # Secondary: confidence (descending)
            )
        )
        logger.debug(f"Sorted {len(_report_data.bugs)} bugs by criticality, then confidence")
    
    # If caller explicitly wants a specific output filename, switch the persisted paths once.
    if output_filename is not None:
        html_path, json_path = _compute_report_output_paths(output_filename)
        _report_data._output_filename = output_filename
        _report_data._output_html_path = html_path
        _report_data._output_json_path = json_path
        _report_data._output_dir = html_path.parent

    # Force a final HTML write (no throttle) so the final report is always complete.
    _persist_report("finalize", force_html=True)

    logger.info("=" * 60)
    logger.info(f"HTML report generated: {_report_data._output_html_path}")
    logger.info(f"JSON data saved: {_report_data._output_json_path}")
    logger.info("=" * 60)
    return str(_report_data._output_html_path)


def get_report_data():
    """
    Get the current report data object.
    
    Returns:
        Current ReportData object or None if not initialized
    """
    return _report_data

