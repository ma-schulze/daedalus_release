"""
TA memory sanitizer plugin: detects suspicious memory access patterns
(tainted/untrusted addresses, normal-world vs secure-world).
"""

import angr
from angr.sim_state import SimState
from reporting import add_detected_bug
from .ta_plugin import TAPlugin, ta_plugin
from explorer.memory import is_tainted, is_trusted
from utils.logging_config import get_logger

logger = get_logger(__name__)

# Key in state.globals for the plugin instance (used by breakpoint callbacks)
TA_MEMSAN_PLUGIN_KEY = "ta_memsan_plugin"


def _eval_concrete_addr(state: SimState, addr) -> int:
    """
    Evaluate address to a concrete int for reporting; fallback to raw addr.
    Args:
        state: The state that triggered the breakpoint.
        addr: The address to evaluate.
    Returns:
        The concrete address.
    """
    try:
        return state.solver.eval_one(addr)
    except Exception:
        return addr if isinstance(addr, int) else 0


def _report_mem_read(state: SimState, kind: str, msg: str, severity: str):
    """
    Report a bugged memory read.
    Args:
        state: The state that triggered the breakpoint.
        kind: The kind of memory read.
        msg: The message to report.
        severity: The severity of the bug.
    """
    addr = state.inspect.mem_read_address
    size = state.inspect.mem_read_length
    concrete_addr = _eval_concrete_addr(state, addr)
    
    # if we access the input buffers, this is not a bug but wanted behavior 
    if state.heap.heap_base <= concrete_addr < state.globals['heap_base']:
        return

    plugin = state.globals.get(TA_MEMSAN_PLUGIN_KEY)
    if plugin is None:
        logger.warning("%s Read: %s size=%s", kind, hex(concrete_addr), size)
        return
    
    faulting_addr = state.solver.eval_one(state.addr)
    bug_id = (faulting_addr, kind)
    if kind == "sw_or_nw_read":
        reported = plugin.reported_sw_or_nw_read
    elif kind == "sw_read":
        reported = plugin.reported_sw_read
    else:
        reported = plugin.reported_nw_read
    if bug_id in reported:
        return

    reported.add(bug_id)
    logger.warning("%s Read: %s size=%s at PC=%s", kind, hex(concrete_addr), size, hex(faulting_addr))
    add_detected_bug(state, msg, concrete_addr, severity)


def _report_mem_write(state: SimState, kind: str, msg: str, severity: str):
    """
    Report a bugged memory write.
    Args:
        state: The state that triggered the breakpoint.
        kind: The kind of memory write.
        msg: The message to report.
        severity: The severity of the bug.
    """
    addr = state.inspect.mem_write_address
    concrete_addr = _eval_concrete_addr(state, addr)

    # if we access the input buffers, this is not a bug but wanted behavior 
    if state.heap.heap_base <= concrete_addr < state.globals['heap_base']:
        return

    data = state.inspect.mem_write_expr
    size = state.inspect.mem_write_length or (len(data) // 8)
    plugin = state.globals.get(TA_MEMSAN_PLUGIN_KEY)
    if plugin is None:
        logger.warning("%s Write: %s size=%s", kind, hex(concrete_addr), size)
        return
    
    faulting_addr = _eval_concrete_addr(state, state.addr)
    bug_id = (faulting_addr, kind)
    if kind == "sw_or_nw_write":
        reported = plugin.reported_sw_or_nw_write
    elif kind == "sw_write":
        reported = plugin.reported_sw_write
    else:
        reported = plugin.reported_nw_write
    
    if bug_id in reported:
        return
    reported.add(bug_id)

    logger.warning("%s Write: %s size=%s at PC=%s", kind, hex(concrete_addr), size, hex(faulting_addr))
    add_detected_bug(state, msg, concrete_addr, severity)


def _ta_memsan_sw_read(state: SimState):
    """
    Triggered when a read from a SW address is detected.
    """
    addr = state.inspect.mem_read_address
    if not (is_tainted(addr) and not is_trusted(addr)):
        return
    _report_mem_read(
        state,
        "sw_read",
        "MemSan: Secure World Read from Tainted Address",
        "WARNING",
    )


def _ta_memsan_sw_write(state: SimState):
    """
    Triggered when a write to a SW address is detected.
    """
    addr = state.inspect.mem_write_address
    if not (is_tainted(addr) and not is_trusted(addr)):
        return
    _report_mem_write(
        state,
        "sw_write",
        "MemSan: Secure World Write to Tainted Address",
        "WARNING",
    )


def _ta_memsan_nw_read(state: SimState):
    """
    Triggered when a read from an NW address is detected.
    """
    addr = state.inspect.mem_read_address
    if is_tainted(addr):
        return
    _report_mem_read(
        state,
        "nw_read",
        "MemSan: Normal World Read from Untainted Address",
        "CRITICAL",
    )


def _ta_memsan_nw_write(state: SimState):
    """
    Triggered when a write to an NW address is detected.
    """
    addr = state.inspect.mem_write_address
    if is_tainted(addr):
        return
    _report_mem_write(
        state,
        "nw_write",
        "MemSan: Normal World Write to Untainted Address",
        "CRITICAL",
    )


def _ta_memsan_sw_or_nw_read(state: SimState):
    """
    Triggered when a read goes above the bounds of a TA memory region.
    """
    _report_mem_read(
        state,
        "sw_or_nw_read",
        "MemSan: Secure World or Normal World Read",
        "CRITICAL",
    )


def _ta_memsan_sw_or_nw_write(state: SimState):
    """
    Triggered when a write goes above the bound of a TA memory region.
    """
    _report_mem_write(
        state,
        "sw_or_nw_write",
        "MemSan: Secure World or Normal World Write",
        "CRITICAL",
    )

@ta_plugin()
class TA_MemSanPlugin(TAPlugin):
    """
    Plugin to detect memory sanitization bugs in the TA.
    Registers breakpoints on memory read/write and reports:
    - Tainted/untrusted address access (secure world) -> warning
    - Untainted address access (normal world) -> critical
    - Possibly normal or secure world access -> critical
    """

    def __init__(self):
        super().__init__()
        logger.info("TA_MemSanPlugin initializing")
        self.reported_sw_write = set()
        self.reported_sw_read = set()
        self.reported_nw_write = set()
        self.reported_nw_read = set()
        self.reported_sw_or_nw_write = set()
        self.reported_sw_or_nw_read = set()

    def init_breakpoints(self, state: SimState):
        """
        Initialize the memory access breakpoints for the plugin.
        When triggered, these call the corresponding check function.
        Args:
            state: The initial state to be stepped.
        """
        state.globals[TA_MEMSAN_PLUGIN_KEY] = self
        state.inspect.b("sw_mem_read", when=angr.BP_BEFORE, action=_ta_memsan_sw_read)
        state.inspect.b("sw_mem_write", when=angr.BP_BEFORE, action=_ta_memsan_sw_write)
        state.inspect.b("nw_mem_read", when=angr.BP_BEFORE, action=_ta_memsan_nw_read)
        state.inspect.b("nw_mem_write", when=angr.BP_BEFORE, action=_ta_memsan_nw_write)
        state.inspect.b("sw_or_nw_mem_read", when=angr.BP_BEFORE, action=_ta_memsan_sw_or_nw_read)
        state.inspect.b("sw_or_nw_mem_write", when=angr.BP_BEFORE, action=_ta_memsan_sw_or_nw_write)
