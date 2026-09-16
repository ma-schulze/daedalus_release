import angr
import claripy

from angr.sim_state import SimState
from typing import List

from reporting import add_detected_bug
from .ta_plugin import TAPlugin, ta_plugin
from utils.logging_config import get_logger
from explorer.memory.ta_memory_utils import _constraint_in_ranges, constraint_access_over_border

logger = get_logger(__name__)

@ta_plugin()
class TA_StackSanPlugin(TAPlugin):
    """
    Plugin to detect stack overflow bugs in the TA.
    It adds a breakpoint on each stackframe allocation.
    Before and after an allocation, additional bytes are allocated from the stack where canaries are stored.
    When a read or write is detected, the plugin checks if the address is within the canary range.
    If it is, the plugin reports a stack overflow.
    """
    def __init__(self):
        """
        Initialize the plugin.
        """
        super().__init__()
        logger.info("TA_StackSanPlugin initializing")
        self.reported_stack_reads = set()
        self.reported_stack_writes = set()
        self.reported_compiler_stack_overflows = set()

    def init_breakpoints(self, state: SimState):
        """
        Initialize the breakpoints for the plugin.
        When triggered, call the corresponding check function.
        Args:
            state: The initial state to be stepped.
        """
        state.globals['stack_san_plugin'] = self
        state.globals['stack_canaries'] : List[int] = []
        state.inspect.b('exit', when=angr.BP_BEFORE, action=on_cf_exit)
        state.inspect.b('sw_mem_read', when=angr.BP_AFTER, action=on_sw_mem_read)
        state.inspect.b('sw_mem_write', when=angr.BP_AFTER, action=on_sw_mem_write)


def on_cf_exit(state: SimState):
    """
    Triggered on each control-flow exit (call or return).
    Tracks canary *ranges* only: we do not modify SP or memory so the engine's
    transition stays correct. We also replace the canaries list instead of mutating
    it so forked states don't share one list.

    Logic:
    1. On call: SP points to the end of the previous (caller's) frame. The canary
       is the 4 bytes just above that (higher addresses), i.e. [sp, sp + canary_size - 1].
    2. On return: remove the topmost guard range (pop).
    """
    try:
        sp = state.solver.eval_one(state.regs.sp)
    except Exception:
        return
    jumpkind = state.inspect.exit_jumpkind
    target = state.inspect.exit_target
    try:
        exit_addr = state.solver.eval_one(target)
        if state.project.is_hooked(exit_addr):
            return
    except Exception:
        pass

    # Copy list so we don't mutate a list shared by forked states
    canaries = list(state.globals["stack_canaries"])

    if jumpkind == "Ijk_Call":
        # 4 bytes just above SP (end of caller's frame) = canary; stack grows down
        canaries.append(sp)
    elif jumpkind == "Ijk_Ret":
        if canaries:
            address = state.addr 
            if not state.project.is_hooked(address):
                canaries.pop()
        else:
            logger.debug("Stack canary not found on ret (tail call or first return)")
    else:
        return

    state.globals["stack_canaries"] = canaries

def on_sw_mem_read(state: SimState):
    """
    Triggered when a read is detected in the secure world.
    Checks if the read address is within the canary range.
    If it is, the plugin reports a stack overflow.
    Args:
        state: The state that triggered the breakpoint.
    """
    read_addr = state.inspect.mem_read_address
    if type(read_addr) == int:
        read_addr = claripy.BVV(read_addr, state.arch.bits)

    plugin = state.globals.get('stack_san_plugin')
    if plugin is None:
        return

    read_size = state.inspect.mem_read_length
    if state.solver.symbolic(read_addr):
        try:
            read_addr = state.solver.eval_one(read_addr)
        except Exception:
            return
    if state.solver.symbolic(read_size):
        read_size = state.solver.max_int(read_size)

    constrints_access_over_canaries = constraint_access_over_border(read_addr, read_size, state.globals['stack_canaries'], state.arch.bits)

    if constrints_access_over_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_access_over_canaries]):
        bug_id = (read_addr, "read")
        if bug_id in plugin.reported_stack_reads:
            return
        plugin.reported_stack_reads.add(bug_id)
        add_detected_bug(state, "Stack overflow access over canaries", read_addr, "CRITICAL")


def on_sw_mem_write(state: SimState):
    """
    Triggered when a write is detected in the secure world.
    Checks if the write address is within the canary range.
    If it is, the plugin reports a stack overflow.
    Args:
        state: The state that triggered the breakpoint.
    """
    write_addr = state.inspect.mem_write_address
    if type(write_addr) == int:
        write_addr = claripy.BVV(write_addr, state.arch.bits)
    
    plugin = state.globals.get('stack_san_plugin')
    if plugin is None:
        return

    write_size = state.inspect.mem_write_length
    if state.solver.symbolic(write_addr):
        write_addr = state.solver.eval_one(write_addr)
    if state.solver.symbolic(write_size):
        write_size = state.solver.max_int(write_size)

    constrints_access_over_canaries = constraint_access_over_border(write_addr, write_size, state.globals['stack_canaries'], state.arch.bits)

    if constrints_access_over_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_access_over_canaries]):
        bug_id = (write_addr, "write")
        if bug_id in plugin.reported_stack_writes:
            return
        plugin.reported_stack_writes.add(bug_id)
        
        add_detected_bug(state, "Stack overflow write over canaries", write_addr, "CRITICAL")


def report_stack_overflow(state: SimState, addr: int, size: int, kind: str = "unknown"):
    """
    Report a stack overflow from another source, e.g., when compiler-based stack check fails are triggered.
    Args:
        state: The state that triggered the breakpoint.
        addr: The address of the stack overflow.
        size: The size of the stack overflow.
        kind: The kind of stack overflow. Default is "unknown".
    """
    
    plugin = state.globals.get('stack_san_plugin')
    if plugin is None:
        return

    bug_id = (addr, kind)
    if bug_id in plugin.reported_stack_overflows:
        return
    
    plugin.reported_stack_overflows.add(bug_id)
    logger.warning(f"Stack overflow from {kind}: {addr} size={size}")
    add_detected_bug(state, f"Stack overflow {kind}", addr, "CRITICAL")