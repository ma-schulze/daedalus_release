import angr
import claripy
import copy
from angr.sim_state import SimState
from typing import List

from reporting import add_detected_bug
from .ta_plugin import TAPlugin, ta_plugin
from utils.logging_config import get_logger
from explorer.memory.ta_memory_utils import _AddrRange, _constraint_in_ranges, _constraint_straddles_ranges

logger = get_logger(__name__)

@ta_plugin()
class TA_HeapSanPlugin(TAPlugin):
    """
    Plugin to detect heap overflow bugs in the TA.
    It adds a breakpoint on each heap allocation.
    Before and after an allocation, additional bytes are allocated from the heap where canaries are stored.
    When a read or write is detected, the plugin checks if the address is within the canary range.
    If it is, the plugin reports a heap overflow.
    """
    def __init__(self):
        """
        Initialize the plugin.
        """
        super().__init__()
        logger.info("TA_HeapSanPlugin initializing")
        self.reported_heap_writes = set()
        self.reported_heap_reads = set()
    
    def init_breakpoints(self, state: SimState):
        """
        Initialize the breakpoints (heap allocation and sw mem read/write) for the plugin.
        When triggered, call the corresponding check functions.
        Args:
            state: The initial state to be stepped.
        """
        state.globals['heap_san_plugin'] = self
        state.globals['heap_canaries_list'] : List[_AddrRange] = []
        state.inspect.b('heap_alloc', when=angr.BP_BEFORE, action=on_heap_alloc)
        state.inspect.b('heap_alloc', when=angr.BP_AFTER, action=on_heap_alloc)
        state.inspect.b('sw_mem_write', when=angr.BP_BEFORE, action=check_heap_write)
        state.inspect.b('sw_mem_read', when=angr.BP_BEFORE, action=check_heap_read)


def on_heap_alloc(state: SimState):
    """
    Triggered when a heap allocation is detected.
    Before and after the allocation, additional bytes are allocated from the heap where canaries are stored.
    Args:
        state: The state that triggered the breakpoint.
    """
    canary_addr = state.heap.allocate(8)   
    state.memory.store(canary_addr, claripy.BVV(0x12345678, 64), size=8, endness=state.arch.memory_endness)
    state.globals['heap_canaries_list'] = copy.deepcopy(state.globals['heap_canaries_list'])
    state.globals['heap_canaries_list'].append((canary_addr, canary_addr + 8 - 1))  # bounds are inclusive I think, TODO double check


def check_heap_read(state: SimState):
    """
    Triggered when a heap read is detected.
    Checks if the read address is within the canary range.
    If it is, the plugin reports a heap overflow.
    Args:
        state: The state that triggered the breakpoint.
    """
    plugin = state.globals.get('heap_san_plugin')
    if plugin is None:
        return

    read_addr = state.inspect.mem_read_address
    if type(read_addr) == int:
        read_addr = claripy.BVV(read_addr, state.arch.bits)

    read_size = state.inspect.mem_read_length
    if state.solver.symbolic(read_addr):
        try:
            read_addr = state.solver.eval_one(read_addr)
        except Exception:
            return
    if state.solver.symbolic(read_size):
        read_size = state.solver.max_int(read_size)

    bug_id = (read_addr, "read")
    if bug_id in plugin.reported_heap_reads:
        return
    plugin.reported_heap_reads.add(bug_id)

    constrints_in_canaries = _constraint_in_ranges(read_addr, read_size, state.globals['heap_canaries_list'], state.arch.bits)
    constrints_straddles_canaries = _constraint_straddles_ranges(read_addr, read_size, state.globals['heap_canaries_list'], state.arch.bits)

    if constrints_in_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_in_canaries]):
        logger.warning(f"Heap read: {read_addr} size={read_size}")
        add_detected_bug(state, "Heap overflow", read_addr, "CRITICAL")

    if constrints_straddles_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_straddles_canaries]):
        logger.warning(f"Heap read: {read_addr} size={read_size}")
        add_detected_bug(state, "Heap overflow straddles", read_addr, "CRITICAL")


def check_heap_write(state: SimState):
    """
    Triggered when a heap write is detected.
    Checks if the write address is within the canary range.
    If it is, the plugin reports a heap overflow.
    Args:
        state: The state that triggered the breakpoint.
    """
    plugin = state.globals.get('heap_san_plugin')
    if plugin is None:
        return

    write_addr = state.inspect.mem_write_address
    if type(write_addr) == int:
        write_addr = claripy.BVV(write_addr, state.arch.bits)

    write_size = state.inspect.mem_write_length
    if state.solver.symbolic(write_addr):
        try:
            write_addr = state.solver.eval_one(write_addr)
        except Exception:
            return
    if state.solver.symbolic(write_size):
        write_size = state.solver.max_int(write_size)

    bug_id = (write_addr, "write")
    if bug_id in plugin.reported_heap_writes:
        return
    
    plugin.reported_heap_writes.add(bug_id)

    constrints_in_canaries = _constraint_in_ranges(write_addr, write_size, state.globals['heap_canaries_list'], state.arch.bits)
    constrints_straddles_canaries = _constraint_straddles_ranges(write_addr, write_size, state.globals['heap_canaries_list'], state.arch.bits)

    if constrints_in_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_in_canaries]):
        logger.warning(f"Heap write: {write_addr} size={write_size}")
        logger.warning(f"Canaries: {state.globals['heap_canaries_list']}")
        add_detected_bug(state, "Heap overflow", write_addr, "CRITICAL")

    if constrints_straddles_canaries is not claripy.false and state.solver.satisfiable(extra_constraints=[constrints_straddles_canaries]):
        logger.warning(f"Heap write: {write_addr} size={write_size}")
        logger.warning(f"Canaries: {state.globals['heap_canaries_list']}")
        add_detected_bug(state, "Heap overflow straddles", write_addr, "CRITICAL")
