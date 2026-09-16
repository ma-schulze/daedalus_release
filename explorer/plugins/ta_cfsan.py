"""
TA control-flow sanitizer plugin: detects suspicious jumps (outside TA memory,
symbolic/tainted targets).
"""

import angr
from angr.sim_state import SimState
from reporting import add_detected_bug
from .ta_plugin import TAPlugin, ta_plugin
from explorer.memory import is_tainted
from explorer.memory.ta_memory_utils import addr_is_outside_ta_memory
from utils.logging_config import get_logger

logger = get_logger(__name__)

TA_CFSAN_PLUGIN_KEY = "ta_cfsan_plugin"


def _get_exit_source_addr(state: SimState):
    """
    Get the address of the block we're exiting from, without triggering solver evaluation.
    At 'exit' BP_BEFORE, state.addr may already be the (possibly symbolic) exit target;
    reading state.addr then calls solver.eval_one(ip) and can raise if the IP is symbolic.
    Use history instead.
    """
    if getattr(state.history, "recent_bbl_addrs", None):
        return state.history.recent_bbl_addrs[-1]
    try:
        return state.addr
    except Exception:
        return None


def _ta_cfsan_check_jumps(state: SimState):
    """
    Check for control-flow issues on exit: outside-TA or symbolic/tainted targets.
    Args:
        state: The state that triggered the breakpoint.
    """
    target = state.inspect.exit_target
    target_tainted = is_tainted(target)
    target_symbolic = state.solver.symbolic(target)
    
    pc = _get_exit_source_addr(state)
    if pc is None:
        return

    plugin = state.globals.get(TA_CFSAN_PLUGIN_KEY)
    if plugin is None:
        return

    bug = ""
    category = ""

    if target_symbolic:
        if addr_is_outside_ta_memory(state, target, 4):
            bug_id = (pc, "symbolic_outside_ta_jump")
            if bug_id not in plugin.reported_symbolic_ta_jumps:
                plugin.reported_symbolic_ta_jumps.add(bug_id)
                logger.warning("Symbolic jump potentially outside TA memory at PC=%s", hex(pc))
                bug = "Symbolic jump potentially outside TA memory"
                category = "CRITICAL"

        elif target_tainted:
            bug_id = (pc, "symbolic_tainted_jump")
            if bug_id not in plugin.reported_symbolic_tainted_jumps:
                plugin.reported_symbolic_tainted_jumps.add(bug_id)
                logger.warning("Symbolic jump to tainted target address at PC=%s", hex(pc))
                bug = "Symbolic jump to tainted target address"
                category = "INFO"
    else:
        concrete_target = state.solver.eval_one(target)
        if state.project.is_hooked(concrete_target):
            return

        if addr_is_outside_ta_memory(state, concrete_target, 4):
            bug_id = (pc, "concrete_outside_ta_jump")
            if bug_id not in plugin.reported_concrete_ta_jumps:
                plugin.reported_concrete_ta_jumps.add(bug_id)
                logger.warning(
                    "Concrete jump potentially outside TA memory at PC=%s to %s",
                    hex(pc),
                    hex(concrete_target),
                )
                bug = "Concrete jump potentially outside TA memory"
                category = "CRITICAL"

        elif target_tainted:
            bug_id = (pc, concrete_target, "concrete_tainted_jump")
            if bug_id not in plugin.reported_concrete_tainted_jumps:
                plugin.reported_concrete_tainted_jumps.add(bug_id)
                logger.warning(
                    "Concrete jump to tainted target address at PC=%s to %s",
                    hex(pc),
                    hex(concrete_target),
                )
                bug = "Concrete jump to tainted target address"
                category = "CRITICAL"
    if bug:
        add_detected_bug(state, bug, pc, category)


@ta_plugin()
class TA_CFSanPlugin(TAPlugin):
    """
    Plugin to detect control flow bugs in the TA.
    Registers a breakpoint on exit (jump) and reports:
    - Jump target outside TA memory (symbolic or concrete) -> critical
    - Symbolic/tainted jump target (when not from hooked call) -> critical
    """

    def __init__(self):
        super().__init__()
        logger.info("TA_CFSanPlugin initializing")
        self.reported_symbolic_ta_jumps = set()
        self.reported_symbolic_tainted_jumps = set()
        self.reported_concrete_tainted_jumps = set()
        self.reported_concrete_ta_jumps = set()

    def init_breakpoints(self, state: SimState):
        """
        Initialize the control flow breakpoints for the plugin.
        When triggered, call the corresponding check function.
        Args:
            state: The initial state to be stepped.
        """
        state.globals[TA_CFSAN_PLUGIN_KEY] = self
        state.inspect.b("exit", when=angr.BP_BEFORE, action=_ta_cfsan_check_jumps)
