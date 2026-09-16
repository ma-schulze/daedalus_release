import angr
from angr.sim_state import SimState
from reporting import add_detected_bug
from .ta_plugin import TAPlugin, ta_plugin
from utils.logging_config import get_logger

logger = get_logger(__name__)

@ta_plugin()
class TA_DoubleFreeSanPlugin(TAPlugin):
    """
    Plugin to detect double free bugs in the TA.
    It adds a breakpoint on each free instruction that then analyzes if the memory may be freed twice.
    """
    def __init__(self):
        """
        Initialize the plugin.
        """
        logger.info("DoubleFreeSanPlugin initializing")
        # Sets to track reported bugs and avoid duplicates
        self.reported_symbolic_ta_jumps = set()
        self.reported_symbolic_tainted_jumps = set()
        self.reported_concrete_tainted_jumps = set()
        self.reported_concrete_ta_jumps = set()

    def init_breakpoints(self, state: SimState):
        """
        Initialize the breakpoints for the plugin.
        When triggered, call check_double_free function.
        
        Args:
            state: The initial state to be stepped.
        """
        state.globals['double_free_san_plugin'] = self
        state.inspect.b('free', when=angr.BP_BEFORE, action=check_double_free)


def check_double_free(state: SimState):
    """
    Check if the memory may be freed twice.
    """
    free_addr = state.inspect.address
    if state.solver.symbolic(free_addr):
        try:
            free_addr = state.solver.eval_one(free_addr)
        except Exception:
            return

    if not hasattr(state.globals, 'free_dict'):
        state.globals['free_dict'] = {}

    if free_addr in state.globals['free_dict']:
        logger.warning(f"Memory at {hex(free_addr)} may be freed twice")
        add_detected_bug(
            state,
            bug_type="Double free",
            bug_address=free_addr,
            target_expr=free_addr,
            satisfiable=True,
            criticality="CRITICAL"
        )
    else:
        state.globals['free_dict'] = dict(state.globals['free_dict'])
        state.globals['free_dict'][free_addr] = 1
