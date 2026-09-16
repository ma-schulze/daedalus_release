from angr import SimulationManager, SimState
from angr.exploration_techniques import ExplorationTechnique

import traceback

from utils.logging_config import get_logger
from reporting import add_detected_bug, add_stub_function

logger = get_logger(__name__)

class TA_Filter(ExplorationTechnique):
    """
    Angr ExplorationTechnique that removes active states if they fulfill certain conditions.
    These conditions are:
    - Paniced 
        - Panic SVC was called 
        - The state timed out
        - Internal execution of the step threw an exception
    - Sys_Return 
        - The TA returned to Normal World (i.e., syscall_sys_return was called)
    - Max_Depth 
        - The maximum call depth was reached
    The states that fulfill these conditions are moved to the respective stash and an entry is added to the report.
    """

    def __init__(self, max_depth_limit: int=1000):
        """
        Args:
            max_depth_limit: The maximum call depth to allow before filtering
        """
        super().__init__()
        self.max_depth_limit = max_depth_limit
        logger.debug("TA_Filter initialized")


    def _filter_panic(self, state: SimState):
        """
        Filter states that are panicked, i.e., the state's global panic flag is set.
        
        Args:
            state: The state to filter

        Returns:
            True if the state is to be filtered, False otherwise
        """
        panic = state.globals.get('ta_panic', False)
        if panic:
            return True
        return False


    def _filter_sys_return(self, state: SimState):
        """
        Filter states that are sys_return, i.e., the state's global sys_return flag is set.
        
        Args:
            state: The state to filter

        Returns:
            True if the state is to be filtered, False otherwise
        """
        sys_return = state.globals.get('ta_sys_return', False)
        if sys_return:
            return True
        return False


    def _filter_max_depth(self, state: SimState):
        """
        Filter states that have exceeded the maximum call depth.
        
        Args:
            state: The state to filter

        Returns:
            True if the state is to be filtered, False otherwise
        """
        max_depth = state.history.depth > self.max_depth_limit
        if max_depth:
            return True
        return False


    def _filter_unhooked_functions(self, state: SimState):
        """
        Filter states that call an unhooked function or a stub (hooked but placeholder).
        Unhooked addresses are moved to the unhooked_functions stash.
        When the address is hooked but the SimProcedure is a stub, the stub name is
        logged and recorded in the report's "Stub functions called" section, then
        the state is filtered as well.

        Args:
            state: The state to filter

        Returns:
            True if the state is to be filtered, False otherwise
        """
        
        try:
            addr = state.solver.eval_one(state.addr)
        except Exception:
            try:
                addr = state.solver.eval_upto(state.addr, 1)[0]
            except Exception:
                addr = None 
        if not addr:
            logger.warning("Address cannot be concretized, skipping unhooked function check")
            return False 

        if not state.project.is_hooked(addr):
            return False 

        hook = state.project.hooked_by(addr)
        if hook is None:
            return False

        if not hook.is_stub:
            return False

        # Hooked but stub: log name and add to report section, then filter
        name = getattr(hook, "display_name", None) or getattr(hook, "__name__", "unknown")
        logger.debug("Stub function called: %s at %s", name, hex(addr) if addr is not None else "?")
        add_stub_function(name, addr)
        return True


    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs):
        """
        Step through the simulation manager and filter states that fulfill certain conditions.
        Args:
            simgr: The simulation manager
            stash: The stash to step from
            **kwargs: Additional arguments passed to parent step

        Returns:
            The simulation manager after stepping
        """

        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as e:
            logger.error(f"Error in step: {e}")
            traceback.print_exc()
            state = simgr.stashes[stash][0]
            state.globals['ta_panic'] = True

        simgr.move(stash, "panicked", self._filter_panic)
        simgr.move(stash, "sysret", self._filter_sys_return)
        simgr.move(stash, "max_depth", self._filter_max_depth)
        simgr.move(stash, "unhooked_functions", self._filter_unhooked_functions)
        return simgr
