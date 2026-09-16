from angr import SimulationManager
from angr.exploration_techniques import ExplorationTechnique

import signal

from utils.logging_config import get_logger

logger = get_logger(__name__)


class StepTimeoutError(Exception):
    """Raised when a step times out."""
    pass


class TA_Timeout(ExplorationTechnique):
    """
    Exploration technique that applies a timeout to each step.
    If a step exceeds the timeout, the active states are marked as panicked
    so they will be filtered out by TA_Filter.
    """
    
    def __init__(self, timeout=30, **kwargs):
        """
        Args:
            timeout: Maximum time in seconds for each step (default: 30)
            **kwargs: Additional arguments passed to parent ExplorationTechnique
        """
        super().__init__(**kwargs)
        self.timeout = timeout
        logger.debug(f"TA_Timeout initialized with {timeout}s timeout per step")


    def _timeout_handler(self, _signum, _frame):
        """
        Signal handler for timeout that triggers a StepTimeoutError.
        """
        raise StepTimeoutError(f"Step exceeded {self.timeout}s timeout")
    

    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        """
        Step through the simulation manager and apply a timeout to each step.
        Args:
            simgr: The simulation manager
            stash: The stash to step from
            **kwargs: Additional arguments passed to parent step

        Returns:
            The simulation manager after stepping
        """
        # Set up the timeout using SIGALRM
        old_handler = signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.timeout)
        
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except StepTimeoutError:
            logger.warning(f"Step timed out after {self.timeout}s! Marking state as panicked.")
            
            state = simgr.stashes[stash][0]
            state.globals['ta_panic'] = True
            state.globals['panic_addr'] = state.addr if hasattr(state, 'addr') else 'timeout'
            state.globals['panic_reason'] = f'Step timeout after {self.timeout}s'
        finally:
            # Cancel the alarm and restore the old handler
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        
        return simgr
