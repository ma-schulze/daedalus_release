from angr import SimulationManager
from angr.exploration_techniques import DFS

from utils.logging_config import get_logger

logger = get_logger(__name__)


class TA_DFS_Exploration(DFS):
    """
    Custom DFS exploration technique.
    This exploration technique inherits from angr DFS exploration technique.
    The only difference is that we also promote states before stepping incase they were pruned by a previous exploration technique.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize the TA DFS exploration technique.
        
        Args:
            **kwargs: Additional arguments passed to parent DFS
        """
        super().__init__(**kwargs)
        logger.debug("TA_DFS_Exploration initialized")
    
    
    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        """
        Promote deferred states if we have no active state.
        Finally, we just call the parent DFS step.
        
        Args:
            simgr: The simulation manager
            stash: The stash to step from
            **kwargs: Additional arguments passed to parent DFS step
            
        Returns:
            The simulation manager after stepping
        """

        logger.debug("Stepping DFS Exploration")
        if not hasattr(simgr, 'deferred'):
            simgr.stashes['deferred'] = []

        if hasattr(simgr, 'active') and not simgr.active and simgr.stashes.get('deferred', []):
            promoted_state = simgr.stashes['deferred'].pop()
            simgr.active.append(promoted_state)
        
        if hasattr(simgr, 'local_stash') and not simgr.local_stash and simgr.stashes.get('deferred', []):
            promoted_state = simgr.stashes['deferred'].pop()
            simgr.local_stash.append(promoted_state)

        simgr = super().step(simgr, stash=stash, **kwargs)
        return simgr
