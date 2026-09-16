from angr import SimulationManager
from angr.exploration_techniques import ExplorationTechnique
from angr.errors import SimValueError

from typing import Set, Optional

from reporting import update_stats, add_function_coverage, update_block_coverage
from utils.logging_config import get_logger

logger = get_logger(__name__)


class TA_Statistics(ExplorationTechnique):
    """
    Exploration technique that collects statistics about the states explored.
    Tracks basic block coverage against the set of reachable blocks.
    The resulting statistics are used to generate the coverage report.
    """

    def __init__(self, reachable_blocks: Optional[Set[int]] = None):
        """
        Initialize the statistics collector.
        
        Args:
            reachable_blocks: Set of all reachable basic block addresses from CFG analysis.
                              If provided, enables coverage percentage calculation.
        """
        super().__init__()
        self.visited_addresses: Set[int] = set()
        self.states_explored = 0
        self.max_depth = 0
        self.reachable_blocks = reachable_blocks or set()
        self._last_coverage_update = 0  # Track when we last updated coverage
        
        if self.reachable_blocks:
            logger.debug(f"TA_Statistics initialized with {len(self.reachable_blocks)} reachable blocks")
        else:
            logger.debug("TA_Statistics initialized (no reachable blocks provided)")


    @staticmethod
    def _get_concrete_pc(state) -> Optional[int]:
        """
        Get the current program counter as a concrete int, or None if it is symbolic
        with multiple solutions (avoids SimValueError from state.addr / eval_one).
        """
        try:
            return state.addr
        except SimValueError:
            # IP has multiple possible values (e.g. unconstrained); take one for stats
            try:
                ip = state.regs._ip
                solutions = state.solver.eval_upto(ip, 1)
                return solutions[0] if solutions else None
            except Exception:
                return None
        except Exception:
            return None


    
    def _update_coverage(self):
        """Update block coverage statistics in the report."""
        blocks_reachable = len(self.reachable_blocks)

        # Calculate which blocks we've actually hit
        # When reachable_blocks is known (from CFG / bb file), we only report
        # coverage for blocks in that set so merged reports can't exceed 100%.
        if self.reachable_blocks:
            covered_addrs = self.visited_addresses & self.reachable_blocks
            if len(covered_addrs) > self._last_coverage_update:
                logger.info(f"New max coverage: {len(covered_addrs)} blocks hit")
            self._last_coverage_update = len(covered_addrs)
        else:
            covered_addrs = self.visited_addresses

        blocks_hit = len(covered_addrs)

        update_block_coverage(
            blocks_hit=blocks_hit,
            blocks_reachable=blocks_reachable,
            visited_block_addrs=list(covered_addrs)
        )
    

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs):
        """
        Step through the simulation manager and collect statistics about the states explored.
        Args:
            simgr: The simulation manager
            stash: The stash to step from
            **kwargs: Additional arguments passed to parent step

        Returns:
            The simulation manager after stepping
        """
        if not simgr.stashes.get(stash):
            return simgr.step(stash=stash, **kwargs)

        # Count each state in the stash as one "state explored" (state-step event),
        # not just one per step() call, so the total reflects exploration volume.
        self.states_explored += len(simgr.stashes[stash])

        for state in simgr.stashes[stash]:
            depth = state.history.depth
            if depth > self.max_depth:
                self.max_depth = depth

            # Collect ALL visited basic block addresses from state history
            # This captures the full path, not just the current address
            if hasattr(state.history, 'bbl_addrs'):
                for addr in state.history.bbl_addrs:
                    if isinstance(addr, int):
                        self.visited_addresses.add(addr & ~1)
            
            # Also add the current address (safely; IP may be symbolic)
            pc = self._get_concrete_pc(state)
            if pc is not None:
                self.visited_addresses.add(pc & ~1)

        
        self._update_coverage()
        update_stats(
            states_explored=self.states_explored,
            targets_found=len(simgr.found) if hasattr(simgr, 'found') else 0,
            max_depth=self.max_depth
        )

        coverage_addresses = list(self.visited_addresses)
        hook_call_counts = state.globals['hook_call_counts']
        if hook_call_counts is not None:
            hook_call_counts = dict(hook_call_counts) 
        add_function_coverage(coverage_addresses, hook_call_counts=hook_call_counts)
        
        simgr = simgr.step(stash=stash, **kwargs)
        
        return simgr
