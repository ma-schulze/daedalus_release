import angr
from angr import SimState, SimulationManager
from angr.exploration_techniques import ExplorationTechnique

import random
from typing import Callable, List, Union

from utils.logging_config import get_logger
from explorer.ta_init_function import TA_INIT_FUNCTION_REGISTRY, get_next_init_functions

logger = get_logger(__name__)

class TA_Reentry(ExplorationTechnique):
    """
    Angr ExplorationTechnique that creates new states at the reentry address when 
    the exit address is reached, using the exited state's memory view.
    
    This allows for finding bugs that require multiple invocations of the TA.
    
    When a command completes:
    - If it has chained next functions defined, a new state is created for EACH
    - If no chained functions, ONE state with a random function from the init functionregistry is created
    - If the registry is empty, the explorer's invoke_command_symbolic_inputs_func is used as fallback
    
    This enables exploring different combinations of init function sequences.
    """
    
    def __init__(self, explorer, exit_addrs: Union[int, List[int]], reentry_addr: int, reentry_count: int = 0, skip_error_states: bool = False, error_state_eval_function: Callable = None, **kwargs):
        """
        Args:
            explorer: The TAExplorer instance
            exit_addrs: The address(es) of the instruction(s) exiting the TA (single int or list of endpoints)
            reentry_addr: The address of the instruction reentering the TA (i.e., first instruction of TAInvokeCommandEntryPoint)
            reentry_count: The number of times a state reenters the TA (default: 0)
            skip_error_states: Whether to skip states that lead to error results from the TA (default: False)
            error_state_eval_function: A function to evaluate if a state is an error state (default: None)
            **kwargs: Additional arguments passed to parent ExplorationTechnique (e.g. exit_addr for backward compat, ignored)
        """
        super().__init__(**kwargs)
        self._exit_addrs = [exit_addrs] if isinstance(exit_addrs, int) else list(exit_addrs)
        self.reentry_addr = reentry_addr
        self.explorer = explorer
        self.reentry_count = reentry_count
        self.skip_error_states = skip_error_states
        self.error_state_eval_function = self._default_error_state_eval_function if error_state_eval_function is None else error_state_eval_function
        logger.debug("TA_Reentry initialized")


    def _default_error_state_eval_function(self, state: SimState) -> bool:
        """
        Evaluate if the state is an error state.
        By default, we evaluate if the return value of the InvokeCommandEntryPoint is non-zero.
        """
        return state.solver.eval(state.regs.x0) != 0


    def _create_reentry_state_with_func(self, simgr: SimulationManager, state: SimState, 
                                         symbolic_inputs_func: Callable) -> SimState:
        """
        Create a new state at the reentry address with a specific symbolic inputs function.
        
        Args:
            simgr: The simulation manager
            state: The state that exited the TA (provides memory context)
            symbolic_inputs_func: The function to apply for symbolic inputs
            
        Returns:
            The new state at the reentry address
        """
        # We need a new init state as a "donor" for a new, clean, register state for an entry-state 
        # We can then transfer these registers to the old state, avoiding having to instead transfer its memory to a new state.
        
        prototype = angr.sim_type.parse_signature(
            "int TA_InvokeCommandEntryPoint(void *a, size_t b, size_t c, void *d)"
        )
        new_state = simgr._project.factory.call_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
            addr=self.reentry_addr,
            prototype=prototype
        )
        
        # Copy register values from new entry state to the exited state
        for reg_name in state.arch.registers.keys():
            try:
                val = new_state.registers.load(reg_name)
                state.registers.store(reg_name, val)
            except KeyError:
                # some pseudo-registers may not be valid to load/store
                pass


        if simgr._project.arch.bits == 64:
            new_state.regs.tpidr_el0 = self.explorer.tls_obj.user_thread_pointer    

        # Apply the symbolic inputs function and track which one was used
        state = symbolic_inputs_func(state)
        state.globals['ta_init_function_name'] = symbolic_inputs_func.__name__
        return state


    def _create_reentry_states(self, simgr: SimulationManager, state: SimState) -> List[SimState]:
        """
        Create new state(s) at the reentry address for the next command(s).
        
        If the current function has chained next functions, creates a new state for EACH.
        Otherwise, creates ONE state with a random function from the registry.

        If the registry is empty, uses the explorer's invoke_command_symbolic_inputs_func.
         
        Args:
            simgr: The simulation manager
            state: The state that exited the TA
            
        Returns:
            List of new states at the reentry address
        """
        new_states = []
        next_funcs = []
        current_init_function_name = state.globals.get('ta_init_function_name')
        
        if current_init_function_name:
            next_funcs = get_next_init_functions(current_init_function_name)
        
        if next_funcs:
            logger.info(f"Creating {len(next_funcs)} reentry state(s) for chained init functions from {current_init_function_name}")
            for next_func in next_funcs:
                logger.debug(f"  -> {next_func.__name__}")
                new_state = self._create_reentry_state_with_func(simgr, state.copy(), next_func)
                new_states.append(new_state)
        else:
            if TA_INIT_FUNCTION_REGISTRY:
                random_func = random.choice(TA_INIT_FUNCTION_REGISTRY)
                logger.info(f"Using random symbolic inputs function from registry: {random_func.__name__}")
                new_state = self._create_reentry_state_with_func(simgr, state, random_func)
                new_states.append(new_state)
            else:
                logger.info("Registry empty, using explorer's invoke_command_symbolic_inputs_func")
                fallback_func = self.explorer.invoke_command_symbolic_inputs_func
                new_state = self._create_reentry_state_with_func(simgr, state, fallback_func)
                new_states.append(new_state)
        
        return new_states


    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        """
        Step through the simulation manager and create new state(s) at the reentry 
        address when the exit address is reached.
        
        Args:
            simgr: The simulation manager
            stash: The stash to step from
            **kwargs: Additional arguments passed to parent step

        Returns:
            The simulation manager after stepping
        """
        states = simgr.stashes[stash]
        for state in states:
            if state.addr in self._exit_addrs and self.reentry_count > 0:
                simgr.stashes[stash].remove(state)

                if self.skip_error_states and not self.error_state_eval_function(state):
                    continue
                
                num_reentries = state.globals.get('num_reentries', 0)
                if num_reentries >= self.reentry_count:
                    continue
                num_reentries += 1
                
                # Create new state(s) for reentry - may be multiple if chained
                new_states = self._create_reentry_states(simgr, state)
                
                # Add all new states to the stash with updated reentry count
                for new_state in new_states:
                    new_state.globals['num_reentries'] = num_reentries
                    simgr.stashes[stash].append(new_state)
                
                break

        simgr = simgr.step(stash=stash, **kwargs)
        return simgr
