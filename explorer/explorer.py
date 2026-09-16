import angr
from angr import SimProcedure, SimState
from angr.exploration_techniques import Threading, Veritesting, UniqueSearch

import claripy
import json
import os
import signal
import sys
import traceback
from multiprocessing import Process
import time
from typing import List, Optional, Dict, Tuple, Set

from utils.logging_config import get_logger
from utils.cfg_analyzer import get_reachable_blocks_from_project, generate_cfg, find_reachable_blocks_from_file
from reporting import finalize_report, init_report, add_syscall_stats
from explorer.hooks import get_syscall_stats
from explorer.hooks import install_os_hooks
from explorer.hooks import install_func_hooks
from explorer.exploration_techniques import TA_DFS_Exploration, TA_Filter, TA_Statistics, TA_Reentry, TA_Timeout
from explorer.plugins import TAPluginManager, TA_DEFAULT_EVENTS
from explorer.memory.ta_memory import TAMemory
from explorer.memory import get_tainted_mem_bits
from explorer.memory_monitor import setup_memory_limit, setup_adaptive_memory_limit



logger = get_logger(__name__)


class TAExplorer:
    """
    Main class for TA analysis.
    The workflow is as follows:
    1. Initialize all angr internals 
    2. Load the TA binary and do some preprocessing 
    3. Run the TA_CreateEntryPoint and TA_OpenSessionEntryPoint functions 
    4. Transfer the state to symbolic exploration 
    5. Run the symbolic exploration of the TA using the specified exploration techniques
    6. Generate the HTML report
    """

    @staticmethod
    def signal_handler(signum: int, _):
        """
        Signal handler for SIGINT (Ctrl+C) and SIGTERM (kill).
        Performs cleanup and finishes reporting before exiting.
        """
        logger.info("Signal handler called")
        signal_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
        
        # Log memory usage at shutdown
        try:
            from explorer.memory_monitor import get_memory_monitor
            monitor = get_memory_monitor()
            if monitor:
                mem_mb = monitor.current_memory_mb
                limit_mb = monitor.limit_mb
                logger.info(f"Memory at shutdown: {mem_mb:.1f}MB / {limit_mb:.1f}MB "
                           f"({mem_mb/limit_mb*100:.1f}%)")
                if monitor.limit_exceeded:
                    logger.warning("Shutdown triggered by memory limit exceeded")
        except Exception:
            pass
        
        logger.info(f"Caught {signal_name} signal. Finishing report generation...")
        
        try:
            # Add syscall statistics to the report
            syscall_stats = get_syscall_stats()
            add_syscall_stats(syscall_stats)
            
            # Finalize and generate HTML report
            report_path = finalize_report()
            logger.info(f"HTML Report generated successfully at: {report_path}")
        except Exception as e:
            logger.error(f"Error during report generation: {e}")
        finally:
            logger.info("Exiting gracefully...")
            sys.exit(0)


    @staticmethod
    def get_function_bounds_by_name(function_name: str, cfg) -> Tuple[int, List[int]]:
        """
        Get the start address and all exit/return addresses of a function by its name.
        Args:
            function_name: The name of the function to search for.
            cfg: angr CFG with kb.functions.
        Returns:
            A tuple (start_addr, list of endpoint addresses). Endpoints are return sites
            or block endpoints so that analysis can hook all exit points (e.g. multiple rets).
        """
        func = cfg.kb.functions.function(name=function_name)
        if func is None:
            return 0, []

        start = func.addr

        # Collect all return/exit addresses (multiple rets or endpoints)
        if func.ret_sites:
            endpoints = [site.addr for site in func.ret_sites]
        else:
            endpoints = [ep.addr for ep in func.endpoints]

        logger.info(f"Found {function_name} at {hex(start)} with {len(endpoints)} endpoint(s): {[hex(a) for a in endpoints]}")

        # return 0, []
        return start, endpoints

    
    @staticmethod
    def load_ta_metadata(ta_path: str) -> Optional[Dict]:
        """
        Load JSON metadata for a .ta file.
        Args:
            ta_path: Path to the .ta file.
        Returns:
            Dictionary containing metadata, or None if not found.
        """
        # Try to find JSON file with same base name
        base_name = os.path.splitext(ta_path)[0]
        json_path = base_name + ".json"
    
        
        # If not found, try to find any JSON file in the same directory
        # This handles cases where the .ta file and .json file have different names
        if not os.path.exists(json_path):
            dir_path = os.path.dirname(ta_path)
            if dir_path and os.path.isdir(dir_path):
                # Look for any .json file in the directory
                for filename in os.listdir(dir_path):
                    if filename.endswith(".json"):
                        candidate_path = os.path.join(dir_path, filename)
                        json_path = candidate_path
                        logger.debug(f"Found potential JSON metadata: {json_path}")
                        break
        
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    metadata = json.load(f)
                    logger.info(f"Loaded TA metadata from {json_path}")
                    return metadata
            except Exception as e:
                logger.warning(f"Failed to load JSON metadata from {json_path}: {e}")
        else:
            logger.debug(f"JSON metadata file not found for {ta_path}")
        
        return {}
    

    @staticmethod
    def get_entry_points_from_metadata(metadata: Dict) -> Dict[str, Tuple[int, List[int]]]:
        """
        Extract entry point addresses from JSON metadata.
        Args:
            metadata: Dictionary containing TA metadata.
        Returns:
            Dictionary mapping entry point names to (start, list of endpoints) tuples.
            JSON may use "_start" / "_end" keys; _end can be a single address or a list of exit addresses.
        """
        entry_points: Dict[str, Tuple[int, List[int]]] = {}

        for key, value in metadata.items():
            if not key.endswith("_start"):
                continue
            func_name = key[:-6]  # Remove "_start" suffix
            end_key = func_name + "_end"

            start_addr = value
            if end_key in metadata:
                end_value = metadata[end_key]
                if isinstance(end_value, list):
                    endpoints = [int(a) for a in end_value if a is not None]
                else:
                    endpoints = [int(end_value)] if end_value is not None else []
            else:
                # If no end address, use start + default size as single fallback endpoint
                endpoints = [start_addr + 256]

            entry_points[func_name] = (start_addr, endpoints)
            logger.debug(f"Entry point {func_name}: start={hex(start_addr)}, endpoints={[hex(a) for a in endpoints]}")
        return entry_points


    # Default configuration values
    DEFAULT_CONFIG = {
        'input_format': 'ta',
        # Hooks and symbolic input functions
        'os_hook_name': 'optee',
        'additional_func_hooks': None,
        'open_session_symbolic_inputs_func': None,
        'invoke_command_symbolic_inputs_func': None,
        # Run identifier (used for report filename to distinguish parallel runs)
        'run_id': None,
        # Exploration techniques
        'enable_dfs': True,
        'enable_loop_seer': False,
        'enable_reentry': False,
        'enable_threading': False,
        'enable_veritesting': False,
        # Timeouts and limits
        'enable_step_timeout': True,
        'step_timeout': 10,
        'reentry_count': 0,
        # Memory limits
        'memory_limit_gb': 500,  # Fixed memory limit in GB (None = no limit)
        'memory_adaptive': False,  # Enable adaptive memory limits
        'memory_total_gb': None,  # Total memory pool for adaptive mode (None = 90% of system)
        'memory_min_gb': 5.0,  # Minimum limit per process in adaptive mode
        'memory_max_gb': None,  # Maximum limit per process in adaptive mode (None = no max)
        'memory_check_interval': 5.0,  # How often to check memory (seconds)
        'memory_threshold_percent': 0.95,  # Trigger at this % of limit
        # Features
        'use_svc_hooks': True,
        'enable_plugins': True,
        'enable_memory_model': True,
        'compute_cfg_coverage': True,  # Whether to compute CFG for coverage tracking
        'cfg_path': None,
    }


    def __init__(self, input_file: str, config: dict = None):
        """
        Initialize the TAExplorer.
        Args:
            input_file: The path to the input file.
            config: Configuration dictionary with the following optional keys:
                - input_format: The format of the input file (default: 'ta')
                - os_hook_name: The name of the Trusted OS to install hooks from (default: 'optee')
                - additional_func_hooks: Additional function hooks to install
                - open_session_symbolic_inputs_func: Function to set symbolic inputs for open session
                - invoke_command_symbolic_inputs_func: Function to set symbolic inputs for invoke command
                - enable_dfs: Enable DFS exploration technique (default: True)
                - enable_reentry: Enable reentry exploration technique (default: False)
                - enable_threading: Enable threading exploration technique (default: False)
                - enable_veritesting: Enable veritesting exploration technique (default: False)
                - enable_step_timeout: Enable step timeout (default: True)
                - step_timeout: Timeout in seconds for each step (default: 10)
                - reentry_count: Number of reentries to allow (default: 10)
                - use_svc_hooks: Use SVC hooks (default: True)
                - enable_plugins: Enable plugins (default: True)
                - enable_memory_model: Enable custom memory model (default: True)
                - cfg_path: Path to a file containing basic block information about the TA CFG (default: None)
        """
        logger.info("Initializing TAExplorer")
        
        # Merge provided config with defaults
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        
        self.ta_path = input_file

        open_session_symbolic_inputs_func = self.config['open_session_symbolic_inputs_func']
        invoke_command_symbolic_inputs_func = self.config['invoke_command_symbolic_inputs_func']

        if open_session_symbolic_inputs_func:
            self.open_session_symbolic_inputs_func = open_session_symbolic_inputs_func
        else:
            self.open_session_symbolic_inputs_func = self._default_symbolic_inputs_func

        if invoke_command_symbolic_inputs_func:
            self.invoke_command_symbolic_inputs_func = invoke_command_symbolic_inputs_func
        else:
            self.invoke_command_symbolic_inputs_func = self._default_symbolic_inputs_func

        angr.state_plugins.inspect.event_types = angr.state_plugins.inspect.event_types.union(TA_DEFAULT_EVENTS)

        self.project = angr.Project(
            self.ta_path,
            load_options={
                "main_opts": {
                    "base_addr": 0x0,
                }
            },
            auto_load_libs=False,
            use_sim_procedures=True,
        )
        self.ta_binary_size = self.project.loader.main_object.max_addr - self.project.loader.main_object.min_addr

        ## remove built-in syscall library
        self.project.simos.syscall_library = None
        self.tls_obj = self.project.loader.tls.new_thread()


        logger.info("Project initialized")

        arch = self.project.arch.name
        self.cfg = generate_cfg(self.project) # preset_starts=974856

        self.metadata = TAExplorer.load_ta_metadata(self.ta_path)
        
        # Try to extract entry points from ELF symbols first
        self.create_entry_point = self.get_function_bounds_by_name("TA_CreateEntryPoint", self.cfg)
        self.open_session = self.get_function_bounds_by_name("__GP11_TA_OpenSessionEntryPoint", self.cfg)
        if self.open_session[0] == 0 or not self.open_session[1]:
            self.open_session = self.get_function_bounds_by_name("TA_OpenSessionEntryPoint", self.cfg)

        self.invoke_command = self.get_function_bounds_by_name("__GP11_TA_InvokeCommandEntryPoint", self.cfg)
        if self.invoke_command[0] == 0 or not self.invoke_command[1]:
            self.invoke_command = self.get_function_bounds_by_name("TA_InvokeCommandEntryPoint", self.cfg)

        # If entry points extraction from ELF failed, try JSON metadata as fallback (for .ta files)
        if (self.invoke_command[0] == 0 or not self.invoke_command[1] or
                self.open_session[0] == 0 or not self.open_session[1] or
                self.create_entry_point[0] == 0 or not self.create_entry_point[1]):
            logger.info("Some entry points not found in ELF, trying JSON metadata as fallback...")
            if self.metadata:
                entry_points = TAExplorer.get_entry_points_from_metadata(self.metadata)
                
                # Use JSON entry points if ELF extraction failed
                def _normalize_bounds(bounds) -> Tuple[int, List[int]]:
                    """Ensure bounds is (start, list of endpoints)."""
                    if not bounds or bounds[0] == 0:
                        return (0, [])
                    start, ends = bounds[0], bounds[1]
                    if isinstance(ends, list):
                        return (start, ends)
                    return (start, [ends] if ends else [])

                if self.create_entry_point[0] == 0 or not self.create_entry_point[1]:
                    self.create_entry_point = _normalize_bounds(entry_points.get("TA_CreateEntryPoint", (0, [])))
                    if self.create_entry_point[0] != 0:
                        logger.info(f"Found TA_CreateEntryPoint from JSON: {hex(self.create_entry_point[0])}")

                if self.open_session[0] == 0 or not self.open_session[1]:
                    self.open_session = _normalize_bounds(entry_points.get("TA_OpenSessionEntryPoint", (0, 0)))
                    if self.open_session[0] == 0:
                        self.open_session = _normalize_bounds(entry_points.get("__GP11_TA_OpenSessionEntryPoint", (0, 0)))
                    if self.open_session[0] != 0:
                        logger.info(f"Found TA_OpenSessionEntryPoint from JSON: {hex(self.open_session[0])}")

                if self.invoke_command[0] == 0 or not self.invoke_command[1]:
                    self.invoke_command = _normalize_bounds(entry_points.get("TA_InvokeCommandEntryPoint", (0, 0)))
                    if self.invoke_command[0] == 0:
                        self.invoke_command = _normalize_bounds(entry_points.get("__GP11_TA_InvokeCommandEntryPoint", (0, 0)))
                    if self.invoke_command[0] != 0:
                        logger.info(f"Found TA_InvokeCommandEntryPoint from JSON: {hex(self.invoke_command[0])}")
            else:
                logger.warning("JSON metadata not available as fallback")
        
        # Compute reachable blocks from CFG for coverage tracking
        self.reachable_blocks: Set[int] = set()
        logger.info("Computing reachable blocks from CFG...")
        if self.config['cfg_path']:
            try: 
                self.reachable_blocks = find_reachable_blocks_from_file(self.config['cfg_path'], self.invoke_command[0])
                logger.info(f"Found {len(self.reachable_blocks)} reachable basic blocks from CFG file")
            except Exception as e:
                logger.warning(f"Failed to compute CFG coverage from file: {e}")
                return
        
        if not self.reachable_blocks:
            try:
                self.reachable_blocks = get_reachable_blocks_from_project(
                    self.cfg, 
                    self.invoke_command[0]
                )
                logger.info(f"Found {len(self.reachable_blocks)} reachable basic blocks from TA_InvokeCommandEntryPoint")
            except Exception as e:
                logger.warning(f"Failed to compute CFG coverage from project: {e}")


    def _make_preparations(self):
        """
        Make the preparations for the run.
        This includes:
        - Registering signal handlers for graceful shutdown
        - Setting up memory monitoring (if limit configured)
        - Initializing the HTML report
        - Installing the Trusted OS and function hooks
        - Registering TAMemory as default memory class
        """
        logger.info("Making run preparations...")
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.memory_monitor = None
        check_interval = self.config.get('memory_check_interval', 5.0)
        threshold = self.config.get('memory_threshold_percent', 0.95)
        
        if self.config.get('memory_adaptive'):
            total_gb = self.config.get('memory_total_gb')  # None = auto-detect
            min_gb = self.config.get('memory_min_gb', 5.0)
            max_gb = self.config.get('memory_max_gb')
            
            logger.info(f"Setting up ADAPTIVE memory monitoring: "
                       f"pool={total_gb or 'auto'}GB, min={min_gb}GB, max={max_gb}GB, "
                       f"threshold={threshold*100}%, interval={check_interval}s")
            
            self.memory_monitor = setup_adaptive_memory_limit(
                total_memory_gb=total_gb,
                min_limit_gb=min_gb,
                max_limit_gb=max_gb,
                check_interval=check_interval,
                threshold_percent=threshold,
                auto_signal=True
            )
        elif self.config.get('memory_limit_gb'):
            limit_gb = self.config['memory_limit_gb']
            
            logger.info(f"Setting up memory monitoring: limit={limit_gb}GB, "
                       f"threshold={threshold*100}%, interval={check_interval}s")
            
            self.memory_monitor = setup_memory_limit(
                limit_gb=limit_gb,
                check_interval=check_interval,
                threshold_percent=threshold,
                auto_signal=True
            )
        else:
            logger.info("Memory monitoring disabled (no limit configured)")
        
        logger.info("Initializing HTML report...")
        init_report(
            binary_path=self.ta_path,
            start_addr=hex(self.invoke_command[0]),
            target_addr=hex(self.invoke_command[1][0]) if self.invoke_command[1] else "0x0",
            mem_base=0,
            run_id=self.config.get('run_id'),
            cfg=self.cfg,
        )

        if self.config.get('use_svc_hooks'):
            logger.info("Installing SVC Hooks...")
            install_os_hooks(self.project, self.ta_path, self.config['os_hook_name'])
        else:
            logger.info("Not installing SVC Hooks")

        install_func_hooks(self.project, self.metadata, self.cfg, providers=self.config['func_hook_providers'].split(','))

        if self.config['enable_memory_model']:
            logger.info("Registering TAMemory as default memory class...")
            SimState.register_default('sym_memory', TAMemory)
        else:
            logger.info("Custom memory model disabled")

        logger.info("Run preparations complete")


    def _setup_tls(self, state: SimState):
        """
        Setup the TLS for the state.
        
        Args:
            state: The state to setup the TLS for.
        """
        if self.project.arch.bits != 64:
            logger.warning("TLS setup not supported for non-64-bit architectures")
            return state.copy() 

        thread_local_stack_size = 0x2000
        thread_local_stack_addr = state.heap.allocate(thread_local_stack_size)

        state.regs.tpidr_el0 = self.tls_obj.user_thread_pointer   
        logger.info(f"TLS user thread pointer: {self.tls_obj.user_thread_pointer}")
        tls_thread_top = thread_local_stack_addr + thread_local_stack_size
        state.memory.store(self.tls_obj.user_thread_pointer - 8, tls_thread_top, size=8, endness=state.arch.memory_endness)
        state.globals['thread_local_stack_addr'] = thread_local_stack_addr
        state.globals['thread_local_stack_size'] = thread_local_stack_size
        logger.info(f"Thread local stack address: {hex(thread_local_stack_addr)}")
        logger.info(f"Thread local stack size: {hex(thread_local_stack_size)}")
        return state.copy()


    def _run_init_funcs_symbolically(self):
        """
        Run the init functions (TA_CreateEntryPoint and TA_OpenSessionEntryPoint) symbolically.
        Returns:
            The state of the TA_CreateEntryPoint function if found, None otherwise.
        """
        logger.info("Running init functions symbolically...")
        prototype = angr.sim_type.parse_signature(
            "int TA_CreateEntryPoint(void *a, size_t b, size_t c, void *d)"
        )
        
        logger.info("Running TA_CreateEntryPoint") 
        state = self.project.factory.call_state(
            self.create_entry_point[0],
            prototype=prototype,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.globals['metadata'] = self.metadata
        state.globals['hook_call_counts'] = {}
        if self.project.arch.bits == 64:
            state.globals['stack_base'] = 0x7ffffffffff0000
        else:
            state.globals['stack_base'] = 0xfffff000
        
        state = self._setup_tls(state)

        #state.inspect.b('instruction', when=angr.BP_BEFORE, action=lambda state: logger.info(f"Address: {hex(state.addr)}"))
        simgr = self.project.factory.simgr(state, veritesting=False)
        simgr.use_technique(TA_DFS_Exploration())
        simgr.use_technique(TA_Statistics(reachable_blocks=self.reachable_blocks))
        simgr = simgr.explore(find=self.create_entry_point[1])

        if not hasattr(simgr, 'found') or not simgr.found:
            print(simgr.stashes)
            return None

        logger.info(f"Found TA_CreateEntryPoint state at {hex(simgr.found[0].addr)}") 
        logger.info("Running TA_OpenSessionEntryPoint")
        current_state = simgr.found[0]

        if self.open_session[0] == -1:
            logger.info("TA does not have an open session entry point, going to invoke command")
            return current_state 

        logger.debug("Symbolizing open session inputs...")
        current_state = self.open_session_symbolic_inputs_func(current_state.copy())

        current_state.regs.pc = self.open_session[0] 
        current_state.history.trim()

        simgr = self.project.factory.simgr(current_state, veritesting=False)
        simgr = simgr.explore(find=self.open_session[1])

        if not hasattr(simgr, 'found') or not simgr.found:
            return None 

        logger.info(f"Found TA_OpenSessionEntryPoint state at {hex(simgr.found[0].addr)}")
        state = simgr.found[0]

        return state


    def _default_symbolic_inputs_func(self, state: SimState):
        """
        Symbolize the inputs for a TA call.
        We assume the TA to follow the GP API and takes four memref params.

        Args:
            state: The state to set the symbolic inputs for.
        Returns:
            The state with the symbolic inputs set.
        """
       
        def _place_sym_memref_param(state, p3, index):
            bits = state.arch.bits
            bytes_ = bits // 8
            ptr = state.heap.allocate(0x8000)
            size = get_tainted_mem_bits(state, bits, name=f'sym_memref_param_size_{index}')
            state.solver.add(size <= 0x8000)
            val = get_tainted_mem_bits(state, 0x8000 * 8, name=f'sym_memref_param_buffer_val_{index}')
            print(f"ptr in place_sym_memref_param: {hex(ptr)}")
            state.memory.store(ptr, val, size=0x8000, endness=state.arch.memory_endness)
            state.memory.store(p3 + index * (bytes_ * 2), ptr, size=bytes_, endness=state.arch.memory_endness)
            state.memory.store(p3 + index * (bytes_ * 2) + bytes_, size, size=bytes_, endness=state.arch.memory_endness)


        def _init_params(state):
            session_ptr = state.heap.allocate(0x1000)  # let's just assume a session is smaller than a page 
            session_val = get_tainted_mem_bits(state, 0x1000 * 8, name='sym_session_val')
            state.memory.store(session_ptr, session_val, size=0x1000, endness=state.arch.memory_endness)
            
            if state.arch.bits == 64:   
                state.regs.x0 = session_ptr
                state.regs.x1 = get_tainted_mem_bits(state, 64, name='sym_cmd_id')
                state.regs.x2 = get_tainted_mem_bits(state, 64, name='sym_param_type')
                p3 = state.heap.allocate(64)
                state.regs.x3 = p3
            else:
                state.regs.r0 = session_ptr
                state.regs.r1 = get_tainted_mem_bits(state, 32, name='sym_cmd_id')
                state.regs.r2 = get_tainted_mem_bits(state, 32, name='sym_param_type')
                p3 = state.heap.allocate(32)
                state.regs.r3 = p3

            return p3

        p3 = _init_params(state)
        _place_sym_memref_param(state, p3, 0)
        _place_sym_memref_param(state, p3, 1)
        _place_sym_memref_param(state, p3, 2)
        _place_sym_memref_param(state, p3, 3)

        return state.copy()


    def _run_symbolic_analysis(self, state: SimState):
        """
        Run the symbolic analysis of the TA.
        This includes enabling the exploration techniques based on the configuration, followed by running the Angr-based exploration.

        Args:
            state: The state to run the symbolic analysis on.
        """

        state.inspect.b('instruction', when=angr.BP_BEFORE, action=lambda state: logger.info(f"Address: {hex(state.addr)}"))
        simgr = self.project.factory.simgr(state, veritesting=False)
        
        # Always use these core techniques
        simgr.use_technique(TA_Filter(max_depth_limit=100000))
        simgr.use_technique(TA_Statistics(reachable_blocks=self.reachable_blocks))
        
        if self.config['enable_step_timeout']:
            logger.info(f"Enabling step timeout ({self.config['step_timeout']}s)")
            simgr.use_technique(TA_Timeout(timeout=self.config['step_timeout']))
        
        if self.config['enable_dfs']:
            logger.info("Enabling DFS exploration technique")
            # simgr.use_technique(TA_DFS_Exploration())
            simgr.use_technique(UniqueSearch())

        if self.config['enable_reentry']:
            logger.info(f"Enabling Reentry exploration technique (count: {self.config['reentry_count']})")
            reentry_count = self.config['reentry_count'] if self.config['reentry_count'] else 0
            simgr.use_technique(TA_Reentry(
                self,
                exit_addrs=self.invoke_command[1],
                reentry_addr=self.invoke_command[0],
                reentry_count=reentry_count
            ))
        
        if self.config['enable_threading']:
            logger.info("Enabling Threading exploration technique")
            simgr.use_technique(Threading(threads=60))
        
        if self.config['enable_veritesting']:
            logger.info("Enabling Veritesting exploration technique")
            simgr.use_technique(Veritesting())

        class Finished(SimProcedure):
            def run(self):
                logger.info(f"Finished state reached at address: {hex(self.state.addr)}")
                self.state.globals['ta_sys_return'] = True
                self.state.globals['sys_return_addr'] = self.state.addr
                self.exit(1)

        for exit_addr in self.invoke_command[1]:
            logger.info(f"Hooking exit address: {hex(exit_addr)}")
            self.project.hook(exit_addr, Finished(), 4)


        # tpidr = state.regs.tpidr_el0
        # val = state.memory.load(tpidr - 8, size=8, endness=state.arch.memory_endness)
        #logger.info(f"tpidr: {(tpidr)}")
        # logger.info(f"stack ptr: {(val)}")

        exploration = simgr.run()
        logger.info(exploration)


    def run(self):
        """
        Run the TA analysis.
        This includes:
        - Making the preparations for the run
        - Running the init functions symbolically
        - Running the symbolic analysis of the TA
        """
        self._make_preparations()
        state = self._run_init_funcs_symbolically()
        if not state:
            logger.error("Failed to run init functions symbolically!")
            syscall_stats = get_syscall_stats()
            add_syscall_stats(syscall_stats)
            
            report_path = finalize_report()
            logger.info(f"HTML Report available at: {report_path}")
            return None

        logger.info("Finished symbolically running init functions")
        prototype = angr.sim_type.parse_signature(
            "int TA_InvokeCommandEntryPoint(void *a, size_t b, size_t c, void *d)"
        )
        logger.info(f"Prototype: {prototype}")
        command_state = self.project.factory.call_state(
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SIMPLIFY_CONSTRAINTS,
                # angr.options.LAZY_SOLVES,
            },
            addr = self.invoke_command[0],
            prototype=prototype
        )
        command_state.globals['metadata'] = self.metadata
        command_state.globals['hook_call_counts'] = {}
        command_state.libc.max_memcpy_size = 0x8000
        command_state.libc.max_variable_size = 0x8000

        logger.info(f"Stack base: {command_state.regs.sp}")
        if self.project.arch.bits == 64:
            command_state.globals['stack_base'] = 0x7ffffffffff0000
        else:
            command_state.globals['stack_base'] = 0xfffff000

        logger.info("Transfering state to symbolic exploration...")
        for addr in range(self.project.loader.main_object.min_addr, self.project.loader.main_object.max_addr, 4069):
            mem_value = state.memory.load(addr, size=4069, endness=state.arch.memory_endness)

            # Check if the memory value is symbolic and concretize it
            if state.solver.symbolic(mem_value):
                concrete_int = state.solver.eval(mem_value)
                concrete_value = claripy.BVV(concrete_int, mem_value.length)  # Match the bit length
                command_state.memory.store(addr, concrete_value, endness=state.arch.memory_endness)
            else:
                command_state.memory.store(addr, mem_value, endness=state.arch.memory_endness)


        logger.debug("Symbolizing invoke command inputs...")
        
        command_state = self.invoke_command_symbolic_inputs_func(command_state.copy())
        command_state.globals['ta_init_function_name'] = self.invoke_command_symbolic_inputs_func.__name__

        command_state.globals['heap_base'] = command_state.heap.heap_location
        logger.info(f"Original Heap Base: {hex(command_state.heap.heap_base)}")
        logger.info(f"New Heap Base: {hex(command_state.globals['heap_base'])}")

        command_state = self._setup_tls(command_state.copy())
        
        if self.config['enable_plugins']:
            logger.info("Starting Plugins...")
            TAPluginManager(command_state)
        else:
            logger.info("Plugins disabled")

        logger.info("Starting symbolic exploration of TA")
        try:
            self._run_symbolic_analysis(command_state)
        except Exception as e:
            logger.error(f"Error during symbolic exploration of TA: {e}")
            traceback.print_exc()
        except KeyboardInterrupt as e:
            logger.error(f"Keyboard interrupt during symbolic exploration of TA: {e}")
            traceback.print_exc()

        logger.info("Symbolic exploration of TA finished")

        syscall_stats = get_syscall_stats()
        add_syscall_stats(syscall_stats)
        
        report_path = finalize_report()
        logger.info(f"HTML Report available at: {report_path}")
