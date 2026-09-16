import argparse
import importlib.util
import sys
from pathlib import Path
import os
import subprocess
from types import ModuleType
from utils.logging_config import setup_logging, get_logger
from explorer.explorer import TAExplorer

logger = get_logger(__name__)

from elftools.elf.relocation import RelocationSection

def safe_iter_relocations(self):
    # Skip malformed relocation sections (common in static PIE TAs)
    if self['sh_size'] == 0 or self['sh_entsize'] == 0:
        return
    count = self['sh_size'] // self['sh_entsize']
    for i in range(count):
        try:
            yield self.get_relocation(i)
        except Exception:
            return

RelocationSection.iter_relocations = safe_iter_relocations

def load_hooks_from_file(hooks_file: str) -> ModuleType:
    """
    Load hook functions from a Python file.
    
    The file should define a HOOK_REGISTRY dict mapping function names to hook functions.
    
    Args:
        hooks_file: Path to the Python file containing hooks
        
    Returns:
        Module containing the hooks
    """
    hooks_path = Path(hooks_file)
    if not hooks_path.exists():
        logger.error(f"Hooks file not found: {hooks_file}")
        return None
    
    try:
        spec = importlib.util.spec_from_file_location("custom_hooks", hooks_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["custom_hooks"] = module
        spec.loader.exec_module(module)
        logger.info(f"Loaded hooks from {hooks_file}")
        return module
    except Exception as e:
        logger.error(f"Error loading hooks from {hooks_file}: {e}")
        return None


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Symbolic execution framework for TrustZone Trusted Applications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./binary.bin
  %(prog)s ./binary.bin --tos optee
  %(prog)s ./binary.bin --hooks ./my_hooks.py
  %(prog)s ./binary.bin --log-level DEBUG --log-file analysis.log
        """
    )
    
    parser.add_argument(
        "filename",
        type=str,
        help="Path to the Trusted Application binary to analyze"
    )

    parser.add_argument(
        "--input-format",
        type=str,
        default="ta",
        choices=["ta", "bin"],
        help="Format of the input file (default: ta)"
    )
    
    parser.add_argument(
        "--tos",
        type=str,
        default=None,
        help="Name of the Trusted OS to simulate (e.g., optee, trusty)"
    )
    
    parser.add_argument(
        "--hooks",
        type=str,
        default=None,
        help="Path to a Python file containing additional function hooks (must define HOOK_REGISTRY dict)"
    )
    
    parser.add_argument(
        "--open-session-symbolic-inputs-func",
        type=str,
        default=None,
        help="Name of a function in the hooks file to use for open_session_symbolic_inputs_func"
    )
    
    parser.add_argument(
        "--invoke-command-symbolic-inputs-func",
        type=str,
        default=None,
        help="Name of a function in the hooks file to use for invoke_command_symbolic_inputs_func"
    )
    
    # Logging options
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to a file to write logs to (in addition to stdout)"
    )
    
    # Exploration technique options
    parser.add_argument(
        "--enable-dfs",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable DFS exploration technique (default: True)"
    )
    
    parser.add_argument(
        "--enable-reentry",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable reentry exploration technique (default: True)"
    )
    
    parser.add_argument(
        "--enable-threading",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Enable threading exploration technique (default: False)"
    )
    
    parser.add_argument(
        "--enable-veritesting",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Enable veritesting exploration technique (default: False)"
    )
    
    parser.add_argument(
        "--enable-step-timeout",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable step timeout (default: True)"
    )
    
    parser.add_argument(
        "--step-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for each step (default: 120)"
    )
    
    parser.add_argument(
        "--reentry-count",
        type=int,
        default=5,
        help="Number of reentries to allow (default: 5)"
    )
    
    parser.add_argument(
        "--enable-plugins",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable plugins (default: True)"
    )
    
    parser.add_argument(
        "--enable-memory-model",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Enable custom memory model (default: True)"
    )
    
    # Memory limit options
    parser.add_argument(
        "--memory-limit-gb",
        type=float,
        default=None,
        help="Fixed memory limit in GB. When reached, generates report and exits gracefully (default: None/unlimited)"
    )
    
    parser.add_argument(
        "--memory-adaptive",
        action="store_true",
        default=False,
        help="Enable adaptive memory limits. Limit = total_memory / active_processes"
    )
    
    parser.add_argument(
        "--memory-total-gb",
        type=float,
        default=None,
        help="Total memory pool for adaptive mode in GB (default: 90%% of system memory)"
    )
    
    parser.add_argument(
        "--memory-min-gb",
        type=float,
        default=5.0,
        help="Minimum memory limit per process in adaptive mode (default: 5.0)"
    )
    
    parser.add_argument(
        "--memory-max-gb",
        type=float,
        default=None,
        help="Maximum memory limit per process in adaptive mode (default: None/no max)"
    )
    
    parser.add_argument(
        "--memory-check-interval",
        type=float,
        default=5.0,
        help="How often to check memory usage in seconds (default: 5.0)"
    )
    
    parser.add_argument(
        "--memory-threshold-percent",
        type=float,
        default=0.95,
        help="Trigger graceful shutdown at this percentage of the memory limit (default: 0.95)"
    )
    
    parser.add_argument(
        "--use-svc-hooks",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Use SVC hooks (default: True)"
    )
    
    parser.add_argument(
        "--func-hook-providers",
        type=str,
        default="gp",
        help="Providers of the function hooks to install (default: gp). Multiple providers can be separated by commas."
    )

    parser.add_argument(
        "--cfg-path",
        type=str,
        default=None,
        help="Path to a file containing basic block information (in the TÄMU format) about the TA CFG (default: None)"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Setup logging first, before any other operations
    setup_logging(log_level=args.log_level, log_file=args.log_file)

    input_file = os.path.abspath(args.filename)
    
    hooks_module = None
    if args.hooks:
        hooks_module = load_hooks_from_file(args.hooks)
    
    # Extract symbolic inputs functions from the hooks module if specified
    open_session_symbolic_inputs_func = None
    if args.open_session_symbolic_inputs_func:
        if hooks_module is None:
            logger.error("--open-session-symbolic-inputs-func requires --hooks to be specified")
            return
        if hasattr(hooks_module, args.open_session_symbolic_inputs_func):
            open_session_symbolic_inputs_func = getattr(hooks_module, args.open_session_symbolic_inputs_func)
            logger.info(f"Loaded open_session_symbolic_inputs_func: {args.open_session_symbolic_inputs_func}")
        else:
            logger.error(f"Function '{args.open_session_symbolic_inputs_func}' not found in hooks file")
            return
    
    invoke_command_symbolic_inputs_func = None
    if args.invoke_command_symbolic_inputs_func:
        if hooks_module is None:
            logger.error("--invoke-command-symbolic-inputs-func requires --hooks to be specified")
            return
        if hasattr(hooks_module, args.invoke_command_symbolic_inputs_func):
            invoke_command_symbolic_inputs_func = getattr(hooks_module, args.invoke_command_symbolic_inputs_func)
            logger.info(f"Loaded invoke_command_symbolic_inputs_func: {args.invoke_command_symbolic_inputs_func}")
        else:
            logger.error(f"Function '{args.invoke_command_symbolic_inputs_func}' not found in hooks file")
            return
    
    # Build configuration dictionary for TAExplorer
    explorer_config = {
        # Hooks and symbolic input functions
        'os_hook_name': args.tos,
        'open_session_symbolic_inputs_func': open_session_symbolic_inputs_func,
        'invoke_command_symbolic_inputs_func': invoke_command_symbolic_inputs_func,
        'func_hook_providers': args.func_hook_providers,

        # Run identifier (used for report filename to distinguish parallel runs)
        'run_id': args.invoke_command_symbolic_inputs_func,
        
        # Exploration techniques
        'enable_dfs': args.enable_dfs,
        'enable_reentry': args.enable_reentry,
        'enable_threading': args.enable_threading,
        'enable_veritesting': args.enable_veritesting,
        
        # Timeouts and limits
        'enable_step_timeout': args.enable_step_timeout,
        'step_timeout': args.step_timeout,
        'reentry_count': args.reentry_count,
        
        # Memory limits
        'memory_limit_gb': args.memory_limit_gb,
        'memory_adaptive': args.memory_adaptive,
        'memory_total_gb': args.memory_total_gb,
        'memory_min_gb': args.memory_min_gb,
        'memory_max_gb': args.memory_max_gb,
        'memory_check_interval': args.memory_check_interval,
        'memory_threshold_percent': args.memory_threshold_percent,
        
        # Features
        'use_svc_hooks': args.use_svc_hooks,
        'enable_plugins': args.enable_plugins,
        'enable_memory_model': args.enable_memory_model,
        'cfg_path': args.cfg_path,
    }
    
    # Create and run the explorer
    ta_explorer = TAExplorer(input_file, config=explorer_config)
    ta_explorer.run()


if __name__ == "__main__":
    main()
