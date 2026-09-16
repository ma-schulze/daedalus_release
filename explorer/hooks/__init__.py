from .os_hooks.optee_hooks import OPTEEHooks, reset_syscall_stats, get_syscall_stats
from .os_hooks.os_hooks import install_os_hooks
from .function_hooks.func_hooks import install_func_hooks

__all__ = [
    # OS Hooks
    'OPTEEHooks',
    'reset_syscall_stats',
    'get_syscall_stats',
    'install_os_hooks',
    
    # Function Hooks
    'install_func_hooks',
]
