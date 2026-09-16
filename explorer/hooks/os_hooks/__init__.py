from .os_hooks import install_os_hooks, os_hook, OS_HOOKS_REGISTRY
from .optee_hooks import OPTEEHooks, reset_syscall_stats, get_syscall_stats

__all__ = [
    'OPTEEHooks',
    'reset_syscall_stats',
    'get_syscall_stats',
    'install_os_hooks',
    'os_hook',
    'OS_HOOKS_REGISTRY',
]
