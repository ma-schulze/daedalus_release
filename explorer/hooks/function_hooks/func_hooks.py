import angr
from angr.procedures.libc.memset import memset as angr_memset
from angr.procedures.libc.memcpy import memcpy as angr_memcpy
from angr.procedures.libc.memmove import memmove as angr_memove
from angr.procedures.libc.strlen import strlen as angr_strlen
from angr.procedures.libc.strcmp import strcmp as angr_strcmp
from angr.procedures.libc.strstr import strstr as angr_strstr
from angr.procedures.libc.strncat import strncat as angr_strncat
from angr.procedures.libc.sprintf import sprintf as angr_sprintf
from angr.procedures.libc.fprintf import fprintf as angr_fprintf
from angr.procedures.libc.printf import printf as angr_printf
from angr.procedures.libc.strnlen import strnlen as angr_strnlen
from angr.procedures.libc.memcmp import memcmp as angr_memcmp
from angr.procedures.libc.strcpy import strcpy as angr_strcpy
from angr.procedures.libc.strncpy import strncpy as angr_strncpy
from angr.procedures.libc.strncmp import strncmp as angr_strncmp
from angr.procedures.libc.puts import puts as angr_puts
from angr.procedures.libc.strcat import strcat as angr_strcat
from angr.procedures.libc.snprintf import snprintf as angr_snprintf
from angr.procedures.libc.vsnprintf import vsnprintf as angr_vsnprintf

from angr.procedures.posix.mmap import mmap as angr_mmap
from angr.procedures.posix.pthread import pthread_once as angr_pthread_once
from angr.procedures.posix.pthread import pthread_create as angr_pthread_create


from typing import Type, Dict

from utils.logging_config import get_logger

logger = get_logger(__name__)

# Global registry of function hook classes
# Maps function name (lowercase) -> function hook class (SimProcedure subclass) + provider
FUNCTION_HOOKS_REGISTRY: Dict[str, tuple[Type, str, int]] = {}

def ta_function_hook(name: str, provider: str = "libc", addr: int = None):
    """
    Decorator to register a class as a TA function hook handler.
    
    Classes decorated with @ta_function_hook(name, provider) will be added to the global
    FUNCTION_HOOKS_REGISTRY and can be used during TA execution.
    The provider states who would provide the function in a concrete environment.
    This may be "gp" for the global platform API or, e.g., "teegris" for the TEERIS API.
    
    The decorated class should be a SimProcedure subclass that implements
    the `run` method to handle the function.
    
    Example:
        @ta_function_hook("printf")
        class printf_symbolic(SimProcedure):
            def run(self, _argc, _argv):
                # Handle printf
                ...
    
    Args:
        name: The function name to register (e.g., "printf", "fprintf")
        provider: The provider of the function (e.g., "gp", "teegris")
    Returns:
        Decorator function that registers the function hook class
    """
    def decorator(cls: Type) -> Type:
        FUNCTION_HOOKS_REGISTRY[name] = [cls, provider, addr]
        return cls
    return decorator

# We sadly have to apply the decorator manually to the imported symbolic functions :/ 
ta_function_hook("memset")(angr_memset)
ta_function_hook("memcpy")(angr_memcpy)
ta_function_hook("strlen")(angr_strlen)
ta_function_hook("strcmp")(angr_strcmp)
ta_function_hook("strncat")(angr_strncat)
ta_function_hook("strstr")(angr_strstr)
ta_function_hook("strnlen")(angr_strnlen)
ta_function_hook("memcmp")(angr_memcmp)
ta_function_hook("memmove")(angr_memove)
ta_function_hook("strcpy")(angr_strcpy)
ta_function_hook("strncpy")(angr_strncpy)
ta_function_hook("strncmp")(angr_strncmp)
ta_function_hook("puts")(angr_puts)
ta_function_hook("snprintf")(angr_snprintf)
ta_function_hook("vsnprintf")(angr_vsnprintf)
ta_function_hook("sprintf")(angr_sprintf)
ta_function_hook("printf")(angr_printf)
ta_function_hook("kprintf")(angr_printf)
#ta_function_hook("TEE_MemMove")(angr_memove)
ta_function_hook("TEE_MemFill")(angr_memset)
ta_function_hook("TEE_MemCompare")(angr_memcmp)
ta_function_hook("mmap")(angr_mmap)
ta_function_hook("strcat")(angr_strcat)
ta_function_hook("pthread_once")(angr_pthread_once)
ta_function_hook("pthread_create")(angr_pthread_create)


class _HookRecordingWrapper(angr.SimProcedure):
    """Wraps a SimProcedure to record the hook name for coverage when it is called."""

    def __init__(self, inner, hook_name: str):
        super().__init__()
        self._inner = inner
        self._hook_name = hook_name
        # Use the inner's prototype/cc so angr extracts the same arguments when invoking the wrapper
        if getattr(inner, "prototype", None) is not None:
            self.prototype = inner.prototype
        if getattr(inner, "num_args", None) is not None:
            self.num_args = inner.num_args

    @staticmethod
    def _record_hook_call(state: angr.SimState, name: str) -> None:
        """Record that a hooked function was called (for coverage). No-op if hook_call_counts not set."""
        logger.info(f"Hook called: {name}")
        counts = state.globals['hook_call_counts']
        if counts is not None:
            counts[name] = counts.get(name, 0) + 1


    def run(self, *args, **kwargs):
        self._record_hook_call(self.state, self._hook_name)

        # Give the inner the same execution context angr sets on the wrapper in execute().
        # _inner is the SimProcedure class; we call its run() with the class as self, so the
        # class must have state, arch, project, cc, etc. (angr normally sets these on an
        # instance in execute(); without that, inner.run() sees self.arch as None and fails).
        self._inner.state = self.state
        self._inner.arguments = getattr(self, "arguments", None)
        if getattr(self._inner, "arch", None) is None:
            self._inner.arch = self.arch
        if getattr(self._inner, "project", None) is None:
            self._inner.project = self.project
        if getattr(self._inner, "cc", None) is None:
            self._inner.cc = self.cc
        if getattr(self._inner, "arg_session", None) is None:
            self._inner.arg_session = self.arg_session
        try:
            res = self._inner.run(*args, **kwargs)
            return res
        except Exception as e:
            logger.error(f"Error in {self._hook_name}: {e}")
            return 0 


def _get_function_start_by_name(metadata: dict, cfg, function_name: str) -> int:
    """
    Get the start address of a function by name inside an angr CFG.

    Args:
        metadata: The metadata of the TA
        cfg: The angr CFG to search in
        function_name: The name of the function to search for
        
    Returns:
        The start address of the function if found, 0 otherwise
    """

    inline = metadata.get('inline', {})
    if inline:
        offset = inline.get(function_name, {}).get('addr', -1)
        if offset != -1:
            return offset
    
    func = cfg.kb.functions.function(name=function_name)
    if func is not None:
        return func.addr
    
    return -1


def _install_func_hooks(project: angr.Project, metadata: dict, cfg, function_hooks: dict[str, tuple[angr.SimProcedure, str, int]], providers: list[str]):
    """
    Install function hooks into an angr project.
    
    Args:
        project: The angr project to install the hooks into
        cfg: The angr CFG to search in
        metadata: The metadata of the TA
        function_hooks: The function hooks to install
        providers: The providers of the function hooks to install
    """
    installed = {}
    for func_name, (hook_impl, hook_provider, hook_addr) in function_hooks.items():
        if hook_provider != "libc" and hook_provider not in providers:
            continue

        if hook_addr is not None:
            offset = hook_addr
        else:
            offset = _get_function_start_by_name(metadata, cfg, func_name)
            if offset == -1:
                continue

        wrapped = _HookRecordingWrapper(hook_impl(), func_name)
        project.hook(offset, wrapped, 4, replace=True)

        logger.info(f"{func_name:30s} @ {hex(offset)} hooked by offset")
        installed[func_name] = offset
    
    logger.info(f"Installed {len(installed)}/{len(function_hooks)} function hooks")
    return installed



def install_func_hooks(project: angr.Project, metadata: dict, cfg, providers: list[str] = ["gp"]):
    """
    Install default function hooks into an angr project.

    Args:
        project: The angr project to install the hooks into
        metadata: The metadata of the TA
        cfg: The angr CFG to search in
        providers: The providers of the function hooks to install
    """
    return _install_func_hooks(project, metadata, cfg, FUNCTION_HOOKS_REGISTRY, providers)
