from typing import Callable, List, Dict, Optional, Union

# Global registry of init functions
TA_INIT_FUNCTION_REGISTRY: List[Callable] = []

# Global registry mapping function names to their next function(s) for command chaining
# Stores function names (strings) that get resolved lazily when needed
TA_INIT_FUNCTION_CHAIN: Dict[str, List[str]] = {}

# Registry mapping function names to actual function objects (for lazy resolution)
TA_INIT_FUNCTION_BY_NAME: Dict[str, Callable] = {}


def ta_init_function(
    _func: Callable = None, 
    *, 
    next_func: Union[Callable, str] = None,
    next_funcs: List[Union[Callable, str]] = None
) -> Callable:
    """
    Decorator to register a function as a TA init function.
    
    Functions decorated with @ta_init_function will be added to the global
    TA_INIT_FUNCTION_REGISTRY and can be executed during TA initialization.
    
    Optionally, specify next function(s) to chain commands in a fixed order.
    When analysis of the decorated function completes, the reentry technique
    will create states for each specified next function (or one random if none).
    
    Note: next_func/next_funcs can be either:
    - Function references (if defined above this function)
    - String names (if defined below - resolved lazily at runtime)
    
    Examples:
        # Simple usage (no chaining, random next command):
        @ta_init_function
        def setup_memory(state):
            return state
        
        # Using function reference (target must be defined above):
        @ta_init_function(next_func=TPM2_Startup)
        def TPM2_Shutdown(state):
            return state
        
        # Using string name (target can be defined anywhere in file):
        @ta_init_function(next_func="TPM2_Unseal")
        def TPM2_Startup(state):
            return state
        
        # Multiple chained functions with strings:
        @ta_init_function(next_funcs=["TPM2_GetRandom", "TPM2_Hash", "TPM2_Sign"])
        def TPM2_Init(state):
            return state
    
    Args:
        _func: The function to register (when used without arguments)
        next_func: Single function (or name) to execute after this one completes
        next_funcs: List of functions (or names) to execute after this one completes
                    (creates a separate state for each)
        
    Returns:
        The original function (unchanged)
    """
    def decorator(func: Callable) -> Callable:
        TA_INIT_FUNCTION_REGISTRY.append(func)
        TA_INIT_FUNCTION_BY_NAME[func.__name__] = func
        
        # Build list of next function names from both parameters
        chained_names = []
        
        if next_func is not None:
            name = next_func if isinstance(next_func, str) else next_func.__name__
            chained_names.append(name)
        
        if next_funcs is not None:
            for f in next_funcs:
                name = f if isinstance(f, str) else f.__name__
                if name not in chained_names:
                    chained_names.append(name)
        
        # Register the chained function names if any were specified
        if chained_names:
            TA_INIT_FUNCTION_CHAIN[func.__name__] = chained_names
        
        return func
    
    # Handle both @ta_init_function and @ta_init_function(next_func=...)
    if _func is not None:
        # Called without arguments: @ta_init_function
        return decorator(_func)
    else:
        # Called with arguments: @ta_init_function(next_func=...) or @ta_init_function(next_funcs=[...])
        return decorator


def register_init_function(func: Callable) -> None:
    """
    Manually register a function as an init function without using the decorator.
    
    Useful for registering functions that shouldn't be randomly selected but
    need to be available for chaining.
    
    Args:
        func: The function to register
    """
    if func.__name__ not in TA_INIT_FUNCTION_BY_NAME:
        TA_INIT_FUNCTION_BY_NAME[func.__name__] = func


def ta_chain_target(
    _func: Callable = None,
    *,
    next_func: Union[Callable, str] = None,
    next_funcs: List[Union[Callable, str]] = None,
) -> Callable:
    """
    Decorator to register a function as a valid chain target WITHOUT adding it
    to the random selection pool.

    Unlike @ta_init_function, this does NOT add the function to TA_INIT_FUNCTION_REGISTRY,
    so it won't be randomly selected as an initial command. It CAN still define follow-up
    commands via next_func/next_funcs, so chain-only commands can themselves form chains.

    Examples:
        @ta_chain_target
        def TPM2_Startup(state):
            return state

        @ta_init_function(next_func="TPM2_Startup")
        def TPM2_Shutdown(state):
            return state

        @ta_chain_target(next_funcs=["TPM2_Update", "TPM2_Final"])
        def TPM2_Begin(state):
            return state
    """
    def decorator(func: Callable) -> Callable:
        TA_INIT_FUNCTION_BY_NAME[func.__name__] = func

        chained_names: List[str] = []
        if next_func is not None:
            name = next_func if isinstance(next_func, str) else next_func.__name__
            chained_names.append(name)
        if next_funcs is not None:
            for f in next_funcs:
                name = f if isinstance(f, str) else f.__name__
                if name not in chained_names:
                    chained_names.append(name)
        if chained_names:
            TA_INIT_FUNCTION_CHAIN[func.__name__] = chained_names

        return func

    # Handle both @ta_chain_target and @ta_chain_target(next_func=...)
    if _func is not None:
        return decorator(_func)
    return decorator


def _resolve_function(name: str) -> Optional[Callable]:
    """
    Resolve a function name to its actual function object.
    
    Looks up in TA_INIT_FUNCTION_BY_NAME first, then falls back to
    searching TA_INIT_FUNCTION_REGISTRY.
    """
    # First check the name registry
    if name in TA_INIT_FUNCTION_BY_NAME:
        return TA_INIT_FUNCTION_BY_NAME[name]
    
    # Fallback: search by name in the registry
    for func in TA_INIT_FUNCTION_REGISTRY:
        if func.__name__ == name:
            return func
    
    return None


def get_next_init_functions(current_func_name: str) -> List[Callable]:
    """
    Get the next init function(s) to execute after the given function.
    
    Resolves function names to actual function objects lazily.
    
    Args:
        current_func_name: Name of the function that just completed
        
    Returns:
        List of functions to execute next (empty list if no chain defined)
    """
    next_names = TA_INIT_FUNCTION_CHAIN.get(current_func_name, [])
    
    resolved_funcs = []
    for name in next_names:
        func = _resolve_function(name)
        if func:
            resolved_funcs.append(func)
        else:
            from utils.logging_config import get_logger
            logger = get_logger(__name__)
            logger.warning(f"Could not resolve chained function '{name}' for {current_func_name}")
    
    return resolved_funcs


# Keep backward compatibility
def get_next_init_function(current_func_name: str) -> Optional[Callable]:
    """
    Get the next init function to execute after the given function.
    
    Deprecated: Use get_next_init_functions() instead for multiple next functions.
    
    Args:
        current_func_name: Name of the function that just completed
        
    Returns:
        The first next function to execute if chained, None otherwise
    """
    funcs = get_next_init_functions(current_func_name)
    return funcs[0] if funcs else None
