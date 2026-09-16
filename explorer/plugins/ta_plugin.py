from angr import SimState
from typing import Type, Dict

# Global registry of plugin classes
# Maps plugin name (lowercase) -> plugin class
PLUGIN_REGISTRY: Dict[str, Type] = {}

def ta_plugin():
    """
    Decorator to register a class as a TA plugin.
    
    Classes decorated with @ta_plugin(name) will be added to the global
    PLUGIN_REGISTRY and can be used during TA execution.
    
    Args:
        name: The plugin name to register (e.g., "memsan", "cfsan")
        
    Returns:
        Decorator function that registers the plugin class
    """
    def decorator(cls: Type) -> Type:
        PLUGIN_REGISTRY[cls.__name__] = cls
        return cls
    return decorator


class TAPlugin:
    """
    Base class for TA analysis plugins.
    """
    def __init__(self):
        """
        Initialize the plugin.
        """
        pass 

    def init_breakpoints(self, state: SimState):
        """
        Initialize the breakpoints for the plugin.
        When triggered, call the corresponding check function.
        Args:
            state: The initial state to be stepped.
        """
        pass
