from angr.sim_state import SimState

from utils.logging_config import get_logger
from .ta_plugin import PLUGIN_REGISTRY
from .ta_heapsan import TA_HeapSanPlugin
from .ta_cfsan import TA_CFSanPlugin
from .ta_memsan import TA_MemSanPlugin
from .ta_stacksan import TA_StackSanPlugin
from .ta_double_free import TA_DoubleFreeSanPlugin


logger = get_logger(__name__)

TA_DEFAULT_EVENTS = {
    'sw_mem_read',
    'sw_mem_write',
    'nw_mem_read',
    'nw_mem_write',
    'sw_or_nw_mem_read',
    'sw_or_nw_mem_write',
    'heap_alloc',
    'heap_free',
    'free',
}


class TAPluginManager:
    """
    Manager for TA analysis plugins.
    It will initialize all the plugins and register the breakpoints when initialized.
    """
    def __init__(self, initial_state: SimState):
        """
        Initialize the plugin manager, initializing all the plugins and registering the breakpoints.

        Args:
            initial_state: The initial state to be stepped.
        """
        logger.info("TAPluginManager initializing")
        for plugin_name, plugin_class in PLUGIN_REGISTRY.items():
            logger.debug(f"Initializing plugin: {plugin_name}")
            plugin = plugin_class()
            plugin.init_breakpoints(initial_state)

