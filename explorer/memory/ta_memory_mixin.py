import angr
from angr.storage.memory_mixins.memory_mixin import MemoryMixin
import claripy

from .ta_memory_utils import addr_is_in_ta_memory, addr_is_outside_ta_memory, addr_in_or_outside_ta_memory
from .ta_taint import get_tainted_mem_bits
from utils.logging_config import get_logger

logger = get_logger(__name__)

class TAMemoryMixin(MemoryMixin):
    """
    Custom memory mixin for Trusted Application memory management.
    When accessing memory, it will check if the memory is in the TA memory or not.

    When an access targets TA memory, this mixin forwards the request to the default memory mixin.
    When a load occurs from outside TA memory, this mixin returns tainted memory.
    When a store occurs to outside TA memory, this is effectively a no-op, since NW memory is considered attacker controlled.

    This mixin also triggers breakpoints depending on the access type and targeted memory type to be used by analysis plugins.
    """

    def load(self, addr: int, size: int = None, endness: str = None, **kwargs):
        """
        Load memory for the TA, checking if the read targets trusted or tainted memory.
        Loads from outside TA memory return tainted memory.
        This function also triggers breakpoints to be used by analysis plugins.

        Args:
            addr: The address to load from
            size: The size to load
            endness: The endness to load
            kwargs: Additional arguments

        Returns:
            The loaded memory bitvector
        """
        if self.category != 'mem':
            return super().load(addr, size, endness=endness, **kwargs)
        
        if addr_in_or_outside_ta_memory(self.state, addr, size):
            logger.debug(f"Loading memory from outside or inside TA memory from {hex(addr)} size={size}")
            self.state._inspect(
                'sw_or_nw_mem_read',
                when=angr.BP_BEFORE,
                mem_read_address=addr,
                mem_read_length=size,
            )
            res = super().load(addr, size, endness=endness, **kwargs)
            
            self.state._inspect(
                'sw_or_nw_mem_read',
                when=angr.BP_AFTER,
                mem_read_address=addr,
                mem_read_length=size,
            )
            return res

        in_ta_memory = addr_is_in_ta_memory(self.state, addr, size)
        if in_ta_memory:
            logger.debug(f"Loading memory from inside TA memory from {hex(addr)} size={size}")
            self.state._inspect(
                'sw_mem_read',
                when=angr.BP_BEFORE,
                mem_read_address=addr,
                mem_read_length=size,
            )

            res = super().load(addr, size, endness=endness, **kwargs)
        
            self.state._inspect(
                'sw_mem_read',
                when=angr.BP_AFTER,
                mem_read_address=addr,
                mem_read_length=size,
                mem_read_expr=res,
            )
            return res

        elif addr_is_outside_ta_memory(self.state, addr, size):
            logger.debug(f"Loading tainted memory from {hex(addr)} size={size}")
            self.state._inspect(
                'nw_mem_read',
                when=angr.BP_BEFORE,
                mem_read_address=addr,
                mem_read_length=size,
            )

            res = get_tainted_mem_bits(self.state, size * 8)

            self.state._inspect(
                'nw_mem_read',
                when=angr.BP_AFTER,
                mem_read_address=addr,
                mem_read_length=size,
                mem_read_expr=res,
            )
            return res
        else:
            logger.warning(f"[TAMemoryMixin] Loading memory from unknown memory from {hex(addr)} size={size}")
            return super().load(addr, size, endness=endness, **kwargs)


    def store(self, addr: int, data: claripy.BVV, size: int = None, **kwargs):
        """
        Store memory for the TA, checking if the write targets trusted or tainted memory.
        Stores to outside TA memory are effectively a no-op, since NW memory is considered attacker controlled.
        This function also triggers breakpoints to be used by analysis plugins.

        Args:
            addr: The address to store to
            data: The data to store
            size: The size of the data to store 
            kwargs: Additional arguments
        """
        if self.category != 'mem':
            return super().store(addr, data, size, **kwargs)

        if addr_in_or_outside_ta_memory(self.state, addr, size):
            self.state._inspect(
                'sw_or_nw_mem_write',
                when=angr.BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )
            res = super().store(addr, data, size, **kwargs)

            self.state._inspect(
                'sw_or_nw_mem_write',
                when=angr.BP_AFTER,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )
            return res

        in_ta_memory = addr_is_in_ta_memory(self.state, addr, size)
        if in_ta_memory:
            self.state._inspect(
                'sw_mem_write',
                when=angr.BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

            super().store(addr, data, size, **kwargs)

            self.state._inspect(
                'sw_mem_write',
                when=angr.BP_AFTER,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

        elif addr_is_outside_ta_memory(self.state, addr, size):
            self.state._inspect(
                'nw_mem_write',
                when=angr.BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

            self.state._inspect(
                'nw_mem_write',
                when=angr.BP_AFTER,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )
        else:
            logger.warning(f"[TAMemoryMixin] Writing memory to unknown memory to {hex(addr)} size={size}")
            return super().store(addr, data, size, **kwargs)
