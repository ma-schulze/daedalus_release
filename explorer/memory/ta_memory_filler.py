from angr.storage.memory_mixins.memory_mixin import MemoryMixin
import claripy

from .ta_memory_utils import addr_is_in_ta_memory
from .ta_taint import get_tainted_mem_bits

class TAMemoryFillerMixin(MemoryMixin):
    """
    Custom memory filler mixin for Trusted Application memory management.
    It fills the memory with 0 (default value) or tainted memory, depending on the address being in or outside the TA memory.
    """
    def _default_value(self, addr: int, size: int, **kwargs):
        """
        Fill the memory with 0 (default value) or tainted memory, depending on the address.

        Args:
            addr: The address to fill
            size: The size to fill
            kwargs: Additional arguments

        Returns:
            The filled memory bitvector
        """
        in_ta = addr_is_in_ta_memory(self.state, addr, size)
        if in_ta:
            return claripy.BVV(0, size * 8)
        else:
            return get_tainted_mem_bits(self.state, size * 8)
