from angr.storage.memory_mixins import (
    PagedMemoryMixin, 
    SymbolicMergerMixin, 
    DefaultFillerMixin, 
    UltraPagesMixin,
    PrivilegedPagingMixin, 
    DictBackerMixin, 
    ClemoryBackerMixin, 
    ConcreteBackerMixin, 
    StackAllocationMixin,
    DirtyAddrsMixin, 
    ConvenientMappingsMixin, 
    ConditionalMixin, 
    ActionsMixinLow, 
    AddressConcretizationMixin,
    SizeNormalizationMixin, 
    SizeConcretizationMixin, 
    UnderconstrainedMixin, 
    ActionsMixinHigh, 
    InspectMixinHigh,
    DataNormalizationMixin, 
    NameResolutionMixin, 
    UnwrapperMixin, 
    SmartFindMixin
)

from .ta_memory_mixin import TAMemoryMixin
from .ta_memory_filler import TAMemoryFillerMixin


class TAMemory(
    # HexDumperMixin,
    SmartFindMixin,
    UnwrapperMixin,
    NameResolutionMixin,
    DataNormalizationMixin,
    # SimplificationMixin,
    InspectMixinHigh,
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    TAMemoryMixin,  
    # InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    StackAllocationMixin,
    ConcreteBackerMixin,
    ClemoryBackerMixin,
    DictBackerMixin,
    PrivilegedPagingMixin,
    UltraPagesMixin,
    TAMemoryFillerMixin,
    SymbolicMergerMixin,
    PagedMemoryMixin,
):
    """
    Custom memory class for Trusted Application memory management.
    It is pretty much the default angr memory class, with the addition of the TAMemoryMixin and TAMemoryFillerMixin.
    """
    pass
