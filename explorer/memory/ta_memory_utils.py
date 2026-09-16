import angr
import claripy

from typing import Any, List, Tuple


# Type for (start_inclusive, end_exclusive) address ranges
_AddrRange = Tuple[int, int]

def _get_ta_image_ranges(state: angr.SimState) -> List[_AddrRange]:
    """
    Get the list of (start, end_exclusive) address ranges that belong to the TA
    image (ELF segments or raw blob). Uses state.project.loader.all_objects.
    Additionally, it also adds the heap and stack ranges to the list.

    Returns:
        List of (min_addr, max_addr_exclusive) for each segment/region.
        Falls back to [0, binary_size) from GLOBAL_TA_STATE if loader is unavailable.
    """
    ranges: List[_AddrRange] = []

    for obj in state.project.loader.all_objects:
        min_addr = obj.min_addr
        max_addr = obj.max_addr
        ranges.append((min_addr, max_addr))

    # TODO, check if the offset to sp is correct. Without this we get tons of false positives.
    heap_base = state.globals['heap_base'] if 'heap_base' in state.globals else state.heap.heap_base
    ranges.append((heap_base, state.heap.heap_location))

    # Location of UTEE params placed there by the TOS, so they are also considered part of the TA memory
    utee_base = state.heap.heap_base
    utee_end = utee_base + 0x1000
    if state.arch.bits == 64:
        utee_end += 64
    else:
        utee_end += 32
    ranges.append((utee_base, utee_end))

    ranges.append((state.solver.eval_one(state.regs.sp) - state.arch.bits // 8, state.globals["stack_base"]))
    if 'thread_local_stack_addr' in state.globals:
        ranges.append((state.globals['thread_local_stack_addr'], state.globals['thread_local_stack_addr'] + state.globals['thread_local_stack_size']))
    return ranges


def _constraint_in_ranges(
    addr: Any, size_val: int, ranges: List[_AddrRange], num_bits: int
) -> Any:
    """
    Generate constraint: (addr, addr+size) lies entirely inside one of the ranges.

    Args:
        addr: The address to check
        size_val: The size to check
        ranges: The list of address ranges
        num_bits: The number of bits in the address

    Returns:
        A claripy constraint
    """
    if not ranges:
        return claripy.false

    terms = []
    for (lo, hi) in ranges:
        lo_bv = claripy.BVV(lo, num_bits)
        hi_bv = claripy.BVV(hi, num_bits)
        in_this = claripy.And(
            addr.UGE(lo_bv),
            (addr + size_val).ULE(hi_bv + 1),
        )
        terms.append(in_this)

    return claripy.Or(*terms)


def _constraint_straddles_ranges(
    addr: Any, size_val: int, ranges: List[_AddrRange], num_bits: int
) -> Any:
    """
    Generate constraint: [addr, addr+size) straddles a boundary of any range.

    Args:
        addr: The address to check
        size_val: The size to check
        ranges: The list of address ranges
        num_bits: The number of bits in the address

    Returns:
        A claripy constraint
    """
    if not ranges:
        return claripy.false

    terms = []
    for (lo, hi) in ranges:
        lo_bv = claripy.BVV(lo, num_bits)
        hi_bv = claripy.BVV(hi, num_bits)
        # Straddles low: addr < lo and addr+size > lo
        terms.append(claripy.And(addr.ULT(lo_bv), (addr + size_val).UGT(lo_bv + 1)))
        # Straddles high: addr < hi and addr+size > hi
        terms.append(claripy.And(addr.ULT(hi_bv), (addr + size_val).UGT(hi_bv + 1)))

    return claripy.Or(*terms)



def constraint_access_over_border(
    addr: Any, size_val: int, borders: List[int], num_bits: int
) -> Any:
    """
    Generate constraint: [addr, addr+size) accesses a border.

    Args:
        addr: The address to check
        size_val: The size to check
        borders: The list of address borders
        num_bits: The number of bits in the address

    Returns:
        A claripy constraint
    """
    if not borders:
        return claripy.false

    terms = []
    for border in borders:
        border_bv = claripy.BVV(border, num_bits)
        terms.append(claripy.And(addr.ULT(border_bv), (addr + size_val).UGT(border_bv)))

    return claripy.Or(*terms)


def addr_is_outside_ta_memory(state: angr.SimState, addr: Any, size: Any = None) -> bool:
    """
    Check if an address may be outside the TA memory (image + heap + stack).
    If the address and/or size are symbolic, we try to solve for a value that
    leads to an address outside the TA memory.

    Args:
        state: The state being stepped
        addr: The address to check
        size: The size of the memory access

    Returns:
        True if it is satisfiable that the access is outside TA memory, False otherwise.
    """
    if addr is None:
        return False

    if size is None:
        size = 0

    num_bits = state.arch.bits

    if type(addr) == int:
        addr = claripy.BVV(addr, num_bits)

    if not state.solver.symbolic(size):
        size_val = state.solver.eval_one(size)
    else:
        size_val = state.solver.max_int(size)

    ta_ranges = _get_ta_image_ranges(state)
    constraint_in_image = _constraint_in_ranges(addr, size_val, ta_ranges, num_bits)
    constraint_outside_ta = claripy.Not(constraint_in_image)
    return state.solver.satisfiable(extra_constraints=[constraint_outside_ta])


def addr_is_in_ta_memory(state: angr.SimState, addr: Any, size: Any = None) -> bool:
    """
    Check if an address may be inside the TA memory (image + heap + stack).
    If the address and/or size are symbolic, we try to solve for a value that
    leads to an address inside the TA memory.

    Args:
        state: The state being stepped
        addr: The address to check
        size: The size of the memory access

    Returns:
        True if it is satisfiable that the access is inside TA memory, False otherwise.
    """
    if addr is None:
        return False

    if size is None:
        size = 0

    num_bits = state.arch.bits

    if type(addr) == int:
        addr = claripy.BVV(addr, num_bits)

    if not state.solver.symbolic(size):
        size_val = state.solver.eval_one(size)
    else:
        size_val = state.solver.max_int(size)

    ta_ranges = _get_ta_image_ranges(state)
    constraint_in_image = _constraint_in_ranges(addr, size_val, ta_ranges, num_bits)

    return state.solver.satisfiable(extra_constraints=[constraint_in_image])


def addr_in_or_outside_ta_memory(state: angr.SimState, addr: Any, size: Any = None) -> bool:
    """
    Check if an access may straddle a TA memory boundary (partly in, partly out).
    If the address and/or size are symbolic, we try to solve for a value that
    straddles any image segment, heap, or stack boundary.

    Args:
        state: The state being stepped
        addr: The address to check
        size: The size of the memory access

    Returns:
        True if it is satisfiable that the access straddles a boundary, False otherwise.
    """
    if addr is None:
        return False

    if size is None:
        size = 0

    num_bits = state.arch.bits

    if type(addr) == int:
        addr = claripy.BVV(addr, num_bits)

    if not state.solver.symbolic(size):
        size_val = state.solver.eval_one(size)
    else:
        size_val = state.solver.max_int(size)

    ta_ranges = _get_ta_image_ranges(state)
    straddles_ta_ranges = _constraint_straddles_ranges(addr, size_val, ta_ranges, num_bits)

    return state.solver.satisfiable(extra_constraints=[straddles_ta_ranges])
