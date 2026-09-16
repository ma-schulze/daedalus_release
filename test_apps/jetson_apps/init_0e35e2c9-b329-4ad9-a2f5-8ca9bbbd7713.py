import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_chain_target
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "0e35e2c9_b329_4ad9_a2f5_8ca9bbbd7713"

# From samples/cpubl-payload-dec/ta/include/ta_cpubl_dec.h
CPUBL_PAYLOAD_DECRYPTION_CMD_IS_USER_KEY_EXISTS = 0
CPUBL_PAYLOAD_DECRYPTION_CMD_DECRYPT_IMAGE = 1

# From samples/cpubl-payload-dec/ta/entry.c
PT_IS_USER_KEY_EXISTS = 0x21  # VALUE_INPUT, VALUE_OUTPUT, NONE, NONE
PT_DECRYPT_IMAGE = 0x17       # MEMREF_INOUT, VALUE_INPUT, NONE, NONE


def _set_cmd_and_ptypes(state: angr.SimState, cmd_id: int, ptypes: int) -> None:
    if state.arch.bits == 64:
        state.regs.x1 = claripy.BVV(cmd_id, 64)
        state.regs.x2 = claripy.BVV(ptypes, 64)
    else:
        state.regs.r1 = claripy.BVV(cmd_id, 32)
        state.regs.r2 = claripy.BVV(ptypes, 32)


def _write_value(state: angr.SimState, p3: int, index: int, a_bv, b_bv) -> None:
    bytes_ = state.arch.bits // 8
    base = p3 + index * (bytes_ * 2)
    state.memory.store(base, a_bv, size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(base + bytes_, b_bv, size=bytes_, endness=state.arch.memory_endness)


def _write_memref(state: angr.SimState, p3: int, index: int, buf: int, size_bv) -> None:
    bytes_ = state.arch.bits // 8
    base = p3 + index * (bytes_ * 2)
    state.memory.store(base, claripy.BVV(buf, state.arch.bits), size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(base + bytes_, size_bv, size=bytes_, endness=state.arch.memory_endness)


def _alloc_buf(state: angr.SimState, size: int) -> int:
    buf = state.heap.allocate(size)
    state.memory.store(buf, get_tainted_mem_bits(state, size * 8), size=size, endness=state.arch.memory_endness)
    return buf


@ta_init_function(next_func="init_0e35e2c9_b329_4ad9_a2f5_8ca9bbbd7713_1")
def init_0e35e2c9_b329_4ad9_a2f5_8ca9bbbd7713_0(state: angr.SimState):
    """IS_USER_KEY_EXISTS: VALUE_INPUT + VALUE_OUTPUT."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, CPUBL_PAYLOAD_DECRYPTION_CMD_IS_USER_KEY_EXISTS, PT_IS_USER_KEY_EXISTS)

    # Value input: allow TA/PTA to interpret; keep small concrete.
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.BVV(0, 64), claripy.BVV(0, 64))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
    else:
        _write_value(state, p3, 0, claripy.BVV(0, 32), claripy.BVV(0, 32))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))

    return state


@ta_init_function
def init_0e35e2c9_b329_4ad9_a2f5_8ca9bbbd7713_1(state: angr.SimState):
    """DECRYPT_IMAGE: memref[0] inout buffer + value[1] input."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, CPUBL_PAYLOAD_DECRYPTION_CMD_DECRYPT_IMAGE, PT_DECRYPT_IMAGE)

    img = _alloc_buf(state, 0x400)
    _write_memref(state, p3, 0, img, claripy.BVV(0x400, state.arch.bits))

    if state.arch.bits == 64:
        _write_value(state, p3, 1, claripy.BVV(0, 64), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 1, claripy.BVV(0, 32), claripy.BVV(0, 32))

    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_0e35e2c9_b329_4ad9_a2f5_8ca9bbbd7713_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

