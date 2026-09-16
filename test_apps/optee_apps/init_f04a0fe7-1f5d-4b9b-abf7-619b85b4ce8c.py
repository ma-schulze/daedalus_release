import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c"

# Derived from optee_os/ta/trusted_keys/include/trusted_keys.h and entry.c
TA_CMD_GET_RANDOM = 0
TA_CMD_SEAL = 1
TA_CMD_UNSEAL = 2

# Param type nibbles: 5=MEMREF_INPUT, 6=MEMREF_OUTPUT, 7=MEMREF_INOUT
PT_MEMREF_OUT_0 = 0x6
PT_MEMREF_IN_0_OUT_1 = 0x65


def _set_cmd_and_ptypes(state: angr.SimState, cmd_id: int, ptypes: int) -> None:
    if state.arch.bits == 64:
        state.regs.x1 = claripy.BVV(cmd_id, 64)
        state.regs.x2 = claripy.BVV(ptypes, 64)
    else:
        state.regs.r1 = claripy.BVV(cmd_id, 32)
        state.regs.r2 = claripy.BVV(ptypes, 32)


def _write_memref(state: angr.SimState, p3: int, index: int, buf: int, size_bv) -> None:
    bytes_ = state.arch.bits // 8
    base = p3 + index * (bytes_ * 2)
    state.memory.store(base, claripy.BVV(buf, state.arch.bits), size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(base + bytes_, size_bv, size=bytes_, endness=state.arch.memory_endness)


def _alloc_buf(state: angr.SimState, size: int) -> int:
    buf = state.heap.allocate(size)
    state.memory.store(buf, get_tainted_mem_bits(state, size * 8), size=size, endness=state.arch.memory_endness)
    return buf


@ta_init_function
def init_f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c_0(state: angr.SimState):
    """TA_CMD_GET_RANDOM: memref[0] output."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_CMD_GET_RANDOM, PT_MEMREF_OUT_0)

    out_size = 64
    out_buf = _alloc_buf(state, out_size)
    _write_memref(state, p3, 0, out_buf, claripy.BVV(out_size, state.arch.bits))
    return state


@ta_init_function(next_func="init_f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c_2")
def init_f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c_1(state: angr.SimState):
    """TA_CMD_SEAL: memref[0] input (plain key), memref[1] output (sealed blob)."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_CMD_SEAL, PT_MEMREF_IN_0_OUT_1)

    # entry.c enforces input size <= 512, output size <= 512 and out >= in + hdr.
    in_size = 32
    out_size = 512
    in_buf = _alloc_buf(state, in_size)
    out_buf = _alloc_buf(state, out_size)
    _write_memref(state, p3, 0, in_buf, claripy.BVV(in_size, state.arch.bits))
    _write_memref(state, p3, 1, out_buf, claripy.BVV(out_size, state.arch.bits))
    return state


@ta_init_function
def init_f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c_2(state: angr.SimState):
    """TA_CMD_UNSEAL: memref[0] input (sealed blob), memref[1] output (plain key)."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_CMD_UNSEAL, PT_MEMREF_IN_0_OUT_1)

    # entry.c checks input size > sizeof(tk_blob_hdr) and <= 512.
    in_size = 96
    out_size = 64
    in_buf = _alloc_buf(state, in_size)
    out_buf = _alloc_buf(state, out_size)
    _write_memref(state, p3, 0, in_buf, claripy.BVV(in_size, state.arch.bits))
    _write_memref(state, p3, 1, out_buf, claripy.BVV(out_size, state.arch.bits))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_f04a0fe7_1f5d_4b9b_abf7_619b85b4ce8c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

