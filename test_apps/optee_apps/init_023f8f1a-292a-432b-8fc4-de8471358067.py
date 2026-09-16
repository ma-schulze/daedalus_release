import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "023f8f1a_292a_432b_8fc4_de8471358067"

# Derived from optee_os/ta/avb/include/ta_avb.h and optee_os/ta/avb/entry.c
TA_AVB_CMD_READ_ROLLBACK_INDEX = 0
TA_AVB_CMD_WRITE_ROLLBACK_INDEX = 1
TA_AVB_CMD_READ_LOCK_STATE = 2
TA_AVB_CMD_WRITE_LOCK_STATE = 3
TA_AVB_CMD_READ_PERSIST_VALUE = 4
TA_AVB_CMD_WRITE_PERSIST_VALUE = 5

# Param type nibbles (OP-TEE/GP): 1=VALUE_INPUT, 2=VALUE_OUTPUT, 5=MEMREF_INPUT, 7=MEMREF_INOUT
PT_READ_RB = 0x21
PT_WRITE_RB = 0x11
PT_READ_LOCK = 0x2
PT_WRITE_LOCK = 0x1
PT_READ_PERSIST = 0x75
PT_WRITE_PERSIST = 0x55


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
    state.memory.store(
        base,
        claripy.BVV(buf, state.arch.bits),
        size=bytes_,
        endness=state.arch.memory_endness,
    )
    state.memory.store(base + bytes_, size_bv, size=bytes_, endness=state.arch.memory_endness)


def _alloc_buf(state: angr.SimState, size: int) -> int:
    buf = state.heap.allocate(size)
    state.memory.store(
        buf,
        get_tainted_mem_bits(state, size * 8),
        size=size,
        endness=state.arch.memory_endness,
    )
    return buf


@ta_init_function(next_funcs=[
    "init_023f8f1a_292a_432b_8fc4_de8471358067_1",
    "init_023f8f1a_292a_432b_8fc4_de8471358067_2",
])
def init_023f8f1a_292a_432b_8fc4_de8471358067_0(state: angr.SimState):
    """WRITE_ROLLBACK_INDEX: good predecessor for READ_ROLLBACK_INDEX."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_WRITE_ROLLBACK_INDEX, PT_WRITE_RB)

    # slot must be < 256 (TA_AVB_MAX_ROLLBACK_LOCATIONS)
    slot = claripy.BVV(0, 32)
    upper = claripy.BVV(0, 32)
    lower = claripy.BVV(1, 32)

    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, slot), claripy.BVV(0, 64))
        _write_value(state, p3, 1, claripy.ZeroExt(32, upper), claripy.ZeroExt(32, lower))
    else:
        _write_value(state, p3, 0, slot, claripy.BVV(0, 32))
        _write_value(state, p3, 1, upper, lower)

    return state


@ta_init_function
def init_023f8f1a_292a_432b_8fc4_de8471358067_1(state: angr.SimState):
    """READ_ROLLBACK_INDEX."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_READ_ROLLBACK_INDEX, PT_READ_RB)

    slot = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, slot), claripy.BVV(0, 64))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
    else:
        _write_value(state, p3, 0, slot, claripy.BVV(0, 32))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))

    return state


@ta_init_function
def init_023f8f1a_292a_432b_8fc4_de8471358067_2(state: angr.SimState):
    """READ_LOCK_STATE."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_READ_LOCK_STATE, PT_READ_LOCK)

    if state.arch.bits == 64:
        _write_value(state, p3, 0, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
    else:
        _write_value(state, p3, 0, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))

    return state


@ta_init_function(next_funcs=[
    "init_023f8f1a_292a_432b_8fc4_de8471358067_4",
    "init_023f8f1a_292a_432b_8fc4_de8471358067_5",
])
def init_023f8f1a_292a_432b_8fc4_de8471358067_3(state: angr.SimState):
    """WRITE_LOCK_STATE: can reset rollback slots; useful predecessor."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_WRITE_LOCK_STATE, PT_WRITE_LOCK)

    lock_state = claripy.BVV(1, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, lock_state), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, lock_state, claripy.BVV(0, 32))

    return state


@ta_init_function
def init_023f8f1a_292a_432b_8fc4_de8471358067_4(state: angr.SimState):
    """READ_PERSIST_VALUE: memref[0]=name, memref[1]=inout buffer."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_READ_PERSIST_VALUE, PT_READ_PERSIST)

    name = _alloc_buf(state, 8)
    value = _alloc_buf(state, 64)
    _write_memref(state, p3, 0, name, claripy.BVV(8, state.arch.bits))
    _write_memref(state, p3, 1, value, claripy.BVV(64, state.arch.bits))
    return state


@ta_init_function(next_func="init_023f8f1a_292a_432b_8fc4_de8471358067_4")
def init_023f8f1a_292a_432b_8fc4_de8471358067_5(state: angr.SimState):
    """WRITE_PERSIST_VALUE then READ_PERSIST_VALUE."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_AVB_CMD_WRITE_PERSIST_VALUE, PT_WRITE_PERSIST)

    name = _alloc_buf(state, 8)
    value = _alloc_buf(state, 32)
    _write_memref(state, p3, 0, name, claripy.BVV(8, state.arch.bits))
    _write_memref(state, p3, 1, value, claripy.BVV(32, state.arch.bits))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_023f8f1a_292a_432b_8fc4_de8471358067_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

