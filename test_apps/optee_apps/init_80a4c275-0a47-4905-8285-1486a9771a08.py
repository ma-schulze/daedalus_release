import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "80a4c275_0a47_4905_8285_1486a9771a08"

# Derived from optee_os/ta/remoteproc/include/ta_remoteproc.h and remoteproc_core.c
TA_RPROC_CMD_LOAD_FW = 1
TA_RPROC_CMD_START_FW = 2
TA_RPROC_CMD_STOP_FW = 3
TA_RPROC_CMD_GET_RSC_TABLE = 4
TA_RPROC_CMD_GET_COREDUMP = 5
TA_RPROC_CMD_RELEASE_FW = 6

# Param type nibbles: 1=VALUE_INPUT, 2=VALUE_OUTPUT, 5=MEMREF_INPUT
PT_LOAD_FW = 0x51
PT_VALUE_IN_0 = 0x1
PT_GET_RSC_TABLE = 0x221


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


@ta_init_function(next_funcs=[
    "init_80a4c275_0a47_4905_8285_1486a9771a08_1",
    "init_80a4c275_0a47_4905_8285_1486a9771a08_3",
    "init_80a4c275_0a47_4905_8285_1486a9771a08_5",
])
def init_80a4c275_0a47_4905_8285_1486a9771a08_0(state: angr.SimState):
    """LOAD_FW: [in] value[0].a=rproc_id, [in] memref[1]=firmware image."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_LOAD_FW, PT_LOAD_FW)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))

    fw = _alloc_buf(state, 0x400)
    _write_memref(state, p3, 1, fw, claripy.BVV(0x400, state.arch.bits))
    return state


@ta_init_function
def init_80a4c275_0a47_4905_8285_1486a9771a08_1(state: angr.SimState):
    """START_FW: [in] value[0].a=rproc_id."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_START_FW, PT_VALUE_IN_0)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))
    return state


@ta_init_function(next_funcs=[
    "init_80a4c275_0a47_4905_8285_1486a9771a08_4",
    "init_80a4c275_0a47_4905_8285_1486a9771a08_5",
])
def init_80a4c275_0a47_4905_8285_1486a9771a08_2(state: angr.SimState):
    """STOP_FW: [in] value[0].a=rproc_id. After stop, release is sensible."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_STOP_FW, PT_VALUE_IN_0)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))
    return state


@ta_init_function
def init_80a4c275_0a47_4905_8285_1486a9771a08_3(state: angr.SimState):
    """GET_RSC_TABLE: [in] value[0].a=rproc_id, [out] value[1], value[2]."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_GET_RSC_TABLE, PT_GET_RSC_TABLE)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
        _write_value(state, p3, 2, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))
        _write_value(state, p3, 2, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))
    return state


@ta_init_function
def init_80a4c275_0a47_4905_8285_1486a9771a08_4(state: angr.SimState):
    """GET_COREDUMP currently returns TEE_ERROR_NOT_IMPLEMENTED (coverage of error path)."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_GET_COREDUMP, PT_VALUE_IN_0)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))
    return state


@ta_init_function(next_func="init_80a4c275_0a47_4905_8285_1486a9771a08_0")
def init_80a4c275_0a47_4905_8285_1486a9771a08_5(state: angr.SimState):
    """RELEASE_FW: [in] value[0].a=rproc_id. After release, load makes sense."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, TA_RPROC_CMD_RELEASE_FW, PT_VALUE_IN_0)

    rproc_id = claripy.BVV(0, 32)
    if state.arch.bits == 64:
        _write_value(state, p3, 0, claripy.ZeroExt(32, rproc_id), claripy.BVV(0, 64))
    else:
        _write_value(state, p3, 0, rproc_id, claripy.BVV(0, 32))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_80a4c275_0a47_4905_8285_1486a9771a08_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

