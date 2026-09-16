import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c"

# From samples/ftpm-helper/ta/include/ftpm_helper_ta.h
FTPM_HELPER_TA_CMD_QUERY_SN = 0xFF000001
FTPM_HELPER_TA_CMD_QUERY_ECID = 0xFF000002
FTPM_HELPER_TA_CMD_QUERY_PROV_MODE = 0xFF000003
FTPM_HELPER_TA_CMD_GET_RSA_EK_CERT = 0xFF000004
FTPM_HELPER_TA_CMD_GET_EC_EK_CERT = 0xFF000005
FTPM_HELPER_TA_CMD_GET_SID_CERT = 0xFFFF0006
FTPM_HELPER_TA_CMD_GET_FW_ID_CERT = 0xFFFF0007
FTPM_HELPER_TA_CMD_GET_RSA_EK_CSR = 0xFFFF0008
FTPM_HELPER_TA_CMD_GET_EC_EK_CSR = 0xFFFF0009
FTPM_HELPER_TA_CMD_SIGN_EK_CSR = 0xFFFF000A
FTPM_HELPER_TA_CMD_INJECT_EPS = 0xFF00000B

FTPM_HELPER_TA_ECID_LENGTH = 8
FTPM_HELPER_TA_SN_LENGTH = 10
FTPM_EK_CERT_BUF_SIZE = 2048
FTPM_EK_CSR_BUF_SIZE = 2048

# Param type nibbles: 2=VALUE_OUTPUT, 5=MEMREF_INPUT, 6=MEMREF_OUTPUT, 7=MEMREF_INOUT
PT_OUT_MEMREF0 = 0x6
PT_OUT_VAL_0_1_2 = 0x222
PT_INOUT_MEMREF0 = 0x7
PT_IN_MEMREF0 = 0x5


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
    "init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_1",
    "init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_2",
    "init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_3",
])
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_0(state: angr.SimState):
    """QUERY_PROV_MODE: value outputs in params[0..2]."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_QUERY_PROV_MODE, PT_OUT_VAL_0_1_2)

    if state.arch.bits == 64:
        _write_value(state, p3, 0, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
        _write_value(state, p3, 2, get_tainted_mem_bits(state, 64), get_tainted_mem_bits(state, 64))
    else:
        _write_value(state, p3, 0, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))
        _write_value(state, p3, 1, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))
        _write_value(state, p3, 2, get_tainted_mem_bits(state, 32), get_tainted_mem_bits(state, 32))

    return state


@ta_init_function
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_1(state: angr.SimState):
    """QUERY_SN: memref[0] output, size must be exactly 10 bytes."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_QUERY_SN, PT_OUT_MEMREF0)

    out = _alloc_buf(state, FTPM_HELPER_TA_SN_LENGTH)
    _write_memref(state, p3, 0, out, claripy.BVV(FTPM_HELPER_TA_SN_LENGTH, state.arch.bits))
    return state


@ta_init_function
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_2(state: angr.SimState):
    """QUERY_ECID: memref[0] output, size must be exactly 8 bytes."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_QUERY_ECID, PT_OUT_MEMREF0)

    out = _alloc_buf(state, FTPM_HELPER_TA_ECID_LENGTH)
    _write_memref(state, p3, 0, out, claripy.BVV(FTPM_HELPER_TA_ECID_LENGTH, state.arch.bits))
    return state


@ta_init_function(next_funcs=[
    "init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_4",
    "init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_5",
])
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_3(state: angr.SimState):
    """GET_RSA_EK_CSR: memref[0] output, size must be 2048 bytes (as checked in TA)."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_GET_RSA_EK_CSR, PT_OUT_MEMREF0)

    out = _alloc_buf(state, FTPM_EK_CSR_BUF_SIZE)
    _write_memref(state, p3, 0, out, claripy.BVV(FTPM_EK_CSR_BUF_SIZE, state.arch.bits))
    return state


@ta_init_function(next_func="init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_5")
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_4(state: angr.SimState):
    """GET_EC_EK_CSR: memref[0] output, size must be 2048 bytes."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_GET_EC_EK_CSR, PT_OUT_MEMREF0)

    out = _alloc_buf(state, FTPM_EK_CSR_BUF_SIZE)
    _write_memref(state, p3, 0, out, claripy.BVV(FTPM_EK_CSR_BUF_SIZE, state.arch.bits))
    return state


@ta_init_function
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_5(state: angr.SimState):
    """SIGN_EK_CSR: memref[0] inout, size <= 2048."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_SIGN_EK_CSR, PT_INOUT_MEMREF0)

    buf = _alloc_buf(state, FTPM_EK_CSR_BUF_SIZE)
    _write_memref(state, p3, 0, buf, claripy.BVV(FTPM_EK_CSR_BUF_SIZE, state.arch.bits))
    return state


@ta_init_function
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_6(state: angr.SimState):
    """INJECT_EPS: memref[0] input, size must be exactly 64 bytes."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, FTPM_HELPER_TA_CMD_INJECT_EPS, PT_IN_MEMREF0)

    eps = _alloc_buf(state, 64)
    _write_memref(state, p3, 0, eps, claripy.BVV(64, state.arch.bits))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_a6a3a74a_77cb_433a_990c_1dfb8a3fbc4c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

