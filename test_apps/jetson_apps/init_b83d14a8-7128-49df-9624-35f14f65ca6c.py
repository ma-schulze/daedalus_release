import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_chain_target, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "b83d14a8_7128_49df_9624_35f14f65ca6c"

# From samples/luks-srv/ta/include/luks_srv_ta.h
LUKS_SRV_TA_CMD_GET_UNIQUE_PASS = 0
LUKS_SRV_TA_CMD_SRV_DOWN = 1
LUKS_SRV_TA_CMD_GET_GENERIC_PASS = 2

# From samples/luks-srv/ta/luks_srv_ta.c
PT_GET_PASS = 0x65  # MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE

LUKS_SRV_CONTEXT_STR_LEN = 40
LUKS_SRV_PASSPHRASE_LEN = 16


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


@ta_init_function(next_func="init_b83d14a8_7128_49df_9624_35f14f65ca6c_2")
def init_b83d14a8_7128_49df_9624_35f14f65ca6c_0(state: angr.SimState):
    """GET_UNIQUE_PASS: context -> passphrase."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, LUKS_SRV_TA_CMD_GET_UNIQUE_PASS, PT_GET_PASS)

    ctx = _alloc_buf(state, LUKS_SRV_CONTEXT_STR_LEN)
    out = _alloc_buf(state, LUKS_SRV_PASSPHRASE_LEN)
    _write_memref(state, p3, 0, ctx, claripy.BVV(LUKS_SRV_CONTEXT_STR_LEN, state.arch.bits))
    _write_memref(state, p3, 1, out, claripy.BVV(LUKS_SRV_PASSPHRASE_LEN, state.arch.bits))
    return state


@ta_init_function(next_func="init_b83d14a8_7128_49df_9624_35f14f65ca6c_2")
def init_b83d14a8_7128_49df_9624_35f14f65ca6c_1(state: angr.SimState):
    """GET_GENERIC_PASS: context -> passphrase."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, LUKS_SRV_TA_CMD_GET_GENERIC_PASS, PT_GET_PASS)

    ctx = _alloc_buf(state, LUKS_SRV_CONTEXT_STR_LEN)
    out = _alloc_buf(state, LUKS_SRV_PASSPHRASE_LEN)
    _write_memref(state, p3, 0, ctx, claripy.BVV(LUKS_SRV_CONTEXT_STR_LEN, state.arch.bits))
    _write_memref(state, p3, 1, out, claripy.BVV(LUKS_SRV_PASSPHRASE_LEN, state.arch.bits))
    return state


@ta_init_function
def init_b83d14a8_7128_49df_9624_35f14f65ca6c_2(state: angr.SimState):
    """SRV_DOWN: disables service via PTA flag; only makes sense after exercising pass APIs."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, LUKS_SRV_TA_CMD_SRV_DOWN, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_b83d14a8_7128_49df_9624_35f14f65ca6c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

