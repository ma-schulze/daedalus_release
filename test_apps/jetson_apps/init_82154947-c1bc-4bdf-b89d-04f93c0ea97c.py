import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_chain_target, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "82154947_c1bc_4bdf_b89d_04f93c0ea97c"

# From samples/hwkey-agent/ta/include/hwkey_agent_ta.h
HWKEY_AGENT_TA_CMD_ENCRYPTION = 0
HWKEY_AGENT_TA_CMD_DECRYPTION = 1
HWKEY_AGENT_TA_CMD_GET_RANDOM = 2

# From samples/hwkey-agent/ta/hwkey_agent_ta.c
PT_CRYPTO = 0x655  # MEMREF_INPUT, MEMREF_INPUT, MEMREF_OUTPUT, NONE
PT_GET_RANDOM = 0x6  # MEMREF_OUTPUT, NONE, NONE, NONE

AES128_KEY_BYTE_SIZE = 16


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


@ta_init_function(next_func="init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_2")
def init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_0(state: angr.SimState):
    """ENCRYPTION: IV(16) + payload -> output."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, HWKEY_AGENT_TA_CMD_ENCRYPTION, PT_CRYPTO)

    iv = _alloc_buf(state, AES128_KEY_BYTE_SIZE)
    payload = _alloc_buf(state, 0x100)
    out = _alloc_buf(state, 0x100)

    _write_memref(state, p3, 0, iv, claripy.BVV(AES128_KEY_BYTE_SIZE, state.arch.bits))
    _write_memref(state, p3, 1, payload, claripy.BVV(0x100, state.arch.bits))
    _write_memref(state, p3, 2, out, claripy.BVV(0x100, state.arch.bits))
    return state


@ta_init_function(next_func="init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_2")
def init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_1(state: angr.SimState):
    """DECRYPTION: IV(16) + payload -> output."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, HWKEY_AGENT_TA_CMD_DECRYPTION, PT_CRYPTO)

    iv = _alloc_buf(state, AES128_KEY_BYTE_SIZE)
    payload = _alloc_buf(state, 0x100)
    out = _alloc_buf(state, 0x100)

    _write_memref(state, p3, 0, iv, claripy.BVV(AES128_KEY_BYTE_SIZE, state.arch.bits))
    _write_memref(state, p3, 1, payload, claripy.BVV(0x100, state.arch.bits))
    _write_memref(state, p3, 2, out, claripy.BVV(0x100, state.arch.bits))
    return state


@ta_init_function
def init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_2(state: angr.SimState):
    """GET_RANDOM: output buffer."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, HWKEY_AGENT_TA_CMD_GET_RANDOM, PT_GET_RANDOM)

    out = _alloc_buf(state, 64)
    _write_memref(state, p3, 0, out, claripy.BVV(64, state.arch.bits))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_82154947_c1bc_4bdf_b89d_04f93c0ea97c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

