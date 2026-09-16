import angr
import claripy

from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function, ta_init_function
from test_apps.utils import init_params, place_sym_value_param


TA_NAME = "fd02c9da_306c_48c7_a49c_bbd827ae86ee"

# Derived from optee_os/ta/pkcs11/include/pkcs11_ta.h and ta/pkcs11/src/*.c
PKCS11_CMD_PING = 0
PKCS11_CMD_SLOT_LIST = 1
PKCS11_CMD_SLOT_INFO = 2
PKCS11_CMD_TOKEN_INFO = 3
PKCS11_CMD_MECHANISM_IDS = 4
PKCS11_CMD_MECHANISM_INFO = 5
PKCS11_CMD_OPEN_SESSION = 6
PKCS11_CMD_CLOSE_SESSION = 7
PKCS11_CMD_SESSION_INFO = 9
PKCS11_CMD_LOGIN = 13
PKCS11_CMD_LOGOUT = 14
PKCS11_CMD_SEED_RANDOM = 41
PKCS11_CMD_GENERATE_RANDOM = 42

# Param type nibbles: 5=MEMREF_INPUT, 6=MEMREF_OUTPUT, 7=MEMREF_INOUT
# Most PKCS11 commands use: memref[0] INOUT, memref[2] OUTPUT
PT_CTRL_INOUT__OUT2 = 0x607  # INOUT, NONE, OUTPUT, NONE
PT_CTRL_INOUT_ONLY = 0x7     # INOUT, NONE, NONE, NONE


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


def _alloc_buf(state: angr.SimState, size: int, *, tainted: bool = True) -> int:
    buf = state.heap.allocate(size)
    data = get_tainted_mem_bits(state, size * 8) if tainted else claripy.BVV(0, size * 8)
    state.memory.store(buf, data, size=size, endness=state.arch.memory_endness)
    return buf


def _mk_ctrl_buf(state: angr.SimState, size: int) -> int:
    # Keep small and structured: first u32 fields are often parsed.
    return _alloc_buf(state, size, tainted=True)


def _store_u32_le(state: angr.SimState, addr: int, value: int) -> None:
    state.memory.store(addr, claripy.BVV(value & 0xFFFFFFFF, 32), size=4, endness=state.arch.memory_endness)


def _setup_ctrl_and_out2(state: angr.SimState, p3: int, ctrl_sz: int, out2_sz: int) -> tuple[int, int]:
    ctrl = _mk_ctrl_buf(state, ctrl_sz)
    out2 = _alloc_buf(state, out2_sz, tainted=True)
    _write_memref(state, p3, 0, ctrl, claripy.BVV(ctrl_sz, state.arch.bits))
    _write_memref(state, p3, 2, out2, claripy.BVV(out2_sz, state.arch.bits))
    return ctrl, out2


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_0(state: angr.SimState):
    """PING: ctrl[0]=0, out2 returns version triplet."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_PING, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=12)
    _store_u32_le(state, ctrl, 0)
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_1(state: angr.SimState):
    """SLOT_LIST: out2 returns token IDs array."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_SLOT_LIST, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=64)
    _store_u32_le(state, ctrl, 0)
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_2(state: angr.SimState):
    """SLOT_INFO: ctrl[0]=slot_id, out2 returns struct pkcs11_slot_info."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_SLOT_INFO, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=128)
    _store_u32_le(state, ctrl, 0)  # slot_id
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_3(state: angr.SimState):
    """TOKEN_INFO: ctrl[0]=slot_id, out2 returns struct pkcs11_token_info."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_TOKEN_INFO, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=256)
    _store_u32_le(state, ctrl, 0)  # slot_id
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_4(state: angr.SimState):
    """MECHANISM_IDS: ctrl[0]=slot_id, out2 returns mechanism IDs array."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_MECHANISM_IDS, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=256)
    _store_u32_le(state, ctrl, 0)  # slot_id
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_5(state: angr.SimState):
    """MECHANISM_INFO: ctrl = [slot_id, mechanism_id], out2 returns struct pkcs11_mechanism_info."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_MECHANISM_INFO, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=8, out2_sz=16)
    _store_u32_le(state, ctrl + 0, 0)       # slot_id
    _store_u32_le(state, ctrl + 4, 0x1080)  # PKCS11_CKM_AES_KEY_GEN (common, should be supported)
    return state


@ta_init_function(next_funcs=[
    "init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_7",
    "init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_8",
])
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_6(state: angr.SimState):
    """OPEN_SESSION: ctrl = [slot_id, flags], out2 returns session handle (u32)."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_OPEN_SESSION, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=8, out2_sz=4)
    _store_u32_le(state, ctrl + 0, 0)   # slot_id
    _store_u32_le(state, ctrl + 4, 0)   # flags (keep simple)
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_7(state: angr.SimState):
    """SESSION_INFO: ctrl[0]=session handle, out2 returns struct pkcs11_session_info."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_SESSION_INFO, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=32)
    # Use symbolic session handle: if chained after OPEN_SESSION, a real handle may exist in memory,
    # but keeping symbolic also explores error handling paths.
    state.memory.store(ctrl, get_tainted_mem_bits(state, 32), size=4, endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_8(state: angr.SimState):
    """CLOSE_SESSION: ctrl[0]=session handle."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_CLOSE_SESSION, PT_CTRL_INOUT_ONLY)

    ctrl = _mk_ctrl_buf(state, 4)
    _write_memref(state, p3, 0, ctrl, claripy.BVV(4, state.arch.bits))
    state.memory.store(ctrl, get_tainted_mem_bits(state, 32), size=4, endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_9(state: angr.SimState):
    """GENERATE_RANDOM: ctrl[0]=session handle, out2 returns random bytes."""
    p3 = init_params(state)
    _set_cmd_and_ptypes(state, PKCS11_CMD_GENERATE_RANDOM, PT_CTRL_INOUT__OUT2)

    ctrl, _out2 = _setup_ctrl_and_out2(state, p3, ctrl_sz=4, out2_sz=64)
    state.memory.store(ctrl, get_tainted_mem_bits(state, 32), size=4, endness=state.arch.memory_endness)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_fd02c9da_306c_48c7_a49c_bbd827ae86ee_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

