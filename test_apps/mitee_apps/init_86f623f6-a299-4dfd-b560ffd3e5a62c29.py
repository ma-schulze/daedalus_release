

import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# =============================================================================
# Analysis of the InvokeCommandEntryPoint at 0x25a78
#
# ABI (AArch64):
#   x0 = session handle
#   x1 = command ID (w19 after save)
#   x2 = parameter type mask (w21 after save)
#   x3 = pointer to parameter array (x20 after save)
#
# The TA first checks x2 (param types) == 0x65.
# If x2 != 0x65 → returns error 0xffff0006.
# If x2 == 0x65, it checks that ~w19 & 0xFF00 == 0  (i.e. (w19 & 0xFF00) == 0xFF00).
#   - If that fails, it reads params[0].buf (x20[0]), params[0].size (x20[8]),
#     params[1].buf (x20[0x10]), params[1].size (x20[0x18]) and uses them directly
#     when (w19 & 0xFF00) == 0xFF00 doesn't hold. BUT actually looking more carefully:
#     mvn w8, w19; tst w8, #0xff00; b.ne => if any bit in 0xFF00 of ~w19 is set
#     i.e. if (w19 & 0xFF00) != 0xFF00 → goes to 0x25b54 (the "not all ff" path).
#   - If (w19 & 0xFF00) == 0xFF00 → loads params directly and dispatches.
#
# For the path where (w19 & 0xFF00) != 0xFF00 (address 0x25b54):
#   Checks params[0].size (w7 = [x20+8]) == 0x1008 and params[1].size (w8 = [x20+0x18]) == 0x1008
#   Then loads params[0].buf (x21 = [x20]) and reads first dword [x21] == 3
#   Then loads params[1].buf (x20 = [x20+0x10])
#   Then falls through to the same command dispatch on w19.
#
# Command dispatch on w19 (after parameter setup):
#   0x0000 → sub_26240 (init/check)
#   0x0102 → sub_25420 (get ID)
#   0x0300 → sub_23220 (process type 0x300)
#   0x2114 → sub_2b148 (attestation report)
#   0x8001 → sub_2a860 (write/store)
#   0x8003 → sub_2ac10 (read/retrieve)
#   0xA000..0xA001 → returns error (unsupported)
#   0xB000 → sub at 0x25e8c (returns 0, stores zero)
#   0xB001 → sub_25968 + sub_28720 (status check)
#   0xF001 → sub_23620 (crypto op - encrypt/sign)
#   0xF002 → sub_26280 (key exchange / attestation)
#   0xF003 → sub_23be0 (crypto op - verify)
#   0xF004 → sub_24338 (seal)
#   0xF005 → sub_24808 (unseal)
#   0xF006 → sub_24a80 (key derive)
#   0xF007 → sub_24c08 (get public key)
#   0xF008 → sub_24e98 (import key)
#   0xF600 → sub_27040 (remote attestation)
#
# Parameter type x2 must be 0x65 for all commands.
#
# For the "simple" path (w19 & 0xFF00 == 0xFF00), params are loaded as:
#   x0 = [x20+0]   (buf0 ptr)
#   w1 = [x20+8]   (buf0 size, as 32-bit)
#   x2 = [x20+0x10] (buf1 ptr)
#   w3 = [x20+0x18] (buf1 size, as 32-bit)
# This matches two memref params: slot0 = (ptr, size), slot1 = (ptr, size).
#
# For the "complex" path at 0x25b54 (w19 & 0xFF00 != 0xFF00):
#   params[0].size must be 0x1008, params[1].size must be 0x1008
#   params[0].buf[0..3] must be 3 (dword)
#   Then params[0].buf and params[1].buf are used.
# =============================================================================

# GP parameter type 0x65 = TEEC_PARAM_TYPES(MEMREF_INPUT, MEMREF_OUTPUT, NONE, NONE)
# Actually 0x65 = 0b01100101 → nibbles: 5,6 → slot0=5(MEMREF_INOUT), slot1=6(MEMREF_OUTPUT)?
# Let's just use 0x65 as the TA expects it.

PARAM_TYPE = 0x65


def _setup_two_memref_params_simple(state, p3):
    """Set up two symbolic memref params (slot 0 and slot 1)."""
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)


def _setup_two_memref_params_complex(state, p3):
    """
    Set up two memref params with size=0x1008 each, and params[0].buf[0:4] = 3.
    This is needed for commands where (w19 & 0xFF00) != 0xFF00.
    """
    bits = state.arch.bits
    bytes_ = bits // 8

    # Slot 0: buf with first dword = 3, size = 0x1008
    buf0 = state.heap.allocate(0x2000)
    # Store concrete 3 at offset 0 (little-endian)
    state.memory.store(buf0, claripy.BVV(3, 32), size=4, endness=state.arch.memory_endness)
    # Rest is symbolic
    sym_data0 = get_tainted_mem_bits(state, (0x2000 - 4) * 8)
    state.memory.store(buf0 + 4, sym_data0, size=0x2000 - 4, endness=state.arch.memory_endness)
    state.memory.store(p3, claripy.BVV(buf0, bits), size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(p3 + bytes_, claripy.BVV(0x1008, bits), size=bytes_, endness=state.arch.memory_endness)

    # Slot 1: symbolic buf, size = 0x1008
    buf1 = state.heap.allocate(0x2000)
    sym_data1 = get_tainted_mem_bits(state, 0x2000 * 8)
    state.memory.store(buf1, sym_data1, size=0x2000, endness=state.arch.memory_endness)
    state.memory.store(p3 + 2 * bytes_, claripy.BVV(buf1, bits), size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * bytes_, claripy.BVV(0x1008, bits), size=bytes_, endness=state.arch.memory_endness)


# --- Command 0x0000: init/check (sub_26240) ---
@ta_init_function(next_funcs=[
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_1",   # get ID
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_3",   # 0x2114
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_4",   # 0x8001 write
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_6",   # 0xB001 status
])
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_0(state):
    """Command 0x0000 - initialization/check. Uses simple param path (0xFF00 bits all set)."""
    p3 = init_params(state)
    # cmd_id = 0xFF00 | 0x0000 won't work because 0x0000 & 0xFF00 != 0xFF00 for dispatch.
    # Actually looking again: for cmd 0x0000, w19=0 → mvn w8,w19 = 0xFFFFFFFF → tst w8, #0xff00
    # → bits set → b.ne taken → goes to 0x25b54 (complex path).
    # So command 0 goes through the complex path requiring size=0x1008 and [buf0]=3.
    state.regs.x1 = claripy.BVV(0x0000, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0x0102: get ID (sub_25420) ---
@ta_init_function(next_funcs=[
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_4",   # write
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_7",   # F001 encrypt
])
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_1(state):
    """Command 0x0102 - get device/TA ID."""
    p3 = init_params(state)
    # 0x0102: mvn → 0xFFFFFEFD, tst with 0xFF00 → 0xFE00 != 0 → complex path
    state.regs.x1 = claripy.BVV(0x0102, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0x0300: process (sub_23220) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_2(state):
    """Command 0x0300 - process operation."""
    p3 = init_params(state)
    # 0x0300: mvn → 0xFFFFFCFF, tst 0xFF00 → 0xFC00 != 0 → complex path
    state.regs.x1 = claripy.BVV(0x0300, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0x2114: attestation report (sub_2b148) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_3(state):
    """Command 0x2114 - attestation report."""
    p3 = init_params(state)
    # 0x2114: mvn → 0xFFFFDEEB, tst 0xFF00 → 0xDE00 != 0 → complex path
    state.regs.x1 = claripy.BVV(0x2114, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0x8001: write/store (sub_2a860) ---
@ta_init_function(next_func="init_86f623f6_a299_4dfd_b560ffd3e5a62c29_5")
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_4(state):
    """Command 0x8001 - write/store data."""
    p3 = init_params(state)
    # 0x8001: mvn → 0xFFFF7FFE, tst 0xFF00 → 0x7F00 != 0 → complex path
    state.regs.x1 = claripy.BVV(0x8001, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0x8003: read/retrieve (sub_2ac10) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_5(state):
    """Command 0x8003 - read/retrieve data (after write)."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0x8003, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xB001: status check (sub_25968 + sub_28720) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_6(state):
    """Command 0xB001 - status/health check."""
    p3 = init_params(state)
    # 0xB001: mvn → 0xFFFF4FFE, tst 0xFF00 → 0x4F00 != 0 → complex path
    state.regs.x1 = claripy.BVV(0xB001, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xB000: simple return (stores zero) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_7b(state):
    """Command 0xB000 - returns 0 and stores xzr to [x20]."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xB000, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF001: crypto encrypt/sign (sub_23620) ---
# Uses the simple path since 0xF001: mvn → 0x0FFE, tst 0xFF00 → 0x0F00 != 0 → complex
# Wait: 0xF001 → mvn = ~0xF001 = 0xFFFF0FFE, tst with 0xFF00 → 0x0F00 & 0xFF00 = 0x0F00 != 0
# → complex path. All commands that don't have 0xFF__ go complex.
# Actually let's check: for simple path we need (w19 & 0xFF00) == 0xFF00, i.e. w19 = 0xFF__.
# Since none of these command IDs are 0xFFxx, they all go complex.
@ta_init_function(next_funcs=[
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_8",   # F002
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_9",   # F003
])
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_7(state):
    """Command 0xF001 - crypto operation (encrypt/sign)."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF001, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF002: key exchange / attestation (sub_26280) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_8(state):
    """Command 0xF002 - key exchange or remote attestation."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF002, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF003: crypto verify (sub_23be0) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_9(state):
    """Command 0xF003 - crypto verify (after encrypt/sign)."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF003, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF004: seal (sub_24338) ---
@ta_init_function(next_func="init_86f623f6_a299_4dfd_b560ffd3e5a62c29_11")
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_10(state):
    """Command 0xF004 - seal data."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF004, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF005: unseal (sub_24808) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_11(state):
    """Command 0xF005 - unseal data (after seal)."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF005, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF006: key derive (sub_24a80) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_12(state):
    """Command 0xF006 - key derivation."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF006, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF007: get public key (sub_24c08) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_13(state):
    """Command 0xF007 - get public key."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF007, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF008: import key (sub_24e98) ---
@ta_init_function(next_funcs=[
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_7",   # F001 encrypt
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_10",  # F004 seal
    "init_86f623f6_a299_4dfd_b560ffd3e5a62c29_13",  # F007 get pub key
])
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_14(state):
    """Command 0xF008 - import key material."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF008, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state


# --- Command 0xF600: remote attestation (sub_27040) ---
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_15(state):
    """Command 0xF600 - remote attestation / quote generation."""
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0xF600, 64)
    state.regs.x2 = claripy.BVV(PARAM_TYPE, 64)
    _setup_two_memref_params_complex(state, p3)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_86f623f6_a299_4dfd_b560ffd3e5a62c29_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

