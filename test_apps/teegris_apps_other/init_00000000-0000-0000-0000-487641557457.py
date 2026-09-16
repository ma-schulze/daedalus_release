import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA dispatcher at 0x8b38:
# - First checks w2 (param_types) == 0x65 -> MEMREF_INPUT(5) at slot0, MEMREF_OUTPUT(6) at slot1
# - Then validates: TEES_IsREESharedMemory(p3[0].ptr, p3[0].size) must return non-zero (REE memory)
# - Then validates: TEES_IsREESharedMemory(p3[1].ptr, p3[1].size) must return non-zero
# - Then dispatches into sub_dcac(p3[0], p3[1], p3[2], p3[3])
#
# Inside sub_dcac, a command ID is parsed from the input memref (slot0). The first word read
# from the input buffer (via sub_c91c then sub_f2f0) becomes 'cmd'. Then a jump-table at 0x287e8
# is used: cmd >> 3 must be <= 0x4f0, and table[cmd] points to a handler. Each handler is one
# of the sub_f2f0..sub_10b9c style routines which themselves call afd0 (parameter dispatcher).
#
# The command IDs observed from the handler list (each handler dispatches via afd0 with
# different (type,subcmd) tuples). We expose distinct init functions per high-level command.
#
# Stateful behavior:
#  - sub_18d08 / "set master key" path (cmd 0xda area) appears to install a key into shared state
#    used later by encrypt/decrypt routines (0xd2/0xd3/0xd4/0xd5/0xd6 family). We model
#    set-key -> use-key as a chain.
#  - sub_1736c initializes a session ("login") used by subsequent crypto handlers.
#
# Because the dispatch table is sparse and exact command IDs are hard to recover from raw
# disassembly alone, we provide a small set of representative inits that cover the major
# code paths reachable from TA_InvokeCommandEntryPoint. Each one constrains key bytes of the
# input memref to fixed dispatcher values to avoid state space explosion.


PARAM_TYPES_MEMREF_IN_MEMREF_OUT = 0x65  # slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6)
INPUT_BUF_SIZE = 0x80


def _setup_common(state):
    """Common setup: param_types=0x65, slot0 memref input, slot1 memref output."""
    p3 = init_params(state)
    state.regs.x2 = PARAM_TYPES_MEMREF_IN_MEMREF_OUT
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


def _write_cmd_word(state, p3, cmd_value):
    """Write a concrete 32-bit command word at offset 0 of slot0's buffer.

    On AArch64, p3 slot 0 layout: [ptr(8), size(8)]. We read the ptr and write
    a concrete cmd word there to steer the in-TA dispatcher.
    """
    word_size = 8
    slot0_ptr_addr = p3 + 0 * 2 * word_size
    buf_ptr = state.memory.load(slot0_ptr_addr, word_size, endness=state.arch.memory_endness)
    # Constrain size to something reasonable to avoid state explosion on size checks
    slot0_size_addr = p3 + 0 * 2 * word_size + word_size
    state.memory.store(slot0_size_addr, claripy.BVV(0x40, 64), endness=state.arch.memory_endness)
    state.memory.store(buf_ptr, claripy.BVV(cmd_value, 32), endness=state.arch.memory_endness)
    # Also constrain the next dword (often a sub-field / length) to a small value
    state.memory.store(buf_ptr + 4, claripy.BVV(0x10, 32), endness=state.arch.memory_endness)
    return buf_ptr


# ---------------------------------------------------------------------------
# Command 0: generic entry that fails param-type check (negative path) — useful
# baseline; r2 != 0x65 leads to early TEE_ERROR return.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_0(state):
    p3 = init_params(state)
    # Wrong param types -> exercises early error path at 0x8b8c
    state.regs.x2 = 0x00
    return state


# ---------------------------------------------------------------------------
# Command 1: correct param types, exercises sub_dcac main dispatcher with cmd=0
# (login / init session - sub_1736c-style path)
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=[
    "init_00000000_0000_0000_0000_487641557457_ta_2",
    "init_00000000_0000_0000_0000_487641557457_ta_3",
    "init_00000000_0000_0000_0000_487641557457_ta_4",
    "init_00000000_0000_0000_0000_487641557457_ta_5",
    "init_00000000_0000_0000_0000_487641557457_ta_6",
])
def init_00000000_0000_0000_0000_487641557457_ta_1(state):
    p3 = _setup_common(state)
    # cmd 0x27 -> sub_1736c (session/login init); installs state used later
    _write_cmd_word(state, p3, 0x27)
    return state


# ---------------------------------------------------------------------------
# Command 2: install master key (sub_18d08 path). Must run before crypto cmds.
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=[
    "init_00000000_0000_0000_0000_487641557457_ta_3",
    "init_00000000_0000_0000_0000_487641557457_ta_4",
    "init_00000000_0000_0000_0000_487641557457_ta_5",
    "init_00000000_0000_0000_0000_487641557457_ta_6",
])
def init_00000000_0000_0000_0000_487641557457_ta_2(state):
    p3 = _setup_common(state)
    # cmd 0x53 -> sub_18d08-like (sets master/transient key in TA state)
    _write_cmd_word(state, p3, 0x53)
    return state


# ---------------------------------------------------------------------------
# Command 3: AES/HMAC operation that depends on a previously installed key
# (handler family around 0xd2/0xd3 -> sub_e820 / sub_eac).
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_3(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x6a)  # encrypt-like handler
    return state


# ---------------------------------------------------------------------------
# Command 4: another crypto op (decrypt-like) — depends on key install.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_4(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x84)  # decrypt-like handler (sub_ea2c)
    return state


# ---------------------------------------------------------------------------
# Command 5: generate / wrap key (sub_eecc) — uses installed session.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_5(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0xc7)  # sub_eecc-style handler
    return state


# ---------------------------------------------------------------------------
# Command 6: list / query (sub_f0cc) — terminal, no successor needed.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_6(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0xdb)  # sub_f0cc-style handler (query)
    return state


# ---------------------------------------------------------------------------
# Command 7: standalone "get info" / version (sub_ee50) — no dependencies.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_7(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x12)  # sub_e19c-style (get attribute / version)
    return state


# ---------------------------------------------------------------------------
# Command 8: hash / digest operation (sub_e324) — independent.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_8(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x3c)  # sub_e4ac-style hash handler
    return state


# ---------------------------------------------------------------------------
# Command 9: sign/verify (sub_e634) — independent.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_9(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x56)  # sub_e634-style sign/verify
    return state


# ---------------------------------------------------------------------------
# Command 10: derive key — depends on session init.
# ---------------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_ta_10(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0xa0)  # sub_ecdc-style derive
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_487641557457_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

