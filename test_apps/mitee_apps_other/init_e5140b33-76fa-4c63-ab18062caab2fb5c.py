import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis summary:
# This TA dispatches based on r2/x2 == 0x65, with p3 memref sizes checked:
#   - p3[1].size == 0x40c
#   - p3[3].size == 0x408
# It then reads a sub-command word from p3[0].buffer[0] (must be == 1),
# then reads x19 (the command ID from x1) and dispatches.
#
# Command ID groups (w19):
#   - 0x100..0x103 (jump table): key generation / similar
#       0x100 -> sub_1edb8 path (generate keypair)
#       0x101 -> sub_1fbc0 with arg 0  (sign-like, no key)
#       0x102 -> sub_1fbc0 with arg 1  (sign-like)
#       0x103 -> sub_1ffd0 path
#   - 0x200 -> erase/close (sub_202a8 with str wzr,[x21] success)
#   - 0x300 -> compute/decrypt (sub_1f540 / sub_1fa98)
#   - 0x301 -> verify/sign (depends on x20[0x18])
#   - 0x400 -> generic dispatch via sub_20750
#
# Dependencies: 0x200/0x300/0x301 work on a previously-generated key (slot in x20),
# so they should follow a 0x100 (key generation) call. 0x400 likely independent.


def _common_setup(state):
    """Common setup: r2/x2 mask = 0x65, p3[1] memref size 0x40c, p3[3] memref size 0x408,
    p3[0] memref with first word == 1 (sub-command gate)."""
    p3 = init_params(state)
    # Set param type mask. The TA checks w20 == 0x65 directly (non-GP-compliant),
    # so just set x2 to that constant.
    state.regs.x2 = 0x65

    # Slot 0: memref pointing to buffer; first 32-bit word must equal 1
    place_sym_memref_param(state, p3, 0)
    # Slot 1: memref, size must be 0x40c
    place_sym_memref_param(state, p3, 1)
    # Slot 3: memref, size must be 0x408
    place_sym_memref_param(state, p3, 3)

    # Force concrete sizes for slot 1 and slot 3
    # Layout: p3 + i*16 = ptr, p3 + i*16 + 8 = size  (64-bit)
    word = 8
    # slot1 size at p3 + 1*16 + 8 = p3 + 24
    state.memory.store(p3 + 1 * 2 * word + word,
                       claripy.BVV(0x40c, 64), endness=state.arch.memory_endness)
    # slot3 size at p3 + 3*16 + 8 = p3 + 56
    state.memory.store(p3 + 3 * 2 * word + word,
                       claripy.BVV(0x408, 64), endness=state.arch.memory_endness)

    # First dword of p3[0].buffer must be 1 (sub-command gate at 0x1e174)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(ptr0, claripy.BVV(1, 32), endness=state.arch.memory_endness)

    return p3


# ---- Command 0x100: key generation (key-init / generate) ----
# This populates internal state and is a prerequisite for later commands.
@ta_init_function(next_funcs=[
    "init_e5140b33_4",  # 0x200 erase (uses key)
    "init_e5140b33_5",  # 0x300 decrypt (uses key)
    "init_e5140b33_6",  # 0x301 sign/verify (uses key)
])
def init_e5140b33_0(state):
    _common_setup(state)
    state.regs.x1 = 0x100
    return state


# ---- Command 0x101: sub_1fbc0 with arg 0 ----
@ta_init_function
def init_e5140b33_1(state):
    _common_setup(state)
    state.regs.x1 = 0x101
    return state


# ---- Command 0x102: sub_1fbc0 with arg 1 ----
@ta_init_function
def init_e5140b33_2(state):
    _common_setup(state)
    state.regs.x1 = 0x102
    return state


# ---- Command 0x103: sub_1ffd0 ----
@ta_init_function
def init_e5140b33_3(state):
    _common_setup(state)
    state.regs.x1 = 0x103
    return state


# ---- Command 0x200: requires a previously-loaded key (chain target) ----
@ta_init_function
def init_e5140b33_4(state):
    _common_setup(state)
    state.regs.x1 = 0x200
    return state


# ---- Command 0x300: requires a previously-loaded key (chain target) ----
@ta_init_function
def init_e5140b33_5(state):
    _common_setup(state)
    state.regs.x1 = 0x300
    return state


# ---- Command 0x301: requires a previously-loaded key (chain target) ----
@ta_init_function
def init_e5140b33_6(state):
    _common_setup(state)
    state.regs.x1 = 0x301
    # The TA reads x20[0x18] and compares to 1; let it remain symbolic but
    # we can leave the buffer symbolic so both branches are explored.
    return state


# ---- Command 0x400: generic dispatch via sub_20750 (independent) ----
@ta_init_function
def init_e5140b33_7(state):
    _common_setup(state)
    state.regs.x1 = 0x400
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_e5140b33_76fa_4c63_ab18062caab2fb5c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

