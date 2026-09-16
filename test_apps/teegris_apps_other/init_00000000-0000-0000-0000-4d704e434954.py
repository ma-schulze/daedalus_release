import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# TA analysis notes:
# TA_InvokeCommandEntryPoint at 0x18df0
# - r2/x2 (param_types) is compared with #0x67 at 0x18e70 (one path) - that path
#   allocates 0x14 bytes and calls TEE_GetPropertyAsIdentity. Otherwise the TA
#   falls through to read p3[0] (memref), checks word at *p3[0] == 0xF0000000,
#   then dispatches further on sizes/content.
#
# Main path (param_types != 0x67): expects:
#   - p3 slot 0: memref pointer (buffer A), buffer first word == 0xF0000000
#   - p3 slot 1: memref pointer (buffer B)
#   - either sizes 0x3D74 / 0x3D74 (full path -> sub_18af0), or sizes 0x840 / 0x840
#     after REEsharedmemory check (=> the larger crypto path through sub_fb64).
#
# We emit distinct init functions for the observable command paths:
#  0: param_types == 0x67  -> early property-identity path
#  1: header path with sizes 0x3D74 / 0x3D74 -> sub_18af0
#  2: header path with sizes 0x840  / 0x840  -> sub_fb64 dispatcher (sub-cmd in *(p3+0x10))
#       sub_fb64 then dispatches on w0 (command id from r1/x1) in range 0x300..0x307.
#       We expose each sub-command as its own init using r1 = 0x300..0x307.


def _common_header_setup(state, sizeA, sizeB):
    """Set up p3 with two memref params whose sizes are forced concrete to sizeA/sizeB.
    Pre-populate the first word of buffer A with 0xF0000000 to pass the magic check."""
    p3 = init_params(state)
    # param_types mask: slot0 = MEMREF_INOUT (7), slot1 = MEMREF_INOUT (7) -> 0x77
    # The TA only checks that ptr/size pairs are non-zero and sizes match constants.
    state.regs.x2 = 0x77
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    word = 8  # AArch64
    # Slot 0: ptr at p3+0, size at p3+8
    bufA_ptr = state.memory.load(p3 + 0, word, endness=state.arch.memory_endness)
    bufB_ptr = state.memory.load(p3 + 2 * word, word, endness=state.arch.memory_endness)

    # Force sizes to concrete expected values
    state.memory.store(p3 + word, claripy.BVV(sizeA, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * word, claripy.BVV(sizeB, 64), endness=state.arch.memory_endness)

    # Put the magic header 0xF0000000 at *bufA so the TA proceeds past 0x18f14.
    state.memory.store(bufA_ptr, claripy.BVV(0xF0000000, 32), endness=state.arch.memory_endness)
    return p3, bufA_ptr, bufB_ptr


# -------------------------------------------------------------------
# Path 0: param_types == 0x67 -> early TEE_GetPropertyAsIdentity branch
# -------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x67
    # p3 may still be read at offset 0 for x3 dereferences after malloc; leave symbolic.
    return state


# -------------------------------------------------------------------
# Path 1: header path, sizes 0x3D74 / 0x3D74 -> sub_18af0 (logging/info path)
# -------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_1(state):
    _common_header_setup(state, 0x3D74, 0x3D74)
    state.regs.x1 = 0x0  # cmd id forwarded to sub_18af0 (only logged)
    return state


# -------------------------------------------------------------------
# Path 2: header path, sizes 0x840 / 0x840 -> sub_fb64 dispatcher.
# Sub-command is in x1 (w0 at sub_fb64). Valid range: 0x300..0x307.
# Each sub-command exposes a distinct crypto/key operation.
# -------------------------------------------------------------------
@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_2(state):
    # sub_fb64 case 0x300: generate/store key (cbz w0,#0x10144 path after sub_1aa80)
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x300
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_3(state):
    # sub_fb64 case 0x301
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x301
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_4(state):
    # sub_fb64 case 0x302
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x302
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_5(state):
    # sub_fb64 case 0x303
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x303
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_6(state):
    # sub_fb64 case 0x304
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x304
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_7(state):
    # sub_fb64 case 0x305
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x305
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_8(state):
    # sub_fb64 case 0x306
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x306
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_ta_9(state):
    # sub_fb64 case 0x307
    _common_header_setup(state, 0x840, 0x840)
    state.regs.x1 = 0x307
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4d704e434954_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

