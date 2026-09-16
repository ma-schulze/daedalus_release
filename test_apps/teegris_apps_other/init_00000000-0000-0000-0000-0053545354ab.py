import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis summary:
# TA_InvokeCommandEntryPoint at 0x5c24 dispatches based on w2 (param_types).
# - If w2 == 0x67 (cmd id-ish check via snprintf, then cmp at 0x5d14): allocates 0x14 bytes,
#   calls TEE_GetPropertyAsIdentity, and then checks param 3 (p3).
# - Otherwise: falls through to error path.
#
# When w2==0x67, code reads from p3 (x20):
#   x1 = *(p3+0)         -> buf ptr (param 0 buffer)
#   *(int*)x19 (first 4B of malloc'd buf) is compared with 0xF0000000 (-0x10000000)
#       at 0x5dfc..0x5e00 -> determines branch:
#       * eq -> "binary" path: requires x20[0]!=0, x20[0x10]!=0, x20[8]==0x1020, x20[0x18]==0x1020
#         then memcpys, calls sub_5a78 (handler taking sub-cmd from offset +4 of the allocated buf -
#         the sub-cmd is at x19+0 which equals 0xF0000000, but sub_5a78 receives w0=w21 (the TA command id w1),
#         and additional params. Calls TEE_MemMove between p3 memref buffers.
#       * ne -> "json" path at 0x5ee8: requires sizes match constraints, calls TEES_IsREESharedMemory,
#         then sub_5924 which dispatches on (w0-2) being in [0,5] (so w21 in [2..7]):
#         0: sub_a8f8 (key gen?) 1: sub_6894 2: sub_c4c0 3: sub_ce1c 4: sub_6378 5: sub_a008
#
# The dispatch is by w21 (TA cmd id from x1). Different subcommands -> separate inits.
#
# So commands are governed by:
#   w2 (param_types) must be 0x67 to proceed
#   p3 layout: slot0 memref (buffer pointer with magic/size), slot1 memref (output), slot2 value? slot3?
#   x1 (w21): TA command ID 2..7 for json path; for binary path, also w21 used as parameter
#
# We'll generate inits for each command id 2..7 (json path), plus the binary path variant.


def _setup_common_p3(state, p3):
    # Setup memref params at slot 0 and slot 1 (input/output buffers)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)


@ta_init_function
def init_0000000000000000000053545354ab_0(state):
    # JSON path, sub-cmd 2 -> sub_a8f8 (algorithm-related)
    p3 = init_params(state)
    state.regs.x1 = 2
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_1(state):
    # JSON path, sub-cmd 3 -> sub_6894
    p3 = init_params(state)
    state.regs.x1 = 3
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_2(state):
    # JSON path, sub-cmd 4 -> sub_c4c0
    p3 = init_params(state)
    state.regs.x1 = 4
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_3(state):
    # JSON path, sub-cmd 5 -> sub_ce1c
    p3 = init_params(state)
    state.regs.x1 = 5
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_4(state):
    # JSON path, sub-cmd 6 -> sub_6378
    p3 = init_params(state)
    state.regs.x1 = 6
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_5(state):
    # JSON path, sub-cmd 7 -> sub_a008
    p3 = init_params(state)
    state.regs.x1 = 7
    state.regs.x2 = 0x67
    _setup_common_p3(state, p3)
    return state


@ta_init_function
def init_0000000000000000000053545354ab_6(state):
    # Error/default path: w2 != 0x67
    p3 = init_params(state)
    state.regs.x1 = 1
    state.regs.x2 = 0x00  # not 0x67 -> hits default error branch
    _setup_common_p3(state, p3)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_0053545354ab_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

