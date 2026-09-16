import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# TA dispatch summary (from 0x88ff: tbh [pc, r4, lsl #1] using r4 = cmd_id - 1):
# Required params: r2 == 7 (MEMREF_INOUT in slot0), p3[0].size must be 0x48 (72 bytes).
# Command IDs (cmd = r1; r4 = cmd-1 used as table index, valid 0..0xFE).
# Each case branches to handler at 0x8b01..0x8cc9.
# We emit one init per observed jump table target (cmd_ids 1..30 cover the visible handlers).

TA = "08030000000000000000000000000000"

def _common_setup(state, cmd_id):
    p3 = init_params(state)
    # r2 must equal 7: MEMREF_INOUT in slot 0
    state.regs.r2 = 7
    # set up memref param 0 with size 0x48
    place_sym_memref_param(state, p3, 0)
    # The TA reads p3[0].ptr and p3[0].size, and requires size == 0x48.
    # place_sym_memref_param has set ptr + symbolic size; overwrite size to 0x48 concretely.
    # p3 slot 0: ptr at p3+0, size at p3+4 (ARM32 word=4).
    state.memory.store(p3 + 4, claripy.BVV(0x48, 32), endness=state.arch.memory_endness)
    # command id in r1
    state.regs.r1 = cmd_id
    return state

@ta_init_function
def init_08030000000000000000000000000000_0(state):
    return _common_setup(state, 1)

@ta_init_function
def init_08030000000000000000000000000000_1(state):
    return _common_setup(state, 2)

@ta_init_function
def init_08030000000000000000000000000000_2(state):
    return _common_setup(state, 3)

@ta_init_function
def init_08030000000000000000000000000000_3(state):
    return _common_setup(state, 4)

@ta_init_function
def init_08030000000000000000000000000000_4(state):
    return _common_setup(state, 5)

@ta_init_function
def init_08030000000000000000000000000000_5(state):
    return _common_setup(state, 6)

@ta_init_function
def init_08030000000000000000000000000000_6(state):
    return _common_setup(state, 7)

@ta_init_function
def init_08030000000000000000000000000000_7(state):
    return _common_setup(state, 8)

@ta_init_function
def init_08030000000000000000000000000000_8(state):
    return _common_setup(state, 9)

@ta_init_function
def init_08030000000000000000000000000000_9(state):
    return _common_setup(state, 10)

@ta_init_function
def init_08030000000000000000000000000000_10(state):
    return _common_setup(state, 11)

@ta_init_function
def init_08030000000000000000000000000000_11(state):
    return _common_setup(state, 12)

@ta_init_function
def init_08030000000000000000000000000000_12(state):
    return _common_setup(state, 13)

@ta_init_function
def init_08030000000000000000000000000000_13(state):
    return _common_setup(state, 14)

@ta_init_function
def init_08030000000000000000000000000000_14(state):
    return _common_setup(state, 15)

@ta_init_function
def init_08030000000000000000000000000000_15(state):
    return _common_setup(state, 16)

@ta_init_function
def init_08030000000000000000000000000000_16(state):
    return _common_setup(state, 17)

@ta_init_function
def init_08030000000000000000000000000000_17(state):
    return _common_setup(state, 18)

@ta_init_function
def init_08030000000000000000000000000000_18(state):
    return _common_setup(state, 19)

@ta_init_function
def init_08030000000000000000000000000000_19(state):
    return _common_setup(state, 20)

@ta_init_function
def init_08030000000000000000000000000000_20(state):
    return _common_setup(state, 21)

@ta_init_function
def init_08030000000000000000000000000000_21(state):
    return _common_setup(state, 22)

@ta_init_function
def init_08030000000000000000000000000000_22(state):
    return _common_setup(state, 23)

@ta_init_function
def init_08030000000000000000000000000000_23(state):
    return _common_setup(state, 24)

@ta_init_function
def init_08030000000000000000000000000000_24(state):
    return _common_setup(state, 25)

@ta_init_function
def init_08030000000000000000000000000000_25(state):
    return _common_setup(state, 26)

@ta_init_function
def init_08030000000000000000000000000000_26(state):
    return _common_setup(state, 27)

@ta_init_function
def init_08030000000000000000000000000000_27(state):
    return _common_setup(state, 28)

@ta_init_function
def init_08030000000000000000000000000000_28(state):
    return _common_setup(state, 29)

@ta_init_function
def init_08030000000000000000000000000000_29(state):
    return _common_setup(state, 30)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_08030000000000000000000000000000_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

