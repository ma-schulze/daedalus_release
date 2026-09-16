import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# InvokeCommandEntryPoint at 0x5893e4:
#   if r2 == 7        -> read r1 from [r3] (i.e. from p3 slot0 ptr) -> dispatch sub_584a04
#   if r2 == 0x3333   -> dispatch sub_584a04 with r1 = r3 (...)
#   else error
#
# sub_584a04 / sub_58278c: switch on (cmd - 0xC8). Valid cmds: 0xC8 .. 0xC8+0x36 = 0xFE.
# So commands range from 0xC8 to 0xFE. We emit one init per command, using param_types=7
# (MEMREF_INOUT in slot 0) which is the common path that loads r1 from [r3].

TA_NAME = "edcf9395"

def _common_setup(state, cmd_id):
    p3 = init_params(state)
    state.regs.r2 = 7  # TEE_PARAM_TYPE_MEMREF_INOUT in slot 0
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    # The TA reads command id from [r3] when r2==7. Override slot 0's first word
    # to the concrete command id.
    p3_val = state.solver.eval(p3)
    state.memory.store(p3_val, claripy.BVV(cmd_id, 32), endness=state.arch.memory_endness)
    state.regs.r1 = cmd_id
    return state


@ta_init_function
def init_edcf9395_0(state):
    return _common_setup(state, 0xC8)

@ta_init_function
def init_edcf9395_1(state):
    return _common_setup(state, 0xC9)

@ta_init_function
def init_edcf9395_2(state):
    return _common_setup(state, 0xCA)

@ta_init_function
def init_edcf9395_3(state):
    return _common_setup(state, 0xCB)

@ta_init_function
def init_edcf9395_4(state):
    return _common_setup(state, 0xCC)

@ta_init_function
def init_edcf9395_5(state):
    return _common_setup(state, 0xCD)

@ta_init_function
def init_edcf9395_6(state):
    return _common_setup(state, 0xCE)

@ta_init_function
def init_edcf9395_7(state):
    return _common_setup(state, 0xCF)

@ta_init_function
def init_edcf9395_8(state):
    return _common_setup(state, 0xD0)

@ta_init_function
def init_edcf9395_9(state):
    return _common_setup(state, 0xD1)

@ta_init_function
def init_edcf9395_10(state):
    return _common_setup(state, 0xD2)

@ta_init_function
def init_edcf9395_11(state):
    return _common_setup(state, 0xD3)

@ta_init_function
def init_edcf9395_12(state):
    return _common_setup(state, 0xD4)

@ta_init_function
def init_edcf9395_13(state):
    return _common_setup(state, 0xD5)

@ta_init_function
def init_edcf9395_14(state):
    return _common_setup(state, 0xD6)

@ta_init_function
def init_edcf9395_15(state):
    return _common_setup(state, 0xD7)

@ta_init_function
def init_edcf9395_16(state):
    return _common_setup(state, 0xD8)

@ta_init_function
def init_edcf9395_17(state):
    return _common_setup(state, 0xD9)

@ta_init_function
def init_edcf9395_18(state):
    return _common_setup(state, 0xDA)

@ta_init_function
def init_edcf9395_19(state):
    return _common_setup(state, 0xDB)

@ta_init_function
def init_edcf9395_20(state):
    return _common_setup(state, 0xDC)

@ta_init_function
def init_edcf9395_21(state):
    return _common_setup(state, 0xDD)

@ta_init_function
def init_edcf9395_22(state):
    return _common_setup(state, 0xDE)

@ta_init_function
def init_edcf9395_23(state):
    return _common_setup(state, 0xDF)

@ta_init_function
def init_edcf9395_24(state):
    return _common_setup(state, 0xE0)

@ta_init_function
def init_edcf9395_25(state):
    return _common_setup(state, 0xE1)

@ta_init_function
def init_edcf9395_26(state):
    return _common_setup(state, 0xE2)

@ta_init_function
def init_edcf9395_27(state):
    return _common_setup(state, 0xE3)

@ta_init_function
def init_edcf9395_28(state):
    return _common_setup(state, 0xE4)

@ta_init_function
def init_edcf9395_29(state):
    return _common_setup(state, 0xE5)

@ta_init_function
def init_edcf9395_30(state):
    return _common_setup(state, 0xE6)

@ta_init_function
def init_edcf9395_31(state):
    return _common_setup(state, 0xE7)

@ta_init_function
def init_edcf9395_32(state):
    return _common_setup(state, 0xE8)

@ta_init_function
def init_edcf9395_33(state):
    return _common_setup(state, 0xE9)

@ta_init_function
def init_edcf9395_34(state):
    return _common_setup(state, 0xEA)

@ta_init_function
def init_edcf9395_35(state):
    return _common_setup(state, 0xEB)

@ta_init_function
def init_edcf9395_36(state):
    return _common_setup(state, 0xEC)

@ta_init_function
def init_edcf9395_37(state):
    return _common_setup(state, 0xED)

@ta_init_function
def init_edcf9395_38(state):
    return _common_setup(state, 0xEE)

@ta_init_function
def init_edcf9395_39(state):
    return _common_setup(state, 0xEF)

@ta_init_function
def init_edcf9395_40(state):
    return _common_setup(state, 0xF0)

@ta_init_function
def init_edcf9395_41(state):
    return _common_setup(state, 0xF1)

@ta_init_function
def init_edcf9395_42(state):
    return _common_setup(state, 0xF2)

@ta_init_function
def init_edcf9395_43(state):
    return _common_setup(state, 0xF3)

@ta_init_function
def init_edcf9395_44(state):
    return _common_setup(state, 0xF4)

@ta_init_function
def init_edcf9395_45(state):
    return _common_setup(state, 0xF5)

@ta_init_function
def init_edcf9395_46(state):
    return _common_setup(state, 0xF6)

@ta_init_function
def init_edcf9395_47(state):
    return _common_setup(state, 0xF7)

@ta_init_function
def init_edcf9395_48(state):
    return _common_setup(state, 0xF8)

@ta_init_function
def init_edcf9395_49(state):
    return _common_setup(state, 0xF9)

@ta_init_function
def init_edcf9395_50(state):
    return _common_setup(state, 0xFA)

@ta_init_function
def init_edcf9395_51(state):
    return _common_setup(state, 0xFB)

@ta_init_function
def init_edcf9395_52(state):
    return _common_setup(state, 0xFC)

@ta_init_function
def init_edcf9395_53(state):
    return _common_setup(state, 0xFD)

@ta_init_function
def init_edcf9395_54(state):
    return _common_setup(state, 0xFE)

# Alt path: r2 == 0x3333 dispatches with r1=r3 (some "all-3" param mask form).
@ta_init_function
def init_edcf9395_55(state):
    p3 = init_params(state)
    state.regs.r2 = 0x3333  # VALUE_INOUT in all 4 slots
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    # r1 is the command id directly; constrain to a valid range to avoid explosion
    state.regs.r1 = 0xC8
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_edcf9395_3518_9067_614cafae2909775b_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

