import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA_InvokeCommandEntryPoint at 0x2f4 loads a function pointer from
# global data at 0x19000+0x180 and jumps to __ta_invoke_cmd (0x23ec), which
# converts GP params (from_gp11_param) and then calls the loaded handler
# via blr x23. The handler itself is not visible in this snippet, so we
# cannot enumerate concrete command IDs. We therefore emit a set of
# generic init functions covering common GP parameter type masks and
# leave the command ID (w1) symbolic or set to small concrete values so
# that the analysis can explore the dispatch inside the handler.


@ta_init_function
def init_ta_0(state):
    # Fully symbolic: command id and param types symbolic, four value params
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_ta_1(state):
    # param_types = 0 (all NONE), cmd id 0
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x0
    return state


@ta_init_function
def init_ta_2(state):
    # param_types = 0x01 -> slot0 VALUE_INPUT
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_ta_3(state):
    # param_types = 0x05 -> slot0 MEMREF_INPUT
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_ta_4(state):
    # param_types = 0x07 -> slot0 MEMREF_INOUT
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_ta_5(state):
    # param_types = 0x11 -> slot0 VALUE_INPUT, slot1 VALUE_INPUT
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x11
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_6(state):
    # param_types = 0x65 -> slot0 MEMREF_INPUT, slot1 MEMREF_OUTPUT
    p3 = init_params(state)
    state.regs.x1 = 0x5
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_7(state):
    # param_types = 0x77 -> slot0 MEMREF_INOUT, slot1 MEMREF_INOUT
    p3 = init_params(state)
    state.regs.x1 = 0x6
    state.regs.x2 = 0x77
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_8(state):
    # param_types = 0x61 -> slot0 VALUE_INPUT, slot1 MEMREF_OUTPUT
    p3 = init_params(state)
    state.regs.x1 = 0x7
    state.regs.x2 = 0x61
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state
