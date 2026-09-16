import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA dispatches through an indirect call (blr x23) to a handler function pointer
# loaded from a global at 0x19180. Without visibility into the actual command handler,
# we generate multiple init functions covering common command IDs and parameter type
# combinations, plus one with fully symbolic x2.

@ta_init_function
def init_ta_0(state):
    # Command 0, all four value params, symbolic param types
    p3 = init_params(state)
    state.regs.x1 = 0x0
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

@ta_init_function
def init_ta_1(state):
    # Command 0 with a single memref input
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_ta_2(state):
    # Command 1 with memref inout
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_ta_3(state):
    # Command 1 with value input
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state

@ta_init_function
def init_ta_4(state):
    # Command 2 with memref input + memref output
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_ta_5(state):
    # Command 3 with value input + memref output
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x61
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_ta_6(state):
    # Command 4 with memref inout + memref output
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_ta_7(state):
    # Command 5 with two value inputs
    p3 = init_params(state)
    state.regs.x1 = 0x5
    state.regs.x2 = 0x11
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    return state

@ta_init_function
def init_ta_8(state):
    # Symbolic command id and symbolic param types with all four symbolic value params
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
