import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target


# The visible code only shows the dispatcher trampoline that calls the actual
# invoke handler via a function pointer. Without visibility into the concrete
# command handler, we emit generic inits covering common command IDs and
# parameter type layouts.


@ta_init_function
def init_1945e8e7_0(state):
    # Fully symbolic parameter types (x2), symbolic value params in all slots
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_1945e8e7_1(state):
    # Command 0 with a single MEMREF_INOUT parameter (types = 7)
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_1945e8e7_2(state):
    # Command 1 with VALUE_INPUT in slot 0 (types = 1)
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_1945e8e7_3(state):
    # Command 2 with MEMREF_INPUT + MEMREF_OUTPUT (types = 0x65)
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_1945e8e7_4(state):
    # Command 3 with VALUE_INPUT + MEMREF_OUTPUT (types = 0x61)
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x61
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_1945e8e7_5(state):
    # Command 4 with MEMREF_INOUT + MEMREF_OUTPUT (types = 0x67)
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_1945e8e7_6(state):
    # Command 5 with four VALUE_INPUT slots (types = 0x1111)
    p3 = init_params(state)
    state.regs.x1 = 0x5
    state.regs.x2 = 0x1111
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
