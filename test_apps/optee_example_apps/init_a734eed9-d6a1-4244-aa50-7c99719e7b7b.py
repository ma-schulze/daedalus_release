import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target


# The disassembly shows a GP wrapper that calls the real InvokeCommand handler via blr x23.
# The actual command dispatch happens inside that callee, which is not shown.
# We provide generic inits covering common param-type masks and a symbolic-mask variant.

@ta_init_function
def init_a734eed9_0(state):
    # All four slots as symbolic value params, keep x2 symbolic
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_a734eed9_1(state):
    # Single MEMREF_INOUT in slot 0
    p3 = init_params(state)
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_a734eed9_2(state):
    # MEMREF_INPUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_a734eed9_3(state):
    # VALUE_INPUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x61
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_a734eed9_4(state):
    # Single VALUE_INPUT slot0
    p3 = init_params(state)
    state.regs.x2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_a734eed9_5(state):
    # MEMREF_INOUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state
