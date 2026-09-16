import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA_InvokeCommandEntryPoint here is essentially a stub: it sets up a stack
# canary, immediately returns 0, and does not dispatch on command ID or params.
# There is only one semantic path; emit a single init.

@ta_init_function
def init_00000000_0000_0000_0000_000000020081_ta_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_000000020081_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

