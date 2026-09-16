import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA_InvokeCommandEntryPoint at 0xbc68 is essentially a stub:
# it just compares a stack canary and returns 0. There is no command
# dispatch, no use of r1/x1, r2/x2, or r3/x3. Only one trivial path exists.

@ta_init_function
def init_TIdspl_0(state):
    p3 = init_params(state)
    # No command ID checked; no params consumed. Provide minimal symbolic setup.
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_54496473706c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

