import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA_InvokeCommandEntryPoint at 0x6b20 immediately checks the stack canary
# and returns 0 without dispatching on any command ID or parameter types.
# There is effectively only one trivial path. We provide a single init.

@ta_init_function
def init_TitanLl_0(state):
    p3 = init_params(state)
    # No command dispatch observed; set up generic params for coverage.
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_544974684c6c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

