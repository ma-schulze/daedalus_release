import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target


# This TA only handles command ID 0x2a (42). Any other command falls through
# to the stack-canary check and returns 0. Only one semantically distinct path.

@ta_init_function
def init_ta_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2a
    # No parameter type checks observed; leave param mask symbolic but params unset.
    return state


@ta_init_function
def init_ta_1(state):
    # Path where command ID is not 0x2a (early return with 0).
    p3 = init_params(state)
    state.regs.x1 = 0x0
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_000000010081_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

