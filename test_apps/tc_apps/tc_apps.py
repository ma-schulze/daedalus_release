import angr
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params

def tc_init_function(state: angr.SimState):
    p3 = init_params(state)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state

