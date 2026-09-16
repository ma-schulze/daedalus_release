import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params


def teegris_init_function(state: angr.SimState):
    p3 = init_params(state)
    state.regs.r1 = claripy.BVV(112, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state


def teegris_init_function_vuln(state: angr.SimState):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    print(f"teegris_init_function_vuln!")
    return state