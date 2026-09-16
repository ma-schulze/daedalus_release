import angr

from utils.logging_config import get_logger
from explorer.hooks.function_hooks.func_hooks import ta_function_hook
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params

logger = get_logger(__name__)

@ta_function_hook("memset", "mitee_14b0", 0x00451f0)
class mitee_memset_symbolic(angr.SimProcedure):
    def run(self, dst, c, n):
        memset = angr.SIM_PROCEDURES["libc"]["memset"]
        self.inline_call(memset, dst, c, n) 
        return 0


def sym_input_14b0(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


def sym_input_377e(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

def sym_input_3d08(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

def sym_input_59a4(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state 

def sym_input_86f6(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

def sym_input_8aaa(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


def sym_input_9811(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


# TODO: has multiple valid inputs?
def sym_input_a734(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state

def sym_input_e97c(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state

def sym_input_f130(state):
    p3 = init_params(state)

    place_sym_memref_param(state, p3, 0)
    return state