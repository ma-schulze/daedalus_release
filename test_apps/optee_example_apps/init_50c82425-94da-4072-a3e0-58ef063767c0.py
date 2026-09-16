import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# The TA_InvokeCommandEntryPoint is a thin wrapper that calls a function pointer
# loaded from [x21, #0x180] (the actual command handler). Since we don't have
# the concrete handler disassembly, we set up generic invocations covering
# common param type masks and command IDs. We keep command ID symbolic in one
# init and provide concrete variants for typical MEMREF/VALUE combos.


@ta_init_function
def init_ta_0(state):
    # All-symbolic entry: command ID and param types stay symbolic
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_ta_1(state):
    # cmd 0, single MEMREF_INOUT slot0
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0, 32)
    state.regs.x2 = claripy.BVV(0x00000007, 32)
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_ta_2(state):
    # cmd 1, MEMREF_INPUT slot0 + MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(1, 32)
    state.regs.x2 = claripy.BVV(0x00000065, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_3(state):
    # cmd 2, VALUE_INPUT slot0
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(2, 32)
    state.regs.x2 = claripy.BVV(0x00000001, 32)
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_ta_4(state):
    # cmd 3, VALUE_INPUT slot0 + MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(3, 32)
    state.regs.x2 = claripy.BVV(0x00000061, 32)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_5(state):
    # cmd 4, MEMREF_INOUT slot0 + MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(4, 32)
    state.regs.x2 = claripy.BVV(0x00000067, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_ta_6(state):
    # cmd 5 with all-value params
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(5, 32)
    state.regs.x2 = claripy.BVV(0x00001111, 32)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
