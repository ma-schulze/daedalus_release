import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# The disassembly only shows the wrapper __ta_invoke_cmd that copies params
# and calls the actual invoke function via blr x23. Without visibility into
# the real command dispatcher, we provide generic inits covering typical
# GP parameter type masks plus a symbolic-mask fallback.

@ta_init_function
def init_f4e750bb_0(state):
    # Symbolic command ID and symbolic param types (fallback broad exploration)
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

@ta_init_function
def init_f4e750bb_1(state):
    # All four VALUE_INPUT
    p3 = init_params(state)
    state.regs.x2 = 0x1111
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

@ta_init_function
def init_f4e750bb_2(state):
    # MEMREF_INPUT slot0
    p3 = init_params(state)
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_f4e750bb_3(state):
    # MEMREF_OUTPUT slot0
    p3 = init_params(state)
    state.regs.x2 = 0x6
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_f4e750bb_4(state):
    # MEMREF_INOUT slot0
    p3 = init_params(state)
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_f4e750bb_5(state):
    # VALUE_INPUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x61
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_f4e750bb_6(state):
    # MEMREF_INPUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_f4e750bb_7(state):
    # MEMREF_INOUT slot0, MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_f4e750bb_8(state):
    # Command 0 with mixed params
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_f4e750bb_9(state):
    # Command 1
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_f4e750bb_10(state):
    # Command 2
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state
