import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The disassembly shows a generic GP wrapper (__ta_invoke_cmd) that dispatches to the
# actual TA_InvokeCommandEntryPoint via a function pointer at [x21+0x130]->x23.
# The real command handler body is not visible in the provided disassembly, so we
# emit a set of exploratory init functions covering common command IDs and GP
# parameter-type masks. This maximizes coverage across possible command paths.


@ta_init_function
def init_f066f150_0(state):
    # Command 0, all NONE params, symbolic param_types (x2) to explore
    p3 = init_params(state)
    state.regs.x1 = 0x0
    return state


@ta_init_function
def init_f066f150_1(state):
    # Command 0 with a single MEMREF_INOUT (0x7)
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_f066f150_2(state):
    # Command 1 with VALUE_INPUT in slot0
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_f066f150_3(state):
    # Command 1 with MEMREF_INPUT slot0 + MEMREF_OUTPUT slot1 (mask 0x65)
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_f066f150_4(state):
    # Command 2 with VALUE_INOUT slot0
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x3
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_f066f150_5(state):
    # Command 2 with MEMREF_INOUT slot0 + MEMREF_OUTPUT slot1
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_f066f150_6(state):
    # Command 3 with MEMREF_OUTPUT slot0
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x6
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_f066f150_7(state):
    # Command 4 with four value params
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x1111
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_f066f150_8(state):
    # Command 5 with mixed memrefs
    p3 = init_params(state)
    state.regs.x1 = 0x5
    state.regs.x2 = 0x5566
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state


@ta_init_function
def init_f066f150_9(state):
    # Fully symbolic x2 (param_types) with four symbolic value params;
    # lets the solver explore any mask the TA checks.
    p3 = init_params(state)
    state.regs.x1 = 0x0
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
