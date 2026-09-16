import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis notes:
# At 0x17430: cmp w21 (= w2, param_types), #0x65 -> b.ne 0x17560 (return 0xfffa0006)
#   So param_types must be 0x65 = MEMREF_INPUT (slot0=5) | MEMREF_OUTPUT (slot1=6)
# Then at 0x17484: cmp w20 (= w1, cmd_id), #3 -> b.hi 0x17560
# So cmd IDs are 0..3, dispatched via a jump table at 0x174a8.
# Without table data, generate 4 inits for command IDs 0-3.


@ta_init_function
def init_mitee_ta_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_mitee_ta_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_mitee_ta_2(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_mitee_ta_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_4d573443_6a56_4272_ac6f2425af9ef9bb_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

