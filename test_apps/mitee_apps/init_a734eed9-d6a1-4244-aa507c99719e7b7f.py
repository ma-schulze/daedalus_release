import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis:
# At 0xee024: cmp w2, #0x537 -> expected param types mask = 0x537
# At 0xee058: loads p3[0] (x1) and p3[8] (w2) then calls sub_757a48 with w0=7
# At 0xee0a4: cmp w20, #1<<12 (0x1000) -> command ID comparison against 0x1000
#   If w1 == 0x1000 -> path A (writes 0xbc at p3+8, calls sub_757ac0)
#   else           -> path B (calls sub_dd030 with p3[0], p3[8])
# p3 slot 0 appears to be used as a memref (ptr at p3[0], size at p3[8])
# No obvious stateful dependencies between the two paths.

@ta_init_function
def init_mitee_cmd_0x1000_0(state):
    # Command ID = 0x1000, param type mask = 0x537
    p3 = init_params(state)
    state.regs.x1 = 0x1000
    state.regs.x2 = 0x537
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_mitee_cmd_other_1(state):
    # Any command ID != 0x1000, param type mask = 0x537
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x537
    place_sym_memref_param(state, p3, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_a734eed9_d6a1_4244_aa507c99719e7b7f_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

