import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA analysis notes:
# - entry checks w2 == 0x65 -> param_types mask = MEMREF_INPUT (slot0=5), MEMREF_OUTPUT (slot1=6)
# - r1/w1 is command id (w19). cmp w19, #4 -> dispatch via jump table for cmd ids 0..4
# - The TA appears to be a TLS/handshake-like flow with stateful steps.
#   Commands 0..4 map to different sub-handlers (sub_3fee0 client hello, sub_402a8 server response,
#   plus complex flows at 0x3c81c, 0x3c9dc, 0x3cac8).
# - Provide one init per command id (0..4) to cover all dispatch paths.


@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x65  # MEMREF_INPUT | MEMREF_OUTPUT<<4
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_2(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_4(state):
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_14b0aad8_c011_4a3f_b66aca8d0e66f273_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

