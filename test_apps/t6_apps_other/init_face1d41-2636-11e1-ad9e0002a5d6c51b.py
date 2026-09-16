import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function


# Command dispatch (r1):
#   0 -> requires r2 == 0       -> calls sub_200c4c (iterates over 5 slots, reads from memory)
#   1 -> requires r2 == 0x65    -> calls sub_200ad8 (memref ops via r3/p3)
#   2 -> requires r2 == 0x6555  -> calls sub_20092c (complex op with multiple memrefs)
#   3 -> requires r2 == 0x51    -> calls sub_200788 (store, requires r0(value0)=1..5)
#
# Likely TA semantics: command 0 enumerates/initializes, then 3 stores, 1 loads, 2 computes.
# Use chaining: store (cmd 3) first, then others can act on stored data.


@ta_init_function
def init_face1d41_0(state):
    # Command 0: param_types == 0 (no slots needed). Triggers enumeration path.
    p3 = init_params(state)
    state.regs.r1 = 0x0
    state.regs.r2 = 0x0
    return state


@ta_init_function(next_funcs=["init_face1d41_2", "init_face1d41_3", "init_face1d41_4"])
def init_face1d41_1(state):
    # Command 3 (store): param_types == 0x51 = VALUE_INPUT(1), MEMREF_INPUT(5)
    # slot0: value.a is index (must be 1..5 after sub 1 <= 4 check)
    # slot1: memref data
    p3 = init_params(state)
    state.regs.r1 = 0x3
    state.regs.r2 = 0x51
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Constrain value.a (slot0 value_a at p3+0) to small range to prevent explosion
    word = state.arch.bytes
    va = state.memory.load(p3 + 0, word, endness=state.arch.memory_endness)
    state.solver.add(va >= 1)
    state.solver.add(va <= 5)
    return state


@ta_init_function
def init_face1d41_2(state):
    # Command 1 (load): param_types == 0x65 = MEMREF_INPUT(5), MEMREF_OUTPUT(6)
    p3 = init_params(state)
    state.regs.r1 = 0x1
    state.regs.r2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_face1d41_3(state):
    # Command 2 (op): param_types == 0x6555 = MEMREF_INPUT, MEMREF_INPUT, MEMREF_INPUT, MEMREF_OUTPUT
    p3 = init_params(state)
    state.regs.r1 = 0x2
    state.regs.r2 = 0x6555
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state


@ta_init_function
def init_face1d41_4(state):
    # Command 0 again as chain target (enumeration after stores)
    p3 = init_params(state)
    state.regs.r1 = 0x0
    state.regs.r2 = 0x0
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_face1d41_2636_11e1_ad9e0002a5d6c51b_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

