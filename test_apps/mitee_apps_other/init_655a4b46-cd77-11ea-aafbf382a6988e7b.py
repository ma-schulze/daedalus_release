import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis:
# At 0x300d8 the InvokeCommandEntryPoint:
#   - w2 (param_types) is compared to 0x2615 at 0x30148; mismatch -> error -0xfffa.
#   - w1 (command id) must be 0 (cbz w20 at 0x30150) to proceed.
#   - Then a JSON-like buffer pointed by p3[0] is parsed via sub_463a8, and a string command
#     is dispatched in sub_36aa0 by comparing the parsed JSON command string against many
#     keywords ("create_object", "load_object", "use_object" etc.).
#
# Param type mask 0x2615 decodes per-nibble as:
#   slot0 = 5 (MEMREF_INPUT), slot1 = 1 (VALUE_INPUT),
#   slot2 = 6 (MEMREF_OUTPUT), slot3 = 2 (VALUE_OUTPUT).
#
# Because the real dispatch happens on a JSON string inside the input buffer (parsed via
# heavy JSON parser), constraining bytes here is critical to avoid state space explosion.
# We provide a single primary init (command id 0, correct param mask) and also a couple of
# alternative inits that exercise the early error paths (wrong cmd id / wrong param mask).
# These alternative paths are short and shouldn't explode.


@ta_init_function
def init_ta_0(state):
    # Main path: correct param types mask, command id 0, memref input symbolic.
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x2615
    # slot0 MEMREF_INPUT, slot2 MEMREF_OUTPUT
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_ta_1(state):
    # Wrong command id path -> early return -0xffff (covers logging branch).
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x2615
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


@ta_init_function
def init_ta_2(state):
    # Wrong param-types mask path -> early return -0xfffa.
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x0
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_655a4b46_cd77_11ea_aafbf382a6988e7b_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

