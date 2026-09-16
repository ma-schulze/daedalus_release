
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# TA Analysis:
# Entry at 0x231b0 checks:
#   - param type (w19 == 0x65) -> matches TEEC_PARAM_TYPES with specific mask 0x65
#   - p3 slot1 size (x23+8) == 0x1000 (4096)
#   - p3 slot3 size (x23+0x18) == 0x1000 (4096)
#   - x20 = p3[0] (memref ptr slot 0), x19 = p3[2] (memref ptr slot 2)
# Command IDs are in w22 (w1):
#   0x9101 -> sub_2c6b8 (some function, size==8)
#   0x9102 -> sub_2c870 (uses slot 0 data)
#   0x9103 -> sub_2ec30 (uses slot 0 data, needs global state == 2)
#   0x9201 -> sub_2e7e8 (uses slot 0 data)
#   0x8001 -> simple path, writes 1 to output
#   0x8004 -> reads [x20+0x10], [x20+0x14] as two words, calls sub_2c3d8
# Default (else) -> sub_2a480 which is the main dispatcher based on [x20] (first byte of input buffer)
#   sub_2a480 dispatches on *(x20) - 0xa001 for values [0,6]:
#     indices 0..6 lead to different sub-commands using global state machines at 0x6f278 and 0x6f280
#
# State machines (stateful TA):
#   state1 @ 0x6f278: initialized by command yielding state=1 (command handler 1)
#   state2 @ 0x6f280: initialized by command yielding state=1 (command handler 2)
#   Progression: state1: init -> 1 -> 2 -> 3 -> 4
#                state2: init -> 1 -> 2 -> 3
# These are sub-commands dispatched via [x20] = 0xa001..0xa007
#
# For simplicity and coverage we create inits per top-level command id + a few sub-command values.


def _setup_common(state):
    """Set up p3 with two memref params (slot 0 input, slot 2 output), size 0x1000."""
    p3 = init_params(state)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 2)
    # Set sizes to 0x1000 as required by top-level entry check
    word = 8  # AArch64
    # slot 0: ptr at p3+0, size at p3+8
    state.memory.store(p3 + word, claripy.BVV(0x1000, 64), endness=state.arch.memory_endness)
    # slot 2: ptr at p3+0x20, size at p3+0x28
    state.memory.store(p3 + 0x20 + word, claripy.BVV(0x1000, 64), endness=state.arch.memory_endness)
    # param types mask (w2 == 0x65)
    state.regs.x2 = claripy.BVV(0x65, 64)
    return p3


@ta_init_function
def init_mitee_0(state):
    # Command 0x8001 - simple terminal path
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x8001, 64)
    return state


@ta_init_function
def init_mitee_1(state):
    # Command 0x8004 - calls sub_2c3d8 with two words from input
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x8004, 64)
    return state


@ta_init_function
def init_mitee_2(state):
    # Command 0x9101 -> sub_2c6b8 (requires size 8)
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x9101, 64)
    return state


@ta_init_function
def init_mitee_3(state):
    # Command 0x9102 -> sub_2c870
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x9102, 64)
    return state


@ta_init_function
def init_mitee_4(state):
    # Command 0x9103 -> sub_2ec30
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x9103, 64)
    return state


@ta_init_function
def init_mitee_5(state):
    # Command 0x9201 -> sub_2e7e8
    p3 = _setup_common(state)
    state.regs.x1 = claripy.BVV(0x9201, 64)
    return state


def _setup_subcmd(state, subcmd_val):
    """Set up for default-path (sub_2a480). Command id is some non-special value,
    and the sub-dispatch byte is a word at [x20] (p3[0].buffer first 4 bytes)."""
    p3 = _setup_common(state)
    # Use command id 0 (not matching any special case) -> falls through to sub_2a480
    state.regs.x1 = claripy.BVV(0x0, 64)
    # Read p3 slot 0 buffer pointer and write subcmd value to [buf]
    word = 8
    buf_ptr = state.memory.load(p3, word, endness=state.arch.memory_endness)
    state.memory.store(buf_ptr, claripy.BVV(subcmd_val, 32), endness=state.arch.memory_endness)
    return state


@ta_init_function(next_func="init_mitee_7")
def init_mitee_6(state):
    # sub-command 0xa001 - initializes state1 (sets state=1)
    return _setup_subcmd(state, 0xa001)


@ta_init_function
def init_mitee_7(state):
    # sub-command 0xa002 - requires state1 == 1, progresses to 2
    return _setup_subcmd(state, 0xa002)


@ta_init_function(next_func="init_mitee_9")
def init_mitee_8(state):
    # sub-command 0xa003 - initializes state2 (sets state=1)
    return _setup_subcmd(state, 0xa003)


@ta_init_function
def init_mitee_9(state):
    # sub-command 0xa004 - requires state2 transitions
    return _setup_subcmd(state, 0xa004)


@ta_init_function
def init_mitee_10(state):
    # sub-command 0xa005 - state1 == 4 path
    return _setup_subcmd(state, 0xa005)


@ta_init_function
def init_mitee_11(state):
    # sub-command 0xa006 - state2 == 3 path
    return _setup_subcmd(state, 0xa006)


@ta_init_function
def init_mitee_12(state):
    # sub-command 0xa007 - remaining dispatch index
    return _setup_subcmd(state, 0xa007)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_8aaaf201_2460_0000_7143fe4f7c823c80_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

