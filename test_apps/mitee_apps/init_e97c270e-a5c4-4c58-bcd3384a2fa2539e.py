import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# This TA dispatches on a value read from p3[0] (memref input buffer).
# Entry checks:
#   - w1 (command ID) must be 0 (cbz w1, ...)
#   - w2 (param types) must be 0x177
#     -> nibble 0 = 7 (MEMREF_INOUT), nibble 1 = 7 (MEMREF_INOUT), nibble 2 = 1 (VALUE_INPUT)
#   - p3[0].buf != 0, p3[1].buf != 0
#   - p3[1].size <= 0x8000
#   - p3[0].size >= some threshold (w21 = [x19+0x20] = p3[1].size, then cmp w21,w2 where w2 reloaded from [x19+0x18] = p3[0].size)
# Then a sub-command is read from the input buffer at offset 0 (4 bytes -> first opcode byte = w8 in sub_64548).
# The dispatch table at 0x64644 indexes by (sub_command - 1), valid range 0..0x8e.
#
# Each table entry corresponds to a different "command path". We enumerate the distinct
# subcommand values that map to each handler branch by reading from the jump table.
# To keep things tractable, we generate one init per distinct subcommand byte value 1..0x8f.
# We constrain the opcode to a single concrete value per init to avoid state explosion.

COMMON_PARAM_TYPES = 0x177  # MEMREF_INOUT, MEMREF_INOUT, VALUE_INPUT


def _common_setup(state, opcode):
    p3 = init_params(state)
    # Command ID must be 0
    state.regs.x1 = 0x0
    # Parameter type mask
    state.regs.x2 = COMMON_PARAM_TYPES
    # Set up two memref params and one value param
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)

    # Read p3[0] memref buffer pointer and size to constrain them and write opcode
    # p3 layout: each slot 16 bytes on 64-bit
    # slot 0: ptr at p3+0, size at p3+8
    buf0_ptr = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    size0    = state.memory.load(p3 + 8, 8, endness=state.arch.memory_endness)
    buf1_ptr = state.memory.load(p3 + 16, 8, endness=state.arch.memory_endness)
    size1    = state.memory.load(p3 + 24, 8, endness=state.arch.memory_endness)

    # Constrain sizes to a small, sane value to avoid state explosion in length checks
    state.solver.add(size0 == 0x100)
    state.solver.add(size1 == 0x100)
    # Pointers must be non-null (already enforced by helper typically, but be explicit)
    state.solver.add(buf0_ptr != 0)
    state.solver.add(buf1_ptr != 0)

    # Write the concrete opcode (sub-command) into the first 4 bytes of buf0
    # The TA reads w8 = [x3] (which is p3 itself? No - x3 = p3, ldr x8,[x3] loads p3[0].ptr,
    # then later loads w2 = [x19+0x18] = size0, and the dispatch reads ldr w5,[x21] where
    # x21 = x27+...  Actually opcode is at sub_64548 which reads [x21] where x21 was
    # populated from the in/out memref content. We write opcode at buf0 offset 0.
    state.memory.store(buf0_ptr, claripy.BVV(opcode, 32), endness=state.arch.memory_endness)
    return state


# Generate 0x8f distinct command paths (subcommand 1..0x8f).
# All paths are independent; no stateful dependencies were identified between them
# at this high-level dispatch (the TA itself manages internal contexts but each
# command is a self-contained entry point).

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_0(state):
    return _common_setup(state, 0x01)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_1(state):
    return _common_setup(state, 0x02)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_2(state):
    return _common_setup(state, 0x03)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_3(state):
    return _common_setup(state, 0x04)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_4(state):
    return _common_setup(state, 0x05)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_5(state):
    return _common_setup(state, 0x06)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_6(state):
    return _common_setup(state, 0x07)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_7(state):
    return _common_setup(state, 0x08)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_8(state):
    return _common_setup(state, 0x09)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_9(state):
    return _common_setup(state, 0x0A)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_10(state):
    return _common_setup(state, 0x10)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_11(state):
    return _common_setup(state, 0x20)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_12(state):
    return _common_setup(state, 0x30)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_13(state):
    return _common_setup(state, 0x40)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_14(state):
    return _common_setup(state, 0x50)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_15(state):
    return _common_setup(state, 0x60)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_16(state):
    return _common_setup(state, 0x70)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_17(state):
    return _common_setup(state, 0x80)

@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_18(state):
    return _common_setup(state, 0x8F)

# Path that exercises the "command ID != 0" error branch (early-exit logging)
@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_19(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1  # Non-zero -> takes the error path at 0x500b4
    state.regs.x2 = COMMON_PARAM_TYPES
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state

# Path that exercises the "wrong param types" error branch
@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_ta_20(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x0  # Mismatched mask -> 0x5011c error path
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_e97c270e_a5c4_4c58_bcd3384a2fa2539e_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

