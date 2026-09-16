import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# TA dispatch table (r1 = command ID). Each command requires a specific param_types mask in r2.
# Commands observed:
#  0x03  -> r2 == 3        (VALUE_INOUT slot0)
#  0x0D  -> r2 == 0x653    (memref slots)
#  0x0E  -> r2 == 0x53     (memref slot0 + value slot1)
#  0x0F  -> r2 == 0x653
#  0x10  -> r2 == 0x653
#  0x11  -> r2 == 0x653
#  0x12  -> r2 == 0x653
#  0x13  -> r2 == 0x653
#  0x14  -> r2 == 0x653
#  0x15  -> r2 == 0x53
#  0x17  -> r2 == 3
#  0x19  -> r2 == 0x53
#  0x1A  -> r2 == 0x653
#  0x1B  -> r2 == 0x602 or 0x603
#  0x1C  -> r2 == 0x653
#  0x1D  -> r2 == 0x653
#  0x1E  -> r2 == 0x653
#  0x1F  -> r2 == 0x53
#  0x20  -> r2 == 3
#  0xFF00 -> r2 == 3
#  0xFF01 -> r2 == 3
#  0xFF03 -> r2 == 0x602 or 0x603
#  0xFF04 -> r2 == 0x50


def _decode_and_place(state, p3, mask):
    """Decode 16-bit mask into per-slot GP types and place params."""
    for i in range(4):
        t = (mask >> (i * 4)) & 0xF
        if t in (1, 2, 3):
            place_sym_value_param(state, p3, i)
        elif t in (5, 6, 7):
            place_sym_memref_param(state, p3, i)


# ---- Command 0x03: param_types == 3 (VALUE_INOUT slot0) ----
@ta_init_function
def init_t6_0(state):
    p3 = init_params(state)
    state.regs.r1 = 0x03
    state.regs.r2 = 3
    _decode_and_place(state, p3, 3)
    return state


# ---- Command 0x0D: param_types == 0x653 (memref0=3? Actually 0x653 -> slot0=3 VALUE_INOUT, slot1=5 MEMREF_IN, slot2=6 MEMREF_OUT) ----
@ta_init_function
def init_t6_1(state):
    p3 = init_params(state)
    state.regs.r1 = 0x0D
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x0E: param_types == 0x53 (slot0=3 VALUE_INOUT, slot1=5 MEMREF_IN) ----
@ta_init_function
def init_t6_2(state):
    p3 = init_params(state)
    state.regs.r1 = 0x0E
    state.regs.r2 = 0x53
    _decode_and_place(state, p3, 0x53)
    return state


# ---- Command 0x0F: r2 == 0x653 ----
@ta_init_function
def init_t6_3(state):
    p3 = init_params(state)
    state.regs.r1 = 0x0F
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x10: r2 == 0x653 ----
@ta_init_function
def init_t6_4(state):
    p3 = init_params(state)
    state.regs.r1 = 0x10
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x11: r2 == 0x653 ----
@ta_init_function
def init_t6_5(state):
    p3 = init_params(state)
    state.regs.r1 = 0x11
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x12: r2 == 0x653 ----
@ta_init_function
def init_t6_6(state):
    p3 = init_params(state)
    state.regs.r1 = 0x12
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x13: r2 == 0x653 ----
@ta_init_function
def init_t6_7(state):
    p3 = init_params(state)
    state.regs.r1 = 0x13
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x14: r2 == 0x653 ----
@ta_init_function
def init_t6_8(state):
    p3 = init_params(state)
    state.regs.r1 = 0x14
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x15: r2 == 0x53 ----
@ta_init_function
def init_t6_9(state):
    p3 = init_params(state)
    state.regs.r1 = 0x15
    state.regs.r2 = 0x53
    _decode_and_place(state, p3, 0x53)
    return state


# ---- Command 0x17: r2 == 3 ----
@ta_init_function
def init_t6_10(state):
    p3 = init_params(state)
    state.regs.r1 = 0x17
    state.regs.r2 = 3
    _decode_and_place(state, p3, 3)
    return state


# ---- Command 0x19: r2 == 0x53 ----
@ta_init_function
def init_t6_11(state):
    p3 = init_params(state)
    state.regs.r1 = 0x19
    state.regs.r2 = 0x53
    _decode_and_place(state, p3, 0x53)
    return state


# ---- Command 0x1A: r2 == 0x653 ----
@ta_init_function
def init_t6_12(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1A
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x1B: r2 == 0x602 (slot0=2 VALUE_OUT, slot1=6 MEMREF_OUT) ----
@ta_init_function
def init_t6_13(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1B
    state.regs.r2 = 0x602
    _decode_and_place(state, p3, 0x602)
    return state


# ---- Command 0x1B alt: r2 == 0x603 ----
@ta_init_function
def init_t6_14(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1B
    state.regs.r2 = 0x603
    _decode_and_place(state, p3, 0x603)
    return state


# ---- Command 0x1C: r2 == 0x653 ----
@ta_init_function
def init_t6_15(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1C
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x1D: r2 == 0x653 ----
@ta_init_function
def init_t6_16(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1D
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x1E: r2 == 0x653 ----
@ta_init_function
def init_t6_17(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1E
    state.regs.r2 = 0x653
    _decode_and_place(state, p3, 0x653)
    return state


# ---- Command 0x1F: r2 == 0x53 ----
@ta_init_function
def init_t6_18(state):
    p3 = init_params(state)
    state.regs.r1 = 0x1F
    state.regs.r2 = 0x53
    _decode_and_place(state, p3, 0x53)
    return state


# ---- Command 0x20: r2 == 3 ----
@ta_init_function
def init_t6_19(state):
    p3 = init_params(state)
    state.regs.r1 = 0x20
    state.regs.r2 = 3
    _decode_and_place(state, p3, 3)
    return state


# ---- Command 0xFF00: r2 == 3 ----
@ta_init_function
def init_t6_20(state):
    p3 = init_params(state)
    state.regs.r1 = 0xFF00
    state.regs.r2 = 3
    _decode_and_place(state, p3, 3)
    return state


# ---- Command 0xFF01: r2 == 3 ----
@ta_init_function
def init_t6_21(state):
    p3 = init_params(state)
    state.regs.r1 = 0xFF01
    state.regs.r2 = 3
    _decode_and_place(state, p3, 3)
    return state


# ---- Command 0xFF03: r2 == 0x602 ----
@ta_init_function
def init_t6_22(state):
    p3 = init_params(state)
    state.regs.r1 = 0xFF03
    state.regs.r2 = 0x602
    _decode_and_place(state, p3, 0x602)
    return state


# ---- Command 0xFF03 alt: r2 == 0x603 ----
@ta_init_function
def init_t6_23(state):
    p3 = init_params(state)
    state.regs.r1 = 0xFF03
    state.regs.r2 = 0x603
    _decode_and_place(state, p3, 0x603)
    return state


# ---- Command 0xFF04: r2 == 0x50 (slot0=0 NONE, slot1=5 MEMREF_IN) ----
@ta_init_function
def init_t6_24(state):
    p3 = init_params(state)
    state.regs.r1 = 0xFF04
    state.regs.r2 = 0x50
    _decode_and_place(state, p3, 0x50)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_9ef77781_7bd5_4e39_965f20f6f211f46b_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

