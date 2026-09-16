import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA: teegris TEESSSU (Samsung TEE Secure Storage-like TA)
# Observed command IDs from the dispatch trees:
#   0x3F, 0x52, 0x68, 0x79, 0x92, 0xAA, 0xED  -> param parsing via sub_18960 (first dispatch block)
#   0x3F, 0x79, 0x92                          -> sub_b810 path (first one)
#   0x38, 0x3F, 0x68, 0x79, 0x92, 0xA3, 0xED  -> require ptr-from-arg[0] (param3 ptr at p3[0].a)
#   Then main dispatch on w1:
#     0x02  -> sub_13e28 (no params needed from p3)
#     0x05  -> sub_1726c (uses p3[0] ptr + p3[0x10] size, byte at x3+0x10)
#     0x14  -> sub_13b60 (param3 byte at +0x10, uses p3[0])
#     0x38  -> sub_b52c
#     0x3F  -> sub_10a40
#     0x52  -> sub_edd0 (uses p3[0x20]/p3[0x28] slots)
#     0x68  -> sub_e634 (uses p3[0x20]/p3[0x28])
#     0x79  -> sub_f568
#     0x92  -> sub_12374
#     0xA3  -> sub_b810 (small path)
#     0xAA  -> sub_11c44 (uses p3[0x20]/p3[0x28])
#     0xC3  -> key-pair set via p3 field at +0x30/+0x34
#     0xC5  -> sub_17d8c (sets internal state)
#     0xC7  -> sub_179c8
#     0xE1  -> sub_b9d0
#     0xE2  -> sub_18c50 (value 4)
#     0xED  -> sub_12374-like (sub_12374 at 0x12374)  [bl 0x12374]
#
# Stateful dependencies (inferred):
#   sub_184a8 (initialize, called from 0x1635c path) and sub_13460 (sub after init) populate
#   global flags at 0x31070/0x31080 that many commands read. So many commands only make sense
#   after commands of class {0x3F,0x52,0x68,0x79,0x92,0xAA,0xED} were first invoked (which trigger
#   sub_184a8 + sub_13460). We therefore mark "use" commands as chain targets of an initializer.
#
# Note: the first pre-processing also reads from p3[0].b (length) at [x8+0x10] and p3[2] ptr/len.
# We'll set p3 slots 0..3 symbolic memrefs/values to be safe.


def _common_setup(state):
    p3 = init_params(state)
    # Provide memref params at indexes 0,1,2,3 to cover all accesses
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return p3


# ---------- Initializer commands (do first-time setup) ----------

@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",  # cmd 0x02
    "init_00000000000000000000544545535355_11",  # cmd 0x05
    "init_00000000000000000000544545535355_12",  # cmd 0x14
    "init_00000000000000000000544545535355_13",  # cmd 0x38
    "init_00000000000000000000544545535355_14",  # cmd 0x52
    "init_00000000000000000000544545535355_15",  # cmd 0x68
    "init_00000000000000000000544545535355_16",  # cmd 0xA3
    "init_00000000000000000000544545535355_17",  # cmd 0xAA
    "init_00000000000000000000544545535355_18",  # cmd 0xC3
    "init_00000000000000000000544545535355_19",  # cmd 0xC5
    "init_00000000000000000000544545535355_20",  # cmd 0xC7
    "init_00000000000000000000544545535355_21",  # cmd 0xE1
    "init_00000000000000000000544545535355_22",  # cmd 0xE2
])
def init_00000000000000000000544545535355_0(state):
    # cmd 0x3F: triggers sub_184a8 + sub_13460 (state init) then sub_10a40
    p3 = _common_setup(state)
    state.regs.x1 = 0x3F
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_1(state):
    # cmd 0x52
    p3 = _common_setup(state)
    state.regs.x1 = 0x52
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_2(state):
    # cmd 0x68
    p3 = _common_setup(state)
    state.regs.x1 = 0x68
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_3(state):
    # cmd 0x79
    p3 = _common_setup(state)
    state.regs.x1 = 0x79
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_4(state):
    # cmd 0x92
    p3 = _common_setup(state)
    state.regs.x1 = 0x92
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_5(state):
    # cmd 0xAA
    p3 = _common_setup(state)
    state.regs.x1 = 0xAA
    return state


@ta_init_function(next_funcs=[
    "init_00000000000000000000544545535355_10",
    "init_00000000000000000000544545535355_11",
    "init_00000000000000000000544545535355_12",
    "init_00000000000000000000544545535355_13",
    "init_00000000000000000000544545535355_14",
    "init_00000000000000000000544545535355_15",
    "init_00000000000000000000544545535355_16",
    "init_00000000000000000000544545535355_17",
    "init_00000000000000000000544545535355_18",
    "init_00000000000000000000544545535355_19",
    "init_00000000000000000000544545535355_20",
    "init_00000000000000000000544545535355_21",
    "init_00000000000000000000544545535355_22",
])
def init_00000000000000000000544545535355_6(state):
    # cmd 0xED
    p3 = _common_setup(state)
    state.regs.x1 = 0xED
    return state


# ---------- Non-initializer standalone commands ----------

@ta_init_function
def init_00000000000000000000544545535355_7(state):
    # cmd 0x02 -> sub_13e28 (simple, no dependency)
    p3 = _common_setup(state)
    state.regs.x1 = 0x02
    return state


@ta_init_function
def init_00000000000000000000544545535355_8(state):
    # cmd 0xE1 -> sub_b9d0 (simple)
    p3 = _common_setup(state)
    state.regs.x1 = 0xE1
    return state


@ta_init_function
def init_00000000000000000000544545535355_9(state):
    # cmd 0xE2 -> sub_18c50 with arg 4
    p3 = _common_setup(state)
    state.regs.x1 = 0xE2
    return state


# ---------- Chain target commands (require prior initializer) ----------

@ta_init_function
def init_00000000000000000000544545535355_10(state):
    # cmd 0x02 (as follow-up)
    p3 = _common_setup(state)
    state.regs.x1 = 0x02
    return state


@ta_init_function
def init_00000000000000000000544545535355_11(state):
    # cmd 0x05 -> sub_1726c (reads state via sub_184a8-loaded keys)
    p3 = _common_setup(state)
    state.regs.x1 = 0x05
    return state


@ta_init_function
def init_00000000000000000000544545535355_12(state):
    # cmd 0x14 -> sub_13b60
    p3 = _common_setup(state)
    state.regs.x1 = 0x14
    return state


@ta_init_function
def init_00000000000000000000544545535355_13(state):
    # cmd 0x38 -> sub_b52c
    p3 = _common_setup(state)
    state.regs.x1 = 0x38
    return state


@ta_init_function
def init_00000000000000000000544545535355_14(state):
    # cmd 0x52 -> sub_edd0
    p3 = _common_setup(state)
    state.regs.x1 = 0x52
    return state


@ta_init_function
def init_00000000000000000000544545535355_15(state):
    # cmd 0x68 -> sub_e634
    p3 = _common_setup(state)
    state.regs.x1 = 0x68
    return state


@ta_init_function
def init_00000000000000000000544545535355_16(state):
    # cmd 0xA3 -> sub_b810 (small path)
    p3 = _common_setup(state)
    state.regs.x1 = 0xA3
    return state


@ta_init_function
def init_00000000000000000000544545535355_17(state):
    # cmd 0xAA -> sub_11c44
    p3 = _common_setup(state)
    state.regs.x1 = 0xAA
    return state


@ta_init_function
def init_00000000000000000000544545535355_18(state):
    # cmd 0xC3 -> writes p3 field+0x34 into session state[0x30]
    p3 = _common_setup(state)
    state.regs.x1 = 0xC3
    return state


@ta_init_function
def init_00000000000000000000544545535355_19(state):
    # cmd 0xC5 -> sub_17d8c (sets session state[0x30])
    p3 = _common_setup(state)
    state.regs.x1 = 0xC5
    return state


@ta_init_function
def init_00000000000000000000544545535355_20(state):
    # cmd 0xC7 -> sub_179c8
    p3 = _common_setup(state)
    state.regs.x1 = 0xC7
    return state


@ta_init_function
def init_00000000000000000000544545535355_21(state):
    # cmd 0xE1 (follow-up variant)
    p3 = _common_setup(state)
    state.regs.x1 = 0xE1
    return state


@ta_init_function
def init_00000000000000000000544545535355_22(state):
    # cmd 0xE2 (follow-up variant)
    p3 = _common_setup(state)
    state.regs.x1 = 0xE2
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_544545535355_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

