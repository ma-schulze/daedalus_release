import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis of TA at 0x198dc:
# - r2/x2 (param_types) is checked against 0x67:
#     0x67 = 7 | (6<<4) = slot0=MEMREF_INOUT, slot1=MEMREF_OUTPUT
# - If param_types == 0x67: a TEE_Malloc(0x14)/GetPropertyAsIdentity path is taken.
#   Then x19 (the malloc'd buffer) is treated as a structure whose first word
#   is compared to 0xF0000000 (mov w9, #-0x10000000):
#     * if [x19] == 0xF0000000: dispatch into sub_18528 with w21 (cmd id from x1).
#       sub_18528 has a jump-table over (w21 - 0x1000), 5 entries (cmd ids 0x1000..0x1004).
#     * else: a second path via TEES_IsREESharedMemory checks (cmd ids 3 and 2),
#       calling into sub_c9dc (which dispatches on (w21 - 0x11) up to 8 entries: 0x11..0x19).
# - param_types != 0x67 -> early return -0xfffa.
#
# Since the dispatch value [x19] comes from TEE_Malloc-allocated memory (TA-internal),
# we cannot easily force it from outside. We provide init functions that:
#   * set r2/x2 = 0x67 and set up memref params for slots 0 and 1
#   * set x1 (cmd id) to each of the discovered command IDs
# This yields coverage of both dispatch tables; the framework will pick the path
# that the symbolic state allows.
#
# The TA appears stateless in the InvokeCommand entry (no obvious cross-command
# persistent state besides TEE_Malloc'd context that is freed each call), so
# no chaining decorators are required.


def _setup_common(state):
    p3 = init_params(state)
    # param_types mask = 0x67: slot0 = MEMREF_INOUT (7), slot1 = MEMREF_OUTPUT (6)
    if state.arch.bits == 64:
        state.regs.x2 = claripy.BVV(0x67, 64)
    else:
        state.regs.r2 = claripy.BVV(0x67, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


def _set_cmd_id(state, cmd_id):
    if state.arch.bits == 64:
        state.regs.x1 = claripy.BVV(cmd_id, 64)
    else:
        state.regs.r1 = claripy.BVV(cmd_id, 32)


# --- Commands dispatched via sub_18528 jump table (cmd ids 0x1000..0x1004) ---

@ta_init_function
def init_msa_0(state):
    _setup_common(state)
    _set_cmd_id(state, 0x1000)
    return state


@ta_init_function
def init_msa_1(state):
    _setup_common(state)
    _set_cmd_id(state, 0x1001)
    return state


@ta_init_function
def init_msa_2(state):
    _setup_common(state)
    _set_cmd_id(state, 0x1002)
    return state


@ta_init_function
def init_msa_3(state):
    _setup_common(state)
    _set_cmd_id(state, 0x1003)
    return state


@ta_init_function
def init_msa_4(state):
    _setup_common(state)
    _set_cmd_id(state, 0x1004)
    return state


# --- Commands dispatched via sub_c9dc jump table (cmd ids 0x11..0x19) ---

@ta_init_function
def init_msa_5(state):
    _setup_common(state)
    _set_cmd_id(state, 0x11)
    return state


@ta_init_function
def init_msa_6(state):
    _setup_common(state)
    _set_cmd_id(state, 0x12)
    return state


@ta_init_function
def init_msa_7(state):
    _setup_common(state)
    _set_cmd_id(state, 0x13)
    return state


@ta_init_function
def init_msa_8(state):
    _setup_common(state)
    _set_cmd_id(state, 0x14)
    return state


@ta_init_function
def init_msa_9(state):
    _setup_common(state)
    _set_cmd_id(state, 0x15)
    return state


@ta_init_function
def init_msa_10(state):
    _setup_common(state)
    _set_cmd_id(state, 0x16)
    return state


@ta_init_function
def init_msa_11(state):
    _setup_common(state)
    _set_cmd_id(state, 0x17)
    return state


@ta_init_function
def init_msa_12(state):
    _setup_common(state)
    _set_cmd_id(state, 0x18)
    return state


@ta_init_function
def init_msa_13(state):
    _setup_common(state)
    _set_cmd_id(state, 0x19)
    return state


# --- Wrong param_types path (early-return -0xfffa) for coverage ---

@ta_init_function
def init_msa_14(state):
    p3 = init_params(state)
    if state.arch.bits == 64:
        state.regs.x2 = claripy.BVV(0x0, 64)
        state.regs.x1 = claripy.BVV(0x0, 64)
    else:
        state.regs.r2 = claripy.BVV(0x0, 32)
        state.regs.r1 = claripy.BVV(0x0, 32)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4d7073617574_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

