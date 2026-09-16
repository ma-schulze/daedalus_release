
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# This TA dispatches on a command id read from p3[0] memref buffer at offset 0 (r5 = *r4 where r4 = *r8 = p3_param_0_ptr)
# Looking at sub_288054:
#   r4 = p3[0].ptr (first param buffer pointer)
#   r5 = *r4  (command id)
#   compares r5 against 0x1000, 0x1005, 0x1006, otherwise falls through to sub_2015a0
# sub_2015a0 further dispatches based on *p3[0].ptr (r3 = [r0]) against many command IDs.
#
# Strategy: create one init per distinct command dispatch value. The command id is stored
# at offset 0 of the buffer pointed to by p3[0].ptr (memref param 0).
#
# We also need to handle stateful behavior: some commands require prior initialization
# (e.g. 0x1000 seems to init something, 0x1005 does sub_286a1c which might terminate session).


def _setup_common(state):
    """Common setup: init params, set p3[0] memref, place a buffer, set r2 mask."""
    p3 = init_params(state)
    # Set up memref at index 0 - this is the main parameter buffer
    place_sym_memref_param(state, p3, 0)
    # Set up memref at index 1 for some commands that use more slots
    place_sym_memref_param(state, p3, 1)
    # r1 (command id in GP ABI) is not directly used here, but set to something reasonable
    # r2 parameter type mask - allow anything; the TA seems to not check it directly at entry
    return p3


def _write_cmd_id(state, p3, cmd_id):
    """Write a concrete command id to the first 4 bytes of the buffer pointed to by p3[0]."""
    # p3[0].ptr is stored at p3 + 0
    ptr = state.memory.load(p3, 4, endness=state.arch.memory_endness)
    state.memory.store(ptr, claripy.BVV(cmd_id, 32), endness=state.arch.memory_endness)
    # Also ensure the buffer size at p3+4 is large enough
    state.memory.store(p3 + 4, claripy.BVV(0x200, 32), endness=state.arch.memory_endness)


# ------------------- Top-level outer dispatch (sub_288054) -------------------

@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_0(state):
    # cmd 0x1000: calls sub_2015a0 (inner dispatch) then specific handling
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1000)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_1(state):
    # cmd 0x1005: calls sub_286a1c (session cleanup / termination-like)
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1005)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_2(state):
    # cmd 0x1006: calls a function via indirect pointer at offset +0x60
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1006)
    return state


# ------------------- Inner dispatch (sub_2015a0) commands -------------------
# These all fall through from the outer dispatch default case (calls sub_2015a0).
# The command id compared in sub_2015a0 is again at [r0] which is the same buffer.

@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_3(state):
    # 0x101b: handled at 0x20276c
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x101b)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_4(state):
    # 0x1025
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1025)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_5(state):
    # 0x1020
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1020)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_6(state):
    # 0x101d
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x101d)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_7(state):
    # 0x101e
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x101e)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_8(state):
    # 0x101f
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x101f)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_9(state):
    # 0x1010
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1010)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_10(state):
    # 0x100a
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x100a)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_11(state):
    # 0x1007
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1007)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_12(state):
    # 0x1008
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1008)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_13(state):
    # 0x1009
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1009)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_14(state):
    # 0x1015
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1015)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_15(state):
    # 0x1018
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1018)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_16(state):
    # 0x1016
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1016)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_17(state):
    # 0x1017
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1017)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_18(state):
    # 0x2006
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2006)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_19(state):
    # 0x2009
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2009)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_20(state):
    # 0x2007
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2007)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_21(state):
    # 0x2008
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2008)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_22(state):
    # 0x1012
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1012)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_23(state):
    # 0x1013
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1013)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_24(state):
    # 0x1014
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1014)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_25(state):
    # 0x2000
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2000)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_26(state):
    # 0x2001
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2001)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_27(state):
    # 0x2004
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2004)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_28(state):
    # 0x1022
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1022)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_29(state):
    # 0x1023
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1023)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_30(state):
    # 0x1024
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1024)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_31(state):
    # 0x100c
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x100c)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_32(state):
    # 0x100d
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x100d)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_33(state):
    # 0x100f
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x100f)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_34(state):
    # 0x1019
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1019)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_35(state):
    # 0x101a
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x101a)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_36(state):
    # 0x2010
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2010)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_37(state):
    # 0x2011
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x2011)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_38(state):
    # 0x1006 (inner)
    p3 = _setup_common(state)
    _write_cmd_id(state, p3, 0x1006)
    return state


@ta_init_function
def init____________test_binaries_taemu_t6_tas_9459b61a_02d3_4d1e_b68be94397e7ca8c_ta_39(state):
    # 0x1026
    p3 = _setup_common(state)
    # Constrain the secondary op byte (r4[0x10]) to small range to avoid explosion:
    # At 0x201de8: ldrb r0, [r4, #0x10]; cmp 1 / cmp 2 — only 0,1,2 paths matter.
    _write_cmd_id(state, p3, 0x1026)
    # Constrain buffer[0x10] to be in {0,1,2}
    ptr = state.memory.load(p3, 4, endness=state.arch.memory_endness)
    sub_op = state.memory.load(ptr + 0x10, 1)
    state.solver.add(sub_op <= 2)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_9459b61a_02d3_4d1e_b68be94397e7ca8c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

