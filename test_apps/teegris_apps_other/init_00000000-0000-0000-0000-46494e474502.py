import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# TA analysis:
# - r2/x2 must equal 7 -> param_types = MEMREF_INOUT in slot 0
# - p3[0] = ptr (x2 in code), p3[1] = size (must equal 0x800000c)
# - TEES_IsREESharedMemory(3, ptr, size) must return 0 (we just set up a memref param)
# - The command ID is in w1 (w19), dispatched via a jump table indexed by (cmd - 1)
#   for cmd in [1..0x13]. cmd > 0x13 returns error.
# - 19 commands total (1..0x13). Each dispatches to a different sub_39xxxx handler.
# Without deeper info on each handler's state dependencies, we emit independent init functions.

TA_SIZE_CONST = 0x800000c  # x21 value

def _setup_common(state, cmd_id):
    p3 = init_params(state)
    # param types = 7 -> MEMREF_INOUT slot 0
    state.regs.x2 = 7
    state.regs.x1 = cmd_id
    place_sym_memref_param(state, p3, 0)
    # Force size slot to TA_SIZE_CONST. p3[0]=ptr, p3[1]=size (each 8 bytes on AArch64).
    size_addr = p3 + 8
    state.memory.store(size_addr, claripy.BVV(TA_SIZE_CONST, 64), endness=state.arch.memory_endness)
    return p3


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_0(state):
    _setup_common(state, 0x1)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_1(state):
    _setup_common(state, 0x2)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_2(state):
    _setup_common(state, 0x3)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_3(state):
    _setup_common(state, 0x4)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_4(state):
    _setup_common(state, 0x5)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_5(state):
    _setup_common(state, 0x6)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_6(state):
    _setup_common(state, 0x7)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_7(state):
    _setup_common(state, 0x8)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_8(state):
    _setup_common(state, 0x9)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_9(state):
    _setup_common(state, 0xa)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_10(state):
    _setup_common(state, 0xb)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_11(state):
    _setup_common(state, 0xc)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_12(state):
    _setup_common(state, 0xd)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_13(state):
    _setup_common(state, 0xe)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_14(state):
    _setup_common(state, 0xf)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_15(state):
    _setup_common(state, 0x10)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_16(state):
    _setup_common(state, 0x11)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_17(state):
    _setup_common(state, 0x12)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_18(state):
    _setup_common(state, 0x13)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_46494e474502_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

