import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# Analysis:
# TA_InvokeCommandEntryPoint:
#   - Checks param_types (w2) == 0x27 (slot0=MEMREF_INOUT(7), slot1=VALUE_INPUT(2)).
#     Actually 0x27 -> low nibble 7 = MEMREF_INOUT, next nibble 2 = VALUE_INPUT.
#   - Calls TEES_IsREESharedMemory(3, p3[0].ptr, p3[0].size) which must return 0.
#   - Then sub_fc2c is called with (cmdID=r1, p3[0].ptr, p3[0].size, p3[0].ptr (again), p3+8)
#     Inside sub_fc2c:
#       - Reads first 4 bytes of memref buffer -> opcode/subcmd (val at *p3[0].ptr).
#       - Subtracts 1, dispatches via switch table on values 0..5 (i.e. opcode in {1..6}).
#         Case opcode==1 (0): calls sub_16430 (checks IRS flag); if flag set -> writes "11"-tag,
#            else calls sub_10174 (open file?) at buffer+8.
#         Case opcode==2 (1): just logs (path c6 -> result type=3, size=4)
#         Case opcode==3 (2): just logs path cc -> result type=1, size=4
#         Case opcode==4 (3): logs path d2 -> type=4, size=4
#         Case opcode==5 (4): type=1, size=0
#         Case opcode==6 (5): writes type=1, calls sub_10450 (read file?) on buffer+8
#       - default (opcode out of 1..6): logs error, type=1, size=1
#
# Param types mask = 0x27: slot0=MEMREF_INOUT(7), slot1=VALUE_INPUT(2)
# Command opcode is stored in first 4 bytes of memref slot 0.
#
# Stateful dependencies:
#   opcode 1 (sub_10174) seems to open/create object; opcode 6 (sub_10450) reads/uses object.
#   So opcode 6 depends on opcode 1 having been executed.

TA_NAME = "00000000_0000_0000_0000_0050524f4341"
PARAM_TYPES_MASK = 0x27


def _setup_common(state):
    p3 = init_params(state)
    # Set parameter types mask: slot0=MEMREF_INOUT(7), slot1=VALUE_INPUT(2)
    state.regs.x2 = PARAM_TYPES_MASK
    # Setup p3 slot 0 as memref, slot 1 as value
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    return p3


def _get_memref_buf_ptr(state, p3):
    # On AArch64, word = 8 bytes; slot 0 ptr at p3+0
    return state.memory.load(p3, 8, endness=state.arch.memory_endness)


def _set_opcode(state, p3, opcode):
    buf_ptr = _get_memref_buf_ptr(state, p3)
    state.memory.store(buf_ptr, claripy.BVV(opcode, 32), endness=state.arch.memory_endness)


@ta_init_function(next_func="init_" + TA_NAME + "_5")
def init_00000000_0000_0000_0000_0050524f4341_0(state):
    # Command path: opcode == 1 (creates/opens object) -> enables opcode 6
    p3 = _setup_common(state)
    state.regs.x1 = 0x27  # Command ID: not strictly checked, set to mask value
    _set_opcode(state, p3, 1)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_1(state):
    # opcode == 2
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 2)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_2(state):
    # opcode == 3
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 3)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_3(state):
    # opcode == 4
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 4)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_4(state):
    # opcode == 5
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 5)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_5(state):
    # opcode == 6: uses object -> depends on opcode 1 having been run
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 6)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_6(state):
    # Default path: opcode outside 1..6 (e.g. 0 or 7+)
    p3 = _setup_common(state)
    state.regs.x1 = 0x27
    _set_opcode(state, p3, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_0050524f4341_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

