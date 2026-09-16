import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA analysis:
# InvokeCommandEntryPoint at 0x177ac dispatches on w2 (param_types mask):
#   - if w2 == 0x67 (param_types), proceeds to parse p3 slots 0 and 1 as memrefs.
#     Both are checked via TEES_IsREESharedMemory; if either is NOT REE shared, goes to 0x178e0.
#   - otherwise, returns BAD_PARAMETERS (-0xfffa).
#
# At 0x178e0: reads p3[0].buf (x20[0]) and size (x20[8]) — size must equal 0x3e829+0x17 = 0x3e840.
# Also reads p3[1].buf (x20[0x10]) and size (x20[0x18]) — size must equal 0x3e829+0x17 = 0x3e840.
# Then calls sub_98ec(w21=cmdID, p3[0].buf, ...).
#
# sub_98ec dispatches on w0 = cmdID (w21 = r1/x1), decremented by 1 and bounded <= 8,
# then uses a jump table at 0x9928. So valid command IDs are 1..9.
# Cases (from jump table order / branches observed):
#   cmd 1 -> 0x9940 : calls sub_9504 (TEEC load monitor check), returns 2 on fail
#   cmd 2 -> 0x99b8 : store buffer (size <= 0x4000) from p3[0].buf+0x14 into allocated buffer at 0x1f000+0x208
#   cmd 3 -> 0x9a48 : returns via tail call to sub_12f18 (process data)
#   cmd 4 -> 0x9aa8 : returns via tail call to sub_12b0c (process, checks byte at offset 0x18 in range)
#   cmd 5 -> 0x9b08 : checks w1=[x19+0x18] <= 0x3e800, returns 7 if not
#   cmd 6 -> 0x9b58 : tail call sub_114ec (cleanup)
#   cmd 7 -> 0x9bbc : error path "prints and returns 1"
#   cmd 8 -> 0x9c28 : tail call sub_97c8 (copy/compare with some buffer)
#   cmd 9 -> (out of range -> default error path at 0x9bec)
# Additionally, cmd 5 triggers sub_17b44 callback at 0x179d4 if sub_98ec returned 0.
#
# The TA is stateful:
#   - cmd 2 (store) must happen before cmd 3/4/6/8 which consume stored data at 0x1f000+0x208.
#   - cmd 1 is an independent monitor check.
# We chain cmd 2 -> cmd 3,4,5,6,8.

TA_NAME = "00000000-0000-0000-0000-4d5053545549_ta"

# Parameter types value checked (w2 == 0x67)
PT_MASK = 0x67
# Required sizes for p3[0] and p3[1] memrefs = 0x3e829 + 0x17 = 0x3e840
REQ_SIZE = 0x3e840


def _setup_common(state, cmd_id):
    """Common setup: two memref params with required sizes, param_types=0x67, r1=cmd_id."""
    p3 = init_params(state)
    # Place two memref parameters (slots 0 and 1)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    # Overwrite the sizes to exact required value so the length checks pass.
    # Slot i layout (64-bit): p3 + i*16 = ptr, p3 + i*16 + 8 = size.
    state.memory.store(p3 + 0 + 8, claripy.BVV(REQ_SIZE, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 16 + 8, claripy.BVV(REQ_SIZE, 64), endness=state.arch.memory_endness)

    # Command ID in x1/w1
    state.regs.x1 = claripy.BVV(cmd_id, 64)
    # Param types mask in x2/w2
    state.regs.x2 = claripy.BVV(PT_MASK, 64)
    return p3


# --- Command 1: TEEC monitor/load check (independent) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_0(state):
    _setup_common(state, 1)
    return state


# --- Command 2: store data buffer; dependency producer ---
# Next funcs: the consumer commands 3,4,5,6,8.
@ta_init_function(next_funcs=[
    "init_00000000_0000_0000_0000_4d5053545549_ta_2",  # cmd 3
    "init_00000000_0000_0000_0000_4d5053545549_ta_3",  # cmd 4
    "init_00000000_0000_0000_0000_4d5053545549_ta_4",  # cmd 5
    "init_00000000_0000_0000_0000_4d5053545549_ta_5",  # cmd 6
    "init_00000000_0000_0000_0000_4d5053545549_ta_7",  # cmd 8
])
def init_00000000_0000_0000_0000_4d5053545549_ta_1(state):
    p3 = _setup_common(state, 2)
    # Constrain the size field read at [buf+0x10] (w20 = *(uint32_t*)(p3[0].buf + 0x10))
    # to <= 0x1000 (used as allocation size) to avoid state explosion on memcpy size.
    # The buffer pointer placed by place_sym_memref_param is symbolic; we constrain via a
    # concrete store into the backing buffer would require knowing its address. Skip here:
    # the memref ptr is symbolic and the TA reads from wherever it points. Leaving symbolic
    # is fine; the compare cmp w20,#0x4000 path to 0x9c90 returns 3 and won't explode much.
    return state


# --- Command 3 (chain target) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_2(state):
    _setup_common(state, 3)
    return state


# --- Command 4 (chain target) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_3(state):
    _setup_common(state, 4)
    return state


# --- Command 5 (chain target) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_4(state):
    _setup_common(state, 5)
    return state


# --- Command 6 (chain target) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_5(state):
    _setup_common(state, 6)
    return state


# --- Command 7: error print path (standalone) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_6(state):
    _setup_common(state, 7)
    return state


# --- Command 8 (chain target): copy/compare against internal buffer ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_7(state):
    _setup_common(state, 8)
    return state


# --- Invalid/default dispatch path (cmd 9) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_8(state):
    _setup_common(state, 9)
    return state


# --- Wrong param_types path (returns BAD_PARAMETERS early) ---
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_ta_9(state):
    p3 = init_params(state)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    state.regs.x1 = claripy.BVV(3, 64)
    # Any value != 0x67 triggers the error branch
    state.regs.x2 = claripy.BVV(0x0, 64)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4d5053545549_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

