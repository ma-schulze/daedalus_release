import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA dispatch summary:
# - r2 (param_types) must equal 0x65 (slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6))
# - Then checks p3[1].size == 0x608 and p3[3].size == 0x608 (via TEE_CheckMemoryAccessRights of slot0 buf,
#   then of slot1 buf size).
# - Reads first word of slot0 buffer; must equal 1 (cmd dispatch prefix).
# - r1 (command id) selects:
#     0x1     -> sub_c468  (store/create key blob: chain target after 0x1001 to use existing data)
#     0x2     -> sub_c9c0  (sub-op dispatched from buffer offset 4: 1,2,3)
#     0x1000  -> sub_c318  (sub-op at buffer[8]: 1,2,3)
#     0x1001  -> sub_c468  (same as 1)
#     0x1002  -> sub_c5e4
#     0x1003  -> sub_c824  (generates key list -> initializer)
#     0x2000  -> sub_ac10
#     0x2001  -> sub_a9d4
#     0x2002  -> sub_ac88

ta_name = "3d08821c33a611e6a1fa089e01c83aa2"


def _setup_common(state, cmd_id):
    """Set up p3 with two memref slots, sized 0x608, and a prefix word == 1."""
    p3 = init_params(state)
    state.regs.r1 = cmd_id
    state.regs.r2 = 0x65  # MEMREF_INPUT, MEMREF_OUTPUT

    # Allocate two buffers of size 0x608
    word = 4
    buf_size = 0x608

    # slot 0: memref input
    buf0 = get_tainted_mem_bits(state, buf_size * 8)
    # Constrain first word to 1 (dispatch prefix)
    state.memory.store(buf0, claripy.BVV(1, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0, claripy.BVV(buf0, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + word, claripy.BVV(buf_size, 32), endness=state.arch.memory_endness)

    # slot 1: memref output
    buf1 = get_tainted_mem_bits(state, buf_size * 8)
    state.memory.store(p3 + 2 * word, claripy.BVV(buf1, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * word, claripy.BVV(buf_size, 32), endness=state.arch.memory_endness)

    return state, buf0, buf1


# ---- 0x1003: generate/list keys (initializer; produces persistent state) ----
@ta_init_function(next_funcs=[
    "init_" + ta_name + "_2",   # 0x1001 store
    "init_" + ta_name + "_3",   # 0x1002 sub_c5e4
    "init_" + ta_name + "_4",   # 0x2000 ac10
    "init_" + ta_name + "_5",   # 0x2001 a9d4
    "init_" + ta_name + "_6",   # 0x2002 ac88
    "init_" + ta_name + "_7",   # 0x1 (alias of 0x1001)
    "init_" + ta_name + "_8",   # 0x2
    "init_" + ta_name + "_9",   # 0x1000
])
def init_3d08821c33a611e6a1fa089e01c83aa2_0(state):
    state, _, _ = _setup_common(state, 0x1003)
    return state


# ---- 0x1000: sub_c318, sub-op from buffer[8] = 1/2/3 ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_1(state):
    state, buf0, _ = _setup_common(state, 0x1000)
    # Constrain buf[8] (sub-op selector) to {1,2,3} to avoid explosion
    sub = state.memory.load(buf0 + 8, 4, endness=state.arch.memory_endness)
    state.solver.add(claripy.Or(sub == 1, sub == 2, sub == 3))
    return state


# ---- 0x1001: sub_c468 store key blob (chain target) ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_2(state):
    state, _, _ = _setup_common(state, 0x1001)
    return state


# ---- 0x1002: sub_c5e4 ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_3(state):
    state, _, _ = _setup_common(state, 0x1002)
    return state


# ---- 0x2000: sub_ac10 ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_4(state):
    state, _, _ = _setup_common(state, 0x2000)
    return state


# ---- 0x2001: sub_a9d4 ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_5(state):
    state, _, _ = _setup_common(state, 0x2001)
    return state


# ---- 0x2002: sub_ac88 ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_6(state):
    state, _, _ = _setup_common(state, 0x2002)
    return state


# ---- 0x1: alias of 0x1001 (sub_c468) ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_7(state):
    state, _, _ = _setup_common(state, 0x1)
    return state


# ---- 0x2: sub_c9c0 -- dispatch on key type byte at buf+8 (1=hex import,2=imp,3=other) ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_8(state):
    state, buf0, _ = _setup_common(state, 0x2)
    sub = state.memory.load(buf0 + 8, 4, endness=state.arch.memory_endness)
    state.solver.add(claripy.Or(sub == 1, sub == 2, sub == 3))
    return state


# ---- 0x1000 alternate as chain target follow-up ----
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_9(state):
    state, buf0, _ = _setup_common(state, 0x1000)
    sub = state.memory.load(buf0 + 8, 4, endness=state.arch.memory_endness)
    state.solver.add(claripy.Or(sub == 1, sub == 2, sub == 3))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_3d08821c33a611e6a1fa089e01c83aa2_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

