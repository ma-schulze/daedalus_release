import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis:
# TA_InvokeCommandEntryPoint at 0x2f40:
#   w19 = cmd_id (w1), w21 = param_types (w2), x20 = p3
#   Checks param_types == 7 (i.e., slot0 = MEMREF_INOUT, others NONE).
#   If yes, loads x1 = p3[0] (buffer ptr), x2 = p3[0+8] (size), calls TEES_IsREESharedMemory(3, ptr, size).
#   On success, loads x21 = p3[0], x2 = p3[8]; checks x21 != 0 and x2 == 0x7_0c10 (size == 0x70c10).
#   Then calls sub_2ca4(cmd_id, buffer_ptr).
# In sub_2ca4, w20 = cmd_id:
#   cmp w20, #1 -> b.ne to error path; so cmd_id == 1 is the main path.
#   Other cmd_ids go to error path.
# So there is essentially one main command (cmd 1) with the memref pointing to a 0x70c10-sized buffer.
# We also emit an init for a non-matching cmd_id to cover the error path.


@ta_init_function
def init_ta_0(state):
    # cmd_id = 1, param_types = 7 (slot0 MEMREF_INOUT), buffer size = 0x70c10
    p3 = init_params(state)
    state.regs.x1 = 1
    state.regs.x2 = 7
    place_sym_memref_param(state, p3, 0)
    # Force the size slot (p3 + 8) to 0x70c10 to satisfy the size check.
    state.memory.store(p3 + 8, claripy.BVV(0x70c10, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_1(state):
    # cmd_id != 1 (e.g. 2): same param mask/size to reach sub_2ca4 error path.
    p3 = init_params(state)
    state.regs.x1 = 2
    state.regs.x2 = 7
    place_sym_memref_param(state, p3, 0)
    state.memory.store(p3 + 8, claripy.BVV(0x70c10, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_2(state):
    # param_types != 7 -> early error return path (TEE_ERROR_BAD_PARAMETERS).
    p3 = init_params(state)
    state.regs.x1 = 1
    state.regs.x2 = 0
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_42494f535542_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

