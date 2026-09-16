import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# TA_InvokeCommandEntryPoint at 0x96d0
# - r2 must equal 0x65 (param type mask), otherwise early exit.
# - p3[0] = memref (checked via TEE_CheckMemoryAccessRights with r1=p3[0], r2=p3[1])
# - p3[1] = memref (checked via TEE_CheckMemoryAccessRights with r1=p3[2], r2=p3[3])
# - ip = p3[1] (size1), r6 = p3[2] (ptr1); both sizes must be <= 0x1000
# - r5 = r1 = command ID; switch on r1 with max value 4:
#     case 0: handler at ~0x97e4 (invalid/log) -> returns 5
#     case 1: sub_ade8 (load/read persistent data)
#     case 2: sub_bd34 (something with persistent obj)
#     case 3: large block at 0x981c - does pattern match then sub_128e4 (key import?)
#     case 4: branch path that checks global flag at 0xf544+0x230; if set -> different path
#
# Likely stateful relationship:
#   - cmd 1 (sub_ade8) reads a persistent object (sub_10624 opens, sub_10a9c reads)
#     -> writes p3[3] output
#   - cmd 2 (sub_bd34) reads and updates persistent object (sub_e278 open, sub_f0c0 read, sub_e4c8)
#   - cmd 3 (sub_128e4) seems to create/register something (sub_12b40/sub_12cd0 etc.)
#   - cmd 4 reads a global state flag at 0xf544+0x230 (1 means initialized)
#
# We'll chain: cmd3 (init) -> cmd1/cmd2/cmd4 as successors.


@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_0(state):
    # Command 0: invalid command / logs error
    p3 = init_params(state)
    state.regs.r1 = 0x0
    state.regs.r2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_1(state):
    # Command 1: sub_ade8 - likely reads persistent data
    p3 = init_params(state)
    state.regs.r1 = 0x1
    state.regs.r2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_2(state):
    # Command 2: sub_bd34 - persistent object read/update
    p3 = init_params(state)
    state.regs.r1 = 0x2
    state.regs.r2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function(next_funcs=[
    "init_14498ace2a8f11e880c8509a4c146f4c_1",
    "init_14498ace2a8f11e880c8509a4c146f4c_2",
    "init_14498ace2a8f11e880c8509a4c146f4c_4",
    "init_14498ace2a8f11e880c8509a4c146f4c_5",
])
def init_14498ace2a8f11e880c8509a4c146f4c_3(state):
    # Command 3: sub_128e4 - register/import key; this likely enables cmd4 path.
    # After block at 0x981c runs a pattern search/compare before calling sub_128e4.
    # Size1 (p3[1]) must be > 8 (bls #0x9a24 exits). Constrain size to small range.
    p3 = init_params(state)
    state.regs.r1 = 0x3
    state.regs.r2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    # Constrain ptr1 size (p3[1].size at p3+4+4) to a small but >8 value to avoid explosion
    # p3 layout: slot 0: ptr@p3, size@p3+4; slot 1: ptr@p3+8, size@p3+12
    size1 = state.memory.load(p3 + 12, 4, endness=state.arch.memory_endness)
    state.solver.add(size1 > 8)
    state.solver.add(size1 <= 0x20)
    return state


@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_4(state):
    # Command 4: path depends on global state flag at 0xf544+0x230 == 1
    # and byte at 0xf544+0x231 == 0x34. Needs prior initialization (cmd3).
    p3 = init_params(state)
    state.regs.r1 = 0x4
    state.regs.r2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    # Constrain size1 (ip) to small values to avoid explosion; must be > 3 for branch
    size1 = state.memory.load(p3 + 12, 4, endness=state.arch.memory_endness)
    state.solver.add(size1 > 3)
    state.solver.add(size1 <= 0x40)
    return state


@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_5(state):
    # Command 4 alternate: the inner branch where global state uses different path.
    # Same command ID=4 but different sizes trigger different sub-paths (0x9ac4, 0x9c90).
    p3 = init_params(state)
    state.regs.r1 = 0x4
    state.regs.r2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    # Force smaller size that triggers alternate branch (ip < r5+4)
    size1 = state.memory.load(p3 + 12, 4, endness=state.arch.memory_endness)
    state.solver.add(size1 >= 4)
    state.solver.add(size1 < 0x24)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_14498ace2a8f11e880c8509a4c146f4c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

