import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target


# TA dispatch on r1 (command id):
#   r1 == 0: -> 0x9cb8: read [r3] and [r3+4], if both non-zero, return -1; else -1. Memref/value type unclear.
#            actually slot0 from p3: reads r3[0] and r3[4] -> these are value0.a and value0.b
#   r1 == 1: -> 0x9c9c (also r1==1 via 0x9cac path): calls 0x10868 with r0=r3 (parameter array ptr). r2 must == 2.
#   r1 == 2: -> 0x9cd8: ldr r0,[r1],#4; calls 0x108a8 (no r2 check) - generic
#   r1 == 3: -> 0x9d1c via path that requires r2==5 first then loads two ints; calls 0x10a30
#   r1 == 4: -> 0x9cec: calls 0x10bf0 - no r2 check on this path
#   r1 == 5: -> 0x9d2c: requires r2==0x65; checks r3[0], r3[4] non-zero, then calls 0x10cfc with r2=r3[8]
#   r1 == 0xf020: -> 0x10ea4 (manage TA properties)


@ta_init_function(next_funcs=["init_ta_1", "init_ta_2", "init_ta_3", "init_ta_4", "init_ta_5", "init_ta_6"])
def init_ta_0(state):
    # cmd 0: simple branch, value params at slot 0
    p3 = init_params(state)
    state.regs.r1 = 0x0
    state.regs.r2 = 0x1  # VALUE_INPUT slot0
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function(next_funcs=["init_ta_2", "init_ta_3", "init_ta_4", "init_ta_5", "init_ta_6"])
def init_ta_1(state):
    # cmd 1: store/create object via sub_10868 -> sub_d7a0 (writes persistent object)
    # Requires r2 == 2 (VALUE_INOUT) -> nibble check at 0x9c94 cmp r2,#2
    p3 = init_params(state)
    state.regs.r1 = 0x1
    state.regs.r2 = 0x3  # VALUE_INOUT
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function(next_funcs=["init_ta_3", "init_ta_4", "init_ta_5", "init_ta_6"])
def init_ta_2(state):
    # cmd 2: dispatches to 0x108a8 - signing/sign-related path
    # First slot used: ldr r0,[r1] (the object handle from prior cmd?), uses memref slot0
    p3 = init_params(state)
    state.regs.r1 = 0x2
    state.regs.r2 = 0x7  # MEMREF_INOUT slot0
    place_sym_memref_param(state, p3, 0)
    # Constrain memref size to small to avoid explosion
    word = state.arch.bytes
    size_addr = p3 + 0 * 2 * word + word
    state.memory.store(size_addr, claripy.BVV(0x80, word * 8), endness=state.arch.memory_endness)
    return state


@ta_init_function(next_funcs=["init_ta_4", "init_ta_5", "init_ta_6"])
def init_ta_3(state):
    # cmd 3: path through 0x9d00 requires r2 == 5 (MEMREF_INPUT) then jumps to 0x9d1c which ldm r3,{r0,r1}
    # Calls 0x10a30 (key derivation/decrypt). Needs memref param.
    p3 = init_params(state)
    state.regs.r1 = 0x3
    state.regs.r2 = 0x5  # MEMREF_INPUT slot0
    place_sym_memref_param(state, p3, 0)
    word = state.arch.bytes
    size_addr = p3 + 0 * 2 * word + word
    # Need size > 0x3f (cmp r6,#0x3f, bls return) -> set 0x80 to satisfy
    state.memory.store(size_addr, claripy.BVV(0x140 + 0x10, word * 8), endness=state.arch.memory_endness)
    return state


@ta_init_function(next_funcs=["init_ta_5", "init_ta_6"])
def init_ta_4(state):
    # cmd 4: -> 0x9cec then 0x10bf0; uses memref slot0 from p3
    p3 = init_params(state)
    state.regs.r1 = 0x4
    state.regs.r2 = 0x5  # MEMREF_INPUT slot0
    place_sym_memref_param(state, p3, 0)
    word = state.arch.bytes
    size_addr = p3 + 0 * 2 * word + word
    state.memory.store(size_addr, claripy.BVV(0x80, word * 8), endness=state.arch.memory_endness)
    return state


@ta_init_function(next_funcs=["init_ta_6"])
def init_ta_5(state):
    # cmd 5: path 0x9c50 requires r2 == 0x65 (MEMREF_INPUT slot0, MEMREF_OUTPUT slot1)
    # then 0x9d2c verifies r3[0] and r3[4] (slot0 buffer ptr & size) non-zero,
    # plus reads r3[8] (slot1 ptr) and calls 0x10cfc.
    p3 = init_params(state)
    state.regs.r1 = 0x5
    state.regs.r2 = 0x65  # slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    word = state.arch.bytes
    # constrain sizes to small values to avoid state explosion
    state.memory.store(p3 + 0 * 2 * word + word, claripy.BVV(0x40, word * 8),
                       endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 2 * word + word, claripy.BVV(0x80, word * 8),
                       endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_6(state):
    # cmd 0xf020: handle TA properties / config branch -> 0x10ea4
    p3 = init_params(state)
    state.regs.r1 = 0xf020
    state.regs.r2 = 0x7  # MEMREF_INOUT
    place_sym_memref_param(state, p3, 0)
    word = state.arch.bytes
    state.memory.store(p3 + 0 * 2 * word + word, claripy.BVV(0x100, word * 8),
                       endness=state.arch.memory_endness)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_08010203000000000000000000000000_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

