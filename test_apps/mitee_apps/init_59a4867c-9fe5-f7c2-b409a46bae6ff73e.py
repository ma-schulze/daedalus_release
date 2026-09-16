
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# Analysis notes:
# - At 0x20284: cmp w21 (=w2, param types mask) with 0x65 -> expects param type mask 0x65
# - At 0x2028c: cbnz w22 where w22 = w19 & 0x10 (w19 = cmd id w1). If bit 4 of cmd id is 0 -> branch A; else branch B
# - Branch A (cmd id bit4 == 0): reads p3[1].size (off 8) expect 0x40c, p3[3].size (off 0x18) expect 0x408
#   Then reads *(uint32*)p3[0].buf at [x20] == 1 else error.
# - Branch B (cmd id bit4 == 1): simply proceeds with different setup.
# - After setup, at 0x20348: w8 = w19 - 0xF001; if w8 > 0x10 -> error (-0xfff6 = TEE_ERROR_NOT_SUPPORTED)
#   So valid command IDs are in range [0xF001, 0xF011].
# - Jump table at 0x1000+0x5a0 dispatches on (cmd_id - 0xF001).
#
# We generate a few representative init functions covering:
# 1) cmd id with bit4==0, param types = 0x65, correct memref sizes and buf[0]==1
# 2) cmd id with bit4==1 (e.g. 0xF011), param types = 0x65
# 3) cmd id outside valid range (triggers error path) - skip, low value
# Parameter type mask 0x65 layout: GP types 4 bits each.
# 0x65 = 0b0110 0101 -> slot0=5(memref input), slot1=6(memref output), slot2=... 
# Actually 0x65 for 4 params: nibbles 5,6,0,0 -> slot0=INPUT memref, slot1=OUTPUT memref? 
# The code accesses p3[0] buf/size, p3[1] size, p3[2] buf, p3[3] size -- so we set memref at all used slots.


@ta_init_function
def init_mitee_ta_0(state):
    # Branch A: cmd_id bit4 == 0, e.g. cmd_id = 0xF001
    # param types mask = 0x65
    # p3[1].size = 0x40c, p3[3].size = 0x408, *(uint32*)p3[0].buf = 1
    p3 = init_params(state)
    state.regs.x1 = 0xF001
    state.regs.x2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    word = 8
    # p3[1].size at p3 + 1*2*8 + 8 = p3 + 0x18
    state.memory.store(p3 + 0x18, claripy.BVV(0x40c, 64), endness=state.arch.memory_endness)
    # p3[3].size at p3 + 3*2*8 + 8 = p3 + 0x38
    state.memory.store(p3 + 0x38, claripy.BVV(0x408, 64), endness=state.arch.memory_endness)

    # p3[0].buf pointer is at p3+0, first 4 bytes at *buf must be 1
    buf0_ptr = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(buf0_ptr, claripy.BVV(1, 32), endness=state.arch.memory_endness)

    return state


@ta_init_function
def init_mitee_ta_1(state):
    # Branch B: cmd_id bit4 == 1, e.g. cmd_id = 0xF011
    p3 = init_params(state)
    state.regs.x1 = 0xF011
    state.regs.x2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    return state


@ta_init_function
def init_mitee_ta_2(state):
    # Branch A with cmd id 0xF005 (bit4==0)
    p3 = init_params(state)
    state.regs.x1 = 0xF005
    state.regs.x2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    state.memory.store(p3 + 0x18, claripy.BVV(0x40c, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0x38, claripy.BVV(0x408, 64), endness=state.arch.memory_endness)

    buf0_ptr = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(buf0_ptr, claripy.BVV(1, 32), endness=state.arch.memory_endness)

    return state


@ta_init_function
def init_mitee_ta_3(state):
    # Branch B with cmd id 0xF015 (bit4==1)
    p3 = init_params(state)
    state.regs.x1 = 0xF015
    state.regs.x2 = 0x65

    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_59a4867c_9fe5_f7c2_b409a46bae6ff73e_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

