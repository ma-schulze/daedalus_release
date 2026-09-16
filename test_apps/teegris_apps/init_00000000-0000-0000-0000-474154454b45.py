import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# Command 0x7e: param type mask == 0x557, needs memref[0] size==0x419, memref[1] size==0x3a, memref[2] non-null
# This path reads existing persistent object (load key-like flow)
@ta_init_function
def init_teegris_getkey_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x7e
    state.regs.x2 = 0x557
    # Slot 0: memref ptr != 0, size == 0x419
    place_sym_memref_param(state, p3, 0)
    # Slot 1: memref ptr != 0, size == 0x3a
    place_sym_memref_param(state, p3, 1)
    # Slot 2: memref ptr != 0 (size unchecked specifically, just non-null check on [x19+0x20])
    place_sym_memref_param(state, p3, 2)

    word = 8
    # Constrain sizes: p3[0].size at offset 8, p3[1].size at offset 0x18, p3[2].ptr at offset 0x20
    size0 = state.memory.load(p3 + 1 * word, word, endness=state.arch.memory_endness)
    size1 = state.memory.load(p3 + 3 * word, word, endness=state.arch.memory_endness)
    ptr2 = state.memory.load(p3 + 4 * word, word, endness=state.arch.memory_endness)
    state.solver.add(size0 == 0x419)
    state.solver.add(size1 == 0x3a)
    state.solver.add(ptr2 != 0)
    return state


# Command 0x3f path A: param type mask == 0x5557, memref[3].size == 0x3a (existing session/key update)
@ta_init_function
def init_teegris_getkey_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3f
    state.regs.x2 = 0x5557
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    word = 8
    # memref[3].size at p3 + 3*2*word + word = p3 + 0x38
    size3 = state.memory.load(p3 + 7 * word, word, endness=state.arch.memory_endness)
    state.solver.add(size3 == 0x3a)
    # memref[3].ptr needs to be non-zero implicit (checked via cbnz on [x19+0x10])
    ptr1 = state.memory.load(p3 + 2 * word, word, endness=state.arch.memory_endness)
    state.solver.add(ptr1 != 0)
    return state


# Command 0x3f path B: param type mask == 0x5557, memref[3].size == 0 AND memref[1].ptr == 0
# This leads to the create-new-object branch (generates key)
@ta_init_function
def init_teegris_getkey_2(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3f
    state.regs.x2 = 0x5557
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)

    word = 8
    # memref[3].size at offset 0x38 must be 0
    size3 = state.memory.load(p3 + 7 * word, word, endness=state.arch.memory_endness)
    state.solver.add(size3 == 0)
    # memref[1].ptr at offset 0x10 must be 0 (ldr x8,[x19,#0x10]; cbnz x8,fail)
    ptr1 = state.memory.load(p3 + 2 * word, word, endness=state.arch.memory_endness)
    state.solver.add(ptr1 == 0)
    return state


# Unknown command (falls to default error path) - covers the bad-command branch
@ta_init_function
def init_teegris_getkey_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x00  # neither 0x7e nor 0x3f
    state.regs.x2 = 0x0
    place_sym_memref_param(state, p3, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_474154454b45_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

