import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target


# Generic init: fully symbolic param types, symbolic command ID
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_0(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


# Command 0 with four value params
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x1111  # 4x VALUE_INPUT
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


# Command 1 with a single memref input
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_2(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x5  # slot0 = MEMREF_INPUT
    place_sym_memref_param(state, p3, 0)
    return state


# Command 2 with a single memref output
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x6  # slot0 = MEMREF_OUTPUT
    place_sym_memref_param(state, p3, 0)
    return state


# Command 3 with a memref inout
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_4(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x7  # slot0 = MEMREF_INOUT
    place_sym_memref_param(state, p3, 0)
    return state


# Command 4 with memref input + memref output
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_5(state):
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x65  # slot0=MEMREF_INPUT, slot1=MEMREF_OUTPUT
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


# Command 5 with value input + memref output
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_6(state):
    p3 = init_params(state)
    state.regs.x1 = 0x5
    state.regs.x2 = 0x61  # slot0=VALUE_INPUT, slot1=MEMREF_OUTPUT
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


# Command 6 with value input only
@ta_init_function
def init___________test_binaries_optee_examples_1dc6a16b_2fba_4aa1_9519_ea8a6c8c16e5_elf_7(state):
    p3 = init_params(state)
    state.regs.x1 = 0x6
    state.regs.x2 = 0x1  # slot0=VALUE_INPUT
    place_sym_value_param(state, p3, 0)
    return state
