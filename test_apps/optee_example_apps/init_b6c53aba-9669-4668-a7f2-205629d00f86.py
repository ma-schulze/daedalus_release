import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The TA_InvokeCommandEntryPoint at 0x288 loads a function pointer from
# [0x19000 + 0x180] and jumps to __ta_invoke_cmd, which converts GP params
# and calls the real invoke handler via blr x23. Without the actual handler
# disassembly, we generate generic inits covering common param type masks
# and keep the command ID symbolic per init (concrete distinct values).

@ta_init_function
def init_b6c53aba_0(state):
    # All params symbolic, mask symbolic - generic exploration
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

@ta_init_function
def init_b6c53aba_1(state):
    # cmd 0, single memref inout
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(0, 32)
    state.regs.x2 = claripy.BVV(0x00000007, 32)
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_b6c53aba_2(state):
    # cmd 1, memref input + memref output
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(1, 32)
    state.regs.x2 = claripy.BVV(0x00000065, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_b6c53aba_3(state):
    # cmd 2, value input + memref output
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(2, 32)
    state.regs.x2 = claripy.BVV(0x00000061, 32)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_b6c53aba_4(state):
    # cmd 3, single value inout
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(3, 32)
    state.regs.x2 = claripy.BVV(0x00000003, 32)
    place_sym_value_param(state, p3, 0)
    return state

@ta_init_function
def init_b6c53aba_5(state):
    # cmd 4, memref inout + memref output
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(4, 32)
    state.regs.x2 = claripy.BVV(0x00000067, 32)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_b6c53aba_6(state):
    # cmd 5, four value inputs
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(5, 32)
    state.regs.x2 = claripy.BVV(0x00001111, 32)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

@ta_init_function
def init_b6c53aba_7(state):
    # cmd 6, single memref input
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(6, 32)
    state.regs.x2 = claripy.BVV(0x00000005, 32)
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function
def init_b6c53aba_8(state):
    # cmd 7, single memref output
    p3 = init_params(state)
    state.regs.x1 = claripy.BVV(7, 32)
    state.regs.x2 = claripy.BVV(0x00000006, 32)
    place_sym_memref_param(state, p3, 0)
    return state
