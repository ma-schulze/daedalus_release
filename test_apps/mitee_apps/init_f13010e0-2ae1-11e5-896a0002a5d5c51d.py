import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Analysis summary:
# At 0x24217c: cmp w2 (param types) must be 7.
# At 0x2421a0: ldr x1,[x3]; ldr w2,[x3,#8]  -> reads memref ptr/size from p3 slot 0.
# Then bl 0x2b5a90 copies memory using the memref; if ok (w0==0) continues.
# At 0x242298: cmp w20,#0x105 -> cmd 0x105 (write 4 bytes into memref tail)
# At 0x2422a0: cmp w20,#0x1000 -> cmd 0x1000 (requires size >= 0xbc, writes a struct and calls 0x2439e8/0x243998/0x243948)
# Other cmds hit error path.
# Param types mask 7 = first param is memref, rest none.

@ta_init_function
def init_f13010e0_2ae1_11e5_896a0002a5d5c51d_0(state):
    # Command 0x1000: requires memref size >= 0xbc
    p3 = init_params(state)
    state.regs.x1 = 0x1000
    state.regs.x2 = 7
    place_sym_memref_param(state, p3, 0)
    # Constrain size to 0xbc to avoid state explosion while passing the check
    size_addr = p3 + 1 * 16 + 8
    size_val = state.memory.load(size_addr, 4, endness=state.arch.memory_endness)
    state.solver.add(size_val == 0xbc)
    return state

@ta_init_function
def init_f13010e0_2ae1_11e5_896a0002a5d5c51d_1(state):
    # Command 0x105: calls sub_23a230 with (ptr, size-4); ptr must be non-null
    p3 = init_params(state)
    state.regs.x1 = 0x105
    state.regs.x2 = 7
    place_sym_memref_param(state, p3, 0)
    # Constrain size to a reasonable value (>= 0x24 based on checks inside sub_23a230)
    size_addr = p3 + 1 * 16 + 8
    size_val = state.memory.load(size_addr, 4, endness=state.arch.memory_endness)
    state.solver.add(size_val == 0x24)
    return state

@ta_init_function
def init_f13010e0_2ae1_11e5_896a0002a5d5c51d_2(state):
    # Unknown/invalid command ID -> error path (0x2423b0)
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 7
    place_sym_memref_param(state, p3, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_f13010e0_2ae1_11e5_896a0002a5d5c51d_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

