import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA: e97c270ea5c44c58bcd3384a2fa2539e
# Analysis:
# - InvokeCommandEntryPoint at 0x9d49 enforces:
#     cmd_id (r1) == 0
#     param_types (r2) == 0x177
#     Then loads p3 as struct with memref-like layout:
#       p3[0..3] = value_a (treated as ptr), p3[4..7] = value_b (treated as size), p3[8..11] = ptr, p3[12..15] = size
#       p3[0xc] = a size field that must be <= 0x8800
# - Then dispatches to a large opcode-driven handler (sub_a8f5) which reads an opcode from internal state
#   read via TEE_ReadObjectData-like calls. The opcode dispatch (cmp r0,#x with many constants) selects
#   one of ~100 sub-commands. The opcode comes from the buffer pointed to by p3 ([sp,#0x70] after parse).
# - 0x177 == 0x177; decoding nibbles: 7,7,1,0 -> slot0=MEMREF_INOUT(7), slot1=MEMREF_INOUT(7),
#   slot2=VALUE_INPUT(1), slot3=NONE. We set p3 accordingly.
#
# Since there are ~100+ opcodes and the dispatcher reads opcode from a deserialized buffer, we provide
# a single generic init that lets the engine explore opcode space symbolically but constrains the
# size field to a small value to prevent explosion. Without clear stateful key/session dependencies
# visible at the InvokeCommand layer (state is mostly internal command-buffer driven), we emit one
# init function.

@ta_init_function
def init_e97c270ea5c44c58bcd3384a2fa2539e_0(state):
    p3 = init_params(state)
    # GP ABI: r1 = cmd_id, r2 = param_types mask
    state.regs.r1 = claripy.BVV(0x0, 32)
    state.regs.r2 = claripy.BVV(0x177, 32)
    # slot 0: MEMREF_INOUT (7) - input command buffer
    place_sym_memref_param(state, p3, 0)
    # slot 1: MEMREF_INOUT (7) - output buffer
    place_sym_memref_param(state, p3, 1)
    # slot 2: VALUE_INPUT (1)
    place_sym_value_param(state, p3, 2)
    # Constrain the size field at p3[0xc] (slot1 size) to be small to avoid huge buffer/explosion;
    # The TA checks size <= 0x8800. Constrain it to a small value.
    # p3 slot1 size lives at p3 + 1*8 + 4 = p3 + 12 on 32-bit
    word_size = state.arch.bytes
    slot1_size_addr = p3 + 1 * 2 * word_size + word_size
    size_val = state.memory.load(slot1_size_addr, word_size, endness=state.arch.memory_endness)
    state.solver.add(size_val > 0)
    state.solver.add(size_val <= 0x100)
    # Also constrain slot0 size similarly (input cmd buffer)
    slot0_size_addr = p3 + 0 * 2 * word_size + word_size
    size0_val = state.memory.load(slot0_size_addr, word_size, endness=state.arch.memory_endness)
    state.solver.add(size0_val > 0)
    state.solver.add(size0_val <= 0x100)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_e97c270ea5c44c58bcd3384a2fa2539e_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

