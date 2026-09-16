import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis summary:
# TA_InvokeCommandEntryPoint at 0x1555c dispatches based on:
#   - w2 (param type mask). Only w2==0x67 takes the special branch that allocates
#     a 0x14-byte buffer and checks if caller is a specific identity via
#     TEE_GetPropertyAsIdentity; on success, further dispatch looks at:
#       * p3[0].ptr (buf_in), p3[0].size == 0x3d74
#       * p3[1].ptr (buf_out), p3[1].size == 0x3d74
#       * *buf_in first dword must equal 0xF0000000 (mov w9,#-0x10000000)
#     Then it calls sub_16940 (logging) and returns success.
#   - Otherwise, checks REE shared memory via TEES_IsREESharedMemory on both
#     memrefs; if either is REE shared, dispatches to a large command handler
#     which requires p3[0].size == 0x880 and p3[1].size == 0x880. Inside, it
#     dispatches on w21 (command id = w1) via sub_ba34, which at 0xbadc:
#       sub w8, w21, #0x200 ; cmp w8, #5 ; b.hi -> error (0x27)
#     so commands 0x200..0x205 are valid sub-commands via a jump table.
# Therefore we create inits for:
#   - command path via w2=0x67 (identity-gated branch)
#   - dispatcher path with w2 != 0x67 and sizes 0x880, for sub-cmds 0x200..0x205


def _setup_common(state):
    """Common setup: prepare p3 with two memref params."""
    p3 = init_params(state)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_0(state):
    # Path: w2 == 0x67 (identity branch). Requires p3[0].ptr, p3[0].size==0x3d74,
    # p3[1].ptr, p3[1].size==0x3d74, and *(uint32_t*)buf_in == 0xF0000000.
    p3 = init_params(state)

    # Allocate concrete-sized memrefs 
    # p3[0]: buf_in of size 0x3d74
    buf_in = state.heap.allocate(0x3d74)
    state.memory.store(p3 + 0, claripy.BVV(buf_in, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 8, claripy.BVV(0x3d74, 64), endness=state.arch.memory_endness)
    # First 4 bytes of buf_in must be 0xF0000000
    state.memory.store(buf_in, claripy.BVV(0xF0000000, 32), endness=state.arch.memory_endness)
    # Fill the rest symbolically (tainted)
    rest = get_tainted_mem_bits(state, (0x3d74 - 4) * 8)
    state.memory.store(buf_in + 4, rest)

    # p3[1]: buf_out of size 0x3d74
    buf_out = state.heap.allocate(0x3d74)
    state.memory.store(p3 + 16, claripy.BVV(buf_out, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 24, claripy.BVV(0x3d74, 64), endness=state.arch.memory_endness)
    buf_out_sym = get_tainted_mem_bits(state, 0x3d74 * 8)
    state.memory.store(buf_out, buf_out_sym)

    state.regs.x1 = claripy.BVV(0, 32)  # command id (not used on this path meaningfully)
    state.regs.x2 = claripy.BVV(0x67, 32)  # triggers identity branch
    return state


def _setup_dispatcher(state, subcmd):
    """Setup for the dispatcher path requiring sizes 0x880 and subcmd in w1 bits 0..9."""
    p3 = init_params(state)

    # p3[0]: buf_in of size 0x880
    buf_in = state.heap.allocate(0x880)
    state.memory.store(p3 + 0, claripy.BVV(buf_in, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 8, claripy.BVV(0x880, 64), endness=state.arch.memory_endness)
    buf_in_sym = get_tainted_mem_bits(state, 0x880 * 8)
    state.memory.store(buf_in, buf_in_sym)

    # p3[1]: buf_out of size 0x880
    buf_out = state.heap.allocate(0x880)
    state.memory.store(p3 + 16, claripy.BVV(buf_out, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 24, claripy.BVV(0x880, 64), endness=state.arch.memory_endness)
    buf_out_sym = get_tainted_mem_bits(state, 0x880 * 8)
    state.memory.store(buf_out, buf_out_sym)

    # w1 is the command id used by sub_ba34 (w21). Dispatcher expects 0x200..0x205.
    # Top bit must be clear (tbnz w21,#0x1f path is error), so just set concrete.
    state.regs.x1 = claripy.BVV(subcmd, 32)
    # w2 must NOT be 0x67. Use a plausible param-type mask for two memref-in/out.
    # 0x5555 covers typical memref in/out/inout combos seen in TAs; any non-0x67 works.
    state.regs.x2 = claripy.BVV(0x5555, 32)
    return state


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_1(state):
    # Dispatcher sub-command 0x200
    return _setup_dispatcher(state, 0x200)


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_2(state):
    # Dispatcher sub-command 0x201
    return _setup_dispatcher(state, 0x201)


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_3(state):
    # Dispatcher sub-command 0x202
    return _setup_dispatcher(state, 0x202)


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_4(state):
    # Dispatcher sub-command 0x203
    return _setup_dispatcher(state, 0x203)


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_5(state):
    # Dispatcher sub-command 0x204
    return _setup_dispatcher(state, 0x204)


@ta_init_function
def init_nnnnnnnn_nnnn_nnnn_nnnn_4d70536b566e_6(state):
    # Dispatcher sub-command 0x205
    return _setup_dispatcher(state, 0x205)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4d70536b566e_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

