import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA_InvokeCommandEntryPoint at 0xb554:
#   if (w2 != 0x65) -> error path (unsupported param type)
#   else: read p3[0].{ptr,size} (x1,x2 from [x3]) -> TEES_IsREESharedMemory check
#         if REE shm check fails -> error
#         else: load (x0,x1) = p3[0].{a,b}, (x2,x3) = p3[1].{a,b}... actually
#         ldp x0,x1,[x19]       -> p3[0].a (ptr), p3[0].b (size)
#         ldp x2,x3,[x19,#0x10] -> p3[1].a, p3[1].b
#         bl sub_efd8 (dispatcher in buffer)
#
# sub_efd8 reads first 0x20 bytes from the REE shared buffer as a header
# (via sub_dfxx -> uses the pointer x22=p3[0].ptr, x24=p3[0].size).
# Then dispatches on sub-command loaded from header at [sp+0x18] (w23 sub-cmd id).
# Sub-command values used in the handler table: 0..0x1f -> entries in table at 0x39228.
# Then further inside, w8 from header[sp+0x10] is used as opcode: 1,3,0x20, and inner w8 at [sp+0xc]: 1,2,0x100
#
# The TA parameter-type mask is 0x65 = TEEC_MEMREF_TEMP_INOUT? value 0x65 => mask bits
# Actually 0x65 = 0b01100101 means param0 = memref(5=TEMP_INPUT?) chain. We just set w2=0x65 and p3[0]=memref.
#
# To avoid state explosion from the huge symbolic header parsed in sub_efd8, we concretely
# constrain the command/sub-command fields to interesting values. We provide separate inits
# for the outer command (header[sub_cmd]) and the inner opcodes.

CMD_PARAM_TYPE = 0x65

def _setup_common(state):
    p3 = init_params(state)
    state.regs.x2 = claripy.BVV(CMD_PARAM_TYPE, 64)
    # p3[0] memref: the REE shared buffer (input command buffer)
    place_sym_memref_param(state, p3, 0)
    # p3[1] value: output params
    place_sym_value_param(state, p3, 1)
    return p3


def _make_buf_with_header(state, sub_cmd, opcode=None, inner=None, size=0x200):
    # Allocate a symbolic buffer representing the REE shared memory content.
    buf_bits = get_tainted_mem_bits(state, size * 8)
    buf_addr = state.heap.allocate(size) if hasattr(state, "heap") else None
    # Simpler: write symbolic bytes into a fresh memory region via state.solver
    # Use angr's state.memory with a claripy symbol stored at an address we choose.
    # Find free address via state.heap._malloc if available
    try:
        addr = state.heap._malloc(size)
    except Exception:
        # Fallback: use a fixed high address
        addr = 0x70000000
    state.memory.store(addr, buf_bits, endness="Iex_Endian_LE")

    # Constrain header fields to avoid state explosion.
    # Based on disassembly of sub_efd8:
    #   header at [sp+8..sp+0x28] (0x20 bytes) copied from buf
    #   [sp+0x18] -> sub-command id (w23) used as table index (0..0x1f)
    #   [sp+0x10] -> opcode (1, 3, 0x20) checked later
    #   [sp+0xc]  -> inner opcode (1, 2, 0x100)
    # These offsets map into the REE buffer starting at some offset; we constrain
    # the whole first 0x20 bytes to a concrete pattern.

    # Write concrete header bytes covering first 0x20 bytes
    # Use best-effort constants at plausible offsets.
    if sub_cmd is not None:
        state.memory.store(addr + 0x10, claripy.BVV(sub_cmd & 0xFFFFFFFF, 32), endness="Iex_Endian_LE")
    if opcode is not None:
        state.memory.store(addr + 0x08, claripy.BVV(opcode & 0xFFFFFFFF, 32), endness="Iex_Endian_LE")
    if inner is not None:
        state.memory.store(addr + 0x04, claripy.BVV(inner & 0xFFFFFFFF, 32), endness="Iex_Endian_LE")

    return addr, size


def _point_p3_memref_to(state, p3, index, addr, size):
    # Overwrite memref slot (ptr,size) at p3 slot index.
    word = 8  # AArch64
    slot_off = index * 2 * word
    state.memory.store(p3 + slot_off, claripy.BVV(addr, 64), endness="Iex_Endian_LE")
    state.memory.store(p3 + slot_off + word, claripy.BVV(size, 64), endness="Iex_Endian_LE")


# --- Initial/dispatch-level paths ---

@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_0(state):
    # Wrong param-type path (w2 != 0x65) -> early error return
    p3 = init_params(state)
    state.regs.x2 = claripy.BVV(0x0, 64)
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_1(state):
    # Correct param type but REE shared memory check fails -> error branch
    p3 = _setup_common(state)
    # Leave buffer symbolic; TEES_IsREESharedMemory may return 0 (fail).
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_2(state):
    # Dispatcher: sub_cmd = 0 (first table entry), opcode=1, inner=1
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=0, opcode=1, inner=1)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_3(state):
    # Dispatcher: sub_cmd = 1, opcode=1, inner=1
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=1, opcode=1, inner=1)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_4(state):
    # Dispatcher: sub_cmd = 2, opcode=3 (triggers different branch), inner=1
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=2, opcode=3, inner=1)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_5(state):
    # Dispatcher: sub_cmd = 3, opcode=0x20, inner=0x100 (alt path in inner dispatcher)
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=3, opcode=0x20, inner=0x100)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_6(state):
    # Dispatcher: sub_cmd = 4, opcode=1, inner=2
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=4, opcode=1, inner=2)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state


@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_ta_7(state):
    # Out-of-range sub_cmd (>=0x1f) -> default/error path
    p3 = _setup_common(state)
    addr, size = _make_buf_with_header(state, sub_cmd=0x1f, opcode=1, inner=1)
    _point_p3_memref_to(state, p3, 0, addr, size)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4662436b6d52_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

