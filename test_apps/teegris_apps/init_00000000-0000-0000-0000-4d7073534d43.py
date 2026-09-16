import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA analysis summary (00000000-0000-0000-0000-4d7073534d43 / "MpsSMC"):
#
# TA_InvokeCommandEntryPoint behavior:
# - If command_id (w2) == 0x67 : special path that allocates 0x14 buffer and calls
#   TEE_GetPropertyAsIdentity; on success it reads a 4-byte "magic" from the allocated
#   buffer at offset 0 and dispatches:
#     * magic == 0xF0000000 : "install/setup" path that copies memrefs from p3[0] and p3[2]
#       (both must have size 0x3D74) into internal state and calls sub_172fc.
#     * otherwise           : "verify/use" path that requires p3[0] and p3[2] to be REE
#       shared memory with size 0x4040 and then does signature verification workflow.
# - Any other command ID goes to an error path that logs "unknown cmd" and returns
#   TEE_ERROR_NOT_SUPPORTED.
#
# Note: w2 here is actually the command ID register (this TA's ABI is unusual: it uses
# w2 as the command selector instead of w1 — confirmed by the `cmp w19, #0x67` where
# w19 = w2 at entry).
#
# Dependencies:
# - The "verify" path (magic != 0xF0000000, size 0x4040) uses internal state populated
#   by the "install" path. So init the install path first, then the verify path.


# ---------------------------------------------------------------------------
# Command 0x67 — install/setup path (magic = 0xF0000000, sizes 0x3D74)
# This path sets up internal state used by the verify path.
# ---------------------------------------------------------------------------
@ta_init_function(next_func="init_MpsSMC_1")
def init_MpsSMC_0(state):
    p3 = init_params(state)

    # Command ID in w2 (this TA uses x2 as command selector)
    state.regs.x2 = 0x67
    # w1 may be used as a sub-parameter; keep symbolic/concrete small
    state.regs.x1 = 0x1

    # p3[0]: memref with size 0x3D74
    place_sym_memref_param(state, p3, 0)
    # p3[1]: unused by this path but present in layout
    place_sym_value_param(state, p3, 1)
    # p3[2]: memref with size 0x3D74
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    # Force sizes to the expected 0x3D74 for slots 0 and 2
    word = 8
    size0_addr = p3 + 0 * 2 * word + word
    size2_addr = p3 + 2 * 2 * word + word
    state.memory.store(size0_addr, claripy.BVV(0x3D74, 64), endness=state.arch.memory_endness)
    state.memory.store(size2_addr, claripy.BVV(0x3D74, 64), endness=state.arch.memory_endness)

    return state


# ---------------------------------------------------------------------------
# Command 0x67 — verify/use path (magic != 0xF0000000, sizes 0x4040)
# Depends on state populated by the install path above.
# ---------------------------------------------------------------------------
@ta_init_function
def init_MpsSMC_1(state):
    p3 = init_params(state)

    state.regs.x2 = 0x67
    state.regs.x1 = 0x1

    # p3[0] and p3[2] are memrefs with size 0x4040; they must be REE shared memory
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    word = 8
    size0_addr = p3 + 0 * 2 * word + word
    size2_addr = p3 + 2 * 2 * word + word
    state.memory.store(size0_addr, claripy.BVV(0x4040, 64), endness=state.arch.memory_endness)
    state.memory.store(size2_addr, claripy.BVV(0x4040, 64), endness=state.arch.memory_endness)

    # Constrain the "magic" / first dword of the buffer pointed to by the TEE_Malloc'd
    # identity buffer path is internal — not directly controllable from here.
    # The dispatch in this path depends on what's read back from the identity-buffer.
    # We leave it symbolic but constrain the first 4 bytes of p3[0]'s buffer to a small
    # set to avoid state explosion in subsequent crypto helpers.
    ptr0 = state.memory.load(p3 + 0 * 2 * word, word, endness=state.arch.memory_endness)
    # Constrain the first byte to a printable/small range to reduce explosion in parser loops
    b0 = state.memory.load(ptr0, 1)
    state.solver.add(claripy.Or(b0 == 0x7B, b0 == 0x22, b0 == 0x30))  # '{', '"', '0'

    return state


# ---------------------------------------------------------------------------
# Any other command ID -> NOT_SUPPORTED error path.
# Included for coverage of the default/error dispatch branch.
# ---------------------------------------------------------------------------
@ta_init_function
def init_MpsSMC_2(state):
    p3 = init_params(state)

    # A non-0x67 command id hits the "cmd not supported" branch
    state.regs.x2 = 0x1
    state.regs.x1 = 0x0

    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4d7073534d43_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

