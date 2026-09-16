
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# Analysis summary:
# TA_InvokeCommandEntryPoint at 0xe1fc
# - Does NOT look at x1 (command ID) for dispatch.
# - Dispatches based on:
#     * param type mask in x2: low nibble must be 7 (memref input at slot 0)
#     * first check at slot 0: memref->size (p3[0].b) must equal 0x21c7d
#     * TEES_IsREESharedMemory(1, 0x21c7d) must succeed => goes to sub_e778 path
#     * then checks upper nibble of x2 (w22 & 0xf0 == 0x70) => memref at slot 1
#     * slot 1 size (p3[1].b) must equal 0x20936
# - Two observable "semantic" paths:
#     Path A (cmd_a): sub_13970 (parse/load big blob from p3[0].a into internal state) then
#                     sub_14898 applies the loaded state using p3[1] info.
#                     sub_13970 is the "load/set" stateful op that must run first to populate state.
#     Path B (cmd_b): sub_12d2c (finalize/operate on loaded state) then sub_14898.
#
# Actually both paths always invoke sub_13970 first (which populates internal state),
# then sub_12d2c, then sub_14898. But sub_13970 can take a shortcut when w0(sub_e778)==0
# producing different semantic results. We provide one init as the primary path.
#
# The TA is heavily stateful. sub_13970 reads a large structured blob from p3[0].a.
# To avoid state-space explosion we constrain the leading "type" byte at p3[0].a[0] == 1
# (required at 0x139b4) and we constrain the memref sizes concretely.
#
# Critical constraints to reduce state explosion:
# - Force p3[0].a[0] = 1 (matches cmp w4, #1 at 0x139b4)
# - Force p3[0].size = 0x21c7d (mandatory)
# - Force p3[1].size = 0x20936 (mandatory)
# - Constrain w22 param type: low nibble 7, high nibble 7 => 0x77 works

TA_NAME = "00000000-0000-0000-0000-656e676d6f64"


def _common_setup(state):
    p3 = init_params(state)
    # param types: low nibble == 7 (memref input at slot 0), high nibble == 7 (memref input at slot 1)
    # Use the GP TEE_PARAM_TYPES encoding observed by w22 checks.
    state.regs.x2 = 0x77
    # r1 (cmd id) is unused by this TA; set to 0 to avoid randomness.
    state.regs.x1 = 0x0

    # Slot 0: memref with size == 0x21c7d
    place_sym_memref_param(state, p3, 0)
    # Overwrite slot 0 size to required constant
    word = 8
    slot0_size_addr = p3 + 0 * 2 * word + word
    state.memory.store(slot0_size_addr, claripy.BVV(0x21c7d, 64), endness=state.arch.memory_endness)

    # Slot 1: memref with size == 0x20936
    place_sym_memref_param(state, p3, 1)
    slot1_size_addr = p3 + 1 * 2 * word + word
    state.memory.store(slot1_size_addr, claripy.BVV(0x20936, 64), endness=state.arch.memory_endness)

    # Constrain the first byte of the buffer pointed to by slot 0 (p3[0].a)
    # to value 1, to force taking the main branch at 0x139b4 (cmp w4, #1).
    slot0_ptr_addr = p3 + 0 * 2 * word
    slot0_ptr = state.memory.load(slot0_ptr_addr, word, endness=state.arch.memory_endness)
    # Store a concrete 1 at the first byte of that buffer to prune other branches.
    state.memory.store(slot0_ptr, claripy.BVV(1, 8))

    return state


@ta_init_function
def init_00000000_0000_0000_0000_656e676d6f64_0(state):
    # Primary path: load big structured blob via sub_13970, then sub_12d2c, then sub_14898.
    # This is the main semantic command exposed by TA_InvokeCommandEntryPoint.
    state = _common_setup(state)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_656e676d6f64_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

