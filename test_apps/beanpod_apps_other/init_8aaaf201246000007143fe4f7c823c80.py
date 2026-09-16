import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA dispatch summary (from TA_InvokeCommandEntryPoint at 0x95f8):
# - r2 (param types) must be 0x65 => slot0 = MEMREF_INPUT (5), slot1 = MEMREF_OUTPUT (6)
# - p3[0].size == 0x1000 and p3[1].size == 0x1000
# - r1 (cmd id) dispatched values observed:
#   0x9001 -> handler at 0x9990
#   0x9002 -> handler at 0x9844 (r3==0x1000 path => 0x9844 via 0x982c branch where r3 = 0x1000+2 => 0x9002? Actually 0x982c: r3=r3-0x1000=0, +3 => 0x9003? Let's re-check.)
#   Actually: 0x982c: r3 (was 0x1000) sub 0x1000 -> 0, cmp r5,r3 => r5==0 ? no. Then add 3 -> r3=3, cmp r5,3 => r5==3 path. So this checks values 0 and 3 — but with r3 starting from 0x1000 these are 0x1000 (TEE_SUCCESS check?) Hmm. Actually r3 starts as 0x1000 from prior block; sub 0x1000 makes it 0; r5 cmp 0 -> branch 0x9bc4 (a "set flag" no-op-ish handler). add 3 -> r5 cmp 3 -> branch 0x9844 (handler).
#   So cmd ids that dispatch via this branch: 0 and 3 (small ids). Hmm but those are checked via subtracting 0x1000 from r3, but r5 is still the original cmd id. So r5 ∈ {0, 3}.
#   Other ids: 0x9001, 0x9003, 0x9005, 0x9006, 0x9007, 0x9101, 0x9103, 0x9201 (0x9103+0xfe=0x9201)
#   Also 0x982c branch is reached when r5 < 0x9001 (bls #0x982c). The compared values there
#   are r3 = 0x1000-0x1000 = 0 and 3. So additional cmd ids are 0 (0x9bc4 small "init" path)
#   and 3 (0x9844 handler).
# - Default (unknown cmd id) falls through to 0x9bf8 -> sub_f540 (state-machine dispatcher
#   based on session->cmd field at sb[0]).

TA_NAME = "8aaaf201246000007143fe4f7c823c80"


def _setup_common(state):
    """Common setup: param_types=0x65, slot0/slot1 memrefs with size 0x1000."""
    p3 = init_params(state)
    # param types mask: slot0 MEMREF_INPUT(5), slot1 MEMREF_OUTPUT(6)
    state.regs.r2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Set sizes to 0x1000 as required by checks at 0x96e0..0x96f4
    # p3 layout (32-bit): slot i memref => ptr at p3+i*8, size at p3+i*8+4
    state.memory.store(p3 + 0 * 8 + 4, claripy.BVV(0x1000, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 8 + 4, claripy.BVV(0x1000, 32), endness=state.arch.memory_endness)
    return p3


# ---------------- Command 0x9001: parse/handle (sub_b2bc) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_0(state):
    _setup_common(state)
    state.regs.r1 = 0x9001
    return state


# ---------------- Command 0x9003 (sub_a88c-like trampoline at 0x9c3c) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_1(state):
    _setup_common(state)
    state.regs.r1 = 0x9003
    return state


# ---------------- Command 0x9005: digest/CheckMemoryAccess (0x9940) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_2(state):
    _setup_common(state)
    state.regs.r1 = 0x9005
    return state


# ---------------- Command 0x9006: sub_b13c (0x99f0) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_3(state):
    _setup_common(state)
    state.regs.r1 = 0x9006
    return state


# ---------------- Command 0x9007: handler at 0x9730 (sub_b6b8) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_4(state):
    _setup_common(state)
    state.regs.r1 = 0x9007
    return state


# ---------------- Command 0x9101: sub_11f4c (0x9a38) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_5(state):
    _setup_common(state)
    state.regs.r1 = 0x9101
    return state


# ---------------- Command 0x9103: sub_12cc0 (0x9b64) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_6(state):
    _setup_common(state)
    state.regs.r1 = 0x9103
    return state


# ---------------- Command 0x9102 (between 0x9101 and 0x9103): sub_12098 (0x9b04) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_7(state):
    _setup_common(state)
    state.regs.r1 = 0x9102
    return state


# ---------------- Command 0x9201 (0x9103 + 0xfe): sub_12934 (0x97a0->0x97cc) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_8(state):
    _setup_common(state)
    state.regs.r1 = 0x9201
    return state


# ---------------- Command 0x0000: small "init" handler at 0x9bc4 (sets flag) ----------------
# This sets r8[0x10]=1 (a state flag). May be a prerequisite for stateful follow-ups.
# Mark as chain entry that can lead to other commands.
@ta_init_function(next_funcs=[
    "init_8aaaf201246000007143fe4f7c823c80_0",
    "init_8aaaf201246000007143fe4f7c823c80_1",
    "init_8aaaf201246000007143fe4f7c823c80_4",
])
def init_8aaaf201246000007143fe4f7c823c80_9(state):
    _setup_common(state)
    state.regs.r1 = 0x0
    return state


# ---------------- Command 0x0003: sub_11d98 handler (0x9844) ----------------
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_10(state):
    _setup_common(state)
    state.regs.r1 = 0x3
    return state


# ---------------- Default fallthrough: sub_f540 internal state-machine dispatcher ----------------
# sub_f540 dispatches based on session->cmd (sb[0]) where sb is the input memref buffer.
# The first 4 bytes of slot0 buffer indicate which sub-command (0xA001..0xA007 via jump table).
# We emit several inits for distinct sub-commands, using cmd id that falls through to default
# (e.g. 0x9999) so it reaches sub_f540 at 0x9bf8.

def _default_fallthrough(state, subcmd_value):
    p3 = _setup_common(state)
    # Use an unrecognized cmd id (not in {0x9001..0x9007, 0x9101..0x9103, 0x9201, 0, 3})
    state.regs.r1 = 0x9999
    # Read slot0 buffer pointer (p3[0].ptr) and write the sub-command as first 4 bytes.
    buf_ptr = state.memory.load(p3 + 0, 4, endness=state.arch.memory_endness)
    state.memory.store(buf_ptr, claripy.BVV(subcmd_value, 32), endness=state.arch.memory_endness)
    return state


# sub_f540 dispatch table (r3 = *sb - 0xa000 - 1; cases 0..6 => 0xa001..0xa007 conceptually)
# We map each table index to a separate init.
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_11(state):
    # Case 0 (cmd 0xa001): leads to sub_10044 (key gen?) sets state[0]=2
    return _default_fallthrough(state, 0xA001)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_12(state):
    # Case 1 (cmd 0xa002): sub_10084 - requires state[0]==2 (set by case 0 above)
    return _default_fallthrough(state, 0xA002)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_13(state):
    # Case 2 (cmd 0xa003): sub_102f4
    return _default_fallthrough(state, 0xA003)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_14(state):
    # Case 3 (cmd 0xa004): sub_10b4c - requires state[0]==3
    return _default_fallthrough(state, 0xA004)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_15(state):
    # Case 4 (cmd 0xa005): sub_10cd4 / sub_10e3c - requires state[0]==4
    return _default_fallthrough(state, 0xA005)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_16(state):
    # Case 5 (cmd 0xa006): sub_1070c - requires state[0]==2
    return _default_fallthrough(state, 0xA006)


@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_17(state):
    # Case 6 (cmd 0xa007): handler (probably init/reset)
    return _default_fallthrough(state, 0xA007)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_8aaaf201246000007143fe4f7c823c80_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

