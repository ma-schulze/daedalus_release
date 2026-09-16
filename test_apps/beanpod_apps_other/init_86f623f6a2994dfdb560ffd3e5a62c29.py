import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# TA dispatch summary:
# - r2 must equal 0x65 (MEMREF_INPUT in slot0, MEMREF_OUTPUT in slot1)
# - After param_type check, reads p3[0] (memref input) ptr/size into r1/r2,
#   and p3[1] (memref output) ptr/size into r1/r2 for TEE_CheckMemoryAccessRights.
# - Then dispatches on r1 (command id, command upper byte 0xff also has special handling)
#   For r5 high byte == 0xff00: ldmib r4, {r1,r2,r3} (reads from p3[0].size,p3[1].ptr,p3[1].size)
#   and ip = [r4] (p3[0].ptr). Then dispatches on full r5 value.
# - Else, checks p3[0].size == 0x1008 -> sub-branch with check on p3[1].ptr == p3[0].size
#   and reads input[0] (uint32) and compares to 3.
#
# Commands (when r5 high byte != 0xff):
#   r5 == 0x1008 && input[0] == 3: stateful "save state" type command (0x9988)
# Commands (when r5 high byte == 0xff or matched table):
#   0xb001 -> 0x9928 (some teardown)
#   0xff03 -> 0xce94
#   0xf600 -> 0x10f50
#   0xff01 -> 0xc874
#   0xff02 -> 0xcbcc
#   0x2114 -> 0x11584
#   0x102  -> 0xadd4 (generate/save key)
#   0x300  -> 0xc5d4
#   0x0    -> 0x1015c
#   0xff05 -> 0xd454
#   0xff06 -> 0xd530
#   0xff07 -> 0xd368
#   0x2115 -> 0x115b0
#   0xa000-0xa001 -> error
#   0xb000 -> success
#   0xf002 -> 0x10190
#
# Dependencies:
# - 0x102 (adds key/store) should precede commands that use stored data (e.g. 0xff03, 0xff05, 0xff06, 0xff07, 0xf002, 0x300, 0x2114, 0x2115, 0xf600)
# - 0x0 (init flag-like) seems independent
# - 0x1008-path also depends on something providing state

PARAM_TYPES_65 = 0x65  # MEMREF_INPUT(slot0=5) | MEMREF_OUTPUT(slot1=6)


def _setup_common(state):
    p3 = init_params(state)
    state.regs.r2 = PARAM_TYPES_65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


# ---------- "key generation / store" — likely prerequisite ----------
@ta_init_function(next_funcs=[
    "init_ta_1", "init_ta_2", "init_ta_3", "init_ta_4",
    "init_ta_5", "init_ta_6", "init_ta_7", "init_ta_8",
    "init_ta_9", "init_ta_10", "init_ta_11", "init_ta_12",
    "init_ta_13", "init_ta_14", "init_ta_15",
])
def init_ta_0(state):
    # CMD 0x102 -> sub_adda: generates random + stores object (key seed)
    _setup_common(state)
    state.regs.r1 = 0x102
    return state


# ---------- CMD 0 ----------
@ta_init_function
def init_ta_1(state):
    _setup_common(state)
    state.regs.r1 = 0x0
    return state


# ---------- CMD 0xb000: trivial success ----------
@ta_init_function
def init_ta_2(state):
    _setup_common(state)
    state.regs.r1 = 0xb000
    return state


# ---------- CMD 0xb001: teardown ----------
@ta_init_function
def init_ta_3(state):
    _setup_common(state)
    state.regs.r1 = 0xb001
    return state


# ---------- CMD 0xff01 -> 0xc874 (depends on stored state) ----------
@ta_init_function
def init_ta_4(state):
    _setup_common(state)
    state.regs.r1 = 0xff01
    return state


# ---------- CMD 0xff02 -> 0xcbcc ----------
@ta_init_function
def init_ta_5(state):
    _setup_common(state)
    state.regs.r1 = 0xff02
    return state


# ---------- CMD 0xff03 -> 0xce94 ----------
@ta_init_function
def init_ta_6(state):
    _setup_common(state)
    state.regs.r1 = 0xff03
    return state


# ---------- CMD 0xff05 -> 0xd454 ----------
@ta_init_function
def init_ta_7(state):
    _setup_common(state)
    state.regs.r1 = 0xff05
    return state


# ---------- CMD 0xff06 -> 0xd530 ----------
@ta_init_function
def init_ta_8(state):
    _setup_common(state)
    state.regs.r1 = 0xff06
    return state


# ---------- CMD 0xff07 -> 0xd368 ----------
@ta_init_function
def init_ta_9(state):
    _setup_common(state)
    state.regs.r1 = 0xff07
    return state


# ---------- CMD 0xf600 -> 0x10f50 ----------
@ta_init_function
def init_ta_10(state):
    _setup_common(state)
    state.regs.r1 = 0xf600
    return state


# ---------- CMD 0xf002 -> 0x10190 ----------
@ta_init_function
def init_ta_11(state):
    _setup_common(state)
    state.regs.r1 = 0xf002
    return state


# ---------- CMD 0x300 -> 0xc5d4 ----------
@ta_init_function
def init_ta_12(state):
    _setup_common(state)
    state.regs.r1 = 0x300
    return state


# ---------- CMD 0x2114 -> 0x11584 ----------
@ta_init_function
def init_ta_13(state):
    _setup_common(state)
    state.regs.r1 = 0x2114
    return state


# ---------- CMD 0x2115 -> 0x115b0 ----------
@ta_init_function
def init_ta_14(state):
    _setup_common(state)
    state.regs.r1 = 0x2115
    return state


# ---------- CMD with r5 == 0x1008 path: requires memref input size == 0x1008 and value 3 ----------
# At 0x9650: cmp r3, #0x1008; r3 = [r4+4] = p3[0].size
# At 0x975c: cmp r1, r3 where r1 = [r4+0xc] = p3[1].size; both must equal 0x1008.
# Then at 0x976c: ldr r3, [r0]; r0 = [r4] (p3[0].ptr); the first dword must be 3.
@ta_init_function
def init_ta_15(state):
    p3 = init_params(state)
    state.regs.r2 = PARAM_TYPES_65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)

    # r1 here is the command id used in dispatch; high byte != 0xff so we
    # pick a value that hits the 0x1008-size path (and isn't in upper-byte 0xff*).
    # The code reads r5 (=cmd) only on the "ff00" branch; this branch is taken when
    # (r5 & 0xff00) != 0xff00. Use any non-0xff** cmd, e.g. 0x1000.
    state.regs.r1 = 0x1000

    # p3[0].size = p3[1].size = 0x1008
    word = 4
    p3_int = state.solver.eval(p3)
    # slot0: ptr at p3+0, size at p3+4
    slot0_size_addr = p3_int + word
    slot1_ptr_addr = p3_int + 2 * word
    slot1_size_addr = p3_int + 3 * word
    slot0_ptr_addr = p3_int + 0

    state.memory.store(slot0_size_addr, claripy.BVV(0x1008, 32), endness=state.arch.memory_endness)
    state.memory.store(slot1_size_addr, claripy.BVV(0x1008, 32), endness=state.arch.memory_endness)

    # Make ptr at slot0 point to a known buffer where first dword == 3
    # Use a tainted buffer for content beyond first dword.
    from explorer.memory.ta_taint import get_tainted_mem_bits
    buf_addr = 0x70000000
    # write 3 as first dword
    state.memory.store(buf_addr, claripy.BVV(3, 32), endness=state.arch.memory_endness)
    # rest of buffer symbolic
    sym_rest = get_tainted_mem_bits(state, (0x1008 - 4) * 8)
    state.memory.store(buf_addr + 4, sym_rest)
    state.memory.store(slot0_ptr_addr, claripy.BVV(buf_addr, 32), endness=state.arch.memory_endness)

    # slot1 ptr: separate buffer
    out_buf = 0x70010000
    state.memory.store(slot1_ptr_addr, claripy.BVV(out_buf, 32), endness=state.arch.memory_endness)

    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_86f623f6a2994dfdb560ffd3e5a62c29_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

