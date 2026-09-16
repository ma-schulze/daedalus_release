import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# TA dispatch summary (command id read from *p3[0], i.e. r5 = *r3; cmd = *r5):
#   0x1001 -> sub_b088 (uses memref param at slot 2: r6 = p3[2] ptr/size)
#   0x1002 -> sub_a570 (uses memref param at slot 2)
#   0x1004 -> sub_a63c (uses memref param at slot 2)
#   0x1006 -> sub_bе58 (uses memref params slot 0/1/2)
#   0x1007 -> sub_c318 (uses memref params 0/1/2)
#   0x1008 -> sub_caa4 (memref param slot 2)
#   0x1009 -> sub_c9b4 (memref params)
#   0x100b -> sub_b7f8 (memref params)
#   0x2001 -> sub_d8a8 (overall TA init/keygen flow)
#   0x2002 -> sub_aa14/sub_ab44 (enable feature A)
#   0x2003 -> sub_aa14/sub_ab44 (enable feature B)
#   0x2004 -> sub_ac80 (uses encrypted state - dependent on 0x2001)
#   0x2005 -> sub_a9a4 (random test)
#   0x2006 -> sub_a76c (verify various stored items - dependent on 0x2001)
#   0x2007 -> sub_b260 (uses encrypted state - dependent on 0x2001)
#
# Memory layout used by entry code:
#   r4 = p3 (param array pointer)
#   r5 = *r4         -> pointer to a struct; *r5 is the command id (32-bit)
#   ip = r4[1]       -> a small length-like value (used for sub r7, ip, #4 etc.)
#   r6 = r4[2]       -> pointer used as memref/output buffer
# So the TA reads pointers from p3 slots 0, 1, 2. We allocate a tainted buffer
# at slot0 whose first dword is the command ID, and use place_sym_memref_param
# for slot 2 (output buffer) and slot 1 (small value).

from explorer.memory.ta_taint import get_tainted_mem_bits


def _setup_common(state, cmd_id):
    """Set up p3 so that *p3[0] points to a buffer whose first dword == cmd_id.
    p3[1] holds a small integer (ip), p3[2] is a memref output buffer."""
    p3 = init_params(state)
    # slot 0: pointer to a structure whose first word is the command id
    word = 4
    # Allocate a small tainted buffer for the command-id struct
    cmd_struct_addr = 0x70000000  # arbitrary scratch addr
    # Make first word concrete = cmd_id
    state.memory.store(cmd_struct_addr, claripy.BVV(cmd_id, 32), endness=state.arch.memory_endness)
    # remaining bytes symbolic/tainted
    sym_rest = get_tainted_mem_bits(state, 0x100 * 8)
    state.memory.store(cmd_struct_addr + 4, sym_rest)
    # write pointer into p3 slot 0 (memref ptr)
    state.memory.store(p3 + 0, claripy.BVV(cmd_struct_addr, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + word, claripy.BVV(0x100, 32), endness=state.arch.memory_endness)
    # slot 1: small ip value; entry computes r7=ip-4, r8=ip-8. Keep it small.
    ip_val_addr = 0x70001000
    state.memory.store(ip_val_addr, claripy.BVV(0x40, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + 2 * word, claripy.BVV(ip_val_addr, 32), endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * word, claripy.BVV(0x40, 32), endness=state.arch.memory_endness)
    # slot 2: memref output buffer
    place_sym_memref_param(state, p3, 2)
    # slot 3: leave NONE / value
    return p3


# ---- Command 0x2001: init/key-generation. Must run before stateful cmds. ----
@ta_init_function(next_funcs=[
    "init_df1edda8627911e980ae507b9d9a7e7d_ta_1",
    "init_df1edda8627911e980ae507b9d9a7e7d_ta_2",
    "init_df1edda8627911e980ae507b9d9a7e7d_ta_3",
    "init_df1edda8627911e980ae507b9d9a7e7d_ta_4",
])
def init_df1edda8627911e980ae507b9d9a7e7d_ta_0(state):
    _setup_common(state, 0x2001)
    return state


# ---- 0x2004: depends on 0x2001 (encrypted state present) ----
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_1(state):
    _setup_common(state, 0x2004)
    return state


# ---- 0x2006: depends on 0x2001 ----
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_2(state):
    _setup_common(state, 0x2006)
    return state


# ---- 0x2007: depends on 0x2001 ----
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_3(state):
    _setup_common(state, 0x2007)
    return state


# ---- 0x1006 / 0x1007 / 0x100b: memref-based crypto ops, likely after 0x2001 ----
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_4(state):
    _setup_common(state, 0x100b)
    return state


# ---- Standalone commands ----
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_5(state):
    _setup_common(state, 0x1001)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_6(state):
    _setup_common(state, 0x1002)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_7(state):
    _setup_common(state, 0x1004)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_8(state):
    _setup_common(state, 0x1006)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_9(state):
    _setup_common(state, 0x1007)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_10(state):
    _setup_common(state, 0x1008)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_11(state):
    _setup_common(state, 0x1009)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_12(state):
    _setup_common(state, 0x2002)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_13(state):
    _setup_common(state, 0x2003)
    return state


@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_ta_14(state):
    _setup_common(state, 0x2005)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_df1edda8627911e980ae507b9d9a7e7d_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

