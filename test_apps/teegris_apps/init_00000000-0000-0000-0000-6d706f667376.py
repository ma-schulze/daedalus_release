
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function


# Analysis summary:
# TA_InvokeCommandEntryPoint at 0x15c10:
# - x1 = cmdID, x2 = param types, x3 = p3
# - If x2 == 0x67: special path (TEE_Malloc + TEE_GetPropertyAsIdentity check) -> command 0x67
# - Else: reads first word from malloc'd buffer; if == 0xf0000000 then
#     requires p3[0].memref(ptr!=0), p3[1].memref(ptr!=0), sizes == 0x3d74
#     -> calls sub_17000 (generic handler)
# - Else: checks TEES_IsREESharedMemory for p3[0] (size 3) and p3[1] (size 2);
#     if both REE shm, proceeds to the key-mgmt block at 0x15eec:
#       requires p3[0].size == 0x880, p3[1].size == 0x880
#       tbnz x21 (cmdID) bit 31 -> different code path; else normal flow
#       calls sub_c12c with cmdID-0x200 in range [0..5] dispatching multiple sub-commands
#
# The sub_c12c dispatches on (cmdID - 0x200) in range 0..5 (6 commands).
# These are the core commands. They use keys/state set up by prior calls.
#
# We will enumerate command IDs:
#   0x67        -> property identity path
#   generic(*)  -> cmdID with first-word-of-session-buffer == 0xf0000000 (session-based)
#   0x200..0x205 -> sub_c12c dispatch table
#   negative cmd (bit 31 set) -> admin path at 0x16124
#
# The 0x200..0x205 commands are likely: init_key, store_key, load_key, encrypt, decrypt, delete
# Dependencies: encrypt/decrypt depend on init+store. We chain a likely order.


def _setup_common_params(state, cmd_id, param_types=0x00000022):
    """Common setup: set x1 (cmdID), x2 (param types), p3 with two memrefs of size 0x880."""
    p3 = init_params(state)
    state.regs.x1 = cmd_id
    # Memref at slot 0 and slot 1, both size 0x880
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Force sizes to 0x880 (word=8 on aarch64): size field at p3 + i*16 + 8
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0x880, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0x880, 64), endness=state.arch.memory_endness)
    return p3


# ---------- Command 0x67: property identity path ----------
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1  # arbitrary; x2 drives this path
    state.regs.x2 = 0x67
    return state


# ---------- sub_c12c sub-commands (cmdID 0x200..0x205) ----------
# Likely semantics (from structure): 0x200=setup/gen, 0x201=store,
# 0x202=load/init-op, 0x203=encrypt-like, 0x204=decrypt-like, 0x205=finalize/free

# 0x200: initial setup (independent)
@ta_init_function(next_func="init_00000000_0000_0000_0000_6d706f667376_2")
def init_00000000_0000_0000_0000_6d706f667376_1(state):
    _setup_common_params(state, 0x200)
    return state


# 0x201: follow-up (depends on 0x200)
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_2(state):
    _setup_common_params(state, 0x201)
    return state


# 0x202: another path
@ta_init_function(next_func="init_00000000_0000_0000_0000_6d706f667376_4")
def init_00000000_0000_0000_0000_6d706f667376_3(state):
    _setup_common_params(state, 0x202)
    return state


# 0x203: depends on prior setup
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_4(state):
    _setup_common_params(state, 0x203)
    return state


# 0x204: dependent
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_5(state):
    _setup_common_params(state, 0x204)
    return state


# 0x205: dependent
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_6(state):
    _setup_common_params(state, 0x205)
    return state


# ---------- Admin/negative cmdID path (bit 31 set) -> 0x16124 ----------
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_7(state):
    _setup_common_params(state, 0x80000001)
    return state


# ---------- Generic path via first-word==0xf0000000 (session buffer branch) ----------
# This path requires the session's allocated buffer to start with 0xf0000000.
# Since we cannot control the TEE_Malloc'd memory contents from here easily,
# we still expose an init that sets param slots to sizes == 0x3d74 and non-null ptrs,
# so if a concolic run reaches that branch it can progress.
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_8(state):
    p3 = init_params(state)
    state.regs.x1 = 0x10  # arbitrary small cmdID
    state.regs.x2 = 0x22  # not 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Constrain sizes to 0x3d74 as required by the 0xf0000000 branch
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0x3d74, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0x3d74, 64), endness=state.arch.memory_endness)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_6d706f667376_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

