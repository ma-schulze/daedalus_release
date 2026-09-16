import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# Dispatch analysis (x1 = cmd id, x2 = param types mask):
# Entry checks: (cmd|1)==0x1001 with x2!=3 -> command 0x1000/0x1001 family (branch taken)
# Valid commands (not rejected): derived from negative checks. The jump table at 0x202b8
# handles cmd in [0x1001 .. 0x100f], index = cmd - 0x1000.
#
# Observed handlers mapping from jump table entries (address -> handler):
# 0x202dc: sub_20d20 (key load ECC sign?) ldp w0,w1,[x20]
# 0x20348: sub_20f30 (verify/secure storage)
# 0x2037c: sub_21538 (encrypt - produces stored key) - stateful producer
# 0x203b8: sub_26098 (decrypt-like using ephemeral key) 
# 0x203f4: sub_21b88 (AES decrypt using stored key) - stateful consumer (reads persistent)
# 0x2042c: sub_22408 (RSA sign/verify)
# 0x2046c: sub_21888 (generate random / store) - stateful producer
# 0x204a4: sub_23950 (AES encrypt with stored key)
# 0x204ec: sub_22cf0 (RSA sign)
# 0x2052c: sub_24320 (operation with session state)
# 0x2059c: checks param index size
# 0x205d4: sub_20838 (set mode from first param, w5<=0xf)
# 0x20610: sub_21a20 (verify data)
# 0x20648: sub_22ed0 (AES encrypt variant)
# 0x20688: sub_24170 (AES encrypt variant 2)
# 0x206c8: sub_247c0 (operation with big state, persistent)
# 0x20728: sub_22a80 (RSA key-based encrypt - persistent producer)
# 0x2076c: sub_23ee8 (key verify/sign)
#
# Accepted (cmd, param_type) combinations per rejection logic at 0x2017c..0x202b8:
# We prefer param_type values that are not rejected. Safe choice: use p_type = 0
# for most (since the negative checks require specific mismatches).
#
# Key stateful relationships:
# - sub_21b88 (cmd 0x1004) uses key stored by sub_21888 (cmd 0x1008) or sub_21a20 (cmd 0x100d)
# - sub_23950/22ed0/24170/22cf0 (AES) use key loaded via sub_21888/21a20
# - sub_247c0 uses persistent session data
# - sub_22a80 is RSA encrypt which may depend on prior key gen
# - sub_21538 (cmd 0x1003) stores data; consumers are sub_26098/22408

def _set_cmd(state, cmd_id, param_types):
    state.regs.x1 = claripy.BVV(cmd_id, 64)
    state.regs.x2 = claripy.BVV(param_types, 64)

# --- Producer: key generation/random (cmd 0x1008, param_type 0x53) ---
@ta_init_function(next_funcs=["init_ta_1", "init_ta_2", "init_ta_3", "init_ta_4",
                               "init_ta_5", "init_ta_6", "init_ta_7"])
def init_ta_0(state):
    p3 = init_params(state)
    # cmd 0x1008 requires p_type == 0x53
    _set_cmd(state, 0x1008, 0x53)
    place_sym_value_param(state, p3, 0)
    return state

# --- Producer: cmd 0x100d (param_type 0x1665) verify/store ---
@ta_init_function(next_funcs=["init_ta_1", "init_ta_2", "init_ta_3", "init_ta_4",
                               "init_ta_5", "init_ta_6", "init_ta_7"])
def init_ta_8(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100d, 0x1665)
    place_sym_value_param(state, p3, 0)
    return state

# --- Consumer: AES decrypt with stored key (cmd 0x1004) ---
@ta_init_function
def init_ta_1(state):
    p3 = init_params(state)
    # not in rejection list for generic pt -> use 0
    _set_cmd(state, 0x1004, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# --- Consumer: AES encrypt variants ---
@ta_init_function
def init_ta_2(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100e, 0)  # sub_24170 handler
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

@ta_init_function
def init_ta_3(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1009, 0)  # sub_22ed0 (rejected only when pt==0x6653)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# --- Consumer: RSA sign using stored state (cmd 0x100a) ---
@ta_init_function
def init_ta_4(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100a, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state

# --- Consumer: cmd 0x100b (sub_24320) with 5 params ---
@ta_init_function
def init_ta_5(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100b, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state

# --- Consumer: cmd 0x100c (sub_247c0) with persistent data, pt must not be 0x6553 ---
@ta_init_function
def init_ta_6(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100c, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

# --- Consumer: sub_23ee8 (cmd 0x100f) key verify ---
@ta_init_function
def init_ta_7(state):
    p3 = init_params(state)
    _set_cmd(state, 0x100f, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state

# --- Producer: cmd 0x1003 (sub_21538) - stores key/data ---
@ta_init_function(next_funcs=["init_ta_10", "init_ta_11"])
def init_ta_9(state):
    p3 = init_params(state)
    # cmd 0x1003 rejected when pt==3 or pt==0x661
    _set_cmd(state, 0x1003, 0)
    place_sym_memref_param(state, p3, 0)
    return state

# --- Consumer: sub_26098 (cmd 0x1005) uses data ---
@ta_init_function
def init_ta_10(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1005, 0)
    place_sym_memref_param(state, p3, 0)
    return state

# --- Consumer: sub_22408 (cmd 0x1006) RSA ---
@ta_init_function
def init_ta_11(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1006, 0)
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state

# --- Standalone: cmd 0x1001 (sub_20d20) - key generation / initial ---
@ta_init_function
def init_ta_12(state):
    p3 = init_params(state)
    # cmd 0x1001: the first check (cmd|1)==0x1001 with pt!=3 is accepted
    _set_cmd(state, 0x1001, 0)
    place_sym_value_param(state, p3, 0)
    return state

# --- Standalone: cmd 0x1000 (maps to same 0x1001 path via OR with 1) ---
@ta_init_function
def init_ta_13(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1000, 0)
    place_sym_value_param(state, p3, 0)
    return state

# --- Standalone: cmd 0x1002 (sub_20f30) verify ---
@ta_init_function
def init_ta_14(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1002, 0)
    place_sym_memref_param(state, p3, 0)
    return state

# --- Standalone: cmd 0x1007 set mode (sub_20838) - constrain small param to avoid explosion ---
@ta_init_function
def init_ta_15(state):
    p3 = init_params(state)
    _set_cmd(state, 0x1007, 0)
    place_sym_memref_param(state, p3, 0)
    # sub_20838 reads w5=*p3_value; only w5<=0xf is accepted; constrain to avoid huge branching
    # The first 4 bytes of the value_a slot control the mode
    # p3 slot 0 value_a at p3+0
    mode_val = state.memory.load(p3, 4, endness=state.arch.memory_endness)
    state.solver.add(claripy.ULE(mode_val, 0xf))
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_377ee4e8_af0e_474f_a9d636a9268fe85c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

