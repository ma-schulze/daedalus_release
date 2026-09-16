import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# Analysis summary of TA at 0x24ae8 (InvokeCommandEntryPoint):
#
# Dispatch:
#  - r2/x2 (param_types) must equal 0x65 -> slot0 = MEMREF_INPUT(5), slot1 = MEMREF_OUTPUT(6)
#  - p3[0].size must equal 0x100c, p3[1].size must equal 0x1008
#  - p3[0].buffer (x21) layout:
#       [0:4]   = op (must be 1 to take the main dispatch; else returns error 0x7a000004)
#       [4:8]   = algo_word (used to compute w20 = algo & 0xffff, w22 = algo>>0x1c+1 when (algo & 0xfffe)==0x1000)
#       [8:12]  = inner length
#       [12:]   = inner data
#  - x20 (params array second slot's pointer? actually x19 = params[1].buffer from p3+0x10) used as output context
#
# After op==1 path (0x24c20), the algo selector w20 is checked:
#   w20 - 0xf001 must be <= 5 (i.e., algo in 0xf001..0xf006) -> jump table to algo handlers
#   Branch table at 0xa000+0xe58 selects one of several handlers:
#     - sub_292a0  : RNG/wrap-like (allocates symmetric crypto context)
#     - sub_28328  : Big handler -- key import/export with sub-commands (size codes 0x30, 0x40, 0x80, 0x100, etc.)
#     - sub_29358  : Asymmetric keypair generate (RSA via 0xa0000030)
#     - sub_29688  : Asymmetric key gen + export (RSA persistent key)
#     - sub_29ab8  : Load by ID and use object
#     - sub_28f98  : Encrypt/process with persistent key
#     - sub_29290  : stub returning 0x7a000004 (always fails -> safe)
#   Other algo values:
#     - w20 == 0x1001 -> sub_28c58 (uses persistent dispatch table; checks global state at 0x7a000010/0x88/0x38)
#     - w20 == 0x1000 -> sub_28328 (the import handler)
#     - otherwise -> error 0x7a000004
#
# Stateful behavior:
#   - sub_29688 (algo 0xf003?) generates+stores a persistent object via storage API; subsequent
#     ops like sub_29ab8 / sub_28f98 require an existing stored object found by ID via sub_2d218.
#   - sub_28328 imports key material; sub_28c58 dispatches via a global function table populated elsewhere.
#
# For deep coverage we enumerate semantically distinct algo values and the import op,
# and we constrain small fields (op, algo, sub-size) to concrete values per init to avoid
# state explosion in the inner switch tables.

TA_CMD_ID = 0x0  # The TA does not check x1; only x2 (param_types) matters.
PARAM_TYPES = 0x65  # MEMREF_INPUT(5) | (MEMREF_OUTPUT(6) << 4)


def _setup_common(state):
    """Set up the common GP parameter layout expected by this TA."""
    p3 = init_params(state)
    state.regs.x1 = TA_CMD_ID
    state.regs.x2 = PARAM_TYPES

    # slot 0: MEMREF_INPUT (input buffer for the command)
    place_sym_memref_param(state, p3, 0)
    # slot 1: MEMREF_OUTPUT (output buffer)
    place_sym_memref_param(state, p3, 1)

    word = 8  # AArch64
    slot0_ptr_addr = p3 + 0 * (2 * word)
    slot0_size_addr = slot0_ptr_addr + word
    slot1_ptr_addr = p3 + 1 * (2 * word)
    slot1_size_addr = slot1_ptr_addr + word

    # Pin the sizes to those checked by the TA
    state.memory.store(slot0_size_addr, claripy.BVV(0x100c, 64), endness=state.arch.memory_endness)
    state.memory.store(slot1_size_addr, claripy.BVV(0x1008, 64), endness=state.arch.memory_endness)

    # Read the symbolic buffer pointer for slot0 to write op/algo concretely
    in_ptr_bv = state.memory.load(slot0_ptr_addr, word, endness=state.arch.memory_endness)
    return p3, in_ptr_bv


def _write_op_and_algo(state, in_ptr_bv, op_val, algo_val, inner_size=0x100):
    """Write op (offset 0), algo (offset 4), and inner length (offset 8) into the input buffer."""
    # op at +0 (32-bit)
    state.memory.store(in_ptr_bv + 0, claripy.BVV(op_val, 32), endness=state.arch.memory_endness)
    # algo at +4 (32-bit)
    state.memory.store(in_ptr_bv + 4, claripy.BVV(algo_val, 32), endness=state.arch.memory_endness)
    # inner length at +8 (32-bit) -- must be <= 0x1000 (the cmp w7, #1, lsl #12 check)
    state.memory.store(in_ptr_bv + 8, claripy.BVV(inner_size & 0xfff, 32), endness=state.arch.memory_endness)


# ---------------------------------------------------------------------------
# Init 0: op != 1 path (catch-all "use stored object" path -> sub_28c58)
# Triggers when algo (w20) == 0x1001. This walks a global dispatch table whose
# entries may be NULL unless a key has been generated/loaded by another command.
# Decorate as chain target so it only runs after a key-generation init.
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_0(state):
    p3, in_ptr_bv = _setup_common(state)
    # op != 1, so the code takes the 0x24ca8 branch then continues to algo dispatch
    # Actually re-reading: op (x21[0]) is checked == 1 at 0x24c18. If !=1, error path.
    # The 0x1001 algo path is inside the op==1 branch. Use op==1 here.
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0x1001, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 1: algo 0xf001 -> sub_292a0 (RNG/symmetric ctx allocation)
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_1(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf001, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 2: algo 0xf002 -> sub_28328 path B (the "import" big handler is reached via 0x1000;
# here 0xf002 -> sub_29358 (asymmetric keypair generate). This populates global state at
# 0x7a000010 / 0x7a000088 etc. Subsequent ops may depend on it.
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_0", "init_88ce8e6b_5", "init_88ce8e6b_6"])
def init_88ce8e6b_2(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf002, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 3: algo 0xf003 -> sub_29688 (asymmetric key gen + persistent store).
# Creates a persistent object identified by an ID derived from p3[1].buffer (x19).
# This is a key-installation command other algos depend on (e.g., 0xf005).
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_5"])
def init_88ce8e6b_3(state):
    p3, in_ptr_bv = _setup_common(state)
    # algo > 0x13f required inside sub_29688 (otherwise quick reject). Use 0xf003.
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf003, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 4: algo 0xf004 -> sub_29ab8 (load object by ID and read out).
# This requires a previously-stored object; treat as chain target.
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_4(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf004, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 5: algo 0xf005 -> sub_28f98 (encrypt/process using a persistent key).
# Requires a stored object created by init 3 (or 6). Chain target.
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_5(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf005, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 6: algo 0xf006 -> sub_29290 (stub returning a fixed error code).
# Standalone and quick; useful for coverage of the dispatch table edge.
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_6(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0xf006, inner_size=0x40)
    return state


# ---------------------------------------------------------------------------
# Init 7: algo 0x1000 -> sub_28328 (big key import handler).
# Inside it, the inner sub-size (read via sub_2e380 at offset +16+8 of x21+0xc)
# selects among several import sub-paths. The size is small (<= 0x3f or one of
# 0x40 / 0x80 / 0x100). To avoid state explosion we constrain it to a single
# concrete value here, and provide separate inits for each interesting size.
# This init handles the "small key" (size 0x30) path.
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_0", "init_88ce8e6b_5"])
def init_88ce8e6b_7(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0x1000, inner_size=0x30)
    # Constrain the byte at offset 12 (first byte of inner sub-size field consumed by sub_2e380)
    # to the concrete small-key value 0x30 to prevent state explosion across the inner switch.
    state.memory.store(in_ptr_bv + 12, claripy.BVV(0x30, 32), endness=state.arch.memory_endness)
    return state


# ---------------------------------------------------------------------------
# Init 8: algo 0x1000, inner size 0x40 (AES-like key length)
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_0", "init_88ce8e6b_5"])
def init_88ce8e6b_8(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0x1000, inner_size=0x40)
    state.memory.store(in_ptr_bv + 12, claripy.BVV(0x40, 32), endness=state.arch.memory_endness)
    return state


# ---------------------------------------------------------------------------
# Init 9: algo 0x1000, inner size 0x80
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_0", "init_88ce8e6b_5"])
def init_88ce8e6b_9(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0x1000, inner_size=0x80)
    state.memory.store(in_ptr_bv + 12, claripy.BVV(0x80, 32), endness=state.arch.memory_endness)
    return state


# ---------------------------------------------------------------------------
# Init 10: algo 0x1000, inner size 0x100 (RSA-like)
# ---------------------------------------------------------------------------
@ta_init_function(next_funcs=["init_88ce8e6b_0", "init_88ce8e6b_5"])
def init_88ce8e6b_10(state):
    p3, in_ptr_bv = _setup_common(state)
    _write_op_and_algo(state, in_ptr_bv, op_val=1, algo_val=0x1000, inner_size=0x100)
    state.memory.store(in_ptr_bv + 12, claripy.BVV(0x100, 32), endness=state.arch.memory_endness)
    return state


# ---------------------------------------------------------------------------
# Init 11: error path - wrong param_types mask to exercise the error reporting code
# ---------------------------------------------------------------------------
@ta_init_function
def init_88ce8e6b_11(state):
    p3 = init_params(state)
    state.regs.x1 = TA_CMD_ID
    # Force a mismatched mask so the TA falls through to the "bad parameters" branch (0x24bc8)
    state.regs.x2 = 0x0
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_88ce8e6b_8646_4092_bb78faf5b55ff4df_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

