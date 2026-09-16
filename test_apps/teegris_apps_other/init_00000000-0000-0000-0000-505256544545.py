import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# Analysis of TA_InvokeCommandEntryPoint at 0x1a614:
# - x0: session handle
# - x1: command id (not directly dispatched; the cmd id is read from p3[0] memref buffer)
# - x2 (w24): param_types - checked (w24 & 0xF) == 7, i.e. slot0 = MEMREF_INOUT
# - x3: p3 pointer
#
# Flow:
#   x21 = *p3            ; p3[0].buffer ptr (header struct)
#   bl sub_1c2b8         ; returns 0 (continues)
#   bl sub_3efc0         ; no-op
#   bl sub_1c308 (x2)    ; allocs scratch
#   bl sub_1c308         ; allocs another scratch
#   (w24 & 0xf) == 7     ; param type slot 0 MEMREF_INOUT required
#   x2 = p3[0].size      ; size of memref
#   w0 = 3
#   bl 0x4ed20 (TEES_IsREESharedMemory)  ; if non-zero error
#   If shared memory OK:
#     ldr x4 = p3[0].size; cmp x4,#7; if <= 7 -> error TEE_ERROR_BAD_PARAMETERS
#     w25 = ldr [x21, #4]        ; sub-command/length field at offset 4 of the input buffer
#     check x25+8 <= x4
#     w26 = *x21 (first dword = sub-cmd id)
#     bl sub_1a2d0(w26, ...)     ; dispatcher on inner cmd id
#
# sub_1a2d0 dispatcher: switch on w0/w4:
#   case 0xa702 -> handler at offset table 0x88 of x51000 (e.g., generate keypair)
#   case 0xa803 -> handler at offset table 0x88 of x51000 (sign/encrypt)
#   case 0xa804 -> handler at offset table 0x90
#   case 0xab07 -> log only, returns 0 (early-out)
#   default     -> TEE_ERROR_NOT_SUPPORTED
#
# After dispatcher success, sub_244b0 derives a wrapping key and seals output blob via AES.
#
# This is a PKCS-like crypto TA (Samsung Teegris). Inner sub-commands are read from the
# input MEMREF_INOUT buffer at offset 0 (4 bytes). We emit one init per known inner cmd.
#
# To keep state space manageable, we constrain the buffer length field and concretize
# the inner command id while leaving payload symbolic.

TA_NAME = "00000000_0000_0000_0000_505256544545"

WORD = 8
MEMREF_INOUT = 7
PARAM_TYPES_MEMREF_INOUT_SLOT0 = 7  # only slot0 used


def _setup_common(state, inner_cmd_id):
    p3 = init_params(state)
    # Command ID register (TA does not strictly check it, but set to inner id for clarity)
    state.regs.x1 = claripy.BVV(inner_cmd_id & 0xFFFFFFFF, 64)
    # Parameter types: slot0 = MEMREF_INOUT (7)
    state.regs.x2 = claripy.BVV(PARAM_TYPES_MEMREF_INOUT_SLOT0, 64)
    # Set up memref param slot 0
    place_sym_memref_param(state, p3, 0)

    # Read back the buffer ptr and size that the helper placed at p3[0]
    buf_ptr = state.memory.load(p3 + 0, WORD, endness=state.arch.memory_endness)
    # Force the size to a small, concrete value >= 8 to satisfy "size > 7" check
    # and keep "w25+8 <= size" feasible with small w25.
    # We pick 64 bytes which is enough for typical headers + small payload.
    concrete_size = 64
    state.memory.store(
        p3 + WORD,
        claripy.BVV(concrete_size, WORD * 8),
        endness=state.arch.memory_endness,
    )

    # Write the inner command id (first 4 bytes of the input buffer)
    state.memory.store(buf_ptr, claripy.BVV(inner_cmd_id & 0xFFFFFFFF, 32),
                       endness=state.arch.memory_endness)
    # Constrain the inner-length field at offset 4 to a small value to prevent
    # state explosion in subsequent loops (must satisfy w25 + 8 <= size = 64).
    inner_len_sym = state.memory.load(buf_ptr + 4, 4, endness=state.arch.memory_endness)
    state.solver.add(inner_len_sym <= 32)
    state.solver.add(inner_len_sym >= 0)
    return state


# Inner command 0xab07: simple log/no-op path - good standalone, no deps
@ta_init_function
def init_00000000_0000_0000_0000_505256544545_0(state):
    return _setup_common(state, 0xab07)


# Inner command 0xa702: key generation / setup path (TEE_TYPE constant 0xF)
# This typically must be invoked before sign/verify which uses persistent state.
@ta_init_function(next_funcs=[
    "init_00000000_0000_0000_0000_505256544545_2",
    "init_00000000_0000_0000_0000_505256544545_3",
])
def init_00000000_0000_0000_0000_505256544545_1(state):
    return _setup_common(state, 0xa702)


# Inner command 0xa803: operation using key (depends on key being generated/loaded)
@ta_init_function
def init_00000000_0000_0000_0000_505256544545_2(state):
    return _setup_common(state, 0xa803)


# Inner command 0xa804: another operation using key (depends on key state)
@ta_init_function
def init_00000000_0000_0000_0000_505256544545_3(state):
    return _setup_common(state, 0xa804)


# Unknown/default inner command - explores the TEE_ERROR_NOT_SUPPORTED branch
@ta_init_function
def init_00000000_0000_0000_0000_505256544545_4(state):
    # use an id that doesn't match any case
    return _setup_common(state, 0x0001)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_505256544545_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

