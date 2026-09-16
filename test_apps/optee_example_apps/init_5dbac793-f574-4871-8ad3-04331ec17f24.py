import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA analysis:
# Dispatch on w1 (command id):
#   cmd 0 (0x00): Prepare - param_types must be 0x111 (three VALUE params), configures algorithm/mode/keysize,
#                  allocates operation, allocates and generates transient key, sets operation key.
#   cmd 1 (0x01): SetKey - param_types must be 0x5 (MEMREF_INPUT at slot 0), populates transient key from buffer,
#                  and re-sets operation key.
#   cmd 2 (0x02): SetIV - param_types must be 0x5 (MEMREF_INPUT at slot 0), calls TEE_CipherInit with IV buffer.
#   cmd 3 (0x03): Cipher - param_types must be 0x65 (MEMREF_INPUT slot0, MEMREF_OUTPUT slot1),
#                  calls TEE_CipherUpdate on in/out buffers.
#   cmd 4 (0x04): AE flow - param_types must be 0x7165 (mix incl. VALUE_INPUT for tag_len),
#                  calls TEE_AEInit / TEE_AEEncryptFinal or TEE_AEDecryptFinal depending on w[sp,#0xc].
#
# Semantic dependencies (stateful TA):
#   - cmd 0 (Prepare) must run first to create operation + key.
#   - cmd 1 (SetKey) and cmd 2 (SetIV) and cmd 3 (Cipher) require cmd 0.
#   - cmd 4 (AE) also requires operation setup (Prepare).
#
# Chain: init_0 -> {init_1, init_2, init_3, init_4}


TA_NAME = "5dbac793_f574_4871_8ad3_04331ec17f24"


@ta_init_function(next_funcs=[
    "init_5dbac793_f574_4871_8ad3_04331ec17f24_1",
    "init_5dbac793_f574_4871_8ad3_04331ec17f24_2",
    "init_5dbac793_f574_4871_8ad3_04331ec17f24_3",
    "init_5dbac793_f574_4871_8ad3_04331ec17f24_4",
])
def init_5dbac793_f574_4871_8ad3_04331ec17f24_0(state):
    # cmd 0: Prepare - param_types = 0x111 (3x VALUE_INPUT)
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x111
    place_sym_value_param(state, p3, 0)  # algo selector (0,1,2)
    place_sym_value_param(state, p3, 1)  # key size (16 or 32)
    place_sym_value_param(state, p3, 2)  # mode (0 or 1)
    # Constrain the algo selector at slot 0 value.a to small values to prevent state explosion
    word = 8
    algo_ptr = p3 + 0 * 2 * word
    algo_val = state.memory.load(algo_ptr, 4, endness=state.arch.memory_endness)
    state.solver.add(algo_val <= 2)
    # Constrain key size to allowed values (16 or 32)
    ksize_ptr = p3 + 1 * 2 * word
    ksize_val = state.memory.load(ksize_ptr, 4, endness=state.arch.memory_endness)
    state.solver.add(claripy.Or(ksize_val == 0x10, ksize_val == 0x20))
    # Constrain mode to 0 or 1
    mode_ptr = p3 + 2 * 2 * word
    mode_val = state.memory.load(mode_ptr, 4, endness=state.arch.memory_endness)
    state.solver.add(mode_val <= 1)
    return state


@ta_chain_target
def init_5dbac793_f574_4871_8ad3_04331ec17f24_1(state):
    # cmd 1: SetKey - param_types = 0x5 (MEMREF_INPUT at slot 0)
    p3 = init_params(state)
    state.regs.x1 = 0x1
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state


@ta_chain_target
def init_5dbac793_f574_4871_8ad3_04331ec17f24_2(state):
    # cmd 2: SetIV - param_types = 0x5 (MEMREF_INPUT at slot 0)
    p3 = init_params(state)
    state.regs.x1 = 0x2
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state


@ta_chain_target
def init_5dbac793_f574_4871_8ad3_04331ec17f24_3(state):
    # cmd 3: Cipher - param_types = 0x65 (MEMREF_INPUT slot0, MEMREF_OUTPUT slot1)
    p3 = init_params(state)
    state.regs.x1 = 0x3
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_chain_target
def init_5dbac793_f574_4871_8ad3_04331ec17f24_4(state):
    # cmd 4: AE - param_types == 0x7165
    # slot0 = VALUE_INPUT(5? actually nibble 5 = MEMREF_INPUT), slot1 = MEMREF_INPUT (6? =OUTPUT)
    # Decode 0x7165: nibbles (LSB..): 5,6,1,7
    #   slot0 = 5 MEMREF_INPUT, slot1 = 6 MEMREF_OUTPUT, slot2 = 1 VALUE_INPUT, slot3 = 7 MEMREF_INOUT
    p3 = init_params(state)
    state.regs.x1 = 0x4
    state.regs.x2 = 0x7165
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state


# Extra init: symbolic x2 to explore parameter-type checks
@ta_init_function
def init_5dbac793_f574_4871_8ad3_04331ec17f24_5(state):
    p3 = init_params(state)
    # leave x1 and x2 symbolic (from init_params); set up four value params
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
