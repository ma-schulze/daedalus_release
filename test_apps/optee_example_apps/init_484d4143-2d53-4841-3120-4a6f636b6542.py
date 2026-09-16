import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# The TA "484d4143-2d53-4841-3120-4a6f636b6542" decodes as ASCII "HMAC-SHA1 JockeB"
# This is likely the OP-TEE HMAC-based One-Time Password / HOTP example TA.
# The standard optee_examples HOTP TA exposes 3 commands:
#   TA_HOTP_CMD_REGISTER_SHARED_KEY = 0  (memref input: shared key)
#   TA_HOTP_CMD_GET_HOTP            = 1  (memref output: HOTP code)
# Depending on variant there may also be a HMAC-SHA1 command variant.
# GET_HOTP depends on prior REGISTER_SHARED_KEY (stateful).


# ---- Command 0: Register shared key (memref input) ----
# Successor: get_hotp (which depends on registered key)
@ta_init_function(next_func="init_hotp_ta_1")
def init_hotp_ta_0(state):
    p3 = init_params(state)
    # Command ID in w1
    state.regs.x1 = 0x0
    # param types: slot0 = MEMREF_INPUT (5)
    state.regs.x2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state


# ---- Command 1: Get HOTP (memref output) ----
# Only meaningful after a key has been registered.
@ta_chain_target
def init_hotp_ta_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1
    # param types: slot0 = MEMREF_OUTPUT (6)
    state.regs.x2 = 0x6
    place_sym_memref_param(state, p3, 0)
    return state


# ---- Fallback / unknown command with symbolic command ID and symbolic mask ----
@ta_init_function
def init_hotp_ta_2(state):
    p3 = init_params(state)
    # Leave x1 (command ID) and x2 (param type mask) symbolic to explore other paths.
    # Set up all 4 slots as symbolic value parameters so the p3 buffer is usable
    # regardless of the concrete type mask chosen by the solver.
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state


# ---- Command 2: possible additional command (e.g., HMAC compute) ----
@ta_init_function
def init_hotp_ta_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2
    # slot0 MEMREF_INPUT, slot1 MEMREF_OUTPUT
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state
