import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA dispatch analysis (VLTKPR - Samsung TEEgris Vault Keeper TA):
# At entry, the TA checks (w2 & 0xF) == 7 (MEMREF_INOUT slot0) AND (w2 & 0xF0) == 0x60
# (MEMREF_OUTPUT slot1). So param_types == 0x67 typically.
# It loads p[0].buffer (x21), p[0].size (w22), p[1].buffer (x19), p[1].size (w20).
# Checks p[0].size == 0xadf8 and p[1].size == 0xae00.
# Then calls TEES_IsREESharedMemory on both. If both are NOT REE-shared,
# it calls sub_1a6a0 which is the main provisioning/verify routine (one command path).
# There's also a fallback path at 0x1a368 that takes (w2 & 0xF) != 7 but
# (w2 & 0xF0) == 0x60 (param_types == 0x6X with X != 7), going to error path
# producing "invalid param" — still a different code path.
#
# The TA itself has essentially one externally-invoked command (no command-id dispatch
# via r1). However, the internal sub_1a6a0 dispatches via TEES_RPMBCheckEnable result
# (returns either -0xfff6 or -0xfff7 or other) — these are runtime/environment-dependent.
#
# Internal state: at 0x41000+0x7b8 there is a flag byte ("provisioned" flag). On second
# invocation when the flag is set, the TA returns immediately. So we have one main init
# (cold) and the same init can be re-run (warm); only one functional path from the
# invoke entry.


@ta_init_function
def init_VLTKPR_0(state):
    # Main provisioning / data-write path:
    # param_types = MEMREF_INOUT (slot0) + MEMREF_OUTPUT (slot1) + NONE + NONE = 0x67
    p3 = init_params(state)
    state.regs.x1 = 0x0  # cmd id not checked by TA, leave as 0
    state.regs.x2 = 0x67

    # Slot 0: MEMREF_INOUT, required size 0xadf8
    place_sym_memref_param(state, p3, 0)
    # Constrain size to expected value to avoid hitting the error path immediately
    word = 8
    size0_addr = p3 + 0 * 2 * word + word
    state.memory.store(size0_addr, claripy.BVV(0xadf8, 64), endness=state.arch.memory_endness)

    # Slot 1: MEMREF_OUTPUT, required size 0xae00
    place_sym_memref_param(state, p3, 1)
    size1_addr = p3 + 1 * 2 * word + word
    state.memory.store(size1_addr, claripy.BVV(0xae00, 64), endness=state.arch.memory_endness)

    return state


@ta_init_function
def init_VLTKPR_1(state):
    # Alternative path: parameter-type mismatch on slot0 nibble (not 7) but slot1 nibble == 6.
    # This exercises the secondary branch at 0x1a368 leading to a different error/log path.
    p3 = init_params(state)
    state.regs.x1 = 0x0
    state.regs.x2 = 0x61  # slot0 = VALUE_INPUT, slot1 = MEMREF_OUTPUT

    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_564c544b5052_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

