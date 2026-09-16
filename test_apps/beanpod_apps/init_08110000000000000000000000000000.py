import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA dispatches on command ID in r1 (cmd = r1; switch on cmd-1, range 1..14 via tbh).
# Observed checks against r2 (param_types mask) for various commands:
#  - 0x7  -> slot0 MEMREF_INOUT
#  - 0x275 -> per-slot decoding: nibbles 5,7,2,0 -> slot0=MEMREF_INPUT, slot1=MEMREF_INOUT, slot2=VALUE_OUTPUT
#  - 0x765 -> nibbles 5,6,7,0 -> slot0=MEMREF_INPUT, slot1=MEMREF_OUTPUT, slot2=MEMREF_INOUT
#  - 0x1   -> slot0=VALUE_INPUT
#  - 0x5   -> slot0=MEMREF_INPUT
# Commands that depend on a created/loaded key/session (stateful):
#  - Command 1 (cmd=1) is "create/open" path at 0x95db (param_types==7), needed before others
#  - Other commands need that state

TA = "ta"

def _setup_common(state):
    p3 = init_params(state)
    return p3


@ta_init_function(next_funcs=[
    "init_ta_1", "init_ta_2", "init_ta_3", "init_ta_4",
    "init_ta_5", "init_ta_6", "init_ta_7", "init_ta_8",
    "init_ta_9", "init_ta_10", "init_ta_11", "init_ta_12",
    "init_ta_13"
])
def init_ta_0(state):
    # cmd=1: initialization / create path (param_types == 7 => slot0 MEMREF_INOUT)
    p3 = _setup_common(state)
    state.regs.r1 = 1
    state.regs.r2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_chain_target
def init_ta_1(state):
    # cmd=2: requires param_types == 0x275; slot0 MEMREF_INPUT, slot1 MEMREF_INOUT, slot2 VALUE_OUTPUT
    p3 = _setup_common(state)
    state.regs.r1 = 2
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_2(state):
    # cmd=3: param_types==0x275 path (memref-heavy)
    p3 = _setup_common(state)
    state.regs.r1 = 3
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_3(state):
    # cmd=4: param_types==0x765 path
    p3 = _setup_common(state)
    state.regs.r1 = 4
    state.regs.r2 = 0x765
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_4(state):
    # cmd=5: param_types==0x765
    p3 = _setup_common(state)
    state.regs.r1 = 5
    state.regs.r2 = 0x765
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_6(state):
    # cmd=7: param_types==1 (VALUE_INPUT) - load/open variant
    p3 = _setup_common(state)
    state.regs.r1 = 7
    state.regs.r2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_chain_target
def init_ta_5(state):
    # cmd=6: param_types==5 (MEMREF_INPUT) - variant requires preceding state
    p3 = _setup_common(state)
    state.regs.r1 = 6
    state.regs.r2 = 0x5
    place_sym_memref_param(state, p3, 0)
    return state


@ta_chain_target
def init_ta_7(state):
    # cmd=8: another memref path (0x275)
    p3 = _setup_common(state)
    state.regs.r1 = 8
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_8(state):
    # cmd=9: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 9
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_9(state):
    # cmd=10: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 10
    state.regs.r2 = 0x765
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_10(state):
    # cmd=11: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 11
    state.regs.r2 = 0x765
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_11(state):
    # cmd=12: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 12
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_12(state):
    # cmd=13: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 13
    state.regs.r2 = 0x275
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    return state


@ta_chain_target
def init_ta_13(state):
    # cmd=14: memref path
    p3 = _setup_common(state)
    state.regs.r1 = 14
    state.regs.r2 = 0x765
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    return state

@ta_init_function
def init_08110000000000000000000000000000_ta_12(state):
    return _generic_setup(state, 0xd)


@ta_init_function
def init_08110000000000000000000000000000_ta_13(state):
    return _generic_setup(state, 0xe)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_08110000000000000000000000000000_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

