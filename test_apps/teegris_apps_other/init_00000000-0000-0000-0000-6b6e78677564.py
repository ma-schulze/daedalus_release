import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA Analysis Summary:
# The TA_InvokeCommandEntryPoint at 0x1ead4 checks:
#   - param_types (w2) must equal 0x67 (slot0=MEMREF_INOUT=7, slot1=MEMREF_OUTPUT=6)
#   - calls TEES_IsREESharedMemory on slot0 and slot1 buffers (both must be REE shared mem)
#   - validates buffer sizes are 0x4440
#   - validates TEES_GetClientCredentials
#   - then dispatches to sub_12b30 based on command id w1 (w21)
#
# sub_12b30 dispatches on command IDs:
#   - cmd id 1 -> branches to 0x16b14 (key generation / certificate provisioning)
#   - cmd ids in range [0x102 .. 0x117] -> jump table at 0xa414 dispatches to:
#       0x102, 0x105 (returned directly without dispatch)
#       Other 0x10X-0x11X command IDs go through main dispatcher at 0x174d4
# 
# Looking at sub_174d4 (the main command handler):
#   - Reads cmd packet from x0 (REE shared input buffer)
#   - Performs various crypto operations: cert load, RSA verify, key derivation,
#     cipher decrypt, AES, etc.
#
# Command dependencies:
#   - cmd 1 (key/cert provisioning at 0x16b14) likely must run first to set up state
#   - subsequent cmds (0x10X, 0x11X) consume state set up by cmd 1
#
# State explosion concerns:
#   - cmd_id check happens via jump table, so we constrain it to a few representative values
#   - The TA reads large buffers; we constrain only critical small fields


def _setup_common(state):
    """Common setup: param_types=0x67 (memref_inout slot0, memref_output slot1)."""
    p3 = init_params(state)
    # param_types mask: slot0 = MEMREF_INOUT (7), slot1 = MEMREF_OUTPUT (6) => 0x67
    state.regs.x2 = 0x67
    # slot0 memref input/output (size 0x4440 expected)
    place_sym_memref_param(state, p3, 0)
    # slot1 memref output (size 0x4440 expected)
    place_sym_memref_param(state, p3, 1)
    return p3


@ta_init_function(next_funcs=[
    "init_00000000_0000_0000_0000_6b6e78677564_1",
    "init_00000000_0000_0000_0000_6b6e78677564_2",
    "init_00000000_0000_0000_0000_6b6e78677564_3",
    "init_00000000_0000_0000_0000_6b6e78677564_4",
])
def init_00000000_0000_0000_0000_6b6e78677564_0(state):
    # Command 1: provisioning/cert/key path (sub_16b14)
    # This is the foundational command that loads keys/certs from REE input.
    _setup_common(state)
    state.regs.x1 = 0x1
    return state


@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_1(state):
    # Command 0x102 - early sub-command in dispatch table
    _setup_common(state)
    state.regs.x1 = 0x102
    return state


@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_2(state):
    # Command 0x105 - certificate/key consume path
    _setup_common(state)
    state.regs.x1 = 0x105
    return state


@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_3(state):
    # Command 0x108 - one of the dispatcher entries (uses crypto/RSA verify)
    _setup_common(state)
    state.regs.x1 = 0x108
    return state


@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_4(state):
    # Command 0x10B - another dispatched command exercising cipher path
    _setup_common(state)
    state.regs.x1 = 0x10B
    return state


@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_5(state):
    # Invalid param_types path: trigger the 0x1eb78 branch where w2 != 0x67
    # This exercises the error/logging path.
    p3 = init_params(state)
    state.regs.x2 = 0x0  # not 0x67 => error path
    state.regs.x1 = 0x1
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_6b6e78677564_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

