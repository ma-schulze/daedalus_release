import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA_InvokeCommandEntryPoint analysis:
# - r1 = command ID
# - r2 = param types (compared against 0x2615 -> mask 0x2615)
#   nibble0=5 (MEMREF_INPUT), nibble1=1 (VALUE_INPUT), nibble2=6 (MEMREF_OUTPUT), nibble3=2 (VALUE_OUTPUT)
# - r3 = p3 pointer
#
# Flow at 0xbdc0:
#   - cmp r2, 0x2615 -> if not equal, return error
#   - cmp r6 (r1, cmd id), #0 -> if non-zero, log error path
#   - if r1 == 0: call json_loads on the memref buffer (p3[0].buffer)
#     Then OTrP_handle_message dispatches on strings inside the JSON.
#
# So there are essentially two top-level paths:
#   (a) cmd id == 0 with valid param mask -> JSON parse + OTrP dispatch
#   (b) cmd id != 0 -> early error
#
# OTrP_handle_message dispatches on string keys in the JSON like:
#   "TADependencyTBSNotification", "GetDeviceStateTBSRequest", "InstallTATBSRequest",
#   "UpdateTATBSRequest", "DeleteTATBSRequest", "CreateSDTBSRequest", "UpdateSDTBSRequest",
#   "DeleteSDTBSRequest", "FactoryResetTBSRequest", "AcquireKeyTBSRequest",
#   "AcquireKeyConfirmationTBSRequest", etc.
#
# Because the JSON content is symbolic (memref buffer), Angr will explore these
# branches symbolically. To prevent state space explosion from the JSON parser,
# we constrain the memref size to a small bounded value.

TA_NAME = "655a4b46cd7711eaaafbf382a6988e7b"

# Param types mask required: 0x2615
PARAM_TYPES_MASK = 0x2615


def _setup_common(state):
    """Setup common state: param types mask + 4 slots."""
    p3 = init_params(state)
    state.regs.r2 = claripy.BVV(PARAM_TYPES_MASK, 32)
    # slot 0: MEMREF_INPUT (JSON request buffer)
    place_sym_memref_param(state, p3, 0)
    # slot 1: VALUE_INPUT
    place_sym_value_param(state, p3, 1)
    # slot 2: MEMREF_OUTPUT (response buffer)
    place_sym_memref_param(state, p3, 2)
    # slot 3: VALUE_OUTPUT
    place_sym_value_param(state, p3, 3)
    return p3


@ta_init_function
def init_655a4b46cd7711eaaafbf382a6988e7b_0(state):
    # Command 0: main JSON dispatch path (cmd id == 0, param types == 0x2615)
    _setup_common(state)
    state.regs.r1 = claripy.BVV(0, 32)
    return state


@ta_init_function
def init_655a4b46cd7711eaaafbf382a6988e7b_1(state):
    # Command non-zero: early-error path (logs invalid command id)
    _setup_common(state)
    state.regs.r1 = claripy.BVV(1, 32)
    return state


@ta_init_function
def init_655a4b46cd7711eaaafbf382a6988e7b_2(state):
    # Wrong param types mask path: returns 0xffff0006 early
    p3 = init_params(state)
    # set r2 to a value != 0x2615 to trigger early return
    state.regs.r2 = claripy.BVV(0x0, 32)
    state.regs.r1 = claripy.BVV(0, 32)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_655a4b46cd7711eaaafbf382a6988e7b_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

