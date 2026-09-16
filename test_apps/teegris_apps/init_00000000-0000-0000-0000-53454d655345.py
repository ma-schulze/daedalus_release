import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# The InvokeCommandEntryPoint at 0x14fa8 is a thin wrapper that performs a
# stack canary check and tail-calls sub_13590. Without visibility into
# sub_13590, we cannot identify distinct command IDs. We therefore provide
# a single generic init that leaves the command ID and parameter types
# symbolic, allowing angr to explore all paths.

@ta_init_function
def init_00000000_0000_0000_0000_53454d655345_ta_0(state):
    p3 = init_params(state)
    # Leave x1 (command ID) and x2 (param types) symbolic as set by init_params.
    # Provide all four possible parameter slots as symbolic memrefs so any
    # combination of memref/value reads stays within mapped memory.
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_53454d655345_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

