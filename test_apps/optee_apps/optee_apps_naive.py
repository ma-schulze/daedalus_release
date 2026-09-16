import angr

from explorer.hooks.function_hooks.func_hooks import ta_function_hook

from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function

@ta_function_hook("tee_session2client", "pkcs11")
class tee_session2client_symbolic(angr.SimProcedure):
    """tee_session2client(): return handle to client"""

    def run(self):
        client = self.state.heap.allocate(64)
        self.state.memory.store(client, get_tainted_mem_bits(self.state, 64 * 8))
        return client


@ta_init_function
def init_pkcs11(state):
    # Command ID 0x283: Standard input processing
    p3 = init_params(state)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state
