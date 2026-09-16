import angr

from utils.logging_config import get_logger
from explorer.hooks.function_hooks.func_hooks import ta_function_hook

from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.ta_init_function import ta_init_function

logger = get_logger(__name__)

@ta_function_hook("panic_symbolic", "t6", 0x00205654)
class panic_symbolic(angr.SimProcedure):
    """panic(): no-op for symbolic execution."""

    def run(self):
        logger.info(f"panic called at {hex(self.state.addr)}")
        self.state.globals['ta_panic'] = True
        self.state.globals['panic_addr'] = self.state.addr
        return 0



@ta_function_hook("optimized_memset", "t6_945", 0x002979e8)
class optimized_memset_symbolic(angr.SimProcedure):
    """optimized_memset(): no-op for symbolic execution."""

    def run(self, dst, c, n):
        memset = angr.SIM_PROCEDURES["libc"]["memset"]
        self.inline_call(memset, dst, c, n) 
        logger.info(f"optimized_memset called at {hex(self.state.addr)}")
        return 0

@ta_function_hook("some_crc", "t6_945", 0x002650e4)
class some_crc_symbolic(angr.SimProcedure):
    """some_crc(): no-op for symbolic execution."""

    def run(self):
        logger.info(f"some_crc called at {hex(self.state.addr)}")
        return get_tainted_mem_bits(self.state, self.state.arch.bits)


@ta_init_function
def init_02662e8e_a(state):
    # Command ID 0x283: Standard input processing
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state


@ta_init_function
def init_9459b61a_a(state):
    # Command ID 0x283: Standard input processing
    p3 = init_params(state)
    
    place_sym_value_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    return state
