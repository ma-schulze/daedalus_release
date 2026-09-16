import angr
import claripy
from explorer.memory.ta_taint import get_tainted_mem_bits
from explorer.hooks.function_hooks.func_hooks import ta_function_hook

from utils.logging_config import get_logger

logger = get_logger(__name__)

@ta_function_hook("SLog", "tc")
class SLog_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] SLog called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("__SRE_HuntByName", "tc")
class __SRE_HuntByName_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] __SRE_HuntByName called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("__SRE_MsgRcv", "tc")
class __SRE_MsgRcv_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] __SRE_MsgRcv called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("__SRE_MsgSnd", "tc")
class __SRE_MsgSnd_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] __SRE_MsgSnd called")
        return claripy.BVV(0, self.state.arch.bits)


@ta_function_hook("cinit00", "tc")
class cinit00_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] cinit00 called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("g_dx_content_path_addr", "tc")
class g_dx_content_path_addr_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] g_dx_content_path_addr called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("get_current_session_id", "tc")
class get_current_session_id_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] get_current_session_id called")
        return get_tainted_mem_bits(self.state, 32)

@ta_function_hook("init_non_std_property", "tc")
class init_non_std_property_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] init_non_std_property called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("set_current_session_type", "tc")
class set_current_session_type_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] set_current_session_type called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("set_global_handle", "tc")
class set_global_handle_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] set_global_handle called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("tee_exit", "tc")
class tee_exit_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] tee_exit called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("tee_init", "tc")
class tee_init_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] tee_init called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("tee_init_context", "tc")
class tee_init_context_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] tee_init_context called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("tee_session_exit", "tc")
class tee_session_exit_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] tee_session_exit called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("tee_session_init", "tc")
class tee_session_init_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] tee_session_init called")
        return claripy.BVV(0, self.state.arch.bits)

@ta_function_hook("uart_printf_func", "tc")
class uart_printf_func_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print("[HOOK] uart_printf_func called")
        return claripy.BVV(0, self.state.arch.bits)