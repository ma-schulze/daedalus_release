import angr
from explorer.memory.ta_taint import get_trusted_mem_bits

from utils.logging_config import get_logger
from explorer.hooks.function_hooks.func_hooks import ta_function_hook

logger = get_logger(__name__)


def _ptr_bits(state):
    """Return pointer size in bits (32 or 64)."""
    return state.arch.bits


def _arg(state, index):
    """Get call argument by index. 0..3 in regs; 4+ from x4-x7 (64-bit) or stack (32-bit)."""
    if state.arch.bits == 64:
        regs = [
            state.regs.x0, state.regs.x1, state.regs.x2, state.regs.x3,
            state.regs.x4, state.regs.x5, state.regs.x6, state.regs.x7,
        ]
        if index < len(regs):
            return regs[index]
    else:
        if index < 4:
            regs = [state.regs.r0, state.regs.r1, state.regs.r2, state.regs.r3]
            return regs[index]
        # ARM 32-bit: 5th+ args on stack (at sp, sp+4, ...)
        off = (index - 4) * 4
        return state.memory.load(state.regs.sp + off, 4, endness=state.arch.memory_endness)
    return None


def _store_at_ptr(state, ptr, num_bits, endness=None):
    """Store symbolic bits at the given pointer."""
    if endness is None:
        endness = state.arch.memory_endness
    state.memory.store(ptr, get_trusted_mem_bits(state, num_bits), size=num_bits // 8, endness=endness)


def _store_ptr_at(state, ptr, value_bv=None, endness=None):
    """Store a pointer-sized value at ptr (e.g. handle). If value_bv is None, store symbolic."""
    bits = _ptr_bits(state)
    if endness is None:
        endness = state.arch.memory_endness
    val = get_trusted_mem_bits(state, bits) if value_bv is None else value_bv
    state.memory.store(ptr, val, size=bits // 8, endness=endness)


def _safe_size(state, size_reg, default=256, max_size=0x2000):
    """Resolve size from register; clamp to [1, max_size]."""
    try:
        n = state.solver.eval_one(size_reg)
    except Exception:
        n = default
    if not isinstance(n, int) or n <= 0:
        n = default
    return min(max(n, 1), max_size)


@ta_function_hook("GetBootSeed", "t6")
class GetBootSeed_symbolic(angr.SimProcedure):
    """GetBootSeed(buf, size): fill buf with symbolic bytes, return 0."""

    def run(self):
        buf = _arg(self.state, 0)
        size_reg = _arg(self.state, 1)
        n = _safe_size(self.state, size_reg, default=32, max_size=256)
        _store_at_ptr(self.state, buf, n * 8)
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("debug_log2", "t6")
class debug_log2_symbolic(angr.SimProcedure):
    """debug_log2(filename, linenumber, nr1, nr2, format, ...): no-op for symbolic execution."""

    def run(self):
        return 0 


@ta_function_hook("debug_log", "t6")
class debug_log_symbolic(angr.SimProcedure):
    """debug_log(log_level, filename, format, ...): no-op for symbolic execution."""

    def run(self):
        log_level = _arg(self.state, 0)
        filename = _arg(self.state, 1)
        format = _arg(self.state, 2)

        filename_str = "" 
        for i in range(0, 100):
            bt = self.state.memory.load(filename + i, 1) 
            concrete_byte = self.state.solver.eval_one(bt)
            char = chr(concrete_byte)
            filename_str += char

        format_str = "" 
        for i in range(0, 100):
            bt = self.state.memory.load(format + i, 1) 
            concrete_byte = self.state.solver.eval_one(bt)
            char = chr(concrete_byte)
            format_str += char

        print(f"debug_log: {log_level}, {filename_str}, {format_str}")
        return 0 


@ta_function_hook("check_license", "t6")
class check_license_symbolic(angr.SimProcedure):
    """check_license(): return 0 (success)."""

    def run(self):
        return 0