import angr
import claripy
from explorer.memory.ta_taint import get_trusted_mem_bits
from explorer.hooks.function_hooks.func_hooks import ta_function_hook
from utils.logging_config import get_logger

logger = get_logger(__name__)

TEE_SUCCESS = 0


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



# ---------------------------------------------------------------------------
# Memory / crypto (from mitee_api.py)
# ---------------------------------------------------------------------------


@ta_function_hook("zx_check_memory_access_rights", "mitee")
class zx_check_memory_access_rights_symbolic(angr.SimProcedure):
    """zx_check_memory_access_rights(perm, buf, size, out): return 0, write 0 to *out."""

    def run(self):
        out_ptr = _arg(self.state, 3)
        _store_at_ptr(self.state, out_ptr, 4 * 8)
        return 0


@ta_function_hook("consttime_memcmp", "mitee")
class consttime_memcmp_symbolic(angr.SimProcedure):
    """consttime_memcmp: constant-time memcmp; return 0 (equal) for symbolic execution."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("time", "mitee")
class time_symbolic(angr.SimProcedure):
    """time(tloc): return symbolic timestamp (e.g. for replay non-determinism)."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEE_KMGetHmacKey", "mitee")
class TEE_KMGetHmacKey_symbolic(angr.SimProcedure):
    """TEE_KMGetHmacKey(buf, size): fill buf with symbolic key bytes, return TEE_SUCCESS."""

    def run(self):
        buf = _arg(self.state, 0)
        size_reg = _arg(self.state, 1)
        n = _safe_size(self.state, size_reg, default=0x20, max_size=0x1000)
        _store_at_ptr(self.state, buf, n * 8)
        return TEE_SUCCESS


# ---------------------------------------------------------------------------
# OPENSSL memory (mitee_api: malloc/free)
# ---------------------------------------------------------------------------


@ta_function_hook("OPENSSL_memory_alloc", "mitee")
class OPENSSL_memory_alloc_symbolic(angr.SimProcedure):
    """OPENSSL_memory_alloc(size): allocate from heap, fill with symbolic."""

    def run(self):
        size_reg = _arg(self.state, 0)
        n = _safe_size(self.state, size_reg, default=256, max_size=0x10000)
        ptr = self.state.heap.allocate(n)
        _store_at_ptr(self.state, ptr, n * 8)
        return ptr


@ta_function_hook("OPENSSL_memory_free", "mitee")
class OPENSSL_memory_free_symbolic(angr.SimProcedure):
    """OPENSSL_memory_free(ptr): no-op."""

    def run(self):
        return None


# ---------------------------------------------------------------------------
# localtime: return pointer to struct (9*4 bytes)
# ---------------------------------------------------------------------------


@ta_function_hook("localtime", "mitee")
class localtime_symbolic(angr.SimProcedure):
    """localtime(timer): return pointer to heap-allocated struct (symbolic contents)."""

    def run(self):
        struct_size = 9 * 4  # 9 ints as in reference
        ptr = self.state.heap.allocate(struct_size)
        _store_at_ptr(self.state, ptr, struct_size * 8)
        return ptr


# ---------------------------------------------------------------------------
# Soter / fingerprint (mitee_api)
# ---------------------------------------------------------------------------

@ta_function_hook("soter_load_fingerprint_result", "mitee")
class soter_load_fingerprint_result_symbolic(angr.SimProcedure):
    """soter_load_fingerprint_result(buf, fp_type): fill buf with symbolic, return 0."""

    def run(self):
        buf = _arg(self.state, 0)
        size = 188  # heuristic
        _store_at_ptr(self.state, buf, size * 8)
        return 0

@ta_function_hook("fdio_get_service_handle", "mitee")
class fdio_get_service_handle_symbolic(angr.SimProcedure):
    """fdio_get_service_handle(name, handle): fill handle with symbolic, return 0."""
    def run(self):
        return 0

# ---------------------------------------------------------------------------
# tee_*: stub returns
# ---------------------------------------------------------------------------

@ta_function_hook("tee_get_cpuid", "mitee")
class tee_get_cpuid_symbolic(angr.SimProcedure):
    """tee_get_cpuid(): return 0."""

    def run(self):
        return 0


@ta_function_hook("tee_se_open_spi_clk", "mitee")
class tee_se_open_spi_clk_symbolic(angr.SimProcedure):
    """tee_se_open_spi_clk(): return 0."""

    def run(self):
        return 0