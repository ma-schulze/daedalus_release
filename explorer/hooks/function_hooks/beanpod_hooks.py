import angr
import claripy

from explorer.memory.ta_taint import get_trusted_mem_bits
from explorer.hooks.function_hooks.func_hooks import ta_function_hook

from utils.logging_config import get_logger

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


# ---------------------------------------------------------------------------
# Logging / printf-style: no-op for symbolic execution
# ---------------------------------------------------------------------------

@ta_function_hook("log_msg", "beanpod")
class log_msg_symbolic(angr.SimProcedure):
    """log_msg(log_level, log_level_2, format, ...): no-op."""

    def run(self):
        return 0 

@ta_function_hook("TEE_LogvPrintf", "beanpod")
class TEE_LogvPrintf_symbolic(angr.SimProcedure):
    """TEE_LogvPrintf: fprintf-style logging; no-op."""

    def run(self):
        return 0 


@ta_function_hook("TEE_LogPrintf", "beanpod")
class TEE_LogPrintf_symbolic(angr.SimProcedure):
    """TEE_LogPrintf: printf-style logging; no-op."""

    def run(self):
        return 0 


@ta_function_hook("ut_pf_log_msg", "beanpod")
class ut_pf_log_msg_symbolic(angr.SimProcedure):
    """ut_pf_log_msg: same as TEE_LogvPrintf; no-op."""

    def run(self):
        return 0 


@ta_function_hook("msee_ta_printf_va", "beanpod")
class msee_ta_printf_va_symbolic(angr.SimProcedure):
    """msee_ta_printf_va: same as TEE_LogPrintf; no-op."""

    def run(self):
        return 0 


@ta_function_hook("localtime", "beanpod")
class localtime_symbolic(angr.SimProcedure):
    """localtime: no-op."""

    def run(self):
        struct_size = 0x32  # TODO
        ptr = self.state.heap.allocate(struct_size)
        _store_at_ptr(self.state, ptr, struct_size * 8)
        return ptr

# ---------------------------------------------------------------------------
# RPMB: session open/close no-op; read/write fill buffers and return success
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_RpmbOpenSession", "beanpod")
class TEE_RpmbOpenSession_symbolic(angr.SimProcedure):
    """TEE_RpmbOpenSession: no-op, return 0."""

    def run(self):
        return 0


@ta_function_hook("TEE_RpmbCloseSession", "beanpod")
class TEE_RpmbCloseSession_symbolic(angr.SimProcedure):
    """TEE_RpmbCloseSession: no-op."""

    def run(self):
        return 0


@ta_function_hook("TEE_RpmbReadData", "beanpod")
class TEE_RpmbReadData_symbolic(angr.SimProcedure):
    """TEE_RpmbReadData(sessionID, buffer, size, retSize): fill buffer, write size to *retSize, return 0."""

    def run(self):
        buf = _arg(self.state, 1)
        size_reg = _arg(self.state, 2)
        ret_size_ptr = _arg(self.state, 3)
        n = _safe_size(self.state, size_reg, default=512, max_size=0x2000)
        _store_at_ptr(self.state, buf, n * 8)
        _store_at_ptr(self.state, ret_size_ptr, 4 * 8)
        return 0


@ta_function_hook("TEE_RpmbWriteData", "beanpod")
class TEE_RpmbWriteData_symbolic(angr.SimProcedure):
    """TEE_RpmbWriteData: no-op, return 0."""

    def run(self):
        return 0


# ---------------------------------------------------------------------------
# mdrv: open returns handle, close no-op
# ---------------------------------------------------------------------------


@ta_function_hook("mdrv_open", "beanpod")
class mdrv_open_symbolic(angr.SimProcedure):
    """mdrv_open: return symbolic handle (concrete reference returns 0x123)."""

    def run(self):
        return 0

@ta_function_hook("mdrv_ioctl", "beanpod")
class mdrv_ioctl_symbolic(angr.SimProcedure):
    """mdrv_ioctl: no-op."""

    def run(self):
        return 0

@ta_function_hook("mdrv_close", "beanpod")
class mdrv_close_symbolic(angr.SimProcedure):
    """mdrv_close: no-op."""

    def run(self):
        return 0


# ---------------------------------------------------------------------------
# ut_pf_cp_rd_random: fill buffer with symbolic bytes
# ---------------------------------------------------------------------------


@ta_function_hook("ut_pf_cp_rd_random", "beanpod")
class ut_pf_cp_rd_random_symbolic(angr.SimProcedure):
    """ut_pf_cp_rd_random(int, buf, size): fill buf with symbolic bytes."""

    def run(self):
        buf = _arg(self.state, 1)
        size_reg = _arg(self.state, 2)
        n = _safe_size(self.state, size_reg, default=32, max_size=4096)
        _store_at_ptr(self.state, buf, n * 8)
        return 0


# ---------------------------------------------------------------------------
# ut_pf_ts_cp_*: trusted storage / container file-like APIs
# ---------------------------------------------------------------------------


@ta_function_hook("ut_pf_ts_cp_exist", "beanpod")
class ut_pf_ts_cp_exist_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_exist(name): return symbolic 0 or 1."""

    def run(self):
        return 0


@ta_function_hook("ut_pf_ts_cp_open", "beanpod")
class ut_pf_ts_cp_open_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_open(name, flags): return symbolic fd (or -1)."""

    def run(self):
        return 0


@ta_function_hook("ut_pf_ts_cp_error", "beanpod")
class ut_pf_ts_cp_error_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_error: return 0."""

    def run(self):
        return 0


@ta_function_hook("ut_pf_ts_cp_write", "beanpod")
class ut_pf_ts_cp_write_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_write(fd, buffer, len): return symbolic bytes written or -1."""

    def run(self):
        return 0


@ta_function_hook("ut_pf_ts_cp_read", "beanpod")
class ut_pf_ts_cp_read_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_read(fd, buffer, len): fill buffer with symbolic, return symbolic count."""

    def run(self):
        buf = _arg(self.state, 1)
        size_reg = _arg(self.state, 2)
        n = _safe_size(self.state, size_reg, default=256, max_size=0x2000)
        _store_at_ptr(self.state, buf, n * 8)
        return 0


@ta_function_hook("ut_pf_ts_cp_close", "beanpod")
class ut_pf_ts_cp_close_symbolic(angr.SimProcedure):
    """ut_pf_ts_cp_close(fd): return 0 or -1 (symbolic)."""

    def run(self):
        return 0


@ta_function_hook("ut_pf_cp_gk_rsakey", "beanpod")
class ut_pf_cp_gk_rsakey_symbolic(angr.SimProcedure):
    """ut_pf_cp_gk_rsakey(fd, e, e_size, n, n_size, d, d_size): return 0."""

    def run(self):
        logger.error("TODO IMPLEMENT ME!")
        return 0


@ta_function_hook("ut_pf_km_enc_pw", "beanpod")
class ut_pf_km_enc_pw_symbolic(angr.SimProcedure):
    """ut_pf_km_enc_pw(pw, pw_size, buf, buf_size): return 0."""

    def run(self):
        out_buff = _arg(self.state, 2)
        out_buff_size = _arg(self.state, 3)
        _store_at_ptr(self.state, out_buff, 0x20 * 8)  # sizes are taken from TÄMU
        _store_ptr_at(self.state, out_buff_size, claripy.BVV(0x20, self.state.arch.bits))
        
        return 0


@ta_function_hook("ut_pf_km_get_hmac_key", "beanpod")
class ut_pf_km_get_hmac_key_symbolic(angr.SimProcedure):
    """ut_pf_km_get_hmac_key(key_size, key_ptr): return 0."""

    def run(self):
        key_ptr = _arg(self.state, 0)
        key_size_ptr = _arg(self.state, 1)
        key_size = self.state.memory.load(key_size_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            key_size = self.state.solver.eval_one(key_size)
        except Exception as e:
            logger.error(f"Error evaluating key_size: {e}")
            key_size = 32
        _store_at_ptr(self.state, key_ptr, key_size * 8)
        return 0

@ta_function_hook("ut_pf_log_msg_fake", "beanpod")
class ut_pf_log_msg_fake_symbolic(angr.SimProcedure):
    """ut_pf_log_msg_fake(level, format, ...): no-op."""

    def run(self):
        return 0

@ta_function_hook("ut_pf_cp_open", "beanpod")
class ut_pf_cp_open_symbolic(angr.SimProcedure):
    """ut_pf_cp_open(name, flags): return symbolic fd (or -1)."""

    def run(self):
        ptr = _arg(self.state, 0)
        new_ptr = self.state.heap.allocate(0x5a0)
        _store_at_ptr(self.state, new_ptr, 0x5a0 * 8)
        _store_ptr_at(self.state, ptr, claripy.BVV(new_ptr, self.state.arch.bits))
        return 0


@ta_function_hook("ut_pf_cp_close", "beanpod")
class ut_pf_cp_close_symbolic(angr.SimProcedure):
    """ut_pf_cp_close(fd): return 0 or -1 (symbolic)."""
    def run(self):
        return 0


@ta_function_hook("ut_pf_rpmb_open", "beanpod")
class ut_pf_rpmb_open_symbolic(angr.SimProcedure):
    """ut_pf_rpmb_open: return symbolic handle (concrete reference returns 0x123)."""

    def run(self):
        return 0

@ta_function_hook("ut_pf_rpmb_read_data_blocks", "beanpod")
class ut_pf_rpmb_read_data_blocks_symbolic(angr.SimProcedure):
    """ut_pf_rpmb_read_data_blocks: fill buffer with symbolic bytes."""

    def run(self):
        buf = _arg(self.state, 1)
        size_reg = _arg(self.state, 2)
        n = _safe_size(self.state, size_reg, default=512, max_size=0x2000)
        _store_at_ptr(self.state, buf, n * 8)
        return 0


@ta_function_hook("ut_pf_rpmb_close", "beanpod")
class ut_pf_rpmb_close_symbolic(angr.SimProcedure):
    """ut_pf_rpmb_close: no-op."""

    def run(self):
        return 0