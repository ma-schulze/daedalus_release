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
# TEES secure object / REE / driver (from teegris_api.py)
# ---------------------------------------------------------------------------

@ta_function_hook("TEES_UnwrapSecureObject", "teegris")
class TEES_UnwrapSecureObject_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_WrapSecureObject", "teegris")
class TEES_WrapSecureObject_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_IsREESharedMemory", "teegris")
class TEES_IsREESharedMemory_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_GetIrsFlagValue", "teegris")
class TEES_GetIrsFlagValue_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_CheckSecureObjectCreator", "teegris")
class TEES_CheckSecureObjectCreator_symbolic(angr.SimProcedure):
    """Reference returns 1 (true)."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_InitDriver", "teegris")
class TEES_InitDriver_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_FiniDriver", "teegris")
class TEES_FiniDriver_symbolic(angr.SimProcedure):
    """Cleanup counterpart of TEES_InitDriver (from TA PLT)."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_DeriveKeyKDF", "teegris")
class TEES_DeriveKeyKDF_symbolic(angr.SimProcedure):
    """Key derivation (from TA PLT). Return TEE_SUCCESS."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


# ---------------------------------------------------------------------------
# Device open/write/close (_open, _write, _close)
# ---------------------------------------------------------------------------

@ta_function_hook("open", "teegris")
class open_symbolic(angr.SimProcedure):
    """open(path) -> fd. Return symbolic fd."""

    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("write", "teegris")
class write_symbolic(angr.SimProcedure):
    """write(fd, buf, len) -> bytes written. Return symbolic or len."""

    def run(self):
        len_reg = _arg(self.state, 2)
        try:
            n = self.state.solver.eval_one(len_reg)
        except Exception:
            return get_trusted_mem_bits(self.state, 32)
        return n if isinstance(n, int) and n >= 0 else get_trusted_mem_bits(self.state, 32)


@ta_function_hook("read", "teegris")
class read_symbolic(angr.SimProcedure):
    def run(self, fd, buf, len):
        n = _safe_size(self.state, len, default=256, max_size=0x2000)
        _store_at_ptr(self.state, buf, n * 8)
        return get_trusted_mem_bits(self.state, 32)

@ta_function_hook("close", "teegris")
class close_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


# ---------------------------------------------------------------------------
# Teegris log / RPMB / ICCC / sleep / TUI
# ---------------------------------------------------------------------------

@ta_function_hook("teegris_log_encrypt", "teegris")
class teegris_log_encrypt_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_El2if", "teegris")
class TEES_El2if_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_TUIGetScreenInfo", "teegris")
class TEES_TUIGetScreenInfo_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_TUIOpenSession", "teegris")
class TEES_TUIOpenSession_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_RPMBCheckEnable", "teegris")
class TEES_RPMBCheckEnable_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_RPMBRead", "teegris")
class TEES_RPMBRead_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("hdm_ICCC_check", "teegris")
class hdm_ICCC_check_symbolic(angr.SimProcedure):
    """Reference returns 0x19."""

    def run(self):
        return get_trusted_mem_bits(self.state, _ptr_bits(self.state))


@ta_function_hook("mpos_ICCC_check", "teegris")
class mpos_ICCC_check_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("nanosleep", "teegris")
class nanosleep_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TA_Communication_mpos_check_iccc", "teegris")
class TA_Communication_mpos_check_iccc_symbolic(angr.SimProcedure):
    """result* (out) -> write 0, return TEE_SUCCESS."""

    def run(self):
        result_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, result_ptr, 32)
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_TUIOpenSession", "teegris")
class TEES_TUIOpenSession_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_TUIDrawImage", "teegris")
class TEES_TUIDrawImage_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_TUIRefreshScreen", "teegris")
class TEES_TUICloseSession_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_SPIInit", "teegris")
class TEES_SPIInit_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_HDCP_SetKeyInfo", "teegris")
class TEES_HDCP_SetKeyInfo_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_SMCCommand", "teegris")
class TEES_SMCCommand_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("TEES_SMCFini", "teegris")
class TEES_SMCFini_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_SMCInit", "teegris")
class TEES_SMCInit_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("TEES_GetClientCredentials", "teegris")
class TEES_GetClientCredentials_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

# ---------------------------------------------------------------------------
# OpenSSL / EC (malloc, free, key free)
# ---------------------------------------------------------------------------

@ta_function_hook("OPENSSL_malloc", "teegris")
class OPENSSL_malloc_symbolic(angr.SimProcedure):
    """OPENSSL_malloc(size) -> ptr. Allocate from heap, fill with symbolic."""

    def run(self):
        size_reg = _arg(self.state, 0)
        n = _safe_size(self.state, size_reg, default=256, max_size=64 * 1024)
        ptr = self.state.heap.allocate(n)
        _store_at_ptr(self.state, ptr, n * 8)
        return ptr


@ta_function_hook("OPENSSL_free", "teegris")
class OPENSSL_free_symbolic(angr.SimProcedure):
    def run(self):
        return None

@ta_function_hook("EVP_sha1", "teegris")
class EVP_sha1_symbolic(angr.SimProcedure):
    sha1 = None
    def run(self):
        if self.sha1 is None:
            self.sha1 = self.state.heap.allocate(256)
        return self.sha1

@ta_function_hook("EVP_PKEY_free", "teegris")
class EVP_PKEY_free_symbolic(angr.SimProcedure):
    def run(self):
        return None


@ta_function_hook("EVP_PKEY_CTX_free", "teegris")
class EVP_PKEY_CTX_free_symbolic(angr.SimProcedure):
    def run(self):
        return None


@ta_function_hook("EVP_MD_CTX_free", "teegris")
class EVP_MD_CTX_free_symbolic(angr.SimProcedure):
    def run(self):
        return None


@ta_function_hook("EVP_MD_CTX_new", "teegris")
class EVP_MD_CTX_new_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("EVP_DigestInit_ex", "teegris")
class EVP_DigestInit_ex_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("EVP_DigestUpdate", "teegris")
class EVP_DigestUpdate_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("EVP_DigestFinal_ex", "teegris")
class EVP_DigestFinal_ex_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("EVP_sha256", "teegris")
class EVP_sha256_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)



@ta_function_hook("EC_KEY_free", "teegris")
class EC_KEY_free_symbolic(angr.SimProcedure):
    def run(self):
        return None


@ta_function_hook("EC_POINT_free", "teegris")
class EC_POINT_free_symbolic(angr.SimProcedure):
    def run(self):
        return None

@ta_function_hook("ASN1_STRING_get0_data", "teegris")
class ASN1_STRING_get0_data(angr.SimProcedure):
    def run(self):
        asn1_string_ptr = _arg(self.state, 0)
        # offset of data field inside ASN1_STRING
        data_offset = 8  # TODO, check if this is correct

        data_ptr = self.state.memory.load(
            asn1_string_ptr + data_offset,
            self.state.arch.bytes,
            endness=self.state.arch.memory_endness
        )

        return data_ptr

@ta_function_hook("ASN1_STRING_length", "teegris")
class ASN1_STRING_length(angr.SimProcedure):
    def run(self):
        asn1_string_ptr = _arg(self.state, 0)
        length_offset = 8  # TODO, check if this is correct
        length = self.state.memory.load(
            asn1_string_ptr + length_offset,
            self.state.arch.bytes,
            endness=self.state.arch.memory_endness)

        return length

@ta_function_hook("ASN1_OCTET_STRING_free", "teegris")
class ASN1_OCTET_STRING_free_symbolic(angr.SimProcedure):
    def run(self):
        return None

@ta_function_hook("ASN1_OCTET_STRING_new", "teegris")
class ASN1_OCTET_STRING_new_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("ASN1_item_free", "teegris")
class ASN1_item_free_symbolic(angr.SimProcedure):
    def run(self):
        return None

@ta_function_hook("ASN1_item_new", "teegris")
class ASN1_item_new_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)


@ta_function_hook("EC_KEY_new_by_curve_name", "teegris")
class EC_KEY_new_by_curve_name_symbolic(angr.SimProcedure):
    def run(self):
        new_key = self.state.heap.allocate(36)
        return new_key


@ta_function_hook("EC_KEY_generate_key", "teegris")
class EC_KEY_generate_key_symbolic(angr.SimProcedure):
    def run(self):
        return 0 

@ta_function_hook("BN_new", "teegris")
class BN_new_symbolic(angr.SimProcedure):
    def run(self):
        bn = self.state.heap.allocate(24)
        return bn

@ta_function_hook("BN_set_word", "teegris")
class BN_set_word_symbolic(angr.SimProcedure):
    def run(self):
        return 0 

@ta_function_hook("BN_free", "teegris")
class BN_free_symbolic(angr.SimProcedure):
    def run(self):
        return 0 

# ---------------------------------------------------------------------------
# Libc exit (from TA PLT; without hook we step to 0x301038 and show as <unknown>)
# ---------------------------------------------------------------------------

@ta_function_hook("ASN1_STRING_get0_data", "teegris")
class ASN1_STRING_get0_data_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("ASN1_STRING_length", "teegris")
class ASN1_STRING_length_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)

@ta_function_hook("exit", "teegris")
class exit_symbolic(angr.SimProcedure):
    """exit(status). Do not step into TEE/OS; add exit successor instead."""

    NO_RET = True

    def run(self, status=None):
        if status is None:
            status = _arg(self.state, 0)
        try:
            code = self.state.solver.eval_one(status)
        except Exception:
            code = 0
        if not isinstance(code, int):
            code = 0
        self.exit(code)


# ---------------------------------------------------------------------------
# Other stuff 
# ---------------------------------------------------------------------------

@ta_function_hook("get_errno_addr", "teegris")
class get_errno_addr_symbolic(angr.SimProcedure):
    
    errno_addr = 0
    
    def run(self):
        if self.errno_addr == 0:
            self.errno_addr = self.state.heap.allocate(8)
            _store_at_ptr(self.state, self.errno_addr, 64)
        
        return claripy.BVV(self.errno_addr, self.state.arch.bits)


@ta_function_hook("uuid_compare", "teegris")
class uuid_compare_symbolic(angr.SimProcedure):
    def run(self):
        return get_trusted_mem_bits(self.state, self.state.arch.bits)
