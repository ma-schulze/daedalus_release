"""
Symbolic replacements for Global Platform TEE Internal Core API functions.
Designed for symbolic execution of ARM TrustZone TAs: return success, fill
in/out pointers with symbolic data, use heap for allocation, ignore frees.
"""

import angr
import claripy
import random
from explorer.memory import get_trusted_mem_bits
from explorer.hooks.function_hooks.func_hooks import ta_function_hook
from explorer.memory.ta_taint import get_trusted_mem_bits
from reporting import add_detected_bug
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
    
    if isinstance(ptr, int):
        ptr = claripy.BVV(ptr, _ptr_bits(state))
    state.memory.store(ptr, get_trusted_mem_bits(state, num_bits), size=num_bits // 8, endness=endness)


def _store_ptr_at(state, ptr, value_bv=None, endness=None):
    """Store a pointer-sized value at ptr (e.g. handle). If value_bv is None, store symbolic."""
    bits = _ptr_bits(state)
    if endness is None:
        endness = state.arch.memory_endness
    val = get_trusted_mem_bits(state, bits) if value_bv is None else value_bv
    state.memory.store(ptr, val, size=bits // 8, endness=endness)


# ---------------------------------------------------------------------------
# Core allocation (existing, 32-bit fix)
# ---------------------------------------------------------------------------

@ta_function_hook("TEE_Malloc", "gp")
class TEE_Malloc_symbolic(angr.SimProcedure):
    """
    Symbolic implementation of TEE_Malloc. Allocates from SimHeap and
    fills the block with symbolic bytes.
    """

    def run(self):
        data_len = _arg(self.state, 0)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        data_len = self.state.heap._conc_alloc_size(data_len)
        ptr = self.state.heap.allocate(data_len)
        _store_at_ptr(self.state, ptr, data_len * 8)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        ret_ptr = claripy.BVV(ptr, _ptr_bits(self.state))
        return ret_ptr


@ta_function_hook("TEE_Free", "gp")
class TEE_Free_symbolic(angr.SimProcedure):
    """Symbolic implementation of TEE_Free. No-op (ignore frees)."""

    def run(self):
        free_addr = _arg(self.state, 0)
        self.state._inspect(
            'free',
            when=angr.BP_BEFORE,
            address=free_addr,
        )
        return 0


# ---------------------------------------------------------------------------
# Crypto operations
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_AllocateOperation", "gp")
class TEE_AllocateOperation_symbolic(angr.SimProcedure):
    """operation*, algorithm, mode, maxKeySize -> TEE_SUCCESS; fills *operation with handle."""

    def run(self):
        op_out = _arg(self.state, 0)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        op = self.state.heap.allocate(72)  # 72 bytes is the size of the operation structure
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        op = claripy.BVV(op, _ptr_bits(self.state))
        _store_at_ptr(self.state, op, 72 * 8)

        # store buffer in operation handle 
        buffer = self.state.heap.allocate(0x1000)  # just a guess, hopefully big enough
        ptr_size = _ptr_bits(self.state) // 8
        buffer_offset = 32 + ptr_size * 2 + 4
        _store_ptr_at(self.state, op + buffer_offset, claripy.BVV(buffer, ptr_size * 8))   
        _store_ptr_at(self.state, op_out, op)
        return 0


@ta_function_hook("TEE_DigestUpdate", "gp")
class TEE_DigestUpdate_symbolic(angr.SimProcedure):
    """operation, chunk*, chunkSize. No return value (void)."""

    def run(self):
        return None


@ta_function_hook("TEE_DigestDoFinal", "gp")
class TEE_DigestDoFinal_symbolic(angr.SimProcedure):
    """operation, chunk*, chunkLen, hash*, hashLen* -> TEE_SUCCESS. Fills hash and *hashLen."""

    def run(self):
        hash_ptr = _arg(self.state, 3)
        hash_len_ptr = _arg(self.state, 4)
        print(f"hash_len_ptr: {hash_len_ptr}")
        print(f"hash_ptr: {hash_ptr}")
        hash_len = self.state.memory.load(hash_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        print(f"hash_len: {hash_len}")
        try: 
            hash_len = self.state.solver.eval_one(hash_len)
        except Exception as e:
            logger.error(f"Error evaluating hash_len: {e}")
            hash_len = 32
        print(f"hash_len: {hash_len}")
        # _store_at_ptr(self.state, hash_ptr, hash_len * 8)  # e.g. 32-byte hash 

        return 0


@ta_function_hook("TEE_FreeOperation", "gp")
class TEE_FreeOperation_symbolic(angr.SimProcedure):
    """operation. Ignore (no-op)."""

    def run(self):
        return None


@ta_function_hook("TEE_SetOperationKey", "gp")
class TEE_SetOperationKey_symbolic(angr.SimProcedure):
    """operation, key -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_SetOperationKey2", "gp")
class TEE_SetOperationKey2_symbolic(angr.SimProcedure):
    """operation, key -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_AsymmetricSignDigest", "gp")
class TEE_AsymmetricSignDigest_symbolic(angr.SimProcedure):
    """Return success."""

    def run(self):
        sig_ptr = _arg(self.state, 5)
        sig_len_ptr = _arg(self.state, 6)
        sig_len = self.state.memory.load(sig_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            sig_len = self.state.solver.eval_one(sig_len)
        except Exception as e:
            logger.error(f"Error evaluating sig_len: {e}")
            sig_len = 32
        _store_at_ptr(self.state, sig_ptr, sig_len * 8)
        return 0


@ta_function_hook("TEE_AsymmetricVerifyDigest", "gp")
class TEE_AsymmetricVerifyDigest_symbolic(angr.SimProcedure):
    """Return success."""

    def run(self):
        return 0


@ta_function_hook("TEE_AsymmetricEncrypt", "gp")
class TEE_AsymmetricEncrypt_symbolic(angr.SimProcedure):
    """Fills destData and *destLen; returns TEE_SUCCESS."""

    def run(self):
        dest_ptr = _arg(self.state, 5)
        dest_len_ptr = _arg(self.state, 6)
        dest_len = self.state.memory.load(dest_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            dest_len = self.state.solver.eval_one(dest_len)
        except Exception as e:
            logger.error(f"Error evaluating dest_len: {e}")
            dest_len = 32
        _store_at_ptr(self.state, dest_ptr, dest_len * 8)
        return 0

@ta_function_hook("TEE_AsymmetricDecrypt", "gp")
class TEE_AsymmetricDecrypt_symbolic(angr.SimProcedure):
    """Fills destData and *destLen; returns TEE_SUCCESS."""

    def run(self):
        dest_ptr = _arg(self.state, 5)
        dest_len_ptr = _arg(self.state, 6)
        dest_len = self.state.memory.load(dest_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            dest_len = self.state.solver.eval_one(dest_len)
        except Exception as e:
            logger.error(f"Error evaluating dest_len: {e}")
            dest_len = 32
        _store_at_ptr(self.state, dest_ptr, dest_len * 8)
        return 0


@ta_function_hook("TEE_CipherInit", "gp")
class TEE_CipherInit_symbolic(angr.SimProcedure):
    """operation, IV*, IVLen. Void."""

    def run(self):
        return 


@ta_function_hook("TEE_CipherUpdate", "gp")
class TEE_CipherUpdate_symbolic(angr.SimProcedure):
    """operation, srcData*, srcLen, dstData*, *dstLen. Void."""

    def run(self):
        dst_len_ptr = _arg(self.state, 4)
        _store_at_ptr(self.state, dst_len_ptr, _ptr_bits(self.state))
        return 

@ta_function_hook("TEE_CipherDoFinal", "gp")
class TEE_CipherDoFinal_symbolic(angr.SimProcedure):
    """Fills dstData and *dstLen; returns TEE_SUCCESS."""

    def run(self):
        dst_data = _arg(self.state, 3)
        dst_len = _arg(self.state, 4)
        _store_at_ptr(self.state, dst_data, 256 * 8)
        _store_ptr_at(self.state, dst_len, claripy.BVV(256, _ptr_bits(self.state)))
        return 0


@ta_function_hook("TEE_MACInit", "gp")
class TEE_MACInit_symbolic(angr.SimProcedure):
    """operation, iv*, ivLen*. Void."""

    def run(self):
        return None


@ta_function_hook("TEE_MACUpdate", "gp")
class TEE_MACUpdate_symbolic(angr.SimProcedure):
    """operation, srcData*, srcLen. Void."""

    def run(self):
        return None


@ta_function_hook("TEE_MACComputeFinal", "gp")
class TEE_MACComputeFinal_symbolic(angr.SimProcedure):
    """Fills mac* and *macLen; returns TEE_SUCCESS."""

    def run(self):
        mac_ptr = _arg(self.state, 3)
        mac_len_ptr = _arg(self.state, 4)
        mac_len = self.state.memory.load(mac_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            mac_len = self.state.solver.eval_one(mac_len)
        except Exception as e:
            logger.error(f"Error evaluating mac_len: {e}")
            mac_len = 32
        _store_at_ptr(self.state, mac_ptr, mac_len * 8)
        _store_ptr_at(self.state, mac_len_ptr, get_trusted_mem_bits(self.state, _ptr_bits(self.state)))
        return 0


# ---------------------------------------------------------------------------
# Transient objects
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_AllocateTransientObject", "gp")
class TEE_AllocateTransientObject_symbolic(angr.SimProcedure):
    """objectType, maxObjectSize, object* -> TEE_SUCCESS. Fills *object with handle."""

    # TODO: is this okey?
    def run(self):
        obj_out = _arg(self.state, 2)
        _store_ptr_at(self.state, obj_out)
        return 0


@ta_function_hook("TEE_GenerateKey", "gp")
class TEE_GenerateKey_symbolic(angr.SimProcedure):
    """object, keySize, params*, paramCount -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_PopulateTransientObject", "gp")
class TEE_PopulateTransientObject_symbolic(angr.SimProcedure):
    """object, attrs*, attrCount -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_ResetTransientObject", "gp")
class TEE_ResetTransientObject_symbolic(angr.SimProcedure):
    """object. Void."""

    def run(self):
        return None


@ta_function_hook("TEE_FreeTransientObject", "gp")
class TEE_FreeTransientObject_symbolic(angr.SimProcedure):
    """object. Ignore (no-op)."""

    def run(self):
        return None


@ta_function_hook("TEE_InitRefAttribute", "gp")
class TEE_InitRefAttribute_symbolic(angr.SimProcedure):
    """attr*, attributeID, buffer*, length. Void."""

    def run(self):
        out_size = 32 + 2 * self.state.arch.bits
        _store_at_ptr(self.state, _arg(self.state, 0), out_size)
        return 


@ta_function_hook("TEE_InitValueAttribute", "gp")
class TEE_InitValueAttribute_symbolic(angr.SimProcedure):
    """attr*, attributeID, a*, b. Void."""

    def run(self):
        out_size = 32 + 2 * self.state.arch.bits
        _store_at_ptr(self.state, _arg(self.state, 0), out_size)
        return 


@ta_function_hook("TEE_CopyObjectAttributes1", "gp")
class TEE_CopyObjectAttributes1_symbolic(angr.SimProcedure):
    """destObject, srcObject -> TEE_SUCCESS."""

    def run(self):
        return 0


# ---------------------------------------------------------------------------
# General objects
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_GetObjectBufferAttribute", "gp")
class TEE_GetObjectBufferAttribute_symbolic(angr.SimProcedure):
    """object, attributeID, buffer*, size* -> TEE_SUCCESS. Fills buffer and *size."""

    def run(self):
        buf_ptr = _arg(self.state, 2)
        size_ptr = _arg(self.state, 3)
        size = self.state.memory.load(size_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        try:
            size = self.state.solver.max(size)
        except Exception as e:
            logger.error(f"Error evaluating size: {e}")
            size = 32
        _store_at_ptr(self.state, buf_ptr, size * 8)
        size_bits = get_trusted_mem_bits(self.state, _ptr_bits(self.state))
        in_size = claripy.BVV(size, _ptr_bits(self.state))
        self.state.solver.add(size_bits <= in_size)
        _store_ptr_at(self.state, size_ptr, size_bits)
        return 0


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_GetPropertyAsUUID", "gp")
class TEE_GetPropertyAsUUID_symbolic(angr.SimProcedure):
    """propsetOrEnumerator, name*, value* -> TEE_SUCCESS. value is 16-byte UUID."""

    def run(self):
        value_ptr = _arg(self.state, 2)
        _store_at_ptr(self.state, value_ptr, 16 * 8)
        return 0


# ---------------------------------------------------------------------------
# Persistent objects
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_CreatePersistentObject", "gp")
class TEE_CreatePersistentObject_symbolic(angr.SimProcedure):
    """storageID, objectID*, objectIDLen, flags, attributes*, initialData*, initialDataLen, object* -> TEE_SUCCESS."""

    def run(self):
        obj_out = _arg(self.state, 7)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        handle = self.state.heap.allocate(_ptr_bits(self.state) // 8)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        _store_ptr_at(self.state, obj_out, claripy.BVV(handle, _ptr_bits(self.state)))
        return 0


@ta_function_hook("TEE_OpenPersistentObject", "gp")
class TEE_OpenPersistentObject_symbolic(angr.SimProcedure):
    """storageID, objectID*, objectIDLen, flags, object* -> TEE_SUCCESS."""

    def run(self):
        obj_out = _arg(self.state, 4)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        handle = self.state.heap.allocate(_ptr_bits(self.state) // 8)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        _store_ptr_at(self.state, obj_out, claripy.BVV(handle, _ptr_bits(self.state)))
        return 0


@ta_function_hook("TEE_WriteObjectData", "gp")
class TEE_WriteObjectData_symbolic(angr.SimProcedure):
    """object, buffer*, size -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_SeekObjectData", "gp")
class TEE_SeekObjectData_symbolic(angr.SimProcedure):
    """object, offset, whence -> TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_CloseObject", "gp")
class TEE_CloseObject_symbolic(angr.SimProcedure):
    """object. Return TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_CloseAndDeletePersistentObject", "gp")
class TEE_CloseAndDeletePersistentObject_symbolic(angr.SimProcedure):
    """object. Ignore (no-op)."""

    def run(self):
        return 0


@ta_function_hook("TEE_CloseAndDeletePersistentObject1", "gp")
class TEE_CloseAndDeletePersistentObject1_symbolic(angr.SimProcedure):
    """object. Ignore (no-op)."""

    def run(self):
        return 0


@ta_function_hook("TEE_ReadObjectData", "gp")
class TEE_ReadObjectData_symbolic(angr.SimProcedure):
    """object, buffer*, size, count* -> TEE_SUCCESS. Fills buffer and *count."""

    def run(self):
        buf_ptr = _arg(self.state, 1)
        count_ptr = _arg(self.state, 3)
        size = _arg(self.state, 2)
        try:
            n = self.state.solver.eval_one(size)
        except Exception:
            n = 256
        if not isinstance(n, int) or n <= 0 or n > 1024 * 1024:
            n = 256
        _store_at_ptr(self.state, buf_ptr, n * 8)
        counter = get_trusted_mem_bits(self.state, self.state.arch.bits)
        self.state.solver.add(counter <= claripy.BVV(n, self.state.arch.bits))
        _store_ptr_at(self.state, count_ptr, counter)
        return 0


@ta_function_hook("TEE_GetObjectInfo", "gp")
class TEE_GetObjectInfo_symbolic(angr.SimProcedure):
    """object, objectInfo* -> TEE_SUCCESS. Fills TEE_ObjectInfo (objectType, objectSize, ...)."""

    def run(self):
        info_ptr = _arg(self.state, 1)
        obj_info_size = 5 * 32 + 2 * self.state.arch.bits
        _store_at_ptr(self.state, info_ptr, obj_info_size)  # 7 uint32_t fields
        return 0


@ta_function_hook("TEE_GetObjectInfo1", "gp")
class TEE_GetObjectInfo1_symbolic(angr.SimProcedure):
    """Alias for TEE_GetObjectInfo."""

    def run(self):
        info_ptr = _arg(self.state, 1)
        obj_info_size = 5 * 32 + 2 * self.state.arch.bits
        _store_at_ptr(self.state, info_ptr, obj_info_size)  # 7 uint32_t fields
        return 0


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


"""
This is a massive TODO! 
We need to handle the session properly.
We can probably do this like in the os_hooks for the according syscalls?
"""
@ta_function_hook("TEE_OpenTASession", "gp")
class TEE_OpenTASession_symbolic(angr.SimProcedure):
    """destination*, timeout, paramTypes, params*, session*, returnOrigin* -> TEE_SUCCESS."""

    # TEE param type constants (GP API)
    TEE_PARAM_TYPE_NONE = 0
    TEE_PARAM_TYPE_VALUE_INPUT = 1
    TEE_PARAM_TYPE_VALUE_OUTPUT = 2
    TEE_PARAM_TYPE_VALUE_INOUT = 3
    TEE_PARAM_TYPE_MEMREF_INPUT = 5
    TEE_PARAM_TYPE_MEMREF_OUTPUT = 6
    TEE_PARAM_TYPE_MEMREF_INOUT = 7
    TEE_NUM_PARAMS = 4
    
    def run(self):
        destination_addr = _arg(self.state, 0)
        timeout = _arg(self.state, 1)
        param_types = _arg(self.state, 2)
        utee_params_addr = _arg(self.state, 3)
        session_addr = _arg(self.state, 4)
        ret_origin_addr = _arg(self.state, 5)
        ptr_bits = _ptr_bits(self.state)

        logger.info(f"TEE_OpenTASession called, destination_addr: {destination_addr}, timeout: {timeout}, param_types: {param_types}, utee_params_addr: {utee_params_addr}, session_addr: {session_addr}, ret_origin_addr: {ret_origin_addr}, ptr_bits: {ptr_bits}")

        _store_at_ptr(self.state, ret_origin_addr, 32)  # result in params stems from the called TA  
        _store_at_ptr(self.state, session_addr, 32)

        try:
            param_types = self.state.solver.eval_one(param_types)
        except Exception:
            logger.warning(f"Error evaluating param_types in TEE_OpenTASession, continuing")
            return 0

        for n in range(self.TEE_NUM_PARAMS):
            param_type = (param_types >> (n * 4)) & 0xF
            if param_type == self.TEE_PARAM_TYPE_NONE:
                continue
            val_a_offset = utee_params_addr + (n * 2 * (ptr_bits // 8))
            val_b_offset = utee_params_addr + (n * 2 * (ptr_bits // 8)) + (ptr_bits // 8)
            logger.info("a") 
            val_a = self.state.memory.load(val_a_offset, ptr_bits // 8, endness=self.state.arch.memory_endness)
            val_b = self.state.memory.load(val_b_offset, ptr_bits // 8, endness=self.state.arch.memory_endness)
            logger.info(f"val_a: {val_a}, val_b: {val_b}")
            if param_type in (self.TEE_PARAM_TYPE_VALUE_INOUT, self.TEE_PARAM_TYPE_VALUE_OUTPUT):
                # Fill value.a and value.b with tainted symbolic values
                logger.info(f"Filling value.a and value.b with tainted symbolic values")
                _store_at_ptr(self.state, val_a_offset, ptr_bits)
                _store_at_ptr(self.state, val_b_offset, ptr_bits)

            elif param_type in (self.TEE_PARAM_TYPE_MEMREF_OUTPUT, self.TEE_PARAM_TYPE_MEMREF_INOUT):
                logger.info(f"Filling buffer_ptr with tainted symbolic values 0")
                try:
                    buffer_ptr = self.state.solver.eval_one(val_a)
                    size = self.state.solver.eval_one(val_b)
                except Exception:
                    logger.info(f"Exception in TEE_OpenTASession, continuing")
                    continue
                
                if size > 0x8000:
                    logger.info("Limiting size to 0x8000")
                    size = 0x8000
                
                logger.info(f"Filling buffer_ptr with tainted symbolic values")
                _store_at_ptr(self.state, buffer_ptr, size * 8)
            else:
                type_names = {
                    self.TEE_PARAM_TYPE_NONE: "NONE",
                    self.TEE_PARAM_TYPE_VALUE_INPUT: "VALUE_INPUT",
                    self.TEE_PARAM_TYPE_MEMREF_INPUT: "MEMREF_INPUT",
                }
                type_name = type_names.get(param_type, f"UNKNOWN({param_type})")

        logger.info(f"TEE_OpenTASession called, returning 0")
        return 0



@ta_function_hook("TEE_InvokeTACommand", "gp")
class TEE_InvokeTACommand_symbolic(angr.SimProcedure):
    """session, timeout, commandID, paramTypes, params*, returnOrigin* -> TEE_SUCCESS. params is inout."""

    # TEE param type constants (GP API)
    TEE_PARAM_TYPE_NONE = 0
    TEE_PARAM_TYPE_VALUE_INPUT = 1
    TEE_PARAM_TYPE_VALUE_OUTPUT = 2
    TEE_PARAM_TYPE_VALUE_INOUT = 3
    TEE_PARAM_TYPE_MEMREF_INPUT = 5
    TEE_PARAM_TYPE_MEMREF_OUTPUT = 6
    TEE_PARAM_TYPE_MEMREF_INOUT = 7
    TEE_NUM_PARAMS = 4
    
    def run(self):
        session_addr = _arg(self.state, 0)
        timeout = _arg(self.state, 1)
        command_id = _arg(self.state, 2)
        param_types = _arg(self.state, 3)
        utee_params_addr = _arg(self.state, 4)
        ret_origin_addr = _arg(self.state, 5)
        ptr_bits = _ptr_bits(self.state)


        try:
            param_types = self.state.solver.eval_one(param_types)
        except Exception:
            logger.warning(f"Error evaluating param_types in TEE_InvokeTACommand, continuing")
            return 0

        _store_at_ptr(self.state, ret_origin_addr, 32)  # result in params stems from the called TA 

        for n in range(self.TEE_NUM_PARAMS):
            param_type = (param_types >> (n * 4)) & 0xF

            val_a_offset = utee_params_addr + (n * 2 * (ptr_bits // 8))
            val_b_offset = utee_params_addr + (n * 2 * (ptr_bits // 8)) + (ptr_bits // 8)
        
            val_a = self.state.memory.load(val_a_offset, ptr_bits // 8, endness=self.state.arch.memory_endness)
            val_b = self.state.memory.load(val_b_offset, ptr_bits // 8, endness=self.state.arch.memory_endness)

            if param_type in (self.TEE_PARAM_TYPE_VALUE_INOUT, self.TEE_PARAM_TYPE_VALUE_OUTPUT):
                # Fill value.a and value.b with tainted symbolic values
                _store_at_ptr(self.state, val_a_offset, ptr_bits)
                _store_at_ptr(self.state, val_b_offset, ptr_bits)

            elif param_type in (self.TEE_PARAM_TYPE_MEMREF_OUTPUT, self.TEE_PARAM_TYPE_MEMREF_INOUT):
                try:
                    buffer_ptr = self.state.solver.eval_one(val_a)
                    size = self.state.solver.eval_one(val_b)
                except Exception:
                    continue

                if size > 0x8000:
                    logger.info("Limiting size to 0x8000")
                    size = 0x8000
                
                _store_at_ptr(self.state, buffer_ptr, size * 8)
            else:
                type_names = {
                    self.TEE_PARAM_TYPE_NONE: "NONE",
                    self.TEE_PARAM_TYPE_VALUE_INPUT: "VALUE_INPUT",
                    self.TEE_PARAM_TYPE_MEMREF_INPUT: "MEMREF_INPUT",
                }
                type_name = type_names.get(param_type, f"UNKNOWN({param_type})")

        return 0


@ta_function_hook("TEE_CloseTASession", "gp")
class TEE_CloseTASession_symbolic(angr.SimProcedure):
    """session. Ignore (no-op)."""

    def run(self):
        return 0


# ---------------------------------------------------------------------------
# BigInt (all return success or fill output; pointer args filled with symbolic)
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_BigIntInit", "gp")
class TEE_BigIntInit_symbolic(angr.SimProcedure):
    """buf*, len*. Void (or no return value in spec)."""

    def run(self):
        big_int_ptr = _arg(self.state, 0)
        big_int_len = _arg(self.state, 1)
        _store_at_ptr(self.state, big_int_ptr, big_int_len * 8)
        return 


@ta_function_hook("TEE_BigIntConvertFromOctetString", "gp")
class TEE_BigIntConvertFromOctetString_symbolic(angr.SimProcedure):
    """dest*, buffer*, bufferLen*, sign -> TEE_SUCCESS."""

    def run(self):
        big_int_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, big_int_ptr, 32)
        return 0


@ta_function_hook("TEE_BigIntConvertToOctetString", "gp")
class TEE_BigIntConvertToOctetString_symbolic(angr.SimProcedure):
    """buffer*, bufferLen*, bigInt* -> TEE_SUCCESS. Fills buffer and *bufferLen."""

    def run(self):
        buf_ptr = _arg(self.state, 0)
        buf_len_ptr = _arg(self.state, 1)
        buf_len = self.state.memory.load(buf_len_ptr, _ptr_bits(self.state) // 8, endness=self.state.arch.memory_endness)
        buf_len = self.state.solver.eval_one(buf_len)
        _store_at_ptr(self.state, buf_ptr, buf_len * 8)
        _store_ptr_at(self.state, buf_len_ptr, get_trusted_mem_bits(self.state, _ptr_bits(self.state)))
        return 0


@ta_function_hook("TEE_BigIntConvertFromS32", "gp")
class TEE_BigIntConvertFromS32_symbolic(angr.SimProcedure):
    """dest*, shortVal -> dest (returns dest)."""

    def run(self):
        big_int_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, big_int_ptr, 32)
        return 0


@ta_function_hook("TEE_BigIntAdd", "gp")
class TEE_BigIntAdd_symbolic(angr.SimProcedure):
    """dest*, op1*, op2*. Void (no return)."""

    def run(self):
        return None


@ta_function_hook("TEE_BigIntSub", "gp")
class TEE_BigIntSub_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntNeg", "gp")
class TEE_BigIntNeg_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntMul", "gp")
class TEE_BigIntMul_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntCmp", "gp")
class TEE_BigIntCmp_symbolic(angr.SimProcedure):
    """Returns comparison result (int). Return symbolic or 0."""

    def run(self):
        return 0


@ta_function_hook("TEE_BigIntCmpS32", "gp")
class TEE_BigIntCmpS32_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntShiftRight", "gp")
class TEE_BigIntShiftRight_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntGetBit", "gp")
class TEE_BigIntGetBit_symbolic(angr.SimProcedure):
    """Returns 0 or 1. Return symbolic bit."""

    def run(self):
        return 0


@ta_function_hook("TEE_BigIntGetBitCount", "gp")
class TEE_BigIntGetBitCount_symbolic(angr.SimProcedure):
    """Returns bit count. Return symbolic."""

    def run(self):
        return 0


@ta_function_hook("TEE_BigIntSetBit", "gp")
class TEE_BigIntSetBit_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntAssign", "gp")
class TEE_BigIntAssign_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntAbs", "gp")
class TEE_BigIntAbs_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntSquare", "gp")
class TEE_BigIntSquare_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntDiv", "gp")
class TEE_BigIntDiv_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntMod", "gp")
class TEE_BigIntMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntAddMod", "gp")
class TEE_BigIntAddMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntSubMod", "gp")
class TEE_BigIntSubMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntMulMod", "gp")
class TEE_BigIntMulMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntSquareMod", "gp")
class TEE_BigIntSquareMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntInvMod", "gp")
class TEE_BigIntInvMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


@ta_function_hook("TEE_BigIntExpMod", "gp")
class TEE_BigIntExpMod_symbolic(angr.SimProcedure):
    def run(self):
        return 0


# ---------------------------------------------------------------------------
# GP API from gp_api.py (time, wait, property, random, memory check, caller info)
# ---------------------------------------------------------------------------


@ta_function_hook("TEE_GetREETime", "gp")
class TEE_GetREETime_symbolic(angr.SimProcedure):
    """time* (out: 8 bytes) -> void. Fills time with symbolic."""

    def run(self):
        time_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, time_ptr, 8 * 8)
        return None


@ta_function_hook("TEE_GetSystemTime", "gp")
class TEE_GetSystemTime_symbolic(angr.SimProcedure):
    """Same as TEE_GetREETime."""

    def run(self):
        time_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, time_ptr, 8 * 8)
        return None


@ta_function_hook("TEE_Wait", "gp")
class TEE_Wait_symbolic(angr.SimProcedure):
    """Return TEE_SUCCESS."""

    def run(self):
        return 0


@ta_function_hook("TEE_GetPropertyAsIdentity", "gp")
class TEE_GetPropertyAsIdentity_symbolic(angr.SimProcedure):
    """propsetOrEnumerator, name, value* -> TEE_SUCCESS. Fills value with symbolic."""

    def run(self):
        value_ptr = _arg(self.state, 2)
        _store_at_ptr(self.state, value_ptr, 18 * 8)
        return 0


@ta_function_hook("TEE_GenerateRandom", "gp")
class TEE_GenerateRandom_symbolic(angr.SimProcedure):
    """randomBuffer*, randomBufferLen -> void. Fills buffer with symbolic bytes."""

    def run(self):
        buf_ptr = _arg(self.state, 0)
        len_reg = _arg(self.state, 1)
        try:
            n = self.state.solver.eval_one(len_reg)
        except Exception:
            n = 256
        if not isinstance(n, int) or n <= 0 or n > 4096:
            n = 256
        random_bytes = random.randbytes(n)
        random_bytes = claripy.BVV(int.from_bytes(random_bytes, 'big'), n * 8)
        self.state.memory.store(buf_ptr, random_bytes, size=n, endness=self.state.arch.memory_endness)
        return None


@ta_function_hook("TEE_CheckMemoryAccessRights", "gp")
class TEE_CheckMemoryAccessRights_symbolic(angr.SimProcedure):
    """accessFlags, buffer, size -> TEE_SUCCESS (always allow)."""

    def run(self):
        logger.info(f"TEE_CheckMemoryAccessRights called")
        return 0


@ta_function_hook("TEE_GetCallerInfo", "gp")
class TEE_GetCallerInfo_symbolic(angr.SimProcedure):
    """caller_info* (out) -> void. Fills with symbolic."""

    # TODO; I cannot find this function in the spec
    def run(self):
        caller_info_ptr = _arg(self.state, 0)
        _store_at_ptr(self.state, caller_info_ptr, _ptr_bits(self.state))
        return None



@ta_function_hook("__assert_fail", "gp")
class __assert_fail_symbolic(angr.SimProcedure):
    """Stack guard check failed. No-op for symbolic execution (continue)."""

    def run(self):
        self.state.globals['ta_panic'] = True
        self.state.globals['panic_addr'] = self.state.addr
        return 0

@ta_function_hook("__stack_chk_fail", "gp")
class stack_chk_fail_symbolic(angr.SimProcedure):
    """Stack guard check failed. No-op for symbolic execution (continue)."""

    def run(self):
        
        plugin = self.state.globals.get('stack_san_plugin')
        if plugin is not None:
            if self.state.addr not in plugin.reported_compiler_stack_overflows:
                plugin.reported_compiler_stack_overflows.add(self.state.addr)
                add_detected_bug(self.state, "stack guard check failed", self.state.addr, "CRITICAL")

        self.state.globals['ta_panic'] = True
        self.state.globals['panic_addr'] = self.state.addr
        return 0


# ---------------------------------------------------------------------------
# LibC / printf family not included in angr (keep custom symbolic) TODO: We must probably go over these again at some point
# ---------------------------------------------------------------------------

@ta_function_hook("vfprintf", "gp")
class vfprintf_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return 0


@ta_function_hook("vprintf", "gp")
class vprintf_symbolic(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return 0

# ---------------------------------------------------------------------------
# other libc functions
# ---------------------------------------------------------------------------
@ta_function_hook("TEE_MemMove", "gp")
class TEE_MemMove_symbolic(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit):
            conditional_size = self.state.solver.eval(limit)
        else:
            max_memcpy_size = self.state.libc.max_memcpy_size  # type: ignore[reportAttributeAccessIssue]
            self.state.add_constraints(limit <= claripy.BVV(max_memcpy_size, self.state.arch.bits))
            logger.info(f"limit: {limit}")
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(max_memcpy_size, max(min_limit, max_limit))
            if max_limit > max_memcpy_size and conditional_size < max_limit:
                logger.warning(
                    "memmove upper bound of %#x outside limit, limiting to %#x instead", max_limit, conditional_size
                )

        logger.info("TEE_MemMove running with conditional_size %#x", conditional_size)
        logger.info(f"dst_addr: {dst_addr}, conditional_size: {conditional_size}")

        if conditional_size > 0:
            src_mem = self.state.memory.load(src_addr, conditional_size, endness="Iend_BE")
            self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness="Iend_BE")

        return dst_addr




@ta_function_hook("calloc", "gp")
class calloc_symbolic(angr.SimProcedure):
    def run(self):
        sim_nmemb = _arg(self.state, 0)
        sim_size = _arg(self.state, 1)
        
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        ptr = self.state.heap._calloc(sim_nmemb, sim_size)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        return ptr


@ta_function_hook("malloc", "gp")
class malloc_symbolic(angr.SimProcedure):
    def run(self):
        size_reg = _arg(self.state, 0)
        try:
            data_len = self.state.solver.eval_one(size_reg)
        except Exception:
            data_len = 256
        if not isinstance(data_len, int) or data_len <= 0 or data_len > 1024 * 1024:
            data_len = 256
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_BEFORE,
        )
        ptr = self.state.heap.allocate(data_len)
        _store_at_ptr(self.state, ptr, data_len * 8)
        self.state._inspect(
            'heap_alloc',
            when=angr.BP_AFTER,
        )
        ret_ptr = claripy.BVV(ptr, _ptr_bits(self.state))
        return ret_ptr


@ta_function_hook("free", "gp")
class free_symbolic(angr.SimProcedure):
    def run(self):
        free_addr = _arg(self.state, 0)
        self.state._inspect(
            'free',
            when=angr.BP_BEFORE,
            address=free_addr,
        )

@ta_function_hook("ioctl", "gp") 
class ioctl_symbolic(angr.SimProcedure):
    def run(self):
        # TODO, this will be hard to do...
        return 0


@ta_function_hook("memmem", "gp")  
class memmem_symbolic(angr.SimProcedure):
    # TODO
    def run(self, haystack, hsize, needle, nsize):
        logger.info(f"memmem called with haystack: {haystack}, hsize: {hsize}, needle: {needle}, nsize: {nsize}")
        nsize = self.state.solver.max_int(nsize)
        hsize = self.state.solver.max_int(hsize)
        if nsize == 0:
            return 
        if hsize == 0:
            return claripy.BVV(0, self.state.arch.bits)

        r, c, i = self.state.memory.find(
            haystack,
            needle,
            hsize,
            nsize,
        )

        self.state.add_constraints(*c)
        return r


@ta_function_hook("posix_memalign", "gp")
class posix_memalign_symbolic(angr.SimProcedure):
    def run(self, ptr, alignment, size):
        buffer = self.state.heap.allocate(size)  # TODO: we should probably do some alignment checks here
        _store_ptr_at(self.state, ptr, buffer)
        return 0


@ta_function_hook("pthread_rwlock_unlock", "gp")
class pthread_rwlock_wrlock_symbolic(angr.SimProcedure):
    def run(self, mutex):
        return 0


@ta_function_hook("pthread_rwlock_wrlock", "gp")
class pthread_rwlock_wrlock_symbolic(angr.SimProcedure):
    def run(self, mutex):
        return 0

@ta_function_hook("pthread_mutex_lock", "gp")
class pthread_mutex_lock_symbolic(angr.SimProcedure):
    def run(self, mutex):
        return 0

@ta_function_hook("pthread_mutex_unlock", "gp")
class pthread_mutex_unlock_symbolic(angr.SimProcedure):
    def run(self, mutex):
        return 0

@ta_function_hook("pthread_mutex_once", "gp")
class pthread_mutex_once_symbolic(angr.SimProcedure):
    def run(self, once_control, init_routine):
        return 0

@ta_function_hook("get_pid", "gp")
class get_pid_symbolic(angr.SimProcedure):
    def run(self):
        return 1337