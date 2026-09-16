from angr import SimProcedure
import claripy
import time
import struct
import random
from explorer.memory.ta_taint import get_trusted_mem_bits, get_tainted_mem_bits
from explorer.hooks.os_hooks.os_hooks import os_hook
from utils.logging_config import get_logger

logger = get_logger(__name__)

_syscall_stats: dict[str, int] = {}


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


def _syscall_num_reg(state):
    """Register holding the syscall number: x8 (AArch64) or r7 (ARM 32-bit)."""
    if state.arch.bits == 64:
        return state.regs.x8
    return state.regs.r7


def _set_return(state, value):
    """Set the return-value register (x0 or r0) to value and return it."""
    bits = _ptr_bits(state)
    bv = claripy.BVV(value, bits) if isinstance(value, int) else value
    if state.arch.bits == 64:
        state.regs.x0 = bv
        return state.regs.x0
    state.regs.r0 = bv
    return state.regs.r0

def get_syscall_stats():
    """
    Get the syscall statistics.
    
    Returns:
        A dictionary containing the syscall statistics
    """
    return dict(_syscall_stats)

def reset_syscall_stats():
    """
    Reset the syscall statistics.
    """
    global _syscall_stats
    _syscall_stats = {}


@os_hook("optee")
class OPTEEHooks(SimProcedure):
    """
    Provides symbolic implementations for the OP-TEE system calls.
    """

    def __init__(
        self,
        project=None,
        cc=None,
        prototype=None,
        symbolic_return=None,
        returns=None,
        is_syscall=False,
        is_stub=False,
        num_args=None,
        display_name=None,
        library_name=None,
        is_function=None,
        **kwargs,
    ):
        super().__init__(project, cc, prototype, symbolic_return, returns, is_syscall, is_stub, num_args, display_name, library_name, is_function, **kwargs)

    PTA_SYSTEM_ADD_RNG_ENTROPY = 0 
    PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY = 1
    PTA_SYSTEM_MAP_ZI = 2
    PTA_SYSTEM_UNMAP = 3
    PTA_SYSTEM_OPEN_TA_BINARY = 4
    PTA_SYSTEM_CLOSE_TA_BINARY = 5
    PTA_SYSTEM_MAP_TA_BINARY = 6
    PTA_SYSTEM_COPY_FROM_TA_BINARY = 7
    PTA_SYSTEM_SET_PROT = 8
    PTA_SYSTEM_REMAP = 9
    PTA_SYSTEM_DLOPEN = 10
    PTA_SYSTEM_DLSYM = 11
    PTA_SYSTEM_GET_TPM_EVENT_LOG = 12
    PTA_SYSTEM_SUPP_PLUGIN_INVOKE = 13

    def pta_system_add_rng_entropy(self):
        return 0

    def pta_system_derive_ta_unique_key(self):
        params_addr = self.state.solver.eval_one(_arg(self.state, 4))
        key_buffer = self.state.heap.allocate(32)
        key = get_trusted_mem_bits(self.state, 32*8)  # max key length  
        key_length = get_trusted_mem_bits(self.state, 64)
        self.state.solver.add(key_length <= 32)
        self.state.memory.store(key_buffer, key)
        self.state.memory.store(params_addr + 16, key_buffer)
        self.state.memory.store(params_addr + 24, key_length)
        return 0

    def pta_system_map_zi(self):
        logger.debug("PTA_SYSTEM_MAP_ZI invoked")
        params_addr = self.state.solver.eval_one(_arg(self.state, 4))
        # Size to alloc is params[0].value.a
        size = self.state.memory.load(params_addr, 4)
        size = self.state.solver.eval_one(size)
        logger.debug(f"PTA_SYSTEM_MAP_ZI: size to alloc: {size}")
        ptr = self.state.heap.allocate(size)
        ptr = claripy.BVV(ptr, _ptr_bits(self.state))
        self.state.memory.store(ptr, claripy.BVV(0, size*8))

        # store the pointer in params[1].value
        self.state.memory.store(params_addr + 8, ptr)
        return 0
    
    def pta_system_unmap(self):
        logger.info("PTA_SYSTEM_UNMAP invoked")
        return 0
    
    def pta_system_open_ta_binary(self):
        logger.info("PTA_SYSTEM_OPEN_TA_BINARY invoked")
        return 0
    
    def pta_system_close_ta_binary(self):
        logger.info("PTA_SYSTEM_CLOSE_TA_BINARY invoked")
        return 0
    
    def pta_system_map_ta_binary(self):
        logger.info("PTA_SYSTEM_MAP_TA_BINARY invoked")
        return 0

    def pta_system_copy_from_ta_binary(self):
        logger.info("PTA_SYSTEM_COPY_FROM_TA_BINARY invoked")
        return 0

    def pta_system_setprot(self):
        logger.info("PTA_SYSTEM_SETPROT invoked")
        return 0

    def pta_system_remap(self):
        logger.info("PTA_SYSTEM_REMAP invoked")
        return 0

    def pta_system_dlopen(self):
        logger.info("PTA_SYSTEM_DLOPEN invoked")
        return 0

    def pta_system_dlsym(self):
        logger.info("PTA_SYSTEM_DLSYM invoked")
        return 0

    def pta_system_get_tpm_event_log(self):
        logger.info("PTA_SYSTEM_GET_TPM_EVENT_LOG invoked")
        return 0

    def pta_system_plugin_invoke(self):
        logger.info("PTA_SYSTEM_PLUGIN_INVOKE invoked")
        return 0       

    # TEE param type constants (GP API)
    TEE_PARAM_TYPE_NONE = 0
    TEE_PARAM_TYPE_VALUE_INPUT = 1
    TEE_PARAM_TYPE_VALUE_OUTPUT = 2
    TEE_PARAM_TYPE_VALUE_INOUT = 3
    TEE_PARAM_TYPE_MEMREF_INPUT = 5
    TEE_PARAM_TYPE_MEMREF_OUTPUT = 6
    TEE_PARAM_TYPE_MEMREF_INOUT = 7
    TEE_NUM_PARAMS = 4

    def pta_call_generic(self):
        """
        Generic handler for PTA calls.
        We check the TA params and fill all inout params with symbolic values.
        The params are packed like this:
        struct utee_params {
            uint64_t types;
            /* vals[n * 2]	   corresponds to either value.a or memref.buffer
            * vals[n * 2 + 1]  corresponds to either value.b or memref.size
            * when converting to/from struct tee_ta_param
            */
            uint64_t vals[TEE_NUM_PARAMS * 2];
        };
        
        Type extraction macro: TEE_PARAM_TYPE_GET(t, i) = ((t >> (i * 4)) & 0xF)
        """ 
        utee_params_addr = self.state.solver.eval_one(self.state.regs.x3)
        logger.info(f"PTA_CALL utee_params at {hex(utee_params_addr)}")

        ret_origin_addr = self.state.solver.eval_one(_arg(self.state, 4))
        ret_origin = claripy.BVV(4, 32)  # result in params stems from the called TA 
        self.state.memory.store(ret_origin_addr, ret_origin, endness=self.state.arch.memory_endness)

        # Load the types field (uint64_t at offset 0)
        types_bv = self.state.memory.load(utee_params_addr, 8, endness=self.state.arch.memory_endness)
        types = self.state.solver.eval_one(types_bv)
        logger.info(f"PTA_CALL param types: {hex(types)}")

        # vals array starts at offset 8 (after the uint64_t types field)
        vals_base = utee_params_addr + 8

        for n in range(self.TEE_NUM_PARAMS):
            # Extract param type using TEE_PARAM_TYPE_GET(types, n) = (types >> (n * 4)) & 0xF
            param_type = (types >> (n * 4)) & 0xF
            
            # Calculate offsets for vals[n*2] (value.a/buffer) and vals[n*2+1] (value.b/size)
            val_a_offset = vals_base + (n * 2) * 8
            val_b_offset = vals_base + (n * 2 + 1) * 8

            if param_type in (self.TEE_PARAM_TYPE_VALUE_INOUT, self.TEE_PARAM_TYPE_VALUE_OUTPUT):
                # Fill value.a and value.b with tainted symbolic values
                logger.info(f"PTA_CALL Param {n}: VALUE_INOUT - filling with tainted values")
                tainted_a = get_tainted_mem_bits(self.state, 64)
                tainted_b = get_tainted_mem_bits(self.state, 64)
                self.state.memory.store(val_a_offset, tainted_a, size=8, endness=self.state.arch.memory_endness)
                self.state.memory.store(val_b_offset, tainted_b, size=8, endness=self.state.arch.memory_endness)

            elif param_type in (self.TEE_PARAM_TYPE_MEMREF_OUTPUT, self.TEE_PARAM_TYPE_MEMREF_INOUT):
                # Read buffer pointer and size
                buffer_bv = self.state.memory.load(val_a_offset, 8, endness=self.state.arch.memory_endness)
                size_bv = self.state.memory.load(val_b_offset, 8, endness=self.state.arch.memory_endness)
                
                buffer_ptr = self.state.solver.eval_one(buffer_bv)
                size = self.state.solver.eval_one(size_bv)
                
                type_name = "MEMREF_OUTPUT" if param_type == self.TEE_PARAM_TYPE_MEMREF_OUTPUT else "MEMREF_INOUT"
                logger.info(f"PTA_CALL Param {n}: {type_name} - buffer={hex(buffer_ptr)}, size={size}")
                
                if buffer_ptr != 0 and size > 0:
                    # Fill the memory region with tainted symbolic values
                    tainted_mem = get_tainted_mem_bits(self.state, size * 8)
                    self.state.memory.store(buffer_ptr, tainted_mem, size=size, endness=self.state.arch.memory_endness)
                    logger.info(f"PTA_CALL Filled {size} bytes at {hex(buffer_ptr)} with tainted data")
            else:
                type_names = {
                    self.TEE_PARAM_TYPE_NONE: "NONE",
                    self.TEE_PARAM_TYPE_VALUE_INPUT: "VALUE_INPUT",
                    self.TEE_PARAM_TYPE_MEMREF_INPUT: "MEMREF_INPUT",
                }
                type_name = type_names.get(param_type, f"UNKNOWN({param_type})")
                logger.info(f"PTA_CALL Param {n}: {type_name} - skipping")

        return 0 
        
    def syscall_open_ta_session(self):
        logger.info("syscall_open_ta_session invoked")
        """
        TEE_UUID struct layout (16 bytes total):
        typedef struct {
            uint32_t timeLow;
            uint16_t timeMid;
            uint16_t timeHiAndVersion;
            uint8_t clockSeqAndNode[8];
        } TEE_UUID;

        #define PTA_SYSTEM_UUID { 0x3a2f8978, 0x5dc0, 0x11e8, { \
			 0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc } }
        """
        
        # Build the PTA_SYSTEM_UUID bytes matching the TEE_UUID struct layout (little-endian)
        PTA_SYSTEM_UUID_BYTES = struct.pack('<IHH',  # little-endian uint32 + 2x uint16
            0x3a2f8978,  # timeLow
            0x5dc0,      # timeMid
            0x11e8       # timeHiAndVersion
        ) + bytes([0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc])  # clockSeqAndNode

        uuid_addr = self.state.solver.eval_one(_arg(self.state, 0))

        # Load the UUID from memory (16 bytes)
        uuid = self.state.memory.load(uuid_addr, 16)
        logger.info(f"Open Session UUID: {uuid}")
        session_addr = self.state.solver.eval_one(_arg(self.state, 0))
        # Create expected bitvector from bytes
        expected_uuid = claripy.BVV(PTA_SYSTEM_UUID_BYTES)
        
        # Compare using the solver
        if self.state.solver.is_false(uuid == expected_uuid):
            logger.info("Open Session calling into other PTA")
            syscall_name = f"SYSCALL_OPEN_TA_SESSION_{uuid}"
            # DEBUG
            if syscall_name not in _syscall_stats:
                _syscall_stats[syscall_name] = 0
            _syscall_stats[syscall_name] += 1
            return 0
        
        syscall_name = "SYSCALL_OPEN_TA_SESSION_PTA_SYSTEM"
        # DEBUG
        if syscall_name not in _syscall_stats:
            _syscall_stats[syscall_name] = 0
        _syscall_stats[syscall_name] += 1

        logger.info("Open Session to PTA_SYSTEM")
        session_addr = self.state.solver.eval_one(_arg(self.state, 4))
        self.state.memory.store(session_addr, claripy.BVV(0x1337, 64))
        return 0

    def syscall_close_ta_session(self):
        logger.info("syscall_close_ta_session invoked")
        return 0

    def pta_invoke_command(self):

        syscall = self.state.solver.min(_arg(self.state, 2))
        session_addr = self.state.solver.eval_one(_arg(self.state, 0))
        session_val = self.state.memory.load(session_addr, 8)
        session_val = self.state.solver.eval_one(session_val)
        logger.info(f"PTA Invoke Command number: {syscall} - Session: {session_val}")
        
        # DEBUG
        syscall_name = f"PTA_INVOKE_COMMAND_{syscall}-{session_val}"
        if syscall_name not in _syscall_stats:
            _syscall_stats[syscall_name] = 0
        
        _syscall_stats[syscall_name] += 1
        if session_val != 0x1337:
            logger.info("PTA Invoke calling into other PTA")
            return self.pta_call_generic()

        logger.info("PTA Invoke calling into PTA_SYSTEM")
        if syscall == self.PTA_SYSTEM_ADD_RNG_ENTROPY:
            return self.pta_system_add_rng_entropy()
        elif syscall == self.PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY:
            return self.pta_system_derive_ta_unique_key()
        if syscall == self.PTA_SYSTEM_MAP_ZI:
            return self.pta_system_map_zi()
        elif syscall == self.PTA_SYSTEM_UNMAP:
            return self.pta_system_unmap()
        elif syscall == self.PTA_SYSTEM_OPEN_TA_BINARY:
            return self.pta_system_open_ta_binary()
        elif syscall == self.PTA_SYSTEM_CLOSE_TA_BINARY:
            return self.pta_system_close_ta_binary()
        elif syscall == self.PTA_SYSTEM_MAP_TA_BINARY:
            return self.pta_system_map_ta_binary()
        elif syscall == self.PTA_SYSTEM_COPY_FROM_TA_BINARY:
            return self.pta_system_copy_from_ta_binary()
        elif syscall == self.PTA_SYSTEM_SET_PROT:
            return self.pta_system_setprot()
        elif syscall == self.PTA_SYSTEM_REMAP:
            return self.pta_system_remap()
        elif syscall == self.PTA_SYSTEM_DLOPEN:
            return self.pta_system_dlopen()
        elif syscall == self.PTA_SYSTEM_DLSYM:
            return self.pta_system_dlsym()
        elif syscall == self.PTA_SYSTEM_GET_TPM_EVENT_LOG:
            return self.pta_system_get_tpm_event_log()
        elif syscall == self.PTA_SYSTEM_SUPP_PLUGIN_INVOKE:
            return  self.pta_system_plugin_invoke()
        else:
            logger.warning(f"Unknown PTA command: {syscall}")       
        
        return 0

    def syscall_sys_return(self):
        """
        Handles syscall_sys_return (syscall 0).
        This indicates the TA is returning to the Normal World.
        We track these for informational purposes.
        """
        logger.debug(f"syscall_sys_return invoked at {hex(self.state.addr)} - TA returning to Normal World")
        # Mark the state as returning to NW
        self.state.globals['ta_sys_return'] = True
        self.state.globals['sys_return_addr'] = self.state.addr
        self.exit(1)
    
    def syscall_log(self):
        ptr = self.state.solver.eval(_arg(self.state, 0))
        len = self.state.solver.eval(_arg(self.state, 1)) 
        
        buff = self.state.memory.load(ptr, len)
        logger.debug(f"SYSCALL_LOG: {claripy.StringV(buff)}")

        return _set_return(self.state, 0)

    def syscall_panic(self):
        """
        Handles the syscall_panic operation.
        In a typical implementation, this would terminate the TA or signal a fatal error.
        For the purpose of this analysis framework, we mark the state to be killed.
        """
        logger.debug("syscall_panic invoked! Marking state for termination.")
        # Mark the state to be killed/filtered out
        self.state.globals['ta_panic'] = True
        self.state.globals['panic_addr'] = self.state.addr
        return self.exit(1)

    def syscall_get_time(self):
        """
        Get current time and write to TEE_Time struct.
        
        TEE_Time struct layout (8 bytes total):
        - uint32_t seconds (4 bytes)
        - uint32_t millis  (4 bytes)
        
        Pointer to struct is in x1 (second argument).
        """
        tee_time_ptr = self.state.solver.eval(_arg(self.state, 1))
        
        seconds = 1735689600  # Fixed timestamp
        millis = 0  # Fixed milliseconds
        
        # Write seconds (first 4 bytes, uint32_t)
        seconds_bv = claripy.BVV(seconds, 32)
        self.state.memory.store(tee_time_ptr, seconds_bv, endness=self.state.arch.memory_endness)
        
        # Write millis (second 4 bytes, uint32_t)
        millis_bv = claripy.BVV(millis, 32)
        self.state.memory.store(tee_time_ptr + 4, millis_bv, endness=self.state.arch.memory_endness)

        return 0

    def syscall_get_property(self):
        logger.debug("Getting property")
        name_ptr = _arg(self.state, 2)
        name_len_ptr = self.state.solver.max(_arg(self.state, 3))
        if name_len_ptr > 0:
            in_name_len = self.state.solver.eval(name_len_ptr)
            name_len = 64 if in_name_len > 64 else in_name_len

            out_name_len = get_trusted_mem_bits(self.state, 32)
            self.state.solver.add(out_name_len <= name_len)
            name_info = get_trusted_mem_bits(self.state, name_len*8)

            self.state.memory.store(name_ptr, name_info)
            self.state.memory.store(name_len_ptr, out_name_len)

        buff_ptr = _arg(self.state, 4)
        buff_len_ptr = self.state.solver.max(_arg(self.state, 5))
        if buff_len_ptr > 0:
            in_buff_len = self.state.solver.eval(buff_len_ptr)
            buff_len = 64 if in_buff_len > 64 else in_buff_len

            out_buff_len = get_trusted_mem_bits(self.state, 32)
            self.state.solver.add(out_buff_len <= buff_len)
            buff_info = get_trusted_mem_bits(self.state, buff_len*8)
            
            self.state.memory.store(buff_ptr, buff_info)
            self.state.memory.store(buff_len_ptr, out_buff_len)

        prop_type_ptr = self.state.solver.eval_one(_arg(self.state, 6))
        if prop_type_ptr != 0:
            prop_type_val = get_trusted_mem_bits(self.state, 32)
            self.state.memory.store(prop_type_ptr, prop_type_val)   

        logger.debug("Done getting property")        
        return 0
    
    def syscall_get_property_name_to_index(self):
        index = self.state.solver.eval_one(_arg(self.state, 3))
        index_val = get_trusted_mem_bits(self.state, 32) 
        self.state.memory.store(index, index_val)
        return 0

    def syscall_set_ta_time(self):
        return 0

    def syscall_cryp_state_alloc(self):
        state_ptr = self.state.solver.eval(_arg(self.state, 4))
        cryp_state_ptr = self.state.heap.allocate(56)
        cryp_state_ptr = claripy.BVV(cryp_state_ptr, 64)
        sym_cryp_state = get_trusted_mem_bits(self.state, 56 * 8)
        self.state.memory.store(cryp_state_ptr, sym_cryp_state)
        self.state.memory.store(state_ptr, cryp_state_ptr)
        return 0

    def syscall_check_access_rights(self):
        return 0

    def syscall_cryp_state_free(self):
        return 0

    def syscall_hash_init(self):
        return 0

    def syscall_hash_update(self):
        return 0

    def syscall_hash_final(self):
        hash_ptr = self.state.solver.eval(_arg(self.state, 4))
        hash_len = self.state.solver.eval(_arg(self.state, 5))
        sym_hash = get_trusted_mem_bits(self.state, hash_len * 8)
        self.state.memory.store(hash_ptr, sym_hash)
        return 0

    def syscall_cipher_init(self):
        return 0

    def syscall_cipher_update(self):
        src_len = self.state.solver.eval(_arg(self.state, 2))
        dst = self.state.solver.eval(_arg(self.state, 3))
        dst_len = self.state.solver.eval(_arg(self.state, 4)) 

        import os
        rand_bytes = os.urandom(src_len)
        sym_dst = claripy.BVV(int.from_bytes(rand_bytes, 'big'), src_len * 8)
        self.state.memory.store(dst, sym_dst)
        self.state.memory.store(dst_len, claripy.BVV(src_len, 64))

        return 0

    def syscall_cipher_final(self):
        src_len = self.state.solver.eval(self.state.regs.x2)
        dst = self.state.solver.eval(_arg(self.state, 3))
        dst_len = self.state.solver.eval(_arg(self.state, 4)) 

        import os
        rand_bytes = os.urandom(src_len)
        sym_dst = claripy.BVV(int.from_bytes(rand_bytes, 'big'), src_len * 8)
        self.state.memory.store(dst, sym_dst)
        self.state.memory.store(dst_len, claripy.BVV(src_len, 64))

        return 0

    def syscall_cryp_obj_get_info(self):
        buff = self.state.solver.eval(_arg(self.state, 1))
        buff_info = get_trusted_mem_bits(self.state, 28 * 8)
        self.state.memory.store(buff, buff_info)
        return 0

    def syscall_cryp_obj_populate(self):
        return 0

    def syscall_cryp_obj_reset(self):
        return 0

    def syscall_cryp_obj_copy(self):
        return 0

    def syscall_crypt_obj_alloc(self):
        x2 = _arg(self.state, 2)
        obj_handle = self.state.solver.eval(x2)
        # Needs to be symbolic since the handle contians meta data
        sym_obj_handle = get_trusted_mem_bits(self.state, 32)
        self.state.memory.store(obj_handle, sym_obj_handle)

        return 0

    def syscall_crypt_obj_close(self):
        return 0

    def syscall_random_number_generate(self):
        buff = self.state.solver.eval(_arg(self.state, 0))
        len = self.state.solver.eval(_arg(self.state, 1))
        buff_random = random.randint(0, 0xFFFFFFFF)
        buff_random = claripy.BVV(buff_random, len * 8)
        # buff_random = claripy.BVV(0x12345678, len * 8) We cannot use fixed values since some TAs might check for entropy
        self.state.memory.store(buff, buff_random)

        return 0

    def syscall_storage_obj_open(self):
        obj_handle = self.state.solver.eval(_arg(self.state, 4))
        # Needs to be symbolic since the handle contians meta data
        sym_obj_handle = get_trusted_mem_bits(self.state, 32)
        self.state.memory.store(obj_handle, sym_obj_handle)

        return 0

    def syscall_storage_obj_create(self):
        obj_handle = self.state.solver.eval(_arg(self.state, 7))
        sym_obj_handle = get_trusted_mem_bits(self.state, 32)
        self.state.memory.store(obj_handle, sym_obj_handle)

        return 0

    def syscall_storage_obj_del(self):
        return 0

    def syscall_storage_obj_rename(self):
        return 0

    def syscall_storage_obj_read(self):
        ptr = self.state.solver.eval(_arg(self.state, 1))
        len = self.state.solver.eval(_arg(self.state, 2))
        buff_read = get_trusted_mem_bits(self.state, len * 8)
        self.state.memory.store(ptr, buff_read)

        sz_ret_ptr = self.state.solver.eval(_arg(self.state, 3))
        sz_ret = claripy.BVV(len, 64)
        self.state.memory.store(sz_ret_ptr, sz_ret, endness=self.state.arch.memory_endness)

        return 0

    def syscall_storage_obj_write(self):
        return 0

    def syscall_storage_obj_seek(self):
        return 0

    def syscall_storage_obj_trunc(self):
        return 0

    def syscall_storage_alloc_enum(self):
        enum_handle = self.state.solver.eval(_arg(self.state, 0))
        sym_enum_handle = get_trusted_mem_bits(self.state, 32)
        self.state.memory.store(enum_handle, sym_enum_handle)
        return 0

    def syscall_storage_free_enum(self):
        return 0

    def syscall_storage_reset_enum(self):
        return 0

    def syscall_storage_start_enum(self):
        return 0

    def syscall_storage_next_enum(self):
        info_hanlde = self.state.solver.eval(_arg(self.state, 0))
        obj_id_handle = self.state.solver.eval(_arg(self.state, 1))
        len_handle = self.state.solver.eval(_arg(self.state, 2)) 

        sym_info = get_trusted_mem_bits(self.state, 28 * 8)
        obj_id = get_trusted_mem_bits(self.state, 32) 
        len = get_trusted_mem_bits(self.state, 64) 
        self.state.memory.store(info_hanlde, sym_info)
        self.state.memory.store(obj_id_handle, obj_id)
        self.state.memory.store(len_handle, len)

        return 0

    # Syscall name mapping (from tee_syscall_table)
    SYSCALL_NAMES = {
        0: ("syscall_sys_return", syscall_sys_return),
        1: ("syscall_log", syscall_log),
        2: ("syscall_panic", syscall_panic),
        3: ("syscall_get_property", syscall_get_property),
        4: ("syscall_get_property_name_to_index", syscall_get_property_name_to_index),
        5: ("syscall_open_ta_session", syscall_open_ta_session),
        6: ("syscall_close_ta_session", syscall_close_ta_session),
        7: ("syscall_invoke_ta_command", pta_invoke_command),
        8: ("syscall_check_access_rights", syscall_check_access_rights),
        9: ("syscall_get_cancellation_flag", None),
        10: ("syscall_unmask_cancellation", None),
        11: ("syscall_mask_cancellation", None),
        12: ("syscall_wait", None),
        13: ("syscall_get_time", syscall_get_time),
        14: ("syscall_set_ta_time", syscall_set_ta_time),
        15: ("syscall_cryp_state_alloc", syscall_cryp_state_alloc),
        16: ("syscall_cryp_state_copy", None),
        17: ("syscall_cryp_state_free", syscall_cryp_state_free),
        18: ("syscall_hash_init", syscall_hash_init),
        19: ("syscall_hash_update", syscall_hash_update),
        20: ("syscall_hash_final", syscall_hash_final),
        21: ("syscall_cipher_init", syscall_cipher_init),
        22: ("syscall_cipher_update", syscall_cipher_update),
        23: ("syscall_cipher_final", syscall_cipher_final),
        24: ("syscall_cryp_obj_get_info", syscall_cryp_obj_get_info),
        25: ("syscall_cryp_obj_restrict_usage", None),
        26: ("syscall_cryp_obj_get_attr", None),
        27: ("syscall_cryp_obj_alloc", syscall_crypt_obj_alloc),
        28: ("syscall_cryp_obj_close", syscall_crypt_obj_close),
        29: ("syscall_cryp_obj_reset", syscall_cryp_obj_reset),               
        30: ("syscall_cryp_obj_populate", syscall_cryp_obj_populate),
        31: ("syscall_cryp_obj_copy", syscall_cryp_obj_copy),
        32: ("syscall_cryp_derive_key", None),               
        33: ("syscall_cryp_random_number_generate", syscall_random_number_generate),
        34: ("syscall_authenc_init", None),
        35: ("syscall_authenc_update_aad", None),
        36: ("syscall_authenc_update_payload", None),
        37: ("syscall_authenc_enc_final", None),
        38: ("syscall_authenc_dec_final", None),
        39: ("syscall_asymm_operate", None),
        40: ("syscall_asymm_verify", None),
        41: ("syscall_storage_obj_open", syscall_storage_obj_open),
        42: ("syscall_storage_obj_create", syscall_storage_obj_create),
        43: ("syscall_storage_obj_del", syscall_storage_obj_del),
        44: ("syscall_storage_obj_rename", syscall_storage_obj_rename),
        45: ("syscall_storage_alloc_enum", syscall_storage_alloc_enum),
        46: ("syscall_storage_free_enum", syscall_storage_free_enum),
        47: ("syscall_storage_reset_enum", syscall_storage_reset_enum),
        48: ("syscall_storage_start_enum", syscall_storage_start_enum),
        49: ("syscall_storage_next_enum", syscall_storage_next_enum),
        50: ("syscall_storage_obj_read", syscall_storage_obj_read),
        51: ("syscall_storage_obj_write", syscall_storage_obj_write),            
        52: ("syscall_storage_obj_trunc", syscall_storage_obj_trunc),
        53: ("syscall_storage_obj_seek", syscall_storage_obj_seek),
        54: ("syscall_obj_generate_key", None),
        55: ("syscall_not_supported", None),
        56: ("syscall_not_supported", None),
        57: ("syscall_not_supported", None),
        58: ("syscall_not_supported", None),
        59: ("syscall_not_supported", None),
        60: ("syscall_not_supported", None),
        61: ("syscall_not_supported", None),
        62: ("syscall_not_supported", None),
        63: ("syscall_not_supported", None),
        64: ("syscall_not_supported", None),
        65: ("syscall_not_supported", None),
        66: ("syscall_not_supported", None),
        67: ("syscall_not_supported", None),
        68: ("syscall_not_supported", None),
        69: ("syscall_cache_operation", None),
    }


    def run(self, _argc, _argv):
        """
        Execute the symbolic equivalent of an OP-TEE system call.
        """
        global _syscall_stats
        
        syscall = self.state.solver.min(_syscall_num_reg(self.state))
        logger.debug(f"Syscall {syscall} -> {self.SYSCALL_NAMES.get(syscall, f'Unknown_{syscall}')}")
        
        # Track syscall statistics
        syscall_name, syscall_handler = self.SYSCALL_NAMES.get(syscall, (f"Unknown_{syscall}", None))
        if syscall_name not in _syscall_stats:
            _syscall_stats[syscall_name] = 0
        _syscall_stats[syscall_name] += 1

        if syscall_handler:
            return syscall_handler(self)
        else:
            logger.warning(f"Unknown syscall: {syscall}")
            return 0
