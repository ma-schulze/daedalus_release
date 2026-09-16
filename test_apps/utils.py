"""
Shared helpers for test-app symbolic input setup (e.g. MiTEE, T6).
"""

from explorer.memory.ta_taint import get_tainted_mem_bits


def place_sym_memref_param(state, p3, index):
    bits = state.arch.bits
    bytes_ = bits // 8
    ptr = state.heap.allocate(0x8000)
    size = get_tainted_mem_bits(state, bits, name=f'sym_memref_param_size_{index}')
    state.solver.add(size <= 0x8000)
    val = get_tainted_mem_bits(state, 0x8000 * 8, name=f'sym_memref_param_buffer_val_{index}')
    print(f"ptr in place_sym_memref_param: {hex(ptr)}")
    state.memory.store(ptr, val, size=0x8000, endness=state.arch.memory_endness)
    state.memory.store(p3 + index * (bytes_ * 2), ptr, size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(p3 + index * (bytes_ * 2) + bytes_, size, size=bytes_, endness=state.arch.memory_endness)


def place_sym_value_param(state, p3, index):
    bits = state.arch.bits
    bytes_ = bits // 8
    val_a = get_tainted_mem_bits(state, bits, name=f'sym_value_param_val_a_{index}')
    val_b = get_tainted_mem_bits(state, bits, name=f'sym_value_param_val_b_{index}')
    state.memory.store(p3 + index * (bytes_ * 2), val_a, size=bytes_, endness=state.arch.memory_endness)
    state.memory.store(p3 + index * (bytes_ * 2) + bytes_, val_b, size=bytes_, endness=state.arch.memory_endness)


def init_params(state):
    session_ptr = state.heap.allocate(0x1000)  # let's just assume a session is smaller than a page 
    session_val = get_tainted_mem_bits(state, 0x1000 * 8, name='sym_session_val')
    state.memory.store(session_ptr, session_val, size=0x1000, endness=state.arch.memory_endness)
    
    if state.arch.bits == 64:   
        state.regs.x0 = session_ptr
        state.regs.x1 = get_tainted_mem_bits(state, 64, name='sym_cmd_id')
        state.regs.x2 = get_tainted_mem_bits(state, 64, name='sym_param_type')
        p3 = state.heap.allocate(64)
        state.regs.x3 = p3
    else:
        state.regs.r0 = session_ptr
        state.regs.r1 = get_tainted_mem_bits(state, 32, name='sym_cmd_id')
        state.regs.r2 = get_tainted_mem_bits(state, 32, name='sym_param_type')
        p3 = state.heap.allocate(32)
        state.regs.r3 = p3

    return p3