import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis of the switch table at 0x78c:
# r8 = command_id, r1 = r8 - 0x11, switch on r1 for values 0..0xa
# So command IDs are 0x11 through 0x1b:
#   r1=0  -> cmd 0x11 -> 0x8e0  (open/search object + delete_object + TEE_CloseObject)
#   r1=1  -> cmd 0x12 -> 0x90c  (search linked list)
#   r1=2  -> cmd 0x13 -> 0x968  (TEE_ReadObjectData)
#   r1=3  -> cmd 0x14 -> 0x9a4  (TEE_WriteObjectData)
#   r1=4  -> cmd 0x15 -> 0x9e8  (TEE_SeekObjectData)
#   r1=5  -> cmd 0x16 -> 0xa78  (unsupported, returns error)
#   r1=6  -> cmd 0x17 -> 0xa78  (unsupported, returns error)
#   r1=7  -> cmd 0x18 -> 0xa0c  (TEE_CloseAndDeletePersistentObject)
#   r1=8  -> cmd 0x19 -> 0xa38  (TEE_InfoObjectData)
#   r1=9  -> cmd 0x1a -> 0x7c0  (TEE_SyncPersistentObject)
#   r1=0xa -> cmd 0x1b -> default at 0x7f4 (create persistent object with hash)
#
# Default (cmd not in 0x11..0x1b) -> 0x7f4 (the complex create/store path)
#
# Parameter usage per command:
# cmd 0x11 (0x8e0): params[0] used as search key (memref). delete_object called.
# cmd 0x12 (0x90c): no params from p3 directly, uses internal linked list
# cmd 0x13 (0x968): params[0] = search key (memref), params[2].a = buffer, params[2].b = size, params[4].a = output count
# cmd 0x14 (0x9a4): params[0] = search key (memref), params[2].a = buffer, params[2].b = size, params[4].a = output
# cmd 0x15 (0x9e8): params[0..2] loaded via ldm r6, {r1, r4, r6} -> params[0]=key, params[1]=offset, params[2]=whence
# cmd 0x18 (0xa0c): params[0] = search key (memref). Close and delete.
# cmd 0x19 (0xa38): params[0] = search key (memref), params[2] and params[3] = output values
# cmd 0x1a (0x7c0): params[0] = search key (memref). Sync.
# cmd 0x1b/default (0x7f4): params[0] = filename (memref ptr in params[0]), params[1] = filename length,
#                            params[2] = flags from session. Complex create path.

# Parameter array layout (p3): each slot is 2 words (8 bytes on ARM32).
# p3[0] at p3+0, p3[1] at p3+8, p3[2] at p3+16, p3[3] at p3+24

# Dependency analysis:
# - cmd 0x1b (default/create) creates persistent objects -> predecessor for read/write/seek/info/sync/delete/close
# - cmd 0x11 (open+delete_object) opens and registers object -> predecessor for read/write/seek
# - cmd 0x13 (read), 0x14 (write), 0x15 (seek) operate on opened objects
# - cmd 0x18 (close+delete), 0x1a (sync) are terminal for an object
# - cmd 0x19 (info) reads object info
# - cmd 0x12 (list) is standalone


# cmd 0x1b / default: Create persistent object (the big path at 0x7f4)
# Uses params[0] as pointer to filename, params[1] as filename length, params[2] as flags
@ta_init_function(next_funcs=[
    "init_7461736b5f73746f7261676500000000_1",   # open/delete_object (0x11)
    "init_7461736b5f73746f7261676500000000_3",   # read (0x13)
    "init_7461736b5f73746f7261676500000000_4",   # write (0x14)
    "init_7461736b5f73746f7261676500000000_5",   # seek (0x15)
    "init_7461736b5f73746f7261676500000000_7",   # close+delete (0x18)
    "init_7461736b5f73746f7261676500000000_8",   # info (0x19)
    "init_7461736b5f73746f7261676500000000_9",   # sync (0x1a)
])
def init_7461736b5f73746f7261676500000000_0(state):
    """Command 0x1b - Create persistent object (default path at 0x7f4)"""
    p3 = init_params(state)
    state.regs.r1 = 0x1b

    # params[0] = pointer to filename buffer (memref)
    place_sym_memref_param(state, p3, 0)
    # params[1] = filename length (value)
    place_sym_value_param(state, p3, 1)
    # params[2] = flags (value) - loaded at 0xf20: ldr r7, [r6, #8] -> p3 offset 8 = slot index 1... 
    # Actually r6 = p3, so [r6, #8] = p3+8 = slot 1 word 0, [r6, #0xc] = p3+12 = slot 1 word 1
    # But for the default path: [r6] = params[0], [r6,#4] = params[0].size
    # The create path reads [r7] at 0x828 where r7 = session ptr (r0)
    # Keep remaining slots symbolic
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x11: Open/search + delete_object + TEE_CloseObject
@ta_init_function(next_funcs=[
    "init_7461736b5f73746f7261676500000000_3",   # read
    "init_7461736b5f73746f7261676500000000_4",   # write
    "init_7461736b5f73746f7261676500000000_5",   # seek
    "init_7461736b5f73746f7261676500000000_7",   # close+delete
    "init_7461736b5f73746f7261676500000000_8",   # info
    "init_7461736b5f73746f7261676500000000_9",   # sync
])
def init_7461736b5f73746f7261676500000000_1(state):
    """Command 0x11 - search_object + delete_object + TEE_CloseObject"""
    p3 = init_params(state)
    state.regs.r1 = 0x11

    # At 0x8e0: ldr r1, [r6] -> search key from params[0]
    # bl search_object; then delete_object; then TEE_CloseObject
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x12: Search linked list (standalone)
@ta_init_function
def init_7461736b5f73746f7261676500000000_2(state):
    """Command 0x12 - Search internal linked list"""
    p3 = init_params(state)
    state.regs.r1 = 0x12

    # This command doesn't seem to use params from p3 directly
    # It accesses internal global data structures
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x13: TEE_ReadObjectData
@ta_init_function
def init_7461736b5f73746f7261676500000000_3(state):
    """Command 0x13 - ReadObjectData"""
    p3 = init_params(state)
    state.regs.r1 = 0x13

    # At 0x968: ldr r1, [r6] = params[0] (search key)
    #           ldr r4, [r6, #8] = params[1].a (buffer ptr)
    #           ldr r7, [r6, #0xc] = params[1].b (buffer size)
    # Then bl search_object with r1
    # Then TEE_ReadObjectData(obj, r4_buf, r7_size, &count)
    # params[4].a at [r6, #0x10] = output count
    place_sym_memref_param(state, p3, 0)  # search key (memref: ptr, size)
    place_sym_value_param(state, p3, 1)   # buffer ptr (value_a) and size (value_b)
    place_sym_value_param(state, p3, 2)   # output count stored at [r6, #0x10] = p3+16
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x14: TEE_WriteObjectData
@ta_init_function
def init_7461736b5f73746f7261676500000000_4(state):
    """Command 0x14 - WriteObjectData"""
    p3 = init_params(state)
    state.regs.r1 = 0x14

    # At 0x9a4: ldr r1, [r6] = params[0] (search key)
    #           ldr r7, [r6, #8] = params[1].a (buffer)
    #           ldr r8, [r6, #0xc] = params[1].b (size)
    # TEE_WriteObjectData; output at [r6, #0x10]
    place_sym_memref_param(state, p3, 0)  # search key
    place_sym_value_param(state, p3, 1)   # buffer ptr and size
    place_sym_value_param(state, p3, 2)   # output
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x15: TEE_SeekObjectData
@ta_init_function
def init_7461736b5f73746f7261676500000000_5(state):
    """Command 0x15 - SeekObjectData"""
    p3 = init_params(state)
    state.regs.r1 = 0x15

    # At 0x9e8: ldm r6, {r1, r4, r6}
    # r1 = [r6+0] = params[0] (search key)
    # r4 = [r6+4] = params[0].size / offset
    # r6 = [r6+8] = params[1].a / whence
    # TEE_SeekObjectData(obj, r4_offset, r6_whence & 0xff)
    place_sym_memref_param(state, p3, 0)  # search key ptr + offset
    place_sym_value_param(state, p3, 1)   # whence in value_a
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x16/0x17: Unsupported commands (return error)
@ta_init_function
def init_7461736b5f73746f7261676500000000_6(state):
    """Command 0x16 - Unsupported (returns error)"""
    p3 = init_params(state)
    state.regs.r1 = 0x16

    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x18: TEE_CloseAndDeletePersistentObject
@ta_init_function
def init_7461736b5f73746f7261676500000000_7(state):
    """Command 0x18 - CloseAndDeletePersistentObject"""
    p3 = init_params(state)
    state.regs.r1 = 0x18

    # At 0xa0c: ldr r1, [r6] = params[0] (search key)
    # bl search_object; then delete_object; then TEE_CloseAndDeletePersistentObject
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x19: TEE_InfoObjectData
@ta_init_function
def init_7461736b5f73746f7261676500000000_8(state):
    """Command 0x19 - InfoObjectData"""
    p3 = init_params(state)
    state.regs.r1 = 0x19

    # At 0xa38: ldr r1, [r6] = params[0] (search key)
    # bl search_object
    # TEE_InfoObjectData(obj, &size, &pos)
    # Output: [r6, #8] = size, [r6, #0xc] = pos
    place_sym_memref_param(state, p3, 0)  # search key
    place_sym_value_param(state, p3, 1)   # output: size and pos stored here
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state


# cmd 0x1a: TEE_SyncPersistentObject
@ta_init_function
def init_7461736b5f73746f7261676500000000_9(state):
    """Command 0x1a - SyncPersistentObject"""
    p3 = init_params(state)
    state.regs.r1 = 0x1a

    # At 0x7c0: ldr r1, [r6] = params[0] (search key)
    # bl search_object; then TEE_SyncPersistentObject
    place_sym_memref_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)

    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_7461736b5f73746f7261676500000000_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

