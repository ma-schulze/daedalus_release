import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis summary:
# TA_InvokeCommandEntryPoint (0x19e58):
#   - Reads x3 (param array), checks p3[0].ptr != 0 (x19 from [x3])
#   - Checks (param_types & 0xf) == 7  -> first slot must be memref-input type (7)
#   - Calls TEES_IsREESharedMemory(3, buf, size) - must be non-zero (we set r2 to 0x7 and pass memref)
#   - Then parses TLV from the memref buffer: reads first 8 bytes as header:
#       low 32 bits = command (w24), high 32 bits (x21) = inner length
#     Calls sub_19320(cmd, buf+8, size-8, ...)
#
# sub_19320 dispatches on the command (w23):
#   - 0x1B4  -> sub_195dc  (uses tag 0x10 TLV; likely "init session"/create key context)
#   - 0xAB07 -> sub_19734  (clears state, no dependency)
#   - 0xB810 -> sub_19518  (TLV 0x12, calls sub_17d4c - needs global state x524 set)
#   - 0xB811 -> sub_19760  (TLV 0x1B, calls sub_17650 - "store key"; sets state x524)
#   - 0xB914 -> sub_197b0  (TLV 0x24 - key operations)
#   - 0xBA17 -> sub_19624  (TLV 0xF)
#   - 0xBB18 <=  (<=0xbb18 branch)
#   - 0xBB19 -> sub_196f4  (TLV 0xF)
#   - 0xBB20 -> sub_194b8  (TLV 0xF)
#   - 0xBB21 -> sub_19624  (TLV 0xF)
#   - 0xBC23 -> returns early (no-op path)
#   - 0x110..0x130 range  -> jump table (jumps to 0x19418 etc.)
#   - 0x1B3 <=  branch (sub_19418: TLV 0xF)
#
# Stateful notes:
#   - sub_17d4c (cmd 0xB810) reads global at 0x54524 (x524) and exits early if zero.
#     That global is set by sub_17650 (cmd 0xB811 path) when storing key.
#   - So 0xB810 depends on 0xB811 having been executed first.
#
# State-space explosion notes:
#   - The TLV parser (sub_2460c) walks bytes with a fully symbolic buffer, which causes
#     explosion when the first byte and inner lengths are symbolic. We constrain the first
#     byte to 0xFE (the expected prefix per 0x24648), the 2-byte length to a small value,
#     and the inner-TLV tag to the expected concrete value per command.
#   - We also constrain the memref size to a small value.

TA = "ta_00000000_0000_0000_0000_00000000534b4d"

P3_MEMREF_TYPE = 0x7  # memref-input in low nibble
MEMREF_SIZE = 0x40    # keep buffer small


def _setup_common(state, inner_cmd, inner_tlv_tag):
    """Set up common InvokeCommand state:
       - r2/x2 param types with low nibble = 7
       - p3[0] = memref pointing to a small buffer
       - Buffer layout (header): low32 = inner_cmd, high32 = inner length
       - Buffer payload starts at offset 8 with TLV: 0xFE <len:2 LE> <tag> <len2:2 LE> ...
       We constrain the outer prefix/length bytes and the inner tag to avoid explosion.
    """
    p3 = init_params(state)

    # x2 / param_types: ensure low nibble == 7 (memref)
    state.regs.x2 = claripy.BVV(P3_MEMREF_TYPE, 64)

    # place symbolic memref at slot 0
    place_sym_memref_param(state, p3, 0)

    # Read the pointer and size we just placed, so we can write concrete header bytes.
    word = 8
    ptr_addr = p3 + 0 * (2 * word)
    size_addr = p3 + 0 * (2 * word) + word
    buf_ptr = state.memory.load(ptr_addr, word, endness=state.arch.memory_endness)
    # Constrain size to MEMREF_SIZE (concrete small) to avoid explosion
    state.memory.store(size_addr, claripy.BVV(MEMREF_SIZE, 64),
                       endness=state.arch.memory_endness)

    # Write the 8-byte header: low32=cmd, high32=inner_length (use small length)
    inner_len = 0x20
    header = claripy.BVV((inner_len << 32) | (inner_cmd & 0xFFFFFFFF), 64)
    state.memory.store(buf_ptr, header, endness=state.arch.memory_endness)

    # Write outer TLV framing at buf+8:
    #   byte0 = 0xFE (prefix check in sub_2460c at 0x24648)
    #   bytes1..2 = outer total length (LE) - small
    #   byte3 = tag (= inner_tlv_tag, e.g. 0xF, 0x12, 0x1B, 0x24, 0x10, 0x1C, 0x27, 0x13, 0x11, 0x1B)
    #   bytes4..5 = inner length (LE) - small
    #   remaining bytes symbolic
    state.memory.store(buf_ptr + 8, claripy.BVV(0xFE, 8))
    state.memory.store(buf_ptr + 9, claripy.BVV(0x0010, 16), endness=state.arch.memory_endness)
    state.memory.store(buf_ptr + 11, claripy.BVV(inner_tlv_tag & 0xFF, 8))
    state.memory.store(buf_ptr + 12, claripy.BVV(0x0004, 16), endness=state.arch.memory_endness)

    # Payload bytes after the inner length stay symbolic (allocated by place_sym_memref_param)
    return p3


# -------- Command 0xAB07: simple/no-op branch (clears state) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_0(state):
    _setup_common(state, inner_cmd=0xAB07, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xBC23: early return path --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_1(state):
    _setup_common(state, inner_cmd=0xBC23, inner_tlv_tag=0x0F)
    return state


# -------- Command 0x1B4: sub_195dc (TLV tag 0x10) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_2(state):
    _setup_common(state, inner_cmd=0x1B4, inner_tlv_tag=0x10)
    return state


# -------- Command 0xBA17: sub_19624 (TLV tag 0x0F) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_3(state):
    _setup_common(state, inner_cmd=0xBA17, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xBB19: sub_196f4 (TLV tag 0x0F) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_4(state):
    _setup_common(state, inner_cmd=0xBB19, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xBB20: sub_194b8 (TLV tag 0x0F) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_5(state):
    _setup_common(state, inner_cmd=0xBB20, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xBB21: sub_19624 (TLV tag 0x0F) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_6(state):
    _setup_common(state, inner_cmd=0xBB21, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xB914: sub_197b0 (TLV tag 0x24) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_7(state):
    _setup_common(state, inner_cmd=0xB914, inner_tlv_tag=0x24)
    return state


# -------- Command 0x110 (jump-table range): sub_19418 (TLV tag 0x0F) --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_8(state):
    _setup_common(state, inner_cmd=0x110, inner_tlv_tag=0x0F)
    return state


# -------- Command 0xB811 (store key): sets global x524 (stateful producer) --------
# This command stores key material. It should be chained into 0xB810 (uses key).
@ta_init_function(next_func="init_ta_00000000_0000_0000_0000_00000000534b4d_10")
def init_ta_00000000_0000_0000_0000_00000000534b4d_9(state):
    _setup_common(state, inner_cmd=0xB811, inner_tlv_tag=0x1B)
    return state


# -------- Command 0xB810 (use key): depends on prior 0xB811 having set state x524 --------
@ta_init_function
def init_ta_00000000_0000_0000_0000_00000000534b4d_10(state):
    _setup_common(state, inner_cmd=0xB810, inner_tlv_tag=0x12)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_000000534b4d_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

