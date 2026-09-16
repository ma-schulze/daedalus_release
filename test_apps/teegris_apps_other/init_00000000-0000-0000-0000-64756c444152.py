import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# TA dispatch summary (TA_InvokeCommandEntryPoint @ 0x7c6c):
# - The TA checks w2 (param_types) == 0x67 -> slot0=MEMREF_INOUT(7), slot1=MEMREF_OUTPUT(6).
# - Reads slot0.ptr (x23), slot0.size (w20=x25), slot1.ptr (x22), slot1.size (w21=x26).
# - Calls TEES_IsREESharedMemory on both buffers. If both OK, then performs further checks
#   and calls sub_6398(buf0, size0, buf1, size1, mode).
# - sub_6398 first calls sub_7fb4 to read some "session" state (RAND-based). If sub_7fb4
#   returns nonzero, dispatches via w21 (the "mode" arg, originally slot1.size w21):
#     * 0xA01 -> AES variant (sub_8150) — needs size0>=0x404, size1>=0xC10
#     * 0xA02 -> ECDH-like (sub_60c8)  — needs size0>=0x1010, size1>=0x80C
#     * 0xA03 -> RSA-like (sub_77b4)   — needs size0>=0xC0C, size1>=0x408
#     * 0x7FFFFAF1 -> EC variant (sub_5ebc) — needs size0>=0x404, size1>=0x408
#
# Only one TA_InvokeCommand path exists (param_types == 0x67), but four logical
# subcommands are dispatched via w21 (= slot1.size value, in the upper 32 bits of x21,
# but used as w21 — the actual second-slot "size" field). Each one needs its own init.
#
# State explosion concerns:
# - The buffers themselves are large (up to 0x1010 / 0xC10 bytes). Avoid symbolic
#   exploration over the entire buffer; the helpers already place symbolic memrefs.
# - The mode/size values w20/w21 must be constrained concretely to one of the
#   four subcommand values to avoid path explosion.
# - param_types must be concretely 0x67.
#
# Note: w20 is slot0.size and w21 is slot1.size from p3. We set them concretely
# in p3 slot fields (size field at +word_size of each slot).

def _setup_common(state, mode_w21, size0_w20):
    """Setup p3 with MEMREF_INOUT slot0 and MEMREF_OUTPUT slot1, then patch the
    size fields concretely to drive the inner dispatch."""
    p3 = init_params(state)
    # param_types = 0x67 -> slot0=MEMREF_INOUT(7), slot1=MEMREF_OUTPUT(6)
    state.regs.x2 = 0x67
    state.regs.x1 = 0  # cmd id not used by TA, but set to 0
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Concretize sizes:
    # slot layout: p3 + i*16 -> ptr; p3 + i*16 + 8 -> size (64-bit on AArch64)
    # But the TA reads them as 32-bit (w20, w21). Write 64-bit values; low 32 bits
    # are what get used as w20/w21.
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(size0_w20, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(mode_w21, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_0(state):
    # Subcommand 0xA01 (AES-like via sub_8150): size0 >= 0x404, size1 >= 0xC10
    _setup_common(state, mode_w21=0xC10, size0_w20=0x404)
    # mode_w21 is slot1.size, which is also used as the dispatch selector (w21).
    # But the dispatch compares w21 to 0xA01/0xA02/0xA03/0x7FFFFAF1.
    # Looking again: w21 in sub_6398 comes from w4 (5th arg) = w24 in caller = w21 in
    # TA_InvokeCmd = slot1.size lower 32 bits. So we must set slot1.size = 0xA01
    # AND also pass size checks against the buffer sizes (cmp w24 = slot0.size).
    # Actually w24 in sub_6398 = slot0.size (w20 in TA_Invoke), and w21 in sub_6398
    # is the mode (w4 arg = w21 in TA_Invoke = slot1.size).
    # So slot1.size IS the mode selector. The buffer-size checks then use w24=slot0.size
    # and w23=slot1.size (still the selector)? Re-reading: cmp w23, #0x80b uses w23
    # which was set from w21 (slot1.size). That conflicts with using it as both
    # selector and size. We'll set slot1.size = 0xA01 and slot0.size large enough
    # to pass cmp w24, #0x1010 check (>= 0x1010). The cmp w23, #0x80b check would fail
    # for slot1.size=0xA01 (0xA01 > 0x80B is true), so it should pass.
    state.memory.store(init_params(state) if False else (state.regs.x3), claripy.BVV(0, 8))  # no-op
    # Re-apply correct selector:
    p3 = state.regs.x3
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0xA01, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0x1010, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_1(state):
    # Subcommand 0xA02 (ECDH-like via sub_60c8): needs size0_w24 >= 0x404 and
    # size1_w23 (=selector) > 0x407. selector=0xA02 satisfies both.
    _setup_common(state, mode_w21=0xA02, size0_w20=0x1010)
    p3 = state.regs.x3
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0xA02, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0x1010, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_2(state):
    # Subcommand 0xA03 (RSA-like via sub_77b4): needs size0_w24 >= 0xC0C and selector
    # check >= 0x408. selector=0xA03 satisfies both.
    _setup_common(state, mode_w21=0xA03, size0_w20=0xC0C)
    p3 = state.regs.x3
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0xA03, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0xC0C, 64), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_ta_3(state):
    # Subcommand 0x7FFFFAF1 (EC variant via sub_5ebc): needs size0_w24 >= 0x404 and
    # selector > 0x407. The selector itself is 0x7FFFFAF1 which is huge, but the
    # branch at 0x7f80 tests tbnz w24,#0x1f (sign bit of slot0.size). slot0.size
    # must NOT have bit31 set to reach sub_6398 normally. The 0x7FFFFAF1 is mode w21
    # not size. set slot0.size = 0x404, slot1.size selector = 0x7FFFFAF1.
    _setup_common(state, mode_w21=0x7FFFFAF1, size0_w20=0x404)
    p3 = state.regs.x3
    state.memory.store(p3 + 1 * 16 + 8, claripy.BVV(0x7FFFFAF1, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 16 + 8, claripy.BVV(0x404, 64), endness=state.arch.memory_endness)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_64756c444152_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

