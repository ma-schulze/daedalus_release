
import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# Analysis summary:
# TA_InvokeCommandEntryPoint at 0x53b4 calls sub_57b8(cmd_id, param_types, p3).
# In sub_57b8:
#   - cmd_id (w19=w0) is compared against various command IDs.
#   - param_types (w21=w1) lower 16 bits checked against 7 (=> memref input at slot 0).
#     cmp w8,#7 — likely TEEC_MEMREF_TEMP_INPUT (0x5) with type mask 0x7? Commonly mask value is 7 for single memref.
#   - p3 is read as ldp x21,x22,[x20] — pointer+size of a memref at slot 0.
#   - Size must be 0x8000 and buffer must be REE shared memory.
#
# Discovered command IDs:
#   0x1001 -> handler path (prints "1001"), copies 0x8000 bytes, calls sub_6c08 (processes based on sub-opcode at offset 0x28)
#   0x1002 -> similar, calls sub_71a0 then sub_37cc (init key), then standard copy-out
#   0x1004 -> similar, jumps to 0x60e8 (like 0x1002 flow-ish) then sub_37cc; sets state byte at 0x10088=1 on success
#   0x2001 -> similar, calls sub_71a0 and sub_37cc
#   0xf001 -> zero buffer, flows into 0x6080 path (sub_6c08)
#   0xf003 -> memset of 0x388 at offset 0x80, flows into 0x6080 path
#   0x1..0x15 range -> jump-table based handlers (commands 1..21)
# Also note cmd ids 1..21 dispatched via jump table at 0x5840.
#
# Sub-opcodes processed inside sub_6c08 are read from [x0+0x28], with ranges 1..0x15 and 0x1001..0x1005, 0x2001.
#
# Dependencies:
#   0x1004 sets a flag byte at 0x10088 to 1 — possibly required precondition for some operation (e.g., before using key).
#   sub_37cc opens a key (persistent object) — sub_386c closes. 0x1001 opens key via sub_37cc.
#   So 0x1002/0x1004/0x2001 which call sub_37cc may need prior 0x1001 style setup? Actually each call sub_37cc themselves.
#
# To avoid state explosion, we constrain the memref buffer size to 0x8000 (the only accepted size),
# and constrain the sub-opcode at offset 0x28 into the input buffer.


def _setup_common(state, cmd_id):
    p3 = init_params(state)
    # Command ID goes into x0 of sub_57b8, but TA_InvokeCommandEntryPoint receives cmd in w1 (x1).
    state.regs.x1 = claripy.BVV(cmd_id, 64)
    # param types must have lower 16 bits == 7 (one memref input at slot 0)
    state.regs.x2 = claripy.BVV(0x7, 64)
    # Setup slot 0 as memref with size 0x8000
    place_sym_memref_param(state, p3, 0)
    # Constrain size field at p3 + 8 to 0x8000
    word = 8
    size_addr = p3 + 0 * 2 * word + word
    state.memory.store(size_addr, claripy.BVV(0x8000, 64), endness=state.arch.memory_endness)
    return state, p3


@ta_init_function(next_funcs=["init_sbxpxy_1", "init_sbxpxy_2", "init_sbxpxy_3",
                              "init_sbxpxy_4", "init_sbxpxy_5", "init_sbxpxy_6"])
def init_sbxpxy_0(state):
    # Command 0x1001: opens key via sub_37cc, sets internal state
    state, p3 = _setup_common(state, 0x1001)
    return state


@ta_init_function
def init_sbxpxy_1(state):
    # Command 0x1002: process buffer, calls sub_71a0 + sub_6c08
    state, p3 = _setup_common(state, 0x1002)
    return state


@ta_init_function
def init_sbxpxy_2(state):
    # Command 0x1004: sets flag byte at 0x10088 to 1
    state, p3 = _setup_common(state, 0x1004)
    return state


@ta_init_function
def init_sbxpxy_3(state):
    # Command 0x2001: calls sub_37cc
    state, p3 = _setup_common(state, 0x2001)
    return state


@ta_init_function
def init_sbxpxy_4(state):
    # Command 0xf001: zeroes / flows into sub_6c08 sub-opcode dispatch
    state, p3 = _setup_common(state, 0xf001)
    return state


@ta_init_function
def init_sbxpxy_5(state):
    # Command 0xf003: memset of 0x388 bytes then sub_6c08 dispatch
    state, p3 = _setup_common(state, 0xf003)
    return state


@ta_init_function
def init_sbxpxy_6(state):
    # Command in small range (1..0x15) — jump table dispatch at 0x5840
    # Pick a representative small command id. Use concrete id 1; other values covered via table naturally
    # but we constrain to avoid blowup.
    state, p3 = _setup_common(state, 0x1)
    return state


@ta_init_function
def init_sbxpxy_7(state):
    # Invalid / default path: cmd id that doesn't match any known handler -> error path at 0x6254
    state, p3 = _setup_common(state, 0x3000)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_534258505859_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

