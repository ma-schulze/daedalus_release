import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# Dispatch summary for InvokeCommandEntryPoint at 0xc6cc8:
# - Checks w2 (param_types) == 0x65 (slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6))
# - For param_types == 0x65, reads p3[0].ptr (x22), p3[0].size (w20 = ldr w20,[x19,#8])
#   Then dispatches on w1 (cmd id):
#     0x10001 -> sub_c6910 (slot accept, also handled later in 0xc6dac path? See cmp w21,#0x10,lsl#12)
#     0x10002 (w8=2; movk #1,lsl#16) -> sub_c5f70 path
#     0x20000 (w8=#0x20,lsl#12) -> sub_c59c8 path
#     0x20001 (w8=1; movk #2,lsl#16) -> sub_c5f70 path? Actually 0xc6dc0 b.ne to 0xc6e9c
#     0x10000 (#0x10,lsl#12) -> sub_c6690 + sub_c6910
#     orr w21,#0x4000 == 0xc000 -> 0xc6f20 path with offset adjustment
#   Default falls to 0xc6f20 (sub_c6f20) which has a big inner dispatch on
#   *p3 (memref content first word) == various large values (cmds embedded in buffer).
#
# Since the inner dispatcher (sub_c6f20) reads cmd from the input buffer at *x21
# (the memref), and compares to many values up to 0x2c000, exploring it as one
# init would cause heavy state explosion. We provide:
#   - One init per top-level command id (w1)
#   - For the buffer-dispatched sub_c6f20 path, we constrain the first 4 bytes of
#     the input memref to specific concrete cmd ids covering the main branches.
#
# We do not have clear stateful dependencies in the disassembly snippet, so all
# inits are standalone.


def _setup_memref_in_out(state):
    """param_types == 0x65: slot0 MEMREF_INPUT, slot1 MEMREF_OUTPUT."""
    p3 = init_params(state)
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


# ---------- Top-level command-id branches ----------

@ta_init_function
def init_mitee_ta_0(state):
    # cmd 0x10001: sub_c6910 (via 0xc6e14..0xc6e38)
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x10001
    return state


@ta_init_function
def init_mitee_ta_1(state):
    # cmd 0x10002 (w21 == 2 | (1<<16)): falls to 0xc6e40 print path
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x10002
    return state


@ta_init_function
def init_mitee_ta_2(state):
    # cmd 0x20000 (#0x20,lsl#12): sub_c59c8 path at 0xc6e64
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x20000
    return state


@ta_init_function
def init_mitee_ta_3(state):
    # cmd 0x10000 (#0x10,lsl#12): sub_c6690 path at 0xc6e7c
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x10000
    return state


@ta_init_function
def init_mitee_ta_4(state):
    # cmd 0x20001 (w8 = 1 | (2<<16)) -> 0xc6dc4: sub_c5f70 path
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x20001
    return state


@ta_init_function
def init_mitee_ta_5(state):
    # cmd matching orr w21,#0x4000 == 0xc000 -> e.g. w21 = 0x8000
    # This routes to sub_c6f20 with x22 adjusted by +8.
    p3 = _setup_memref_in_out(state)
    state.regs.x1 = 0x8000
    return state


# ---------- Inner dispatcher sub_c6f20: cmd encoded in memref buffer ----------
# sub_c6f20 reads w1 = *(x21) where x21 is the input memref pointer.
# It compares w1 to many constants and branches via a jump table for w1 < 0x91.
# To avoid state explosion from the symbolic switch, we constrain the first
# 4 bytes of the input buffer to specific concrete sub-cmd ids.

# Distinct sub-cmd constants observed in sub_c6f20:
#   small (<0x91, jump-table): 0x00..0x90 cases - we pick a few representative
#   large compared values: 0x4000, 0x4004, 0x8000, 0x28000, 0x2c000, 0xc000

_SUB_CMDS = [
    0x00,      # jump table entry 0
    0x01,      # jump table entry 1
    0x02,      # jump table entry 2
    0x10,
    0x20,
    0x48,      # referenced explicitly via cmp w8,#0x48
    0x4000,    # cmp w1,#4,lsl#12
    0x4004,    # explicit constant
    0x8000,    # cmp w1,#8,lsl#12
    0xc000,    # cmp w1,#0xc,lsl#12
    0x28000,   # cmp w1,#0x28,lsl#12
    0x2c000,   # cmp w1,#0x2c,lsl#12
]


def _setup_subcmd(state, subcmd):
    """Top-level cmd that reaches sub_c6f20 with a sub-cmd in the memref buffer.
    Use top-level cmd 0x8000 which falls through to 0xc6eb0 -> 0xc6f20 default."""
    p3 = init_params(state)
    state.regs.x2 = 0x65
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    state.regs.x1 = 0x8000  # routes to sub_c6f20 default path
    # Read p3[0].ptr and constrain the first 4 bytes (the sub-cmd) to subcmd.
    word = state.arch.bytes  # 8 on AArch64
    slot0_ptr_addr = p3 + 0 * 2 * word
    buf_ptr = state.memory.load(slot0_ptr_addr, word, endness=state.arch.memory_endness)
    state.memory.store(buf_ptr, claripy.BVV(subcmd, 32), endness=state.arch.memory_endness)
    return state


@ta_init_function
def init_mitee_ta_6(state):
    return _setup_subcmd(state, _SUB_CMDS[0])


@ta_init_function
def init_mitee_ta_7(state):
    return _setup_subcmd(state, _SUB_CMDS[1])


@ta_init_function
def init_mitee_ta_8(state):
    return _setup_subcmd(state, _SUB_CMDS[2])


@ta_init_function
def init_mitee_ta_9(state):
    return _setup_subcmd(state, _SUB_CMDS[3])


@ta_init_function
def init_mitee_ta_10(state):
    return _setup_subcmd(state, _SUB_CMDS[4])


@ta_init_function
def init_mitee_ta_11(state):
    return _setup_subcmd(state, _SUB_CMDS[5])


@ta_init_function
def init_mitee_ta_12(state):
    return _setup_subcmd(state, _SUB_CMDS[6])


@ta_init_function
def init_mitee_ta_13(state):
    return _setup_subcmd(state, _SUB_CMDS[7])


@ta_init_function
def init_mitee_ta_14(state):
    return _setup_subcmd(state, _SUB_CMDS[8])


@ta_init_function
def init_mitee_ta_15(state):
    return _setup_subcmd(state, _SUB_CMDS[9])


@ta_init_function
def init_mitee_ta_16(state):
    return _setup_subcmd(state, _SUB_CMDS[10])


@ta_init_function
def init_mitee_ta_17(state):
    return _setup_subcmd(state, _SUB_CMDS[11])

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_dba51a17_0563_11e7_93b16fa7b0071a51_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

