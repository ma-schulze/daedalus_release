import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA Analysis:
# - r2 must be 0x65 -> slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6)
# - p3[0]: memref input, must have size 0x40c
# - p3[1]: memref output, must have size 0x408
# - First word of input buffer (r6[0]) must be 1 to proceed
# - r1 (r4) is the command ID, dispatched as follows:
#   0x001: TEE_OpenPersistentObject style (generate key)         -> b904 -> sub_b904
#   0x002: similar create                                        -> b904
#   0x100: load/restore key + sign (depends on r6[0x14]==0)     -> a290 sub_b9d0
#   0x101: similar load + verify (r6[0x14]==0)                  -> a290 sub_b9e0
#   0x102: open persistent + load (b9ec)
#   0x103: sub_b174 + ba04
#   0x200: ba1c (delete?)
#   0x300: complex with abb8
#   0x301: complex with a8f0
#   0x400: sub_b174
# Stateful: 0x100/0x101/0x102 read from a persistent object - they should
# follow a create command (0x001 or 0x002).

CMD_CREATE_1 = 0x001
CMD_CREATE_2 = 0x002
CMD_LOAD_SIGN = 0x100
CMD_LOAD_VERIFY = 0x101
CMD_LOAD_OPEN = 0x102
CMD_CMD_103 = 0x103
CMD_DELETE = 0x200
CMD_CMD_300 = 0x300
CMD_CMD_301 = 0x301
CMD_CMD_400 = 0x400


def _setup_common(state):
    """Common parameter setup: r2=0x65, memref in/out, first word=1."""
    p3 = init_params(state)
    state.regs.r2 = 0x65

    # Slot 0: MEMREF_INPUT, size must be 0x40c
    place_sym_memref_param(state, p3, 0)
    # Override size to 0x40c
    word = 4
    state.memory.store(p3 + 0 * 2 * word + word, claripy.BVV(0x40c, 32), endness=state.arch.memory_endness)

    # Slot 1: MEMREF_OUTPUT, size must be 0x408
    place_sym_memref_param(state, p3, 1)
    state.memory.store(p3 + 1 * 2 * word + word, claripy.BVV(0x408, 32), endness=state.arch.memory_endness)

    # Read buffer pointer of slot 0 (r6)
    buf_ptr = state.memory.load(p3 + 0, word, endness=state.arch.memory_endness)
    # First word at [r6] must be 1
    state.memory.store(buf_ptr, claripy.BVV(1, 32), endness=state.arch.memory_endness)

    return p3, buf_ptr


@ta_init_function(next_funcs=["init_e5140b3376fa4c63ab18062caab2fb5c_2",
                              "init_e5140b3376fa4c63ab18062caab2fb5c_3",
                              "init_e5140b3376fa4c63ab18062caab2fb5c_4"])
def init_e5140b3376fa4c63ab18062caab2fb5c_0(state):
    # Command 0x001: create/generate persistent key (first variant)
    _setup_common(state)
    state.regs.r1 = CMD_CREATE_1
    return state


@ta_init_function(next_funcs=["init_e5140b3376fa4c63ab18062caab2fb5c_2",
                              "init_e5140b3376fa4c63ab18062caab2fb5c_3",
                              "init_e5140b3376fa4c63ab18062caab2fb5c_4"])
def init_e5140b3376fa4c63ab18062caab2fb5c_1(state):
    # Command 0x002: create variant
    _setup_common(state)
    state.regs.r1 = CMD_CREATE_2
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_2(state):
    # Command 0x100: load key + sign (requires prior create)
    _setup_common(state)
    state.regs.r1 = CMD_LOAD_SIGN
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_3(state):
    # Command 0x101: load key + verify (requires prior create)
    _setup_common(state)
    state.regs.r1 = CMD_LOAD_VERIFY
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_4(state):
    # Command 0x102: open persistent (requires prior create)
    _setup_common(state)
    state.regs.r1 = CMD_LOAD_OPEN
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_5(state):
    # Command 0x103
    _setup_common(state)
    state.regs.r1 = CMD_CMD_103
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_6(state):
    # Command 0x200: delete
    _setup_common(state)
    state.regs.r1 = CMD_DELETE
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_7(state):
    # Command 0x300
    _setup_common(state)
    state.regs.r1 = CMD_CMD_300
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_8(state):
    # Command 0x301
    _setup_common(state)
    state.regs.r1 = CMD_CMD_301
    return state


@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_9(state):
    # Command 0x400
    _setup_common(state)
    state.regs.r1 = CMD_CMD_400
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_e5140b3376fa4c63ab18062caab2fb5c_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

