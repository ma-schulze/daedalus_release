import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA_InvokeCommandEntryPoint at 0x11704
# - Checks w2 (param types) == 0x67 (GP param types mask expected)
# - Command ID is in w1 (cmd_id, stored in w21)
# - p3 layout: param[0] is memref (ptr+size=0x1c), param[2] is memref (ptr+size=0x1c)
#   Both sizes must equal 0x1c for the "first-call" path that goes into sub_11b6c (0x11870).
#   Alternatively, if sizes are 0x3300, dispatch goes to sub_b318 path (via TEES_IsREESharedMemory check).
#
# sub_11b6c dispatches on cmd_id (w21) in {1,2,3,4,5} -> several sub-commands.
# sub_b318 dispatches on cmd_id (w21) in {1..7} -> bigger crypto-like flow.
#
# We define inits for both the small-size (0x1c) path for cmd_ids 1..5,
# and the large-size (0x3300) path for cmd_ids 1..7.
#
# The TA appears stateful (see sub_12118 checking stored state in 0x18000 region),
# but without more info, we treat most as standalone. We chain "init key" style
# commands where possible by using sub_12118 success as a prerequisite.


TA_NAME = "00000000-0000-0000-0000-54412d48444d"


def _setup_small_path(state, cmd_id):
    """Param types = 0x67; two memrefs of size 0x1c each."""
    p3 = init_params(state)
    state.regs.x1 = cmd_id
    state.regs.x2 = 0x67

    # param[0]: memref with size 0x1c
    buf0 = claripy.BVV(get_tainted_mem_bits(state, 0x1c * 8), 0x1c * 8)
    addr0 = 0x70000000
    state.memory.store(addr0, buf0)
    word = 8
    state.memory.store(p3 + 0 * 2 * word, claripy.BVV(addr0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 2 * word + word, claripy.BVV(0x1c, 64), endness=state.arch.memory_endness)

    # param[1]: zero (not used in comparison, but p3[1*2]=param[1].a is checked at [x20]+0x10)
    # Actually the code reads [x20+0x10] and [x20+0x18] - that's param[2] memref ptr/size.
    # param[1] values irrelevant but set to zero.
    state.memory.store(p3 + 1 * 2 * word, claripy.BVV(0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 2 * word + word, claripy.BVV(0, 64), endness=state.arch.memory_endness)

    # param[2]: memref with size 0x1c
    addr2 = 0x70001000
    buf2 = claripy.BVV(get_tainted_mem_bits(state, 0x1c * 8), 0x1c * 8)
    state.memory.store(addr2, buf2)
    state.memory.store(p3 + 2 * 2 * word, claripy.BVV(addr2, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 2 * 2 * word + word, claripy.BVV(0x1c, 64), endness=state.arch.memory_endness)

    # param[3]: zero
    state.memory.store(p3 + 3 * 2 * word, claripy.BVV(0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * 2 * word + word, claripy.BVV(0, 64), endness=state.arch.memory_endness)

    return state


def _setup_large_path(state, cmd_id):
    """Param types = 0x67; two memrefs of size 0x3300 each. Goes to sub_b318 via TEES_IsREESharedMemory path."""
    p3 = init_params(state)
    state.regs.x1 = cmd_id
    state.regs.x2 = 0x67

    word = 8
    addr0 = 0x70000000
    # Keep content symbolic but small — whole buffer is huge (0x3300). We cap tainted region.
    # Only a few fields matter to symbolic exec; the rest can remain concrete zero to avoid explosion.
    state.memory.store(addr0, claripy.BVV(0, 0x3300 * 8))
    state.memory.store(p3 + 0 * 2 * word, claripy.BVV(addr0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 0 * 2 * word + word, claripy.BVV(0x3300, 64), endness=state.arch.memory_endness)

    state.memory.store(p3 + 1 * 2 * word, claripy.BVV(0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 1 * 2 * word + word, claripy.BVV(0, 64), endness=state.arch.memory_endness)

    addr2 = 0x70100000
    state.memory.store(addr2, claripy.BVV(0, 0x3300 * 8))
    state.memory.store(p3 + 2 * 2 * word, claripy.BVV(addr2, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 2 * 2 * word + word, claripy.BVV(0x3300, 64), endness=state.arch.memory_endness)

    state.memory.store(p3 + 3 * 2 * word, claripy.BVV(0, 64), endness=state.arch.memory_endness)
    state.memory.store(p3 + 3 * 2 * word + word, claripy.BVV(0, 64), endness=state.arch.memory_endness)

    # Plant a small tainted header area at start of each buf so symbolic exec can explore parsing.
    hdr0 = claripy.BVV(get_tainted_mem_bits(state, 0x40 * 8), 0x40 * 8)
    state.memory.store(addr0, hdr0)
    hdr2 = claripy.BVV(get_tainted_mem_bits(state, 0x40 * 8), 0x40 * 8)
    state.memory.store(addr2, hdr2)

    return state


# --- Small-size path (sub_11b6c), cmd_ids 1..5 ---

@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_0(state):
    # sub_11b6c cmd 1: calls sub_12118 then sub_cf90
    return _setup_small_path(state, 0x1)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_1(state):
    # sub_11b6c cmd 2: calls sub_12118 then sub_cdfc
    return _setup_small_path(state, 0x2)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_2(state):
    # sub_11b6c cmd 3: calls sub_fe8c (reads state)
    return _setup_small_path(state, 0x3)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_3(state):
    # sub_11b6c cmd 4: sub_f234
    return _setup_small_path(state, 0x4)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_4(state):
    # sub_11b6c cmd 5: sub_f234 + OR
    return _setup_small_path(state, 0x5)


# --- Large-size path (sub_b318), cmd_ids 1..7 ---

@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_5(state):
    # sub_b318 cmd 1
    return _setup_large_path(state, 0x1)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_6(state):
    # sub_b318 cmd 2
    return _setup_large_path(state, 0x2)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_7(state):
    # sub_b318 cmd 3
    return _setup_large_path(state, 0x3)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_8(state):
    # sub_b318 cmd 4
    return _setup_large_path(state, 0x4)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_9(state):
    # sub_b318 cmd 5
    return _setup_large_path(state, 0x5)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_10(state):
    # sub_b318 cmd 6
    return _setup_large_path(state, 0x6)


@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_11(state):
    # sub_b318 cmd 7
    return _setup_large_path(state, 0x7)

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_54412d48444d_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

