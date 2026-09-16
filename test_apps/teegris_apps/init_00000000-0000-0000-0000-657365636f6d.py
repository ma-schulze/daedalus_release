import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# TA_InvokeCommandEntryPoint dispatch at 0x83e8:
# - Checks p3 layout: buffer[0] pointer non-null, buffer[0].size >= 0x1018, buffer[0].size <= 0x2030
#                     buffer[2] pointer non-null, buffer[2].size >= 0x1018, buffer[2].size <= 0x2030
# - Checks command ID (w2 / param types arg at [x29,#-0x18]) == 0x67
# - Then calls sub_8654 which verifies TEES_IsREESharedMemory on memrefs 0/1 (r0=3) and 2/3 (r0=2)
# - Then calls sub_9658 which dispatches on *(param0 + 0x1000) value (the subcommand read from in-buffer)
#
# Sub-command dispatch values (read at offset 0x1000 of memref[0].buffer -> w1):
#   0x00000003 -> sub_9148   (init/setup state: sets count++, clears flag byte 0x20 and pointer 0xa8)
#   0x00000004 -> sub_87e0   (uses buffer[0].buffer[0x1000] as w, requires w==0x20 or w==0x40)
#   0x00020021 -> sub_929c   (encryption-like, uses sub_8db0 with size check)
#   0x00020022 -> sub_8a30   (cleanup: requires count>0)
#   0x00020024 -> sub_8e3c   (info/print; terminal)
#   0x00020025 -> sub_8b18   (some crypto op; uses buf[0x1000] sized)
#   0x00020026 -> sub_87e0   (same handler as 4? no — distinct but similar wrapper)
#   0x00020028 -> sub_8e3c   (info wrapper variant)
#   0x00020029 -> sub_e9a8   (key op, uses [x+0x100])
#   0x00020030 -> sub_e674   (after sub_9cb4 gate; uses [x+0x200])
#   0x00022021 -> sub_d0f0   (key load; sets state.active=? — sets count++, clears state bytes, but in sub_9148 actually)
#   0x00022022 -> sub_f248   (uses loaded state ; reads heavy struct including 0x132..0x139 -> state space explosion source)
#
# Stateful dependency analysis:
# - sub_9148 (cmd 0x3) increments a counter at offset 0 and clears flag (byte 0x20) and ptr (0xa8)
#   -> initializer/reset. Many subsequent operations inspect *param0 != 0 etc.
# - sub_8a30 (cmd 0x20022): requires *param0 != 0 (count > 0) and then optionally invokes state->callback at 0xa8.
#   Must run AFTER cmd 0x3 at least once.
# - sub_d0f0 (cmd 0x22021): memsets param0, then copies [param1][0..0x10] to offset 0x84 -> initializes context.
# - sub_f248 (cmd 0x22022): uses param0 state with context established. Must run AFTER cmd 0x22021.
#
# State space explosion considerations:
# - sub_f248 reads many byte fields from the input memref (buf[0x132..0x139], buf[0x32], buf[0x11] lengths)
#   which are used as memcpy sizes (up to 256 bytes). Constrain lengths small.
# - sub_87e0 checks buf[0x1000] in {0x20,0x40}: set it concretely to reduce branching.

TA_NAME = "00000000_0000_0000_0000_657365636f6d"

# Helper: the TA expects memref parameter at index 0 AND index 2, both with size in [0x1018, 0x2030].
# We set up 4 memrefs (indices 0..3) because sub_8654 also checks param_types covering all 4 memrefs.

SIZE = 0x1100  # within [0x1018, 0x2030]


def _setup_common(state):
    p3 = init_params(state)
    # Command ID register w2 (at [x29,#-0x18]) must be 0x67
    state.regs.x2 = 0x67
    # x1 stored at [x29,#-0x14] (used by sub_9658 as cmd_id param) - keep symbolic/concrete later
    # Set up 4 memref parameters (all shared memory)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    place_sym_memref_param(state, p3, 2)
    place_sym_memref_param(state, p3, 3)
    # Constrain sizes so (size[0] and size[2]) are in [0x1018, 0x2030]
    word = 8
    for idx in (0, 2):
        size_addr = p3 + idx * 2 * word + word
        state.memory.store(size_addr, claripy.BVV(SIZE, 64), endness=state.arch.memory_endness)
    return p3


def _set_subcmd(state, p3, subcmd_val):
    # sub_9658 receives as its w1 the value of TA_InvokeCommandEntryPoint's w1 register.
    # Set x1 (cmd id) directly — this is what sub_9658 dispatches on.
    state.regs.x1 = subcmd_val & 0xFFFFFFFF


# ---------- Command 0x3: init/reset (sub_9148) ----------
@ta_init_function(next_funcs=[
    "init_" + TA_NAME + "_1",   # cmd 4
    "init_" + TA_NAME + "_2",   # cmd 0x20021
    "init_" + TA_NAME + "_3",   # cmd 0x20022 (cleanup) depends on this
    "init_" + TA_NAME + "_4",   # cmd 0x20024
    "init_" + TA_NAME + "_5",   # cmd 0x20025
    "init_" + TA_NAME + "_6",   # cmd 0x20026
    "init_" + TA_NAME + "_7",   # cmd 0x20028
    "init_" + TA_NAME + "_8",   # cmd 0x20029
    "init_" + TA_NAME + "_9",   # cmd 0x20030
    "init_" + TA_NAME + "_10",  # cmd 0x22021 (load ctx)
])
def init_00000000_0000_0000_0000_657365636f6d_0(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x3)
    return state


# ---------- Command 0x4: sub_87e0 ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_1(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x4)
    # Constrain buf[0][0x1000] = key size to concrete 0x20 to avoid branching
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(ptr0 + 0x1000, claripy.BVV(0x20, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x20021: sub_929c ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_2(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20021)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(ptr0 + 0x1000, claripy.BVV(0x20, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x20022: sub_8a30 (cleanup) — DEPENDS on 0x3 ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_3(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20022)
    return state


# ---------- Command 0x20024: sub_8e3c (info print) ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_4(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20024)
    return state


# ---------- Command 0x20025: sub_8b18 ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_5(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20025)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    # size field at buf[0][0x1000]
    state.memory.store(ptr0 + 0x1000, claripy.BVV(0x40, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x20026: sub_87e0 variant ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_6(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20026)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    state.memory.store(ptr0 + 0x1000, claripy.BVV(0x20, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x20028: sub_8e3c variant ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_7(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20028)
    return state


# ---------- Command 0x20029: sub_e9a8 ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_8(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20029)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    # size at buf[0][0x100] must be in [0x30, 0x200]; concrete to 0x30
    state.memory.store(ptr0 + 0x100, claripy.BVV(0x30, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x20030: sub_e674 (after sub_9cb4 gate) ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_9(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x20030)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    # size at buf[0][0x200] must equal 0x30
    state.memory.store(ptr0 + 0x200, claripy.BVV(0x30, 32), endness=state.arch.memory_endness)
    return state


# ---------- Command 0x22021: sub_d0f0 (context/key load) ----------
@ta_init_function(next_func="init_" + TA_NAME + "_11")
def init_00000000_0000_0000_0000_657365636f6d_10(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x22021)
    return state


# ---------- Command 0x22022: sub_f248 — DEPENDS on 0x22021 ----------
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_11(state):
    p3 = _setup_common(state)
    _set_subcmd(state, p3, 0x22022)
    ptr0 = state.memory.load(p3 + 0, 8, endness=state.arch.memory_endness)
    # Constrain size-like fields to small concrete values to avoid state explosion:
    # buf[0x11] used as memcpy size (up to 255) - set small
    state.memory.store(ptr0 + 0x11, claripy.BVV(0x08, 8))
    # buf[0x32] used as memcpy size - set small
    state.memory.store(ptr0 + 0x32, claripy.BVV(0x08, 8))
    # buf[0x137] length byte — small
    state.memory.store(ptr0 + 0x137, claripy.BVV(0x04, 8))
    # buf[0x138] 32-bit size used for memset (up to 0x100 allowed; must be <= 0x100)
    state.memory.store(ptr0 + 0x138, claripy.BVV(0x10, 16), endness=state.arch.memory_endness)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_657365636f6d_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

