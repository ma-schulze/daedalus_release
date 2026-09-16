import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis of dispatch in sub_22538 (TA_InvokeCommandEntryPoint):
# After auth (sub_2eb78) check (cbz w0, #0x22644), command IDs in w1/w23 are checked:
#   - w23 <= 0x1FFFFFFF: subtract 0x10000000, must be <= 3 -> jump table at 0x22678
#     -> branches handled via lookup, with one entry calling sub_1ffd8 (cmd "A").
#     Other entries in the jump table call sub_1fb68 (0x226cc), sub_1fe20 (0x226dc),
#     sub_21120 (0x226ec). So cmd IDs are 0x10000000..0x10000003.
#   - w23 == 0x20000000 -> calls sub_21250 (0x22700)
#   - w23 == 0x20000001 -> calls sub_21368 (0x22750)
#   - w23 == 0x20000002 -> calls sub_219f0 (0x226b8)
# 
# sub_2eb78 (auth) seems to acquire mutex and produces w0=0 to allow dispatch.
# Returning non-zero from auth returns directly. We let it be symbolic; framework
# typically allows auth check to be bypassed.
#
# Stateful dependencies:
# - sub_21368 (cmd 0x20000001) opens/initializes secure storage objects (calls
#   sub_22c18 which calls 0x22770 -> creates persistent object). This sets up
#   internal state (key blob, etc.) used by other commands.
# - sub_219f0 (cmd 0x20000002) loads/operates on stored key (calls sub_2ea28 which
#   does TEE_OpenPersistentObject-like). Depends on storage being initialized first.
# - sub_1ffd8/sub_21120 (cmd 0x10000000/0x10000003) process APDUs that may depend
#   on prior state too.
#
# We chain: cmd 0x20000001 (init/provision) -> cmd 0x20000002 (use key)
#           cmd 0x20000001 -> cmd 0x10000000 (APDU dispatch)
#           cmd 0x20000001 -> cmd 0x10000003 (APDU with memref)
#
# Constrain memref sizes (e.g. APDU lengths) to small values to avoid explosion.


@ta_init_function(next_funcs=["init_mitee_pkcs11_3", "init_mitee_pkcs11_4",
                              "init_mitee_pkcs11_5", "init_mitee_pkcs11_6"])
def init_mitee_pkcs11_0(state):
    # cmd 0x20000001 -> sub_21368 (provision / init storage). Sets up internal
    # state required for subsequent key-based commands.
    p3 = init_params(state)
    state.regs.x1 = 0x20000001
    # sub_21368 expects param array (x3 = p3). Slot 0 used as memref output for
    # data (size checked later). Use a memref input/output.
    state.regs.x2 = 0x00000007  # slot0 = MEMREF_INOUT
    place_sym_memref_param(state, p3, 0)
    # Constrain memref size to small value to avoid loop explosion in sub_21368
    # (loops over buffer bytes building output).
    size_bv = state.memory.load(p3 + 1 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(size_bv <= 16)
    state.solver.add(size_bv >= 1)
    return state


@ta_init_function
def init_mitee_pkcs11_1(state):
    # cmd 0x10000001 -> jump table entry; calls sub_1fb68 (per jump table at
    # 0x22678 -> branch 0x226cc). sub_1fb68 inspects param0 value.
    p3 = init_params(state)
    state.regs.x1 = 0x10000001
    state.regs.x2 = 0x00000001  # slot0 = VALUE_INPUT
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_mitee_pkcs11_2(state):
    # cmd 0x10000002 -> jump table entry -> sub_1fe20 (per branch 0x226dc).
    # sub_1fe20 requires w1==0 path; uses session struct. Standalone.
    p3 = init_params(state)
    state.regs.x1 = 0x10000002
    state.regs.x2 = 0x00000001
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_mitee_pkcs11_3(state):
    # cmd 0x10000000 -> sub_1ffd8 (APDU processing). Requires session state from
    # provision command (sub_21368). sub_1ffd8 checks param_types == 0x65 path
    # (param0 memref input, param1 memref output) and ldr w2,[x19,#8] >= 4.
    p3 = init_params(state)
    state.regs.x1 = 0x10000000
    state.regs.x2 = 0x00000065  # slot0 = MEMREF_INPUT (5), slot1 = MEMREF_OUTPUT (6)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    # Constrain APDU input length (size field) to small range to avoid explosion
    sz0 = state.memory.load(p3 + 1 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz0 >= 4)
    state.solver.add(sz0 <= 16)
    sz1 = state.memory.load(p3 + 3 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz1 <= 64)
    return state


@ta_init_function
def init_mitee_pkcs11_4(state):
    # cmd 0x10000003 -> sub_21120 (per jump table branch 0x226ec). Checks
    # cmp w21,#0x65 and ldr w2,[x19,#8] >= 4. Uses memref params.
    p3 = init_params(state)
    state.regs.x1 = 0x10000003
    state.regs.x2 = 0x00000065
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    sz0 = state.memory.load(p3 + 1 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz0 >= 4)
    state.solver.add(sz0 <= 16)
    sz1 = state.memory.load(p3 + 3 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz1 <= 64)
    return state


@ta_init_function
def init_mitee_pkcs11_5(state):
    # cmd 0x20000000 -> sub_21250. Checks w21==0x61 and reads value param.
    # Uses keys/objects loaded via cmd 0x20000001.
    p3 = init_params(state)
    state.regs.x1 = 0x20000000
    state.regs.x2 = 0x00000001  # slot0 = VALUE_INPUT (ldr w8,[x2,#0x18]!)
    place_sym_value_param(state, p3, 0)
    # Constrain sub-command discriminator (read from p3+0x18 in sub_21250 ->
    # value.b of slot1, but slot1 also needed). Add slot1 too.
    state.regs.x2 = 0x00000011  # slot0 VALUE_INPUT, slot1 VALUE_INPUT
    place_sym_value_param(state, p3, 1)
    # The dispatch reads w8 from value at p3+0x18 (slot1 value.b), constrained 0..3
    sub_cmd = state.memory.load(p3 + 3 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sub_cmd <= 3)
    return state


@ta_init_function
def init_mitee_pkcs11_6(state):
    # cmd 0x20000002 -> sub_219f0 (use key / RSA op). Depends on provision.
    p3 = init_params(state)
    state.regs.x1 = 0x20000002
    state.regs.x2 = 0x00000065  # MEMREF_INPUT + MEMREF_OUTPUT (typical crypto op)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    sz0 = state.memory.load(p3 + 1 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz0 >= 1)
    state.solver.add(sz0 <= 32)
    sz1 = state.memory.load(p3 + 3 * 8, 8, endness=state.arch.memory_endness)
    state.solver.add(sz1 <= 64)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_2e8fade5_0c7a_46cc_810e6468baee66b9_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

