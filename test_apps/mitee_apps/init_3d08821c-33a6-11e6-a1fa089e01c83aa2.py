import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function

# TA dispatch analysis (entry 0x26190):
#   - x2 (param types) must equal 0x65  (cmp w19,#0x65)
#   - p3[0] (value.a) must equal 1      (ldr w5,[x0]; cmp w5,#1)
#   - p3[1].size field at offset 8 == 0x608  (value.b of slot0 region)
#   - p3[3].size field at offset 0x18 == 0x608
#   - x1 is the command ID (w21)
# Command IDs (w21):
#   < 0x1000                   -> error (not valid cmd)
#   1..0x1003 range handled via table/switch:
#       0x1000 : sub_226d0 (sign/key op; chain-capable)
#       0x1001 : sub_22888
#       0x1002 : sub_22a18
#       0x1003 : sub_22e70
#   == 0x2000 : sub_20cf0 (check)
#   == 0x2001 : sub_20550 (generate/store key - producer)
#   == 0x2002 : sub_20d98 (load/use stored key)
# Stateful: 0x2001 populates internal key storage; 0x2002 and 0x1000..0x1003
# depend on a stored key existing.

# Parameter type 0x65: low nibble 5=VALUE_INPUT? In any case the code checks
# p3[0] word0==1, p3[1] word1(==size field)==0x608, p3[3] word1==0x608.

P_TYPES = 0x65

def _setup_common(state):
    p3 = init_params(state)
    # slot 0: value-like; place as value, then force word0=1
    place_sym_value_param(state, p3, 0)
    # slot 1: memref-like (size must be 0x608)
    place_sym_memref_param(state, p3, 1)
    # slot 2: unused but place a value to be safe
    place_sym_value_param(state, p3, 2)
    # slot 3: memref-like (size must be 0x608)
    place_sym_memref_param(state, p3, 3)

    # x2 = param types
    state.regs.x2 = P_TYPES

    # p3[0] word0 = 1 (selects the operation group at 0x2622c)
    # slot i starts at p3 + i*16 (AArch64, 2*word_size=16)
    state.memory.store(p3 + 0, claripy.BVV(1, 32), endness=state.arch.memory_endness)

    # p3[1] size (at p3 + 16 + 8) = 0x608
    state.memory.store(p3 + 16 + 8, claripy.BVV(0x608, 32), endness=state.arch.memory_endness)
    # p3[3] size (at p3 + 48 + 8) = 0x608
    state.memory.store(p3 + 48 + 8, claripy.BVV(0x608, 32), endness=state.arch.memory_endness)

    return p3


# ------- Producer: key/credential generation (cmd 0x2001) -------
@ta_init_function(next_funcs=[
    "init_3d08821c_1",
    "init_3d08821c_2",
    "init_3d08821c_3",
    "init_3d08821c_4",
    "init_3d08821c_5",
    "init_3d08821c_6",
])
def init_3d08821c_0(state):
    # 0x2001 -> sub_20550 (stores/generates key material; producer)
    _setup_common(state)
    state.regs.x1 = 0x2001
    return state


# ------- Consumers that likely depend on stored key -------
@ta_init_function
def init_3d08821c_1(state):
    # 0x2002 -> sub_20d98 (uses stored key)
    _setup_common(state)
    state.regs.x1 = 0x2002
    return state


@ta_init_function
def init_3d08821c_2(state):
    # 0x1000 -> sub_226d0 (sign/crypto op; needs state)
    _setup_common(state)
    state.regs.x1 = 0x1000
    return state


@ta_init_function
def init_3d08821c_3(state):
    # 0x1001 -> sub_22888
    _setup_common(state)
    state.regs.x1 = 0x1001
    return state


@ta_init_function
def init_3d08821c_4(state):
    # 0x1002 -> sub_22a18
    _setup_common(state)
    state.regs.x1 = 0x1002
    return state


@ta_init_function
def init_3d08821c_5(state):
    # 0x1003 -> sub_22e70
    _setup_common(state)
    state.regs.x1 = 0x1003
    return state


# ------- Standalone: check/status command -------
@ta_init_function
def init_3d08821c_6(state):
    # 0x2000 -> sub_20cf0 (query whether key exists; standalone)
    _setup_common(state)
    state.regs.x1 = 0x2000
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_3d08821c_33a6_11e6_a1fa089e01c83aa2_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

