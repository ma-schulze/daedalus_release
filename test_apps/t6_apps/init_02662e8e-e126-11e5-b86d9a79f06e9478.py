import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits


# Analysis summary:
# Entry: 0x200fad (TA_InvokeCommandEntryPoint)
# - r1 == 0 => require r2 == 0x5573, then checks [r4+0xc] == 0x3a (param type for slot?),
#   then requires r4[0x1c] != 0 and r4[0x10] != 0 and r4[0x18] != 0.
#   This path does "generate/initialize" logic (sub_200671 stores a persistent object "THORELLA").
# - r1 == 1 => require r2 == 0x5733, then checks [r4+0x14] == 0x7f,
#   requires r4[0x1c] != 0, r4[0x10] != 0, r4[0x18] != 0.
#   This path performs "verify/use" logic which reads the persistent object via sub_2007b5
#   (sub_200671 reads THORELLA). It will fail early if object not created, so it depends on cmd 0.
#
# r4 is p3 (the param array pointer). The offsets accessed are:
#   [r4+0x0]  - slot0.a (session/object handle, sl)
#   [r4+0x4]  - slot0.b (written with 0 / result)
#   [r4+0x8]  - slot1.a (memref ptr) / value
#   [r4+0xc]  - slot1.b (must be 0x3a for cmd 0, is a size/length)
#   [r4+0x10] - slot2.a (memref ptr)
#   [r4+0x14] - slot2.b (must be 0x7f for cmd 1)
#   [r4+0x18] - slot3.a (memref ptr)
#   [r4+0x1c] - slot3.b (size, must be non-zero)
#
# So p3 is treated as 4 memref-like slots (ptr, size) pairs. We set r2 to the expected
# parameter type mask and craft the slots with appropriate sizes.
#
# Dependency: cmd 1 (verify) requires the persistent object created by cmd 0 (init/generate).


def _setup_common_slots(state, p3, size1, size2, size3):
    # Slot 0: value param (a, b) - used as handle/output
    place_sym_value_param(state, p3, 0)
    # Slot 1: memref-like (ptr, size=size1)
    place_sym_memref_param(state, p3, 1)
    state.memory.store(p3 + 0x0c, claripy.BVV(size1, 32), endness=state.arch.memory_endness)
    # Slot 2: memref-like (ptr, size=size2)
    place_sym_memref_param(state, p3, 2)
    state.memory.store(p3 + 0x14, claripy.BVV(size2, 32), endness=state.arch.memory_endness)
    # Slot 3: memref-like (ptr, size=size3)
    place_sym_memref_param(state, p3, 3)
    state.memory.store(p3 + 0x1c, claripy.BVV(size3, 32), endness=state.arch.memory_endness)


@ta_init_function(next_func="init_t6_1")
def init_t6_0(state):
    # Command 0: initialize/generate (sub_200da1 path) — required first.
    # Requires: r2 == 0x5573, p3[1].size == 0x3a, slot2 ptr !=0, slot3 ptr !=0, slot3 size !=0.
    p3 = init_params(state)
    state.regs.r1 = 0x0
    state.regs.r2 = 0x5573
    _setup_common_slots(state, p3, size1=0x3a, size2=0x40, size3=0x40)
    return state


@ta_init_function
def init_t6_1(state):
    # Command 1: verify/use — depends on cmd 0 having created the persistent object.
    # Requires: r2 == 0x5733, p3[2].size == 0x7f, slot2 ptr !=0, slot3 ptr !=0, slot3 size !=0.
    p3 = init_params(state)
    state.regs.r1 = 0x1
    state.regs.r2 = 0x5733
    _setup_common_slots(state, p3, size1=0x20, size2=0x7f, size3=0x40)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_02662e8e_e126_11e5_b86d9a79f06e9478_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

