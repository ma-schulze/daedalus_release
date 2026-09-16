import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function


# Command dispatch table at 0x1ff8 indexes by w1 (cmd id), w1 in [0,4].
# cmd 0: open device (stores fd at 0x5000)
# cmd 1: close device (uses fd at 0x5000)
# cmd 2: ioctl with buffer (uses fd, needs fd open first)
# cmd 3: ioctl variant
# cmd 4: ioctl variant
# Dependency: cmds 1,2,3,4 use the fd stored by cmd 0.


@ta_init_function(next_funcs=["init_mst_TA_1", "init_mst_TA_2", "init_mst_TA_3", "init_mst_TA_4"])
def init_mst_TA_0(state):
    p3 = init_params(state)
    state.regs.x1 = 0x0
    return state


@ta_init_function
def init_mst_TA_1(state):
    p3 = init_params(state)
    state.regs.x1 = 0x1
    return state


@ta_init_function
def init_mst_TA_2(state):
    p3 = init_params(state)
    state.regs.x1 = 0x2
    return state


@ta_init_function
def init_mst_TA_3(state):
    p3 = init_params(state)
    state.regs.x1 = 0x3
    return state


@ta_init_function
def init_mst_TA_4(state):
    p3 = init_params(state)
    state.regs.x1 = 0x4
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_6d73745f5441_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

