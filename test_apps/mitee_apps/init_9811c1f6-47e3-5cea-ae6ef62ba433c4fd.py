import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# TA dispatch summary (from TA_InvokeCommandEntryPoint at 0x45ba0):
# - Checks param_types (w2) == 0x65, i.e. slot0 = MEMREF_INPUT (5), slot1 = MEMREF_OUTPUT (6).
# - Then dispatches on cmd_id (w1, w23). Valid range w1 <= 0x48.
# - Uses jump table at 0x11000+0x3e8. Many cmd_ids share handlers (the default at 0x45c8c
#   covers any unhandled index in [0..0x48]). We enumerate the distinct command handlers
#   that appear as explicit case targets in the disassembly.

TA_NAME = "ta_9811c1f6"

# Distinct command IDs observed as explicit case targets. We pick representative IDs
# that the jump table likely dispatches to each handler. To avoid path explosion we
# pick a single representative cmd ID per distinct handler.
# Indexes/handlers seen (one representative cmd_id chosen per handler block):
COMMAND_IDS = [
    0x00,  # default/load-key handler at 0x45c8c -> sub_6e850
    0x01,  # handler at 0x45ce0 -> sub_70cb8
    0x02,  # handler at 0x45d2c -> sub_738c8
    0x03,  # handler at 0x45d70 -> sub_6ea68
    0x04,  # handler at 0x45dbc -> sub_6ee50
    0x05,  # handler at 0x45e08 -> sub_6f700
    0x06,  # handler at 0x45e54 -> sub_70798
    0x07,  # handler at 0x45e98 -> sub_71310
    0x08,  # handler at 0x45ee4 -> sub_71938
    0x09,  # handler at 0x45f30 -> sub_71bf8
    0x0a,  # handler at 0x45f74 -> sub_71ce0
    0x0b,  # handler at 0x45fb8 -> sub_71f20
    0x0c,  # handler at 0x46004 -> sub_728e8
    0x0d,  # handler at 0x46050 -> sub_732f8
    0x0e,  # handler at 0x4609c -> sub_737e0
    0x0f,  # handler at 0x460e0 -> sub_73a00
    0x10,  # handler at 0x4612c -> sub_71830
    0x11,  # handler at 0x46178 -> sub_71708
    0x12,  # handler at 0x461c4 -> sub_70a98
    0x13,  # handler at 0x46210 -> sub_70b90
    0x14,  # handler at 0x4625c -> sub_70de0
    0x15,  # handler at 0x462a8 -> sub_6f080
    0x16,  # handler at 0x462f4 -> sub_6faa8
    0x17,  # handler at 0x46340 -> sub_6fd70
    0x18,  # handler at 0x4638c -> sub_702b0
    0x19,  # handler at 0x463d8 -> sub_70888
    0x1a,  # handler at 0x46424 -> sub_72220
    0x1b,  # handler at 0x46470 -> sub_71dc8
    0x1c,  # handler at 0x464ac -> sub_71df0
    0x1d,  # handler at 0x464f8 -> sub_72578
    0x1e,  # handler at 0x46544 -> sub_72d80
    0x1f,  # handler at 0x46590 -> sub_73d58
    0x20,  # handler at 0x465dc -> sub_71210
    0x21,  # handler at 0x46628 -> sub_70ec8
    0x22,  # handler at 0x46674 -> sub_6ef58
    0x23,  # handler at 0x466c0 -> sub_6f340
    0x24,  # handler at 0x4670c -> sub_71078
]


def _common_setup(state, cmd_id):
    p3 = init_params(state)
    # param_types == 0x65: slot0 = MEMREF_INPUT (5), slot1 = MEMREF_OUTPUT (6).
    # Set on both register widths to be safe (AArch64 uses w2/x2).
    state.regs.x2 = 0x65
    state.regs.x1 = cmd_id
    # slot 0: memref input (buffer + size)
    place_sym_memref_param(state, p3, 0)
    # slot 1: memref output (buffer + size)
    place_sym_memref_param(state, p3, 1)
    return state


# The TA appears stateful: many commands operate on an internal key/session that
# is set up by the "load key" / init command (cmd 0x00 -> sub_6e850, which calls
# into sub_44958 with key load semantics). We model this dependency by making
# cmd 0x00 the "initializer" and chaining the remaining commands as successors.

_SUCCESSORS = [f"init_{TA_NAME}_{i}" for i in range(1, len(COMMAND_IDS))]


@ta_init_function(next_funcs=_SUCCESSORS)
def init_ta_9811c1f6_0(state):
    # cmd 0x00: load/initialize key (default handler). This sets up the internal
    # state required by other commands.
    return _common_setup(state, COMMAND_IDS[0])


@ta_init_function
def init_ta_9811c1f6_1(state):
    return _common_setup(state, COMMAND_IDS[1])


@ta_init_function
def init_ta_9811c1f6_2(state):
    return _common_setup(state, COMMAND_IDS[2])


@ta_init_function
def init_ta_9811c1f6_3(state):
    return _common_setup(state, COMMAND_IDS[3])


@ta_init_function
def init_ta_9811c1f6_4(state):
    return _common_setup(state, COMMAND_IDS[4])


@ta_init_function
def init_ta_9811c1f6_5(state):
    return _common_setup(state, COMMAND_IDS[5])


@ta_init_function
def init_ta_9811c1f6_6(state):
    return _common_setup(state, COMMAND_IDS[6])


@ta_init_function
def init_ta_9811c1f6_7(state):
    return _common_setup(state, COMMAND_IDS[7])


@ta_init_function
def init_ta_9811c1f6_8(state):
    return _common_setup(state, COMMAND_IDS[8])


@ta_init_function
def init_ta_9811c1f6_9(state):
    return _common_setup(state, COMMAND_IDS[9])


@ta_init_function
def init_ta_9811c1f6_10(state):
    return _common_setup(state, COMMAND_IDS[10])


@ta_init_function
def init_ta_9811c1f6_11(state):
    return _common_setup(state, COMMAND_IDS[11])


@ta_init_function
def init_ta_9811c1f6_12(state):
    return _common_setup(state, COMMAND_IDS[12])


@ta_init_function
def init_ta_9811c1f6_13(state):
    return _common_setup(state, COMMAND_IDS[13])


@ta_init_function
def init_ta_9811c1f6_14(state):
    return _common_setup(state, COMMAND_IDS[14])


@ta_init_function
def init_ta_9811c1f6_15(state):
    return _common_setup(state, COMMAND_IDS[15])


@ta_init_function
def init_ta_9811c1f6_16(state):
    return _common_setup(state, COMMAND_IDS[16])


@ta_init_function
def init_ta_9811c1f6_17(state):
    return _common_setup(state, COMMAND_IDS[17])


@ta_init_function
def init_ta_9811c1f6_18(state):
    return _common_setup(state, COMMAND_IDS[18])


@ta_init_function
def init_ta_9811c1f6_19(state):
    return _common_setup(state, COMMAND_IDS[19])


@ta_init_function
def init_ta_9811c1f6_20(state):
    return _common_setup(state, COMMAND_IDS[20])


@ta_init_function
def init_ta_9811c1f6_21(state):
    return _common_setup(state, COMMAND_IDS[21])


@ta_init_function
def init_ta_9811c1f6_22(state):
    return _common_setup(state, COMMAND_IDS[22])


@ta_init_function
def init_ta_9811c1f6_23(state):
    return _common_setup(state, COMMAND_IDS[23])


@ta_init_function
def init_ta_9811c1f6_24(state):
    return _common_setup(state, COMMAND_IDS[24])


@ta_init_function
def init_ta_9811c1f6_25(state):
    return _common_setup(state, COMMAND_IDS[25])


@ta_init_function
def init_ta_9811c1f6_26(state):
    return _common_setup(state, COMMAND_IDS[26])


@ta_init_function
def init_ta_9811c1f6_27(state):
    return _common_setup(state, COMMAND_IDS[27])


@ta_init_function
def init_ta_9811c1f6_28(state):
    return _common_setup(state, COMMAND_IDS[28])


@ta_init_function
def init_ta_9811c1f6_29(state):
    return _common_setup(state, COMMAND_IDS[29])


@ta_init_function
def init_ta_9811c1f6_30(state):
    return _common_setup(state, COMMAND_IDS[30])


@ta_init_function
def init_ta_9811c1f6_31(state):
    return _common_setup(state, COMMAND_IDS[31])


@ta_init_function
def init_ta_9811c1f6_32(state):
    return _common_setup(state, COMMAND_IDS[32])


@ta_init_function
def init_ta_9811c1f6_33(state):
    return _common_setup(state, COMMAND_IDS[33])


@ta_init_function
def init_ta_9811c1f6_34(state):
    return _common_setup(state, COMMAND_IDS[34])


@ta_init_function
def init_ta_9811c1f6_35(state):
    return _common_setup(state, COMMAND_IDS[35])


@ta_init_function
def init_ta_9811c1f6_36(state):
    return _common_setup(state, COMMAND_IDS[36])

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_9811c1f6_47e3_5cea_ae6ef62ba433c4fd_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

