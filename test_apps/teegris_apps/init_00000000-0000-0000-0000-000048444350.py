import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

# HDCP2 TA (ARM32 vuln_tas build, TA_InvokeCommandEntryPoint @ 0x1d10).
# Invoke ABI: r1 = command byte; p3[0] = request memref (ptr, size);
# p3[1] = response memref (ptr, res_size_ptr). r2 is unused at entry.
# TZ_COMMAND dispatches on cmd in [0x66..0xe7] (subset valid); copies request
# into a malloc buffer then calls the per-command handler.


def _setup_hdcp_cmd(state, cmd_id):
    p3 = init_params(state)
    state.regs.r1 = cmd_id
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    word = 4
    req_ptr = state.memory.load(p3, word, endness=state.arch.memory_endness)
    resp_ptr = state.memory.load(p3 + 2 * word, word, endness=state.arch.memory_endness)
    resp_size_ptr = state.memory.load(p3 + 3 * word, word, endness=state.arch.memory_endness)
    state.solver.add(req_ptr != 0)
    state.solver.add(resp_ptr != 0)
    state.solver.add(resp_size_ptr != 0)
    return p3


# --- Invalid / default error path (cmd < 0x65 or unmapped) ---

@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_0(state):
<<<<<<< HEAD
    _setup_hdcp_cmd(state, 0x00)
    return state


# --- Transmitter (T) HDCP2 AKE protocol chain ---
# HW_Init -> LOADKEY -> SET_PAIRING_INFO -> AKE_Init -> cert/km exchange -> pairing info

@ta_init_function(next_func="init_00000000_0000_0000_0000_000048444350_ta_2")
def init_00000000_0000_0000_0000_000048444350_ta_1(state):
    _setup_hdcp_cmd(state, 0x82)  # TZ_HW_Init_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_3")
def init_00000000_0000_0000_0000_000048444350_ta_2(state):
    _setup_hdcp_cmd(state, 0x98)  # TZ_HDCP2_LOADKEY_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_4")
def init_00000000_0000_0000_0000_000048444350_ta_3(state):
    _setup_hdcp_cmd(state, 0x96)  # TZ_AKE_SET_PAIRING_INFO_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_5")
def init_00000000_0000_0000_0000_000048444350_ta_4(state):
    _setup_hdcp_cmd(state, 0x66)  # TZ_AKE_Init_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_6")
def init_00000000_0000_0000_0000_000048444350_ta_5(state):
    _setup_hdcp_cmd(state, 0x67)  # TZ_AKE_Send_Cert_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_7")
def init_00000000_0000_0000_0000_000048444350_ta_6(state):
    _setup_hdcp_cmd(state, 0x68)  # TZ_AKE_No_Store_km_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_8")
def init_00000000_0000_0000_0000_000048444350_ta_7(state):
    _setup_hdcp_cmd(state, 0x69)  # TZ_AKE_Store_km_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_9")
def init_00000000_0000_0000_0000_000048444350_ta_8(state):
    _setup_hdcp_cmd(state, 0x6a)  # TZ_AKE_Send_rrx_T
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_10")
def init_00000000_0000_0000_0000_000048444350_ta_9(state):
    _setup_hdcp_cmd(state, 0x6b)  # TZ_AKE_Send_h_prime_T
    return state


@ta_chain_target
def init_00000000_0000_0000_0000_000048444350_ta_10(state):
    _setup_hdcp_cmd(state, 0x6c)  # TZ_AKE_Send_Pairing_Info_T
    return state


# --- Transmitter standalone commands ---

@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_11(state):
    _setup_hdcp_cmd(state, 0x6d)  # TZ_LC_Init_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_12(state):
    _setup_hdcp_cmd(state, 0x6e)  # TZ_LC_Send_L_prime_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_13(state):
    _setup_hdcp_cmd(state, 0x6f)  # TZ_SKE_Send_Eks_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_14(state):
    _setup_hdcp_cmd(state, 0x70)  # TZ_RepeaterAuth_Send_ReceiverId_List_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_15(state):
    _setup_hdcp_cmd(state, 0x72)  # TZ_RTT_Challenge_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_16(state):
    _setup_hdcp_cmd(state, 0x73)  # TZ_RepeaterAuth_Send_Ack_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_17(state):
    _setup_hdcp_cmd(state, 0x74)  # TZ_RepeaterAuth_Stream_Manage_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_18(state):
    _setup_hdcp_cmd(state, 0x75)  # TZ_RepeaterAuth_Stream_Ready_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_19(state):
    _setup_hdcp_cmd(state, 0x76)  # TZ_Receiver_AuthStatus_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_20(state):
    _setup_hdcp_cmd(state, 0x77)  # TZ_AKE_Transmitter_Info_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_21(state):
    _setup_hdcp_cmd(state, 0x78)  # TZ_AKE_Receiver_Info_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_22(state):
    _setup_hdcp_cmd(state, 0x79)  # TZ_ENC_Data
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_23(state):
    _setup_hdcp_cmd(state, 0x7f)  # TZ_SET_HDCP_VERSION_T
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_24(state):
    _setup_hdcp_cmd(state, 0x83)  # TZ_HW_Close_T
    return state


# --- Receiver (R) HDCP2 AKE protocol chain ---

@ta_init_function(next_func="init_00000000_0000_0000_0000_000048444350_ta_26")
def init_00000000_0000_0000_0000_000048444350_ta_25(state):
    _setup_hdcp_cmd(state, 0xe6)  # TZ_HW_Init_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_27")
def init_00000000_0000_0000_0000_000048444350_ta_26(state):
    _setup_hdcp_cmd(state, 0xca)  # TZ_AKE_Init_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_28")
def init_00000000_0000_0000_0000_000048444350_ta_27(state):
    _setup_hdcp_cmd(state, 0xcb)  # TZ_AKE_Send_Cert_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_29")
def init_00000000_0000_0000_0000_000048444350_ta_28(state):
    _setup_hdcp_cmd(state, 0xcc)  # TZ_AKE_No_Store_km_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_30")
def init_00000000_0000_0000_0000_000048444350_ta_29(state):
    _setup_hdcp_cmd(state, 0xcd)  # TZ_AKE_Store_km_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_31")
def init_00000000_0000_0000_0000_000048444350_ta_30(state):
    _setup_hdcp_cmd(state, 0xce)  # TZ_AKE_Send_rrx_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_32")
def init_00000000_0000_0000_0000_000048444350_ta_31(state):
    _setup_hdcp_cmd(state, 0xcf)  # TZ_AKE_Send_h_prime_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_33")
def init_00000000_0000_0000_0000_000048444350_ta_32(state):
    _setup_hdcp_cmd(state, 0xd0)  # TZ_AKE_Send_Pairing_Info_R
    return state


@ta_chain_target(next_func="init_00000000_0000_0000_0000_000048444350_ta_34")
def init_00000000_0000_0000_0000_000048444350_ta_33(state):
    _setup_hdcp_cmd(state, 0xd1)  # TZ_LC_Init_R
    return state


@ta_chain_target
def init_00000000_0000_0000_0000_000048444350_ta_34(state):
    _setup_hdcp_cmd(state, 0xd2)  # TZ_LC_Send_L_prime_R
    return state


# --- Receiver standalone commands ---

@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_35(state):
    _setup_hdcp_cmd(state, 0xd3)  # TZ_SKE_Send_Eks_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_36(state):
    _setup_hdcp_cmd(state, 0xd4)  # TZ_RepeaterAuth_Send_ReceiverId_List_Rep
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_37(state):
    _setup_hdcp_cmd(state, 0xd5)  # TZ_RTT_READY_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_38(state):
    _setup_hdcp_cmd(state, 0xd6)  # TZ_RTT_CHALLENGE_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_39(state):
    _setup_hdcp_cmd(state, 0xd7)  # TZ_RepeaterAuth_Send_Ack_Rep
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_40(state):
    _setup_hdcp_cmd(state, 0xd8)  # TZ_RepeaterAuth_Stream_Manage_Rep
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_41(state):
    _setup_hdcp_cmd(state, 0xd9)  # TZ_RepeaterAuth_Stream_Ready_Rep
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_42(state):
    _setup_hdcp_cmd(state, 0xda)  # TZ_Receiver_AuthStatus_Rep
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_43(state):
    _setup_hdcp_cmd(state, 0xdb)  # TZ_AKE_Transmitter_Info_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_44(state):
    _setup_hdcp_cmd(state, 0xdc)  # TZ_AKE_Receiver_Info_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_45(state):
    _setup_hdcp_cmd(state, 0xde)  # TZ_DEC_Data
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_46(state):
    _setup_hdcp_cmd(state, 0xe2)  # TZ_SPSPPS_COPY
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_47(state):
    _setup_hdcp_cmd(state, 0xe3)  # TZ_SET_HDCP_VERSION_R
    return state


@ta_init_function
def init_00000000_0000_0000_0000_000048444350_ta_48(state):
    _setup_hdcp_cmd(state, 0xe7)  # TZ_HW_Close_R
    return state


# --- Key-wrap / load-key receiver commands (jump-table tail @ 0x1380+) ---
# 0xfb -> TZ_HDCP2_WRAPKEY(cmd+56, ...); 0xfc -> TZ_HDCP2_LOADKEY_R(cmd+56, ...)

@ta_init_function(next_func="init_00000000_0000_0000_0000_000048444350_ta_50")
def init_00000000_0000_0000_0000_000048444350_ta_49(state):
    _setup_hdcp_cmd(state, 0xfb)  # TZ_HDCP2_WRAPKEY
    return state


@ta_chain_target
def init_00000000_0000_0000_0000_000048444350_ta_50(state):
    _setup_hdcp_cmd(state, 0xfc)  # TZ_HDCP2_LOADKEY_R
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_000048444350_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
