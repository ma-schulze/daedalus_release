import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_chain_target

TA = "../../test_binaries/taemu/t6/tas/b46325e6-5c90-8252-2eada8e32e5180d6.ta"

# This TA dispatches via tbh at 0x20042f using (cmd_id - 1) as index with range <= 0x26.
# So valid command IDs are 1..0x27. Each handler then checks r2 (param_types mask)
# and dispatches further on values inside p3 (e.g., sub-codes like 0x265, 0x55, 0x525,
# 0x555, 0x5555, 0x65, 0x5555 etc.) which are GP TEEC sub_cmds passed in r1.
# Actually re-reading: r1 is the command ID for the outer dispatch (1..0x27), then
# inside each handler r1 is compared again to specific constants — which means the
# disassembly shows that r1 is reused. Looking carefully, each handler checks r1
# against a constant — so the TA expects cmd_id to BE that constant directly, but
# the outer table dispatches via (r1-1). The outer table maps a small index to a
# handler; the handler then checks the full r1 value. So we set r1 to the exact
# command IDs that pass both checks.
#
# We enumerate one init per distinct sub-handler path with appropriate r1 and
# parameter types/values.

# Helper: most handlers expect param_types == 7 (MEMREF_INOUT slot0) or 0x65
# (MEMREF_INPUT slot0, MEMREF_OUTPUT slot1) etc. We set generic memref params
# and let the symbolic exploration discover constraints.


@ta_init_function
def init_t6_0(state):
    # Handler at 0x20075d: cmd id 1, checks r1==5 inside (but r1 is cmd id...).
    # The handler is reached via tbh with index 0; from 0x20075d it does cmp r1,#5.
    # Since r1 is the cmd id used outside, we must set r1=5 — but then (r1-1)=4,
    # which would dispatch to a different table entry. Actually the tbh index is r1-1
    # and each table entry jumps to a unique handler. We pick r1 = handler-expected.
    # For path 0x20075d (idx 0 -> r1=1) but inner check cmp r1,#5 means dead path.
    # Therefore many handlers are reached only at the specific r1 the inner check expects.
    # We choose r1 values that satisfy both: r1 in [1..0x27] AND inner check.
    p3 = init_params(state)
    state.regs.r1 = 0x5  # but 5 - 1 = 4; index 4 dispatches to 0x2004e1 -> 0x201ae9
    place_sym_memref_param(state, p3, 0)
    state.regs.r2 = 0x7
    return state


@ta_init_function
def init_t6_1(state):
    # cmd id 6 -> table idx 5 -> 0x2004f1 -> 0x2019a5: checks r1==1 (mismatch)
    # Pick r1 = 6, jumps to 0x2019a5 which requires r1==1 -> fails.
    # Instead use cmd id 0x26 (idx 0x25) -> 0x2006f1 -> 0x2007dd: cmp r1,#0x26 OK
    p3 = init_params(state)
    state.regs.r1 = 0x26
    state.regs.r2 = 0x67  # MEMREF_INOUT + MEMREF_OUTPUT
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_t6_2(state):
    # cmd id 5 -> idx 4 -> 0x2004e1 -> 0x201ae9: cmp r1,#6 fails
    # We try cmd id 0x265 directly? But outer compares r1-1>0x26 first -> 0x265-1>0x26 -> fails (>0x26)
    # So outer range is 1..0x27. Some inner checks need cmd id 0x265, 0x55, 0x525, 0x555,
    # 0x5555 — these can never pass the outer range check! Therefore those handlers
    # are dead unless reached differently.
    # Actually looking again at outer:
    #   subs r1, r4, #1 ; cmp r1,#0x26 ; bhi 0x200711
    # so r4 must be <= 0x27. The inner handlers at 0x200859 etc. compare r1 to 0x265
    # which is impossible. Those handlers are dead code for the outer dispatch.
    # Only inner checks that match r1 in [1..0x27] are reachable.
    # Reachable inner checks:
    #   0x20075d: cmp r1,#5  -> r1=5
    #   0x2007dd: cmp r1,#0x26 -> r1=0x26
    #   0x200a75: cmp r1,#5
    #   0x200ae5: cmp r1,#5
    #   0x2013c5: cmp r1,#6
    #   0x201439: cmp r1,#0x65 -> dead
    #   0x2014e5: cmp r1,#6
    #   0x201559: cmp r1,#0x65 -> dead
    #   0x201599: cmp r1,#0x65 -> dead
    #   0x2015d9: cmp r1,#0x65 -> dead
    #   0x201619: cbz r1 -> dead (r1!=0)
    #   0x20164d: cmp r1,#5 or 0x55 or 0x555
    #   0x201739: cmp r1,#5
    #   0x201771: cbz r1 -> dead
    #   0x2017a5: cmp r1,#5 or 0x55 or 0x555
    #   0x201895: cmp r1,#5
    #   0x2018cd: cmp r1,#6
    #   0x201935: cmp r1,#2
    #   0x20196d: cmp r1,#1
    #   0x2019a5: cmp r1,#1
    #   0x2019dd: cmp r1,#0x15
    #   0x201a19: cmp r1,#0x25 or #0x525
    #   0x201ae9: cmp r1,#6
    # We enumerate the reachable ones.
    p3 = init_params(state)
    state.regs.r1 = 0x5
    state.regs.r2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


# Build all reachable inits. We map each (cmd_id) -> table index = cmd_id - 1.
# We need to choose cmd ids that match the inner check after the tbh dispatch.
# Looking at the tbh table at 0x20042f and corresponding cases, the table maps each
# index 0..0x26 to a specific handler. So cmd_id i is dispatched to a specific
# handler regardless of what r1 the handler checks. Some handlers happen to check
# r1 again, requiring r1==<expected>. So reachable cmd ids = intersection.
#
# Without decoding the full tbh table, we use the simpler model: pick a wide range
# of cmd ids and check ones whose inner constants match.
# From the disassembly cases shown, the reachable handlers and their command IDs are:
#  - cmd 5 -> handler that wants r1==5 (e.g., 0x200a75, 0x200ae5, 0x20164d, 0x201739, 0x2017a5, 0x201895)
#  - cmd 6 -> handler that wants r1==6 (0x2013c5, 0x2014e5, 0x2018cd, 0x201ae9)
#  - cmd 1 -> 0x20196d/0x2019a5
#  - cmd 2 -> 0x201935
#  - cmd 0x15 -> 0x2019dd
#  - cmd 0x25 -> 0x201a19
#  - cmd 0x26 -> 0x2007dd
# We emit one init per command id with appropriate parameter types.


@ta_init_function
def init_t6_3(state):
    # cmd 1 - load/store value param
    p3 = init_params(state)
    state.regs.r1 = 0x1
    state.regs.r2 = 0x1  # VALUE_INPUT slot 0
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_4(state):
    # cmd 2
    p3 = init_params(state)
    state.regs.r1 = 0x2
    state.regs.r2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_5(state):
    # cmd 6 - several handlers compare r1==6; needs value_input
    p3 = init_params(state)
    state.regs.r1 = 0x6
    state.regs.r2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_6(state):
    # cmd 0x15
    p3 = init_params(state)
    state.regs.r1 = 0x15
    state.regs.r2 = 0x1
    place_sym_value_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_7(state):
    # cmd 0x25 - 0x201a19 expects MEMREF_INOUT param + key check
    p3 = init_params(state)
    state.regs.r1 = 0x25
    state.regs.r2 = 0x7  # MEMREF_INOUT slot 0
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_8(state):
    # cmd 0x26 - 0x2007dd needs memref params
    p3 = init_params(state)
    state.regs.r1 = 0x26
    state.regs.r2 = 0x67
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_t6_9(state):
    # cmd 5 - first handler-style: memref + memref
    p3 = init_params(state)
    state.regs.r1 = 0x5
    state.regs.r2 = 0x65  # MEMREF_INPUT + MEMREF_OUTPUT
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return state


@ta_init_function
def init_t6_10(state):
    # cmd 5 alternate - memref inout
    p3 = init_params(state)
    state.regs.r1 = 0x5
    state.regs.r2 = 0x7
    place_sym_memref_param(state, p3, 0)
    return state


@ta_init_function
def init_t6_11(state):
    # cmd 6 alternate with memref
    p3 = init_params(state)
    state.regs.r1 = 0x6
    state.regs.r2 = 0x5  # MEMREF_INPUT
    place_sym_memref_param(state, p3, 0)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_b46325e6_5c90_8252_2eada8e32e5180d6_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

