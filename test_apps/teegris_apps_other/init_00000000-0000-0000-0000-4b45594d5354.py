import angr
import claripy
from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
from explorer.ta_init_function import ta_init_function, ta_init_function
from explorer.memory.ta_taint import get_tainted_mem_bits

# Analysis of the TA (KEYMSTR - KeyMaster TA):
#
# The InvokeCommandEntryPoint reads a command struct from p3[0] (memref input).
# At offset 0x50 (sp) the buffer is copied. The first word at offset 0x50 is read as
# command discriminator (w8 = cmd_id), then:
#   - cmp w8, #6: if > 6 -> different branch
#   - tst against 0x63 mask (bits 0,1,5,6) -> values 0,1,5,6 take one path
#   - if cmd == 4 and w21 (x2 param_types) == 0x65 -> call sub_5d710 (op 0x65 path)
#   - else if w8 == 0xF0000000 (a special tag) -> further branch:
#       - check w21 == 0x65, then call sub_5d7d8 which validates a UUID-like tag
#       - then dispatches on a sub-operation that ultimately reaches command
#         dispatcher sub_35e40 -> sub_372dc which dispatches into a function table at 0x9f610.
#
# This TA is a complex KeyMaster-like TA with many subcommands. The parameter mask
# expected is 0x65 = slot0=MEMREF_INPUT(5), slot1=MEMREF_OUTPUT(6).
#
# We provide one init per distinct "cmd_id" path (the first word in the input buffer
# at offset 0x50 after the initial memcpy). The framework will then explore each.
# Stateful: many crypto/keystore subcommands require prior init/provisioning.
# We model a couple of explicit dependency chains where evident.


def _setup_common(state):
    """Common setup: param_types=0x65, memref input slot0, memref output slot1."""
    p3 = init_params(state)
    # x1 is command ID for the GP entry but this TA does not seem to dispatch on it;
    # leave it symbolic-ish but constrain to 0 for determinism.
    state.regs.x1 = claripy.BVV(0, 64)
    # param_types mask 0x65: slot0 MEMREF_INPUT, slot1 MEMREF_OUTPUT
    state.regs.x2 = claripy.BVV(0x65, 64)
    place_sym_memref_param(state, p3, 0)
    place_sym_memref_param(state, p3, 1)
    return p3


def _write_cmd_word(state, p3, cmd_word):
    """The TA copies the first 0x10 bytes from p3[0].buffer into its stack at sp+0x50,
    then reads dword at sp+0x50 as the command discriminator. So write cmd at offset 0
    of the input buffer pointed to by p3 slot 0."""
    # p3 slot 0 memref: [ptr, size]
    word_size = state.arch.bytes
    ptr_addr = p3 + 0 * 2 * word_size
    buf_ptr = state.memory.load(ptr_addr, word_size, endness=state.arch.memory_endness)
    # Constrain size to be at least 0x20 so the memcpy reads valid data
    size_addr = ptr_addr + word_size
    state.memory.store(size_addr, claripy.BVV(0x40, word_size * 8),
                       endness=state.arch.memory_endness)
    # Write the concrete command word at buffer offset 0
    state.memory.store(buf_ptr, claripy.BVV(cmd_word, 32),
                       endness=state.arch.memory_endness)
    return buf_ptr


# --- Path 0: cmd == 0 (in low-cmd group via tst mask 0x63) ---
@ta_init_function
def init_keymstr_0(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x0)
    return state


# --- Path 1: cmd == 1 ---
@ta_init_function
def init_keymstr_1(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x1)
    return state


# --- Path 2: cmd == 5 ---
@ta_init_function
def init_keymstr_2(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x5)
    return state


# --- Path 3: cmd == 6 ---
@ta_init_function
def init_keymstr_3(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x6)
    return state


# --- Path 4: cmd == 4 with param_types == 0x65 -> sub_5d710 path (provision/init key) ---
# This is the "initial provisioning" entrypoint - other subcommands depend on it.
@ta_init_function(next_func="init_keymstr_5")
def init_keymstr_4(state):
    p3 = _setup_common(state)
    buf_ptr = _write_cmd_word(state, p3, 0x4)
    return state


# --- Path 5: cmd == 0xF0000000 (special tagged command -> sub_5d7d8 path) ---
# This is a tagged command requiring UUID-like match against a table at 0x9a4e0.
# Depends on a prior provisioning call. Marked as chain target.
@ta_init_function
def init_keymstr_5(state):
    p3 = _setup_common(state)
    buf_ptr = _write_cmd_word(state, p3, 0xF0000000)
    # The TA also reads sub-fields at offsets 4..0x10 of the buffer (UUID/tag bytes)
    # which are compared against a 32-byte table entry. Leave them symbolic so angr
    # may discover matching values, but constrain the upper bits of w20 (cmd id from r1)
    # to zero to avoid the "lsr w9, w20, #0x10; cbnz" early exit.
    state.regs.x1 = claripy.BVV(0, 64)
    return state


# --- Path 6: cmd == 2 (in low-cmd group) ---
@ta_init_function
def init_keymstr_6(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x2)
    return state


# --- Path 7: cmd == 3 ---
@ta_init_function
def init_keymstr_7(state):
    p3 = _setup_common(state)
    _write_cmd_word(state, p3, 0x3)
    return state

# Generic symbolic init: four GP VALUE_INPUT parameter slots (value.a, value.b each). Command ID and param-type mask stay symbolic.
@ta_init_function
def init_00000000_0000_0000_0000_4b45594d5354_value_pairs(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state

