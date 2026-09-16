"""
LLM prompt and helpers for generating TA InvokeCommandEntryPoint init functions.
Uses the Anthropic API (see llm_connection.py) to analyze a TA and emit Python
init functions for symbolic analysis.
"""

import argparse
import re
import sys
from pathlib import Path
from utils.logging_config import get_logger
import angr

from .llm_connection import call_llm
from utils.cfg_analyzer import generate_cfg
from utils.binary_utils import extract_function_assembly

logger = get_logger(__name__)

from elftools.elf.relocation import RelocationSection

def safe_iter_relocations(self):
    # Skip malformed relocation sections (common in static PIE TAs)
    if self['sh_size'] == 0 or self['sh_entsize'] == 0:
        return
    count = self['sh_size'] // self['sh_entsize']
    for i in range(count):
        try:
            yield self.get_relocation(i)
        except Exception:
            return

RelocationSection.iter_relocations = safe_iter_relocations


# -----------------------------------------------------------------------------
# Prompt: system + user template for TA init function generation
# -----------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert in trusted application (TA) binary analysis and symbolic execution using Angr and claripy.
Your task is to analyze a TA binary and output valid Python code that defines init functions which prepare
the initial state for symbolic analysis of its TA_InvokeCommandEntryPoint.
The goal is to achieve deep program coverage of the TA by avoiding state space explosion and being able to analyze stateful TAs.

You will be given (as user input):
- TA name (used for init function names)
- InvokeCommandEntryPoint entry address
- Parts of the TA's disassembly or source code starting at the InvokeCommandEntryPoint

The final goal consists of three parts:
1. Analyze the TA to identify the semantically different command paths and the inputs that lead to them.
2. Analyze semantic dependencies between command paths (i.e., command A only works after command B has been executed) and annotate the python code with custom decorators to indicate such dependencies.
3. Detect small inputs that lead to state space explosion and constrain them to avoid state space explosion.
4. Generate individual init functions for each command path that set the initial state of the TA to values that lead to the invocation of this path.

These initialization functions will then be used to initialize the state of the TA for symbolic analysis using Angr.

You must output ONLY Python code (imports + function definitions). No prose before/after the code, except
short inline comments inside the code when needed for uncertainty.
All code must be valid Python code and must be able to be executed by Angr and claripy.

Write static, explicit Python only. Every init function must be a top-level `def` with
`@ta_init_function` or `@ta_chain_target` applied directly at definition time. Do NOT use
exec, eval, compile, globals(), locals(), or loops/factories that create or register
functions at runtime. Do NOT build Python source strings and execute them. The framework
discovers inits via decorators at import time; dynamically generated functions are
unreliable. If many command paths exist, emit one explicit `def init_<ta_name>_<n>(state):`
per path with consecutive counters.

Furthermore, here are some insights that may help you in your task:

## TA_InvokeCommandEntryPoint ABI (ARM 32-bit: r0–r3; AArch64: x0–x3) — Global Platform TA Invoke Command
- r0/x0: session handle (opaque pointer).
- r1/x1: Command ID (integer). This is the ONLY register that carries the command ID.
- r2/x2: Parameter type mask (Global Platform TEE param types). NOT a command ID or sub-command.
- r3/x3: pointer to the parameter array p3, whose layout is described by r2/x2.

If the disassembly shows comparisons like cmp r2,#0x5733 (or x2,#0x5573), those constants are parameter
type masks expected by the TA for that path. Set r2/x2 accordingly AND set up p3 slots to match.

Do NOT put command IDs or “sub-command” values in r2/x2.

Hints:
- Some TAs are not fully GP compliant and may not use/check r1/r2.
- Sometimes the TA dispatches on a command-like value read from p3 or from a buffer pointed to by p3.
  In that case, make one init per such value and set it concretely in the correct slot/buffer.

Layout of p3 in memory (word = 4 bytes on 32-bit, 8 bytes on 64-bit):
- Slot i starts at p3 + i * (2 * word_size).
- Memref: store ptr at p3 + i*2*word_size, size at p3 + i*2*word_size + word_size.
- Value: store value_a at p3 + i*2*word_size, value_b at p3 + i*2*word_size + word_size.

## Global Platform parameter type mask encoding (CRITICAL)

The value in r2/x2 is a **parameter type mask**: it describes the *kind* of each of the
four p3 slots. It is NOT command data and NOT a concrete parameter value.

Each slot occupies one 4-bit nibble in the mask (slot 0 = bits 3:0, slot 1 = bits 7:4, …):

  slot_n_type = (param_types >> (n * 4)) & 0xF    # n = 0, 1, 2, 3

The mask is built as: TEEC_PARAM_TYPES(t0, t1, t2, t3) = t0 | (t1 << 4) | (t2 << 8) | (t3 << 12)

Global Platform type constants (type **tags**, not data to store in p3):

| Value | Constant                     | Meaning                         | p3 slot contents      | Setup helper              |
|-------|------------------------------|---------------------------------|-----------------------|---------------------------|
| 0     | TEE_PARAM_TYPE_NONE          | unused slot                     | —                     | (leave slot empty)        |
| 1     | TEE_PARAM_TYPE_VALUE_INPUT   | two integer inputs              | value.a, value.b      | place_sym_value_param     |
| 2     | TEE_PARAM_TYPE_VALUE_OUTPUT  | two integer outputs             | value.a, value.b      | place_sym_value_param     |
| 3     | TEE_PARAM_TYPE_VALUE_INOUT   | two integer in/out              | value.a, value.b      | place_sym_value_param     |
| 5     | TEE_PARAM_TYPE_MEMREF_INPUT  | shared memory buffer (input)    | buffer ptr, size      | place_sym_memref_param    |
| 6     | TEE_PARAM_TYPE_MEMREF_OUTPUT | shared memory buffer (output)   | buffer ptr, size      | place_sym_memref_param    |
| 7     | TEE_PARAM_TYPE_MEMREF_INOUT  | shared memory buffer (in/out)   | buffer ptr, size      | place_sym_memref_param    |

**IMPORTANT:** The integer 5 means MEMREF_INPUT (a shared memory buffer with pointer + size),
NOT a scalar "value" parameter and NOT the literal number 5 as slot content. Types 5–7 always
denote memory references; types 1–3 denote inline integer pairs. Value 4 is unused in GP.

When disassembly compares r2/x2 to a constant, decode it into per-slot types, set r2/x2 to
that constant, and call the matching helper for each non-NONE slot:

- param_types == 7        → slot0 = MEMREF_INOUT (7); slots 1–3 = NONE
- param_types == 0x65     → slot0 = MEMREF_INPUT (5), slot1 = MEMREF_OUTPUT (6)
- param_types == 0x61     → slot0 = VALUE_INPUT (1), slot1 = MEMREF_OUTPUT (6)
- param_types == 0x67     → slot0 = MEMREF_INOUT (7), slot1 = MEMREF_OUTPUT (6)

Some TAs check only one nibble (e.g. `w2 & 0xF == 7`); that nibble is still the GP type
tag for slot 0. Do NOT treat type constants (especially 5, 6, 7) as concrete values to
write into p3 — they tell you *what* belongs in each slot, not the slot's payload.
Also, add one init function that sets up four symbolic value parameters for the TA but keeps x2/r2 symbolic.

## Stateful TAs
Stateful TAs are TAs that have internal state that is mutated by the commands.
For example, a TA that manages may save and load a key using two different commands.
When we enter the TA using an intialization function that leads to loading a key, but the internal state of the TA does not contain a stored key, it terminates early.
With this, the actual program path is not executed and we do not get any coverage.
Therefore, we must detect such semantic dependencies between commands so that our framework can accurately simulate the needed behavior by first entering the TA with an initialization function that leads to loading a key and then entering the TA with an initialization function that leads to using the key.
For this, you must analyze the TA's dissassembly or source code to identify the different commands and their dependencies.

## State space explosion prevention
Some TAs have huge input spaces where small pieces may lead to state space explosion.
To avoid this, you must detect small parts of the input that are actually responsible for state space explosion and constrain them to avoid state space explosion.
You must detect these by analyzing the TA's dissassembly or source code.

## Output requirements

1) One init per distinct command path.
2) Naming: init_<ta_name>_<counter> where counter is 0,1,2,... (ta_name exactly as given).
3) Signature: def init_<ta_name>_<counter>(state): ...; return state
4) After init_params(state), set command selection:
   - If TA uses r1/x1: set it concrete per init (state.regs.r1 or state.regs.x1).
   - If TA dispatches from p3/buffer: set that memory value concrete per init.
5) Set up p3 slots using place_sym_memref_param / place_sym_value_param and set r2/x2 to match (or set
   it to a constant seen in comparisons against r2/x2). Decode the mask into per-slot GP types first
   (see "parameter type mask encoding" above): use place_sym_memref_param for types 5/6/7 and
   place_sym_value_param for types 1/2/3.
6) Optional (valuable): constrain small critical byte ranges (length/opcode/tag) to avoid state explosion.

Required imports in generated code:
- import angr
- import claripy (only if you use BVV for concrete bytes)
- from test_apps.utils import place_sym_memref_param, place_sym_value_param, init_params
- from explorer.ta_init_function import ta_init_function, ta_chain_target
- if using custom buffers: from explorer.memory.ta_taint import get_tainted_mem_bits

You may use ONLY the following helpers for setting up the symbolic parameters unless you define additional helpers
yourself in the generated code:

def init_params(state): ... -> Setup symbolic x0-x3 (or r0-r3) and returns the p3 buffer pointing to the parameter array
def place_sym_memref_param(state, p3, index): ... -> sets up a symbolic memref parameter at the given index in the p3 buffer
def place_sym_value_param(state, p3, index): ... -> sets up a symbolic value parameter at the given index in the p3 buffer

For any symbolic value you need (including custom buffers), use:
- explorer.memory.ta_taint.get_tainted_mem_bits(state, bits)

Do NOT use claripy.BVS. Use claripy.BVV only for concrete constants/bytes.


## Command dependencies and init-function chaining (stateful TAs)

Some TAs are stateful: command B only works after command A. 
Dervie the internal state machine of the TA that checks for such dependencies so that we can then encode such behavior in the init functions using custom decorators.

Framework behavior:
- If an init has next_func(s), reentry will spawn states for those successors after the current init function returns.
- If an init has no next_func(s), a random init may be picked.
Therefore: list as next_func(s) only those inits that are semantically valid follow-ups.

Decorator usage:
- Standalone/terminal command: @ta_init_function
- One successor: @ta_init_function(next_func="init_<ta_name>_<j>")
- Multiple successors: @ta_init_function(next_funcs=["init_<ta_name>_<j1>", ...])
- If a command must ONLY run as a successor (never as initial random entry), decorate it with @ta_chain_target.

Minimal examples (format only; adapt content to the TA):

@ta_init_function
def init_<ta_name>_0(state):
    p3 = init_params(state)
    state.regs.r1 = 0x0
    place_sym_memref_param(state, p3, 0)
    return state

@ta_init_function(next_func="init_<ta_name>_1")
def init_<ta_name>_0(state):
    p3 = init_params(state)
    state.regs.r1 = 0x01
    place_sym_memref_param(state, p3, 0)
    return state

@ta_chain_target
def init_<ta_name>_1(state):
    p3 = init_params(state)
    state.regs.r1 = 0x02
    place_sym_memref_param(state, p3, 0)
    return state

"""


USER_PROMPT_TEMPLATE = """
## Target TA

- TA name: {ta_name}
- InvokeCommandEntryPoint entry address: {entry_addr}
- TA ELF dissassembly or source code starting at the InvokeCommandEntryPoint:
{disassembly_section}
"""


# Max disassembly chars to stay under API token limit (~4 chars/token; 1M limit leaves room for system + prompt)
MAX_DISASSEMBLY_CHARS = 600_000


def build_ta_init_prompt(
    entry_addr: int,
    ta_name: str,
    disassembly_text: str | None = None,
) -> str:
    """Build the user prompt for TA init function generation."""
    disassembly_section = ""
    if disassembly_text:
        text = disassembly_text.strip()
        if len(text) > MAX_DISASSEMBLY_CHARS:
            print(f"Warning: disassembly truncated to {MAX_DISASSEMBLY_CHARS} chars (was {len(text)}) to stay under API limit.", file=sys.stderr)
            text = text[:MAX_DISASSEMBLY_CHARS] + "\n\n... [truncated for API token limit]"
        disassembly_section = "\n## Disassembly or code summary (use to infer params and command IDs)\n\n```\n" + text + "\n```\n"

    return USER_PROMPT_TEMPLATE.format(
        entry_addr=hex(entry_addr),
        ta_name=ta_name,
        disassembly_section=disassembly_section,
    ).strip()


def generate_ta_init_functions(
    entry_addr: int,
    ta_name: str,
    disassembly_text: str | None = None,
    system_prompt: str | None = None,
) -> str:
    """
    Call the LLM to generate Python init functions for the given TA.
    Returns the raw response text (expected to be Python code).
    Init functions are post-processed to be named init_<ta_name>_0, init_<ta_name>_1, ...
    """
    user_prompt = build_ta_init_prompt(entry_addr, ta_name, disassembly_text)
    code = call_llm(
        user_prompt=user_prompt,
        system_prompt=system_prompt or SYSTEM_PROMPT,
    )
    return code


def _get_callees(project: angr.Project, func) -> set[int]:
    """Return set of function addresses that are direct call targets of the given function."""
    callees = set()

    for block in func.blocks:
        try:
            for succ in block.vex.constant_jump_targets:
                if succ in project.kb.functions:
                    callees.add(succ)
        except Exception as e:
            logger.error("Failed to get callees for function %s: %s", func.name, e)
            continue

    return callees


def _functions_to_include(
    project: angr.Project, entry_addr: int, call_depth: int
) -> list[tuple[int, str]]:
    """
    BFS from the function containing entry_addr; include that function and
    callees up to call_depth levels. Returns list of (func_addr, func_name) in BFS order.
    """
    entry_func = project.kb.functions.floor_func(entry_addr)
    if entry_func is None:
        return []
    result: list[tuple[int, str]] = [
        (entry_func.addr, entry_func.name or f"sub_{entry_func.addr:x}")
    ]
    seen: set[int] = {entry_func.addr}
    frontier: list[int] = [entry_func.addr]

    for _ in range(call_depth):
        next_frontier: list[int] = []
        for func_addr in frontier:
            func = project.kb.functions.get(func_addr)
            if func is None:
                continue
            for callee_addr in _get_callees(project, func):
                if callee_addr not in seen:
                    seen.add(callee_addr)
                    next_frontier.append(callee_addr)
                    cf = project.kb.functions.get(callee_addr)
                    name = cf.name if cf else f"sub_{callee_addr:x}"
                    result.append((callee_addr, name))
                    logger.info("Added callee %s (%s) to result", name, hex(callee_addr))

        frontier = next_frontier
        if not frontier:
            break
    return result


def _disassemble_function_to_text(project: angr.Project, func_addr: int, func_name: str) -> str:
    """Format one function's disassembly as text (objdump-like: address, bytes, mnemonic op_str)."""
    data = extract_function_assembly(project, func_addr, mem_base=0)
    logger.info("Disassembled function %s (%s): %s", func_name, hex(func_addr), data)
    if not data or "instructions" not in data:
        return ""
    lines: list[str] = []
    lines.append(f"  {hex(func_addr)} <{func_name}>:")
    for insn in data["instructions"]:
        addr = insn.get("address", "0")
        full = insn.get("full_insn", insn.get("mnemonic", "") + " " + insn.get("op_str", ""))
        lines.append(f"  {addr}:\t{full}")
    return "\n".join(lines)


def generate_disassembly(
    ta_elf_path: str,
    entry_addr: int,
    call_depth: int = 2,
) -> str:
    """
    Load the TA with angr, build a CFG, then extract disassembly only for
    InvokeCommandEntryPoint and its callees up to call_depth levels (1 = entry + direct
    callees, 2 = entry + two levels). Uses the same CFG and disassembly approach as
    the rest of the project (utils.cfg_analyzer, utils.binary_utils).
    Returns disassembly text, or empty string on failure.
    """
    path = Path(ta_elf_path)
    if not path.is_file():
        logger.error("TA file does not exist")
        return ""

    try:
        project = angr.Project(
            str(path),
            load_options={"main_opts": {"base_addr": 0}},
            auto_load_libs=False,
            use_sim_procedures=True,
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        logger.error("Failed to load TA: %s", e)
        return ""

    cfg = None
    try:
         logger.info("Generating CFGEmulated... for entry address %s with call depth %d", hex(entry_addr), call_depth+1)
         cfg = project.analyses.CFGEmulated(starts=[entry_addr], call_depth=call_depth+1, 
             max_steps=25000, resolve_indirect_jumps=True, context_sensitivity_level=1, normalize=True)
         if cfg is None or not getattr(project.kb, "functions", None):
             logger.error("Failed to generate CFG")
             return ""
    except Exception as e:
         import traceback
         traceback.print_exc()
         logger.error("Failed to generate CFG: %s", e)
         logger.error("Trying fast CFG generation...")
        
    if cfg is None:
        try:
            cfg = project.analyses.CFGFast(
                     force_complete_scan=False,
                     resolve_indirect_jumps=True,
                     symbols=True,
                     data_references=True,
                     normalize=True)
        except Exception as e:
            logger.error("Failed to generate CFG: %s", e)
            return ""

    logger.info("Generated CFG")

    funcs = _functions_to_include(project, entry_addr, call_depth)
    if not funcs:
        logger.error("Failed to decide which functions to include")
        return ""

    logger.info("Decided which functions to include: %s", funcs)

    parts: list[str] = []
    for func_addr, func_name in funcs:
        part = _disassemble_function_to_text(project, func_addr, func_name)
        if part:
            parts.append(part)

    logger.info("Disassembled functions")

    return "\n\n".join(parts).strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate TA init functions via LLM: disassemble TA, call Gemini, write Python to file.",
    )
    parser.add_argument(
        "ta_elf",
        metavar="TA_ELF",
        help="Path to the TA ELF file",
    )
    parser.add_argument(
        "--entry",
        required=True,
        metavar="ADDR",
        help="InvokeCommandEntryPoint entry address (hex, e.g. 0x287cf4)",
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        metavar="FILE",
        help="Output file path for the generated Python code",
    )
    parser.add_argument(
        "--no-disasm",
        action="store_true",
        help="Do not run angr CFG; send no disassembly to the LLM",
    )
    parser.add_argument(
        "--call-depth",
        type=int,
        default=2,
        choices=(1, 2, 3,4),
        metavar="N",
        help="CFG call depth: 1 = entry + direct callees, 2 = + callees of callees (default: 2)",
    )
    args = parser.parse_args()

    def parse_hex(s: str) -> int:
        s = s.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s, 16)

    entry_addr = parse_hex(args.entry)
    ta_elf_path = str(Path(args.ta_elf).resolve())
    # TA name for init function names: stem of path, hyphens -> underscores (valid Python identifier)
    ta_name = Path(args.ta_elf)
    out_path = Path(args.output)

    disassembly_text: str | None = None
    if not args.no_disasm:
        disassembly_text = generate_disassembly(
            ta_elf_path, entry_addr, call_depth=args.call_depth
        )
        if not disassembly_text:
            print(f"Warning: no disassembly produced (angr CFG or extraction failed) for TA {ta_name}; aborting...", file=sys.stderr)
            return 

    print("Calling LLM...", file=sys.stderr)
    code = generate_ta_init_functions(
        entry_addr=entry_addr,
        ta_name=ta_name,
        disassembly_text=disassembly_text or None,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(code, encoding="utf-8")
    print(f"Wrote {len(code)} bytes to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
