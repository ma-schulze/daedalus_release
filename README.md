# DAEDALUS

**DAEDALUS: Symbolic Execution for Arm TrustZone Trusted Applications**

DAEDALUS is a symbolic-execution framework for Arm TrustZone Trusted Applications (TAs),
built on top of the [angr](https://github.com/angr/angr) binary-analysis engine. It is the
first framework that applies symbolic execution to detect previously unknown software
vulnerabilities (and their trigger conditions) in closed-source TrustZone TAs.

This repository contains the source code and research artifact for the paper
*"DAEDALUS: Symbolic Execution for Arm TrustZone Trusted Applications"*, accepted at
**IEEE Symposium on Security and Privacy (S&P) 2027**.

> **Artifact evaluation:** reviewers should follow the step-by-step functional-evaluation
> instructions in [`SP_AE_README.md`](SP_AE_README.md).

## Overview

DAEDALUS analyzes a TA in three stages (see the paper, Figure 2):

1. **Preprocessing (LLM).** DAEDALUS extracts disassembly around
   `TA_InvokeCommandEntryPoint` and queries an LLM to produce *init functions* that
   implement two novel techniques:
   - **LLM-constrained inputs** — partially concretized inputs that delay state-space
     explosion caused by complex/structured input formats, and inputs that isolate each
     semantically distinct TA command so it can be explored in a separate parallel run.
   - **Smart reentries** — a command-dependency graph encoding the TA's internal state
     machine, so that stateful TAs are re-entered with the correct preconditions met.
2. **Symbolic exploration (angr + TA extensions).** The TA is loaded into angr together
   with the generated init functions and analyzed inside a symbolic TrustZone runtime:
   a GlobalPlatform-compliant syscall interface, a high-level-emulation (HLE) layer for
   library functions, a TrustZone-aware memory model (Secure vs. Normal World, taint
   tracking), and bug-detection plugins.
3. **Reporting.** Findings (coverage, bugs, unsupported syscalls/libraries) are written
   as HTML + JSON reports and served through a small web viewer. Parallel runs can be
   merged into a single report.

## Repository layout

| Path | Purpose |
|------|---------|
| `main.py` | CLI entry point for a single analysis run |
| `setup_venv.sh` | Creates the virtual environment and installs dependencies |
| `requirements.txt` | Python dependencies |
| `explorer/` | Core engine (see below) |
| `preprocessing/` | Offline LLM tooling that generates `init_*.py` files (LLM-constrained inputs + smart reentries) |
| `reporting/` | Report generation, merging, and the web viewer |
| `test_apps/` | Per-platform TA init functions (`init_<uuid>.py`) and batch run scripts |
| `test_binaries/` | TA binaries used for evaluation, plus the vendored TÄMU fork |
| `dependencies/` | Vendored dependencies (`angr-targets`) |
| `reports/` | Generated reports (git-ignored) |
| `utils/` | Logging configuration and shared helpers |

### `explorer/`

| Path | Purpose |
|------|---------|
| `explorer.py` | Orchestrates loading, initialization, exploration, and reporting |
| `ta_init_function.py` | `@ta_init_function` / `@ta_chain_target` decorators and the init-function registry |
| `exploration_techniques/` | angr exploration techniques: filtering, statistics, per-step timeout, DFS/unique search, reentry |
| `hooks/os_hooks/` | Trusted-OS SVC emulation (e.g. OP-TEE) |
| `hooks/function_hooks/` | Function/library hook providers (`gp`, `libc`, `mitee`, `beanpod`, `teegris`, `t6`, `tc`) |
| `memory/` | TrustZone memory model (`TAMemory`), trust/taint annotations, memory filling |
| `plugins/` | Bug-detection plugins (memory, control-flow, heap, stack, double-free) |
| `memory_monitor.py` | RSS monitoring for fixed/adaptive memory limits and graceful shutdown |
| `llm/api_keys.py` | Optional API-key storage for LLM tooling |

### `test_apps/`

Contains the LLM-generated (and, where noted, manually curated) init functions per
vendor/T-OS, together with helper scripts:

- `optee_example_apps/` — open-source OP-TEE example TAs used for the functional
  artifact evaluation (see [`SP_AE_README.md`](SP_AE_README.md)).
- `optee_apps/`, `beanpod_apps/`, `mitee_apps/`, `t6_apps/`, `teegris_apps/`, `tc_apps/`,
  `jetson_apps/`, `ms-ftpm/` — init functions for the evaluated datasets. The `*_other`
  folders hold additional/auxiliary init functions.
- `utils.py` — helpers to place symbolic value/value and buffer/size (`memref`)
  parameters and to set up the GP parameter array.
- `run_init_funcs.sh` — launches one analysis process per init function in a hooks file
  (parallel runs used for LLM-constrained inputs / smart reentries).

### `test_binaries/`

TA binaries used throughout the evaluation, plus per-dataset `bbs/` folders that hold
reachable-basic-block CFG files in the TÄMU format (used with `--cfg-path` for coverage
tracking).

- `optee_examples/` — open-source OP-TEE example TAs (source-available; used by the AE).
- `optee_tas/`, `ftpm/`, `nvidia/` — additional open-source targets (OP-TEE, Microsoft
  fTPM reference, and NVIDIA Jetson TAs).
- `taemu/` — the **modified TÄMU** high-level-emulation framework we build upon
  (see below).

### `test_binaries/taemu/` — vendored TÄMU fork

DAEDALUS reuses and extends [TÄMU](https://arxiv.org/abs/2601.20507), the
state-of-the-art GlobalPlatform-API-layer TA emulator/fuzzer, as its baseline and as a
source of supporting tooling. This is a modified version that we use for:

- **The TA datasets** used for the coverage comparison (`beanpod/`, `mitee/`, `t6/`,
  `teegris/`, `trustedcore/`
- **Ghidra plugins** (`ghidra/`) that we extended to compute the number of reachable
  basic blocks per TA, producing the CFG/basic-block files consumed by DAEDALUS via
  `--cfg-path`.
- **The HLE reference** (`emulator/`) — the qiling-based emulation environment and the
  AFL++ fuzzing setup that TÄMU uses; DAEDALUS reimplements the relevant HLE hooks inside
  `explorer/hooks/`.

See `test_binaries/taemu/README.md` for TÄMU's own build/run instructions (Docker-based).

## Requirements

`angr-targets` (vendored under `dependencies/`).

## Setup

```bash
./setup_venv.sh
source venv/bin/activate
```

`setup_venv.sh` creates `./venv`, installs `requirements.txt`, and installs the vendored
`dependencies/angr-targets/`.

## Quick start

Analyze a TA binary (`.elf` or `.ta`):

```bash
source venv/bin/activate
python3 main.py path/to/ta.elf --tos optee
```

On interrupt (Ctrl+C), on graceful shutdown (SIGTERM), or when a memory limit is reached,
an HTML + JSON report is written under `reports/`. (JSON is also persisted incrementally
during the run, so partial results survive a hard kill.)

View reports in a browser:

```bash
source venv/bin/activate
python3 reporting/serve_reports.py
```

Open `http://localhost:8081`.

**Typical OP-TEE run with LLM-generated init functions:**

```bash
python3 main.py test_binaries/optee_examples/<uuid>.elf \
  --tos optee \
  --hooks test_apps/optee_example_apps/init_<uuid>.py \
  --invoke-command-symbolic-inputs-func init_<uuid>_0 \
  --func-hook-providers gp
```

## Command-line options

| Argument | Default | Description |
|----------|---------|-------------|
| `filename` | — | Path to the TA binary to analyze |
| `--input-format` | `ta` | Input format: `ta` or `bin` |
| `--tos` | `None` | Trusted OS for SVC emulation (use `optee` for standard GP TAs) |
| `--hooks` | `None` | Python file loaded at startup (init functions, custom hooks) |
| `--open-session-symbolic-inputs-func` | `None` | Function in the hooks file for `TA_OpenSession` input setup |
| `--invoke-command-symbolic-inputs-func` | `None` | Function in the hooks file for `TA_InvokeCommand` input setup (also used as the report `run_id`) |
| `--func-hook-providers` | `gp` | Comma-separated function-hook providers (see below) |
| `--cfg-path` | `None` | External basic-block CFG (TÄMU format) for coverage tracking |
| `--enable-dfs` / `--no-enable-dfs` | `True` | Enable path-prioritization via angr `UniqueSearch` |
| `--enable-reentry` / `--no-enable-reentry` | `True` | Re-enter `TA_InvokeCommandEntryPoint` after normal exit |
| `--reentry-count` | `5` | Maximum number of reentries per path |
| `--enable-threading` / `--no-enable-threading` | `False` | Multi-threaded exploration (60 workers) |
| `--enable-veritesting` / `--no-enable-veritesting` | `False` | angr veritesting (path merging) |
| `--enable-step-timeout` / `--no-enable-step-timeout` | `True` | Per-step timeout via `SIGALRM` |
| `--step-timeout` | `120` | Timeout in seconds per exploration step |
| `--use-svc-hooks` / `--no-use-svc-hooks` | `True` | Install Trusted OS SVC hooks at syscall sites |
| `--enable-plugins` / `--no-enable-plugins` | `True` | Enable bug-detection plugins |
| `--enable-memory-model` / `--no-enable-memory-model` | `True` | Use the custom TrustZone memory model |
| `--memory-limit-gb` | `None` | Fixed RSS limit; triggers graceful shutdown and report |
| `--memory-adaptive` | `False` | Share a memory pool across parallel processes |
| `--memory-total-gb` | `None` | Total pool for adaptive mode (default: 90% of system RAM) |
| `--memory-min-gb` | `5.0` | Minimum per-process limit in adaptive mode |
| `--memory-max-gb` | `None` | Maximum per-process limit in adaptive mode |
| `--memory-check-interval` | `5.0` | Memory polling interval (seconds) |
| `--memory-threshold-percent` | `0.95` | Shutdown when this fraction of the limit is reached |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `--log-file` | `None` | Optional log file (in addition to stdout) |

## Hooks and TA initialization

The `--hooks` file is imported as a Python module. Decorators register hooks and
initialization functions at import time.

### `@ta_init_function` — invoke-command setup

Each decorated function receives an angr `SimState` at `TA_InvokeCommandEntryPoint`, sets
up registers and the GP parameter array `p3`, and returns the state. When passed to
`--invoke-command-symbolic-inputs-func`, the function name becomes the report `run_id`,
which keeps parallel runs of the same TA separate.

Use `next_func` / `next_funcs` to chain commands for stateful TAs (handled by
`TA_Reentry`). Mark successors that must not be used as random entry points with
`@ta_chain_target`.

```python
from test_apps.utils import init_params, place_sym_memref_param, place_sym_value_param
from explorer.ta_init_function import ta_init_function, ta_chain_target

@ta_init_function
def init_my_ta_0(state):
    p3 = init_params(state)
    place_sym_value_param(state, p3, 0)
    place_sym_value_param(state, p3, 1)
    place_sym_value_param(state, p3, 2)
    place_sym_value_param(state, p3, 3)
    return state
```

### `@ta_function_hook` — replace TA/library functions

```python
from angr import SimProcedure
from explorer.hooks.function_hooks.func_hooks import ta_function_hook

@ta_function_hook("MyHelper", "gp")
class MyHelperHook(SimProcedure):
    def run(self, arg0):
        return 0
```

### `@os_hook` — custom Trusted OS

```python
from angr import SimProcedure
from explorer.hooks.os_hooks import os_hook

@os_hook("my_os")
class MyOSHooks(SimProcedure):
    def run(self, _argc, _argv):
        syscall = self.state.solver.eval(self.state.regs.x8)
        ...
        return 0
```

Run with `--tos my_os`. Built-in OS emulation: **OP-TEE** (`optee`).

### Function hook providers

Select providers with `--func-hook-providers` (comma-separated). Built-in providers:

| Provider | Typical use |
|----------|-------------|
| `gp` | GlobalPlatform TEE Internal Core API (`TEE_*`) |
| `libc` | Standard C library (always installed when matched) |
| `mitee` | Xiaomi MiTEE-specific helpers |
| `beanpod` | Beanpod platform helpers |
| `teegris` | Samsung TEEGRIS helpers |
| `t6` | Trustonic T6 helpers |
| `tc` | TrustedCore helpers |

Additional hooks (e.g. fTPM) can be defined in the hooks file with
`@ta_function_hook(..., "ftpm")`.

## Optional: LLM-assisted init-function generation

`preprocessing/llm_ta_init_prompt.py` generates `init_*.py` files by sending disassembly
around `TA_InvokeCommandEntryPoint` to an LLM (Anthropic API via
`preprocessing/llm_connection.py`). This is **offline tooling** for bootstrapping init
functions; it is not used during the symbolic-execution runtime. It requires the
`ANTHROPIC_API_KEY` environment variable to be set.

```bash
export ANTHROPIC_API_KEY=...   # required only for regenerating init functions
python3 -m preprocessing.llm_ta_init_prompt path/to/ta.elf \
  --entry 0x1234 \
  --call-depth 2 \
  -o test_apps/optee_example_apps/init_<uuid>.py
```

Pre-generated init functions are already checked in under `test_apps/`, so running the
analysis does **not** require an API key.

## Internals

### Trusted OS emulation

When `--use-svc-hooks` is enabled, SVC instructions in the TA are hooked and dispatched to
the OS handler selected by `--tos`. OP-TEE emulation covers session management, crypto,
storage, and PTA system calls. Syscall return values are modeled symbolically where
needed; syscall statistics are included in reports.

### Exploration techniques

| Technique | When | Role |
|-----------|------|------|
| `TA_Filter` | Always | Drop panicked, sys-return, and over-depth states |
| `TA_Statistics` | Always | Coverage and exploration metrics for the report |
| `TA_Timeout` | Default on | Abort steps that exceed `--step-timeout` |
| `UniqueSearch` | `--enable-dfs` (default) | Prefer states that reach new basic blocks |
| `TA_Reentry` | Default on | After normal invoke exit, re-enter with new symbolic inputs (respecting `@ta_init_function` chains) |
| `Threading` | Optional | 60-worker threaded stepping |
| `Veritesting` | Optional | Solver-based path merging |

### Memory model

`TAMemory` tracks Secure World vs. Normal World accesses and annotates data with
trust/taint metadata (`TA_Trusted_Annotation`, `TA_Taint_Annotation`). Trusted regions
include the TA image, heap, and stack. Memory events (`sw_mem_*`, `nw_mem_*`,
`heap_alloc`, `heap_free`, …) drive the plugins.

### Plugins

All plugins register via `@ta_plugin` and hook memory/control-flow events:

| Plugin | Detects |
|--------|---------|
| `TA_MemSanPlugin` | Tainted addresses in SW memory; untrusted data used as pointers (boomerang / arbitrary read-write) |
| `TA_CFSanPlugin` | Jumps outside TA memory; symbolic or tainted control flow |
| `TA_HeapSanPlugin` | Heap buffer overflows (canary regions around allocations) |
| `TA_StackSanPlugin` | Stack buffer overflows (canary regions around stack frames) |
| `TA_DoubleFreeSanPlugin` | Double-free of heap objects |

Disable all plugins with `--no-enable-plugins`.

### Memory limits

**Fixed mode** (`--memory-limit-gb`): each process has a static RSS cap.

**Adaptive mode** (`--memory-adaptive`): active processes share `--memory-total-gb`; the
per-process limit grows as jobs finish. Processes coordinate via
`/tmp/ta_explorer_processes/`.

When the threshold is hit, DAEDALUS finalizes the report and exits cleanly (SIGTERM
handler).

### Logging

Logs go to stdout at `--log-level` (default `INFO`). Use `--log-file` to mirror logs to a
file. `DEBUG` includes memory-access and exploration detail.

## Reports

Reports land in `reports/` as HTML and JSON, keyed by the analyzed binary and an optional
`run_id` (taken from `--invoke-command-symbolic-inputs-func`). The folder layout mirrors
the binary's path under the repository (e.g. `reports/others/test_binaries/.../<ta>.elf/`).

- `reporting/serve_reports.py` groups reports by TA, sorts by timestamp, and serves them
  at `http://localhost:8081` (also on `0.0.0.0` for remote access). It supports CSV export
  of a coverage/bug overview.
- `reporting/merge_reports.py` combines the parallel runs of one TA into a single merged
  report (union of covered basic blocks, aggregated bugs and syscall statistics).
- `reporting/batch_merge_test_binaries.py` runs the merge for every TA folder under
  `reports/`.

## Artifact evaluation

Reviewers evaluating this artifact should follow [`SP_AE_README.md`](SP_AE_README.md),
which walks through a minimal functional run on a single open-source OP-TEE example TA.

## License

Released under the MIT License; see [`LICENSE`](LICENSE). The vendored TÄMU fork under
`test_binaries/taemu/` and the vendored `dependencies/angr-targets/` retain their
respective upstream licenses.
