# Daedalus

Daedalus is a symbolic-execution framework for Arm TrustZone Trusted Applications (TAs) built upon [angr](https://github.com/angr/angr).

## Requirements

`angr-targets` (vendored under `dependencies/`) depends on packages that are not available on Python 3.12+. Use **Python 3.11 or earlier**.

## Setup

```bash
./setup_venv.sh
source venv/bin/activate
```

## Quick start

Analyze a TA binary (`.elf` or `.ta`):

```bash
source venv/bin/activate
python3 main.py path/to/ta.elf --tos optee
```

On interrupt (Ctrl+C) or graceful shutdown, an HTML report is written under `reports/`.

View reports in a browser:

```bash
source venv/bin/activate
python3 reporting/serve_reports.py
```

Open `http://localhost:8080`.

## Repository layout

| Path | Purpose |
|------|---------|
| `main.py` | CLI entry point |
| `explorer/` | Core engine: exploration techniques, OS/function hooks, memory model, plugins |
| `test_apps/` | Per-platform TA init functions (`init_<uuid>.py`) and batch run scripts |
| `preprocessing/` | Tooling to preprocess TAs with an LLM to generate init functions implementing LLM-constrained inputs and smart reentries |
| `reporting/` | Report generation, merging, and the web viewer |


## Command-line options

| Argument | Default | Description |
|----------|---------|-------------|
| `filename` | — | Path to the TA binary to analyze |
| `--input-format` | `ta` | Input format: `ta` or `bin` |
| `--tos` | `None` | Trusted OS for SVC emulation (use `optee` for standard GP TAs) |
| `--hooks` | `None` | Python file loaded at startup (init functions, custom hooks) |
| `--open-session-symbolic-inputs-func` | `None` | Function in the hooks file for `TA_OpenSession` input setup |
| `--invoke-command-symbolic-inputs-func` | `None` | Function in the hooks file for `TA_InvokeCommand` input setup |
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

**Typical OP-TEE run with custom inputs:**

```bash
python3 main.py test_binaries/optee_tas/example.elf \
  --tos optee \
  --hooks test_apps/optee_apps/init_<uuid>.py \
  --invoke-command-symbolic-inputs-func init_<uuid>_value_pairs \
  --func-hook-providers gp
```


## Hooks and TA initialization

The `--hooks` file is imported as a Python module. Decorators register hooks and initialization functions at import time.

### `@ta_init_function` — invoke-command setup

Each decorated function receives an angr `SimState` at `TA_InvokeCommandEntryPoint`, sets up registers and the GP parameter array `p3`, and returns the state.

Use `next_func` / `next_funcs` to chain commands for stateful TAs (handled by `TA_Reentry`). Mark successors that must not be used as random entry points with `@ta_chain_target`.

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

Additional hooks (e.g. fTPM) can be defined in the hooks file with `@ta_function_hook(..., "ftpm")`.


## Optional: LLM-assisted init function generation for Smart Reentries and LLM-constrained inputs

`preprocessing/llm_ta_init_prompt.py` can generate `init_*.py` files by sending disassembly around `TA_InvokeCommandEntryPoint` to an LLM (Anthropic API via `preprocessing/llm_connection.py`). This is **offline tooling** for bootstrapping init functions; it is not used during the symbolic execution runtime.

```bash
python3 -m preprocessing.llm_ta_init_prompt path/to/ta.elf \
  --entry 0x1234 \
  -o test_apps/optee_apps/init_<uuid>.py
```

## Internals

### Trusted OS emulation

When `--use-svc-hooks` is enabled, SVC instructions in the TA are hooked and dispatched to the OS handler selected by `--tos`. OP-TEE emulation covers session management, crypto, storage, and PTA system calls. Syscall return values are modeled symbolically where needed; syscall statistics are included in reports.

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

`TAMemory` tracks Secure World vs Normal World accesses and annotates data with trust/taint metadata (`TA_Trusted_Annotation`, `TA_Taint_Annotation`). Trusted regions include the TA image, heap, and stack. Memory events (`sw_mem_*`, `nw_mem_*`, `heap_alloc`, `heap_free`, …) drive the plugins.


### Plugins

All plugins register via `@ta_plugin` and hook memory/control-flow events:

| Plugin | Detects |
|--------|---------|
| `TA_MemSanPlugin` | Tainted addresses in SW memory; untrusted data in NW memory |
| `TA_CFSanPlugin` | Jumps outside TA memory; symbolic or tainted control flow |
| `TA_HeapSanPlugin` | Heap buffer overflows (canary regions around allocations) |
| `TA_StackSanPlugin` | Stack buffer overflows (canary regions around stack frames) |
| `TA_DoubleFreeSanPlugin` | Double-free of heap objects |

Disable all plugins with `--no-enable-plugins`.

### Memory limits

**Fixed mode** (`--memory-limit-gb`): each process has a static RSS cap.

**Adaptive mode** (`--memory-adaptive`): active processes share `--memory-total-gb`; the per-process limit grows as jobs finish. Processes coordinate via `/tmp/ta_explorer_processes/`.

When the threshold is hit, Daedalus finalizes the HTML report and exits cleanly (SIGTERM handler).

### Logging

Logs go to stdout at `--log-level` (default `INFO`). Use `--log-file` to mirror logs to a file. `DEBUG` includes memory-access and exploration detail.

## Reports

Reports land in `reports/` as HTML and JSON, keyed by binary name and optional `run_id` (from `--invoke-command-symbolic-inputs-func`). `reporting/merge_reports.py` can combine parallel runs. `reporting/serve_reports.py` groups reports by TA and sorts by timestamp.
