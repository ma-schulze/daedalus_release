# DAEDALUS — Artifact Evaluation (IEEE S&P 2027)

This document describes how to functionally evaluate the DAEDALUS artifact.

We are applying for the **Available** and **Functional** badges.

## Scope of this evaluation

The evaluation in the paper was performed on a high-performance computing (HPC) cluster
(nodes with 2× AMD EPYC 7502 CPUs and 512 GB RAM), analyzing 75 TAs with a 24-hour /
512 GB budget per run. We sadly cannot provide reviewers with access to that cluster, so we
target the **Functional** badge only: the goal is to demonstrate that DAEDALUS builds,
runs end-to-end, and produces the expected artifacts (coverage reports, potential bug findings, and
merged reports) on a single, open-source, source-available TA.

Reproducing the full paper-scale coverage numbers is **out of scope** for this evaluation
(it requires the HPC budget above). Instead, reviewers run a minimal but complete instance
of the DAEDALUS pipeline on one TA:

1. a **naive** symbolic-execution run (no LLM techniques), and
2. an **LLM-enhanced** run that uses LLM-constrained inputs and smart reentries across
   multiple parallel processes,

followed by **merging** and **inspecting** the resulting reports.

The target TA is the open-source **OP-TEE secure-storage example TA**
(UUID `f4e750bb-1437-4fbf-8785-8d3580c34994`), located at
`test_binaries/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf`.

## 1. Environment: CloudLab profile

We provide a CloudLab profile that provisions a machine with all OS-level prerequisites 
already available, so reviewers do not need to configure
the base system themselves.

<!-- TODO(authors): fill in the concrete CloudLab instantiation details below. -->

> **CloudLab instantiation instructions (to be completed by the authors):**
>
> 1. Log in to [CloudLab](https://www.cloudlab.us/).
> 2. Instantiate the profile: **`<PROFILE NAME / URL — TODO>`**.
> 3. Recommended hardware type: **`<HARDWARE TYPE — TODO>`** (≥ `<N>` cores,
>    ≥ `<M>` GB RAM recommended for the parallel LLM-enhanced run).
> 4. Operating system image: **`<IMAGE — TODO>`**.
> 5. Once the node is ready, SSH in as: `ssh <user>@<node>` **`<— TODO>`**.
> 6. The repository is located at / should be cloned to: **`<PATH — TODO>`**.
>
> _(Placeholder — replace with the final CloudLab profile name, URL, hardware, and any
> profile-specific setup steps.)_

Everything below assumes you are logged into the provisioned CloudLab node and are in the
repository root (the directory that contains `main.py`).

## 2. One-time setup

From the repository root, create the virtual environment and install dependencies:

```bash
./setup_venv.sh
source venv/bin/activate
```

This creates `./venv`, installs the Python dependencies from `requirements.txt`, and
installs the vendored `dependencies/angr-targets/` package.

> **No API key required.** The LLM-generated init functions for this TA are already
> checked in (`test_apps/optee_example_apps/init_f4e750bb-1437-4fbf-8785-8d3580c34994.py`),
> so no LLM/Anthropic API key is needed to run the evaluation.

## 3. Minimal test run

All analysis commands for this test live in `test_apps/optee_example_apps/`. The run
scripts activate the virtual environment themselves, so you do not strictly need it
active, but keeping it active (from step 2) is fine.

### Step 3a — Naive run (no LLM techniques)

This runs a single DAEDALUS process on the secure-storage TA with reentry and step
timeouts disabled (the "naive" configuration from the paper, `DAEDALUS_NAIVE`).

```bash
cd test_apps/optee_example_apps
./run_optee_examples_naive.sh
```

This run **terminates on its own** once symbolic exploration is exhausted (typically a few
minutes to some tens of minutes, depending on the machine). When it finishes you will see:

```
All executions completed.
```

The report for this run is written under:

```
reports/others/test_binaries/optee_examples/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf/
```

### Step 3b — Inspect the naive report

Start the report web server (from the repository root):

```bash
cd ../..                       # back to the repository root
source venv/bin/activate       # if not already active
python3 reporting/serve_reports.py
```

Then open a browser at **`http://localhost:8081`** and navigate to the
`f4e750bb-...-8d3580c34994.elf` folder. Each report shows the covered basic blocks,
exploration statistics, any detected bugs, and the emulated syscalls/library functions.

If you are on a headless node (no GUI/browser), you can either:

- forward the port over SSH, e.g. `ssh -L 8081:localhost:8081 <user>@<node>`, and open
  `http://localhost:8081` on your local machine; **or**
- inspect the generated files directly on disk:

```bash
ls reports/others/test_binaries/optee_examples/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf/
# open the report_*.html in any browser, or read the machine-readable report_*.json:
cat reports/others/test_binaries/optee_examples/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf/report_*.json
```

Stop the server with `Ctrl+C` when done (you can also leave it running and reload it
after step 3d).

### Step 3c — LLM-enhanced run (LLM-constrained inputs + smart reentries)

This run uses the checked-in, LLM-generated init functions for the secure-storage TA. It
launches **one analysis process per init function in parallel**, each exploring the TA
with different, LLM-provided `TEE_Params` types and constrained inputs, and re-entering
the TA according to the inferred command-dependency graph (`DAEDALUS_LLM`).

```bash
cd test_apps/optee_example_apps
./run_optee_examples.sh
```

You will see one `Starting: init_f4e750bb_<n>` line per init function, after which several
DAEDALUS processes run concurrently and write into the same TA report folder as before.

> **This run does not terminate on its own for 24 hours** (it keeps exploring / re-entering). Let it run
> for about **1 hour**, then stop it.

**To stop the run after ~1 hour**, open a second terminal on the node (or forward another
SSH session) and send a graceful termination signal to all analysis processes:

```bash
pkill -f main.py
```

`SIGTERM` is handled gracefully: each process finalizes and flushes its report before
exiting. (Reports are also persisted incrementally during the run, so results are not lost
even on a hard kill.) After `pkill`, you may also need to stop the launcher script itself
(the terminal running `run_optee_examples.sh`) with `Ctrl+C`, since it sleeps after
starting the workers.

> **Tip:** confirm the workers have exited with `pgrep -af main.py` (should print
> nothing, otherwise wait a little bit).

### Step 3d — Merge the parallel runs

Combine all runs for this TA (the naive run plus every LLM-enhanced parallel run, which
all live in the same folder) into a single merged report:

```bash
cd ../..                       # repository root
source venv/bin/activate       # if not already active

python3 reporting/merge_reports.py f4e750bb-1437-4fbf-8785-8d3580c34994.elf \
  --ta-report-dir others/test_binaries/optee_examples/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf
```

This writes `merged_report_f4e750bb-1437-4fbf-8785-8d3580c34994.elf_<timestamp>.html`
(and `.json`) into the same folder. The merged report contains the union of the basic
blocks covered across all runs and the aggregated bug findings and syscall statistics.

> Alternatively, `python3 reporting/batch_merge_test_binaries.py` merges every TA folder
> found under `reports/` in one go.

### Step 3e — Inspect the merged report

Start (or reload) the report server and open the TA folder again:

```bash
python3 reporting/serve_reports.py
# browse http://localhost:8081  ->  f4e750bb-...-8d3580c34994.elf
```

The merged report (prefixed `merged_report_`) should show **higher basic-block coverage**
than the individual naive run, illustrating the benefit of the LLM-constrained inputs and
smart-reentry techniques described in the paper. As with step 3b, on a headless node you
can instead open the `merged_report_*.html` file directly or read the
`merged_report_*.json`.

## 4. What success looks like

The evaluation is successful (Functional badge) if:

- `setup_venv.sh` completes and `python3 main.py --help` runs inside the venv;
- the **naive** run (step 3a) terminates and produces a `report_*.html`/`.json`;
- the **LLM-enhanced** run (step 3c) launches multiple parallel DAEDALUS processes that
  produce additional per-run reports in the same folder;
- the **merge** step (step 3d) produces a `merged_report_*` file; and
- the reports are viewable (in the browser at `http://localhost:8081`, or as HTML/JSON on
  disk), with the merged report showing coverage at least as high as the naive run.

## 5. Troubleshooting

- **The LLM-enhanced run seems idle / uses a lot of RAM.** This is expected: symbolic
  execution is memory-intensive. You can cap memory per process by editing the
  `COMMON_OPTS` in `test_apps/optee_example_apps/run_optee_examples.sh` to add e.g.
  `--memory-limit-gb 8`; a process finalizes its report and exits when it hits the limit.
- **Port 8081 already in use.** Stop any previous `serve_reports.py`, or change `PORT` at
  the top of `reporting/serve_reports.py`.
- **`pkill -f main.py` didn't stop everything.** Re-run it, and check with
  `pgrep -af main.py`. Also stop the `run_optee_examples.sh` launcher with `Ctrl+C`.
- **No reports appear.** Verify you ran the scripts from
  `test_apps/optee_example_apps/` and that the TA exists at
  `test_binaries/optee_examples/f4e750bb-1437-4fbf-8785-8d3580c34994.elf`.

For a full description of the framework, its options, and its internals, see
[`README.md`](README.md).
