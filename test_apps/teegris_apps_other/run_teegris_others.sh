#!/bin/bash
# Run symbolic execution for each Teegris TA that has an init file in test_apps/teegris_apps/.
# For each init_<uuid>.py, runs analysis for every init function in that file (in parallel).
# All TAs are started in parallel.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

. ../../venv/bin/activate

RUN_INIT_FUNCS="$SCRIPT_DIR/../run_init_funcs.sh"
TAS_DIR="../../test_binaries/taemu/teegris/tas"
VULN_DIR="../../test_binaries/taemu/teegris/vuln_tas"
TAS_BBS_DIR="../test_binaries/taemu/teegris/tas/bbs"
VULN_BBS_DIR="../test_binaries/taemu/teegris/vuln_tas/bbs"
INIT_DIR="./"

COMMON_OPTS=(
  --tos optee
  --no-enable-step-timeout
  --no-use-svc-hooks
  --func-hook-providers gp,teegris
)

TA_LIST=(
  #00000000-0000-0000-0000-000000010081
  #00000000-0000-0000-0000-000000020081
  #00000000-0000-0000-0000-0050524f4341
  #00000000-0000-0000-0000-0053545354ab
  #00000000-0000-0000-0000-4b45594d5354
  #00000000-0000-0000-0000-4d704e434954
  #00000000-0000-0000-0000-4d7073617574
  00000000-0000-0000-0000-6b6e78677564
  #00000000-0000-0000-0000-6d73745f5441
  #00000000-0000-0000-0000-564c544b5052
  #00000000-0000-0000-0000-42494f535542
  # COVERAGE BROKEN? 00000000-0000-0000-0000-46494e474502
  #00000000-0000-0000-0000-64756c444152
  #00000000-0000-0000-0000-544974684c6c
  #00000000-0000-0000-0000-54496473706c
  #00000000-0000-0000-0000-487641557457
  #00000000-0000-0000-0000-505256544545
)

# not loadale: 00000000-0000-0000-0000-5345435f4652

for ta in "${TA_LIST[@]}"; do
  init_file="$INIT_DIR/init_${ta}.py"
  [[ -f "$init_file" ]] || continue
  base=$(basename "$init_file" .py)
  uuid="${base#init_}"
  ta_path="$TAS_DIR/${uuid}.ta"
  cfg_path="$TAS_BBS_DIR/bb_$uuid.ta.json"
  if [[ ! -f "$ta_path" ]]; then
    echo "Warning: TA not found $ta_path, skipping." >&2
    continue
  fi
  echo "=== TA: $uuid (hooks: $init_file) ==="
  "$RUN_INIT_FUNCS" "teegris_apps_other/$ta_path" \
    "${COMMON_OPTS[@]}" \
    --hooks "teegris_apps_other/$init_file" \
    --cfg-path "$cfg_path"
done

sleep 24h
echo "All executions completed."


