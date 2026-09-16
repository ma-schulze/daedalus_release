#!/bin/bash
# Run symbolic execution for each Beanpod TA that has an init file in test_apps/beanpod_apps/.
# For each init_<uuid>.py, runs analysis for every init function in that file (in parallel).
# All TAs are started in parallel.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

. ../../venv/bin/activate

RUN_INIT_FUNCS="$SCRIPT_DIR/../run_init_funcs.sh"
TAS_DIR="../../test_binaries/optee_tas"
BBS_DIR="../test_binaries/optee_tas/bbs"
INIT_DIR="."

COMMON_OPTS=(
  --tos optee
  --no-enable-step-timeout
  --func-hook-providers gp
)

for init_file in "$INIT_DIR"/init_*.py; do
  [[ -f "$init_file" ]] || continue
  base=$(basename "$init_file" .py)
  uuid="${base#init_}"
  ta_path="$TAS_DIR/${uuid}.elf"
  cfg_path="$BBS_DIR/bb_${uuid}.elf.json"
  if [[ ! -f "$ta_path" ]]; then
    echo "Warning: TA not found $ta_path, skipping." >&2
    continue
  fi
  echo "=== TA: $uuid (hooks: $init_file) ==="
  "$RUN_INIT_FUNCS" "optee_apps/$ta_path" "${COMMON_OPTS[@]}" --hooks "optee_apps/$init_file" --cfg-path "$cfg_path"
done

sleep 24h
echo "All executions completed."

