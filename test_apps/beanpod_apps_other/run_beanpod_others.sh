#!/bin/bash
# Run symbolic execution for each Beanpod TA that has an init file in test_apps/beanpod_apps/.
# For each init_<uuid>.py, runs analysis for every init function in that file (in parallel).
# All TAs are started in parallel.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

. ../../venv/bin/activate

RUN_INIT_FUNCS="$SCRIPT_DIR/../run_init_funcs.sh"
TAS_DIR="../../test_binaries/taemu/beanpod/tas"
BBS_DIR="../test_binaries/taemu/beanpod/tas/bbs"
INIT_DIR="."

COMMON_OPTS=(
  --tos optee
  --no-use-svc-hooks
  --func-hook-providers gp,beanpod
)

TAS_LIST=(
     e97c270ea5c44c58bcd3384a2fa2539e
     e5140b3376fa4c63ab18062caab2fb5c
#8aaaf201246000007143fe4f7c823c80
     86f623f6a2994dfdb560ffd3e5a62c29
     655a4b46cd7711eaaafbf382a6988e7b
     3d08821c33a611e6a1fa089e01c83aa2
#08030000000000000000000000000000
#08010203000000000000000000000000
#df1edda8627911e980ae507b9d9a7e7d
)

for ta in "${TAS_LIST[@]}"; do
  init_file="$INIT_DIR/init_${ta}.py"
  [[ -f "$init_file" ]] || continue
  ta_path="$TAS_DIR/${ta}.ta"
  cfg_path="$BBS_DIR/bb_${ta}.ta.json"
  if [[ ! -f "$ta_path" ]]; then
    echo "Warning: TA not found $ta_path, skipping." >&2
    continue
  fi
  echo "=== TA: $ta (hooks: $init_file) ==="
  "$RUN_INIT_FUNCS" "beanpod_apps_other/$ta_path" "${COMMON_OPTS[@]}" --hooks "beanpod_apps_other/$init_file" --cfg-path "$cfg_path"
done

sleep 24h
echo "All executions completed."

