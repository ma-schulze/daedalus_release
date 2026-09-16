#!/bin/bash
# Run symbolic execution for each MITEE TA that has an init file in test_apps/mitee_apps/.
# For each init_<uuid>.py, runs analysis for every init function in that file (in parallel).
# All TAs are started in parallel.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

. ../../venv/bin/activate

RUN_INIT_FUNCS="$SCRIPT_DIR/../run_init_funcs.sh"
TAS_DIR="../../test_binaries/taemu/mitee/tas"
BBS_DIR="../test_binaries/taemu/mitee/tas/bbs"
INIT_DIR="./"

COMMON_OPTS=(
  --tos optee
  --no-enable-step-timeout
  --no-use-svc-hooks
  --func-hook-providers gp,mitee
)

TA_LIST=(
    # 86f623f6-a299-4dfd-b560ffd3e5a62c29
    #e97c270e-a5c4-4c58-bcd3384a2fa2539e
    #377ee4e8-af0e-474f-a9d636a9268fe85c
    #59a4867c-9fe5-f7c2-b409a46bae6ff73e
    #f13010e0-2ae1-11e5-896a0002a5d5c51d            
    #3d08821c-33a6-11e6-a1fa089e01c83aa2
    #a734eed9-d6a1-4244-aa507c99719e7b7f
    #8aaaf201-2460-0000-7143fe4f7c823c80
    #9811c1f6-47e3-5cea-ae6ef62ba433c4fd
   14b0aad8-c011-4a3f-b66aca8d0e66f273
)

for ta in "${TA_LIST[@]}"; do
  init_file="$INIT_DIR/init_${ta}.py"
  [[ -f "$init_file" ]] || continue
  base=$(basename "$init_file" .py)
  uuid="${base#init_}"
  ta_path="$TAS_DIR/${uuid}.ta"
  cfg_path="$BBS_DIR/bb_${uuid}.ta.json"
  if [[ ! -f "$ta_path" ]]; then
    echo "Warning: TA not found $ta_path, skipping." >&2
    continue
  fi
  echo "=== TA: $uuid (hooks: $init_file) ==="
  "$RUN_INIT_FUNCS" "mitee_apps/$ta_path" \
    "${COMMON_OPTS[@]}" \
    --hooks "mitee_apps/$init_file" \
    --cfg-path "$cfg_path"
done

sleep 24h
echo "All executions completed."


