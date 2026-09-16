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
	#00000000-0000-0000-0000-000048444350      # 000048444350_fuzz
	#00000000-0000-0000-0000-0000534b504d      # 0000534b504d_fuzz
	#00000000-0000-0000-0000-53454d655345      # semese_fuzz
  #00000000-0000-0000-0000-00575644524d      # 00575644524d_fuzz
  #00000000-0000-0000-0000-4d7073534d43      # MpsSMC_fuzz
	#00000000-0000-0000-0000-4662436b6d52      # 4662436b6d52_fuzz
	#00000000-0000-0000-0000-544545535355      # teessu_fuzz
	#00000000-0000-0000-0000-474154454b45      # 474154454b45_cmd7e
	#00000000-0000-0000-0000-54412d48444d      # hdm_fuzz
	#00000000-0000-0000-0000-000000534b4d      # 000000534b4d_fuzz
	#00000000-0000-0000-0000-657365636f6d      # 657365636f6d_fuzz
	#00000000-0000-0000-0000-656e676d6f64      # engmode_fuzz
	#00000000-0000-0000-0000-534258505859      # sspproxy_fuzz
	#00000000-0000-0000-0000-4d5053545549      # MPSTUI_fuzz
	 00000000-0000-0000-0000-4d70536b566e      # MpSkFn_fuzz
   00000000-0000-0000-0000-6d706f667376      # 6d706f667376_fuzz
)

for ta in "${TA_LIST[@]}"; do
  init_file="$INIT_DIR/init_${ta}.py"
  [[ -f "$init_file" ]] || continue
  base=$(basename "$init_file" .py)
  uuid="${base#init_}"
  if [ -f "$VULN_DIR/${uuid}.ta" ]; then
    ta_path="$VULN_DIR/${uuid}.ta"
    cfg_path="$TAS_BBS_DIR/bb_$uuid.ta.json"
  else
    ta_path="$TAS_DIR/${uuid}.ta"
    cfg_path="$TAS_BBS_DIR/bb_$uuid.ta.json"
  fi
  if [[ ! -f "$ta_path" ]]; then
    echo "Warning: TA not found $ta_path, skipping." >&2
    continue
  fi
  echo "=== TA: $uuid (hooks: $init_file) ==="
  "$RUN_INIT_FUNCS" "teegris_apps/$ta_path" \
    "${COMMON_OPTS[@]}" \
    --hooks "teegris_apps/$init_file" \
    --cfg-path "$cfg_path"
done

sleep 24h
echo "All executions completed."


