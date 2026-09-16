#!/bin/bash
# Run symbolic execution only on TAs that have a harness under test_binaries/taemu/teegris/harness/.
# Each harness folder's ta.txt gives the TA filename; we use vuln_tas if present, else tas.

. ../../venv/bin/activate

TAS_DIR="../../test_binaries/taemu/teegris/tas"
VULN_DIR="../../test_binaries/taemu/teegris/vuln_tas"

# TAs from harness/*/ta.txt (one per harness folder)
HARNESS_TAS=(
	00000000-0000-0000-0000-4d7073534d43.ta      # MpsSMC_fuzz
	00000000-0000-0000-0000-000048444350.ta      # 000048444350_fuzz
	# 00000000-0000-0000-0000-4662436b6d52.ta      # 4662436b6d52_fuzz
	# 00000000-0000-0000-0000-544545535355.ta      # teessu_fuzz
	# 00000000-0000-0000-0000-0000534b504d.ta      # 0000534b504d_fuzz
	# 00000000-0000-0000-0000-53454d655345.ta      # semese_fuzz
	# 00000000-0000-0000-0000-474154454b45.ta      # 474154454b45_cmd7e
	# 00000000-0000-0000-0000-54412d48444d.ta      # hdm_fuzz
	# 00000000-0000-0000-0000-00575644524d.ta      # 00575644524d_fuzz
	# 00000000-0000-0000-0000-000000534b4d.ta      # 000000534b4d_fuzz
	# 00000000-0000-0000-0000-657365636f6d.ta      # 657365636f6d_fuzz
	# 00000000-0000-0000-0000-656e676d6f64.ta      # engmode_fuzz
	# 00000000-0000-0000-0000-534258505859.ta      # sspproxy_fuzz
	# 00000000-0000-0000-0000-4d5053545549.ta      # MPSTUI_fuzz
	# 00000000-0000-0000-0000-4d70536b566e.ta      # MpSkFn_fuzz
	# 00000000-0000-0000-0000-6d706f667376.ta      # 6d706f667376_fuzz
)

for ta in "${HARNESS_TAS[@]}"; do
	if [ -f "$VULN_DIR/$ta" ]; then
		elf="$VULN_DIR/$ta"
	elif [ -f "$TAS_DIR/$ta" ]; then
		elf="$TAS_DIR/$ta"
	else
		echo "Skipping (not found): $ta"
		continue
	fi
	echo "Starting: $elf"
	bb_path="../../test_binaries/taemu/teegris/tas/bbs/bb_$ta.json"

	python3 ../../main.py "$elf" --tos optee --no-enable-reentry --func-hook-providers gp,teegris --hooks ./teegris_apps_naive.py --cfg-path "$bb_path" &
done

wait
echo "All executions completed."
