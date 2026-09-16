#!/bin/bash
# Run symbolic execution only on TAs that have a harness under test_binaries/taemu/teegris/harness/.
# Each harness folder's ta.txt gives the TA filename; we use vuln_tas if present, else tas.

. ../../venv/bin/activate

TAS_DIR="../../test_binaries/taemu/teegris/tas"
VULN_DIR="../../test_binaries/taemu/teegris/vuln_tas"

# TAs from harness/*/ta.txt (one per harness folder)
HARNESS_TAS=(
	# 00000000-0000-0000-0000-000000000046.ta      # MpsSMC_fuzz
	00000000-0000-0000-0000-000048444350.ta      # 000048444350_fuzz
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
	if [ -f "$VULN_DIR/$ta" ]; then
		bb_path="../../test_binaries/taemu/teegris/vuln_tas/bbs/bb_$ta.json"
	else
		bb_path="../../test_binaries/taemu/teegris/tas/bbs/bb_$ta.json"
	fi

	python3 ../../main.py "$elf" --no-enable-step-timeout --tos optee --no-enable-reentry --func-hook-providers gp,teegris --hooks ./teegris_apps_naive.py --cfg-path "$bb_path" --invoke-command-symbolic-inputs-func teegris_init_function &
done

wait
echo "All executions completed."
