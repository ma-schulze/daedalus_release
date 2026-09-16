#!/bin/bash
# Run symbolic execution only on TAs that have a harness under test_binaries/taemu/teegris/harness/.
# Each harness folder's ta.txt gives the TA filename; we use vuln_tas if present, else tas.

. ../../venv/bin/activate

TAS_DIR="../../test_binaries/taemu/teegris/tas"

HARNESS_TAS=(
  #00000000-0000-0000-0000-000000010081.ta
  #00000000-0000-0000-0000-000000020081.ta
  #00000000-0000-0000-0000-0050524f4341.ta
  #00000000-0000-0000-0000-0053545354ab.ta
  #00000000-0000-0000-0000-4b45594d5354.ta
  #00000000-0000-0000-0000-4d704e434954.ta
  #00000000-0000-0000-0000-4d7073617574.ta
  #00000000-0000-0000-0000-6b6e78677564.ta
  #00000000-0000-0000-0000-6d73745f5441.ta
  #00000000-0000-0000-0000-564c544b5052.ta
  #00000000-0000-0000-0000-42494f535542.ta
  #COVERAGE BROKEN? 00000000-0000-0000-0000-46494e474502.ta
  #00000000-0000-0000-0000-64756c444152.ta
  00000000-0000-0000-0000-544974684c6c.ta
  00000000-0000-0000-0000-54496473706c.ta
  00000000-0000-0000-0000-487641557457.ta
  00000000-0000-0000-0000-505256544545.ta
)

for ta in "${HARNESS_TAS[@]}"; do
	if [ -f "$TAS_DIR/$ta" ]; then
		elf="$TAS_DIR/$ta"
	else
		echo "Skipping (not found): $ta"
		continue
	fi
	echo "Starting: $elf"
	bb_path="../../test_binaries/taemu/teegris/tas/bbs/bb_$ta.json"

	python3 ../../main.py "$elf" --tos optee --no-enable-reentry --func-hook-providers gp,teegris --cfg-path "$bb_path" &
done

wait
echo "All executions completed."
