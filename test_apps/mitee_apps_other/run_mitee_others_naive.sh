#!/bin/bash
# Run symbolic execution only on TAs that have a harness under test_binaries/taemu/mitee/harness/.
# Each harness folder's ta.txt gives the TA filename. 655a_fuzz is excluded.
# We use vuln_tas if present, else tas (mitee currently has no vuln_tas).

. ./../../venv/bin/activate

TAS_DIR="../../test_binaries/taemu/mitee/tas"

python3 ../../main.py "$TAS_DIR/2e8fade5-0c7a-46cc-810e6468baee66b9.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_2e8fade5-0c7a-46cc-810e6468baee66b9.ta.json" &
python3 ../../main.py "$TAS_DIR/4d573443-6a56-4272-ac6f2425af9ef9bb.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_4d573443-6a56-4272-ac6f2425af9ef9bb.ta.json" &
python3 ../../main.py "$TAS_DIR/88ce8e6b-8646-4092-bb78faf5b55ff4df.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_88ce8e6b-8646-4092-bb78faf5b55ff4df.ta.json" &
python3 ../../main.py "$TAS_DIR/dba51a17-0563-11e7-93b16fa7b0071a51.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_dba51a17-0563-11e7-93b16fa7b0071a51.ta.json" &
python3 ../../main.py "$TAS_DIR/e5140b33-76fa-4c63-ab18062caab2fb5c.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_e5140b33-76fa-4c63-ab18062caab2fb5c.ta.json" &            

# Not loadable: python3 ../../main.py "$TAS_DIR/f13010e0-2ae1-11e5-896a0002a5d5c51d.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --func-hook-providers gp,mitee --cfg-path "$TAS_DIR/bbs/bb_f13010e0-2ae1-11e5-896a0002a5d5c51d.ta.json" &            

wait
echo "All executions completed."
