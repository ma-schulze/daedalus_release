#!/bin/bash
# Run symbolic execution only on TAs that have a harness under test_binaries/taemu/mitee/harness/.
# Each harness folder's ta.txt gives the TA filename. 655a_fuzz is excluded.
# We use vuln_tas if present, else tas (mitee currently has no vuln_tas).

. ./../../venv/bin/activate

TAS_DIR="../../test_binaries/taemu/mitee/tas"

# python3 ../../main.py "$TAS_DIR/86f623f6-a299-4dfd-b560ffd3e5a62c29.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_86f6 --cfg-path "$TAS_DIR/bbs/bb_86f623f6-a299-4dfd-b560ffd3e5a62c29.ta.json" &
#python3 ../../main.py "$TAS_DIR/e97c270e-a5c4-4c58-bcd3384a2fa2539e.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_e97c --cfg-path "$TAS_DIR/bbs/bb_e97c270e-a5c4-4c58-bcd3384a2fa2539e.ta.json" &
# python3 ../../main.py "$TAS_DIR/377ee4e8-af0e-474f-a9d636a9268fe85c.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_377e --cfg-path "$TAS_DIR/bbs/bb_377ee4e8-af0e-474f-a9d636a9268fe85c.ta.json" &
# python3 ../../main.py "$TAS_DIR/59a4867c-9fe5-f7c2-b409a46bae6ff73e.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_59a4 --cfg-path "$TAS_DIR/bbs/bb_59a4867c-9fe5-f7c2-b409a46bae6ff73e.ta.json" &
# python3 ../../main.py "$TAS_DIR/f13010e0-2ae1-11e5-896a0002a5d5c51d.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_f130 --cfg-path "$TAS_DIR/bbs/bb_f13010e0-2ae1-11e5-896a0002a5d5c51d.ta.json" &            
# python3 ../../main.py "$TAS_DIR/3d08821c-33a6-11e6-a1fa089e01c83aa2.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_3d08 --cfg-path "$TAS_DIR/bbs/bb_3d08821c-33a6-11e6-a1fa089e01c83aa2.ta.json" &
# python3 ../../main.py "$TAS_DIR/a734eed9-d6a1-4244-aa507c99719e7b7f.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_a734 --cfg-path "$TAS_DIR/bbs/bb_a734eed9-d6a1-4244-aa507c99719e7b7f.ta.json" &
# python3 ../../main.py "$TAS_DIR/8aaaf201-2460-0000-7143fe4f7c823c80.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_8aaa --cfg-path "$TAS_DIR/bbs/bb_8aaaf201-2460-0000-7143fe4f7c823c80.ta.json" &
python3 ../../main.py "$TAS_DIR/9811c1f6-47e3-5cea-ae6ef62ba433c4fd.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_9811 --cfg-path "$TAS_DIR/bbs/bb_9811c1f6-47e3-5cea-ae6ef62ba433c4fd.ta.json" &
python3 ../../main.py "$TAS_DIR/14b0aad8-c011-4a3f-b66aca8d0e66f273.ta" --no-enable-step-timeout --no-enable-reentry --tos optee --hooks mitee_apps_naive.py --func-hook-providers gp,mitee --invoke-command-symbolic-inputs-func sym_input_14b0 --cfg-path "$TAS_DIR/bbs/bb_14b0aad8-c011-4a3f-b66aca8d0e66f273.ta.json" &

wait
echo "All executions completed."
