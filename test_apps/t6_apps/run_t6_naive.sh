#!/bin/bash

. ../../venv/bin/activate

# Only these two TAs (from harness/1449_fuzz and harness/0811_test)
python3 ../../main.py "../../test_binaries/taemu/t6/tas/02662e8e-e126-11e5-b86d9a79f06e9478.ta" --tos optee \
   --hooks ./t6_apps_naive.py --no-enable-reentry --invoke-command-symbolic-inputs-func init_02662e8e_a \
   --no-enable-step-timeout --func-hook-providers gp,t6 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_02662e8e-e126-11e5-b86d9a79f06e9478.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/t6/tas/9459b61a-02d3-4d1e-b68be94397e7ca8c.ta" --tos optee \
    --hooks ./t6_apps_naive.py --no-enable-reentry --invoke-command-symbolic-inputs-func init_9459b61a_a \
    --no-enable-step-timeout --func-hook-providers gp,t6,t6_945 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_9459b61a-02d3-4d1e-b68be94397e7ca8c.ta.json" &

wait
echo "All executions completed."
