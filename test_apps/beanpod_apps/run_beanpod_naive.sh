#!/bin/bash

. ../../venv/bin/activate

# Only these two TAs (from harness/1449_fuzz and harness/0811_test)
python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/14498ace2a8f11e880c8509a4c146f4c.ta" --tos optee \
    --hooks "./beanpod_apps_naive.py" --invoke-command-symbolic-inputs-func sym_input_1449 \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_14498ace2a8f11e880c8509a4c146f4c.ta.json" &


python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/08110000000000000000000000000000.ta" --tos optee \
    --hooks "./beanpod_apps_naive.py" --invoke-command-symbolic-inputs-func sym_input_0811_a \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_08110000000000000000000000000000.ta.json" &
wait
echo "All executions completed."
