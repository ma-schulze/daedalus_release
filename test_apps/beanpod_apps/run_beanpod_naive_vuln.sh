#!/bin/bash

. ../../venv/bin/activate

# Only these two TAs (from harness/1449_fuzz and harness/0811_test)
python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/d78d338b1ac349e09f65f4efe179739d.ta" --tos optee \
    --hooks "./beanpod_apps_naive.py" --invoke-command-symbolic-inputs-func sym_input_d78d \
    --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_d78d338b1ac349e09f65f4efe179739d.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/08110000000000000000000000000000.ta" --tos optee \
    --hooks "./beanpod_apps_naive.py" --invoke-command-symbolic-inputs-func sym_input_0811_a \
    --no-enable-reentry --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_08110000000000000000000000000000.ta.json" &

#python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/df1edda8627911e980ae507b9d9a7e7d.ta" --tos optee --no-enable-reentry \
#    --hooks "./beanpod_apps_naive.py" --invoke-command-symbolic-inputs-func sym_input_df1ed_vuln \
#    --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_df1edda8627911e980ae507b9d9a7e7d.ta.json" &
wait
echo "All executions completed."
