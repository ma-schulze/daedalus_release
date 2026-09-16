#!/bin/bash

. ../../venv/bin/activate

#python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/08010203000000000000000000000000.ta" --tos optee \
#    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_08010203000000000000000000000000.ta.json" &

#python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/08030000000000000000000000000000.ta" --tos optee \
#    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_08030000000000000000000000000000.ta.json" &

#python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/3d08821c33a611e6a1fa089e01c83aa2.ta" --tos optee \
#    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_3d08821c33a611e6a1fa089e01c83aa2.ta.json" &

#python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/655a4b46cd7711eaaafbf382a6988e7b.ta" --tos optee \
#    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_655a4b46cd7711eaaafbf382a6988e7b.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/86f623f6a2994dfdb560ffd3e5a62c29.ta" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_86f623f6a2994dfdb560ffd3e5a62c29.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/8aaaf201246000007143fe4f7c823c80.ta" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_8aaaf201246000007143fe4f7c823c80.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/df1edda8627911e980ae507b9d9a7e7d.ta" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_df1edda8627911e980ae507b9d9a7e7d.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/e5140b3376fa4c63ab18062caab2fb5c.ta" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_e5140b3376fa4c63ab18062caab2fb5c.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/beanpod/tas/e97c270ea5c44c58bcd3384a2fa2539e.ta" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,beanpod --cfg-path "../../test_binaries/taemu/beanpod/tas/bbs/bb_e97c270ea5c44c58bcd3384a2fa2539e.ta.json" &


wait
echo "All executions completed."
