#!/bin/bash

. ../../venv/bin/activate

# Only these two TAs (from harness/1449_fuzz and harness/0811_test)
python3 ../../main.py "../../test_binaries/taemu/t6/tas/9ef77781-7bd5-4e39-965f20f6f211f46b.ta" --tos optee \
    --no-enable-reentry \
    --no-enable-step-timeout --func-hook-providers gp,t6 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_9ef77781-7bd5-4e39-965f20f6f211f46b.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/t6/tas/b46325e6-5c90-8252-2eada8e32e5180d6.ta" --tos optee \
   --no-enable-reentry \
    --no-enable-step-timeout --func-hook-providers gp,t6 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_b46325e6-5c90-8252-2eada8e32e5180d6.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/t6/tas/edcf9395-3518-9067-614cafae2909775b.ta" --tos optee \
    ---no-enable-reentry \
    --no-enable-step-timeout --func-hook-providers gp,t6 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_edcf9395-3518-9067-614cafae2909775b.ta.json" &

python3 ../../main.py "../../test_binaries/taemu/t6/tas/face1d41-2636-11e1-ad9e0002a5d6c51b.ta" --tos optee \
    --no-enable-reentry \
    --no-enable-step-timeout --func-hook-providers gp,t6 --no-enable-dfs --cfg-path "../../test_binaries/taemu/t6/tas/bbs/bb_face1d41-2636-11e1-ad9e0002a5d6c51b.ta.json" &
wait
echo "All executions completed."
