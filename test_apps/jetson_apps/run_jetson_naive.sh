#!/bin/bash

. ../../venv/bin/activate

python3 ../../main.py "../../test_binaries/nvidia/0e35e2c9-b329-4ad9-a2f5-8ca9bbbd7713.elf" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp  --cfg-path "../../test_binaries/nvidia/bbs/bb_0e35e2c9-b329-4ad9-a2f5-8ca9bbbd7713.elf.json" &

python3 ../../main.py "../../test_binaries/nvidia/82154947-c1bc-4bdf-b89d-04f93c0ea97c.elf" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp --cfg-path "../../test_binaries/nvidia/bbs/bb_82154947-c1bc-4bdf-b89d-04f93c0ea97c.elf.json" &

python3 ../../main.py "../../test_binaries/nvidia/a6a3a74a-77cb-433a-990c-1dfb8a3fbc4c.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp --cfg-path "../../test_binaries/nvidia/bbs/bb_a6a3a74a-77cb-433a-990c-1dfb8a3fbc4c.elf.json" &

python3 ../../main.py "../../test_binaries/nvidia/b83d14a8-7128-49df-9624-35f14f65ca6c.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp --cfg-path "../../test_binaries/nvidia/bbs/bb_b83d14a8-7128-49df-9624-35f14f65ca6c.elf.json" &

python3 ../../main.py "../../test_binaries/nvidia/bc50d971-d4c9-42c4-82cb-343fb7f37896.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,ftpm --cfg-path "../../test_binaries/nvidia/bbs/bb_bc50d971-d4c9-42c4-82cb-343fb7f37896.elf.json" &



wait
echo "All executions completed."
