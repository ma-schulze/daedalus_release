#!/bin/bash

. ../../venv/bin/activate


python3 ../../main.py "../../test_binaries/ftpm/bc50d971-d4c9-42c4-82cb-343fb7f37896.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp,ftpm --cfg-path "../../test_binaries/ftpm/bbs/bb_bc50d971-d4c9-42c4-82cb-343fb7f37896.elf.json" &



wait
echo "All executions completed."
