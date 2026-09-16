#!/bin/bash

. ../../venv/bin/activate

for elf in ../../test_binaries/optee_examples/f4e75*.elf; do
    echo "Starting: $elf"

    python3 ../../main.py "$elf" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp &
done

wait
echo "All executions completed."
