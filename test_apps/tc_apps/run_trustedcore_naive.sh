#!/bin/bash

. ../../venv/bin/activate

for elf in ../../test_binaries/taemu/trustedcore/tas/7461736b5f73746f7261676500000000.ta; do
    echo "Starting: $elf"
    python3 ../../main.py "$elf" --tos optee --func-hook-providers gp,tc --hooks ./tc_apps.py --no-enable-reentry --invoke-command-symbolic-inputs-func tc_init_function &
done

wait
echo "All executions completed."

