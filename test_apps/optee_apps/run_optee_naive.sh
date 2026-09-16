#!/bin/bash

. ../../venv/bin/activate

python3 ../../main.py "../../test_binaries/optee_tas/023f8f1a-292a-432b-8fc4-de8471358067.elf" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers gp --cfg-path "../../test_binaries/optee_tas/bbs/bb_023f8f1a-292a-432b-8fc4-de8471358067.elf.json" &

python3 ../../main.py "../../test_binaries/optee_tas/f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c.elf" --tos optee \
    --no-enable-reentry --no-enable-step-timeout --func-hook-providers None --cfg-path "../../test_binaries/optee_tas/bbs/bb_f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c.elf.json" &

python3 ../../main.py "../../test_binaries/optee_tas/80a4c275-0a47-4905-8285-1486a9771a08.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --func-hook-providers None --cfg-path "../../test_binaries/optee_tas/bbs/bb_80a4c275-0a47-4905-8285-1486a9771a08.elf.json" &

python3 ../../main.py "../../test_binaries/optee_tas/fd02c9da-306c-48c7-a49c-bbd827ae86ee.elf" --tos optee \
   --no-enable-reentry --no-enable-step-timeout --hooks optee_apps_naive.py --func-hook-providers pkcs11,gp --cfg-path "../../test_binaries/optee_tas/bbs/bb_fd02c9da-306c-48c7-a49c-bbd827ae86ee.elf.json" &

wait
echo "All executions completed."
