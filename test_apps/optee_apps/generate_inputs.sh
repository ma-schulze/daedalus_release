#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
  ["fd02c9da-306c-48c7-a49c-bbd827ae86ee"]="0xc5c"
  ["f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c"]="0x53c"
  ["023f8f1a-292a-432b-8fc4-de8471358067"]="0x258"
  ["80a4c275-0a47-4905-8285-1486a9771a08"]="0x4d0"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/optee_tas/${TA}.elf --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done