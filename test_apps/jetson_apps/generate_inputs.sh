#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
  ["a6a3a74a-77cb-433a-990c-1dfb8a3fbc4c"]="0x2c0"
  ["0e35e2c9-b329-4ad9-a2f5-8ca9bbbd7713"]="0xf0"
  ["82154947-c1bc-4bdf-b89d-04f93c0ea97c"]="0x490"
  ["b83d14a8-7128-49df-9624-35f14f65ca6c"]="0x174"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/optee_tas/${TA}.elf --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done