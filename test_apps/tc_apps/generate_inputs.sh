#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
  ["7461736b5f73746f7261676500000000"]="0x74c"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/trustedcore/tas/${TA}.ta --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done