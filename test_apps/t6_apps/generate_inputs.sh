#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
  ["9459b61a-02d3-4d1e-b68be94397e7ca8c"]="0x288054"
  ["02662e8e-e126-11e5-b86d9a79f06e9478"]="0x200fad"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/t6/tas/${TA}.ta --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done