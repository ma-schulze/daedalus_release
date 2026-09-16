#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
  ["14498ace2a8f11e880c8509a4c146f4c"]="0x96d0"
  ["08110000000000000000000000000000"]="0x953d"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/beanpod/tas/${TA}.ta --entry ${ENTRY} --call-depth=4 -o ./init_${TA}.py
done
