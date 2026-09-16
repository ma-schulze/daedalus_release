#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
["1dc6a16b-2fba-4aa1-9519-ea8a6c8c16e5"]="0x974"
["2a287631-de1b-4fdd-a55c-b9312e40769a"]="0x2f4"
["5dbac793-f574-4871-8ad3-04331ec17f24"]="0x1d4"
["8aaaf200-2450-11e4-abe2-0002a5d5c51b"]="0x3bc"
["50c82425-94da-4072-a3e0-58ef063767c0"]="0x838"
["484d4143-2d53-4841-3120-4a6f636b6542"]="0x554"
["1945e8e7-0278-4bfb-bb99-af1080b2a934"]="0x8d4"
["a734eed9-d6a1-4244-aa50-7c99719e7b7b"]="0x578"
["b6c53aba-9669-4668-a7f2-205629d00f86"]="0x288"
["f066f150-42af-404f-ae32-c8e6cd117e70"]="0x620"
["f4e750bb-1437-4fbf-8785-8d3580c34994"]="0x5a0"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/optee_examples/${TA}.elf --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done
