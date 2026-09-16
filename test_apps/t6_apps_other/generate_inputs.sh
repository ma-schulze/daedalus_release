#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
#["9ef77781-7bd5-4e39-965f20f6f211f46b"]="0x2047f8"
#["b46325e6-5c90-8252-2eada8e32e5180d6"]="0x2003f0"
["edcf9395-3518-9067-614cafae2909775b"]="0x5893e4"  # Not loadable
#["face1d41-2636-11e1-ad9e0002a5d6c51b"]="0x200370"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/t6/tas/${TA}.ta --entry ${ENTRY} --call-depth=2 -o ./init_${TA}.py
done
