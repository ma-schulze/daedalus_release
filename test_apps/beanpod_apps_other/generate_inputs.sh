#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
["08010203000000000000000000000000"]="0x9bb4"
["08030000000000000000000000000000"]="0x8888"
["3d08821c33a611e6a1fa089e01c83aa2"]="0x9228"
["655a4b46cd7711eaaafbf382a6988e7b"]="0xbdc0"
["86f623f6a2994dfdb560ffd3e5a62c29"]="0x95d0"
["8aaaf201246000007143fe4f7c823c80"]="0x95f8"
["df1edda8627911e980ae507b9d9a7e7d"]="0x9024"
["e5140b3376fa4c63ab18062caab2fb5c"]="0x9268"
["e97c270ea5c44c58bcd3384a2fa2539e"]="0x9d48"
)

for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/beanpod/tas/${TA}.ta --entry ${ENTRY} --call-depth=3 -o ./init_${TA}.py
done
