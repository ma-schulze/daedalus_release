#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
	["2e8fade5-0c7a-46cc-810e6468baee66b9"]="0x22538"
	["4d573443-6a56-4272-ac6f2425af9ef9bb"]="0x173c0"
	["88ce8e6b-8646-4092-bb78faf5b55ff4df"]="0x24ae8"
	["655a4b46-cd77-11ea-aafbf382a6988e7b"]="0x300d8"
	["dba51a17-0563-11e7-93b16fa7b0071a51"]="0xc6cc8"
	["e5140b33-76fa-4c63-ab18062caab2fb5c"]="0x1e0e8"
)


for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/mitee/tas/${TA}.ta --entry ${ENTRY} --call-depth=4 -o ./init_${TA}.py

	sleep 10
done
