#!/bin/bash

. ../../venv/bin/activate

declare -A TAS=(
	#["86f623f6-a299-4dfd-b560ffd3e5a62c29"]="0x25a78"	
	# ["e97c270e-a5c4-4c58-bcd3384a2fa2539e"]="0x50078"
	#["377ee4e8-af0e-474f-a9d636a9268fe85c"]="0x20098"
	#["59a4867c-9fe5-f7c2-b409a46bae6ff73e"]="0x201b0"
	#["f13010e0-2ae1-11e5-896a0002a5d5c51d"]="0x242160"
	#["3d08821c-33a6-11e6-a1fa089e01c83aa2"]="0x26190"
	#["a734eed9-d6a1-4244-aa507c99719e7b7f"]="0xee008"
	#["8aaaf201-2460-0000-7143fe4f7c823c80"]="0x231b0"
	# ["9811c1f6-47e3-5cea-ae6ef62ba433c4fd"]="0x45ba0"
	["14b0aad8-c011-4a3f-b66aca8d0e66f273"]="0x3c578"
)


for TA in "${!TAS[@]}"; do
    ENTRY=${TAS[$TA]}
    echo "Generating inputs for ${TA} at ${ENTRY}"

    PYTHONPATH=../../:${PYTHONPATH} python -m preprocessing.llm_ta_init_prompt ../../test_binaries/taemu/mitee/tas/${TA}.ta --entry ${ENTRY} --call-depth=3 -o ./init_${TA}.py

	sleep 60
done
