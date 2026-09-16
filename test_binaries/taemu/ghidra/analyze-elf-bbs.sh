#!/bin/bash

dirs=(
    # "../../ftpm/"
    "../../optee_examples/"
)

for dir in "${dirs[@]}"; do
    echo "Checking $dir"
    echo "Teename $tee_name"
    for file in "$dir"/*.elf; do
        echo "Checking $file"
        # Check if any files matched
        [ -e "$file" ] || continue
        basefile=$(basename "$file")
        jsonfile="${file%.elf}.json"               
        if [ -f "$jsonfile" ]; then
            echo "Calling bbs for $jsonfile"
            make bbs TARGET="$basefile" TEE="optee_examples"
        fi
    done
done

