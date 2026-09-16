#!/bin/bash

for file in "../../optee_tas"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make optee TARGET="$basefile"
done


