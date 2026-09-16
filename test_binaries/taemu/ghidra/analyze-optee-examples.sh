#!/bin/bash

for file in "../../optee_examples"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make optee_examples TARGET="$basefile"
done


