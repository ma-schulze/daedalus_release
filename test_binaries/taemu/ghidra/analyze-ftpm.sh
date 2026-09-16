#!/bin/bash

for file in "../../ftpm"/*.elf; do
    # Check if any files matched
    [ -e "$file" ] || continue
	basefile=$(basename "$file")
    make ftpm TARGET="$basefile"
done


