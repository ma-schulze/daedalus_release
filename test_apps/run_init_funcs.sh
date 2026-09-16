#!/bin/bash
# Run symbolic execution for each init function in the --hooks file.
# Parses the hooks file for all init_* functions (def init_*(state)) and runs
# main.py once per init function with --invoke-command-symbolic-inputs-func,
# in parallel (background with &), then waits for all.
#
# Usage: run_init_funcs.sh <ta_path> [options...]
#   First argument is the TA binary path; remaining arguments are passed through
#   to main.py (must include --hooks <path> and any other desired options).
#   This script adds --invoke-command-symbolic-inputs-func <name> for each run.

set -e

TA_PATH="$1"
shift
OPTS=("$@")

if [[ -z "$TA_PATH" ]]; then
  echo "Usage: run_init_funcs.sh <ta_path> [options...]" >&2
  echo "  Options must include --hooks <path>." >&2
  exit 1
fi


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"


# Find --hooks <path> in OPTS
HOOKS_FILE=""
i=0
while [[ $i -lt ${#OPTS[@]} ]]; do
  if [[ "${OPTS[$i]}" == "--hooks" ]]; then
    (( i++ )) || true
    if [[ $i -lt ${#OPTS[@]} ]]; then
      HOOKS_FILE="${OPTS[$i]}"
      break
    fi
  fi
  (( i++ )) || true
done

if [[ -z "$HOOKS_FILE" || ! -f "$HOOKS_FILE" ]]; then
  echo "run_init_funcs.sh: could not find or read --hooks file in arguments." >&2
  exit 1
fi

# Extract init function names: def init_<name>(state) or def init_<name> (state)
# (handles optional space and optional : type annotation)
INIT_FUNCS=()
while IFS= read -r line; do
  if [[ "$line" =~ def[[:space:]](init_[a-zA-Z0-9_]+)[[:space:]]*\( ]]; then
    INIT_FUNCS+=("${BASH_REMATCH[1]}")
  fi
done < <(grep -E 'def[[:space:]]+init_[a-zA-Z0-9_]+[[:space:]]*\(' "$HOOKS_FILE")

if [[ ${#INIT_FUNCS[@]} -eq 0 ]]; then
  echo "run_init_funcs.sh: no init functions found in $HOOKS_FILE" >&2
  exit 1
fi

echo "run_init_funcs.sh: found ${#INIT_FUNCS[@]} init function(s) in $HOOKS_FILE"

for func in "${INIT_FUNCS[@]}"; do
  echo "  Starting: $func"
  python3 ../main.py "$TA_PATH" "${OPTS[@]}" --invoke-command-symbolic-inputs-func "$func" &
done

