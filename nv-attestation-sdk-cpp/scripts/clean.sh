#!/bin/bash

set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

rm -rf "$PROJECT_DIR/build" "$PROJECT_DIR/out" "$PROJECT_DIR/docs"
echo "--- Removed build directories ---"
