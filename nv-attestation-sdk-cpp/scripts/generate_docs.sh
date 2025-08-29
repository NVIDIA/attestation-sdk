#!/bin/bash

set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "--- Generating Doxygen Documentation ---"
cd "$PROJECT_DIR"
doxygen "Doxyfile"

echo "--- Documentation Complete ---"
echo "Find documentation site at '$PROJECT_DIR/docs/html/index.html'"