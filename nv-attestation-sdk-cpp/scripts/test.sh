#!/bin/bash
# Build SDK and run tests.
# Arguments of this script will be passed directly to ctest.
# Examples:
#   ./test.sh
#   ./test.sh -L unit
#   ./test.sh -L unit -R Rim
# This script can be run from any directory.

set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
readonly BUILD_DIR="$PROJECT_DIR/build"

"$SCRIPT_DIR/build.sh"

echo "--- Testing SDK ---"
echo "Note: GoogleTest/Ctest will redirect Setup logs (from unit-tests/main.cpp) to build/Testing/Temporary/LastTest.log. They will not appear in the console."
cd "$BUILD_DIR"
ctest --output-on-failure "$@"