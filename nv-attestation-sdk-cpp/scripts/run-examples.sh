#!/bin/bash
# Script to run all example executables and verify they execute without errors
# Usage: ./run-examples.sh <examples-build-directory>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <examples-build-directory>"
    exit 1
fi

EXAMPLES_BUILD_DIR="$1"

if [ ! -d "$EXAMPLES_BUILD_DIR" ]; then
    echo "Error: Directory '$EXAMPLES_BUILD_DIR' does not exist"
    exit 1
fi

# Find all executable files in the examples build directory
mapfile -t EXAMPLE_PATHS < <(find "$EXAMPLES_BUILD_DIR" -type f -executable | sort)

if [ ${#EXAMPLE_PATHS[@]} -eq 0 ]; then
    echo "Error: No executable files found in '$EXAMPLES_BUILD_DIR'"
    exit 1
fi

echo "Running examples from: $EXAMPLES_BUILD_DIR"
echo "Found ${#EXAMPLE_PATHS[@]} executable(s)"
echo "========================================"
echo ""

FAILED_EXAMPLES=()
SUCCESS_COUNT=0
TOTAL_COUNT=${#EXAMPLE_PATHS[@]}

for EXAMPLE_PATH in "${EXAMPLE_PATHS[@]}"; do
    EXAMPLE_NAME=$(basename "$EXAMPLE_PATH")
    
    echo "Running $EXAMPLE_NAME..."
    
    if "$EXAMPLE_PATH"; then
        echo "$EXAMPLE_NAME completed successfully"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        EXIT_CODE=$?
        echo "$EXAMPLE_NAME failed with exit code $EXIT_CODE"
        FAILED_EXAMPLES+=("$EXAMPLE_NAME")
    fi
    echo ""
done

echo "========================================"
echo "Results: $SUCCESS_COUNT/$TOTAL_COUNT examples passed"

if [ ${#FAILED_EXAMPLES[@]} -gt 0 ]; then
    echo ""
    echo "Failed examples:"
    for failed in "${FAILED_EXAMPLES[@]}"; do
        echo "  - $failed"
    done
    exit 1
fi

echo "All examples ran successfully!"
exit 0

