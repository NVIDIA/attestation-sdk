#!/bin/bash

set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
readonly PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
readonly BUILD_DIR="$PROJECT_DIR/build"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
echo "--- Configuring CMAKE ---"
cmake .. \
      -DENABLE_NSCQ=${ENABLE_NSCQ:-ON} \
      -DENABLE_NVML=${ENABLE_NVML:-ON} \
      -DBUILD_TESTING=ON \
      -DBUILD_EXAMPLES=${BUILD_EXAMPLES:-OFF} \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -DSANITIZER=${SANITIZER:-}
echo "--- Building SDK ---"
cmake --build .
