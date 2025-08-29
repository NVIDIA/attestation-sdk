#!/bin/bash
# Usage: source activate.sh; cd anywhere; build.sh; test.sh

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
export PATH="$SCRIPT_DIR:$PATH"