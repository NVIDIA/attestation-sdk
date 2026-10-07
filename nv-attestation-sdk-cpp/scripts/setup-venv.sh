#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
VENV_DIR="$REPO_ROOT/venv"
REQ_FILE="$REPO_ROOT/requirements-dev.txt"

if [ -x "$VENV_DIR/bin/python3" ]; then
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not available on PATH; install it via your distro's package manager" >&2
    exit 1
fi

# `import venv` succeeds even when ensurepip's bundled wheels are absent —
# `python3 -m venv` then fails with "ensurepip is not available". Probe
# ensurepip explicitly to fail fast with a uniform remediation hint.
if ! python3 -m ensurepip --version >/dev/null 2>&1; then
    echo "error: python3 venv/ensurepip not usable; on Debian/Ubuntu install python3-venv (or python3.X-venv matching your interpreter)" >&2
    exit 1
fi

echo "Creating venv at $VENV_DIR"
python3 -m venv "$VENV_DIR"

echo "Installing $REQ_FILE into venv"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$REQ_FILE" || {
    echo "error: pip install failed" >&2
    exit 2
}

echo "venv ready"
