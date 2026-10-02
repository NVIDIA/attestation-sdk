#!/bin/bash
# Materialise unit-test fixtures: certs, unsigned CoRIM/CoMID (.diag -> .cbor),
# and signed CoRIM (Python wrapper around x509 chain).
#
# Both the Makefile `prepare-test-data` target and `Environment::SetUp()` (the
# unit-test gtest environment) invoke this so the recipe lives in one place.
# The fuzz-test corpus generator picks the fixtures up indirectly via
# `generate-fuzz-corpus: prepare-test-data`.
#
# Usage: prepare-test-data.sh <testdata-root>
#   <testdata-root>: absolute path to the directory containing
#                    x509_cert_chain/, tls_test/, sample_rims/.

set -euo pipefail

TESTDATA="${1:?usage: $0 <testdata-root>}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
VENV_PY="$REPO_ROOT/venv/bin/python3"

export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cbor-diag >/dev/null 2>&1; then
    echo "Error: cbor-diag missing. Run 'make install-deps' or 'cargo install cbor-diag-cli'." >&2
    exit 1
fi

bash "$SCRIPT_DIR/setup-venv.sh"
if [ ! -x "$VENV_PY" ]; then
    echo "Error: $VENV_PY missing after setup-venv.sh; cannot run generate_fixtures.py" >&2
    exit 1
fi

(cd "$TESTDATA/x509_cert_chain" && bash generate_test_certs.sh)
(cd "$TESTDATA/tls_test" && bash generate_tls_certs.sh)

for dir in "$TESTDATA/sample_rims/corim" "$TESTDATA/sample_rims/comid" "$TESTDATA/sample_rims/coev" "$TESTDATA/sample_rims/eat"; do
    for diag in "$dir"/*.diag; do
        [ -e "$diag" ] || continue
        cbor-diag --from=diag --to=bytes < "$diag" > "${diag%.diag}.cbor"
    done
done

"$VENV_PY" "$TESTDATA/sample_rims/corim/generate_fixtures.py" >/dev/null
