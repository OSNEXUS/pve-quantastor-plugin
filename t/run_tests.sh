#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_tests.sh - Run the QuantaStor PVE plugin test suite
# ---------------------------------------------------------------------------
# Usage:
#   ./t/run_tests.sh            # unit tests only
#   ./t/run_tests.sh --all      # unit + integration (requires env vars)
#   ./t/run_tests.sh --verbose  # verbose TAP output
#
# Integration test environment variables (only needed with --all):
#   QS_HOST      QuantaStor appliance IP
#   QS_USER      API username (default: admin)
#   QS_PASSWORD  API password
#   QS_POOL      Storage pool name or UUID
#   QS_PORTAL    iSCSI portal (defaults to QS_HOST)
# ---------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default options
RUN_INTEGRATION=0
PROVE_ARGS=("-l" "--formatter=TAP::Formatter::Console")
UNIT_TESTS=("$SCRIPT_DIR/01-api-client.t" "$SCRIPT_DIR/02-iscsi-manager.t")

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --all)       RUN_INTEGRATION=1 ;;
        --verbose|-v) PROVE_ARGS+=("-v") ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# Ensure prove is available
if ! command -v prove &>/dev/null; then
    echo "ERROR: 'prove' not found. Install it with: apt install libtest-harness-perl" >&2
    exit 1
fi

# Check required Perl modules
perl -e 'use JSON::PP; use LWP::UserAgent; use URI::Escape' 2>/dev/null || {
    echo "ERROR: Missing required Perl modules. Install with:" >&2
    echo "  apt install libwww-perl liburi-perl" >&2
    echo "  (JSON::PP and File::Temp are included in Perl core)" >&2
    exit 1
}

echo "=== QuantaStor PVE Plugin Test Suite ==="
echo ""

# Build the include path so prove finds our source + test libs
PERL_INCLUDE=(
    "-I$REPO_ROOT/src/perl5"
    "-I$SCRIPT_DIR/lib"
)

# Run unit tests
echo "--- Unit Tests ---"
prove "${PROVE_ARGS[@]}" "${PERL_INCLUDE[@]}" "${UNIT_TESTS[@]}"
UNIT_RC=$?

if [[ $UNIT_RC -ne 0 ]]; then
    echo ""
    echo "FAIL: Unit tests failed." >&2
    exit $UNIT_RC
fi

echo ""
echo "PASS: All unit tests passed."

# Run integration tests if requested
if [[ $RUN_INTEGRATION -eq 1 ]]; then
    echo ""
    echo "--- Integration Tests ---"

    if [[ -z "${QS_HOST:-}" || -z "${QS_PASSWORD:-}" || -z "${QS_POOL:-}" ]]; then
        echo "SKIP: QS_HOST, QS_PASSWORD, and QS_POOL must be set for integration tests."
        echo "      Export them and re-run with --all."
        exit 0
    fi

    prove "${PROVE_ARGS[@]}" "${PERL_INCLUDE[@]}" "$SCRIPT_DIR/03-integration.t"
    INT_RC=$?

    if [[ $INT_RC -ne 0 ]]; then
        echo ""
        echo "FAIL: Integration tests failed." >&2
        exit $INT_RC
    fi

    echo ""
    echo "PASS: All integration tests passed."
else
    echo ""
    echo "NOTE: Integration tests skipped (pass --all to enable)."
fi
