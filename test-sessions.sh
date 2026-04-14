#!/usr/bin/env bash
#
# Interactive test for keymaster session groups.
# Calls real TouchID — run it and report what you see.

set -euo pipefail

KM="$(cd "$(dirname "$0")" && pwd)/keymaster"
TMPGROUPS="$(mktemp)"
TESTKEY_A="test_session_a_$$"
TESTKEY_B="test_session_b_$$"
TESTKEY_C="test_session_c_$$"

cleanup() {
  rm -f "$TMPGROUPS"
  "$KM" delete "$TESTKEY_A" 2>/dev/null || true
  "$KM" delete "$TESTKEY_B" 2>/dev/null || true
  "$KM" delete "$TESTKEY_C" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Setup: storing 3 test secrets ==="
echo "(You'll get up to 3 TouchID prompts for the set operations.)"
echo
echo "secret_a" | "$KM" set "$TESTKEY_A"
echo "secret_b" | "$KM" set "$TESTKEY_B"
echo "secret_c" | "$KM" set "$TESTKEY_C"

# Clear any session cache from the sets above by waiting or using a short TTL
export KEYMASTER_TTL=0

echo
echo "=== Test: session groups ==="
echo
echo "Groups file puts keys A and B in [deploy], key C is ungrouped."
cat > "$TMPGROUPS" <<EOF
[deploy]
$TESTKEY_A
$TESTKEY_B
EOF

# Reset TTL to something reasonable for the shared session test
export KEYMASTER_TTL=300

echo
echo "--- Step 1: Getting key A (grouped in [deploy]) ---"
"$KM" -v -g "$TMPGROUPS" get "$TESTKEY_A" 2>&1
echo
echo "--- Step 2: Getting key B (also in [deploy]) ---"
"$KM" -v -g "$TMPGROUPS" get "$TESTKEY_B" 2>&1
echo
echo "--- Step 3: Getting key C (not in any group) ---"
"$KM" -v -g "$TMPGROUPS" get "$TESTKEY_C" 2>&1
echo
echo "--- Step 4: Getting key A with -s override ---"
"$KM" -v -s custom_session -g "$TMPGROUPS" get "$TESTKEY_A" 2>&1
echo
echo "=== Done. ==="
echo "Expected behavior:"
echo "  Step 1: TouchID prompt (new session for 'deploy' group)"
echo "  Step 2: NO TouchID (reuses 'deploy' session from step 1)"
echo "  Step 3: TouchID prompt (key C is ungrouped, separate session)"
echo "  Step 4: TouchID prompt (override session 'custom_session' is new)"
