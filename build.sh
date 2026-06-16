#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

SIGNING_IDENTITY="keymaster-signing"

build() {
  swiftc -O -o keymaster keymaster.swift -framework LocalAuthentication -framework Security
}

if security find-identity -p codesigning | grep -qF "\"$SIGNING_IDENTITY\""; then
  build
  codesign -f -s "$SIGNING_IDENTITY" -i keymaster keymaster
  echo "Built and signed with '$SIGNING_IDENTITY'."
else
  build
  cat >&2 <<EOF

############################################################################
# WARNING: code-signing identity '$SIGNING_IDENTITY' was not found.
#
# Built UNSIGNED (ad-hoc). macOS records this binary's Keychain trust
# against its cdhash, which changes on EVERY rebuild -- so you will get
# "Always Allow" Keychain prompts (and TouchID) again after each build.
#
# To make the trust survive rebuilds, create the self-signed identity
# once. See the "Building" section of README.md.
############################################################################
EOF
fi
