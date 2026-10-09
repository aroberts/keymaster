#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Sign with $KEYMASTER_SIGNING_IDENTITY if set, else the first valid Apple
# Development identity, matched by SHA-1 so a renewed cert sitting next to the
# old one isn't ambiguous.
if [[ -n "${KEYMASTER_SIGNING_IDENTITY:-}" ]]; then
  SIGNING_IDENTITY="$KEYMASTER_SIGNING_IDENTITY"
else
  SIGNING_IDENTITY="$(security find-identity -v -p codesigning \
    | awk '/"Apple Development: /{print $2; exit}')"
fi

build() {
  swiftc -O -o keymaster Sources/*.swift
}

if [[ -n "$SIGNING_IDENTITY" ]]; then
  build
  codesign -f -s "$SIGNING_IDENTITY" -i keymaster keymaster
  echo "Built and signed with '$SIGNING_IDENTITY'."
else
  build
  cat >&2 <<EOF

############################################################################
# WARNING: no Apple Development code-signing identity was found.
#
# Built UNSIGNED (ad-hoc). macOS records this binary's Keychain trust
# against its cdhash, which changes on EVERY rebuild -- so you will get
# Keychain password prompts again after each build.
#
# To make the trust survive rebuilds, get an Apple Development identity
# from Xcode. See the "Code signing" section of README.md.
############################################################################
EOF
fi
