#!/usr/bin/env bash
set -euo pipefail

# Build and run keymaster's tests: the Swift tests (everything except
# Sources/main.swift, plus Tests/), and, when Go is installed, the relay's Go
# tests and an integration run against a local relay with a fake phone.
# Nothing here touches the keychain or TouchID.

cd "$(dirname "$0")"
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/keymaster-test.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

sources=()
for f in Sources/*.swift; do
  [[ "$f" == Sources/main.swift ]] || sources+=("$f")
done
swiftc -o "$build_dir/keymaster-tests" "${sources[@]}" Tests/*.swift

if command -v go >/dev/null; then
  (cd relay && go vet ./... && go test ./...)
  (cd relay && go build -o "$build_dir/relay" . && go build -o "$build_dir/fakephone" ./cmd/fakephone)
  KM_RELAY="$build_dir/relay" KM_FAKEPHONE="$build_dir/fakephone" "$build_dir/keymaster-tests"
else
  echo "go not found; skipping relay and integration tests" >&2
  "$build_dir/keymaster-tests"
fi
