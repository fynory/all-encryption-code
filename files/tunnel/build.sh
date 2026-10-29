#!/usr/bin/env bash
# Build the tunnel node into dist/ (standard library only, no cgo).
#
#   build.sh [node|test-node|blind-mutant|blind-mutant-vm|chaos-node|loadgen|all]     (default: all)
#
#   node       cross-compile the production node for the Ubuntu 24.04 VM (linux/amd64, static) and print its SHA-256
#   chaos-node [OUT [POLICY]]   build the CHAOS NODE (-tags testcp: the production control-plane client against a loopback control plane, see backend_loopcp.go)
#              for THIS machine into OUT (default dist/all-tunnel-chaosnode). POLICY, a policy.json with the long windows shortened, replaces the embedded one
#              for this build only (go build -overlay), which is how the chaos suite compresses hours into seconds. Never deployed.
#   loadgen [OUT]   build the load and chaos generator (cmd/loadgen) for THIS machine into OUT (default dist/loadgen)
#   test-node  build the TEST NODE for THIS machine (-tags testnode: file-driven fakes for the control plane's keys and answers, see testnode.go).
#              It is what ALL_TEST_NODE_BIN names for the device's tests:
#                export ALL_TEST_NODE_BIN="$PWD/dist/all-tunnel-testnode"
#              It is never deployed.
#   blind-mutant-vm  the same mutant cross-compiled for the gate's VMs (no go toolchain there): dist/all-tunnel-blindmutant-linux-amd64 and dist/all-tunnel-blindmutant-windows.exe.
#              The gate picks them up from dist (or ALL_TEST_BLIND_MUTANT_BIN_LINUX / _WINDOWS) so the blindness selftest runs on the VMs too.
#   blind-mutant  the test node plus ONE test-only change: it terminates a client's TLS itself and logs the request in the clear (blindmutant_test_hook.go).
#              It is the node that the blindness gate must catch; it is not part of `all` and is never deployed.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
version="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
what="${1:-all}"

node() {
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.version=${version}" -o dist/all-tunnel-linux-amd64 .
  shasum -a 256 dist/all-tunnel-linux-amd64 | tee dist/all-tunnel-linux-amd64.sha256
}

test_node() {
  CGO_ENABLED=0 go build -trimpath -tags testnode -ldflags "-X main.version=${version}-testnode" -o dist/all-tunnel-testnode .
  echo "$PWD/dist/all-tunnel-testnode"
}

blind_mutant() {
  CGO_ENABLED=0 go build -trimpath -tags "testnode blindmutant" -ldflags "-X main.version=${version}-blindmutant" -o dist/all-tunnel-blindmutant .
  echo "$PWD/dist/all-tunnel-blindmutant"
}

blind_mutant_vm() {
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags "testnode blindmutant" -ldflags "-X main.version=${version}-blindmutant" -o dist/all-tunnel-blindmutant-linux-amd64 .
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -tags "testnode blindmutant" -ldflags "-X main.version=${version}-blindmutant" -o dist/all-tunnel-blindmutant-windows.exe .
  shasum -a 256 dist/all-tunnel-blindmutant-linux-amd64 dist/all-tunnel-blindmutant-windows.exe
}

chaos_node() {
  local out="${1:-dist/all-tunnel-chaosnode}" policy="${2:-}" overlay=() file=""
  trap '[ -z "$file" ] || rm -f "$file"' RETURN
  if [ -n "$policy" ]; then
    file="$(mktemp)"
    printf '{"Replace":{"%s/policy.json":"%s"}}' "$PWD" "$(cd "$(dirname "$policy")" && pwd)/$(basename "$policy")" > "$file"
    overlay=(-overlay "$file")
  fi
  CGO_ENABLED=0 go build -trimpath -tags testcp ${overlay[@]+"${overlay[@]}"} -ldflags "-X main.version=${version}-chaos" -o "$out" .
  echo "$out"
}

loadgen() {
  local out="${1:-dist/loadgen}"
  CGO_ENABLED=0 go build -trimpath -o "$out" ./cmd/loadgen
  echo "$out"
}

case "$what" in
  node) node ;;
  test-node) test_node ;;
  blind-mutant) blind_mutant ;;
  blind-mutant-vm) blind_mutant_vm ;;
  chaos-node) shift; chaos_node "$@" ;;
  loadgen) shift; loadgen "$@" ;;
  all) node; test_node ;;
  *) echo "usage: build.sh [node|test-node|blind-mutant|blind-mutant-vm|chaos-node [OUT [POLICY]]|loadgen [OUT]|all]" >&2; exit 2 ;;
esac
