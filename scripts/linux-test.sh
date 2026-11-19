#!/bin/bash
# Cross-compile this package's tests for Linux and run them in the sbx-dev
# Lima VM (Debian 13, arm64, bubblewrap from apt). Extra arguments go to the
# test binary, e.g. scripts/linux-test.sh -test.run TestIsolation -test.v
#
# CGO=1 builds with cgo; the default is CGO_ENABLED=0, as releases are.
set -euo pipefail

vm=${SBX_VM:-sbx-dev}
root=$(cd "$(dirname "$0")/.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

cd "$root"
GOOS=linux GOARCH=arm64 CGO_ENABLED=${CGO:-0} go test -c -o "$out/sandbox.test" .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./... >/dev/null

# The binary goes in its own directory: the tests make that directory
# readable inside the sandbox, and it must not be /tmp itself, which the
# sandbox covers.
rdir=/tmp/sandbox-test-$$
remote=$rdir/sandbox.test
limactl shell --workdir /tmp "$vm" -- mkdir "$rdir"
limactl copy "$out/sandbox.test" "$vm:$remote"
limactl shell --workdir /tmp "$vm" -- sh -c "chmod +x $remote && $remote $* ; rc=\$?; rm -rf $rdir; exit \$rc"
