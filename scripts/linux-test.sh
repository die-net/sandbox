#!/bin/bash
# Build this package's tests for Linux and run them on a Linux machine.
# Extra arguments go to the test binary, e.g.
#   scripts/linux-test.sh -test.run TestIsolation -test.v
#
# Targets:
#   default          the sbx-dev Lima VM (Debian 13, arm64, bubblewrap from
#                    apt). SBX_VM names another Lima VM, such as sbx-ubuntu.
#   SBX_SSH=u@host   a machine reached by passwordless ssh, whose architecture
#                    comes from uname -m, e.g. SBX_SSH=user@host.
#   SBX_LOCAL=1      this machine, which must be Linux. CI uses it.
#
# CGO=1 builds with cgo; the default is CGO_ENABLED=0, as releases are. Cgo
# needs a C compiler for the target, which the host usually lacks, so CGO=1
# copies the sources to the target and builds there. The target needs go
# (on PATH, /usr/local/go/bin, or /usr/local/bin) and gcc.
#
# RACE=1 builds with the race detector, which needs cgo on Linux, so it goes
# with CGO=1.
#
# SBX_APPARMOR=1 loads the AppArmor profile for the test binary before the
# tests and removes it after, with scripts/apparmor.sh. Ubuntu 24.04 and 26.04 need it.
# Without it the tests fail there, which is the library's behavior.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cd "$root"

cgo=${CGO:-0}
race=
if [ -n "${RACE:-}" ]; then
	if [ "$cgo" != 1 ]; then
		echo "RACE=1 needs CGO=1, since the race detector needs cgo on Linux" >&2
		exit 1
	fi
	race=-race
fi
args=$(printf " %q" "$@")

# rsh <cmd> runs a shell command on the target, in /tmp. put <file> <dest>
# copies a file there.
if [ -n "${SBX_LOCAL:-}" ]; then
	target=local
	rsh() { (cd /tmp && sh -c "$1"); }
	put() { cp "$1" "$2"; }
	arch=$(uname -m)
elif [ -n "${SBX_SSH:-}" ]; then
	target=$SBX_SSH
	rsh() { ssh "$target" "cd /tmp && $1"; }
	put() { scp -q "$1" "$target:$2"; }
	arch=$(rsh 'uname -m')
else
	target=${SBX_VM:-sbx-dev}
	rsh() { limactl shell --workdir /tmp "$target" -- sh -c "$1"; }
	put() { limactl copy "$1" "$target:$2"; }
	arch=$(rsh 'uname -m')
fi
case $arch in
x86_64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*) echo "unsupported architecture $arch on $target" >&2; exit 1 ;;
esac

# The binary goes in its own directory: the tests make that directory
# readable inside the sandbox, and it must not be /tmp itself, which the
# sandbox covers.
rdir=/tmp/sandbox-run-$$
remote=$rdir/sandbox.test
rsh "mkdir $rdir"
# The AppArmor profile is removed here, once its load has started, so an
# interrupt or a failed load doesn't leave it behind, loaded and in
# /etc/apparmor.d, on a path another account could create under /tmp.
loaded=
cleanup() {
	if [ -n "$loaded" ]; then
		rsh "$rdir/apparmor.sh remove $remote" || true
	fi
	rsh "rm -rf $rdir" || true
	rm -rf "$out"
}
trap cleanup EXIT
trap 'exit 1' HUP INT QUIT TERM

if [ -n "${SBX_LOCAL:-}" ]; then
	CGO_ENABLED=$cgo go test -c $race -o "$out/sandbox.test" .
	put "$out/sandbox.test" "$remote"
elif [ "$cgo" = 1 ]; then
	tar --no-xattrs -c --exclude=.git --exclude=spikes . >"$out/src.tar"
	put "$out/src.tar" "$rdir/src.tar"
	rsh "mkdir $rdir/src && tar -x -C $rdir/src -f $rdir/src.tar && rm $rdir/src.tar && cd $rdir/src && PATH=\$PATH:/usr/local/go/bin:/usr/local/bin CGO_ENABLED=1 go test -c $race -o $remote ."
else
	GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go test -c -o "$out/sandbox.test" .
	put "$out/sandbox.test" "$remote"
fi
if [ -z "${SBX_LOCAL:-}" ]; then
	for a in amd64 arm64 arm; do
		GOOS=linux GOARCH=$a CGO_ENABLED=0 go vet ./... >/dev/null
	done
fi

rc=0
if [ -n "${SBX_APPARMOR:-}" ]; then
	put scripts/apparmor.sh "$rdir/apparmor.sh"
	rsh "chmod +x $remote $rdir/apparmor.sh"
	loaded=1
	rsh "$rdir/apparmor.sh load $remote"
	rsh "$remote$args" || rc=$?
else
	rsh "chmod +x $remote && $remote$args" || rc=$?
fi
exit $rc
