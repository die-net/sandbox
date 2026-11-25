#!/bin/sh
# Load or remove the AppArmor profile the library prints for a test binary,
# which Ubuntu 24.04 and 26.04 need before a sandbox can start.
#   scripts/apparmor.sh load   /path/to/sandbox.test
#   scripts/apparmor.sh remove /path/to/sandbox.test
# It runs where the binary runs, as the test account, and uses sudo. The
# profile comes from the binary itself (TestWriteApparmorProfile), so it is
# the one Probe prints. It is for the binary's exact path.
set -eu
op=$1
bin=$2
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
SBX_APPARMOR_OUT=$dir "$bin" -test.run '^TestWriteApparmorProfile$' >/dev/null
for f in "$dir"/*; do
	name=$(basename "$f")
	case $op in
	load)
		sudo install -m 644 "$f" "/etc/apparmor.d/$name"
		sudo apparmor_parser -r "/etc/apparmor.d/$name"
		;;
	remove)
		sudo apparmor_parser -R "/etc/apparmor.d/$name" || true
		sudo rm -f "/etc/apparmor.d/$name"
		;;
	esac
done
