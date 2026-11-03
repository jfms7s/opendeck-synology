#!/usr/bin/env bash
# Checks a release binary for one target: the right format, signed, and it
# starts. CI and the Release workflow both call this, so a check fixed in one
# is fixed in the other before a tag exists.
#
# Usage: scripts/check-binary.sh <target-triple> <path-to-binary>
#
#   aarch64-apple-darwin       an arm64 Mach-O; on macOS also the ad-hoc
#                              signature and `--version` (on Linux, e.g. the
#                              Release's bundle job, only `file` can check it)
#   aarch64-unknown-linux-gnu  starts under qemu (`--version`)
#   x86_64-unknown-linux-gnu   starts (`--version`)
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <target-triple> <path-to-binary>" >&2
	exit 2
fi
triple=$1
bin=$2
if [[ ! -x $bin ]]; then
	echo "$bin is missing or not executable" >&2
	exit 1
fi

case $triple in
aarch64-apple-darwin)
	file "$bin"
	# macOS's file says "executable arm64", Linux's "arm64 executable".
	if ! file -b "$bin" | grep -Eq '^Mach-O 64-bit (arm64 executable|executable arm64)'; then
		echo "$bin is not an arm64 Mach-O executable" >&2
		exit 1
	fi
	if [[ $(uname -s) == Darwin ]]; then
		# Apple Silicon kills unsigned binaries; the linker's ad-hoc
		# signature must survive `strip = true`.
		codesign --verify --verbose "$bin"
		"$bin" --version
	fi
	;;
aarch64-unknown-linux-gnu)
	qemu-aarch64 -L /usr/aarch64-linux-gnu "$bin" --version
	;;
x86_64-unknown-linux-gnu)
	"$bin" --version
	;;
*)
	echo "no binary check for target $triple" >&2
	exit 1
	;;
esac
