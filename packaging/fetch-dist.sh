#!/bin/sh
# Copy the packages built on the build VM (packaging/build.sh, run through scripts/vm.sh)
# into <repo>/dist/ on this machine. dist/ is never committed (dist/.gitignore = '*').
#   packaging/fetch-dist.sh            # override host/dir with PW_VM / PW_VM_DIR like scripts/vm.sh
set -e
VM="${PW_VM:-root@192.168.122.150}"
DIR="${PW_VM_DIR:-pwr/src}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/dist"
# only the build outputs are mirrored (with --delete inside each of them): everything else under
# dist/ (scratch directories, notes, ...) belongs to this machine and is left alone
for d in ipk apk release; do
	if ssh "$VM" "test -d '$DIR/dist/$d'"; then
		mkdir -p "$ROOT/dist/$d"
		rsync -a --delete "$VM:$DIR/dist/$d/" "$ROOT/dist/$d/"
	else
		rm -rf "${ROOT:?}/dist/$d"
	fi
done
printf '*\n' >"$ROOT/dist/.gitignore"
find "$ROOT/dist" -type f \( -name '*.ipk' -o -name '*.apk' \) | sed "s|^$ROOT/||" | sort
