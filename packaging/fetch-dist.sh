#!/bin/sh
# Copy the packages built on the build VM (packaging/build.sh, run through scripts/vm.sh)
# into <repo>/dist/ on this machine. dist/ is never committed (dist/.gitignore = '*').
#   packaging/fetch-dist.sh            # override host/dir with PW_VM / PW_VM_DIR like scripts/vm.sh
set -e
VM="${PW_VM:-root@192.168.122.150}"
DIR="${PW_VM_DIR:-pwr/src}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/dist"
rsync -a --delete --exclude .gitignore --exclude .work "$VM:$DIR/dist/" "$ROOT/dist/"
printf '*\n' >"$ROOT/dist/.gitignore"
find "$ROOT/dist" -type f \( -name '*.ipk' -o -name '*.apk' \) | sed "s|^$ROOT/||" | sort
