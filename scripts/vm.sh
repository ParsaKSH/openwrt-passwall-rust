#!/bin/sh
# Run a command on the build VM inside a synced copy of this repo.
#   scripts/vm.sh 'cargo check'        scripts/vm.sh 'cargo test'
# Builds never happen on the local machine. Override host with PW_VM=user@host.
set -e
VM="${PW_VM:-root@192.168.122.150}"
DIR="${PW_VM_DIR:-pwr/src}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rsync -a --delete --exclude target --exclude .git --exclude dist "$ROOT/" "$VM:$DIR/"
exec ssh "$VM" ". ~/.cargo/env 2>/dev/null; cd ~/$DIR && export CARGO_TARGET_DIR=~/pwr/target && $*"
