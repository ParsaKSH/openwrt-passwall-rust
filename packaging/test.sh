#!/usr/bin/env bash
# Structural checks of the packages produced by packaging/build.sh (run after it, on the VM/CI):
#   packaging/test.sh [dist-dir]
# Verifies the ipk layout (outer tar.gz with debian-binary/data/control like ipkg-build),
# control fields, maintainer scripts, file modes/owners, translations and that the APK v3
# packages (if present) carry the expected metadata.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${1:-$ROOT/dist}"
fail=0
ok() { printf 'ok   %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }
check() { local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check_ipk() {
	local f="$1" kind="$2" d="$tmp/$(basename "$f")"
	mkdir -p "$d"
	tar -xzf "$f" -C "$d" || { bad "$f: outer tar.gz"; return; }
	local members
	members="$(tar -tzf "$f" | tr '\n' ' ')"
	[ "$members" = "./debian-binary ./data.tar.gz ./control.tar.gz " ] || bad "$f: members '$members'"
	[ "$(cat "$d/debian-binary")" = "2.0" ] || bad "$f: debian-binary"
	mkdir -p "$d/c" "$d/r"
	tar -xzf "$d/control.tar.gz" -C "$d/c"
	tar -xzf "$d/data.tar.gz" -C "$d/r"
	local c="$d/c/control" field
	for field in Package Version Architecture Installed-Size Description Maintainer License Section; do
		grep -q "^$field: " "$c" || bad "$f: control lacks $field"
	done
	[ -x "$d/c/postinst" ] && grep -q 'default_postinst' "$d/c/postinst" || bad "$f: postinst"
	[ -x "$d/c/prerm" ] && grep -q 'default_prerm' "$d/c/prerm" || bad "$f: prerm"
	tar -tvzf "$d/data.tar.gz" | awk '{ print $2 }' | grep -vqx '0/0' && bad "$f: files not owned by 0/0"
	if [ "$kind" = bin ]; then
		[ -x "$d/r/usr/bin/passwall2" ] || bad "$f: /usr/bin/passwall2 missing or not executable"
		grep -q '^Depends:' "$c" && bad "$f: static binary must not depend on anything"
	else
		local p
		for p in etc/init.d/passwall2 etc/init.d/passwall2_server etc/uci-defaults/luci-app-passwall2 \
			etc/uci-defaults/luci-app-passwall2_server etc/hotplug.d/iface/98-passwall2 \
			etc/hotplug.d/ntp/30-passwall2-resync usr/libexec/rpcd/luci.passwall2 usr/share/passwall2/haproxy_check.sh; do
			[ -x "$d/r/$p" ] || bad "$f: $p missing or not executable"
		done
		for p in etc/config/passwall2_server usr/share/passwall2/0_default_config usr/share/passwall2/direct_ip \
			usr/share/passwall2/domains_excluded usr/lib/lua/luci/i18n/passwall2.zh-cn.lmo \
			usr/lib/lua/luci/i18n/passwall2.zh-tw.lmo usr/lib/lua/luci/i18n/passwall2.fa.lmo \
			usr/lib/lua/luci/i18n/passwall2.ru.lmo; do
			[ -f "$d/r/$p" ] || bad "$f: $p missing"
		done
		[ -e "$d/r/etc/config/passwall2" ] && bad "$f: must not ship /etc/config/passwall2 (created by uci-defaults)"
		grep -q '^Provides: luci-app-passwall2$' "$c" || bad "$f: Provides"
		grep -q '^Conflicts: luci-app-passwall2' "$c" || bad "$f: Conflicts"
		grep -q '^Depends: passwall2-rs (= ' "$c" || bad "$f: versioned passwall2-rs dependency"
		grep -q 'xray-core | sing-box' "$c" || bad "$f: core alternative"
		[ "$(cat "$d/c/conffiles")" = "$(printf '%s\n' /etc/config/passwall2 /etc/config/passwall2_server /usr/share/passwall2/direct_ip /usr/share/passwall2/domains_excluded)" ] || bad "$f: conffiles"
		grep -q 'rpcd reload' "$d/c/postinst-pkg" || bad "$f: postinst-pkg"
		[ -x "$d/c/postrm" ] && grep -q 'passwall2-update' "$d/c/postrm" && sh -n "$d/c/postrm" || bad "$f: postrm"
		local s
		for s in "$d/r"/etc/init.d/* "$d/r"/etc/uci-defaults/* "$d/r"/etc/hotplug.d/*/* "$d/r/usr/libexec/rpcd/luci.passwall2"; do
			sh -n "$s" || bad "$f: syntax error in ${s#$d/r}"
		done
	fi
	ok "$(basename "$f")"
}

shopt -s nullglob
n=0
for f in "$DIST"/ipk/all/*.ipk; do check_ipk "$f" luci; n=$((n + 1)); done
for f in "$DIST"/ipk/*/passwall2-rs_*.ipk; do check_ipk "$f" bin; n=$((n + 1)); done
[ "$n" -gt 0 ] || bad "no ipk packages in $DIST/ipk"

apks=("$DIST"/apk/*/*.apk)
if [ "${#apks[@]}" -gt 0 ]; then
	if command -v docker >/dev/null 2>&1; then
		for f in "${apks[@]}"; do
			out="$(docker run --rm -v "$(dirname "$f"):/p:ro" "${APK_DOCKER_IMAGE:-alpine:3.23}" apk adbdump "/p/$(basename "$f")" 2>&1)" || { bad "$f: adbdump"; continue; }
			grep -q '^  name: ' <<<"$out" || bad "$f: no name"
			grep -q 'post-install' <<<"$out" || bad "$f: no post-install script"
			grep -q 'pre-deinstall' <<<"$out" || bad "$f: no pre-deinstall script"
			grep -q 'user: root' <<<"$out" || bad "$f: files not owned by root"
			case "$f" in
				*/noarch/*) grep -q 'luci-app-passwall2=' <<<"$out" || bad "$f: provides"
					grep -q 'post-deinstall' <<<"$out" || bad "$f: no post-deinstall script"
					grep -q 'arch: noarch' <<<"$out" || bad "$f: arch" ;;
			esac
			ok "$(basename "$(dirname "$f")")/$(basename "$f")"
		done
	else
		echo "skip apk checks (no docker)"
	fi
fi

# install.sh must know every arch that build.sh publishes
want="$(awk '!/^#/ && NF >= 3 && ($3 == "core" || $3 == "extra") { print $1 }' "$ROOT/packaging/arches.txt" | sort | tr '\n' ' ')"
have="$(sed -n '/^SUPPORTED_ARCHES="/,/"$/p' "$ROOT/install.sh" | sed 's/SUPPORTED_ARCHES=//; s/"//g' | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ')"
[ "$want" = "$have" ] && ok "install.sh SUPPORTED_ARCHES matches packaging/arches.txt" || bad "install.sh SUPPORTED_ARCHES differs from packaging/arches.txt"

[ -s "$DIST/release/SHA256SUMS" ] && (cd "$DIST/release" && sha256sum -c --quiet SHA256SUMS) && ok "SHA256SUMS" || bad "SHA256SUMS"
exit "$fail"
