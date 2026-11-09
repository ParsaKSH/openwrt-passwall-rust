#!/usr/bin/env bash
# Build passwall2-rs release packages WITHOUT the OpenWrt SDK.
#
#   packaging/build.sh                      # core arches (see packaging/arches.txt), ipk + apk
#   ARCHES="x86_64 arm_cortex-a7_neon-vfpv4" packaging/build.sh
#   ARCHES=all packaging/build.sh           # core + extra arches
#
# Run it on the build VM (never on the laptop):  scripts/vm.sh 'packaging/build.sh'
# then copy the result back with:                packaging/fetch-dist.sh
#
# Produces (in $DIST, default <repo>/dist):
#   ipk/<arch>/passwall2-rs_<ver>_<arch>.ipk        arch-specific binary package
#   ipk/all/luci-app-passwall2-rs_<ver>_all.ipk     LuCI frontend, scripts, data, translations
#   apk/<arch>/passwall2-rs-<ver>.apk               the same as APK v3 packages (OpenWrt >= 25.x)
#   apk/noarch/luci-app-passwall2-rs-<ver>.apk
#   release/                                        flat, version-less names used as GitHub
#                                                   release assets (install.sh downloads these)
#                                                   + SHA256SUMS
#
# Environment knobs:
#   ARCHES        OpenWrt arches to build ("core" default, "all", or a list)
#   PKG_VERSION   package version (default: version of passwall2/Cargo.toml)
#   PKG_RELEASE   package release (default 1) -> version string <PKG_VERSION>-r<PKG_RELEASE>
#   DIST          output directory (default <repo>/dist)
#   NO_IPK=1 / NO_APK=1     skip a package format
#   APK_REQUIRED=1          fail if no apk-tools v3 (`apk mkpkg`) can be found
#   APK           path to an apk-tools v3 binary with `mkpkg` (else: `apk` in PATH, else docker
#                 image $APK_DOCKER_IMAGE (default alpine:3.23), else APK packages are skipped)
#   NO_BUILD=1    reuse binaries already in $CARGO_TARGET_DIR (no cargo invocation)
#   RUSTUP_ADD=1  `rustup target add` missing Rust targets (default 1)
#   PO2LMO        path to po2lmo (default: built from LuCI sources, cached in $PW_CACHE)
#   LUCI_GIT / LUCI_REF     LuCI source for po2lmo (default openwrt/luci, openwrt-24.10)
#   PW_CACHE      tool cache directory (default ~/.cache/passwall2-rs)
#   JSMIN=1       minify JS with LuCI's jsmin like luci.mk does by default (off: keeps sources readable)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKGDIR="$ROOT/packaging"
LUCIDIR="$ROOT/luci-app-passwall2"
DIST="${DIST:-$ROOT/dist}"
WORK="$DIST/.work"
PW_CACHE="${PW_CACHE:-$HOME/.cache/passwall2-rs}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
ARCHES="${ARCHES:-core}"
PKG_RELEASE="${PKG_RELEASE:-1}"
RUSTUP_ADD="${RUSTUP_ADD:-1}"
APK_DOCKER_IMAGE="${APK_DOCKER_IMAGE:-alpine:3.23}"
LUCI_GIT="${LUCI_GIT:-https://github.com/openwrt/luci.git}"
LUCI_REF="${LUCI_REF:-openwrt-24.10}"
URL="https://github.com/ParsaKSH/openwrt-passwall-rust"
MAINTAINER="ParsaKSH <https://github.com/ParsaKSH>"
LICENSE="GPL-3.0-only"

# Runtime dependencies (upstream luci-app-passwall2 LUCI_DEPENDS minus the Lua runtime, which is
# not used any more: libuci-lua lua luci-compat luci-lib-jsonc lyaml).
LUCI_DEPENDS="libc luci-base rpcd coreutils coreutils-base64 coreutils-nohup coreutils-timeout curl ip-full resolveip tcping geoview v2ray-geoip v2ray-geosite unzip"
# Upstream defaults to the Xray and/or sing-box core; opkg can express the alternative.
CORE_ALTERNATIVE="xray-core | sing-box"
# Upstream translation packages ship the same .lmo files we bundle.
I18N_PKGS="luci-i18n-passwall2-fa luci-i18n-passwall2-ru luci-i18n-passwall2-zh-cn luci-i18n-passwall2-zh-tw"
CONFFILES="/etc/config/passwall2
/etc/config/passwall2_server
/usr/share/passwall2/direct_ip
/usr/share/passwall2/domains_excluded"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------ version
if [ -z "${PKG_VERSION:-}" ]; then
	PKG_VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/passwall2/Cargo.toml" | head -n1)"
fi
[ -n "$PKG_VERSION" ] || die "cannot determine PKG_VERSION"
VERSION="${PKG_VERSION}-r${PKG_RELEASE}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
TAR_OPTS=(--format=gnu --numeric-owner --owner=0 --group=0 --sort=name "--mtime=@$SOURCE_DATE_EPOCH")

# ------------------------------------------------------------------ arch table
# rust_target_of <openwrt_arch> -> prints the rust target ("" if unknown)
rust_target_of() {
	awk -v a="$1" '!/^#/ && NF >= 3 && $1 == a { print $2; exit }' "$PKGDIR/arches.txt"
}
arch_set_of() {
	awk -v a="$1" '!/^#/ && NF >= 3 && $1 == a { print $3; exit }' "$PKGDIR/arches.txt"
}
select_arches() {
	case "$ARCHES" in
		core) awk '!/^#/ && NF >= 3 && $3 == "core" { print $1 }' "$PKGDIR/arches.txt" ;;
		all) awk '!/^#/ && NF >= 3 && ($3 == "core" || $3 == "extra") { print $1 }' "$PKGDIR/arches.txt" ;;
		*) for a in $ARCHES; do echo "$a"; done ;;
	esac
}

SELECTED=()
while read -r a; do
	[ -n "$a" ] || continue
	t="$(rust_target_of "$a")"
	[ -n "$t" ] || die "unknown OpenWrt arch '$a' (see packaging/arches.txt)"
	if [ "$(arch_set_of "$a")" = "sdk" ]; then
		warn "$a ($t) has no prebuilt Rust std; build it with the OpenWrt SDK (luci-app-passwall2/Makefile). Skipping."
		continue
	fi
	SELECTED+=("$a")
done < <(select_arches)
[ "${#SELECTED[@]}" -gt 0 ] || die "no architectures selected"

TARGETS=()
for a in "${SELECTED[@]}"; do
	t="$(rust_target_of "$a")"
	case " ${TARGETS[*]-} " in *" $t "*) ;; *) TARGETS+=("$t") ;; esac
done

rm -rf "$WORK"
mkdir -p "$WORK" "$DIST" "$PW_CACHE"

# ------------------------------------------------------------------ 1. binaries
build_binary() {
	local t="$1" envname flagsname
	envname="CARGO_TARGET_$(echo "$t" | tr 'a-z-' 'A-Z_')_LINKER"
	flagsname="CARGO_TARGET_$(echo "$t" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
	if [ -z "${NO_BUILD:-}" ]; then
		if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -x "$t" >/dev/null; then
			[ "$RUSTUP_ADD" = 1 ] || die "Rust target $t is not installed (rustup target add $t)"
			log "rustup target add $t"
			rustup target add "$t"
		fi
		log "cargo build --release --target $t"
		# rust-lld links the self-contained musl CRT shipped with each target's std; force a
		# static binary (some musl targets, e.g. riscv64gc/loongarch64, default to dynamic)
		env "$envname=${!envname:-rust-lld}" "$flagsname=${!flagsname:--C target-feature=+crt-static}" \
			cargo build --manifest-path "$ROOT/Cargo.toml" -p passwall2 --release --target "$t"
	fi
	local bin="$TARGET_DIR/$t/release/passwall2"
	[ -f "$bin" ] || die "binary not found: $bin"
	mkdir -p "$WORK/bin/$t"
	cp "$bin" "$WORK/bin/$t/passwall2"
}
for t in "${TARGETS[@]}"; do build_binary "$t"; done

# ------------------------------------------------------------------ 2. po2lmo / jsmin (host tools from LuCI)
luci_src() {
	local src="$PW_CACHE/luci-$LUCI_REF"
	if [ ! -f "$src/modules/luci-base/src/po2lmo.c" ]; then
		log "fetching LuCI sources ($LUCI_REF) for po2lmo"
		rm -rf "$src"
		git clone -q --depth 1 --filter=blob:none --sparse -b "$LUCI_REF" "$LUCI_GIT" "$src" >&2
		git -C "$src" sparse-checkout set modules/luci-base/src >&2
	fi
	echo "$src/modules/luci-base/src"
}
host_tool() {
	local name="$1" s
	if [ -x "$PW_CACHE/bin/$name" ]; then echo "$PW_CACHE/bin/$name"; return; fi
	s="$(luci_src)"
	log "building $name"
	make -s -C "$s" "$name" CC="${HOSTCC:-cc}" >&2
	mkdir -p "$PW_CACHE/bin"
	cp "$s/$name" "$PW_CACHE/bin/$name"
	echo "$PW_CACHE/bin/$name"
}
if [ -z "${PO2LMO:-}" ]; then
	if command -v po2lmo >/dev/null 2>&1; then PO2LMO="$(command -v po2lmo)"; else PO2LMO="$(host_tool po2lmo)"; fi
fi

# ------------------------------------------------------------------ 3. staging trees
# set_modes <root>: executables 0755, everything else 0644, directories 0755
set_modes() {
	local r="$1"
	find "$r" -type d -exec chmod 0755 {} +
	find "$r" -type f -exec chmod 0644 {} +
	local p
	for p in usr/bin usr/sbin etc/init.d etc/uci-defaults etc/hotplug.d usr/libexec/rpcd; do
		[ -d "$r/$p" ] && find "$r/$p" -type f -exec chmod 0755 {} +
	done
	find "$r" -type f -name '*.sh' -exec chmod 0755 {} +
}

stage_luci() {
	local r="$WORK/luci-root"
	mkdir -p "$r"
	[ -d "$LUCIDIR/root" ] && cp -R "$LUCIDIR/root/." "$r/"
	if [ -d "$LUCIDIR/htdocs" ]; then
		mkdir -p "$r/www"
		cp -R "$LUCIDIR/htdocs/." "$r/www/"
	fi
	# drop editor/VCS leftovers
	find "$r" \( -name '*~' -o -name '*.orig' -o -name '*.rej' -o -name '.git*' -o -name '.DS_Store' \) -exec rm -rf {} + 2>/dev/null || true
	if [ "${JSMIN:-0}" = 1 ] && [ -d "$r/www" ]; then
		local jsmin src
		jsmin="$(host_tool jsmin)"
		while IFS= read -r src; do
			if "$jsmin" <"$src" >"$src.o"; then mv "$src.o" "$src"; else rm -f "$src.o"; fi
		done < <(find "$r/www" -type f -name '*.js')
	fi
	# translations: same language codes/aliases as luci.mk (zh_Hans -> zh-cn, zh_Hant -> zh-tw)
	local d lang po n=0
	mkdir -p "$r/usr/lib/lua/luci/i18n"
	for d in "$LUCIDIR"/po/*; do
		[ -d "$d" ] || continue
		lang="$(basename "$d")"
		case "$lang" in
			templates) continue ;;
			zh_Hans) lang=zh-cn ;;
			zh_Hant) lang=zh-tw ;;
			pt_BR) lang=pt-br ;;
			bn_BD) lang=bn ;;
			nb_NO) lang=no ;;
			zh-cn) [ -e "$LUCIDIR/po/zh_Hans" ] && continue ;;
			zh-tw) [ -e "$LUCIDIR/po/zh_Hant" ] && continue ;;
		esac
		for po in "$d"/*.po; do
			[ -f "$po" ] || continue
			"$PO2LMO" "$po" "$r/usr/lib/lua/luci/i18n/$(basename "$po" .po).$lang.lmo"
			n=$((n + 1))
		done
	done
	log "compiled $n translation catalog(s)"
	set_modes "$r"
}
stage_luci

stage_bin() {
	local t="$1" r="$WORK/bin-root/$1"
	mkdir -p "$r/usr/bin"
	cp "$WORK/bin/$t/passwall2" "$r/usr/bin/passwall2"
	set_modes "$r"
}
for t in "${TARGETS[@]}"; do stage_bin "$t"; done

# ------------------------------------------------------------------ 4. maintainer scripts (as OpenWrt generates them)
LUCI_POSTINST_PKG='#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] || { rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload 2>/dev/null
	exit 0
}'
# the backend binary changes the rpcd method list: let rpcd re-read it
BIN_POSTINST_PKG='#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] || {
	[ -x /usr/libexec/rpcd/luci.passwall2 ] && /etc/init.d/rpcd reload 2>/dev/null
	exit 0
}'

# The backend's self-update writes progress files to /www/luci-static/resources/passwall2-update/
# (owned by no package). Clean it up when the LuCI package is removed. Files younger than 5 minutes
# are kept: opkg runs the removal scripts of the old package on --force-reinstall, which is
# exactly when a self-update is reporting progress there.
LUCI_POSTRM='#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
d=/www/luci-static/resources/passwall2-update
[ -d "$d" ] || exit 0
find "$d" -type f -mmin +5 -exec rm -f {} + 2>/dev/null
rmdir "$d" 2>/dev/null
exit 0'

IPK_POSTINST='#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_postinst $0 $@'
IPK_PRERM='#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_prerm $0 $@'

# ------------------------------------------------------------------ 5. ipk (same layout as OpenWrt's ipkg-build)
# mk_ipk <name> <arch> <rootdir> <depends> <provides> <conflicts> <description> <postinst-pkg> <conffiles> <outdir> [postrm]
mk_ipk() {
	local name="$1" arch="$2" root="$3" depends="$4" provides="$5" conflicts="$6" desc="$7" pinst="$8" conff="$9" outdir="${10}" postrm="${11:-}"
	local tmp="$WORK/ipk.$name.$arch" section=net
	[ "${name#luci-}" != "$name" ] && section=luci
	rm -rf "$tmp"
	mkdir -p "$tmp/control" "$outdir"
	(cd "$root" && tar "${TAR_OPTS[@]}" -cpf - .) | gzip -9n >"$tmp/data.tar.gz"
	local isize
	isize="$(gzip -dc "$tmp/data.tar.gz" | wc -c | tr -d ' ')"
	{
		echo "Package: $name"
		echo "Version: $VERSION"
		[ -n "$depends" ] && echo "Depends: $depends"
		[ -n "$provides" ] && echo "Provides: $provides"
		[ -n "$conflicts" ] && echo "Conflicts: $conflicts"
		[ -n "$conflicts" ] && echo "Replaces: $conflicts"
		echo "Source: $URL"
		echo "SourceName: $name"
		echo "License: $LICENSE"
		echo "Section: $section"
		echo "SourceDateEpoch: $SOURCE_DATE_EPOCH"
		echo "URL: $URL"
		echo "Maintainer: $MAINTAINER"
		echo "Architecture: $arch"
		echo "Installed-Size: $isize"
		printf 'Description: '
		echo "$desc" | sed -e 's,^[[:space:]]*, ,g'
	} >"$tmp/control/control"
	printf '%s\n' "$IPK_POSTINST" >"$tmp/control/postinst"
	printf '%s\n' "$IPK_PRERM" >"$tmp/control/prerm"
	[ -n "$pinst" ] && printf '%s\n' "$pinst" >"$tmp/control/postinst-pkg"
	[ -n "$conff" ] && printf '%s\n' "$conff" >"$tmp/control/conffiles"
	[ -n "$postrm" ] && printf '%s\n' "$postrm" >"$tmp/control/postrm"
	chmod 0644 "$tmp/control/"*
	chmod 0755 "$tmp/control/postinst" "$tmp/control/prerm"
	[ -f "$tmp/control/postrm" ] && chmod 0755 "$tmp/control/postrm"
	[ -f "$tmp/control/postinst-pkg" ] && chmod 0755 "$tmp/control/postinst-pkg"
	(cd "$tmp/control" && tar "${TAR_OPTS[@]}" -cf - .) | gzip -9n >"$tmp/control.tar.gz"
	echo "2.0" >"$tmp/debian-binary"
	local out="$outdir/${name}_${VERSION}_${arch}.ipk"
	(cd "$tmp" && tar "${TAR_OPTS[@]}" -cf - ./debian-binary ./data.tar.gz ./control.tar.gz) | gzip -9n >"$out"
	rm -rf "$tmp"
	log "built $(basename "$out")"
}

# ------------------------------------------------------------------ 6. apk (APK v3 via `apk mkpkg`, as OpenWrt's package-pack.mk)
APK_MODE=""
# has_mkpkg <apk command...>: `apk mkpkg --help` exits 1, so look at what it prints
has_mkpkg() { { "$@" mkpkg --help 2>&1 || true; } | grep -c -- '--files' >/dev/null; }
find_apk() {
	if [ -n "${APK:-}" ]; then
		has_mkpkg "$APK" || die "APK=$APK has no mkpkg applet (apk-tools v3 required)"
		APK_MODE=native; return
	fi
	if command -v apk >/dev/null 2>&1 && has_mkpkg apk; then
		APK="$(command -v apk)"; APK_MODE=native; return
	fi
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
		if docker image inspect "$APK_DOCKER_IMAGE" >/dev/null 2>&1 || docker pull -q "$APK_DOCKER_IMAGE" >/dev/null; then
			if has_mkpkg docker run --rm "$APK_DOCKER_IMAGE" apk; then
				APK_MODE=docker; return
			fi
		fi
	fi
	APK_MODE=""
}

# mk_apk <name> <arch> <rootdir> <depends(space sep)> <provides> <description> <postinst-pkg> <conffiles> <outdir> [postrm]
mk_apk() {
	local name="$1" arch="$2" root="$3" depends="$4" provides="$5" desc="$6" pinst="$7" conff="$8" outdir="$9" postrm="${10:-}"
	local tmp="$WORK/apk.$name.$arch"
	rm -rf "$tmp"
	mkdir -p "$tmp/files" "$tmp/scripts" "$outdir"
	cp -a "$root/." "$tmp/files/"
	local meta="$tmp/files/lib/apk/packages"
	mkdir -p "$meta"
	# file list, conffiles and conffiles_static exactly like package-pack.mk
	(cd "$tmp/files" && find . \( -type f -o -type l \) -printf '/%P\n' | sort) >"$tmp/list"
	mv "$tmp/list" "$meta/$name.list"
	if [ -n "$conff" ]; then
		printf '%s\n' "$conff" >"$meta/$name.conffiles"
		local f
		while IFS= read -r f; do
			[ -f "$tmp/files/$f" ] || continue
			echo "$f $(sha256sum "$tmp/files/$f" | cut -d' ' -f1)" >>"$meta/$name.conffiles_static"
		done <<<"$conff"
	fi
	chmod 0755 "$tmp/files/lib" "$tmp/files/lib/apk" "$meta"
	chmod 0644 "$meta"/*
	find "$tmp/files" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	{
		echo '#!/bin/sh'
		echo '[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0'
		echo '[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0'
		echo '. ${IPKG_INSTROOT}/lib/functions.sh'
		echo 'export root="${IPKG_INSTROOT}"'
		echo "export pkgname=\"$name\""
		echo 'add_group_and_user'
		echo 'default_postinst'
		[ -n "$pinst" ] && printf '%s\n' "$pinst" | sed '/^\s*#!/d'
	} >"$tmp/scripts/post-install"
	{
		echo '#!/bin/sh'
		echo 'export PKG_UPGRADE=1'
		sed '/^\s*#!/d' "$tmp/scripts/post-install"
	} >"$tmp/scripts/post-upgrade"
	{
		echo '#!/bin/sh'
		echo '[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0'
		echo '. ${IPKG_INSTROOT}/lib/functions.sh'
		echo 'export root="${IPKG_INSTROOT}"'
		echo "export pkgname=\"$name\""
		echo 'default_prerm'
	} >"$tmp/scripts/pre-deinstall"
	[ -n "$postrm" ] && printf '%s\n' "$postrm" >"$tmp/scripts/post-deinstall"
	chmod 0755 "$tmp/scripts/"*
	local apkarch="$arch"
	[ "$arch" = all ] && apkarch=noarch
	local out="$outdir/$name-$VERSION.apk"
	local args=(
		--info "name:$name"
		--info "version:$VERSION"
		--info "description:$desc"
		--info "arch:$apkarch"
		--info "license:$LICENSE"
		--info "origin:$name"
		--info "url:$URL"
		--info "maintainer:$MAINTAINER"
	)
	[ -n "$provides" ] && args+=(--info "provides:$provides")
	args+=(
		--script "post-install:$tmp/scripts/post-install"
		--script "post-upgrade:$tmp/scripts/post-upgrade"
		--script "pre-deinstall:$tmp/scripts/pre-deinstall"
	)
	[ -n "$postrm" ] && args+=(--script "post-deinstall:$tmp/scripts/post-deinstall")
	args+=(
		--info "depends:$depends"
		--files "$tmp/files"
		--output "$out"
	)
	case "$APK_MODE" in
		native)
			if [ "$(id -u)" = 0 ]; then
				chown -R 0:0 "$tmp/files"
				"$APK" mkpkg "${args[@]}"
			elif command -v fakeroot >/dev/null 2>&1; then
				fakeroot -- sh -c 'chown -R 0:0 "$1" && shift && exec "$@"' sh "$tmp/files" "$APK" mkpkg "${args[@]}"
			else
				warn "not root and no fakeroot: files in $(basename "$out") keep uid $(id -u)"
				"$APK" mkpkg "${args[@]}"
			fi
			;;
		docker)
			# files are copied inside the container so that they are owned by root:root there
			local inner=() a from="$tmp/files" to=/tmp/pkgroot
			for a in "${args[@]}"; do inner+=("${a//"$from"/$to}"); done
			docker run --rm -e "OUT=$out" -v "$tmp:$tmp" -v "$outdir:$outdir" "$APK_DOCKER_IMAGE" sh -c \
				'mkdir -p /tmp/pkgroot && cp -a "$1/." /tmp/pkgroot/ && chown -R 0:0 /tmp/pkgroot && shift && apk mkpkg "$@" && chown '"$(id -u):$(id -g)"' "$OUT"' \
				sh "$tmp/files" "${inner[@]}"
			;;
	esac
	[ -f "$out" ] || die "apk mkpkg failed for $name ($arch)"
	rm -rf "$tmp"
	log "built $(basename "$(dirname "$out")")/$(basename "$out")"
}

# ------------------------------------------------------------------ 7. assemble
rm -rf "$DIST/ipk" "$DIST/apk" "$DIST/release"
mkdir -p "$DIST/release"

LUCI_DESC="LuCI support for PassWall 2 (passwall2-rs: Rust backend, LuCI JS frontend). Drop-in replacement for luci-app-passwall2 using the same configuration."
BIN_DESC="PassWall 2 backend (Rust): service runtime, Xray/sing-box config generators, firewall, DNS, subscriptions and rpcd backend for luci-app-passwall2-rs."

ipk_luci_depends() {
	local d out="passwall2-rs (= $VERSION)"
	for d in $LUCI_DEPENDS; do out="$out, $d"; done
	echo "$out, $CORE_ALTERNATIVE"
}
apk_luci_depends() {
	# apk has no "a | b" alternatives: the proxy core is left to install.sh / the user.
	local d out="passwall2-rs=$VERSION"
	for d in $LUCI_DEPENDS; do [ "$d" = libc ] || out="$out $d"; done
	for d in $I18N_PKGS; do out="$out !$d"; done
	echo "$out"
}
ipk_conflicts() {
	local d out="luci-app-passwall2"
	for d in $I18N_PKGS; do out="$out, $d"; done
	echo "$out"
}

if [ -z "${NO_IPK:-}" ]; then
	mk_ipk luci-app-passwall2-rs all "$WORK/luci-root" "$(ipk_luci_depends)" "luci-app-passwall2" \
		"$(ipk_conflicts)" "$LUCI_DESC" "$LUCI_POSTINST_PKG" "$CONFFILES" "$DIST/ipk/all" "$LUCI_POSTRM"
	cp "$DIST/ipk/all/luci-app-passwall2-rs_${VERSION}_all.ipk" "$DIST/release/luci-app-passwall2-rs_all.ipk"
	for a in "${SELECTED[@]}"; do
		t="$(rust_target_of "$a")"
		mk_ipk passwall2-rs "$a" "$WORK/bin-root/$t" "" "" "" "$BIN_DESC" "$BIN_POSTINST_PKG" "" "$DIST/ipk/$a"
		cp "$DIST/ipk/$a/passwall2-rs_${VERSION}_${a}.ipk" "$DIST/release/passwall2-rs_${a}.ipk"
	done
fi

if [ -z "${NO_APK:-}" ]; then
	find_apk
	if [ -z "$APK_MODE" ]; then
		[ -n "${APK_REQUIRED:-}" ] && die "apk-tools v3 (apk mkpkg) not available; set APK=... or install docker"
		warn "apk-tools v3 (apk mkpkg) not available (no APK=, no apk in PATH, no docker): skipping APK packages"
	else
		log "apk mkpkg via $APK_MODE"
		mk_apk luci-app-passwall2-rs all "$WORK/luci-root" "$(apk_luci_depends)" "luci-app-passwall2=$VERSION" \
			"$LUCI_DESC" "$LUCI_POSTINST_PKG" "$CONFFILES" "$DIST/apk/noarch" "$LUCI_POSTRM"
		cp "$DIST/apk/noarch/luci-app-passwall2-rs-$VERSION.apk" "$DIST/release/luci-app-passwall2-rs_noarch.apk"
		for a in "${SELECTED[@]}"; do
			t="$(rust_target_of "$a")"
			mk_apk passwall2-rs "$a" "$WORK/bin-root/$t" "" "" "$BIN_DESC" "$BIN_POSTINST_PKG" "" "$DIST/apk/$a"
			cp "$DIST/apk/$a/passwall2-rs-$VERSION.apk" "$DIST/release/passwall2-rs_${a}.apk"
		done
	fi
fi

# bare binaries (handy for testing) + checksums
for t in "${TARGETS[@]}"; do
	cp "$WORK/bin/$t/passwall2" "$DIST/release/passwall2-$t"
done
cp "$ROOT/install.sh" "$DIST/release/install.sh"
echo "$VERSION" >"$DIST/release/VERSION"
(cd "$DIST/release" && sha256sum -- * | grep -v ' SHA256SUMS$' >SHA256SUMS)

rm -rf "$WORK"
log "done: version $VERSION, ${#SELECTED[@]} arch(es) -> $DIST"
