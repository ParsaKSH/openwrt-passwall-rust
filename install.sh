#!/bin/sh
# passwall2-rs one-command installer for OpenWrt routers.
#
#   wget -qO- https://github.com/ParsaKSH/openwrt-passwall-rust/releases/latest/download/install.sh | sh
#   (or: curl -fsSL <same url> | sh -s -- [options])
#
# What it does:
#   1. detects OpenWrt release, package architecture and package manager (opkg or apk)
#   2. downloads the matching passwall2-rs + luci-app-passwall2-rs packages from GitHub releases
#   3. makes sure the dependencies (xray-core/sing-box, geoview, tcping, chinadns-ng, ...) can be
#      found, adding the Openwrt-Passwall "passwall_packages" feed when they are missing
#   4. checks that every dependency can be satisfied, then replaces the original
#      luci-app-passwall2 (+ its translation packages) if installed, KEEPING /etc/config/passwall2,
#      /etc/config/passwall2_server and the direct/excluded lists. On apk the switch is one
#      transaction; on opkg a copy of the original package is kept and reinstalled if the
#      installation fails.
#   5. installs the packages and the recommended extras, then restarts the service
#
# Options:
#   --version TAG       install release TAG (e.g. v26.11.0) instead of the latest one
#                       (an older release downgrades the installed one)
#   --mirror PREFIX     prefix GitHub URLs with PREFIX (e.g. https://gh-proxy.org/)
#   --minimal           only install the packages and their hard dependencies
#   --no-feed           never add the Openwrt-Passwall packages feed
#   --no-dnsmasq-full   do not replace dnsmasq with dnsmasq-full
#   --force             reinstall even if the same version is installed
#   --uninstall         remove passwall2-rs (configuration is kept)
#   -h, --help          this help
#
# Environment: PW2_REPO (default ParsaKSH/openwrt-passwall-rust), PW2_TMP (parent of the private
#              download dir, default /tmp; only the passwall2-rs-install.* dir inside it is deleted),
#              PW2_BASE_URL (download packages from this URL instead of GitHub releases).

set -u

REPO="${PW2_REPO:-ParsaKSH/openwrt-passwall-rust}"
TAG=""
MIRROR=""
MINIMAL=0
ADD_FEED=1
DNSMASQ_FULL=1
FORCE=0
UNINSTALL=0
TMPD=""   # private work dir, created by make_tmpdir (never a user-supplied path: it is rm -rf'd)
BACKUP=""
FEED_BASE="https://master.dl.sourceforge.net/project/openwrt-passwall-build"
KEEP_FILES="/etc/config/passwall2 /etc/config/passwall2_server /usr/share/passwall2/direct_ip /usr/share/passwall2/domains_excluded"
UPSTREAM_PKGS="luci-app-passwall2 luci-i18n-passwall2-fa luci-i18n-passwall2-ru luci-i18n-passwall2-zh-cn luci-i18n-passwall2-zh-tw"
# runtime state written by the backend's self-update (owned by no package)
UPDATE_STATUS_DIR="/www/luci-static/resources/passwall2-update"
# rollback state (see rollback())
REMOVE=""             # original packages that are being replaced
UPSTREAM_REMOVED=0    # opkg: they were removed
WORLD_SAVED=0         # apk: /etc/apk/world was edited, the original copy is $TMPD/world
SERVICE_STOPPED=0
BIN_WAS_INSTALLED=0

# Architectures published as release assets (keep in sync with packaging/arches.txt "core"+"extra").
SUPPORTED_ARCHES="x86_64 aarch64_generic aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76
arm_cortex-a5_vfpv4 arm_cortex-a7_neon-vfpv4 arm_cortex-a7_vfpv4 arm_cortex-a8_vfpv3 arm_cortex-a9_neon
arm_cortex-a9_vfpv3-d16 arm_cortex-a15_neon-vfpv4 arm_arm1176jzf-s_vfp arm_cortex-a7 arm_cortex-a9
arm_mpcore arm_arm926ej-s arm_xscale i386_pentium4 i386_pentium-mmx riscv64_riscv64 riscv64_generic
loongarch64_generic"

if [ -t 1 ]; then
	C_I='\033[1;34m' C_W='\033[1;33m' C_E='\033[1;31m' C_O='\033[1;32m' C_N='\033[0m'
else
	C_I='' C_W='' C_E='' C_O='' C_N=''
fi
info() { printf "${C_I}==>${C_N} %s\n" "$*"; }
ok() { printf "${C_O}==>${C_N} %s\n" "$*"; }
warn() { printf "${C_W}WARN:${C_N} %s\n" "$*" >&2; }
die() {
	trap - INT TERM HUP
	printf "${C_E}ERROR:${C_N} %s\n" "$*" >&2
	rollback
	restore_backup 2>/dev/null
	[ -n "$TMPD" ] && rm -rf "$TMPD"
	exit 1
}

# Undo a failed switch from the original package (called by die()). Functions used here are
# defined further down; they are only reached once the state flags are set, i.e. after that.
rollback() {
	local p f missing
	[ "$WORLD_SAVED$UPSTREAM_REMOVED$SERVICE_STOPPED" = 000 ] && return 0
	# the new packages are in place: nothing to undo
	pkg_installed_exact luci-app-passwall2-rs && return 0
	if [ "$WORLD_SAVED" = 1 ]; then
		# apk: the switch is a single transaction, so a failure left the installed set alone
		warn "restoring /etc/apk/world"
		cp -p "$TMPD/world" /etc/apk/world
		missing=""
		for p in $REMOVE; do pkg_installed_exact "$p" || missing="$missing $p"; done
		# shellcheck disable=SC2086
		[ -z "$missing" ] || apk add $missing >/dev/null 2>&1 ||
			warn "could not reinstall${missing}; run: apk add${missing}"
	fi
	if [ "$UPSTREAM_REMOVED" = 1 ]; then
		warn "reinstalling the original package:${REMOVE}"
		if [ "$BIN_WAS_INSTALLED" = 0 ] && pkg_installed_exact passwall2-rs; then
			opkg remove passwall2-rs >/dev/null 2>&1
		fi
		set --
		for p in $REMOVE; do
			for f in "$TMPD/upstream/${p}_"*.ipk; do [ -f "$f" ] && set -- "$@" "$f"; done
		done
		# shellcheck disable=SC2086
		{ [ $# -gt 0 ] && opkg install "$@" >/dev/null 2>&1; } || opkg install $REMOVE >/dev/null 2>&1 ||
			warn "could not reinstall${REMOVE}; run: opkg install${REMOVE}"
		restore_backup 2>/dev/null
	fi
	if [ "$SERVICE_STOPPED" = 1 ] && [ -x /etc/init.d/passwall2 ] &&
		[ "$(uci -q get passwall2.@global[0].enabled)" = 1 ]; then
		/etc/init.d/passwall2 restart >/dev/null 2>&1
	fi
	return 0
}

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0" 2>/dev/null || echo "see https://github.com/$REPO"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--version) TAG="${2:-}"; shift ;;
		--version=*) TAG="${1#*=}" ;;
		--mirror) MIRROR="${2:-}"; shift ;;
		--mirror=*) MIRROR="${1#*=}" ;;
		--minimal) MINIMAL=1 ;;
		--no-feed) ADD_FEED=0 ;;
		--no-dnsmasq-full) DNSMASQ_FULL=0 ;;
		--force) FORCE=1 ;;
		--uninstall) UNINSTALL=1 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage; exit 1 ;;
	esac
	shift
done

# ------------------------------------------------------------------ environment
[ "$(id -u)" = 0 ] || die "run as root"
[ -f /etc/openwrt_release ] || die "this is not OpenWrt (/etc/openwrt_release missing)"
. /etc/openwrt_release
RELEASE="${DISTRIB_RELEASE:-}"

if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then
	PM=apk
	EXT=apk
	ARCH="$(apk --print-arch 2>/dev/null)"
elif command -v opkg >/dev/null 2>&1; then
	PM=opkg
	EXT=ipk
	ARCH="$(opkg print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { print $3, $2 }' | sort -n | tail -n 1 | cut -d' ' -f2)"
else
	die "neither opkg nor apk found"
fi
[ -n "$ARCH" ] || ARCH="${DISTRIB_ARCH:-}"
[ -n "$ARCH" ] || die "cannot determine the package architecture"

case "$ARCH" in
	x86_64|aarch64*|arm*|i386*) CORE_ALL=1 ;;
	*) CORE_ALL=0 ;;
esac

# PW2_TMP is only the parent: the script works in (and deletes) a fresh directory of its own.
make_tmpdir() {
	local parent="${PW2_TMP:-/tmp}"
	parent="${parent%/}"
	[ -n "$parent" ] || parent=/
	[ -d "$parent" ] || mkdir -p "$parent" || die "cannot create $parent"
	TMPD="$(mktemp -d "$parent/passwall2-rs-install.XXXXXX" 2>/dev/null)" || TMPD=""
	if [ -z "$TMPD" ] || [ ! -d "$TMPD" ]; then
		# no mktemp: mkdir without -p fails instead of reusing an existing directory
		TMPD="$parent/passwall2-rs-install.$$"
		mkdir "$TMPD" || { TMPD=""; die "cannot create a temporary directory in $parent"; }
	fi
	BACKUP="$TMPD/backup"
}
make_tmpdir
trap 'die "interrupted"' INT TERM HUP

# ------------------------------------------------------------------ helpers
fetch() { # fetch URL FILE   (file:///dir/... = offline install from a local directory)
	case "$1" in
		file://*) cp "${1#file://}" "$2"; return ;;
	esac
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 2 --connect-timeout 15 -o "$2" "$1"
	else
		wget -q -T 30 -O "$2" "$1"
	fi
}

pkg_installed() {
	if [ "$PM" = apk ]; then
		apk info -e "$1" >/dev/null 2>&1
	else
		[ -n "$(opkg list-installed "$1" 2>/dev/null | awk -v p="$1" '$1 == p')" ]
	fi
}

# exact package name (not a virtual name provided by another package, e.g. our own
# luci-app-passwall2-rs provides luci-app-passwall2)
pkg_installed_exact() {
	if [ "$PM" = apk ]; then
		[ -f "/lib/apk/packages/$1.list" ] || [ -n "$(pkg_version "$1")" ]
	else
		[ -f "/usr/lib/opkg/info/$1.control" ]
	fi
}

pkg_available() {
	if [ "$PM" = apk ]; then
		apk search -e "$1" 2>/dev/null | grep -q "^$1-[0-9]"
	else
		[ -n "$(opkg list "$1" 2>/dev/null | awk -v p="$1" '$1 == p')" ]
	fi
}

# installed version of an exact package name (empty if not installed)
pkg_version() {
	if [ "$PM" = apk ]; then
		apk info -e -v "$1" 2>/dev/null | sed -n "s/^$1-\([0-9].*\)/\1/p" | head -n 1
	else
		sed -n 's/^Version: *//p' "/usr/lib/opkg/info/$1.control" 2>/dev/null | head -n 1
	fi
}

# control file of an ipk (outer tar.gz with ./control.tar.gz, as made by ipkg-build)
ipk_control() {
	tar -xzOf "$1" ./control.tar.gz 2>/dev/null | tar -xzOf - ./control 2>/dev/null
}
ipk_depends() { ipk_control "$1" | sed -n 's/^Depends: *//p'; }

# print the dependency groups of the given ipks that no installed or available package satisfies
# (alternatives "a | b" are satisfied by either; version constraints are not checked)
missing_ipk_depends() {
	local f
	for f in "$@"; do ipk_depends "$f"; echo; done | tr ',' '\n' | sed 's/([^)]*)//g; s/|/ /g' |
		while read -r alts; do
			[ -n "$alts" ] || continue
			found=0
			for a in $alts; do
				case "$a" in passwall2-rs) found=1; break ;; esac # shipped next to it
				if pkg_installed "$a" || pkg_available "$a"; then found=1; break; fi
			done
			[ "$found" = 1 ] || echo "$alts" | sed 's/ / | /g'
		done
}

# rebuild an installed opkg package from its database entry so that it can be reinstalled
# offline (the feeds may be unreachable once the original proxy is gone)
repack_ipk() { # repack_ipk NAME OUTDIR
	local p="$1" out="$2" info=/usr/lib/opkg/info d s f
	d="$TMPD/repack.$p"
	[ -f "$info/$p.control" ] && [ -f "$info/$p.list" ] || return 1
	rm -rf "$d"
	mkdir -p "$d/control" "$out" || return 1
	grep -v '^Status:\|^Installed-Time:\|^Auto-Installed:' "$info/$p.control" >"$d/control/control"
	for s in conffiles preinst postinst prerm postrm postinst-pkg prerm-pkg; do
		[ -f "$info/$p.$s" ] && cp -p "$info/$p.$s" "$d/control/$s"
	done
	# list entries are files and symlinks (opkg may append a tab and the mode); skip deleted ones
	while IFS= read -r f; do
		f="${f%%	*}"
		[ -L "$f" ] || { [ -e "$f" ] && [ ! -d "$f" ]; } || continue
		echo ".$f"
	done <"$info/$p.list" >"$d/files"
	(cd / && tar -czf "$d/data.tar.gz" -T "$d/files") || return 1
	(cd "$d/control" && tar -czf ../control.tar.gz ./*) || return 1
	echo "2.0" >"$d/debian-binary"
	(cd "$d" && tar -czf "$out/${p}_repack.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz) || return 1
	rm -rf "$d"
}

# keep installable copies of the packages that are about to be removed
save_upstream() {
	local p
	mkdir -p "$TMPD/upstream"
	for p in "$@"; do
		repack_ipk "$p" "$TMPD/upstream" && continue
		(cd "$TMPD/upstream" && opkg download "$p" >/dev/null 2>&1) && continue
		warn "could not keep a copy of $p; if the installation fails it is reinstalled from the feeds"
	done
}

pm_update() {
	info "updating package lists"
	if [ "$PM" = apk ]; then apk update >/dev/null 2>&1 || warn "apk update reported errors"
	else opkg update >/dev/null 2>&1 || warn "opkg update reported errors"; fi
}

pm_install() { # names or files
	if [ "$PM" = apk ]; then apk add --allow-untrusted "$@"
	else opkg install "$@"; fi
}

pm_remove() {
	if [ "$PM" = apk ]; then apk del "$@"
	else opkg remove "$@"; fi
}

# best-effort install of optional packages, one at a time
install_optional() {
	local p
	for p in "$@"; do
		pkg_installed "$p" && continue
		# virtual packages (opkg cannot query providers by name)
		case "$p" in
			nftables) command -v nft >/dev/null 2>&1 && continue ;;
			iptables) command -v iptables >/dev/null 2>&1 && continue ;;
		esac
		if pkg_available "$p"; then
			info "installing $p"
			pm_install "$p" >/dev/null 2>&1 || warn "could not install $p"
		else
			warn "$p is not available in the configured feeds, skipped"
		fi
	done
}

backup_configs() {
	local f
	mkdir -p "$BACKUP"
	for f in $KEEP_FILES /etc/config/dhcp; do
		[ -f "$f" ] || continue
		mkdir -p "$BACKUP${f%/*}"
		cp -p "$f" "$BACKUP$f"
	done
}

# restore user files that a package removal/installation dropped or replaced
restore_backup() {
	local f
	[ -d "$BACKUP" ] || return 0
	# /etc/config/dhcp is only put back when a dnsmasq swap lost it (uci-defaults edit it later)
	[ -f "$BACKUP/etc/config/dhcp" ] && [ ! -f /etc/config/dhcp ] && cp -p "$BACKUP/etc/config/dhcp" /etc/config/dhcp
	for f in $KEEP_FILES; do
		[ -f "$BACKUP$f" ] || continue
		if [ ! -f "$f" ] || ! cmp -s "$BACKUP$f" "$f"; then
			mkdir -p "${f%/*}"
			cp -p "$BACKUP$f" "$f"
		fi
	done
	# remove package-manager leftovers of the restored conffiles
	for f in $KEEP_FILES; do
		rm -f "$f-opkg" "$f.apk-new"
	done
}

# ------------------------------------------------------------------ uninstall
if [ "$UNINSTALL" = 1 ]; then
	info "removing passwall2-rs (configuration is kept)"
	backup_configs
	[ -x /etc/init.d/passwall2 ] && /etc/init.d/passwall2 stop >/dev/null 2>&1
	[ -x /etc/init.d/passwall2_server ] && /etc/init.d/passwall2_server stop >/dev/null 2>&1
	pm_remove luci-app-passwall2-rs passwall2-rs || die "package removal failed"
	restore_backup
	rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null
	rm -rf /tmp/luci-modulecache
	rm -rf "$UPDATE_STATUS_DIR"
	/etc/init.d/rpcd restart >/dev/null 2>&1
	rm -rf "$TMPD"
	ok "passwall2-rs removed; /etc/config/passwall2 kept"
	exit 0
fi

# ------------------------------------------------------------------ download
info "OpenWrt ${RELEASE:-?} (${DISTRIB_TARGET:-?}), arch $ARCH, package manager $PM"
case " $(echo $SUPPORTED_ARCHES) " in
	*" $ARCH "*) ;;
	*) die "no prebuilt package for $ARCH. Build it with the OpenWrt SDK: see https://github.com/$REPO#building" ;;
esac

if [ -n "${PW2_BASE_URL:-}" ]; then
	BASE="$PW2_BASE_URL"
elif [ -n "$TAG" ]; then
	BASE="${MIRROR}https://github.com/$REPO/releases/download/$TAG"
else
	BASE="${MIRROR}https://github.com/$REPO/releases/latest/download"
fi
if [ "$PM" = apk ]; then
	BIN_FILE="passwall2-rs_${ARCH}.apk"
	LUCI_FILE="luci-app-passwall2-rs_noarch.apk"
else
	BIN_FILE="passwall2-rs_${ARCH}.ipk"
	LUCI_FILE="luci-app-passwall2-rs_all.ipk"
fi

for f in VERSION SHA256SUMS "$BIN_FILE" "$LUCI_FILE"; do
	info "downloading $f"
	fetch "$BASE/$f" "$TMPD/$f" || die "download failed: $BASE/$f"
	[ -s "$TMPD/$f" ] || die "downloaded file is empty: $f"
done
NEW_VERSION="$(cat "$TMPD/VERSION")"
if command -v sha256sum >/dev/null 2>&1; then
	for f in "$BIN_FILE" "$LUCI_FILE"; do
		want="$(awk -v f="$f" '$2 == f || $2 == "*"f { print $1 }' "$TMPD/SHA256SUMS")"
		got="$(sha256sum "$TMPD/$f" | cut -d' ' -f1)"
		[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $f"
	done
	ok "checksums verified"
fi

# ------------------------------------------------------------------ feeds & dependencies
pm_update

need_feed=0
for p in geoview tcping; do pkg_installed "$p" || pkg_available "$p" || need_feed=1; done
if [ "$need_feed" = 1 ]; then
	if [ "$ADD_FEED" = 1 ]; then
		case "$RELEASE" in
			*SNAPSHOT*|"") warn "snapshot build: add a packages feed providing geoview/tcping manually" ;;
			*)
				rel="${RELEASE%.*}"
				feed="$FEED_BASE/releases/packages-$rel/$ARCH/passwall_packages"
				info "adding Openwrt-Passwall packages feed ($feed)"
				if [ "$PM" = apk ]; then
					fetch "$FEED_BASE/apk.pub" "$TMPD/passwall.pem" && cp "$TMPD/passwall.pem" /etc/apk/keys/passwall.pem ||
						warn "could not fetch the feed key"
					mkdir -p /etc/apk/repositories.d
					touch /etc/apk/repositories.d/customfeeds.list
					grep -q "/passwall_packages/" /etc/apk/repositories.d/customfeeds.list ||
						echo "$feed/packages.adb" >>/etc/apk/repositories.d/customfeeds.list
				else
					if fetch "$FEED_BASE/ipk.pub" "$TMPD/passwall.pub"; then
						opkg-key add "$TMPD/passwall.pub" >/dev/null 2>&1 || warn "opkg-key add failed"
					else
						warn "could not fetch the feed key"
					fi
					grep -q " passwall_packages " /etc/opkg/customfeeds.conf 2>/dev/null ||
						echo "src/gz passwall_packages $feed" >>/etc/opkg/customfeeds.conf
				fi
				pm_update
				;;
		esac
	else
		warn "geoview/tcping not available and --no-feed given: installation may fail"
	fi
fi

# user files a package removal/installation below may drop (restored by restore_backup)
backup_configs

# ------------------------------------------------------------------ dnsmasq-full (needed for nftset/ipset DNS rules)
if [ "$MINIMAL" = 0 ] && [ "$DNSMASQ_FULL" = 1 ] && ! pkg_installed dnsmasq-full && pkg_installed dnsmasq; then
	if pkg_available dnsmasq-full; then
		info "replacing dnsmasq with dnsmasq-full"
		# download both first: once dnsmasq is removed the router has no DNS resolver
		mkdir -p "$TMPD/dnsmasq"
		if [ "$PM" = apk ]; then
			(cd "$TMPD/dnsmasq" && apk fetch dnsmasq-full dnsmasq >/dev/null 2>&1)
		else
			(cd "$TMPD/dnsmasq" && opkg download dnsmasq-full >/dev/null 2>&1 && opkg download dnsmasq >/dev/null 2>&1)
		fi
		pkgfile="$(ls "$TMPD"/dnsmasq/dnsmasq-full[-_]* 2>/dev/null | head -n 1)"
		origfile="$(ls "$TMPD"/dnsmasq/dnsmasq[-_][0-9]* 2>/dev/null | head -n 1)"
		if [ -n "$pkgfile" ]; then
			pm_remove dnsmasq >/dev/null 2>&1
			# the files were verified against the signed index when fetched; a lone .apk has no signature
			if [ "$PM" = apk ]; then apk add --allow-untrusted "$pkgfile" >/dev/null 2>&1; else opkg install "$pkgfile" >/dev/null 2>&1; fi || {
				warn "dnsmasq-full install failed, restoring dnsmasq"
				if [ -n "$origfile" ]; then pm_install "$origfile" >/dev/null 2>&1; else pm_install dnsmasq >/dev/null 2>&1; fi
			}
			restore_backup
			/etc/init.d/dnsmasq restart >/dev/null 2>&1
		else
			warn "could not download dnsmasq-full, keeping dnsmasq"
		fi
	else
		warn "dnsmasq-full is not available, keeping dnsmasq"
	fi
fi

# ------------------------------------------------------------------ proxy cores (upstream default: Xray + sing-box on arm/aarch64/x86, else Xray)
if ! pkg_installed xray-core && ! pkg_installed sing-box; then
	if [ "$PM" = apk ] || [ "$MINIMAL" = 0 ]; then
		if [ "$CORE_ALL" = 1 ] && [ "$MINIMAL" = 0 ]; then
			install_optional xray-core sing-box
		else
			install_optional xray-core
		fi
	fi
fi
# The generated configs follow upstream PassWall 2, which targets current Xray/sing-box
# releases (e.g. Xray >= 26 stream "method"); the OpenWrt base feed often ships much older
# cores. Upgrade installed cores when a newer build (e.g. from the passwall feed) exists.
if [ "$MINIMAL" = 0 ]; then
	for p in xray-core sing-box; do
		pkg_installed "$p" || continue
		if [ "$PM" = apk ]; then
			apk upgrade "$p" >/dev/null 2>&1 && info "upgraded $p (if a newer build was available)"
		elif opkg list-upgradable 2>/dev/null | awk -v p="$p" '$1 == p { f = 1 } END { exit !f }'; then
			info "upgrading $p"
			opkg upgrade "$p" >/dev/null 2>&1 || warn "could not upgrade $p"
		fi
	done
fi

# ------------------------------------------------------------------ replace the original package and install
# Nothing is removed before it is known that the new packages can be installed, and a failure
# puts the original package back (see rollback()).
for p in $UPSTREAM_PKGS; do
	pkg_installed_exact "$p" && REMOVE="$REMOVE $p"
done
pkg_installed_exact passwall2-rs && BIN_WAS_INSTALLED=1
OLD_VERSION="$(pkg_version luci-app-passwall2-rs)"

stop_upstream() {
	[ -n "$REMOVE" ] && [ -x /etc/init.d/passwall2 ] || return 0
	/etc/init.d/passwall2 stop >/dev/null 2>&1
	SERVICE_STOPPED=1
}

info "installing passwall2-rs $NEW_VERSION${OLD_VERSION:+ (installed: $OLD_VERSION)}"
if [ "$PM" = apk ]; then
	set -- --allow-untrusted
	[ "$FORCE" = 1 ] && set -- "$@" --force-reinstall
	set -- "$@" "$TMPD/$BIN_FILE" "$TMPD/$LUCI_FILE"
	if [ -n "$REMOVE" ]; then
		info "replacing original:${REMOVE} (configuration is kept)"
		# One solver run: drop the original packages from world and add ours. A separate
		# `apk del` would also purge every dependency only they pulled in (geoview, tcping,
		# geodata with the updated rules, ...) and our install would have to download them again.
		# The proxy cores the original package pulled in are kept explicitly: our apk package
		# cannot depend on "xray-core | sing-box".
		for p in xray-core sing-box; do pkg_installed_exact "$p" && set -- "$@" "$p"; done
		cp -p /etc/apk/world "$TMPD/world" || die "cannot back up /etc/apk/world"
		WORLD_SAVED=1
		awk -v rm=" $REMOVE " '{ n = $0; sub(/[<>=~].*/, "", n) } index(rm, " " n " ") == 0' \
			"$TMPD/world" >"$TMPD/world.new" && cat "$TMPD/world.new" >/etc/apk/world ||
			die "cannot update /etc/apk/world"
	fi
	apk add --simulate "$@" >"$TMPD/simulate.log" 2>&1 || {
		grep -v '^WARNING' "$TMPD/simulate.log" >&2
		die "the packages cannot be installed (see above); nothing was changed"
	}
	stop_upstream
	apk add "$@" || die "installation failed"
else
	for f in "$BIN_FILE" "$LUCI_FILE"; do
		ipk_control "$TMPD/$f" | grep -q '^Package: ' || die "$f is not a readable package; nothing was changed"
	done
	missing="$(missing_ipk_depends "$TMPD/$BIN_FILE" "$TMPD/$LUCI_FILE" | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
	[ -z "$missing" ] || die "not installed and not available in the configured feeds: $missing." \
		"Nothing was changed. Run 'opkg update' and check the passwall_packages feed in /etc/opkg/customfeeds.conf"
	if [ -n "$REMOVE" ]; then
		info "replacing original:${REMOVE} (configuration is kept)"
		# shellcheck disable=SC2086
		save_upstream $REMOVE
		stop_upstream
		UPSTREAM_REMOVED=1
		# one package per call, translations first: opkg refuses to remove luci-app-passwall2
		# while a package that depends on it is still installed, even in the same command
		for p in $(echo $REMOVE | tr ' ' '\n' | sort -r); do
			opkg remove "$p" || die "could not remove $p"
		done
		restore_backup
	fi
	set --
	[ "$FORCE" = 1 ] && set -- --force-reinstall
	# --version TAG may be older than what is installed: opkg skips downgrades unless told
	if [ -n "$OLD_VERSION" ] && opkg compare-versions "$OLD_VERSION" '>>' "$NEW_VERSION" 2>/dev/null; then
		info "downgrading from $OLD_VERSION"
		set -- "$@" --force-downgrade
	fi
	opkg install "$@" "$TMPD/$BIN_FILE" "$TMPD/$LUCI_FILE" || die "installation failed"
fi
for p in passwall2-rs luci-app-passwall2-rs; do
	v="$(pkg_version "$p")"
	[ "$v" = "$NEW_VERSION" ] || die "$p is at version ${v:-<not installed>} after installing $NEW_VERSION"
done
trap - INT TERM HUP
restore_backup
[ -s /etc/config/passwall2 ] || cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2

# ------------------------------------------------------------------ recommended extras (upstream Kconfig defaults)
if [ "$MINIMAL" = 0 ]; then
	if [ -x /sbin/fw4 ] || command -v fw4 >/dev/null 2>&1; then
		install_optional nftables kmod-nft-socket kmod-nft-tproxy kmod-nft-nat chinadns-ng
	else
		install_optional chinadns-ng ipset iptables iptables-mod-conntrack-extra iptables-mod-extra \
			iptables-mod-iprange iptables-mod-socket iptables-mod-tproxy ip6tables-mod-nat kmod-ipt-nat
	fi
	install_optional shadowsocksr-libev-ssr-local shadowsocksr-libev-ssr-redir simple-obfs-client
	case "$ARCH" in
		x86_64|aarch64*|arm*|i386*) install_optional haproxy v2ray-plugin ;;
	esac
	case "$ARCH" in
		x86_64|aarch64*) install_optional shadowsocks-rust-sslocal ;;
	esac
fi

# ------------------------------------------------------------------ restart
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null
rm -rf /tmp/luci-modulecache
/etc/init.d/rpcd restart >/dev/null 2>&1
/etc/init.d/passwall2 enable >/dev/null 2>&1
/etc/init.d/passwall2_server enable >/dev/null 2>&1
if [ "$(uci -q get passwall2.@global[0].enabled)" = 1 ]; then
	info "restarting passwall2"
	/etc/init.d/passwall2 restart >/dev/null 2>&1
fi
if [ "$(uci -q get passwall2_server.global.enable)" = 1 ]; then
	/etc/init.d/passwall2_server restart >/dev/null 2>&1
fi
rm -rf "$TMPD"
ok "passwall2-rs $NEW_VERSION installed. Open LuCI -> Services -> PassWall 2."
