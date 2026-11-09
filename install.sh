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
#   4. removes the original luci-app-passwall2 (+ its translation packages) if installed,
#      KEEPING /etc/config/passwall2, /etc/config/passwall2_server and the direct/excluded lists
#   5. installs the packages and the recommended extras, then restarts the service
#
# Options:
#   --version TAG       install release TAG (e.g. v26.11.0) instead of the latest one
#   --mirror PREFIX     prefix GitHub URLs with PREFIX (e.g. https://gh-proxy.org/)
#   --minimal           only install the packages and their hard dependencies
#   --no-feed           never add the Openwrt-Passwall packages feed
#   --no-dnsmasq-full   do not replace dnsmasq with dnsmasq-full
#   --force             reinstall even if the same version is installed
#   --uninstall         remove passwall2-rs (configuration is kept)
#   -h, --help          this help
#
# Environment: PW2_REPO (default ParsaKSH/openwrt-passwall-rust), PW2_TMP (download dir),
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
TMPD="${PW2_TMP:-/tmp/passwall2-rs-install.$$}"
BACKUP="$TMPD/backup"
FEED_BASE="https://master.dl.sourceforge.net/project/openwrt-passwall-build"
KEEP_FILES="/etc/config/passwall2 /etc/config/passwall2_server /usr/share/passwall2/direct_ip /usr/share/passwall2/domains_excluded"
UPSTREAM_PKGS="luci-app-passwall2 luci-i18n-passwall2-fa luci-i18n-passwall2-ru luci-i18n-passwall2-zh-cn luci-i18n-passwall2-zh-tw"

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
	printf "${C_E}ERROR:${C_N} %s\n" "$*" >&2
	restore_backup 2>/dev/null
	rm -rf "$TMPD"
	exit 1
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
		[ -f "/lib/apk/packages/$1.list" ]
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

rm -rf "$TMPD"
mkdir -p "$TMPD" || die "cannot create $TMPD"

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
for p in geoview tcping; do pkg_available "$p" || need_feed=1; done
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

# ------------------------------------------------------------------ remove the original package
backup_configs
for p in $UPSTREAM_PKGS; do
	if pkg_installed_exact "$p"; then
		REMOVE="${REMOVE:-} $p"
	fi
done
if [ -n "${REMOVE:-}" ]; then
	info "removing original:${REMOVE} (configuration is kept)"
	[ -x /etc/init.d/passwall2 ] && /etc/init.d/passwall2 stop >/dev/null 2>&1
	# shellcheck disable=SC2086
	pm_remove $REMOVE || die "could not remove${REMOVE}"
	restore_backup
fi

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

# ------------------------------------------------------------------ install
info "installing passwall2-rs $NEW_VERSION"
if [ "$PM" = apk ]; then
	set -- --allow-untrusted
	[ "$FORCE" = 1 ] && set -- "$@" --force-reinstall
	apk add "$@" "$TMPD/$BIN_FILE" "$TMPD/$LUCI_FILE" || die "installation failed"
else
	set --
	[ "$FORCE" = 1 ] && set -- --force-reinstall
	opkg install "$@" "$TMPD/$BIN_FILE" "$TMPD/$LUCI_FILE" || die "installation failed"
fi
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
