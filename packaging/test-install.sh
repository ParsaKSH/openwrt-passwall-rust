#!/usr/bin/env bash
# End-to-end tests of install.sh in throwaway OpenWrt containers (run on the build VM, after
# packaging/build.sh):   packaging/test-install.sh [dist-dir]
#
# Everything is offline (--network none, PW2_BASE_URL=file://...). Images are never pulled:
#   OPKG_IMAGE (default pwtest:latest)  OpenWrt 24.10 rootfs with passwall2-rs and its dependencies
#                                       installed (the integration image)
#   APK_IMAGE  (default openwrt/rootfs:x86_64-25.12.6)  stock apk-based OpenWrt rootfs
#   ALPINE_IMAGE (default alpine:3.23)  only used to build fake apk dependency packages
# A missing image skips its tests. Containers are capped with --memory 500m and always removed.
#
# opkg cases: switch from the original luci-app-passwall2 (+ i18n), missing dependency (nothing
# changed), install failure after the removal (original package reinstalled), --version downgrade,
# PW2_TMP=/tmp safety, --uninstall cleanup.
# apk cases: switch in one transaction keeps the shared dependencies and their files, install
# failure leaves the original package and /etc/apk/world untouched.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${1:-$ROOT/dist}"
REL="$DIST/release"
OPKG_IMAGE="${OPKG_IMAGE:-pwtest:latest}"
APK_IMAGE="${APK_IMAGE:-openwrt/rootfs:x86_64-25.12.6}"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.23}"
NAME="pw2-install-test-$$"
fail=0
ok() { printf 'ok   %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }
have_image() { docker image inspect "$1" >/dev/null 2>&1; }

work="$(mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$work"; }
trap cleanup EXIT

[ -f "$REL/VERSION" ] || { echo "no $REL/VERSION: run packaging/build.sh first" >&2; exit 1; }
VERSION="$(cat "$REL/VERSION")"

start() { # start IMAGE: fresh container with procd running, release + install.sh in /root/rel
	docker rm -f "$NAME" >/dev/null 2>&1
	docker run -d --name "$NAME" --memory 500m --network none "$1" /sbin/init >/dev/null || return 1
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		docker exec "$NAME" test -d /var/lock && break
		sleep 1
	done
	docker cp "$REL" "$NAME:/root/rel" >/dev/null
	docker cp "$ROOT/install.sh" "$NAME:/root/install.sh" >/dev/null
}
x() { docker exec "$NAME" sh -c "$1"; }
# run install.sh: inst [env...] -- [args...]; output in $work/out, exit status in $rc
inst() {
	local envs=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=(-e "$1"); shift; done
	[ "${1:-}" = -- ] && shift
	docker exec -e PW2_BASE_URL=file:///root/rel "${envs[@]}" "$NAME" \
		sh /root/install.sh --no-feed --no-dnsmasq-full --minimal "$@" >"$work/out" 2>&1
	rc=$?
}
expect() { # expect DESCRIPTION SHELL-TEST (inside the container)
	if x "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; sed 's/^/     | /' "$work/out" | tail -n 25; fi
}

# shell helpers copied into the containers
cat >"$work/lib.sh" <<'EOF'
# mkipk NAME VERSION DEPENDS ROOTDIR OUT [conffiles]: ipkg-build layout (outer tar.gz)
mkipk() {
	d=/tmp/mkipk.$1; rm -rf "$d"; mkdir -p "$d/c"
	printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: test\nDescription: fake\n' "$1" "$2" >"$d/c/control"
	[ -n "$3" ] && echo "Depends: $3" >>"$d/c/control"
	[ -n "${6:-}" ] && printf '%s\n' "$6" >"$d/c/conffiles"
	(cd "$4" && tar -czf "$d/data.tar.gz" .)
	(cd "$d/c" && tar -czf ../control.tar.gz ./*)
	echo 2.0 >"$d/debian-binary"
	(cd "$d" && tar -czf "$5" ./debian-binary ./data.tar.gz ./control.tar.gz)
	rm -rf "$d"
}
# reipk IN OUT SED-EXPR: rewrite the control file of an ipk
reipk() {
	case "$1" in /*) ;; *) set -- "$PWD/$1" "$2" "$3" ;; esac
	case "$2" in /*) ;; *) set -- "$1" "$PWD/$2" "$3" ;; esac
	d=/tmp/reipk; rm -rf "$d"; mkdir -p "$d/c"
	(cd "$d" && tar -xzf "$1" && tar -xzf control.tar.gz -C c)
	sed -i "$3" "$d/c/control"
	(cd "$d/c" && tar -czf ../control.tar.gz ./*)
	(cd "$d" && tar -czf "$2" ./debian-binary ./data.tar.gz ./control.tar.gz)
	rm -rf "$d"
}
resum() { (cd /root/rel && sha256sum passwall2-rs_* luci-app-passwall2-rs_* >SHA256SUMS); }
# replace passwall2-rs by a fake original luci-app-passwall2 + luci-i18n-passwall2-fa that own
# /etc/config/passwall2 (as upstream does) and depend on tcping/geoview
setup_upstream() {
	cp /etc/config/passwall2 /root/passwall2.orig
	opkg remove luci-app-passwall2-rs passwall2-rs >/dev/null 2>&1
	cp /root/passwall2.orig /etc/config/passwall2
	rm -f /etc/config/passwall2-opkg
	r=/tmp/up; rm -rf $r; mkdir -p $r/etc/config $r/etc/init.d $r/usr/share/passwall2
	cp /root/passwall2.orig $r/etc/config/passwall2
	printf '#!/bin/sh /etc/rc.common\nSTART=99\nstart() { :; }\nstop() { :; }\n' >$r/etc/init.d/passwall2
	chmod 755 $r/etc/init.d/passwall2
	echo upstream >$r/usr/share/passwall2/upstream_marker
	mkipk luci-app-passwall2 25.1.1-r1 "tcping, geoview, xray-core" $r /root/up.ipk /etc/config/passwall2
	r=/tmp/i18n; rm -rf $r; mkdir -p $r/usr/lib/lua/luci/i18n; echo fa >$r/usr/lib/lua/luci/i18n/passwall2.fa.lmo
	mkipk luci-i18n-passwall2-fa 25.1.1-r1 "luci-app-passwall2" $r /root/i18n.ipk
	opkg install /root/up.ipk /root/i18n.ipk >/dev/null 2>&1
	[ -f /usr/lib/opkg/info/luci-app-passwall2.control ] && [ -f /usr/lib/opkg/info/luci-i18n-passwall2-fa.control ]
}
EOF

upstream_intact='[ -f /usr/lib/opkg/info/luci-app-passwall2.control ] && [ -f /usr/lib/opkg/info/luci-i18n-passwall2-fa.control ] && [ -f /usr/share/passwall2/upstream_marker ] && [ -f /usr/lib/lua/luci/i18n/passwall2.fa.lmo ] && [ -x /etc/init.d/passwall2 ] && cmp -s /root/passwall2.orig /etc/config/passwall2'
no_ours='[ ! -f /usr/lib/opkg/info/luci-app-passwall2-rs.control ] && [ ! -f /usr/lib/opkg/info/passwall2-rs.control ]'
no_tmp='! ls -d /tmp/passwall2-rs-install.* >/dev/null 2>&1'

opkg_case() { # opkg_case NAME: fresh container with the helpers and a fake original package
	start "$OPKG_IMAGE" || { bad "$1: container"; return 1; }
	docker cp "$work/lib.sh" "$NAME:/root/lib.sh" >/dev/null
	[ "${2:-}" = keep ] && return 0
	x '. /root/lib.sh; setup_upstream' || { bad "$1: fake upstream setup"; return 1; }
}

if [ -f "$REL/passwall2-rs_x86_64.ipk" ] && have_image "$OPKG_IMAGE"; then
	echo "== opkg ($OPKG_IMAGE)"

	opkg_case swap && {
		inst
		expect "swap: exit 0" "[ $rc = 0 ]"
		expect "swap: new packages at $VERSION" "grep -qx 'Version: $VERSION' /usr/lib/opkg/info/luci-app-passwall2-rs.control && grep -qx 'Version: $VERSION' /usr/lib/opkg/info/passwall2-rs.control"
		expect "swap: original packages removed" "[ ! -f /usr/lib/opkg/info/luci-app-passwall2.control ] && [ ! -f /usr/lib/opkg/info/luci-i18n-passwall2-fa.control ] && [ ! -f /usr/share/passwall2/upstream_marker ]"
		expect "swap: /etc/config/passwall2 kept" "cmp -s /root/passwall2.orig /etc/config/passwall2"
		expect "swap: shared dependencies kept" "[ -f /usr/lib/opkg/info/tcping.control ] && [ -f /usr/lib/opkg/info/geoview.control ]"
		expect "swap: temp dir removed" "$no_tmp"
	}

	opkg_case missing-dep && {
		x 'opkg remove --force-depends tcping >/dev/null 2>&1; [ ! -f /usr/lib/opkg/info/tcping.control ]'
		inst
		expect "missing dependency: exit 1" "[ $rc = 1 ]"
		grep -q 'tcping' "$work/out" && ok "missing dependency: error names tcping" || bad "missing dependency: error names tcping"
		expect "missing dependency: original package untouched" "$upstream_intact"
		expect "missing dependency: nothing of ours installed" "$no_ours"
	}

	opkg_case unreadable && {
		x 'head -c 3000 /root/rel/luci-app-passwall2-rs_all.ipk >/tmp/t && mv /tmp/t /root/rel/luci-app-passwall2-rs_all.ipk; . /root/lib.sh; resum'
		inst
		expect "unreadable package: exit 1" "[ $rc = 1 ]"
		expect "unreadable package: original package untouched" "$upstream_intact"
		expect "unreadable package: nothing of ours installed" "$no_ours"
	}

	opkg_case rollback && {
		# readable package with satisfiable dependencies (passes every check made before the
		# removal) that opkg then refuses: built for another architecture
		x ". /root/lib.sh; cd /root/rel
			reipk passwall2-rs_x86_64.ipk /tmp/b.ipk 's/^Architecture: .*/Architecture: mips_24kc/'
			mv /tmp/b.ipk passwall2-rs_x86_64.ipk; resum"
		inst
		expect "rollback: exit 1" "[ $rc = 1 ]"
		grep -q 'reinstalling the original package' "$work/out" && ok "rollback: announced" || bad "rollback: announced"
		expect "rollback: original package + i18n reinstalled, config intact" "$upstream_intact"
		expect "rollback: nothing of ours left installed" "$no_ours"
		expect "rollback: temp dir removed" "$no_tmp"
	}

	opkg_case downgrade keep && {
		old="26.1.0-r1"
		x ". /root/lib.sh; cd /root/rel
			reipk luci-app-passwall2-rs_all.ipk /tmp/l.ipk 's/^Version: .*/Version: $old/; s/passwall2-rs (= [^)]*)/passwall2-rs (= $old)/'
			reipk passwall2-rs_x86_64.ipk /tmp/b.ipk 's/^Version: .*/Version: $old/'
			mv /tmp/l.ipk luci-app-passwall2-rs_all.ipk; mv /tmp/b.ipk passwall2-rs_x86_64.ipk
			echo $old >VERSION; resum"
		inst -- --version v26.1.0
		expect "downgrade: exit 0" "[ $rc = 0 ]"
		expect "downgrade: both packages at $old" "grep -qx 'Version: $old' /usr/lib/opkg/info/luci-app-passwall2-rs.control && grep -qx 'Version: $old' /usr/lib/opkg/info/passwall2-rs.control"
	}

	opkg_case pw2-tmp keep && {
		x 'echo keep >/tmp/keep-me; mkdir -p /tmp/keep-dir'
		inst PW2_TMP=/tmp -- --force
		expect "PW2_TMP=/tmp: exit 0" "[ $rc = 0 ]"
		expect "PW2_TMP=/tmp: other files in /tmp kept" "[ -f /tmp/keep-me ] && [ -d /tmp/keep-dir ] && [ -d /var/run ] && [ -d /var/lock ]"
		expect "PW2_TMP=/tmp: own dir removed" "$no_tmp"
		x 'mkdir -p /mnt/usb; echo k >/mnt/usb/data'
		inst PW2_TMP=/mnt/usb/ -- --force
		expect "PW2_TMP=/mnt/usb/: exit 0, directory content kept" "[ $rc = 0 ] && [ -f /mnt/usb/data ] && ! ls -d /mnt/usb/passwall2-rs-install.* >/dev/null 2>&1"
	}

	opkg_case uninstall keep && {
		x 'mkdir -p /www/luci-static/resources/passwall2-update && echo {} >/www/luci-static/resources/passwall2-update/1.json; cp /etc/config/passwall2 /root/passwall2.orig'
		inst -- --uninstall
		expect "uninstall: exit 0" "[ $rc = 0 ]"
		expect "uninstall: packages removed" "$no_ours"
		expect "uninstall: self-update status dir removed" "[ ! -e /www/luci-static/resources/passwall2-update ]"
		expect "uninstall: /etc/config/passwall2 kept" "cmp -s /root/passwall2.orig /etc/config/passwall2"
	}

	opkg_case postrm keep && {
		# package postrm: stale status files go, a fresh one (update in progress) stays
		inst -- --force
		expect "postrm: current package installed" "[ $rc = 0 ] && [ -x /usr/lib/opkg/info/luci-app-passwall2-rs.postrm ]"
		x 'd=/www/luci-static/resources/passwall2-update; mkdir -p $d && echo {} >$d/old.json && touch -d "2020-01-01 00:00" $d/old.json'
		x 'opkg remove luci-app-passwall2-rs >/dev/null 2>&1'
		expect "postrm: stale status dir removed" "[ ! -e /www/luci-static/resources/passwall2-update ]"
	}
else
	echo "skip opkg tests (no $REL/passwall2-rs_x86_64.ipk or no image $OPKG_IMAGE)"
fi

if [ -f "$REL/passwall2-rs_x86_64.apk" ] && have_image "$APK_IMAGE" && have_image "$ALPINE_IMAGE"; then
	echo "== apk ($APK_IMAGE)"
	# fake dependencies (the image has no feeds offline) and a fake original package
	mkdir -p "$work/fake"
	cat >"$work/mkfake.sh" <<'EOF'
set -e
mk() {
	r=/tmp/r.$1; rm -rf $r; mkdir -p $r/usr/share/fake; echo $1 >$r/usr/share/fake/$1
	case $1 in
		v2ray-geoip) mkdir -p $r/usr/share/v2ray; echo packaged >$r/usr/share/v2ray/geoip.dat ;;
		luci-app-passwall2) mkdir -p $r/etc/init.d $r/usr/share/passwall2; echo upstream >$r/usr/share/passwall2/upstream_marker
			printf '#!/bin/sh /etc/rc.common\nstart() { :; }\nstop() { :; }\n' >$r/etc/init.d/passwall2; chmod 755 $r/etc/init.d/passwall2 ;;
	esac
	apk mkpkg --info name:$1 --info version:$2 --info arch:noarch --info description:fake \
		--info "depends:$3" --files $r --output /out/$1.apk
}
DEPS="coreutils coreutils-base64 coreutils-nohup coreutils-timeout curl ip-full resolveip tcping geoview v2ray-geoip v2ray-geosite unzip xray-core"
for p in $DEPS; do mk $p 1.0-r1 ""; done
mk luci-app-passwall2 25.1.1-r1 "$DEPS"
mk luci-i18n-passwall2-fa 25.1.1-r1 luci-app-passwall2
EOF
	if docker run --rm --memory 500m --network none -v "$work/fake:/out" -v "$work/mkfake.sh:/mkfake.sh:ro" \
		"$ALPINE_IMAGE" sh /mkfake.sh >/dev/null 2>&1; then
		apk_case() {
			start "$APK_IMAGE" || { bad "$1: container"; return 1; }
			docker cp "$work/fake" "$NAME:/root/fake" >/dev/null
			# installed as dependencies of luci-app-passwall2 only (world lists just the original
			# package), the geodata changed by the rule updater
			x 'cp /etc/apk/world /root/world.base && apk add --allow-untrusted /root/fake/*.apk >/dev/null 2>&1 &&
				{ cat /root/world.base; echo luci-app-passwall2; echo luci-i18n-passwall2-fa; } | sort >/etc/apk/world &&
				echo updated >/usr/share/v2ray/geoip.dat && cp /etc/apk/world /root/world.before &&
				apk info -e luci-app-passwall2 tcping >/dev/null' || { bad "$1: fake upstream setup"; return 1; }
		}
		apk_case apk-swap && {
			inst
			expect "apk swap: exit 0" "[ $rc = 0 ]"
			expect "apk swap: new packages at $VERSION" "apk info -e -v luci-app-passwall2-rs | grep -qx 'luci-app-passwall2-rs-$VERSION' && apk info -e -v passwall2-rs | grep -qx 'passwall2-rs-$VERSION'"
			expect "apk swap: original packages removed" "! apk info -e -v luci-app-passwall2 luci-i18n-passwall2-fa | grep -q -e '^luci-app-passwall2-2' -e '^luci-i18n' && ! grep -q '^luci-app-passwall2\$' /etc/apk/world"
			expect "apk swap: shared dependencies and cores kept" "apk info -e tcping geoview v2ray-geoip xray-core curl | wc -l | grep -qx 5"
			expect "apk swap: updated geodata kept" "grep -qx updated /usr/share/v2ray/geoip.dat"
			expect "apk swap: temp dir removed" "$no_tmp"
		}
		apk_case apk-fail && {
			x 'head -c 3000 /root/rel/luci-app-passwall2-rs_noarch.apk >/tmp/t && mv /tmp/t /root/rel/luci-app-passwall2-rs_noarch.apk &&
				cd /root/rel && sha256sum passwall2-rs_* luci-app-passwall2-rs_* >SHA256SUMS'
			inst
			expect "apk failure: exit 1" "[ $rc = 1 ]"
			expect "apk failure: original package and dependencies untouched" "apk info -e -v luci-app-passwall2 | grep -qx luci-app-passwall2-25.1.1-r1 && apk info -e -v luci-i18n-passwall2-fa | grep -qx luci-i18n-passwall2-fa-25.1.1-r1 && apk info -e tcping geoview xray-core | wc -l | grep -qx 3 && grep -qx updated /usr/share/v2ray/geoip.dat"
			expect "apk failure: /etc/apk/world restored" "cmp -s /root/world.before /etc/apk/world"
			expect "apk failure: nothing of ours installed" "[ ! -f /lib/apk/packages/luci-app-passwall2-rs.list ] && [ ! -f /lib/apk/packages/passwall2-rs.list ]"
		}
	else
		bad "could not build the fake apk packages with $ALPINE_IMAGE"
	fi
else
	echo "skip apk tests (no $REL/passwall2-rs_x86_64.apk or no image $APK_IMAGE / $ALPINE_IMAGE)"
fi

[ "$fail" = 0 ] && echo "all install.sh tests passed"
exit "$fail"
