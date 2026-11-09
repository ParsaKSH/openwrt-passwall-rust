#!/bin/sh
# Self-update installer of passwall2-rs (started in the background by the rpc backend):
#   luci_update.sh <dir> <status-json> <opkg|apk> <force 0|1>
# <dir> holds luci-app-passwall2-rs.<ext> and passwall2-rs.<ext> downloaded from our GitHub release.
CONFIG=passwall2
dir="$1"
status="$2"
manager="$3"
force="$4"

acl_file="/usr/share/rpcd/acl.d/luci-app-${CONFIG}.json"
acl_md5_before=$(md5sum "$acl_file" 2>/dev/null | awk '{print $1}')

[ "$manager" = apk ] && extension=apk || extension=ipk
set -- "$dir/passwall2-rs.${extension}" "$dir/luci-app-${CONFIG}-rs.${extension}"

if [ "$manager" = apk ]; then
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall --force-overwrite"
	apk add --allow-untrusted $extra "$@" >"$dir.log" 2>&1
	result=$?
else
	extra=""
	[ "$force" = 1 ] && extra="--force-reinstall"
	opkg install $extra "$@" >"$dir.log" 2>&1
	result=$?
fi

rm -rf "$dir"
if [ "$result" = 0 ]; then
	rm -f "$dir.log" "/tmp/etc/${CONFIG}_tmp/${CONFIG}_version" /tmp/luci-indexcache /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	acl_md5_after=$(md5sum "$acl_file" 2>/dev/null | awk '{print $1}')
	# rpcd reads ACL definitions only at startup: restart it only when the ACL changed
	if [ "$acl_md5_before" != "$acl_md5_after" ] && [ -x /etc/init.d/rpcd ]; then
		/etc/init.d/rpcd restart >/dev/null 2>&1
	elif [ -x /etc/init.d/rpcd ]; then
		/etc/init.d/rpcd reload >/dev/null 2>&1
	fi
	if [ -x /etc/init.d/uhttpd ]; then
		/etc/init.d/uhttpd reload >/dev/null 2>&1
	fi
fi
[ "$result" = 0 ] && echo '{"code":0}' > "$status" || echo '{"code":1}' > "$status"
(sleep 60; rm -f "$status") >/dev/null 2>&1 &
