# 01 – Runtime core: app.sh, utils.sh, init/hotplug/uci-defaults, packaging, helper scripts

Source: `luci-app-passwall2` 26.11.3-1. Files covered:

| File | Lines | Role |
|---|---|---|
| `root/usr/share/passwall2/app.sh` | 1105 | main start/stop orchestrator, per-core launchers, socks, cron, haproxy, dnsmasq copies |
| `root/usr/share/passwall2/utils.sh` | 482 | shared shell library (paths, UCI getters, cache vars, logging, port allocation, process launcher) |
| `root/etc/init.d/passwall2` | 98 | procd-less rc.common service with flock |
| `root/etc/init.d/passwall2_server` | 31 | server service wrapper (calls `server_app.lua`) |
| `root/etc/uci-defaults/luci-app-passwall2{,_server}` | 43/16 | first-install config |
| `root/etc/hotplug.d/iface/98-passwall2` | 39 | WAN ifup/ifupdate handler |
| `root/etc/hotplug.d/ntp/30-passwall2-resync` | 22 | NTP step handler |
| `root/etc/config/passwall2_server` | 4 | default server config |
| `root/usr/share/passwall2/0_default_config` | 228 | default `/etc/config/passwall2` (there is NO `root/etc/config/passwall2` in the tree; it is copied from here by uci-defaults) |
| `root/usr/share/ucitrack/*.json`, `root/usr/share/rpcd/acl.d/*.json` | | LuCI/rpcd glue |
| `root/usr/share/passwall2/{monitor.sh,tasks.sh,test.sh,lease2hosts.sh,haproxy_check.sh,luci_update.sh,i18n.lua,direct_ip,domains_excluded}` | | helpers owned by this group |
| `Makefile` | 133 | package deps / Kconfig / conffiles |

Other groups own: `nftables.sh`, `iptables.sh`, `subscribe.lua`, `clash_subconverter.lua`, `rule_update.lua`, `helper_dnsmasq.lua`, `haproxy.lua`, `socks_auto_switch.sh`, `app_acl.lua`, `server_app.lua`. Their *interfaces* as used from this group are documented in §11.

---

## 1. Global constants (utils.sh)

```
CONFIG=passwall2
DIRECT_GID=9912                      # gid used by firewall scripts for "direct" traffic (not used inside app.sh itself)
APP_PATH=/usr/share/passwall2
TMP_PATH=/tmp/etc/passwall2          # runtime root, deleted on stop
TMP_PATH2=/tmp/etc/passwall2_tmp     # persistent-across-restart cache (geo output, dhcp-hosts, version); removed by uci-defaults
LOCK_PATH=/var/lock
LOG_FILE=/tmp/log/passwall2.log
TMP_ACL_PATH=$TMP_PATH/acl
TMP_BIN_PATH=$TMP_PATH/bin           # symlinks to core binaries; used to identify our processes via pgrep
TMP_IFACE_PATH=$TMP_PATH/iface
TMP_ROUTE_PATH=$TMP_PATH/route       # one file per device, listing IPs added with `route add -host`
TMP_SCRIPT_FUNC_PATH=$TMP_PATH/script_func   # one file per launched process: the command line (used by monitor.sh to respawn)
TMP_PROCESS_LIST_PATH=$TMP_PATH/process_list # queued (not yet started) commands
```
utils.sh sources `/lib/functions/network.sh` (network_get_gateway/device/ipaddr/ipaddr6).
app.sh additionally sources `/lib/functions.sh`, `/lib/functions/service.sh`, `/usr/share/libubox/jshn.sh` (json_init/json_add_string/json_add_null/json_dump).

app.sh constants:
```
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall2
UTIL_SINGBOX=$LUA_UTIL_PATH/util_sing-box.lua
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua
SINGBOX_BIN=$(first_type "$(uci passwall2.@global_app[0].sing_box_file)" sing-box)
XRAY_BIN=$(first_type "$(uci passwall2.@global_app[0].xray_file)" xray)
```
(computed at script load, every invocation of app.sh)

### Lock files (all under /var/lock)
| File | Owner | Semantics |
|---|---|---|
| `passwall2.lock` | init.d | fd 9, `flock -xn` for start/restart, `flock -x` (blocking) for stop |
| `passwall2_ready.lock` | init.d boot_func | existence = "boot completed"; removed at beginning of boot_func, touched after successful boot restart. Gate for hotplug scripts |
| `passwall2_sub_rule.lock` | subscribe.lua / rule_update.lua | init.d restart waits on it (nixio `tlock`) |
| `passwall2_ifup.lock` | iface hotplug | fd 9 `flock -xn`, never deleted (deliberately: keep same inode) |
| `passwall2_ntp.lock` | ntp hotplug | contains `$$`; never deleted by any script ⇒ NTP-triggered restart happens at most once per boot (tmpfs) |
| `passwall2_tasks.lock` | tasks.sh | fd 99 `flock -n`; removed by clean_crontab |
| `passwall2_monitor.lock` | monitor.sh | plain existence lock per loop iteration; `passwall2_monitor*` removed at stop |
| `passwall2_lease2hosts.lock` | lease2hosts.sh | fd 9 `flock -n` |
| `passwall2_update_wan_sets.lock` | nftables/iptables.sh | (other group) |

---

## 2. utils.sh – function reference

All UCI reads use `uci -q get`, stderr discarded; empty result → default.

- `config_get_type SECTION [DEFAULT]` → `uci get passwall2.SECTION` (section type) or DEFAULT.
- `config_n_get SECTION OPTION [DEFAULT]` → `uci get passwall2.SECTION.OPTION` or DEFAULT. SECTION may be `@type[0]`. NOTE: list options come back space-joined.
- `config_t_get TYPE OPTION [DEFAULT] [INDEX=0]` → `passwall2.@TYPE[INDEX].OPTION`.
- `eval_set_val ARGS...` → for each word `k=v`, `eval k=v` (sets shell vars from `key=value` arg list; values cannot contain spaces).
- `eval_unset_val ARGS...` → `unset` each word.

### Cache variable store: `$TMP_PATH/var`
Line format: `KEY="VALUE"` (append-only, later dup removed on set).
- `eval_cache_var` → if file non-empty, `eval $(cat var)` (loads all into shell).
- `get_cache_var KEY` → last line matching `^KEY=`, value between the first pair of `"`. Empty if file missing.
- `del_cache_var KEY` → `sed -i "/KEY=/d"` (NOTE: unanchored substring match – deleting `foo` also deletes `xfoo=`; reproduce or fix consciously).
- `set_cache_var KEY VALUE...` → delete KEY, then if VALUE (all remaining args joined by space) non-empty: mkdir TMP_PATH, append `KEY="VALUE"`, and `eval KEY="VALUE"` in current shell. Empty value ⇒ key just removed.

Rust: implement as a key→string map persisted in exactly this file format (other shell/Lua scripts and the LuCI side read it; `api.set_cache_var`/`get_cache_var` in Lua use the same file).

### Logging
- `echolog MSG` → `echo -e "$*" >> /tmp/log/passwall2.log`.
- `echolog_date MSG` → prefix `YYYY-mm-dd HH:MM:SS: `.
- `log N MSG` → N≥1: indent = `"  "`×N, line = `<date>: <indent>- MSG`; N=0: `<date>: MSG`.
- `i18n FMT ARGS...` → `lua /usr/share/passwall2/i18n.lua FMT ARGS...` = `api.i18n.translatef(FMT, ARGS...)` (printf-style with %s, translated via LuCI po).
- `log_i18n N FMT ARGS...` = `log N "$(i18n FMT ARGS)"`.
- `clean_log` → if log has >1000 lines, truncate to "" and log "Log file is too long, clear it!".
- `lua_api EXPR` → runs `lua -e "local api = require 'luci.passwall2.api' print(api.EXPR)"`; echoes output word-split/joined (so multiple return values become space separated; `nil` prints `nil`). Used with `get_domain_from_url("url")`, `is_ip("host")` (prints `true`/`false`), `parseDNS("str")` (prints `server port` or `nil`).

### Host/IP helpers
- `check_host H` → return 1 if H contains `/` or any non-printable-ASCII (`[!-~]` removed leaves something, e.g. CJK or space); else 0.
- `first_type PATH_OR_NAME [ALT]` → if arg1 is absolute and executable echo it; else first executable of `/bin/$1`, `/usr/bin/$1`, `${TMP_BIN_PATH:-/tmp}/$1`; else `command -v $1` or `command -v $2`. (Called with an absolute uci path like `/usr/bin/xray` plus fallback name `xray`.)
- `get_enabled_anonymous_secs TYPE` → `uci -q show passwall2 | grep "TYPE\[.*\.enabled='1'" | cut -d. -sf2` (returns `@TYPE[n]` tokens).
- `get_geoip CODE ipv4|ipv6|other` → output cache `$TMP_PATH2/geo_output/geoip-CODE-<2nd arg>`; if not cached: geoip path = `@global_rules[0].v2ray_location_asset` with trailing `/` stripped + `/geoip.dat`; bin = first_type(`@global_app[0].geoview_file`, geoview); if bin missing or dat missing → echo "" return. Run `"$bin" -input <geoip.dat> -list <CODE> [-ipv6=false | -ipv4=false] -lowmem=true -output <cache>` (ipv4 → `-ipv6=false`, ipv6 → `-ipv4=false`, else no flag). Then cat cache if non-empty.
- `get_host_ip ipv4|ipv6 HOST [COUNT=3]` → ipv6: if HOST matches `([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}` return it with `[]` stripped; ipv4: if matches `([0-9]{1,3}\.){3}[0-9]{1,3}` return it. Else `resolveip -4|-6 -t COUNT HOST | head -1`.
- `get_node_host_ip NODE` → address=`NODE.address`; family ipv6 if `NODE.use_ipv6 == 1`; echo get_host_ip.
- `get_ip_port_from HOSTSTR IPVAR PORTVAR [UCIPRIORITY]` → port = digits after the last `:` or `#` at end of string; ip = string minus `[:#]port...` suffix. If UCIPRIORITY non-empty, HOSTSTR is treated as a section id: port=`uci HOST.port` (default parsed), ip=`uci HOST.address` (default parsed). Assigns via eval.
- `host_from_url URL` → strip leading `http://`,`https://`,`ftp://`,`sftp://`; strip userinfo (`*:*@`, `*@`); cut at first `/`; cut at first `:`.
- `hosts_foreach VARNAME FUNC DEFAULT_PORT [EXTRA...]` → split `$VARNAME` by space/comma; for each host: parse ip/port; call `FUNC host ip port(or default) EXTRA`; abort returning code if code ≥ `${ERROR_NO_CATCH:-1}` (so by default any nonzero aborts).
- `check_port_exists PORT [tcp|udp|tcp,udp]` → count of `netstat -tln|-uln|-tuln` lines containing `:PORT ` (default proto tcp,udp). Echoes the count ("0" when free).

### get_new_port PORT|auto [PROTO]
```
default_start=2001, min=1025, max=49151
if arg1=="auto": port = cache[last_get_new_port_auto]+1 if set else 2001
if port<1025 or port>49151: port=2001
proto = lowercase(arg2)
busy = check_port_exists(port, proto) != 0  OR cache["get_port_<port>"] non-empty
if busy: next = port+1 if port<49151 elif port>1025 then port-1 else 2001; recurse get_new_port(next, proto)
         (NOTE recursion passes a number, not "auto", so last_get_new_port_auto is NOT updated in that path)
else: set cache get_port_<port>=1; if arg1=="auto": set cache last_get_new_port_auto=port; echo port
```
Rust: same algorithm; the reserved-port cache must survive across invocations (it lives in `$TMP_PATH/var`, cleared on stop).

- `has_1_65535 VAL` → replace `:` with `-`; true if `,VAL,` contains `,1-65535,`.

### Routes
- `add_ip2route HOST IFACE` → ip=get_host_ip ipv4 HOST; fail → log 1 "Unable to resolve [%s], route table addition failed!" return 1. remarks=`HOST` or `HOST(ip)`. gateway=network_get_gateway IFACE; device=network_get_device IFACE, else `ubus call network.interface.IFACE status | jsonfilter -e '@.device'`, else IFACE if `/sys/class/net/IFACE` exists, else IFACE. If gateway: `route add -host <ip> gw <gw> dev <device>`; append ip to `$TMP_ROUTE_PATH/<device>`; log success. Else log failure ("gateway cannot be found").
- `delete_ip2route` → for each file in TMP_ROUTE_PATH (name=interface), for each ip: `route del -host <ip> dev <interface>`.

### Process launcher: ln_run QUEUE FILE_FUNC LN_NAME OUTPUT ARGS...
```
if FILE_FUNC contains '/':                       # it's a path
    if FILE_FUNC is not a symlink:
        ln -s FILE_FUNC $TMP_BIN_PATH/LN_NAME     # (errors ignored, e.g. already exists)
        FILE_FUNC = $TMP_BIN_PATH/LN_NAME
    if not executable: log 1 "%s does not have execute permissions and cannot be started: %s %s"
if FILE_FUNC empty: log 1 "%s not found, unable to start..." (LN_NAME); return 1
if QUEUE == "1":
    mkdir -p process_list; n = count(files in process_list not starting with "_") + 1
    write "FILE_FUNC ARGS >OUTPUT" to process_list/n ; return      # started later by run_process_queue
FILE_FUNC ARGS > OUTPUT 2>&1 &                    # background
if NO_REC_PROCESS set: return
n = count(script_func files not starting "_") + 1
write "FILE_FUNC ARGS >OUTPUT" to script_func/n   # record for monitor.sh
```
Key point: every core binary is executed via a symlink inside `/tmp/etc/passwall2/bin/` named `xray`, `sing-box`, `haproxy`, `dnsmasq`, `dnsmasq_<flag>`, `chinadns-ng`, `ssr-local`, `sslocal`. `pgrep -f /tmp/etc/passwall2/bin` therefore finds all our children. The `flag` value appears in the config-file path so processes can be found by flag.

- `run_process_queue` → if process_list dir exists: mkdir script_func; for each file (ls order: lexicographic! "10" before "2"): cmd=content; cmd_check = part before first `>`; if `busybox pgrep -f "<cmd_check>"` count == 0 → `eval "nohup <cmd> 2>&1 &"` in background; move file to `script_func/queued_<name>`. Finally `rm -rf process_list`.
- `kill_all NAMES...` → `kill -9 $(pidof NAMES)`.

### Address enumeration
- `get_wan_ips ip4|ip6` → interfaces = `ubus call network.interface dump | jsonfilter -e '@.interface[!(@.interface ~ /lan/) && !(@.l3_device ~ /\./) && @.route[0]].interface'`; for each: ipv6 → network_get_ipaddr6 skip empty/`fe80*`; ipv4 → network_get_ipaddr skip empty/`0.0.0.0`. Unique, space separated.
- `get_local_ips ip4|ip6` → all = `ip -o -4|-6 addr show scope global | awk '{print $4}' | cut -d/ -f1` plus `127.0.0.1` (v4) / `::1` (v6); exclude empty, `0.0.0.0`, `::`, and WAN IPs; unique; one per line.

---

## 3. app.sh entry points (CLI)

```
app.sh start [ACTION]          # ACTION ∈ "", boot, cron
app.sh stop  [ACTION]          # ACTION ∈ "", cron
app.sh run_socks k=v ...       # get_direct_dns; QUEUE_RUN=0; run_socks
app.sh socks_node_switch flag=<socks_sid> new_node=<node_sid>   # get_direct_dns; QUEUE_RUN=0
```
Callers of `run_socks` outside this file (must remain supported by the Rust CLI with the same `key=value` arguments):
- controller `passwall2.lua:230`: `app.sh run_socks flag=config_<id> node=<id> bind=127.0.0.1 socks_port=1080 config_file=<file> no_run=1` (generate config only, for "view config").
- `test.sh url_test_node`: `NO_REC_PROCESS=1 app.sh run_socks flag=url_test_<id> node=<id> bind=127.0.0.1 socks_port=<p> config_file=url_test_<id>.json`.
- `util_xray.lua` / `util_sing-box.lua` / `haproxy.lua`: `app.sh run_socks "flag=<port> node=<id> bind=127.0.0.1 socks_port=<port> config_file=nodesocks_<id>_<port>.json relay_port=<p>"` (whole arg list in ONE quoted argument – eval_set_val word-splits it; `relay_port` may be empty).
- `socks_auto_switch.sh` calls `app.sh socks_node_switch flag=.. new_node=..`.
- start_socks itself calls `NO_REC_PROCESS=1 app.sh run_socks ...` for autoswitch-enabled socks.

---

## 4. Configuration loading

### get_config (called from start)
| Shell var | Source | Default |
|---|---|---|
| ENABLED_DEFAULT_ACL | 1 iff `@global[0].enabled==1` AND `@global[0].node` non-empty AND section type of that node == `nodes` | 0 |
| ENABLED | `@global[0].enabled` | 0 |
| NODE | `@global[0].node` | "" |
| ENABLED_ACLS | `@global[0].acl_enable` | 0 |
| SOCKS_ENABLED | `@global[0].socks_enabled` | 0 |
| TCP_PROXY_WAY | `@global_forwarding[0].tcp_proxy_way` | `redirect` |
| PROXY_IPV6 | `@global_forwarding[0].ipv6_tproxy` | 0 |
| DIRECT_DNS_QUERY_STRATEGY | `@global[0].direct_dns_query_strategy` | `UseIP` |

Then `get_direct_dns`; then cache `DIRECT_DNS` = `"$DIRECT_DNS_SERVER#$DIRECT_DNS_PORT"` if proto udp, else first entry of AUTO_DNS (`${AUTO_DNS%%,*}`).

dnsmasq conf dir: `DEFAULT_DNSMASQ_CFGID` = section name of `dhcp.@dnsmasq[0]` (first line of `uci -q show dhcp.@dnsmasq[0]`, token between `.` and `=`; e.g. `cfg01411c`). If `/var/etc/dnsmasq.conf.<cfgid>` exists, DNSMASQ_CONF_DIR = value of its `conf-dir=` line (trailing `/` stripped), else `/tmp/dnsmasq.d`. Cache:
- `DEFAULT_DNSMASQ_CONF` = `<DNSMASQ_CONF_DIR>/dnsmasq-passwall2.conf`
- `DEFAULT_DNSMASQ_CONF_PATH` = `/tmp/etc/passwall2/acl/acl_default_dnsmasq.d`

Set `QUEUE_RUN=1` (all core launches during start are queued and started together at the end by run_process_queue).

### get_direct_dns
```
RESOLVFILE = /tmp/resolv.conf.d/resolv.conf.auto if exists & non-empty else /tmp/resolv.conf.auto
ISP_DNS  = all IPv4 dotted quads in RESOLVFILE except 0.0.0.0 / 127.0.0.1, uniq preserving order
ISP_DNS6 = lines matching ipv6 regex → strip %scope → field 2 → drop ::1 and :: → uniq   (computed, unused here)
DNSMASQ_UPSTREAM_DNS = values of `dhcp.@dnsmasq[0].server` list entries (uci show, quotes removed, split by space),
     excluding entries containing '/', appending '#53' when no '#' present, first 2, joined by ','
DEFAULT_DNS = DNSMASQ_UPSTREAM_DNS or first 2 ISP_DNS joined ','
AUTO_DNS = DEFAULT_DNS or "119.29.29.29"
RETURN_DNS = AUTO_DNS
AUTO_DNS_1 = first comma field
DIRECT_DNS_PROTO=udp; DIRECT_DNS_SERVER = AUTO_DNS_1 before '#'; DIRECT_DNS_PORT = after '#' or 53
if @global[0].direct_dns_protocol ∈ {tcp,udp}:
    DIRECT_DNS = @global[0].direct_dns
    r = api.parseDNS(DIRECT_DNS)  ("server port")
    if r != nil: PROTO=that; SERVER, PORT from r
        if udp: DIRECT_DNS_DNSMASQ_SERVER="SERVER#PORT"
        RETURN_DNS += ",SERVER#PORT#PROTO"
# direct_dns_protocol 'auto' (default) → use AUTO_DNS
```
(RETURN_DNS / ISP_DNS6 are exported globals consumed by sourced nftables.sh/iptables.sh.)

### check_run_environment → sets USE_TABLES and nftflag
```
prefer_nft = @global_forwarding[0].prefer_nft (default 1)
info = `dnsmasq -v`; ver = first line "version X.Y" number
dnsmasq_ipset = word "ipset" in info; dnsmasq_nftset = word "nftset" in info
has_ipt = command iptables-legacy or iptables exists; has_ipset = ipset exists; has_fw4 = fw4 exists
if prefer_nft==1:
    if nftset && fw4: USE_TABLES=nftables
    elif ipset && ipt && dnsmasq_ipset: warn "Warning: The %s application environment is incomplete. Switch to %s. (%s)" ("nftables (fw4)","iptables","has_fw4:X/dnsmasq_nftset:Y"); USE_TABLES=iptables
else:
    if ipset && ipt && dnsmasq_ipset: USE_TABLES=iptables
    elif nftset && fw4: warn (... "iptables (fw3)","nftables","has_ipt:X/has_ipset:Y/dnsmasq_ipset:Z"); USE_TABLES=nftables
if USE_TABLES:
    pkg db: /usr/lib/opkg/info/<pkg>.control, or if /lib/apk/packages exists: /lib/apk/packages/<pkg>.list
    iptables deps: iptables-mod-tproxy iptables-mod-socket iptables-mod-iprange iptables-mod-conntrack-extra iptables-mod-extra kmod-ipt-nat
    nftables deps: kmod-nft-socket kmod-nft-tproxy kmod-nft-nat ; also nftflag=1;
        if digits(ver) < 290 (e.g. "2.89"→289): log "Note: Dnsmasq (%s) is below 2.90. Upgrading is recommended to improve stability."
    for each dep missing/empty file: log "Warning: %s transparent proxy is missing basic dependency %s!"
else:
    log "Warning: Not compatible with any transparent proxy system environment. (has_fw4:../has_ipt:../has_ipset:../dnsmasq_nftset:../dnsmasq_ipset:..)"
```
(Missing deps only warn; they don't block.)

---

## 5. Core launchers

### Common: argument passing
All launchers take `k=v` words (eval_set_val). JSON for Lua generators is built with jshn: every field is a **string** (`json_add_string`), except `json_add_null` where noted. The JSON is passed as ONE argv to `lua <util> gen_config '<json>'` whose stdout is the config file. The generators are other groups' specs; field names below are the contract.

### run_xray (args)
Args: `flag node redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_udp_server remote_dns_udp_port remote_dns_tcp_server remote_dns_tcp_port remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy dns_cache loglevel log_file config_file`.

```
node_protocol = node.protocol
log_file default /dev/null; loglevel default @global[0].loglevel or "warning"
json: loglevel
if flag: kill -9 all pids from `busybox pgrep -af /tmp/etc/passwall2/bin` whose line matches flag (case-insensitive regex); json flag
if socks_address && socks_port: json local_socks_address, local_socks_port; if user&&pass: local_socks_username, local_socks_password
if http_address && http_port: json local_http_address, local_http_port; if user&&pass: local_http_username, local_http_password
direct_dns_proto/server/port = DIRECT_DNS_PROTO/SERVER/PORT
if dns_listen_port:
    dns_msg = "DNS[<port>]:(" + i18n("Direct DNS: %s", "<proto>://<server>:<port>")
    json dns_listen_port; json dns_cache if set
    if node_protocol == "_shunt": write_ipset_direct = node.write_ipset_direct (default 0)
    if write_ipset_direct == 1:
        direct_dnsmasq_listen_port = get_new_port auto
        conf = $TMP_ACL_PATH/dns_<flag>_direct.conf
        if nftflag==1: set4="psw2_<node>_white", set6="psw2_<node>_white6",
                        direct_nftset="4#inet#passwall2#<set4>,6#inet#passwall2#<set6>"
        else:          direct_ipset="<set4>,<set6>" (same names)
        run_ipset_dns_server listen_port=<p> proto=<direct_dns_proto> server_dns="<server>#<port>" ipset=<..> nftset=<..> config_file=<conf>
        direct DNS for the core becomes udp://127.0.0.1:<p>
        if ipset: json direct_ipset; cache node_<node>_direct_ipset4 / _direct_ipset6
        if nftset: json direct_nftset; cache node_<node>_direct_nftset4 / _direct_nftset6
    case remote_dns_protocol:
      udp: json remote_dns_udp_server, remote_dns_udp_port; msg "Remote DNS: udp://s:p"
      tcp: json remote_dns_tcp_server, remote_dns_tcp_port; msg "tcp://s:p"
      doh: url = remote_dns_doh split ',' [0]; hostport = api.get_domain_from_url(url); host=hostport[:0]; port=hostport[:1] or 443
           bootstrap = remote_dns_doh fields 2.. (cut -s: empty if no comma); if api.is_ip(host)=="true": bootstrap=host
           json remote_dns_doh_port, remote_dns_doh_url, remote_dns_doh_host, [remote_dns_doh_ip=bootstrap]; msg "Remote DNS: <url>"
    if remote_fakedns==1: json remote_dns_fake="1", remote_dns_fake_strategy=<remote_dns_query_strategy>; msg += " + FakeDNS "
    json (if set) remote_dns_detour, remote_dns_query_strategy, remote_dns_client_ip
    log_out = dns_msg + ")"
json "direct_dns_<proto>_server" = server, "direct_dns_<proto>_port" = port   # key name embeds proto: direct_dns_udp_server / direct_dns_tcp_server
json direct_dns_query_strategy
if redir_port: json redir_port; cache node_<node>_redir_port; json tcp_proxy_way=$TCP_PROXY_WAY; log_out = "Xray[<redir_port>] " + log_out (only if log_out set)
json node
lua util_xray.lua gen_config '<json>' > config_file
test_log = log_file, or $TMP_PATH/test.log if /dev/null
$XRAY_BIN run -test -c <config_file> > test_log      (stdout only)
if ok: ln_run $QUEUE_RUN $XRAY_BIN xray <log_file> run -c <config_file>; log 2 log_out (if set)
else: _error_log_file = test_log; return status
```

### run_singbox
Same args plus `remote_rewrite_ttl`. Differences vs run_xray:
- `type` = lowercase(node.type); return 1 if empty.
- loglevel default `@global[0].loglevel` or `"warn"`.
- `singbox_tag` = `$SINGBOX_BIN version | grep 'Tags:' | awk '{print $2}'` → json `tags`.
- json `log`: `"0"` if log_file is /dev/null else `"1"` + `logfile`=log_file. Then `loglevel`.
- remote DNS cases:
  - `udp|quic`: udp server/port; if quic json `remote_dns_quic="1"`; msg `<proto>://s:p`.
  - `tcp|tls`: tcp server/port; if tls json `remote_dns_tls="1"`.
  - `doh|http3`: same doh fields (`remote_dns_doh_ip` added first if bootstrap); if http3 json `remote_dns_http3="1"`.
- fakedns: only `remote_dns_fake="1"` (no `_strategy`).
- extra: `remote_rewrite_ttl` if set.
- log prefix `Sing-Box[<redir_port>] `.
- generator: `lua util_sing-box.lua gen_config`; check: `$SINGBOX_BIN check -c <config_file> > test_log 2>&1`; run: `ln_run $QUEUE_RUN $SINGBOX_BIN sing-box <log_file> run -c <config_file>`.

### run_socks
Args: `flag node bind socks_port config_file http_port http_config_file relay_port log_file no_run`.
```
config_file / http_config_file: if not containing "/tmp/etc/passwall2", prefix "$TMP_PATH/"
http_port default 0
log_file: if non-empty, != /dev/null and not containing TMP_PATH → "$TMP_PATH/<log_file>"; else /dev/null
   (NOTE: a log_file already containing TMP_PATH is ALSO forced to /dev/null by this if/else)
type=lowercase(node.type); remarks=node.remarks; server_host=node.address; server_port=node.port
if relay_port: server_host=127.0.0.1, server_port=relay_port
if host && port: if check_host fails → log 1 "Socks node: [%s]%s is an invalid server address and cannot be started!"; return 1
                 tmp="host:port"
else error_msg = "For some reason, the configuration for this Socks service has been lost, and its startup has been aborted!"
if type ∈ {sing-box,xray} and protocol ∈ {_balancing,_shunt,_iface,_urltest}: clear error
if error and (node.hysteria_hop or node.hysteria2_hop non-empty or node.hysteria2_realms == "1"): clear error
if error: (if bind != 127.0.0.1) log 1 "Socks node: [%s]%s, start failed %s:%s %s"; return 1
if bind != 127.0.0.1: log 1 "Socks node: [%s]%s, starting %s:%s"
json: node, server_host, server_port
case type:
 sing-box:
   if http_port != 0: http_flag=1; config_file = "<name>+http<.ext>" (insert "+http" before first '.', e.g. /tmp/etc/passwall2/abc.json → abc+http.json; NOTE path has dots? first '.' of full path – TMP_PATH has none); json local_http_address=bind, local_http_port
   if !relay_port: json_add_null server_host, server_port (override to null)
   if log_file != /dev/null: json log="1", loglevel=@global[0].loglevel|"warn", logfile=log_file
   if no_run: json no_run="1"
   json flag, local_socks_address=bind, local_socks_port=socks_port,
        direct_dns_<DIRECT_DNS_PROTO>_server, direct_dns_<..>_port, direct_dns_query_strategy=$DIRECT_DNS_QUERY_STRATEGY
   lua util_sing-box.lua gen_config > config_file
   if !no_run: ln_run $QUEUE_RUN $SINGBOX_BIN sing-box /dev/null run -c config_file
 xray: same as sing-box except log: json log="1", loglevel (no logfile) and generator util_xray.lua;
   run: ln_run $QUEUE_RUN $XRAY_BIN xray <log_file> run -c config_file
 ssr: json local_addr=bind, local_port=socks_port; lua util_shadowsocks.lua gen_config > config_file
   run: ln_run Q "$(first_type ssr-local)" ssr-local <log_file> -c <config_file> -v -u
 ss-rust: json local_socks_address, local_socks_port; if http_port!=0: http_flag, +http rename, local_http_address/port
   if !no_run: json plugin_sh = "<config_file without .json>_plugin.sh"
   lua util_shadowsocks.lua gen_config > config_file
   run: ln_run Q "$(first_type sslocal)" sslocal <log_file> -c <config_file> -v
 (other types: nothing launched)
# HTTP-over-socks helper (types other than sing-box/xray/socks that didn't handle http themselves)
if !http_flag && http_port!=0 && http_config_file && type ∉ {sing-box,xray,socks}:
   json local_http_port, server_proto="socks", server_address="127.0.0.1", server_port=socks_port,
        server_username=$_username, server_password=$_password   (globals – normally empty)
   prefer sing-box bin+util, else xray: lua <util> gen_proto_config '<json>' > http_config_file
   if !no_run: ln_run Q <bin> <sing-box|xray> /dev/null run -c http_config_file
if !no_run && server_host != 127.0.0.1 && type ∉ {sing-box,xray}: echo node >> $TMP_PATH/direct_node_list
```
(`direct_node_list` is consumed by nftables/iptables `filter_direct_node_list` to whitelist node server IPs.) SS plugin processes write `$TMP_PATH/<flag>[+http]_plugin.pid` (written by the generated plugin_sh – shadowsocks util spec).

### socks_node_switch flag=<socks_sid> new_node=<node>
```
for suffix in "" "+http": kill -9 first line of $TMP_PATH/<flag><suffix>_plugin.pid
kill -9 pids from `busybox pgrep -af /tmp/etc/passwall2/bin` matching flag (ci) and NOT matching /acl\/|acl_/
rm -rf $TMP_PATH/<flag>* , <flag>+http* , <flag>_http*
remove script_func entries whose content contains flag
bind = 127.0.0.1 if socks.bind_local==1 else 0.0.0.0; port=socks.port
config_file=<flag>.json; log_file=<flag>.log unless socks.log (default 1) == 0 → ""
http_port=socks.http_port (0); http_config_file=<flag>_http.json
LOG_FILE=/dev/null   (suppresses logging)
run_socks flag=<flag> node=<new_node> bind port config_file http_port http_config_file log_file   (QUEUE_RUN=0 → immediate)
sleep 2s
if check_port_exists(port, tcp)=="0": return 1
cache <flag>=<new_node>
USE_TABLES = cache USE_TABLES; if set: source $APP_PATH/<USE_TABLES>.sh filter_direct_node_list
return 0
```

### start_socks (if SOCKS_ENABLED == 1)
```
ids = section names of type "socks" (uci show | grep "=socks" — NOTE: grep also matches option values ending in "=socks..."? it's `.sid=socks` lines only in practice)
if any: log "Analyzing the node configuration of the Socks service..."
for id: skip if enabled(default 0)==0 or node empty
   bind, port, config_file=<id>.json, log_file=<id>.log (or "" if log==0), http_port (0), http_config_file=<id>_http.json
   if enable_autoswitch(0)==1: NO_REC_PROCESS=1 app.sh run_socks ... (separate process; runs immediately, not queued, not recorded for monitor)
   else run_socks ... (in-process; queued since QUEUE_RUN=1)
   cache <id>=<node>
   if autoswitch: socks_auto_switch.sh <id> &  (background)
```
UCI `socks` section options read: `enabled`(0), `node`, `bind_local`(0), `port`, `log`(1), `http_port`(0), `enable_autoswitch`(0).

### start_haproxy
If `@global_haproxy[0].balancing_enable` != 1 → return. Else `lua $APP_PATH/haproxy.lua -path /tmp/etc/passwall2/haproxy -conf config.cfg`, then `ln_run 0 "$(first_type haproxy)" haproxy /dev/null -f /tmp/etc/passwall2/haproxy/config.cfg` (not queued).

---

## 6. DNS helper instances

### run_copy_dnsmasq flag listen_port local_dns tun_dns default_dns
```
conf = $TMP_ACL_PATH/<flag>_dnsmasq.conf ; dir = $TMP_ACL_PATH/<flag>_dnsmasq.d ; pid = $TMP_ACL_PATH/<flag>_dnsmasq.pid
mkdir -p dir
lua helper_dnsmasq.lua copy_instance '{"LISTEN_PORT":"<p>","DNSMASQ_CONF":"<conf>"}'
lua helper_dnsmasq.lua add_rule '{"FLAG":..,"TMP_DNSMASQ_PATH":dir,"DNSMASQ_CONF_FILE":conf,"DEFAULT_DNS":..,"LOCAL_DNS":..,"TUN_DNS":..,"NFTFLAG":"<0|1>","NO_LOGIC_LOG":"<0>"}'
ln_run 0 "$(first_type dnsmasq)" dnsmasq_<flag> /dev/null -C <conf> -x <pid>
cache ACL_<flag>_dns_port = listen_port
```

### run_ipset_dns_server → chinadns-ng if `first_type chinadns-ng` exists, else dnsmasq.

### run_ipset_chinadns_ng listen_port proto server_dns ipset nftset config_file
```
if $TMP_ACL_PATH/vpslist empty/missing:
   node_servers = all values of options named *address / *download_address in passwall2 (uci show, between single quotes)
   hosts_foreach → host_from_url → keep lines ending in a letter (domains) → sort -u → drop engage.cloudflareclient.com > vpslist
ipset given:  set_names=ipset ; vps_set_names="psw2_vps,psw2_vps6"
nftset given: set_names = "<f1 minus '4#'>,<f2 minus '6#'>" with '#'→'@' → "inet@passwall2@psw2_<n>_white,inet@passwall2@psw2_<n>_white6"
              vps_set_names="inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6"
config_file content (exact):
  bind-addr 127.0.0.1
  bind-port <listen_port>
  china-dns <proto>://<server_dns>          # server_dns is "ip#port"
  trust-dns <proto>://<server_dns>
  filter-qtype 65
  add-tagchn-ip <set_names>
  default-tag chn
  group vpslist
  group-dnl /tmp/etc/passwall2/acl/vpslist
  group-upstream <proto>://<server_dns>
  group-ipset <vps_set_names>
ln_run 0 "$(first_type chinadns-ng)" chinadns-ng /dev/null -C <config_file> -v
```

### run_ipset_dnsmasq listen_port server_dns ipset nftset cache_size dns_forward_max config_file
```
port=<listen_port>
no-poll
no-resolv
strict-order
cache-size=<cache_size:-0>
dns-forward-max=<dns_forward_max:-1000>
server=<each comma-separated server_dns>
[ipset=<ipset>]
[nftset=<nftset>]
→ ln_run 0 "$(first_type dnsmasq)" dnsmasq /dev/null -C <config_file>
```

---

## 7. acl_node (called by nftables.sh/iptables.sh during their `start`)

```
if uci dhcp.@dnsmasq[0].dns_redirect == 1:
    uci set passwall2.@global[0].dnsmasq_dns_redirect=1; commit passwall2     # backup marker
    uci set dhcp.@dnsmasq[0].dns_redirect=0; commit dhcp
    lua helper_dnsmasq.lua restart '{"LOG":"0"}'
run_func = run_singbox if SINGBOX_BIN else run_xray if XRAY_BIN
for nid in jsonfilter(ACL_JSON, '$.node_order[*]'):
    skip if no file $TMP_ACL_PATH/acl_node_<nid>
    _var = file content (space separated k=v produced by app_acl.lua: flag node redir_port socks_address socks_port dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_tcp_server remote_dns_tcp_port remote_dns_udp_server remote_dns_udp_port remote_dns_doh remote_dns_client_ip remote_dns_detour remote_dns_query_strategy remote_fakedns remote_rewrite_ttl config_file loglevel log_file)
    eval local _var ; type = lowercase(node.type); skip if empty
    choose run_xray if type==xray && XRAY_BIN; run_singbox if type==sing-box && SINGBOX_BIN (else keep previous run_func)
    run_func _var
    on failure: log_i18n 2 "[%s] process %s error, skip this transparent proxy!" node config_file; append _error_log_file to LOG_FILE; continue
    run_new_dnsmasq=1
    TUN_DNS="127.0.0.1#<dns_listen_port>"; DEFAULT_DNS=AUTO_DNS; LOCAL_DNS = $LOCAL_DNS or AUTO_DNS; override LOCAL_DNS=DIRECT_DNS_DNSMASQ_SERVER if set
    if flag == "acl_default":
        cache ACL_acl_default_node=node, ACL_acl_default_node_socks_port=socks_port
        run_new_dnsmasq = @global[0].dns_redirect (default 1)
        if != 1:   # integrate into the system dnsmasq instead of a separate instance
            lua helper_dnsmasq.lua stretch
            lua helper_dnsmasq.lua add_rule '{FLAG:acl_default, TMP_DNSMASQ_PATH:$DEFAULT_DNSMASQ_CONF_PATH, DNSMASQ_CONF_FILE:$DEFAULT_DNSMASQ_CONF, DEFAULT_DNS, LOCAL_DNS, TUN_DNS, NFTFLAG, NO_LOGIC_LOG}'
            uci add_list dhcp.@dnsmasq[0].addnmount=$DEFAULT_DNSMASQ_CONF_PATH; commit dhcp
            lua helper_dnsmasq.lua logic_restart
    if run_new_dnsmasq == 1:
        port = get_new_port auto
        run_copy_dnsmasq flag listen_port=port local_dns tun_dns default_dns
        lease2hosts.sh &     (singleton via flock)
        log 2 "Dnsmasq[<port>]:(127.0.0.1:<dns_listen_port>)"
    rm acl_node_<nid>
```
Default mode (`dns_redirect` unset/1): a dedicated dnsmasq copy per ACL listens on an auto port, and the firewall redirects client DNS to it (nftables group). Mode `dns_redirect=0`: rules are injected into the main dnsmasq via conf-dir file `dnsmasq-passwall2.conf`.

---

## 8. Cron / scheduled tasks

### clean_crontab
```
touch /etc/crontabs/root
delete lines containing "/etc/init.d/passwall2"
delete lines containing "lua /usr/share/passwall2/rule_update.lua log"
delete lines containing "lua /usr/share/passwall2/subscribe.lua start"
kill -9 processes from `busybox pgrep -af passwall2/` matching tasks.sh
rm -f /var/lock/passwall2_tasks.lock
```

### start_crontab ACTION
```
if ENABLED_DEFAULT_ACL==1 || ENABLED_ACLS==1:
    if @global_delay[0].start_daemon (0)==1: monitor.sh &
if ACTION=="cron": log "The task is currently running automatically as a scheduled task; no reconfiguration of the scheduled task is required."; return
clean_crontab
if ENABLED != 1: /etc/init.d/cron restart; return
setsid_cmd = "setsid " if setsid exists
time "HH:MM" → hh, mm; week_mode: 0-6 cron weekday, 7 = every day ("*"), 8 = interval loop (handled by tasks.sh)
cron line template: "<mm> <hh> * * <week|*> <setsid>CMD > /dev/null 2>&1 &"
@global_delay[0].stop_week_mode/stop_time_mode    → CMD "/etc/init.d/passwall2 stop cron";   log "Scheduled tasks: Auto stop service."
   (stop/start do not special-case 8; "8" would be written literally)
@global_delay[0].start_week_mode/start_time_mode  → "/etc/init.d/passwall2 start cron";       log "Scheduled tasks: Auto start service."
@global_delay[0].restart_week_mode/restart_time_mode → if 8: update_loop=1 else "/etc/init.d/passwall2 restart cron"; log "Scheduled tasks: Auto restart service."
@global_rules[0].update_week_mode/update_time_mode → if 8: update_loop=1 else "lua /usr/share/passwall2/rule_update.lua log all cron"; log "Scheduled tasks: Auto update rules."
subscribe_list sections with update_week_mode set: group by "<week>_<time>" into $TMP_PATH/sub_crontabs/<week>_<time>;
   log "Scheduled tasks: Auto update [%s] subscription." (remark)
   per group: if week==8 update_loop=1 else CMD "lua /usr/share/passwall2/subscribe.lua start <id1,id2,..> cron"
   rm -rf sub_crontabs
if proxy enabled (default ACL or ACLs):
   if update_loop: tasks.sh &; log "Auto updates: Starts a cyclical update process."
else: log "Running in no proxy mode, it only allows scheduled tasks for starting and stopping services."
/etc/init.d/cron restart
```
Note: cron entries are written only when `ENABLED==1` (global enabled), even when no node configured.

### stop_crontab ACTION → if ACTION=="cron" return; clean_crontab; `/etc/init.d/cron restart`.

### tasks.sh (interval loop)
```
flock -n fd99 /var/lock/passwall2_tasks.lock else exit 0
T=0 (minutes)
loop:
  if T != 0:
    if @global_delay[0].restart_week_mode == 8 and T % (restart_interval_mode*60) == 0: /etc/init.d/passwall2 restart cron &
    if @global_rules[0].update_week_mode == 8 and T % (update_interval_mode*60) == 0: lua rule_update.lua log all cron &
    subscribe_list with update_week_mode==8 and update_interval_mode set: group by interval → $TMP_PATH/sub_tasks/8_<interval>;
       if T % (interval*60) == 0: lua subscribe.lua start <ids,> cron &
  T += 10 ; sleep 600
```
`*_interval_mode` unit: hours. Check granularity: 10 min. (`expr` with empty interval errors → condition false.)

### monitor.sh (process watchdog)
```
exit unless @global[0].enabled==1 and @global_delay[0].start_daemon==1
sleep 58s
forever:
  if /var/lock/passwall2_monitor.lock exists: sleep 6s; continue
  touch lock
  for each file in script_func not starting "_" (includes queued_*):
     cmd = content; check = part before first '>'; escape every non-alnum char with '\'
     if `busybox pgrep -f "<escaped>"` finds none: log 0 "<cmd> crashed, restarting."; eval "nohup <cmd> 2>&1 &"
  rm lock; sleep 58s
```
(stop kills `sleep` processes matching `sleep.*(6s|9s|58s)` — these magic durations identify our sleepers.)

---

## 9. start sequence (app.sh start ACTION) – exact order

1. If any process matches `pgrep -f /tmp/etc/passwall2/bin` (leftovers): `logger -t PW2-RESTART "Upgrade or overload residue is detected, and the subprocess is being called to perform complete cleaning..."`; run `stop ACTION` in a subshell (stop calls `exit 0`); sleep 2.
2. `mkdir -p /tmp/etc /tmp/log $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2`.
3. `get_config` (§4) → also get_direct_dns, caches DIRECT_DNS, DEFAULT_DNSMASQ_CONF, DEFAULT_DNSMASQ_CONF_PATH; QUEUE_RUN=1.
4. Export env (inherited by every core process):
   - `V2RAY_LOCATION_ASSET` = `@global_rules[0].v2ray_location_asset` (default `/usr/share/v2ray/`)
   - `XRAY_LOCATION_ASSET` = same
   - `ENABLE_DEPRECATED_GEOSITE=true`, `ENABLE_DEPRECATED_GEOIP=true` (sing-box)
   - `SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN=1` (shadowsocks-rust)
   - `ulimit -n 65535`
5. `start_haproxy` (immediate launch).
6. `start_socks` (queued launches; autoswitch ones immediate in sub-process).
7. `nftflag=0; USE_TABLES=""; check_run_environment`.
8. If USE_TABLES:
   - `ACL_JSON=$(lua app_acl.lua)` (generates `$TMP_ACL_PATH/<flag>/var`, `/source_list`, `$TMP_ACL_PATH/acl_node_<flag>`, sets cache `ENABLED_ACLS` and others; prints JSON with `acl[]` (each has `.flag`) and `node_order[]`).
   - If `$TMP_ACL_PATH/acl_node_acl_default` absent → ENABLED_DEFAULT_ACL=0.
   - n = count of node_order entries; if 0 → ENABLED_DEFAULT_ACL=0, ENABLED_ACLS=0; else `source $APP_PATH/<USE_TABLES>.sh start` (firewall group; it calls `acl_node` from app.sh's namespace since it's sourced) and cache `USE_TABLES`.
   - NOTE ENABLED_ACLS shell var may have been overwritten by app_acl.lua's set_cache_var only in the file, not in shell; shell keeps the value from get_config unless set to 0 here. (nftables.sh may `eval_cache_var`.)
9. Cache `ENABLED_DEFAULT_ACL`, `ENABLED_ACLS`.
10. If proxy active (either ==1): cache `bak_bridge_nf_ipt` = `sysctl -e -n net.bridge.bridge-nf-call-iptables`; `sysctl -w net.bridge.bridge-nf-call-iptables=0`; if PROXY_IPV6==1 same for `bridge-nf-call-ip6tables` (`bak_bridge_nf_ip6t`).
11. `run_process_queue` – launches all queued cores (xray/sing-box/ssr/sslocal) at once.
12. `start_crontab ACTION` (monitor.sh, cron, tasks.sh).
13. `log_i18n 0 "Running complete!"`; `echolog "\n"`.
14. If ENABLED==1 and ACTION=="boot": collect subscribe_list ids with `boot_update==1` joined by ','; if any: sleep 5; `lua subscribe.lua start <ids> cron &`.
15. return 0.

## 10. stop sequence (app.sh stop ACTION) – exact order

1. `clean_log`.
2. `eval_cache_var` (loads USE_TABLES, DEFAULT_DNSMASQ_CONF[_PATH], ACL_acl_default_dns_port, bak_bridge_nf_*…).
3. If USE_TABLES: `source $APP_PATH/<USE_TABLES>.sh stop`.
4. `delete_ip2route`.
5. For every `*_plugin.pid` under TMP_PATH: read first line, `kill -9`.
6. `busybox pgrep -af "passwall2/monitor\.sh" | xargs -r kill -9`.
7. `busybox pgrep -f "sleep.*(6s|9s|58s)" | xargs -r kill -9`.
8. `busybox pgrep -af "passwall2/"` → kill -9 every pid whose command line does NOT match `app\.sh|subscribe\.lua|rule_update\.lua|tasks\.sh|server_app\.lua|ujail` (kills cores via /tmp/etc/passwall2/bin/*, lease2hosts.sh, socks_auto_switch.sh, haproxy, dnsmasq copies…).
9. unset V2RAY_LOCATION_ASSET, XRAY_LOCATION_ASSET, SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN.
10. `stop_crontab ACTION` (skipped when ACTION=cron; so cron-triggered stop keeps cron entries and tasks.sh).
11. `rm -rf $DEFAULT_DNSMASQ_CONF $DEFAULT_DNSMASQ_CONF_PATH` (empty vars if no cache → no-op).
12. Restore:
    - `bak = @global[0].dnsmasq_dns_redirect`; if set: `uci set dhcp.@dnsmasq[0].dns_redirect=<bak>`, commit dhcp; `uci delete passwall2.@global[0].dnsmasq_dns_redirect`, commit passwall2.
    - If cache `ACL_acl_default_dns_port` empty (i.e. default ACL used the system dnsmasq / no copy instance) OR bak set: `uci del_list dhcp.@dnsmasq[0].addnmount=<DEFAULT_DNSMASQ_CONF_PATH>`, commit dhcp; `lua helper_dnsmasq.lua restart '{"LOG":"0"}'`.
    - If bak_bridge_nf_ipt: `sysctl -w net.bridge.bridge-nf-call-iptables=<v>`; same for ip6tables.
13. `rm -rf /tmp/etc/passwall2`; `rm -f /var/lock/passwall2_monitor*`.
14. `log_i18n 0 "Clearing and closing related programs and cache complete."`; `exit 0`.

(TMP_PATH2 `/tmp/etc/passwall2_tmp` is NOT removed on stop.)

---

## 11. Interfaces to other groups used here
- `app_acl.lua` stdout JSON: `{ "acl":[{"flag":..},...], "node_order":[flag,...], ... }`; files `acl/acl_node_<flag>`, `acl/<flag>/var`, `acl/<flag>/source_list`.
- `<USE_TABLES>.sh start|stop|filter_direct_node_list|update_wan_sets` – start/stop are `source`d (share variables/functions incl. `acl_node`, `get_new_port`, etc.); hotplug runs `update_wan_sets` as a separate process.
- `helper_dnsmasq.lua` subcommands: `copy_instance`, `add_rule`, `stretch`, `logic_restart`, `restart` (JSON arg).
- `haproxy.lua -path DIR -conf FILE` (sets cache `HAPROXY_PROBE_URL`); haproxy external-check uses `haproxy_check.sh`.
- `socks_auto_switch.sh <socks_id>`.
- `subscribe.lua start <ids> cron`, `rule_update.lua log all cron` – both take `/var/lock/passwall2_sub_rule.lock`.
- Lua `api` functions: `get_domain_from_url`, `is_ip`, `parseDNS`, `i18n.translatef`, `set_cache_var/get_cache_var`, `get_new_port`.

Cache keys written in this group: `DIRECT_DNS`, `DEFAULT_DNSMASQ_CONF`, `DEFAULT_DNSMASQ_CONF_PATH`, `USE_TABLES`, `ENABLED_DEFAULT_ACL`, `ENABLED_ACLS`, `bak_bridge_nf_ipt`, `bak_bridge_nf_ip6t`, `get_port_<n>`, `last_get_new_port_auto`, `node_<node>_redir_port`, `node_<node>_direct_ipset4/6`, `node_<node>_direct_nftset4/6`, `ACL_<flag>_dns_port`, `ACL_acl_default_node`, `ACL_acl_default_node_socks_port`, `<socks_id>` (=current node).

---

## 12. /etc/init.d/passwall2 (rc.common, START=99, STOP=15)
Sources utils.sh (`$IPKG_INSTROOT` prefix). APP_FILE=`/usr/share/passwall2/app.sh`. LOCK_FILE=`/var/lock/passwall2.lock`.

- `set_lock`: mkdir LOCK_PATH; `exec 9>LOCK_FILE`; `flock -xn 9` (non-blocking).
- `set_lock_wait`: same with blocking `flock -x 9`.
- `unset_lock`: `flock -u 9; exec 9>&-`.
- action normalisation for start/stop/restart: `action=${2:-$1}`; if action equals the verb name itself, action="" (rc.common passes the verb as $1? — effectively `start boot`→"boot", `start cron`→"cron", plain `start`→"").
- `boot()`: run `boot_func` in background (stdout/err null).
- `boot_func`: rm `/var/lock/passwall2_ready.lock`; delay = `uci -q get passwall2.@global_delay[0].start_delay` or 1; if >0: log "Start after a delay of %s seconds!" and sleep; `restart boot || return 1`; touch ready.lock.
- `start`: set_lock or (log "The script is already running, do not run it again. Exit."; return 0); `app.sh start <action> 9>&-`; unlock; return status.
- `stop`: set_lock_wait or (log "Unable to acquire the stop lock. Exiting."; return 1); `app.sh stop <action> 9>&-`; unlock.
- `restart`: set_lock or (log same; return 1 if action==boot else 0). Wait for subscription/rule update: up to 300 tries, each runs Lua `nixio.open(/var/lock/passwall2_sub_rule.lock,"a"):lock("tlock")` → exit 0 if lock obtained, 1 if busy, 2 if file can't open; break when !=1; sleep 2 between (max ≈600s). If final status != 0: log "Failed or timed out waiting for subscription/rule updates. Restart cancelled."; unlock; return 1. Then `app.sh stop <action>`; `app.sh start <action>`; unlock; return start status. (The tlock is released immediately when that Lua process exits — it only tests availability.)
- `reload`: echo "Warning: This service does not support configuration reloading" / "Performing full restart instead..."; restart.
- No `enable`/procd; no `service_triggers`. fd 9 is closed for children (`9>&-`) so cores don't hold the lock.

### /etc/init.d/passwall2_server (START=99)
- boot → background: `sleep 90; restart`.
- start → `lua /usr/lib/lua/luci/passwall2/server_app.lua start`; stop → `... stop`; restart = stop+start; reload = same warning + restart.

---

## 13. Hotplug

### /etc/hotplug.d/iface/98-passwall2
```
exit unless ACTION ∈ {ifup, ifupdate} and DEVICE non-empty
source utils.sh
exit unless /var/lock/passwall2_ready.lock exists
exit unless cache ENABLED_DEFAULT_ACL==1 or ENABLED_ACLS==1
default_device  = dev of first `ip route show default` line; default6_device = same for `ip -6 route show default`
exit unless DEVICE equals either
if ACTION == ifupdate: USE_TABLES=cache; if set: "/usr/share/passwall2/<USE_TABLES>.sh update_wan_sets" & ; exit 0
mkdir LOCK_PATH or (logger -p err -t network -s "passwall2: cannot create lock directory /var/lock"; exit 1)
background subshell (stdin/out/err null):
   exec 9>/var/lock/passwall2_ifup.lock (fail → logger err "passwall2: cannot open ifup lock"; exit 1)
   flock -xn 9 || exit 0
   logger -p notice -t network -s "passwall2: restart when $INTERFACE ifup"
   /etc/init.d/passwall2 restart 9>&-
exit 0
```

### /etc/hotplug.d/ntp/30-passwall2-resync
```
exit unless ACTION == step
offset = abs(int(offset))    (strip leading '-', drop fractional part)
exit if offset < 120
source utils.sh
exit if /var/lock/passwall2_ntp.lock exists
if (cache ENABLED_DEFAULT_ACL==1 or ENABLED_ACLS==1) and ready.lock exists:
    echo $$ > ntp.lock
    /etc/init.d/passwall2 restart &
    logger -p notice -t network -s "passwall2: restart after NTP time step (<offset>s)"
```

---

## 14. uci-defaults

### luci-app-passwall2
```
if /etc/config/ucitrack exists:
  uci batch: delete ucitrack.@passwall2[-1]; add ucitrack passwall2; set ucitrack.@passwall2[-1].init=passwall2; commit ucitrack
uci batch:
  delete firewall.passwall2
  set firewall.passwall2=include
  set firewall.passwall2.type='script'
  set firewall.passwall2.path='/var/etc/passwall2.include'
  set dhcp.@dnsmasq[0].localuse=1 ; commit dhcp
  set uhttpd.main.max_requests=50 ; commit uhttpd
if /sbin/fw3 executable: uci set firewall.passwall2.reload='1'
else: uci delete firewall.passwall2.reload ; uci delete firewall.passwall2.fw4_compatible
uci commit firewall
[ ! -s /etc/config/passwall2 ] && cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2
chmod +x /usr/share/passwall2/*.sh
rm -rf /tmp/etc/passwall2_tmp
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* ; rm -rf /tmp/luci-modulecache
killall -HUP rpcd
exit 0
```
(`/var/etc/passwall2.include` is written by the firewall scripts – fw3 re-runs it on firewall reload.)

### luci-app-passwall2_server
ucitrack entry `passwall2_server` (init=passwall2_server) same pattern; clear luci caches; `killall -HUP rpcd`; exit 0.

---

## 15. LuCI glue files (verbatim)

`/usr/share/ucitrack/luci-app-passwall2.json`
```json
{ "config": "passwall2", "init": "passwall2" }
```
`/usr/share/ucitrack/luci-app-passwall2-server.json`
```json
{ "config": "passwall2_server", "init": "passwall2_server" }
```
`/usr/share/rpcd/acl.d/luci-app-passwall2.json`
```json
{
  "luci-app-passwall2": {
    "description": "Grant UCI access for luci-app-passwall2",
    "read":  { "uci": [ "passwall2", "passwall2_server" ] },
    "write": { "uci": [ "passwall2", "passwall2_server" ] }
  }
}
```
(The new JS frontend will additionally need `file`/`ubus` ACLs for its rpc calls – out of scope of original.)

---

## 16. Package Makefile

- `PKG_NAME=luci-app-passwall2`, `PKG_VERSION=26.11.3`, `PKG_RELEASE=1`, `LUCI_PKGARCH=all`, `LUCI_TITLE="LuCI support for PassWall 2"`, built via `feeds/luci/luci.mk` (so i18n packages `luci-i18n-passwall2-<lang>` are produced from po/).
- `LUCI_DEPENDS`: `+coreutils +coreutils-base64 +coreutils-nohup +coreutils-timeout +curl +ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +lyaml +resolveip +tcping +geoview +v2ray-geoip +v2ray-geosite +unzip`.
- Kconfig menu "Configuration":
  - choice "Basic Core": `_Basic_Core_Xray` (select xray-core), `_Basic_Core_SingBox` (select sing-box), `_Basic_Core_All` (both); default All on aarch64/arm/i386/x86_64 else Xray.
  - `_Iptables_Transparent_Proxy` (default y if !firewall4): selects chinadns-ng dnsmasq-full dnsmasq_full_ipset ipset iptables iptables-nft iptables-zz-legacy iptables-mod-conntrack-extra iptables-mod-extra iptables-mod-iprange iptables-mod-socket iptables-mod-tproxy ip6tables-mod-nat kmod-ipt-nat.
  - `_Nftables_Transparent_Proxy` (default y if firewall4): chinadns-ng dnsmasq-full dnsmasq_full_nftset nftables kmod-nft-socket kmod-nft-tproxy kmod-nft-nat.
  - `_INCLUDE_Haproxy` → haproxy (default y on aarch64/arm/i386/x86_64).
  - `_INCLUDE_Shadowsocks_Rust_Client` (!i386) → shadowsocks-rust-sslocal (default y aarch64/x86_64).
  - `_INCLUDE_Shadowsocks_Rust_Server` (!i386) → shadowsocks-rust-ssserver (n).
  - `_INCLUDE_ShadowsocksR_Libev_Client` → shadowsocksr-libev-ssr-local + ssr-redir (y).
  - `_INCLUDE_ShadowsocksR_Libev_Server` → shadowsocksr-libev-ssr-server (n).
  - `_INCLUDE_Simple_Obfs` → simple-obfs-client (y).
  - `_INCLUDE_V2ray_Plugin` → v2ray-plugin (y on aarch64/arm/i386/x86_64).
- conffiles: `/etc/config/passwall2`, `/etc/config/passwall2_server`, `/usr/share/passwall2/direct_ip`, `/usr/share/passwall2/domains_excluded`.
- No custom postinst/prerm: luci.mk's default postinst runs uci-defaults (`default_postinst` + `/etc/uci-defaults/luci-app-passwall2*` executed then deleted) and clears LuCI caches. Rust package must reproduce: run uci-defaults on install, keep conffiles. Note `/etc/config/passwall2` is NOT shipped in the package; it's created by uci-defaults from `0_default_config`.

---

## 17. Other helper scripts

### test.sh
- `test.sh test_url URL [TRY=1] [TIMEOUT=2] [EXTRA]` → if `curl --help all` lists `--retry-all-errors`, prepend it. `curl -I -o /dev/null -skL $EXTRA --connect-timeout T --retry TRY -w %{http_code} URL`; 204 or 200 → print `200`, else raw code.
- `test_proxy` (not dispatched from CLI; uses globals retry_num/connect_timeout): google generate_204 ok → 0; else baidu ok → 1; else `ping -c 3 -W 1 223.5.5.5` ok → 1 else 2.
- `test.sh url_test_node NODE_ID [ignored]` → if node.type non-empty: port=`get_new_port 48900 tcp,udp`; `NO_REC_PROCESS=1 app.sh run_socks flag=url_test_<id> node=<id> bind=127.0.0.1 socks_port=<port> config_file=url_test_<id>.json`; sleep 2s; url = `@global_other[0].url_test_url` (default `https://www.google.com/generate_204`); `curl --connect-timeout 3 --max-time 5 -o /dev/null -I -skL -w "%{http_code}:%{time_pretransfer}" -x socks5h://127.0.0.1:<port> <url>`; kill plugin pid `$TMP_PATH/url_test_<id>_plugin.pid`; kill -9 processes matching `url_test_<id>` except test.sh; `rm -rf $TMP_PATH/*url_test_<id>*.*`. Prints `CODE:SECONDS` (or `0` if type empty). Called by controller `passwall2.lua:350`.

### haproxy_check.sh LISTEN_ADDR LISTEN_PORT SERVER_ADDR SERVER_PORT (HAProxy external-check)
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin. If any `passwall2/` process matches `app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua` → exit 0 (healthy, skip). probeUrl=cache `HAPROXY_PROBE_URL` or `https://www.google.com/generate_204`. Bracket bare IPv6 server address. `curl -q -I -o /dev/null -sk --noproxy "" -x socks5h://<addr>:<port> --connect-timeout 3 --max-time 6 -w %{http_code} <probeUrl>` ; curl fail → exit 1; code 200/204 → 0 else 1.

### lease2hosts.sh (daemon)
- flock -n `/var/lock/passwall2_lease2hosts.lock` else exit.
- Lease files: `dhcp.@dnsmasq[0].leasefile` (default `/tmp/dhcp.leases`), `dhcp.odhcpd.leasefile` (default `/tmp/odhcpd.leases`). Output `$TMP_PATH2/dhcp-hosts` (=/tmp/etc/passwall2_tmp/dhcp-hosts), temp `/tmp/dhcp-hosts.tmp`.
- STATIC_HOSTS computed once: every `dhcp` `host` section with `name` (≠`*`) and `ip` (≠`ignore`) → `"<ip> <name>"`.
- odhcpd parsing: lines starting `#`: require NF≥9, `$5` valid name (`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`), expiry `$6` == -1 or > now; only `$4=="ipv4" && $8==32` or non-ipv4 `&& $8==128`; for fields 9..NF print `<addr without /len> <$5>`. Legacy hosts-format lines (`$1` hex/dots/colons, NF≥2): print `$1 $i` for each valid name until a field starting `#`.
- dnsmasq leases: NF≥4 and `$4 != "*"` → `$3 $4`.
- Every 60s: combine (static, dnsmasq leases, odhcpd) | sort -u → tmp. If non-empty and differs from hosts file → move into place and HUP every live pid from `$TMP_PATH/acl/*_dnsmasq.pid`. If empty and hosts file non-empty → truncate and HUP. (The copy dnsmasq configs reference this file via `addn-hosts` – helper_dnsmasq group.)

### luci_update.sh DIR STATUS_FILE MANAGER FORCE (self-update installer, launched by `api.lua` ~1682 via nohup after copying itself into DIR)
- remember md5 of `/usr/share/rpcd/acl.d/luci-app-passwall2.json`.
- ext = apk if MANAGER==apk else ipk; packages = `DIR/luci-app-passwall2.<ext>` + any `DIR/luci-i18n-passwall2-*.<ext>`.
- apk: `apk add --allow-untrusted [--force-reinstall --force-overwrite] pkgs`; opkg: `opkg install [--force-reinstall] pkgs`.
- `rm -rf DIR`. On success: rm `/tmp/etc/passwall2_tmp/passwall2_version`, `/tmp/luci-indexcache*`; if ACL md5 changed and `/etc/init.d/rpcd` exists → `rpcd restart`; `uhttpd reload` if present.
- write `{"code":0}` or `{"code":1}` to STATUS_FILE; background `(sleep 60; rm -f STATUS_FILE)`.

### i18n.lua
`lua i18n.lua FMT [ARGS]` → prints `api.i18n.translatef(FMT, ARGS...)`. Rust needs an equivalent translation lookup (msgids are the English strings quoted in this spec; translations live in po/ files).

### direct_ip (conffile; default content, one CIDR per line, used by firewall group as built-in direct list)
```
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
::/127
fc00::/7
fe80::/10
ff00::/8
```
(no trailing newline after last line)

### domains_excluded (conffile; domains never proxied/hijacked; consumed by helper_dnsmasq/firewall groups)
```
courier.push.apple.com
rbsxbxp-mim.vivox.com
rbsxbxp.www.vivox.com
rbsxbxp-ws.vivox.com
rbspsxp.www.vivox.com
rbspsxp-mim.vivox.com
rbspsxp-ws.vivox.com
rbswxp.www.vivox.com
rbswxp-mim.vivox.com
disp-rbspsp-5-1.vivox.com
disp-rbsxbp-5-1.vivox.com
proxy.rbsxbp.vivox.com
proxy.rbspsp.vivox.com
proxy.rbswp.vivox.com
rbswp.vivox.com
rbsxbp.vivox.com
rbspsp.vivox.com
rbspsp.www.vivox.com
rbswp.www.vivox.com
rbsxbp.www.vivox.com
rbsxbxp.vivox.com
rbspsxp.vivox.com
rbswxp.vivox.com
Mijia Cloud
dlg.io.mi.com
marscdn.c2c.wechat.com
```
("Mijia Cloud" is a comment-like label line; consumers must tolerate it.)

---

## 18. UCI options read/written by this group (summary)

| Section | Option | Default (in code) | Use |
|---|---|---|---|
| @global[0] | enabled | 0 | master switch |
| | node | "" | default ACL node (must be section type `nodes`) |
| | acl_enable | 0 | ENABLED_ACLS |
| | socks_enabled | 0 | start socks services |
| | loglevel | warning (xray) / warn (sing-box) | core log level |
| | direct_dns_protocol | (auto) | tcp/udp → use direct_dns |
| | direct_dns | | parsed with api.parseDNS |
| | direct_dns_query_strategy | UseIP | |
| | dns_redirect | 1 | 1 = separate dnsmasq copy; else inject into main dnsmasq |
| | dnsmasq_dns_redirect | (written) | backup of dhcp dns_redirect; deleted at stop |
| @global_forwarding[0] | prefer_nft | 1 | |
| | tcp_proxy_way | redirect | passed to cores |
| | ipv6_tproxy | 0 | bridge-nf ip6tables toggle |
| @global_delay[0] | start_daemon | 0 | monitor.sh |
| | start_delay | 1 (code) / 60 (default config) | boot delay seconds |
| | start/stop/restart_week_mode, *_time_mode ("HH:MM"), restart_interval_mode (hours) | | cron |
| @global_rules[0] | v2ray_location_asset | /usr/share/v2ray/ | env + geoip.dat path |
| | update_week_mode, update_time_mode, update_interval_mode | | rule cron |
| @global_app[0] | xray_file, sing_box_file, geoview_file | | binary paths |
| @global_haproxy[0] | balancing_enable | 0 | |
| @global_other[0] | url_test_url | https://www.google.com/generate_204 | test.sh |
| socks (named) | enabled, node, bind_local, port, log(1), http_port(0), enable_autoswitch | | |
| subscribe_list | remark, update_week_mode, update_time_mode, update_interval_mode, boot_update | | |
| nodes | type, protocol, remarks, address, port, use_ipv6, write_ipset_direct, hysteria_hop, hysteria2_hop, hysteria2_realms | | |
| any section | address, download_address | | vpslist for chinadns-ng |
| dhcp.@dnsmasq[0] | dns_redirect (r/w), addnmount (list r/w), server (r), leasefile (r), localuse (w=1) | | |
| dhcp.odhcpd | leasefile | | |
| dhcp host sections | name, ip | | lease2hosts |
| firewall.passwall2 (include) | type=script, path=/var/etc/passwall2.include, reload=1 (fw3 only) | | |
| uhttpd.main | max_requests=50 | | |
| ucitrack | passwall2/init=passwall2 | | |

Week-mode values: `0`–`6` = weekday (cron DOW), `7` = daily, `8` = every N hours (interval loop).

---

## 19. External commands used (exhaustive for this group)
`uci`, `busybox pgrep -f/-af`, `kill -9`, `pidof`, `xargs`, `awk`, `sed`, `grep`, `netstat -tln/-uln/-tuln`, `resolveip -4|-6 -t N`, `route add -host IP gw GW dev DEV`, `route del -host IP dev DEV`, `ubus call network.interface dump`, `ubus call network.interface.<if> status`, `jsonfilter`, `ip -o -4|-6 addr show scope global`, `ip [-6] route show default`, `sysctl -e -n` / `sysctl -w net.bridge.bridge-nf-call-ip[6]tables=`, `dnsmasq -v`, `command -v iptables-legacy|iptables|ipset|fw4|setsid|chinadns-ng`, `xray run -test -c` / `xray run -c`, `sing-box version` / `check -c` / `run -c`, `ssr-local -c F -v -u`, `sslocal -c F -v`, `haproxy -f F`, `dnsmasq -C F [-x PID]`, `chinadns-ng -C F -v`, `geoview -input .. -list .. -lowmem=true -output ..`, `lua <script> ...`, `/etc/init.d/cron restart`, `logger`, `flock`, `curl`, `ping`, `opkg`/`apk`, `md5sum`, `/etc/init.d/rpcd restart`, `/etc/init.d/uhttpd reload`, `killall -HUP rpcd`, `nohup`, `setsid`, `ulimit -n 65535`, `cmp`, `date`.

## 20. Generated runtime files (this group)
```
/tmp/log/passwall2.log
/tmp/etc/passwall2/var                         cache vars
/tmp/etc/passwall2/bin/<name>                  symlinks to binaries
/tmp/etc/passwall2/script_func/<n>|queued_<n>  launched command lines
/tmp/etc/passwall2/process_list/<n>            (transient queue)
/tmp/etc/passwall2/route/<device>              added host routes
/tmp/etc/passwall2/test.log                    core config test output when log is /dev/null
/tmp/etc/passwall2/direct_node_list            node ids for direct whitelist
/tmp/etc/passwall2/<socks_id>.json, <id>+http.json, <id>_http.json, <id>.log, <id>_plugin.sh/.pid
/tmp/etc/passwall2/haproxy/config.cfg
/tmp/etc/passwall2/sub_crontabs/, sub_tasks/   (transient)
/tmp/etc/passwall2/acl/<flag>.json|.log         ACL core config/log (paths from app_acl.lua)
/tmp/etc/passwall2/acl/dns_<flag>_direct.conf   chinadns-ng/dnsmasq direct-ipset config
/tmp/etc/passwall2/acl/vpslist
/tmp/etc/passwall2/acl/<flag>_dnsmasq.conf, <flag>_dnsmasq.d/, <flag>_dnsmasq.pid
/tmp/etc/passwall2/acl/acl_default_dnsmasq.d/   (DEFAULT_DNSMASQ_CONF_PATH)
<dnsmasq conf-dir>/dnsmasq-passwall2.conf       (DEFAULT_DNSMASQ_CONF, only in dns_redirect=0 mode)
/tmp/etc/passwall2_tmp/geo_output/geoip-<code>-<fam>
/tmp/etc/passwall2_tmp/dhcp-hosts
/etc/crontabs/root                              lines added/removed
/var/lock/passwall2*.lock
```

---

## 21. Default `/etc/config/passwall2` (verbatim copy of `/usr/share/passwall2/0_default_config`)

```
config global
	option enabled '0'
	option node_socks_port '1070'
	option localhost_proxy '1'
	option client_proxy '1'
	option socks_enabled '0'
	option acl_enable '0'
	option node 'rulenode'
	option direct_dns_protocol 'auto'
	option direct_dns_query_strategy 'UseIP'
	option remote_dns_protocol 'tcp'
	option remote_dns '1.1.1.1'
	option remote_dns_query_strategy 'UseIPv4'
	option dns_hosts 'cloudflare-dns.com 1.1.1.1
dns.google.com 8.8.8.8'
	option log_node '1'
	option loglevel 'error'

config global_haproxy
	option balancing_enable '0'

config global_delay
	option start_daemon '1'
	option start_delay '60'

config global_forwarding
	option tcp_redir_ports '1:65535'
	option udp_redir_ports '1:65535'
	option accept_icmp '0'
	option prefer_nft '1'
	option tcp_proxy_way 'redirect'
	option ipv6_tproxy '0'

config global_xray
	option sniffing_override_dest '0'

config global_other
	option auto_detection_time 'tcping'
	option show_node_info '0'

config global_rules
	option geosite_update '1'
	option geoip_update '1'
	option v2ray_location_asset '/usr/share/v2ray/'
	option geoip_url 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat'
	option geosite_url 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat'

config global_app
	option geoview_file '/usr/bin/geoview'
	option xray_file '/usr/bin/xray'
	option sing_box_file '/usr/bin/sing-box'

config global_subscribe
	option filter_keyword_mode '1'

config global_singbox

config nodes 'examplenode'
	option remarks 'Example'
	option type 'Xray'
	option protocol 'socks'
	option address 'passwall2.github'
	option port '1080'
	option tls '0'
	option transport 'raw'
	option tcp_guise 'none'
	option tcp_fast_open '0'
	option tcpMptcp '0'

config nodes 'rulenode'
	option remarks 'rulenode'
	option type 'Xray'
	option protocol '_shunt'
	option PrivateIP '_direct'
	option default_node 'examplenode'
	option domainStrategy 'IPOnDemand'
	option domainMatcher 'hybrid'
	option write_ipset_direct '1'
	option enable_geoview_ip '1'
	option shunt_group 'CN'

config shunt_rules 'DirectFront'
	option remarks 'DirectFront'
	option network 'tcp,udp'
	option domain_list 'domain:ip233.cn'
	option group 'CN'

config shunt_rules 'ProxyFront'
	option remarks 'ProxyFront'
	option network 'tcp,udp'
	option domain_list 'domain:www.gstatic.com
domain:ssl.gstatic.com
domain:fonts.gstatic.com'
	option group 'CN'

config shunt_rules 'DirectGame'
	option remarks 'DirectGame'
	option domain_list '# steam直连域名获取国内CDN走国内线路下载
cm.steampowered.com
steamserver.net

# steam国内CDN华为云
steampipe.steamcontent.tnkjmec.com
# steam国内CDN白山云
st.dl.eccdnx.com
st.dl.bscstorage.net
st.dl.pinyuncloud.com
# steam国内CDN新流云(原金山云)(支持ipv6)
dl.steam.clngaa.com
# steam国内CDN网宿
cdn.mileweb.cs.steampowered.com.8686c.com
cdn-ws.content.steamchina.com
# steam国内CDN腾讯云 (蒸汽中国独占)
cdn-qc.content.steamchina.com
# steam国内CDN阿里云(支持ipv6)
cdn-ali.content.steamchina.com
xz.pphimalayanrt.com
lv.queniujq.cn
alibaba.cdn.steampipe.steamcontent.com

# 国内游戏geosite域名
geosite:category-games@cn'
	option ip_list '# steam直连IP
45.121.184.0/24
103.10.124.0/23
103.28.54.0/24
146.66.152.0/24
146.66.155.0/24
153.254.86.0/24
155.133.224.0/22
155.133.230.0/24
155.133.232.0/23
155.133.234.0/24
155.133.236.0/22
155.133.240.0/23
155.133.244.0/23
155.133.246.0/24
155.133.248.0/21
162.254.192.0/21
185.25.182.0/23
190.217.32.0/22
192.69.96.0/22
205.196.6.0/24
208.64.200.0/22
208.78.164.0/22
205.185.194.0/24'
	option network 'tcp,udp'
	option group 'CN'

config shunt_rules 'ProxyGame'
	option remarks 'ProxyGame'
	option domain_list '# steam 商店/客服/聊天/网页布局/API/二维码/Google云同步 代理URL
steamcommunity.com
www.steamcommunity.com
store.steampowered.com
checkout.steampowered.com
api.steampowered.com
help.steampowered.com
login.steampowered.com
store.akamai.steamstatic.com
steambroadcast.akamaized.net
steamvideo-a.akamaihd.net
steamusercontent-a.akamaihd.net
steamstore-a.akamaihd.net
steamcommunity-a.akamaihd.net
steamcdn-a.akamaihd.net
steamuserimages-a.akamaihd.net
community.akamai.steamstatic.com
avatars.akamai.steamstatic.com
community.steamstatic.com
cdn.akamai.steamstatic.com
avatars.steamstatic.com
shared.akamai.steamstatic.com
clan.akamai.steamstatic.com
cdn.cloudflare.steamstatic.com
community.cloudflare.steamstatic.com
store.cloudflare.steamstatic.com
avatars.cloudflare.steamstatic.com
clan.cloudflare.steamstatic.com
shared.cloudflare.steamstatic.com
steam-chat.com
steamcloud-ugc.storage.googleapis.com
steamcloud-eu-ams.storage.googleapis.com
steamcloud-eu-fra.storage.googleapis.com
steamcloud-finland.storage.googleapis.com
steamcloud-saopaulo.storage.googleapis.com
steamcloud-singapore.storage.googleapis.com
steamcloud-sydney.storage.googleapis.com
steamcloud-taiwan.storage.googleapis.com
steamcloud-eu.storage.googleapis.com
domain:blizzard.com
geosite:category-games'
	option network 'tcp,udp'
	option group 'CN'

config shunt_rules 'CN'
	option remarks 'CN'
	option domain_list 'geosite:cn'
	option ip_list 'geoip:cn'
	option network 'tcp,udp'
	option group 'CN'

config shunt_rules 'Iran'
	option remarks 'Iran'
	option network 'tcp,udp'
	option domain_list 'geosite:ir
#rule-set:remote:https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs'
	option ip_list 'geoip:ir
#rule-set:remote:https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs'
	option group 'IR'

config shunt_rules 'Russia_Block'
	option remarks 'Russia_Block'
	option network 'tcp,udp'
	option domain_list 'geosite:ru-blocked
#rule-set:remote:https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/refs/heads/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs'
	option ip_list 'geoip:ru-blocked
#rule-set:remote:https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/refs/heads/release/sing-box/rule-set-geoip/geoip-ru-blocked.srs'
	option group 'RU'

config shunt_rules 'Russia'
	option remarks 'Russia'
	option network 'tcp,udp'
	option ip_list 'geoip:ru
#rule-set:remote:https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/refs/heads/release/sing-box/rule-set-geoip/geoip-ru.srs'
	option group 'RU'
```
(File begins with one empty line.)

Default `/etc/config/passwall2_server`:
```

config global 'global'
	option enable '0'
```

---

## 22. Rewrite notes / gotchas to preserve
- All option values are strings; `eval_set_val` means values with spaces break — Rust CLI should accept `k=v` words AND a single argument containing space-separated `k=v` pairs (Lua callers pass one quoted string).
- The `flag` is the process identity: kill-by-flag uses case-insensitive regex substring on full cmdline of processes under `/tmp/etc/passwall2/bin`. Rust supervisor can track PIDs directly, but must still kill external leftovers on start (step 1) and keep config file names containing the flag.
- Core processes must be started with symlinked argv[0] in `/tmp/etc/passwall2/bin/` (other tools – monitor, stop, haproxy_check — rely on path patterns). A Rust implementation may replace monitor.sh with an internal supervisor but must keep `start_daemon` semantics (respawn crashed processes ~every 58 s).
- Queue semantics: during `start`, all cores are written to the queue and spawned only after firewall rules are applied (step 11); haproxy and dnsmasq/chinadns-ng instances (QUEUE=0) start immediately.
- `restart` waits up to 600 s for subscription/rule updates.
- On stop, processes named `app.sh`, `subscribe.lua`, `rule_update.lua`, `tasks.sh`, `server_app.lua`, `ujail` are spared.
- `stop` always `exit 0`.
