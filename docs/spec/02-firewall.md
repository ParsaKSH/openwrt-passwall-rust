# 02 — Firewall layer: `nftables.sh` and `iptables.sh`

Source files (upstream luci-app-passwall2):

- `root/usr/share/passwall2/nftables.sh` (1009 lines): fw4 / nftables backend
- `root/usr/share/passwall2/iptables.sh` (1012 lines): fw3 / iptables + ipset backend

Both scripts export the same entry points (`start`, `stop`, `filter_direct_node_list`, `update_wan_sets`). They build the transparent-proxy rule set: REDIRECT or TPROXY for TCP, TPROXY for UDP, optional ICMP redirect, DNS hijack per ACL, IPv6 TPROXY, bypass sets and fwmark policy routing. The Rust rewrite must produce the same kernel state (same table, chain, set, mark and comment names), because other components (the dnsmasq/chinadns-ng `nftset=`/`ipset=` directives, the firewall include, mwan3 integration, LuCI status checks) refer to these names.

---

## 0. How the scripts are invoked and what they get from outside

### 0.1 Callers

| Caller | Invocation | Context |
|---|---|---|
| `app.sh start()` | `source $APP_PATH/${USE_TABLES}.sh start` | Sourced. Inherits all of app.sh's variables and functions (utils.sh is already loaded). Runs only when `USE_TABLES` is non-empty **and** `ACL_JSON.node_order` is not empty. app.sh then sets cache var `USE_TABLES`. |
| `app.sh stop()` | `eval_cache_var; [ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh stop` | Sourced. `USE_TABLES` is read from the cache file. |
| `app.sh` (after a non-xray/sing-box node starts, ~line 560) | `source $APP_PATH/${USE_TABLES}.sh filter_direct_node_list` | Sourced. |
| Firewall include `/var/etc/passwall2.include` | `/usr/share/passwall2/<backend>.sh update_wan_sets` (both backends); iptables also uses `iptables.sh insert_rule_after ...` and `iptables.sh insert_rule_before ...` | Executed as a standalone program (not sourced). `update_wan_sets` sources `utils.sh` itself when `get_wan_ips` is missing. |
| `/etc/init.d/mwan3` (patched by nftables.sh) | `/usr/share/passwall2/nftables.sh mwan3_start` / `mwan3_stop` | Standalone. |

Dispatcher at the end of each script: `arg1=$1; shift; case $arg1 in ... esac`. Unknown args do nothing.

- nftables.sh accepts: `filter_direct_node_list`, `mwan3_start`, `mwan3_stop`, `update_wan_sets "$@"`, `stop`, `start`.
- iptables.sh accepts: `RULE_LAST_INDEX "$@"`, `insert_rule_before "$@"`, `insert_rule_after "$@"`, `get_ipt_bin`, `get_ip6t_bin`, `filter_direct_node_list`, `update_wan_sets "$@"`, `stop`, `start`.

### 0.2 Backend selection (in app.sh `check_run_environment`, listed here for completeness)

- `prefer_nft = uci passwall2.@global_forwarding[0].prefer_nft` (default `1`).
- `dnsmasq_nftset`: `dnsmasq -v` output contains the word `nftset`. `dnsmasq_ipset`: it contains `ipset`.
- `has_ipt`: `iptables-legacy` or `iptables` is in PATH. `has_ipset`: `ipset` is in PATH. `has_fw4`: `fw4` is in PATH.
- If prefer_nft=1: use nftables if (dnsmasq_nftset && has_fw4); else iptables if (has_ipset && has_ipt && dnsmasq_ipset), with a warning log. Otherwise nothing.
- If prefer_nft!=1: the same two checks in the opposite order.
- If no backend fits, log a warning and set up no transparent proxy.
- Dependency warnings (package list files under `/usr/lib/opkg/info/<pkg>.control` or `/lib/apk/packages/<pkg>.list`):
  - iptables: `iptables-mod-tproxy iptables-mod-socket iptables-mod-iprange iptables-mod-conntrack-extra iptables-mod-extra kmod-ipt-nat`
  - nftables: `kmod-nft-socket kmod-nft-tproxy kmod-nft-nat`. Also sets `nftflag=1`, and warns if the dnsmasq version digits are below 290.

### 0.3 Global variables consumed (all set by app.sh / utils.sh)

| Var | Source / value | Use |
|---|---|---|
| `CONFIG` | `passwall2` | UCI package name and lock name |
| `DIRECT_GID` | `9912` | Proxy core processes run with this gid; their output skips the firewall rules |
| `TMP_PATH` | `/tmp/etc/passwall2` | `direct_node_list`, `PSW2_RULE.nft`, cache file `var` |
| `TMP_PATH2` | `/tmp/etc/passwall2_tmp` | geoview output `geo_output/`, `singbox*` |
| `TMP_ACL_PATH` | `/tmp/etc/passwall2/acl` | per-ACL dirs `<sid>/var`, `<sid>/source_list` |
| `TMP_IFACE_PATH` | `/tmp/etc/passwall2/iface` | If this dir exists, each entry name is an interface whose output is excluded. **No current code writes this dir** (legacy), but keep the behaviour. |
| `LOCK_PATH` | `/var/lock` | `update_wan_sets` lock |
| `ACL_JSON` | stdout of `lua app_acl.lua` | `$.acl[*].flag` gives the ordered ACL list |
| `ENABLED_DEFAULT_ACL`, `ENABLED_ACLS` | 0/1 | `start` returns immediately when both are 0 |
| `TCP_PROXY_WAY` | `@global_forwarding[0].tcp_proxy_way`, default `redirect`; values `redirect`/`tproxy` | TCP mode |
| `PROXY_IPV6` | `@global_forwarding[0].ipv6_tproxy`, default `0` | Enables IPv6 proxying |
| `NODE` | `@global[0].node` | Its `address`/`download_address` go into the VPS set (nft only) |
| `ISP_DNS` | IPv4s from `/tmp/resolv.conf.d/resolv.conf.auto` (falls back to `/tmp/resolv.conf.auto`), excluding 0.0.0.0/127.0.0.1, de-duplicated, whitespace-separated | Added to the direct set |
| `ISP_DNS6` | IPv6 addresses from the same file, with `%scope` removed, excluding `::1` and `::` | Added to direct6 |
| `RETURN_DNS` | Comma list `addr[#port[#proto]]`, = AUTO_DNS (dnsmasq upstream `server` list, else the first 2 ISP DNS, else `119.29.29.29`), plus `,<server>#<port>#<proto>` when `@global[0].direct_dns_protocol` is tcp/udp | Router-originated DNS to these servers is never proxied |

Helper functions used (from utils.sh / app.sh; to be reimplemented in Rust):

- `config_n_get <section> <option> [default]` = `uci -q get passwall2.<section>.<option>`, or the default when empty.
- `get_cache_var key` / `set_cache_var key val`: key="val" lines in `$TMP_PATH/var`.
- `has_1_65535 list`: replace `:` with `-`; true when `,list,` contains `,1-65535,`.
- `get_local_ips ip4|ip6`: global-scope addresses from `ip -o -4|-6 addr show scope global` (field 4, without the prefix length), plus `127.0.0.1` or `::1`, excluding `0.0.0.0`, `::`, the WAN IPs and duplicates. Output is one IP per line.
- `get_wan_ips ip4|ip6`: for interfaces from `ubus call network.interface dump | jsonfilter -e '@.interface[!(@.interface ~ /lan/) && !(@.l3_device ~ /\./) && @.route[0]].interface'`, takes `network_get_ipaddr` (skip empty or `0.0.0.0`) or `network_get_ipaddr6` (skip empty or `fe80*`). De-duplicated, space-separated.
- `get_geoip <codes> ipv4|ipv6`: cached at `$TMP_PATH2/geo_output/geoip-<codes>-<type>`. Otherwise runs `<geoview> -input <v2ray_location_asset>/geoip.dat -list <codes> -ipv6=false|-ipv4=false -lowmem=true -output <file>`, where the asset dir comes from `@global_rules[0].v2ray_location_asset` and the binary from `@global_app[0].geoview_file` or `geoview`. Prints nothing if the binary or the dat file is missing.
- `get_host_ip ipv4|ipv6 host [count=3]`: a literal IP is returned as is (IPv6 with `[]` stripped). Otherwise `resolveip -4|-6 -t <count> host`, first line.
- `first_type name`: find a binary.
- `network_get_gateway`, `network_get_device` come from `/lib/functions/network.sh`.
- `log level msg`, `log_i18n level fmt args...`, `i18n fmt args...`: logging only.

### 0.4 Per-ACL variable file `$TMP_ACL_PATH/<sid>/var` (written by app_acl.lua)

Lines of the form `key="value"`, for every string field of the ACL entry. Fields:

| Key | Default ACL (`sid=acl_default`) | `acl_rule` section `<sid>` |
|---|---|---|
| `flag` | `acl_default` | section name |
| `remarks` | translated "Default" | `remarks` |
| `interface` | — (unset) | `interface` (logical network name, optional) |
| `tcp_no_redir_ports` / `udp_no_redir_ports` | `@global_forwarding[0].*` | the rule's option. `mode=0` forces both to `1:65535` |
| `tcp_redir_ports` / `udp_redir_ports` | `@global_forwarding[0].*` (defaults `1:65535`) | the rule's option |
| `local_proxy` | `@global[0].localhost_proxy` (default config `1`) | always `0` |
| `client_proxy` | `@global[0].client_proxy` (default config `1`) | always `1` |
| `use` | `acl_default`, if the global node exists and is of type `nodes` | own sid when it has a valid node. `mode=2` uses `acl_default`, forcing the default node to be enabled and setting the default ACL's local_proxy=0 and client_proxy=0 |
| `node` | the UCI node section id (written after the fields, so it overrides) | same |
| `node_remarks` | the node's `remarks` | same |
| `redir_port` | the port allocated for the core's dokodemo/redirect inbound | same |

`node` is removed (no node is used) when both no_redir lists are `1:65535`.

`$TMP_ACL_PATH/<sid>/source_list` has one token per line:

- `any`: no sources configured, or none recognised.
- `iprange:<a-b>`
- `ipset:ipset:<name>`: the UCI value already starts with `ipset:` and Lua prefixes it again. The shell removes every `ipset:` occurrence with `sed 's#ipset:##g'`, which leaves `<name>`.
- `ip:<ip or cidr>`
- `mac:<mac>`

DNS redirect port: `dns_redirect_port = get_cache_var "ACL_${use}_dns_port"`. This is set by `run_copy_dnsmasq` (the per-ACL dnsmasq copy instance). It is not set for `acl_default` when `@global[0].dns_redirect`=0, because the main dnsmasq is modified instead.

### 0.5 ACL processing order

`for sid in $(jsonfilter -s "$ACL_JSON" -e '$.acl[*].flag')`: first the enabled `acl_rule` sections in UCI order, then `acl_default` **last**. Rule order inside the chains follows this order. Before the loop, `load_acl` calls `acl_node` (app.sh; it starts the cores and dnsmasq instances for every ACL node, and therefore creates the `ACL_*_dns_port` cache vars).

---

## 1. Shared constants

| Name | Value |
|---|---|
| FWMARK | `0x50535732` ("PSW2") |
| Routing table / rule priority | table `999`, `ip rule add fwmark 0x50535732 table 999 priority 999`, `ip route add local 0.0.0.0/0 dev lo table 999` (v6: `ip -6 ...` and `local ::/0`) |
| FAKE_IP | `198.18.0.0/16` |
| FAKE_IP_6 | `2001:2::/48` |
| FWI (include path) | `uci -q get firewall.passwall2.path`, = `/var/etc/passwall2.include`. uci-defaults creates `firewall.passwall2=include`, `type=script`, `path=/var/etc/passwall2.include`, plus `reload=1` on fw3. |
| Direct IP list file | `/usr/share/passwall2/direct_ip`: lines; `#` comments and blanks are skipped; an entry containing `::` goes to v6; `geoip:<code>` is expanded; anything else goes to v4. Shipped content: `0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ::/127 fc00::/7 fe80::/10 ff00::/8` |
| Mark mask check | `meta mark and 0xff == 0xff` / `-m mark --mark 0xff/0xff` means skip. Some cores mark their own sockets with `0xff`. |

Set names (identical for nft sets and ipsets):

| v4 | v6 | Content |
|---|---|---|
| `psw2_local` | `psw2_local6` | router's own IPs (`get_local_ips`) |
| `psw2_direct` | `psw2_direct6` | direct_ip file + LAN subnet + ISP DNS; never proxied as destination; also used as "source is LAN" in DNS hijack |
| `psw2_vps` | `psw2_vps6` | all node server IPs, so proxy-server traffic is never looped |
| `psw2_wan` | `psw2_wan6` | WAN IPs (`get_wan_ips`) |
| `psw2_<node>_<shunt_id>` | `psw2_<node>_<shunt_id>6` | Shunt rule IP preloading (geoview) |
| `psw2_<node>_white` | `psw2_<node>_white6` | Direct-domain resolved IPs, filled at runtime by the direct DNS server (chinadns-ng/dnsmasq). The name comes from cache var `node_<node>_direct_nftset4/6` or `node_<node>_direct_ipset4/6`. |

The nft set spec string handed to dnsmasq elsewhere is `4#inet#passwall2#psw2_<node>_white,6#inet#passwall2#psw2_<node>_white6`.

---

## 2. nftables backend (`nftables.sh`)

### 2.1 Table and base chains

`NFTABLE_NAME="inet passwall2"`. `gen_nft_tables()` runs only if `nft list table inet passwall2` fails, and then executes `nft -f -` with:

```
table inet passwall2 {
  chain dstnat            { type nat    hook prerouting priority dstnat - 1; policy accept; }
  chain mangle_prerouting { type filter hook prerouting priority mangle - 1; policy accept; }
  chain mangle_output     { type route  hook output     priority mangle - 1; policy accept; }
  chain nat_output        { type nat    hook output     priority -1;         policy accept; }
}
```

The table and its base chains are **never deleted** by `stop` (`flush_table` exists but is unused and commented out). Only PSW2_* rules, PSW2_* chains and the main sets are removed.

Regular chains created with `nft add chain inet passwall2 X` followed by `nft flush chain inet passwall2 X`: `PSW2_DNS`, `PSW2_RULE`, `PSW2_MANGLE`, `PSW2_OUTPUT_MANGLE`, `PSW2_NAT` (redirect mode only), `PSW2_OUTPUT_NAT` (redirect mode only), `PSW2_ICMP_REDIRECT` (accept_icmp=1 only), `PSW2_MANGLE_V6`, `PSW2_OUTPUT_MANGLE_V6`.

Mode variables (set in `add_firewall_rule`):

- `TCP_PROXY_WAY=redirect`: `is_tproxy` unset, `nft_prerouting_chain=PSW2_NAT`, `nft_output_chain=PSW2_OUTPUT_NAT`.
- `TCP_PROXY_WAY=tproxy`: `is_tproxy=TPROXY`, `nft_prerouting_chain=PSW2_MANGLE`, `nft_output_chain=PSW2_OUTPUT_MANGLE`.
- Any other value leaves these unset, so the rules are malformed. Treat it as redirect, or reject it.

### 2.2 Helper functions

**`factor <value> <prefix>`** builds the nft match fragment:

```
if value=="" or prefix=="" or value=="1:65535": return ""
if value matches /([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}/:   # MAC
    return "<prefix> {<value>}"
items = value without spaces; ':'→'-'; split on ','; dedupe (keep first); drop empties
if items empty: return ""
if any item == "1-65535": return ""
return "<prefix> {" + join(items, ",") + "}"
```

Examples: `factor "80,443,1000:2000" "tcp dport"` gives `tcp dport {80,443,1000-2000}`. `factor 53 "udp dport"` gives `udp dport {53}`.

Upstream quirk: the same function is applied to `ip:` and `iprange:` sources (`ip saddr {...}`). An IPv6 `ip:` source therefore has its colons turned into `-`, which produces an invalid rule. The Rust version should not mangle IPs; for IPv6 sources it should use `ip6 saddr`. If the upstream behaviour is replicated instead, this has to be documented.

**`REDIRECT [port] [mode]`** returns the action string:

- no port: `counter redirect` (to the local host, used for ICMP)
- port, no mode: `counter redirect to :<port>`
- mode `TPROXY`: `counter meta mark 0x50535732 tproxy to :<port>`
- mode `TPROXY4`: `counter meta mark 0x50535732 tproxy ip to :<port>`
- mode `TPROXY6`: `counter meta mark 0x50535732 tproxy ip6 to :<port>`

`meta mark 0x50535732` here is a **match**: the TPROXY rule fires only for packets that `PSW2_RULE` has already marked.

**`gen_nftset name type timeout_set timeout_elem`**: if `nft list set inet passwall2 <name>` fails:

- timeout_set=="0" (all callers pass 0): `nft "add set inet passwall2 <name> { type <ipv4_addr|ipv6_addr>; flags interval, timeout; auto-merge; }"`
- otherwise: `... { type T; flags interval, timeout; timeout <t>; gc-interval 1h; auto-merge; }`
- timeout_elem is unused.

**`insert_nftset name`**: reads stdin, splits it on any whitespace, and if there is at least one token pipes the following to `nft -f -`:

```
add element inet passwall2 <name> { 
 tok1,
 tok2
 }
```

Empty input gives empty nft input, which does nothing. Duplicates and overlaps are handled by auto-merge. nft errors are not checked.

**`destroy_nftset names...`**: `nft flush set inet passwall2 <n>; nft delete set inet passwall2 <n>` (errors ignored).

**`insert_rule_before/insert_rule_after/RULE_LAST_INDEX`** (nft variants) are defined but **unused** in nftables.sh. They look up a handle with `nft -a list chain T C | grep kw` and then `nft insert rule T C position <h> ...` or `add rule`.

**`add_shunt_t_rule shunt_list cmd_prefix jump [comment]`**: for each token `set:outbound` in shunt_list, run `<cmd_prefix> @<set> <action> [comment "<c>"]`. The action is `counter return` when outbound=`direct`, otherwise `jump`. cmd_prefix is a complete `nft add rule ...` command ending in `ip daddr` / `ip6 daddr`.

**`gen_shunt_list node out4var out6var`**:

```
unset out4, out6
if config(node).protocol == "_shunt":
  enable_geoview_ip = config(node).enable_geoview_ip default 0; forced 0 if no geoview binary
  if enable_geoview_ip == 1:
    default_outbound = (config(node).default_node default "_direct") == "_direct" ? direct : redirect
    for shunt_id in all sections of type shunt_rules (uci order):
      if config(node).shunt_group != config(shunt_id).group: skip   (both may be empty and still match)
      shunt_node = config(node).<shunt_id>
      if shunt_node non-empty:
        v4="psw2_<node>_<shunt_id>", v6="psw2_<node>_<shunt_id>6"
        gen_nftset v4 ipv4_addr 0 0; gen_nftset v6 ipv6_addr 0 0
        outbound = shunt_node=="_direct" ? direct : shunt_node=="_default" ? default_outbound : redirect
        append " v4:outbound" to L4, " v6:outbound" to L6
        ip_list (list option; strip "#..." comments):
          lines matching IPv4 regex (\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3} → insert_nftset v4
          lines matching IPv6 regex ([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4} → insert_nftset v6
        codes = ip_list lines starting "geoip:" except "geoip:private", prefix stripped, joined by ","
        if codes: get_geoip codes ipv4 | v4-regex → v4 set; get_geoip codes ipv6 | v6-regex → v6 set
  d4 = cache node_<node>_direct_nftset4; if set: gen_nftset d4 ipv4_addr; append " d4:direct" to L4
  d6 = cache node_<node>_direct_nftset6; likewise for v6
set out4=L4, out6=L6 if non-empty
set_cache_var node_<node>_gen_shunt_list 1
```

Upstream quirk: in `load_acl` the list is generated only once per node (guarded by the cache var), but `shunt_list4/6` are shell globals. A later ACL that uses a node already processed reuses whatever list was generated last, which may belong to a different node. The Rust version should keep a per-node map.

### 2.3 `add_firewall_rule()`: exact order

1. `log_i18n 0 "Starting to load nftables firewall rules..."`
2. `gen_nft_tables`
3. `add_script_mwan3`, then `mwan3_start` (§2.7)
4. Create sets with `gen_nftset ... 0 -1`: `psw2_local psw2_direct psw2_vps psw2_wan` (ipv4_addr), then `psw2_local6 psw2_direct6 psw2_vps6 psw2_wan6` (ipv6_addr).
5. `get_local_ips ip4 | insert_nftset psw2_local`; `get_local_ips ip6 | insert_nftset psw2_local6`
6. Process the direct_ip file one entry at a time: `*::*` goes to `psw2_direct6`; `geoip:<code>` (the code is field 2 split on `:`) is expanded with get_geoip ipv4 (v4 regex) into `psw2_direct` and ipv6 (v6 regex) into `psw2_direct6`; anything else goes to `psw2_direct`.
7. LAN: `lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)`. If it is non-empty, the CIDRs from `ip address show <if>`, `inet` → psw2_direct and `inet6` → psw2_direct6. On modern OpenWrt this value is normally empty.
8. `update_wan_sets` (§2.6)
9. ISP_DNS → psw2_direct; ISP_DNS6 → psw2_direct6 (one log line per IP)
10. In the background (`&`, output discarded): `filter_vpsip`, `filter_haproxy`, `filter_vps_addr <NODE.address>`, `filter_vps_addr <NODE.download_address>` (§2.5)
11. `accept_icmp = @global_forwarding[0].accept_icmp` (default 0); `accept_icmpv6 = @global_forwarding[0].accept_icmpv6` (default 0)
12. Set the mode variables (§2.1)
13. PSW2_DNS:
    ```
    add chain inet passwall2 PSW2_DNS ; flush chain inet passwall2 PSW2_DNS
    if @global[0].dns_redirect (default "1") == "0":
      insert rule inet passwall2 dstnat ip saddr @psw2_direct ip daddr @psw2_local jump PSW2_DNS
      insert rule inet passwall2 dstnat ip6 saddr @psw2_direct6 ip6 daddr @psw2_local6 jump PSW2_DNS
    else:
      insert rule inet passwall2 dstnat ip saddr @psw2_direct jump PSW2_DNS
      insert rule inet passwall2 dstnat ip6 saddr @psw2_direct6 jump PSW2_DNS
    ```
    (`insert` prepends, so the v6 rule ends up above the v4 rule.)
14. PSW2_RULE (marking):
    ```
    PSW2_RULE: counter meta mark set ct mark
    PSW2_RULE: meta mark 0x50535732 counter return
    PSW2_RULE: tcp flags & (fin|syn|rst|ack) == syn counter meta mark set 0x50535732
    PSW2_RULE: meta l4proto udp ct state { new, related } counter meta mark set 0x50535732
    PSW2_RULE: counter ct mark set mark
    ```
15. PSW2_MANGLE:
    ```
    PSW2_MANGLE: ip daddr @psw2_vps counter return
    PSW2_MANGLE: ct direction reply counter return
    ```
    PSW2_OUTPUT_MANGLE:
    ```
    ip daddr @psw2_vps counter return
    ct direction reply counter return
    meta mark and 0xff == 0xff counter return
    ```
16. mangle_prerouting jumps:
    ```
    mangle_prerouting: meta nfproto ipv4 meta l4proto tcp socket transparent 1 mark set 0x50535732 counter accept comment PSW2_SOCKET
    mangle_prerouting: ip daddr != @psw2_direct ip protocol udp counter jump PSW2_MANGLE
    [tproxy] mangle_prerouting: ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_MANGLE
    ```
17. Redirect mode only:
    ```
    add/flush PSW2_NAT; PSW2_NAT: ip daddr @psw2_vps counter return
    dstnat: ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_NAT
    add/flush PSW2_OUTPUT_NAT
    PSW2_OUTPUT_NAT: ip daddr @psw2_vps counter return
    PSW2_OUTPUT_NAT: meta mark and 0xff == 0xff counter return
    ```
18. If accept_icmp=1:
    ```
    add/flush PSW2_ICMP_REDIRECT
    PSW2_ICMP_REDIRECT: ip daddr @psw2_vps counter return
    [accept_icmpv6=1] PSW2_ICMP_REDIRECT: ip6 daddr @psw2_vps6 counter return
    dstnat:     ip daddr != @psw2_direct meta l4proto icmp counter jump PSW2_ICMP_REDIRECT
    dstnat:     ip6 daddr != @psw2_direct6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT
    nat_output: ip daddr != @psw2_direct meta l4proto icmp counter jump PSW2_ICMP_REDIRECT
    nat_output: ip6 daddr != @psw2_direct6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT
    ```
    The icmpv6 jumps are added even when accept_icmpv6=0. If accept_icmp=0 the chain does not exist, and later icmpv6 rules targeting it fail; most of those failures are silenced.
19. WAN returns:
    ```
    [redirect] PSW2_NAT: ip daddr @psw2_wan counter return comment "WAN_IP_RETURN"
    PSW2_MANGLE: ip daddr @psw2_wan counter return comment "WAN_IP_RETURN"
    ```
20. `ip rule add fwmark 0x50535732 table 999 priority 999`; `ip route add local 0.0.0.0/0 dev lo table 999`
21. IPv6 chains (always created):
    ```
    PSW2_MANGLE_V6: ip6 daddr @psw2_vps6 counter return
    PSW2_MANGLE_V6: ct direction reply counter return
    PSW2_OUTPUT_MANGLE_V6: ip6 daddr @psw2_vps6 counter return
    PSW2_OUTPUT_MANGLE_V6: ct direction reply counter return
    PSW2_OUTPUT_MANGLE_V6: meta mark and 0xff == 0xff counter return
    ```
22. RETURN_DNS: for each comma item `addr#port#proto` (proto defaults to udp, port to 53):
    - addr contains `::`: `insert rule inet passwall2 PSW2_OUTPUT_MANGLE_V6 meta l4proto <proto> ip6 daddr <addr> <proto> dport {<port>} counter return`
    - otherwise: `insert rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol <proto> ip daddr <addr> <proto> dport {<port>} counter return`

    (Insert means top of chain, so the last item ends up first.) The IPv4 rule always goes to the mangle output chain, even in redirect mode.
23. If PROXY_IPV6=1:
    ```
    mangle_prerouting: meta nfproto ipv6 meta l4proto tcp socket transparent 1 mark set 0x50535732 counter accept comment PSW2_SOCKET
    mangle_prerouting: ip6 daddr != @psw2_direct6 meta nfproto {ipv6} counter jump PSW2_MANGLE_V6
    mangle_output:     ip6 daddr != @psw2_direct6 meta nfproto {ipv6} counter jump PSW2_OUTPUT_MANGLE_V6 comment "PSW2_OUTPUT_MANGLE"
    PSW2_MANGLE_V6:    ip6 daddr @psw2_wan6 counter return comment "WAN6_IP_RETURN"
    ip -6 rule add fwmark 0x50535732 table 999 priority 999
    ip -6 route add local ::/0 dev lo table 999
    ```
24. `load_acl` (§2.4)
25. `filter_direct_node_list` in the background (§2.5)
26. ```
    insert rule inet passwall2 mangle_output meta skgid 9912 counter return comment "PSW2_DIRECT"
    insert rule inet passwall2 nat_output    meta skgid 9912 counter return comment "PSW2_DIRECT"
    ```
27. `log_i18n 0 "nftables firewall rules load complete!"`

IPv6 TCP is always TPROXY, even in redirect mode. UDP is always TPROXY.

### 2.4 `load_acl()` (nft)

For each `sid` (order per §0.5):

```
eval vars from $TMP_ACL_PATH/<sid>/var
if node non-empty and cache node_<node>_gen_shunt_list empty: gen_shunt_list node shunt_list4 shunt_list6
if use non-empty: dns_redirect_port = cache ACL_<use>_dns_port
```

#### A. `local_proxy == "1"` (router's own traffic; only the default ACL can have this)

Notation: `T=inet passwall2`; `OC=$nft_output_chain`.

1. If tcp_no_redir_ports is non-empty:
   - `OC: ip protocol tcp <factor(tcp_no_redir_ports,"tcp dport")> counter return`
   - `PSW2_OUTPUT_MANGLE_V6: meta l4proto tcp <factor...> counter return`
   - If has_1_65535: set `no_tcp_local_proxy=1`. The rule above then has an empty factor and returns all TCP.
2. If udp_no_redir_ports is non-empty: the same, with `PSW2_OUTPUT_MANGLE: ip protocol udp ...` and `PSW2_OUTPUT_MANGLE_V6: meta l4proto udp ...`, setting `no_udp_local_proxy`.
3. If node is set and (TCP or UDP is still proxied) and dns_redirect_port is set:
   ```
   nat_output: oif lo meta l4proto udp udp dport 53 counter redirect to :<dns_port> comment "PSW2_DNS"
   nat_output: oif lo meta l4proto tcp tcp dport 53 counter redirect to :<dns_port> comment "PSW2_DNS"
   ```
4. Local TCP, if node is set and no_tcp_local_proxy is unset:
   - accept_icmp=1:
     ```
     PSW2_ICMP_REDIRECT: oif lo ip protocol icmp ip daddr 198.18.0.0/16 counter redirect
     shunt4 → PSW2_ICMP_REDIRECT: oif lo ip protocol icmp ip daddr @<set> {counter redirect | counter return}
     PSW2_ICMP_REDIRECT: oif lo ip protocol icmp counter redirect
     PSW2_ICMP_REDIRECT: oif lo ip protocol icmp counter return
     ```
   - accept_icmpv6=1: the same four forms with `meta l4proto icmpv6 ip6 daddr 2001:2::/48`, shunt6, then `meta l4proto icmpv6 counter redirect` and `... counter return`.
   - In tproxy mode: `chain=PSW2_OUTPUT_MANGLE`, `J="counter jump PSW2_RULE"`. In redirect mode: `chain=PSW2_OUTPUT_NAT`, `J="counter redirect to :<redir_port>"`.
     ```
     chain: ip protocol tcp ip daddr 198.18.0.0/16 J
     shunt4 → chain: ip protocol tcp <tcp dport {redir}> ip daddr @<set> {J | counter return}
     chain: ip protocol tcp <tcp dport {redir}> J
     [redirect] nat_output: ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_NAT
     [tproxy]   PSW2_MANGLE: ip protocol tcp iif lo counter meta mark 0x50535732 tproxy ip to :<redir_port> comment "<Local>"
     [tproxy]   PSW2_MANGLE: ip protocol tcp iif lo counter return comment "<Local>"
     [tproxy]   mangle_output: ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_MANGLE comment "PSW2_OUTPUT_MANGLE"
     ```
   - PROXY_IPV6=1:
     ```
     PSW2_OUTPUT_MANGLE_V6: meta l4proto tcp ip6 daddr 2001:2::/48 jump PSW2_RULE        (no counter)
     shunt6 → PSW2_OUTPUT_MANGLE_V6: meta l4proto tcp <tcp dport {redir}> ip6 daddr @<set> {counter jump PSW2_RULE | counter return}
     PSW2_OUTPUT_MANGLE_V6: meta l4proto tcp <tcp dport {redir}> counter jump PSW2_RULE
     PSW2_MANGLE_V6: meta l4proto tcp iif lo counter meta mark 0x50535732 tproxy ip6 to :<redir_port> comment "<Local>"
     PSW2_MANGLE_V6: meta l4proto tcp iif lo counter return comment "<Local>"
     ```
   - For each entry in TMP_IFACE_PATH: `OC: ip protocol tcp oif <iface> counter return` and `PSW2_OUTPUT_MANGLE_V6: ip protocol tcp oif <iface> counter return`. The second rule is an upstream quirk: it matches only IPv4, so it is ineffective.
5. Local UDP, if node is set and no_udp_local_proxy is unset:
   ```
   PSW2_OUTPUT_MANGLE: ip protocol udp ip daddr 198.18.0.0/16 counter jump PSW2_RULE
   shunt4 → PSW2_OUTPUT_MANGLE: ip protocol udp <udp dport {redir}> ip daddr @<set> {counter jump PSW2_RULE | counter return}
   PSW2_OUTPUT_MANGLE: ip protocol udp <udp dport {redir}> counter jump PSW2_RULE
   PSW2_MANGLE: ip protocol udp iif lo counter meta mark 0x50535732 tproxy ip to :<redir_port> comment "<Local>"
   PSW2_MANGLE: ip protocol udp iif lo counter return comment "<Local>"
   mangle_output: ip daddr != @psw2_direct ip protocol udp counter jump PSW2_OUTPUT_MANGLE comment "PSW2_OUTPUT_MANGLE"
   [PROXY_IPV6] same 5 v6 forms as for TCP with udp (PSW2_OUTPUT_MANGLE_V6 / PSW2_MANGLE_V6, tproxy ip6)
   iface loop: OC: ip protocol udp oif <iface> counter return ; PSW2_OUTPUT_MANGLE_V6: ip protocol udp oif <iface> counter return
   ```
6. Always, when local_proxy=1 (appended after the jumps, so effectively at the end of mangle_output):
   ```
   mangle_output: oif lo counter return comment "PSW2_OUTPUT_MANGLE"
   mangle_output: meta mark 0x50535732 counter return comment "PSW2_OUTPUT_MANGLE"
   ```

`<Local>` is the translated string "Local".

#### B. `client_proxy == "1"` (LAN clients)

For each token `i` in `source_list`:

- Interface prefix: if `interface` is set, resolve `device` with `network_get_device`. If that is empty, try `ubus call network.interface.<if> status | jsonfilter -e '@.device'`; then `<if>` itself if `/sys/class/net/<if>` exists; otherwise `<if>` anyway. `S="iifname <device> "`. If no interface is set, S="".
- `iprange:R`: `S = factor(R, S+"ip saddr")`, giving `iifname X ip saddr {a-b}`. Sets `_ipv4=1`.
- `ipset:N`: `S = S+"ip daddr @N"`. **Upstream quirk:** this matches the destination, not the source, and does not check that the set exists. The Rust version should use the same expression for compatibility, or fix it deliberately.
- `ip:A`: `S = factor(A, S+"ip saddr")`. Sets `_ipv4=1`.
- `mac:M`: `S = factor(M, S+"ether saddr")`, giving `ether saddr {M}`.
- `any`: S stays as is (interface only, or empty).
- Any other token: skip it.

In the rules below `rem="<remarks>"` means `comment "<remarks>"`, and `PC=$nft_prerouting_chain`.

1. tcp_no_redir_ports non-empty:
   - Not has_1_65535: `PC: S ip protocol tcp tcp dport {..} counter return rem`; and if not `_ipv4`: `PSW2_MANGLE_V6: S meta l4proto tcp tcp dport {..} counter return rem`.
   - has_1_65535: set `no_tcp_proxy=1` and add no rule.
2. udp_no_redir_ports non-empty:
   - Not has_1_65535: `PSW2_MANGLE: ip protocol udp S udp dport {..} counter return rem`; and if not `_ipv4`: `PSW2_MANGLE_V6: meta l4proto udp S udp dport {..} counter return rem`.
   - has_1_65535: set `no_udp_proxy=1`.
3. DNS:
   - If (TCP or UDP is proxied) and dns_redirect_port is set:
     ```
     PSW2_MANGLE: ip protocol udp S udp dport 53 counter accept
     PSW2_MANGLE: ip protocol tcp S tcp dport 53 counter accept
     PSW2_MANGLE_V6: meta l4proto udp S udp dport 53 counter accept
     PSW2_MANGLE_V6: meta l4proto tcp S tcp dport 53 counter accept
     PSW2_DNS: meta l4proto udp S udp dport 53 counter redirect to :<dns_port> rem
     PSW2_DNS: meta l4proto tcp S tcp dport 53 counter redirect to :<dns_port> rem
     ```
   - Otherwise:
     ```
     PSW2_DNS: meta l4proto udp S udp dport 53 counter return rem
     PSW2_DNS: meta l4proto tcp S tcp dport 53 counter return rem
     ```
4. TCP, if not no_tcp_proxy and redir_port is set:
   - tproxy: `C=PSW2_MANGLE`, `J="counter jump PSW2_RULE"`. redirect: `C=PSW2_NAT`, `J="counter redirect to :<redir_port>"`.
   - accept_icmp=1:
     ```
     PSW2_ICMP_REDIRECT: ip protocol icmp S ip daddr 198.18.0.0/16 counter redirect rem
     shunt4 → PSW2_ICMP_REDIRECT: ip protocol icmp S ip daddr @<set> {counter redirect | counter return} rem
     PSW2_ICMP_REDIRECT: ip protocol icmp S counter redirect rem
     PSW2_ICMP_REDIRECT: ip protocol icmp S return rem
     ```
   - accept_icmpv6=1 and PROXY_IPV6=1: the same with `meta l4proto icmpv6 S ip6 daddr 2001:2::/48 ...`.
   - Main TCP rules:
     ```
     C: ip protocol tcp S ip daddr 198.18.0.0/16 J rem
     shunt4 → C: ip protocol tcp S <tcp dport {redir}> ip daddr @<set> {J | counter return} rem
     C: ip protocol tcp S <tcp dport {redir}> J rem
     [tproxy] PSW2_MANGLE: ip protocol tcp S counter meta mark 0x50535732 tproxy ip to :<redir_port> rem
     ```
   - PROXY_IPV6=1 and not `_ipv4`:
     ```
     PSW2_MANGLE_V6: meta l4proto tcp S ip6 daddr 2001:2::/48 counter jump PSW2_RULE rem
     shunt6 → PSW2_MANGLE_V6: meta l4proto tcp S <tcp dport> ip6 daddr @<set> {counter jump PSW2_RULE|counter return} rem
     PSW2_MANGLE_V6: meta l4proto tcp S <tcp dport> counter jump PSW2_RULE rem
     PSW2_MANGLE_V6: meta l4proto tcp S counter meta mark 0x50535732 tproxy to :<redir_port> rem    (TPROXY generic, not ip6)
     ```
5. Always: `PC: ip protocol tcp S counter return rem`; and if not `_ipv4`: `PSW2_MANGLE_V6: meta l4proto tcp S counter return rem`.
6. UDP, if not no_udp_proxy and redir_port is set:
   ```
   PSW2_MANGLE: ip protocol udp S ip daddr 198.18.0.0/16 counter jump PSW2_RULE rem
   shunt4 → PSW2_MANGLE: ip protocol udp S <udp dport {redir}> ip daddr @<set> {counter jump PSW2_RULE|counter return} rem
   PSW2_MANGLE: ip protocol udp S <udp dport {redir}> counter jump PSW2_RULE rem
   PSW2_MANGLE: ip protocol udp S counter meta mark 0x50535732 tproxy ip to :<redir_port> rem
   [PROXY_IPV6 && !_ipv4] same 4 with PSW2_MANGLE_V6 / meta l4proto udp / ip6 daddr 2001:2::/48 / tproxy to :<port>
   ```
7. Always: `PSW2_MANGLE: ip protocol udp S counter return rem`; and if not `_ipv4`: `PSW2_MANGLE_V6: meta l4proto udp S counter return rem`.
8. Unset the per-source vars.

After each sid: unset `dns_redirect_port` and every key from the var file.

Notes:

- With redir ports `1:65535` (the default), the factor is empty, so the "ports" rule matches all ports.
- With **empty** redir ports the factor is also empty, so nft proxies all ports. iptables behaves differently (§3.4).
- Packets that reach the end of PSW2_MANGLE / PSW2_NAT without a match fall through (accept), i.e. they are not proxied. The default ACL is processed last, so specific ACLs take precedence over it.

### 2.5 Node and VPS bypass helpers (nft)

- **`filter_vpsip`**: `uci show passwall2` lines matching the regex `(.address=|.download_address=)` (the regex `.` matches any char, so in practice any option whose name ends with `address`), value between single quotes:
  - values matching `([0-9]{1,3}[\.]){3}[0-9]{1,3}`, excluding exactly `127.0.0.1`, go to psw2_vps
  - values matching the IPv6 regex go to psw2_vps6
  - each step is logged.
- **`filter_haproxy`**: only if `@global_haproxy[0].balancing_enable`=1. For each `uci show passwall2` line containing `.lbss=`, take the quoted value `host:port`, take `host` (field 1 split on `:`), and run `get_host_ip ipv4 host 1`. All results go to psw2_vps.
- **`filter_vps_addr hosts...`**: get_host_ip ipv4 for each host into psw2_vps, and ipv6 into psw2_vps6.
- **`filter_server_port addr port stream`**: stream is lowercased. For ip_type in (ip, ip6): if `nft list chain inet passwall2 <OC>` does not contain `addr:port`, run `nft insert rule inet passwall2 <OC> meta l4proto <stream> <ip_type> daddr <addr> <stream> dport <port> return comment "<addr>:<port>"` (errors ignored, so the address family that does not match fails silently). `_is_tproxy` is computed but unused, so UDP also goes to `nft_output_chain`. In redirect mode that is PSW2_OUTPUT_NAT.
- **`filter_node node stream`**: address and port from the node section. If both are empty, return 1. Otherwise it calls filter_server_port twice (the second call is a no-op because of the grep).
- **`filter_direct_node_list`**: if `$TMP_PATH/direct_node_list` is non-empty, for each unique line (node id; these are nodes whose binaries are not xray/sing-box, whose server is not 127.0.0.1, appended by app.sh) run `filter_node id TCP; filter_node id UDP`.

### 2.6 `update_wan_sets` (both backends, same logic)

```
source utils.sh if get_wan_ips undefined
( flock -x 9 || exit 1
  WAN_IP=$(get_wan_ips ip4); non-empty → add to psw2_wan
  WAN6_IP=$(get_wan_ips ip6); non-empty → add to psw2_wan6
) 9>/var/lock/passwall2_update_wan_sets.lock
```

Sets are not flushed (the flush is commented out), so they only grow. nft adds with `insert_nftset`; iptables uses `ipset -! add psw2_wan <ip>` per IP.

### 2.7 mwan3 integration (nft only)

- `del_script_mwan3`: if `/etc/init.d/mwan3` is non-empty, run `sed -i "/passwall2/d"` on it.
- `add_script_mwan3`: run del first, then if the file exists:
  - `sed -i '/start_service()/,/}/ s/^}/    \/usr\/share\/passwall2\/nftables.sh mwan3_start\n}/'`: inserts `    /usr/share/passwall2/nftables.sh mwan3_start` before the closing `}` of start_service.
  - `sed -i '/stop_service().*{/a \    \/usr\/share\/passwall2\/nftables.sh mwan3_stop'`: inserts the stop line after the `stop_service() {` line.
- `MWAN3_RULE_ARGS="-m connmark --mark 0x50535732/0xffffffff -j RETURN"`
- `mwan3_stop`: if `nft list chain ip mangle mwan3_hook` succeeds, delete each rule in it whose `nft -a` listing contains `0x50535732` (by handle). Then loop `iptables -w 5 -t mangle -D mwan3_hook <ARGS>` until it fails.
- `mwan3_start`: if the chain exists, run mwan3_stop, then `iptables -w 5 -t mangle -I mwan3_hook 1 <ARGS>`. On failure: `logger -t passwall2 "mwan3: failed to add 0x50535732 exemption rule to mangle/mwan3_hook"`.
- `del_firewall_rule` calls `del_script_mwan3` but **not** `mwan3_stop`, so the exemption rule stays in place.

### 2.8 `del_firewall_rule` (nft)

```
for C in dstnat srcnat nat_output mangle_prerouting mangle_output:
    for each handle of rules in `nft -a list chain inet passwall2 C` whose text matches "PSW2_":
        nft delete rule inet passwall2 C handle H          (errors ignored)
for each handle in `nft -a list chains` lines matching "chain PSW2_" except PSW2_RULE:
    nft delete chain inet passwall2 handle H
nft delete chain inet passwall2 handle <handle of PSW2_RULE>       # last, to avoid "Resource busy"
ip rule del fwmark 0x50535732; ip route del local 0.0.0.0/0 dev lo table 999
ip -6 rule del fwmark 0x50535732; ip -6 route del local ::/0 dev lo table 999
destroy_nftset psw2_local psw2_wan psw2_direct psw2_vps psw2_local6 psw2_wan6 psw2_direct6 psw2_vps6
del_script_mwan3
log "Delete nftables rules is complete."
```

Rules in base chains are deleted because they reference `PSW2_*`, either as a jump target or in a comment. That is why every base-chain rule carries a PSW2_* comment or jump: PSW2_SOCKET, PSW2_DIRECT, PSW2_DNS, PSW2_OUTPUT_MANGLE. A rule with neither is not cleaned up. Example: in nat_output, `ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_NAT` is caught through its jump target.

Upstream quirk: `nft -a list chains` is not limited to the passwall2 table. The Rust version should list only `inet passwall2`.

Shunt and white sets (`psw2_<node>_*`) survive a stop. They are removed only by `flush_nftset`.

### 2.9 `flush_nftset`

Log "Clear NFTSet." Then for every set name in `nft -a list sets` containing `psw2_`, run `destroy_nftset <name>` (in `inet passwall2`).

### 2.10 Firewall include (nft) `gen_include`

```
flush_include                              # echo '#!/bin/sh' > /var/etc/passwall2.include
f=$TMP_PATH/PSW2_RULE.nft                  # /tmp/etc/passwall2/PSW2_RULE.nft
echo '#!/bin/sh' > f; nft list table inet passwall2 >> f      # full table dump incl. set elements
append to FWI:
    [ -z "$(nft list chain inet passwall2 mangle_prerouting | grep PSW2)" ] && nft -f /tmp/etc/passwall2/PSW2_RULE.nft

    /usr/share/passwall2/nftables.sh update_wan_sets

    return 0
```

Resulting include file:

```
#!/bin/sh
[ -z "$(nft list chain inet passwall2 mangle_prerouting | grep PSW2)" ] && nft -f /tmp/etc/passwall2/PSW2_RULE.nft

/usr/share/passwall2/nftables.sh update_wan_sets

return 0
```

`MY_PATH` is `$DIR/nftables.sh`. When the script is sourced, `DIR` resolves from `$0`, i.e. app.sh's directory `/usr/share/passwall2`.

### 2.11 `start` / `stop` (nft)

```
start: if ENABLED_DEFAULT_ACL==0 and ENABLED_ACLS==0: return
       add_firewall_rule; gen_include
stop:  source utils.sh if log_i18n undefined
       del_firewall_rule
       if @global[0].flush_set (default 0) == "1":
           uci -q delete passwall2.@global[0].flush_set; uci -q commit passwall2
           flush_nftset; rm -rf $TMP_PATH2/singbox* $TMP_PATH2/geo_output
       flush_include        # FWI becomes just "#!/bin/sh"
```

---

## 3. iptables backend (`iptables.sh`)

### 3.1 Binaries and table handles

```
ipt  = command -v iptables-legacy || command -v iptables
ip6t = command -v ip6tables-legacy || command -v ip6tables
ipt_n  = "$ipt -t nat -w"     ; ipt_m  = "$ipt -t mangle -w"
ip6t_n = "$ip6t -t nat -w"    ; ip6t_m = "$ip6t -t mangle -w"
if ip6t empty or `lsmod | grep ip6table_nat` empty:    ip6t_n = "eval #$ip6t -t nat -w"     (no-op)
if ip6t empty or `lsmod | grep ip6table_mangle` empty: ip6t_m = "eval #$ip6t -t mangle -w"  (no-op)
```

The `eval #...` prefix turns every command into a shell comment, which disables those IPv6 rules silently. The Rust version should have an "ip6 nat/mangle available" flag and skip those rules.

### 3.2 Helpers

- `factor v prefix`: returns "" if either argument is empty or v=="1:65535"; otherwise `"<prefix> <v>"`. No mangling.
- `dst set [!]`: `-m set [!] --match-set <set> dst`. With `!` it renders as `-m set ! --match-set X dst`.
- `comment s`: `-m comment --comment <s with spaces→_>`.
- **`add_port_rules cmd ports target`**:
  ```
  if ports contains no digit: return          (=> empty list adds NO rule)
  list = ports without spaces; '-'→':'; split ','; dedupe; drop empty
  if any item == "1:65535": eval "cmd target"; return
  singles grouped in chunks of 15: eval "cmd -m multiport --dport p1,p2,...,p15 target"
  remaining singles chunk likewise
  each range a:b: eval "cmd --dport a:b target"
  ```
  The multiport chunks come before the ranges, in input order.
- `destroy_ipset names`: `ipset -q -F n; ipset -q -X n`.
- **`insert_rule_before ipt chain keyword rule [default_index=0]`**: idx = the first line number of `$ipt -n -L chain --line-numbers` matching keyword. If idx is empty and default=0, run `$ipt -A chain rule`. Otherwise run `$ipt -I chain <idx or default> rule`.
- **`insert_rule_after`**: the same, but uses the **last** matching line, and the position is idx+1.
- `RULE_LAST_INDEX ipt chain keyword [default=0]`: first matching line number, or the default. It logs an error if fewer than 3 args are given.
- `REDIRECT [port] [mode]`:
  - no port: `-j REDIRECT`
  - port: `-j REDIRECT --to-ports P`
  - mode `TPROXY`: `-m mark --mark 0x50535732 -j TPROXY --on-port P`
- `get_redirect_ipt` / `get_redirect_ip6t` (unused): `REDIRECT $2 $3`.
- `gen_shunt_list`: same logic as the nft version, with these differences:
  - sets: `ipset -! create psw2_<node>_<sid> nethash maxelem 1048576` and `ipset -! create psw2_<node>_<sid>6 nethash family inet6 maxelem 1048576`
  - fill: matching lines are turned into `add <set> <line>`, followed by `COMMIT`, piped to `ipset -! -R`
  - direct sets come from cache `node_<node>_direct_ipset4/6`: `ipset -! create <name> iphash maxelem 1048576 timeout 259200`, and for v6 `iphash family inet6 maxelem 1048576 timeout 259200`
- `add_shunt_t_rule list cmd jump [ports]`: for each `set:outbound`, the action is `-j RETURN` when outbound=direct, otherwise the jump. If ports is empty or `1:65535`, run `cmd $(dst set) action`. Otherwise `add_port_rules "cmd $(dst set)" ports action`.

### 3.3 `add_firewall_rule()` (iptables): exact order

1. Log "Starting to load iptables firewall rules..."
2. ipsets:
   ```
   ipset -! create psw2_local  nethash maxelem 1048576
   ipset -! create psw2_direct nethash maxelem 1048576
   ipset -! create psw2_vps    iphash  maxelem 1048576
   ipset -! create psw2_wan    nethash maxelem 1048576
   ipset -! create psw2_local6  nethash family inet6 maxelem 1048576
   ipset -! create psw2_direct6 nethash family inet6 maxelem 1048576
   ipset -! create psw2_vps6    iphash  family inet6 maxelem 1048576
   ipset -! create psw2_wan6    nethash family inet6 maxelem 1048576
   ```
3. `get_local_ips ip4 | sed "s/^/add psw2_local /" | ipset -! -R`, and the same for ip6 into psw2_local6. `get_local_ips` prints one IP per line.
4. direct_ip file: `*::*` → `ipset -! add psw2_direct6 ip`; `geoip:` → geoview output piped as `add psw2_direct ...` / `COMMIT` into `ipset -! -R` (v4 and v6); anything else → `ipset -! add psw2_direct ip`.
5. LAN ifname (same detection as nft): each CIDR via `ipset -! -R` with `add psw2_direct <cidr>` (or direct6).
6. `update_wan_sets`
7. ISP_DNS: `ipset -! add psw2_direct ip` per IP; ISP_DNS6 into psw2_direct6.
8. In the background: `filter_vpsip`, `filter_haproxy`. **There is no `filter_vps_addr` for NODE, unlike nft.**
9. accept_icmp and accept_icmpv6 (default 0). Mode: `is_tproxy` unset for redirect, `TPROXY` for tproxy.
10. `IPT_N=1` if (not tproxy or accept_icmp=1). `IP6T_N=1` if (not tproxy or accept_icmpv6=1).
11. nat (v4):
    ```
    iptables -t nat -w -N PSW2
    -A PSW2 -m set --match-set psw2_vps dst -j RETURN
    -A PSW2 -m comment --comment WAN_IP_RETURN -m set --match-set psw2_wan dst -j RETURN
    [accept_icmp=1] insert_rule_after nat PREROUTING "prerouting_rule" "-m set ! --match-set psw2_direct dst -p icmp -j PSW2"
    [redirect]      insert_rule_after nat PREROUTING "prerouting_rule" "-m set ! --match-set psw2_direct dst -p tcp -j PSW2"
    -N PSW2_OUTPUT
    -A PSW2_OUTPUT -m set --match-set psw2_vps dst -j RETURN
    -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN
    -N PSW2_DNS
    dns_redirect=="0": -I PREROUTING -m set --match-set psw2_direct src -m set --match-set psw2_local dst -j PSW2_DNS
    else:              -I PREROUTING -m set --match-set psw2_direct src -j PSW2_DNS
    ```
    `prerouting_rule` is fw3's user chain jump in nat PREROUTING. The rule goes after it, or at the end if it is absent.
12. mangle (v4):
    ```
    -N PSW2_RULE
    -A PSW2_RULE -j CONNMARK --restore-mark
    -A PSW2_RULE -m mark --mark 0x50535732 -j RETURN
    -A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark 0x50535732
    -A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark 0x50535732
    -A PSW2_RULE -j CONNMARK --save-mark
    -N PSW2
    -A PSW2 -p tcp -m socket --transparent -j MARK --set-mark 0x50535732
    -A PSW2 -p tcp -m socket --transparent -j ACCEPT
    -A PSW2 -m set --match-set psw2_vps dst -j RETURN
    -A PSW2 -m comment --comment WAN_IP_RETURN -m set --match-set psw2_wan dst -j RETURN
    -A PSW2 -m conntrack --ctdir REPLY -j RETURN
    insert_rule_before mangle PREROUTING "mwan3" "-m set ! --match-set psw2_direct dst -j PSW2"
    -N PSW2_OUTPUT
    -A PSW2_OUTPUT -m set --match-set psw2_vps dst -j RETURN
    -A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN
    -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN
    ```
    The PREROUTING jump goes before the first mwan3 rule, or is appended if there is none.
13. `ip rule add fwmark 0x50535732 table 999 priority 999`; `ip route add local 0.0.0.0/0 dev lo table 999`
14. ip6 nat, if accept_icmpv6=1:
    ```
    -N PSW2 ; -A PSW2 -m set --match-set psw2_vps6 dst -j RETURN
    -A PREROUTING -m set ! --match-set psw2_direct6 dst -p ipv6-icmp -j PSW2
    -N PSW2_OUTPUT ; -A PSW2_OUTPUT -m set --match-set psw2_vps6 dst -j RETURN ; -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN
    ```
15. ip6 nat PSW2_DNS (always): `-N PSW2_DNS`, then PREROUTING insert as in step 11, using psw2_direct6 and psw2_local6.
16. ip6 mangle: PSW2_RULE (the same 5 rules); PSW2 (socket mark, socket accept, vps6 return, `WAN6_IP_RETURN` wan6 return, ctdir REPLY return); `insert_rule_before ip6 mangle PREROUTING mwan3 "-m set ! --match-set psw2_direct6 dst -j PSW2"`; PSW2_OUTPUT in a **different order**: `mark 0xff/0xff RETURN`, `vps6 RETURN`, `ctdir REPLY RETURN`.
17. RETURN_DNS: for each `addr#port#proto` (proto udp, port 53 by default):
    - addr contains `::`: `ip6tables -t mangle -I PSW2_OUTPUT -p <proto> -d <addr> --dport <port> -j RETURN`
    - otherwise: `iptables -t mangle -I PSW2_OUTPUT ...` (always mangle, even in redirect mode)
18. `ip -6 rule add fwmark 0x50535732 table 999 priority 999`; `ip -6 route add local ::/0 dev lo table 999`. This happens **unconditionally** (nft does it only when PROXY_IPV6=1).
19. `load_acl` (§3.4)
20. `filter_direct_node_list &`
21. If IPT_N is unset: `iptables -t nat -F/-X PSW2` and `PSW2_OUTPUT` (errors ignored). The same for ip6 nat when IP6T_N is unset.
22. For each of ipt_n, ipt_m, ip6t_n, ip6t_m: `-I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN`
23. Log "iptables firewall rules load complete!"

### 3.4 `load_acl()` (iptables)

The same loop as nft (`eval local` of the var file). `ipt_tmp = ipt_n` in redirect mode, `ipt_m` in tproxy mode.

#### A. local_proxy=1

1. tcp_no_redir_ports: `add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" ports "-j RETURN"` and the same with `$ip6t_m -A PSW2_OUTPUT -p tcp`. has_1_65535 sets no_tcp_local_proxy (the add_port_rules call then emits a plain `-p tcp -j RETURN`).
2. udp_no_redir_ports: `$ipt_m -A PSW2_OUTPUT -p udp` and `$ip6t_m ...`, setting no_udp_local_proxy.
3. DNS, if node is set, TCP or UDP is proxied, and dns_port is set:
   ```
   nat  v4: -A OUTPUT -m comment --comment PSW2_DNS -p udp -o lo --dport 53 -j REDIRECT --to-ports <dns_port>
   nat  v6: same (errors ignored)
   nat  v4: ... -p tcp ...
   nat  v6: ... -p tcp ...
   ```
4. TCP, if node is set and no_tcp_local_proxy is unset:
   - accept_icmp=1 (nat v4):
     ```
     -A OUTPUT -m set ! --match-set psw2_direct dst -p icmp -j PSW2_OUTPUT
     -A PSW2_OUTPUT -p icmp -d 198.18.0.0/16 -j REDIRECT
     shunt4: -A PSW2_OUTPUT -p icmp -m set --match-set <set> dst {-j REDIRECT | -j RETURN}
     -A PSW2_OUTPUT -p icmp -j REDIRECT
     ```
   - accept_icmpv6=1 (nat v6): the same with `psw2_direct6`, `-p ipv6-icmp`, `-d 2001:2::/48`, shunt6.
   - `J = -j PSW2_RULE` in tproxy mode, otherwise `-j REDIRECT --to-ports <redir_port>`.
   - Rules:
     ```
     $ipt_tmp -A PSW2_OUTPUT -p tcp -d 198.18.0.0/16 J
     add_shunt_t_rule shunt4 "$ipt_tmp -A PSW2_OUTPUT -p tcp" J tcp_redir_ports
     add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" tcp_redir_ports J
     [redirect] nat: -A OUTPUT -m set ! --match-set psw2_direct dst -p tcp -j PSW2_OUTPUT
     [tproxy]   mangle: -A PSW2 -m comment --comment <Local> -p tcp -i lo -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
                mangle: -A PSW2 -m comment --comment <Local> -p tcp -i lo -j RETURN
                insert_rule_before mangle OUTPUT "mwan3" "-m comment --comment mangle-OUTPUT-PSW2 -m set ! --match-set psw2_direct dst -p tcp -j PSW2_OUTPUT"
     ```
   - PROXY_IPV6=1 (ip6 mangle), independent of redirect/tproxy:
     ```
     -A PSW2_OUTPUT -p tcp -d 2001:2::/48 -j PSW2_RULE
     add_shunt_t_rule shunt6 "... -A PSW2_OUTPUT -p tcp" "-j PSW2_RULE" tcp_redir_ports
     add_port_rules "... -A PSW2_OUTPUT -p tcp" tcp_redir_ports "-j PSW2_RULE"
     -A PSW2 -m comment --comment <Local> -p tcp -i lo -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
     -A PSW2 -m comment --comment <Local> -p tcp -i lo -j RETURN
     insert_rule_before ip6 mangle OUTPUT "mwan3" "-m comment --comment mangle-OUTPUT-PSW2 -m set ! --match-set psw2_direct6 dst -p tcp -j PSW2_OUTPUT"
     ```
   - iface loop: `nat -A PSW2_OUTPUT -o <if> -p tcp -j RETURN`; `mangle -A PSW2_OUTPUT -o <if> -p tcp -j RETURN`.
5. UDP, if node is set and no_udp_local_proxy is unset (mangle v4):
   ```
   -A PSW2_OUTPUT -p udp -d 198.18.0.0/16 -j PSW2_RULE
   shunt4 (ports udp_redir_ports) -j PSW2_RULE
   add_port_rules "-A PSW2_OUTPUT -p udp" udp_redir_ports "-j PSW2_RULE"
   -A PSW2 -m comment --comment <Local> -p udp -i lo -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
   -A PSW2 -m comment --comment <Local> -p udp -i lo -j RETURN
   insert_rule_before mangle OUTPUT mwan3 "-m comment --comment mangle-OUTPUT-PSW2 -m set ! --match-set psw2_direct dst -p udp -j PSW2_OUTPUT"
   ```
   PROXY_IPV6=1 adds the same in ip6 mangle (psw2_direct6, FAKE_IP_6). iface loop: nat and mangle `-o <if> -p udp -j RETURN`.
6. Always, when local_proxy=1:
   ```
   mangle v4: -I OUTPUT -m comment --comment mangle-OUTPUT-PSW2 -o lo -j RETURN          (top)
   insert_rule_before mangle OUTPUT mwan3 "-m comment --comment mangle-OUTPUT-PSW2 -m mark --mark 0x50535732 -j RETURN"
   mangle v6: same two
   ```

#### B. client_proxy=1 (per source)

Source match `S`:

- interface: `-i <device> ` (device resolved as in nft)
- `iprange:R`: `S + "-m iprange --src-range R"` (sets `_ipv4`)
- `ipset:N`: run `ipset -q list N`. If it exists: `S + "-m set --match-set N src"`. Otherwise log "[remarks],...Does not exist, ignore." and **skip** the source.
- `ip:A`: `S + "-s A"` (sets `_ipv4`)
- `mac:M`: `S + "-m mac --mac-source M"`
- `any`: S only
- anything else: skip

`C(rem)` is `-m comment --comment <remarks with _>`.

1. tcp_no_redir (not has_1_65535):
   - if not `_ipv4`: `add_port_rules "$ip6t_m -A PSW2 C S -p tcp" ports "-j RETURN"`
   - `add_port_rules "$ipt_tmp -A PSW2 C S -p tcp" ports "-j RETURN"`
   - has_1_65535 instead sets no_tcp_proxy.
2. udp_no_redir: the same with `$ipt_m` / `$ip6t_m`, `-p udp`. has_1_65535 sets no_udp_proxy.
3. DNS, if (TCP or UDP is proxied) and dns_port is set:
   ```
   mangle v4/v6: -A PSW2 C -p udp S --dport 53 -j ACCEPT ; -A PSW2 C -p tcp S --dport 53 -j ACCEPT
   nat v4/v6:    -A PSW2_DNS C -p udp S --dport 53 -j REDIRECT --to-ports <dns_port> ; same tcp
   ```
   (Exact order: m4 udp, m4 tcp, m6 udp, m6 tcp, n4 udp, n6 udp, n4 tcp, n6 tcp.) Otherwise: `nat v4/v6 -A PSW2_DNS C -p udp|tcp S --dport 53 -j RETURN` (order n4 udp, n6 udp, n4 tcp, n6 tcp).
4. TCP, if not no_tcp_proxy and redir_port is set. `J` as in §A.4.
   - accept_icmp=1 (nat v4 PSW2):
     ```
     -A PSW2 C -p icmp S -d 198.18.0.0/16 -j REDIRECT
     shunt4 → "-A PSW2 C -p icmp S" -m set --match-set X dst {-j REDIRECT|-j RETURN}
     -A PSW2 C -p icmp S -j REDIRECT
     ```
   - accept_icmpv6=1 and PROXY_IPV6=1: nat v6 equivalents with `-p ipv6-icmp` and `-d 2001:2::/48`.
   - Main rules:
     ```
     $ipt_tmp -A PSW2 C -p tcp S -d 198.18.0.0/16 J
     add_shunt_t_rule shunt4 "$ipt_tmp -A PSW2 C -p tcp S" J tcp_redir_ports
     add_port_rules "$ipt_tmp -A PSW2 C -p tcp S" tcp_redir_ports J
     [tproxy] mangle: -A PSW2 C -p tcp S -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
     ```
   - PROXY_IPV6=1 and not `_ipv4` (ip6 mangle):
     ```
     -A PSW2 C -p tcp S -d 2001:2::/48 -j PSW2_RULE
     add_shunt_t_rule shunt6 "... -A PSW2 C -p tcp S" J tcp_redir_ports
     add_port_rules "... -A PSW2 C -p tcp S" tcp_redir_ports "-j PSW2_RULE"
     -A PSW2 C -p tcp S -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
     ```
     The shunt6 call passes `J`. In redirect mode that is `-j REDIRECT`, which is invalid in mangle and fails silently (upstream bug). The correct action is `-j PSW2_RULE`.
5. Always: `$ipt_tmp -A PSW2 C S -p tcp -j RETURN`; and if not `_ipv4`: `ip6 mangle -A PSW2 C S -p tcp -j RETURN`.
6. UDP, if not no_udp_proxy and redir_port is set (mangle v4):
   ```
   -A PSW2 C -p udp S -d 198.18.0.0/16 -j PSW2_RULE
   shunt4 udp_redir_ports -j PSW2_RULE
   add_port_rules "-A PSW2 C -p udp S" udp_redir_ports "-j PSW2_RULE"
   -A PSW2 C -p udp S -m mark --mark 0x50535732 -j TPROXY --on-port <redir_port>
   ```
   PROXY_IPV6=1 and not `_ipv4`: the same in ip6 mangle with FAKE_IP_6.
7. Always: `mangle -A PSW2 C S -p udp -j RETURN`; and if not `_ipv4`: the ip6 mangle equivalent.

Behaviour difference from nft: with **empty** `tcp_redir_ports`/`udp_redir_ports`, iptables `add_port_rules` adds **no** catch-all proxy rule; only the FAKE_IP and shunt rules apply. nft proxies all ports in that case. With the default `1:65535` both backends proxy all ports.

### 3.5 Bypass helpers (iptables)

- `filter_haproxy`: as in nft, but each IP is added with `ipset -q add psw2_vps <ip>`.
- `filter_vpsip`: the same address selection as nft; lines `add psw2_vps <ip>` + `COMMIT` piped to `ipset -! -R` (and psw2_vps6).
- `filter_server_port addr port stream`:
  - v4 table: nat if TCP in redirect mode, mangle if UDP or tproxy. v6 table: always ip6 mangle.
  - For each: if `$ipt -n -L PSW2_OUTPUT` does not contain `addr:port`, run `-I PSW2_OUTPUT -m comment --comment <addr>:<port> -p <stream> -d <addr> --dport <port> -j RETURN` (errors ignored).
- `filter_node` and `filter_direct_node_list`: identical to nft.

### 3.6 `del_firewall_rule` (iptables)

```
for ipt in ipt_n ipt_m ip6t_n ip6t_m:
  for chain in PREROUTING OUTPUT:
     repeat (count of lines in `$ipt -nL chain` containing "PSW2") times:
        idx = first line number from `$ipt --line-number -nL chain | grep PSW2`
        $ipt -D chain idx
  for chain in PSW2 PSW2_OUTPUT PSW2_DNS PSW2_RULE: $ipt -F chain; $ipt -X chain   (errors ignored)
ip rule del fwmark 0x50535732 ; ip route del local 0.0.0.0/0 dev lo table 999
ip -6 rule del fwmark 0x50535732 ; ip -6 route del local ::/0 dev lo table 999
log "Delete iptables rules is complete."
```

"PSW2" matches jump targets and comments (`PSW2_DIRECT`, `PSW2_DNS`, `mangle-OUTPUT-PSW2`, ...). ipsets are **not** destroyed on stop. `ipset -! create` reuses them on the next start, so the old elements persist. They are removed only by `flush_ipset`, which runs when `flush_set=1`.

`flush_ipset`: log "Clear IPSet."; for each `Name:` in `ipset list` containing `psw2_`, run destroy_ipset.

### 3.7 Firewall include (iptables) `gen_include`

`flush_include` writes `#!/bin/sh` to FWI. `extract_rules <4|6> <table>` is evaluated **at generation time**:

```
echo "*<table>"
<ipt>-save -t <table> | grep PSW2 | grep -v PSW2_DIRECT | grep -v -- "-j PSW2$" \
   | sed 's/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/'
echo COMMIT
```

It keeps the `:PSW2...` chain declarations and the `-A PSW2*` rules. Base-chain rules (DNS jump, OUTPUT jumps, local DNS redirect) become `-I <chain> 1`, which reverses their relative order. The main `-j PSW2` jumps are removed and re-added at run time with the index helpers. `<ipt>-save` is the binary path with `-save` appended (for example `/usr/sbin/iptables-legacy-save`).

Generated v4 block (only if `ipt` exists). `$(...)` with a backslash is literal text executed at include time; everything else is expanded at generation time:

```
/usr/share/passwall2/iptables.sh update_wan_sets
<ipt>-save -c | grep -v "PSW2" | <ipt>-restore -c
<ipt>-restore -n <<-EOT
*nat
...extracted nat rules...
COMMIT
*mangle
...extracted mangle rules...
COMMIT
EOT
<ipt> -t nat -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN
<ipt> -t mangle -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN

[ "<accept_icmp>" = "1" ] && $(/usr/share/passwall2/iptables.sh insert_rule_after "<ipt> -t nat -w" "PREROUTING" "prerouting_rule" "-m set ! --match-set psw2_direct dst -p icmp -j PSW2")
[ -z "<is_tproxy>" ] && $(/usr/share/passwall2/iptables.sh insert_rule_after "<ipt> -t nat -w" "PREROUTING" "prerouting_rule" "-m set ! --match-set psw2_direct dst -p tcp -j PSW2")

$(/usr/share/passwall2/iptables.sh insert_rule_before "<ipt> -t mangle -w" "PREROUTING" "mwan3" "-m set ! --match-set psw2_direct dst -j PSW2")
```

v6 block (only if `ip6t` exists): the same pattern with ip6t, `extract_rules 6 nat/mangle`, both PSW2_DIRECT rules, then:

- `[ "<accept_icmpv6>" = "1" ] && <ip6t_n> -A PREROUTING -m set ! --match-set psw2_direct6 dst -p ipv6-icmp -j PSW2`
- `$(... insert_rule_before "<ip6t_m>" "PREROUTING" "mwan3" "-m set ! --match-set psw2_direct6 dst -j PSW2")`

If an ip6 module is missing, `<ip6t_n>` is the `eval #...` string, which leaves a comment in the file.

The file ends with an empty line and `return 0`.

### 3.8 start/stop (iptables)

The same as nft (§2.11), with `flush_ipset` in place of `flush_nftset`. There is no mwan3 init-script patching.

`get_ipt_bin` prints `$ipt` and `get_ip6t_bin` prints `$ip6t`, for other scripts.

---

## 4. Packet-flow summary (for the Rust design)

1. **LAN → Internet, TCP, redirect mode.** The packet hits dstnat (nft) or nat PREROUTING (ipt) when `daddr ∉ direct`, and goes to PSW2_NAT / nat PSW2. It returns if `daddr ∈ vps|wan`. Then the per-ACL source rules run: DNS-related rules, FAKE_IP, shunt sets (direct sets return), port list, then REDIRECT to `:redir_port`, and finally a per-source return.
2. **LAN, UDP, or TCP in tproxy mode.** mangle prerouting jumps to PSW2_MANGLE / mangle PSW2. A socket-transparent match marks and accepts established TPROXY flows. Return when `daddr ∈ vps|wan` or the packet is a reply. Per source: jump to PSW2_RULE (sets fwmark on new connections and saves it in conntrack), then `mark==FWMARK` → TPROXY to `:redir_port`. Policy routing (fwmark → table 999 → local route via lo) delivers the packet to the local TPROXY socket.
3. **Router-local traffic** (default ACL with localhost_proxy=1):
   - Redirect TCP goes through nat_output → PSW2_OUTPUT_NAT → REDIRECT.
   - TPROXY/UDP: mangle_output → PSW2_OUTPUT_MANGLE → PSW2_RULE marks the packet → it is rerouted to lo → it re-enters prerouting with `iif lo` → PSW2_MANGLE `iif lo` TPROXY rule.
   - Core processes running with gid 9912 skip all of this (PSW2_DIRECT rule at the top of the output chains).
   - The DNS servers in RETURN_DNS are exempt.
   - Router-local DNS to `:53` via lo is redirected to the ACL's dnsmasq port.
4. **DNS hijack for LAN clients.** In dstnat or nat PREROUTING, a packet whose source is in direct (private ranges / LAN) and, when dns_redirect=0, whose destination is in local, jumps to PSW2_DNS. There, per ACL source, it is redirected to that ACL's dnsmasq copy (`:dns_port`), or returned.
5. **ICMP (accept_icmp).** ICMP to non-direct destinations is REDIRECTed to the router itself, so ping replies locally (fake success), except for VPS IPs and direct-shunt sets.

---

## 5. Implementation checklist for the Rust rewrite

- [ ] Choose the backend exactly as in §0.2 and store it in cache var `USE_TABLES`.
- [ ] Use the same table (`inet passwall2`), chain, set and comment names, fwmark `0x50535732`, routing table/priority 999 and gid 9912.
- [ ] nft: build the whole ruleset as one `nft -f` transaction where possible. The rule order **must** match §2.3/§2.4, because first match wins. Keep the trailing comments, since cleanup relies on them.
- [ ] Set filling must handle large lists (geoip): the batched `add element` / `ipset restore` style.
- [ ] Background tasks (filter_vpsip, haproxy, VPS addr, direct node list) may run asynchronously after the main rules.
- [ ] Generate `/var/etc/passwall2.include` exactly as in §2.10/§3.7, so fw4/fw3 reloads restore the rules. Keep the CLI subcommands `update_wan_sets`, `mwan3_start`, `mwan3_stop`, `insert_rule_before`, `insert_rule_after`, `filter_direct_node_list`, `start`, `stop` at the same paths (`/usr/share/passwall2/{nftables,iptables}.sh`), or install shell shims that call the Rust binary.
- [ ] Patch the mwan3 init script exactly as in §2.7, since its text is used for removal (`/passwall2/d`).
- [ ] `stop` must handle `@global[0].flush_set` as described: delete the option, commit, destroy all `psw2_*` sets, and remove `$TMP_PATH2/singbox*` and `$TMP_PATH2/geo_output`.
- [ ] Decide which upstream quirks to keep (all marked "quirk"/"bug" above): nft `ipset:` source matching `ip daddr`; the IPv6 `ip:` source mangled by factor; `shunt_list` reuse across ACLs; the nft empty-port-list difference; ICMPv6 rules with no chain when accept_icmp=0; ip6 shunt with a REDIRECT target in mangle; mwan3 exemption not removed on stop.
