# 05 — Core API library & helper scripts

Source files covered (paths relative to `luci-app-passwall2/`):

| File | Installed at | Role |
|---|---|---|
| `luasrc/passwall2/api.lua` | `/usr/lib/lua/luci/passwall2/api.lua` (module `luci.passwall2.api`) | Shared library used by every Lua script, CBI model, and by shell via `lua_api` |
| `luasrc/passwall2/com.lua` | `luci.passwall2.com` | Component descriptor table (xray / sing-box / geoview / passwall2) for the updater |
| `luasrc/passwall2/server_app.lua` | `/usr/lib/lua/luci/passwall2/server_app.lua` | Server-side (inbound) launcher, called by `/etc/init.d/passwall2_server` |
| `luasrc/passwall2/util_shadowsocks.lua` | `luci.passwall2.util_shadowsocks` | SSR / SS-Rust config JSON generator (client and server) |
| `root/usr/share/passwall2/helper_dnsmasq.lua` | same | dnsmasq integration (rules, instance copy, restart, backup/restore of servers) |
| `root/usr/share/passwall2/haproxy.lua` | same | HAProxy config generator (load-balancing) |
| `root/usr/share/passwall2/socks_auto_switch.sh` | same | Per-socks-instance health check & auto failover loop |
| `root/usr/share/passwall2/app_acl.lua` | same | Computes ACL list + per-ACL node run args, writes ACL state files, prints JSON |

`util_xray.lua` / `util_sing-box.lua` are specified elsewhere.

---

## 0. Global constants (api.lua)

```
appname        = "passwall2"
c_config       = "passwall2"            -- client UCI config
s_config       = "passwall2_server"     -- server UCI config
curl_args      = { "-skfL", "--connect-timeout 3", "--retry 3", "-H 'Accept: */*'" }
command_timeout= 300                    -- seconds (used by to_move mv)
DIRECT_GID     = 9912                   -- processes run with this GID bypass the proxy (firewall rules match on gid)
LOCK_PREFIX    = "/var/lock/passwall2"
LOG_FILE       = "/tmp/log/passwall2.log"
TMP_PATH       = "/tmp/etc/passwall2"
CACHE_PATH     = "/tmp/etc/passwall2_tmp"
S_TMP_PATH     = "/tmp/etc/passwall2_server"
TMP_IFACE_PATH = "/tmp/etc/passwall2/iface"
TMP_ACL_PATH   = "/tmp/etc/passwall2/acl"
OPENWRT_ARCH, DISTRIB_ARCH = nil (lazy cached)
```

Matching shell constants (utils.sh, for context): `LOCK_PATH=/var/lock`, `TMP_BIN_PATH=$TMP_PATH/bin`, `TMP_ROUTE_PATH=$TMP_PATH/route`, cache-var file = `$TMP_PATH/var`.

### Language init (module load time)
```
lang = uci luci.main.lang or "auto"
if lang=="auto": lang = passwall2.@global[0].auto_lang if set
if lang=="auto": lang = i18n.default
i18n.setlanguage(lang)
```
UCI read: `luci.main.lang`, `passwall2.@global[0].auto_lang` (string, written by `set_default_cbi`, see §1.17).

---

## 1. api.lua — function reference

### 1.1 Logging
- `echolog(...)`: join args with `" "`, append `result.."\n"` to `LOG_FILE` (`/tmp/log/passwall2.log`). Silently ignore open errors.
- `echolog_date(...)`: prefix `os.date("%Y-%m-%d %H:%M:%S: ")` then `echolog`.
- `log(level, ...)`: if `level>=1`: indent = `"  "` × level; line = indent .. `"- "` .. join(args," "). Else line = join(args). Written via `echolog_date`.
  - Example level 2: `2026-01-01 12:00:00:     - Node: ...`

### 1.2 UCI wrappers
- `is_old_uci()` → `grep -E 'require[ \t]*"uci"' /usr/lib/lua/luci/model/uci.lua` exit 0.
- `uci_del(config, section, option?)` → delete option or whole section.
- `uci_get(config, section?, option?)`: no section → `get_all(config)`; option → `get` (nil if absent); else `get_all(config, section)` (table with `.name`, `.type`, options; list options are Lua arrays).
- `uci_set(config, section, option, value)`: numbers → string. If `#value>0`: option given → `set_list` if table else `set`; option nil → `uci:set(config, section, value)` (creates section of type `value`). If value empty (string "" or empty table) → `uci_del`.
- `*_c` variants bind config=`passwall2`; `*_s` variants bind `passwall2_server`: `uci_del_c/s`, `uci_foreach_c/s(stype, fn)`, `uci_get_c/s`, `uci_set_c/s`, `uci_save_c/s(commit, apply)`.
- `uci_save(cursor, config, commit, apply)`:
  ```
  cursor = cursor or global uci
  if is_old_uci(): save(config); if commit: commit(config); if apply: sh "/etc/init.d/<config> reload > /dev/null 2>&1 &"
  else: (commit forced true) if apply: cursor:commit(config) else sh_uci_commit(config)
  ```
  Note: in the new-uci branch `apply` does NOT trigger a reload; it only decides between cursor commit vs `uci -q commit`.
- Shell UCI helpers (all via `exec_call`):
  - `sh_uci_get(c,s,o)` → `uci -q get c.s.o` → output string (trimmed).
  - `sh_uci_set(c,s,o,val,commit)` → `uci -q set c.s.o="val"`; commit → `uci -q commit c`.
  - `sh_uci_del(c,s,o,commit)` → `uci -q delete c.s.o`.
  - `sh_uci_add_list(c,s,o,val,commit)` → `uci -q del_list c.s.o="val"` then `uci -q add_list c.s.o="val"` (dedupe-append).
  - `sh_uci_commit(c)` → `uci -q commit c`.

### 1.3 Cache variables (file `/tmp/etc/passwall2/var`, lines `KEY="VAL"`)
All implemented by sourcing `/usr/share/passwall2/utils.sh`:
- `del_cache_var(key)` → `. utils.sh ; del_cache_var "key"` (sed deletes lines matching `key=` — note: substring match, no anchor).
- `set_cache_var(key,val)` → `. utils.sh ; set_cache_var '<key>' '<val>'` (shell-quoted). Deletes old, appends `key="val"` if val non-empty (mkdir -p TMP_PATH).
- `get_cache_var(key)` → `echo -n $(get_cache_var "key")`; shell impl: last line `^key=`, value between first pair of `"`. Returns nil for "".
- `get_new_port(start_port, protocol)`: start_port = number or `"auto"`; protocol must be `tcp`/`udp` else `"tcp,udp"`; runs `get_new_port '<start>' '<proto>'` and returns number.
  Shell semantics (for reimplementation): default start 2001, range [1025,49151]; `auto` → last cached `last_get_new_port_auto`+1 or 2001; out-of-range → 2001; port is "used" if `netstat -tuln` shows `:<port> ` for the protocol(s) OR cache var `get_port_<port>` exists; if used, try port+1 (or port-1 at max) recursively; on success set cache `get_port_<port>=1` (and for auto, `last_get_new_port_auto`).
- `get_socks_port_by_cache(node_id)` = `get_cache_var("node_<id>_socks_port")`; `set_socks_port_to_cache(id,v)` sets it.

Known cache keys referenced in this file set: `DIRECT_DNS`, `ENABLED_DEFAULT_ACL`, `ENABLED_ACLS`, `ACL_acl_default_node_socks_port`, `DEFAULT_DNS`, `HAPROXY_PROBE_URL`, `node_<id>_socks_port`, `<socks section id>` (current node of a socks instance, used by auto-switch), `get_port_<n>`, `last_get_new_port_auto`.

### 1.4 Process execution
- `exec_call(cmd)`: tag = `"\x01__RC__" .. random(100000..999999) .. "\x01"`; runs `(cmd) 2>&1; printf "\n<tag>%d" "$?"` via popen; parses rc from trailing tag. If tag missing → `(255, trim(out))`. Else strip `\n?<tag>\d+\s*$` → `(rc, trim(out))`. Stdout+stderr merged.
- `exec_call_as_gid(cmd, gid)`: pipe+fork; child dup stdout/stderr to pipe, `setgid(gid)` (exit 1 on failure), exec `/bin/sh -c cmd` (exit 127 on fail). Parent reads all, waitpid; returns `(code if exited else 255, trim(out))`. Errors: `255,"Unable to create command pipe"`, `255,"Unable to fork command"`.
- `exec(cmd, args, writer?, timeout?)`: fork; child dup stdout to pipe, `exece(cmd,args,nil)` (exit 1 on fail). Parent: if writer or timeout → loop: if elapsed>=timeout → SIGTERM child, return 1; if writer: read ≤2048 bytes and pass to writer; waitpid nohang → return exit code when exited; sleep 1s if no writer. Else blocking waitpid → exit code (or false/nil).
- `remove(...)`: for each non-empty string ≠ `/`: `rm -rf -- <value>` (NOT quoted — globs expand, used intentionally with `*`).
- `is_install(pkg)`: if `/usr/lib/opkg/info` dir exists → check `[ -s /usr/lib/opkg/info/<pkg>.control ]`, else `[ -s /lib/apk/packages/<pkg>.list ]`.
- `finded(e)` → `echo -n $(type -t -p "/bin/e" -p "/usr/bin/e" "e" | head -n1)`; `is_finded(e)` = non-empty.
- `finded_com(e)`: bin = `get_app_path(e)` (only for com.lua apps); `type -t -p "<bin>" | head -n1`; nil if empty.
- `chmod_755(file)`: if not access mode rwx/rx/rx → chmod 755.
- `gen_uuid()` → contents of `/proc/sys/kernel/random/uuid` (no newline).
- `gen_random_char(len=8)` → `head /dev/urandom | tr -dc A-Za-z0-9 | head -c len`.
- `get_customed_path(e)` → `passwall2.@global_app[0].<e>_file`.

### 1.5 Encoding / hashing
- `base64Decode(text)`: non-string → `""`. Normalize: remove NULs and control chars, `_`→`/`, `-`→`+`, strip trailing `=`. If empty → return original text. If not `^[A-Za-z0-9+/]*$` → original. If len%4==1 → original. Pad with `=` to multiple of 4, decode; on fail → original. **Canonical check**: re-encode result and strip `=`; if ≠ normalized input → return original. Return decoded with NULs removed. (So "returns input unchanged" == "not base64".)
- `base64Encode(text)` → standard b64 with padding; nil for nil.
- `UrlEncode(s)`: every byte not in `[A-Za-z0-9-_.~]` → `%XX` (uppercase hex). Non-string → "".
- `UrlDecode(s)`: `+`→space, `%XX`→byte.
- `md5_file(path)` → first 32 chars of `md5sum '<path>'` ('' on error).
- `md5_string(str)` → write to `mktemp /tmp/md5.XXXXXX`, md5_file, unlink.
- `verify_sha256(file, digest)`: digest must match `^sha256:(hex{64})$`; run `sha256sum '<file>'`; true iff rc 0 and case-insensitive match.
- `sha256_xray_sb(str)` (hex fingerprint → base64): if base64Decode(str) differs from str and is 32 bytes → already base64, return str. Else strip `:`; must be 64 hex chars → convert to 32 bytes → base64Encode. Else return str.
- `sha256_sb_xray(str)` (base64 → hex): decode; if unchanged or ≠32 bytes return str; else uppercase hex (no colons).
- `fetch_cert_sha256(host, port=443, sni=host, timeout=5)`:
  ```
  timeout <t> openssl s_client -connect <host>:<port> -servername <sni> -showcerts </dev/null 2>/dev/null
   | awk 'BEGIN{c=0}/BEGIN CERT/{c++} c==1{print} /END CERT/{if(c==1)exit}'
   | openssl x509 -outform der 2>/dev/null | sha256sum 2>/dev/null
  ```
  Leaf cert DER SHA-256, returned UPPERCASE hex. Returns "" if no host, no hex, or hash starts with `e3b0c44298fc1c149afbf4c8996fb924` (empty input).

### 1.6 Networking helpers
- `get_domain_port_from_url(url)`: match `^(https?)://([%w.-]+):?(%d*)`; else `^(https?)://(%b[])([^:/]*)/?` (bracketed IPv6 — note port capture here is whatever follows `]` up to `:`/`/`, effectively ""); strip brackets; port default 443 (https)/80. If domain is an IP (v4/v6) → `nil,nil`. Returns `domain, port`.
- `resolve_domain(domain, dns?)`:
  ```
  dns = dns or cache DIRECT_DNS or "223.5.5.5"
  parse "addr#port" | "[addr]:port" | "host:port" | bare; strip []; port default "53"
  server = "[addr]" if ipv6 else addr
  dns_servers = { server..":"..port, addr.."#"..port, "223.5.5.5" }
  busybox version from `LC_ALL=C busybox nslookup -v 2>&1` ("BusyBox vX.Y.Z"); if < 1.35.0 swap first two entries
  for each s: (rc,out) = exec_call_as_gid("LC_ALL=C busybox nslookup '<domain>' '<s>'", 9912)
     parse lines: after a line matching ^\s*Name: set answer=true; then lines ^\s*Address\s*\d*:\s*(\S+) that are valid IPv4/IPv6 → unique list
     if list non-empty → return list
  return nil, last_out, last_rc
  ```
- `curl_base(url, file?, args={}, gid?)`: if file → append `"-o <file>"` to args (mutates args!); cmd = `curl <args joined by space> "<url>"`; run with exec_call_as_gid(gid) or exec_call → `(rc, output)`.
- `curl_proxy(url, file, args)`: port = cache `ACL_acl_default_node_socks_port`; if set → clone args, append `-x socks5h://127.0.0.1:<port>`, curl_base. Else `nil,nil`.
- `curl_direct(url, file, args)`:
  ```
  if cache ENABLED_DEFAULT_ACL != "1" and ENABLED_ACLS != "1": return curl_base(url,file,args)   -- proxy not active
  a = clone(args) + "--noproxy '*'"
  (domain,port) = get_domain_port_from_url(url)
  if domain: ips = resolve_domain(domain); if none → return 6, err
            ipv6 ips wrapped in []; a += "--resolve '<domain>:<port>:<ip1>,<ip2>...'"
  return curl_base(url, file, a, gid=9912)
  ```
- `curl_logic(url,file,args)`: try curl_proxy; if nil or rc≠0 → curl_direct.
- `curl_auto(url,file,args)`: if `@global[0].localhost_proxy` (default "1") == "1" → curl_base (router traffic is proxied transparently anyway); else curl_logic.
- `url(...)` → LuCI `build_url("admin/services/passwall2/<non-empty args joined by />")`.
- `get_domain_from_url(url)` → text after `//` up to next `/` (includes port), or the url itself.
- `parseURL(url_str)` → table: `protocol` (scheme before `://`), `pathname` (path without `?`/`#`, only if path non-empty), `username`/`password` (from leftmost `user[:pass]@`, password "" if absent), `hostname`, `port` (number), `host` (raw host:port). Handles `[v6]:port`, `[v6]`, `host:port`, `host`.
- `parseDNS(dns)` → `(address, port)`: `[v6]:port` (valid) → (v6, port string); bare/bracketed IPv6 → (v6 without brackets, 53); `ipv4:port` (valid) → (ip, port); else `(dns, 53)`. nil for nil. When called via shell `lua_api "parseDNS(...)"` print shows `addr\tport`.
- `get_dnsmasq_server_domain()`: reads `dhcp.@dnsmasq[0].server` list; for entries containing `/` and splitting by `/` into >2 parts: domain = part[2], upstream = last part; split upstream by `#` → server, port (default 53). Returns `{ [domain] = { dnsmasq_dns=upstream, server=..., port=<number> } }`.
- `get_network_devices()` → array of `{name, label, sort}` sorted by `sort`:
  - UCI `network` `interface` sections (except `loopback`): maps iface→`device`, device→[ifaces], iface→`proto`.
  - For each entry in `/sys/class/net/` except `lo`, `veth*`, `ifb*`, `gre*`, `sit*`, `ip6tnl*`, `erspan*`, and those having `<dev>/master` or `<dev>/dsa`: type = "Bridge" if `<dev>/bridge` dir; "Wireless Adapter" if `<dev>/wireless` dir; "Tunnel Interface" if name ^tun|^tap|^wg|^ppp; else "Ethernet Adapter". label = `<type>: "<dev>"` + ` (<iface1>, <iface2>)` if mapped. sort = `<type>:<dev>`.
  - For UCI ifaces whose device not seen: type = "Bridge" if device `^br-`; "Tunnel Interface" if proto in wireguard/pppoe/pptp/l2tp; else "Interface". name=iface, label=`<type>: "<iface>"`, sort=`zzz:<iface>`.
  - Type strings are translated (i18n).

### 1.7 String / table / validation helpers
- `trim(s)`: strip bytes ≤ 32 from both ends; non-string → "".
- `split(full, sep)`: remove NULs; split on Lua pattern `sep`; inner empty pieces kept, trailing empty piece dropped. nil → {}.
- `is_exist(t, v)`; `repeat_exist(t, v)`: true if >1 entries contain `-` and equal v.
- `get_args(arg)`: CLI parser: for each i>0, `var[arg[i]] = arg[i+1]` unless arg[i+1] is a `-`-containing value appearing more than once. (So `-path X -conf Y` → `{["-path"]="X", ["X"]="-conf", ["-conf"]="Y"}`; consumers only read the `-flag` keys.)
- `get_function_args(arg)` → get_args(arg[2..]) or nil.
- `strToTable(str)` → evaluates Lua table literal (unsafe; Rust: parse JSON instead).
- `is_json(str)`; also registered as `datatypes.json`.
- `is_timehhmm(str)`: `^\d?\d:\d\d$`, h 0-23, m 0-59; registered `datatypes.timehhmm`.
- `is_uuid(str)`: 8-4-4-4-12 hex; registered `datatypes.uuid`.
- `is_normal_node(e)`: false iff `e.type` and `e.protocol` in {`_balancing`,`_shunt`,`_iface`,`_urltest`}. `is_special_node` = not normal.
- `is_ip(val)`: trim, lowercase, use content in `[...]` if present → valid IPv4/IPv6. `is_ipv6` same but IPv6 only.
- `is_ipv6addrport(val)`: `[v6]:port` with valid v6 + port.
- `get_ipv6_only(val)` → inner v6 without brackets or "". `get_ipv6_full(val)` → `[v6]` or "".
- `get_ip_type(val)` → "6" / "4" / "".
- `is_mac(val)`; `ip_or_mac(val)` → "ip" (IPv4 only) / "mac" / "".
- `iprange(val)`: `^A-B$` both IPv4 (no `/`).
- `clone(t)`: deep copy.
- `_unpack`, `table_join(t, sep=" ")`.
- `table_remove_duplicates(t)`: nil if empty; keep first occurrences, drop empty strings.
- `cleanEmptyTables(t)`: recursively removes empty sub-tables; returns nil if t becomes empty.
- `cacheFileCompareToLogic(file, str)`: if both given: read file (via `cat`), if content ≠ str → `rm -f file`, result=false else true; then (always) rewrite file with str. Returns result (nil if args missing).
- `format_go_time(input, default="0s")`: input trimmed; pure digits → seconds; else sum all `(\d+)\s*([hms])`. N<=0 → default. Output `XhYmZs` omitting zero parts; seconds shown if non-zero or nothing else (e.g. 3600→"1h", 90→"1m30s").
- `compare_versions(v1, comp, v2)`: split on `.` or `-`; each part numeric, or `r<N>`/`R<N>` → N, else 0; missing parts=0. Iterate: `~=` true on first diff; `<`/`<=` true if s1<s2; `>`/`>=` true if s1>s2; any diff → false. All equal → true unless comp is `<` or `>`. (Note `~=` with equal → true too — quirk: returns `not (comp=="<" or comp==">")`.)
- `gen_wireguard_key()` → `{private_key, public_key}`: prefer `wg genkey` / `echo "<priv>" | wg pubkey`; else xray: `<xray> wg | awk -F ': ' '{print $2}'` (line1 priv, line2 pub); else sing-box: `<sb> generate wg-keypair | awk '{print $2}'`. nil if none.

### 1.8 Filesystem helpers
- `is_file(path)` / `is_dir(path)`: `#path>1` and stat type `reg`/`dir` → true else nil.
- `get_final_dir(path)`: walk up dirname until an existing dir.
- `get_free_space(dir="/")` → KB available: `df -k dir | awk 'NR>1' | awk '{print $4}'`; 0 on df failure.
- `get_file_space(file)` → `du -k file | awk '{print $1}'` or 0.
- `is_js_luci()` → `/www/luci-static/resources/uci.js` is regular file.

### 1.9 Node naming & listing
Node section type: `nodes` in `/etc/config/passwall2`. Options read here: `type` (e.g. `Xray`, `sing-box`, `SSR`, `SS-Rust`, `Socks`, ...), `protocol`, `remarks`, `group`, `address`, `port`, `hysteria_hop`, `hysteria2_hop`, `hysteria2_realms`, `chain_proxy`, `download_address`.

Protocol display map (used for `type` ∈ {Xray, sing-box}):
`vmess→VMess, vless→VLESS, shadowsocks→SS, shadowsocksr→SSR, wireguard→WG, hysteria→HY, hysteria2→HY2, anytls→AnyTLS, ssh→SSH, other→first letter uppercased`.
Type display: `sing-box` → `Sing-Box`, others as-is. Separator is fullwidth colon `：` (U+FF1A).

- `get_node_name(node_id|table)`: only for protocol `_balancing|_shunt|_iface` (not `_urltest`): `"<TypeName> <translatef(protocol)>：[<remarks>] "` (trailing space). Else "".
- `get_valid_nodes()` → ordered list (nodes without group first, then with group; each in UCI order). For each `nodes` section with `type` and `remarks` (`e.id = .name`):
  - special protocol (4 values) → `remark = trim("<TypeName> <translatef(proto)>：[<remarks>]")`, `node_type="special"`, added.
  - Then (also evaluated for special nodes!) port = `port or hysteria_hop or hysteria2_hop`; is_realm = protocol `hysteria2` and `hysteria2_realms` set. If (port and address) or is_realm, and address is IP or hostname or is_realm:
    - type_name += " "..ProtoDisplay for Xray/sing-box; IPv6 address bracketed; `" Realm"` appended if is_realm.
    - `remark = trim("<type_name>：[<remarks>]")`; if `@global_other[0].show_node_info`=="1" and not realm: remark += ` <address>:<port with ':'→'-'>`.
    - `node_type="normal"`, added (could duplicate a special node in theory if it had address+port).
- `get_node_list()` → `{ socks_list=[{id, remark="<tr Socks Config> [<port><tr Port>]", group="Socks"}] for socks sections with node, normal_list=[{id, remark, type, chain_proxy, group}], <proto>_list=[{id, remark, group, o=<full node>}] for protocols starting with "_" (balancing_list, shunt_list, iface_list, urltest_list) }`.
- `get_node_remarks(n)`: same naming as get_valid_nodes without address info and without IP/host validation (realm suffix if hysteria2 + hysteria2_realms).
- `get_full_node_remarks(n)`: remarks + ` <address>:<port('-' for ':')>` if address and port/hop.
- `get_random_normal_node(exclude_id|list)`: random among normal valid nodes not excluded (seed os.time()); nil if none.
- `match_node_rule(name, rule)`: nil name → false; empty rule → true. Rule grammar: OR groups split by `||`, AND conditions split by `&&` (trimmed, empty dropped). Condition: `!k` → name does not contain k (plain); `^k` → prefix; `k$` → suffix; else contains (plain substring). True if any OR-group fully matches.
- `get_batch_nodes(node)`: lazily builds (module-level cache) list of normal nodes with empty `chain_proxy` → `{id, remarks, group}`. If `node.node_group` empty → {}. For each space-separated group token (URL-decoded): include nodes where `(group or "default"):lower() == token:lower()` and `match_node_rule(remarks, node.node_match_rule)`. Returns ids (may contain duplicates across groups; order = group order then UCI order).
- `get_socks_backup_nodes(id)` (called from shell via `lua_api`): socks section = `uci_get_c(id)`; if `backup_node_add_mode == "batch"` → `get_batch_nodes({node_group=backup_node_group, node_match_rule=backup_node_match_rule})`; else list `autoswitch_backup_node`. Remove entries equal to `socks.node`, dedupe; return space-joined string. Empty id → "".
- `get_core(field, candidates)`: candidates = `{{bool_available, "name"}, ...}`. If `@global_subscribe[0].<field>` is set and matches an available candidate → it; else first available candidate name; else nil. Fields used elsewhere: `ss_type`, `trojan_type`, `vmess_type`, `vless_type`, `hysteria2_type`.
- `parse_realm_uri(uri)`: accepts `realm://` or `realm+http://`; format `token@server/realm_id?query`. Strips trailing `/` from realm_id. server `[v6]:port` | `host:port` | `[v6]` | host; port default 80 for realm+http, 443 for realm. Returns `{scheme, token, server_url, address, port(number), realm_id, stun_servers=[values of all case-insensitive stun=... query params] or nil}`; nil if invalid.

### 1.10 UCI options read in api.lua (summary)
| Section | Option | Default | Use |
|---|---|---|---|
| `@global[0]` | `auto_lang` | – | language override when luci lang=auto |
| `@global[0]` | `localhost_proxy` | "1" | curl_auto direct vs logic |
| `@global_other[0]` | `show_node_info` | "0" | append addr:port to node remarks |
| `@global_app[0]` | `<app>_file` (`xray_file`, `sing_box_file`, `geoview_file`) | com default_path | binary path |
| `@global_app[0]` | `gh_proxy_url` | "" | prefix for GitHub URLs (forces curl_direct) |
| `@global_subscribe[0]` | `ss_type` etc. | – | get_core |
| `socks` | `node`, `port`, `backup_node_add_mode`, `backup_node_group`, `backup_node_match_rule`, `autoswitch_backup_node` (list) | | |
| `nodes` | `node_group`, `node_match_rule` (for batch/urltest/balancing callers) | | |
| luci | `main.lang`, `languages.<code>` | | i18n |
| dhcp | `@dnsmasq[0].server` | | get_dnsmasq_server_domain |
| network | `interface` sections `.device`, `.proto` | | devices |

### 1.11 Binary version cache
`get_bin_version_cache(file, cmd, sb_tags)` (local):
```
if file accessible:
  chmod_755(file)
  stat → cache_file = CACHE_PATH/binver_<dev>_<ino>_<size>_<mtime>_<ctime>
  if cache exists and first line non-empty → return version (and 2nd line as tags if sb_tags)
  if sb_tags: out = `'<file>' version`; version = match ^sing-box\s+version\s+(\S+); tags = trimmed text after "\nTags:"
  else: version = `echo -n $('<file>' <cmd>)`
  if version non-empty: write cache (sb: "version\ntags\n", else "version") ; return
return ""
```
- `get_app_path(app)`: only if `com[app]` exists: `@global_app[0].<app with '-'→'_'>_file` if non-empty else `com[app].default_path`.
- `get_app_version(app, file?)`: version via cache, sing-box uses sb_tags mode.
- `get_singbox_tags()` → tags string (e.g. `with_gvisor,with_quic,...`) or "".

### 1.12 com.lua component table
```
order = {"geoview", "xray", "sing-box"}
gh_release_url(self)     = "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/<lower(name)>-release-api.json"
gh_pre_release_url(self) = ".../api-cache/<lower(name)>-pre-release-api.json"
```
| key | name | get_url | cmd_version | zipped | zipped_suffix | default_path | match_fmt_str | file_tree overrides |
|---|---|---|---|---|---|---|---|---|
| `passwall2` | PassWall2 | release | – | – | – | – | – | – |
| `sing-box` | Sing-Box | release | `version` | true | `tar.gz` | /usr/bin/sing-box | `linux%%-%s` | x86_64=`amd64%-musl`, x86=`386%-musl`, aarch64/rockchip/armv8=`arm64%-musl`, mips=`mips%-softfloat`, mips64=`mips64%-softfloat`, mipsel=`mipsle%-softfloat%-musl`, mips64el=`mips64le%-softfloat`, armv7=`armv7%-musl`, riscv64=`riscv64%-musl` |
| `xray` | Xray | **pre-release** | `version \| awk '{print $2}' \| sed -n 1P` | true | (zip) | /usr/bin/xray | `linux%%-%s` | x86_64=`64`, x86=`32`, mips=`mips32`, mipsel=`mips32le`, mips64el=`mips64le` |
| `geoview` | Geoview | release | `-version 2>/dev/null \| awk 'NR==1 && $1=="Geoview" {print $2}'` | false | – | /usr/bin/geoview | `linux%%-%s` | mipsel=`mipsle`, mips64el=`mips64le` |

(`repo` fields: SagerNet/sing-box, XTLS/Xray-core, snowie2000/geoview — informational only.)
Patterns are Lua patterns (`%-` = literal `-`); asset name match = `string.match(name, format(match_fmt_str, file_tree))` e.g. sing-box x86_64 → pattern `linux%-amd64%-musl` (unanchored).

Default file_tree (fallback): x86_64=amd64, x86=386, aarch64=arm64, rockchip=arm64, mips=mips, mips64=mips64, mipsel=mipsel, mips64el=mips64el, armv5=`arm.*5`, armv6=`arm.*6[^4]*`, armv7=`arm.*7`, armv8=arm64, riscv64=riscv64.

### 1.13 Arch detection `auto_get_arch()`
```
arch = uname().machine
OPENWRT_ARCH = value of OPENWRT_ARCH in /usr/lib/os-release (quoted value)   (cached)
DISTRIB_ARCH = value of DISTRIB_ARCH in /etc/openwrt_release                  (cached)
i?86 → x86; contains armv5 → armv5; armv6 → armv6; armv7 → armv7
if either known:
  mips and (OPENWRT_ARCH or DISTRIB_ARCH contains "mipsel") → mipsel
  armv7 and (OPENWRT_ARCH lacks vfp & neon OR DISTRIB_ARCH lacks vfp & neon) → armv5
return trim(arch)
```

### 1.14 Component updater (used by LuCI controller endpoints)
`get_api_json(url)`: if `gh_proxy_url` set → `curl_direct(gh_proxy..url, nil, curl_args)` else `curl_auto(url, nil, curl_args)`. rc≠0 or empty → `{}`; else parsed JSON or `{}`.

`check_path(app)` → `{code=1, error="You did not fill in the %s path. Please save and apply then update manually."}` or `{code=0, app_path}`.

`cache_update_digests(app, assets)`: writes `CACHE_PATH/update_<app>.json` = `{ "<browser_download_url>": "<digest>" }` for assets whose `digest` is a string (GitHub format `sha256:<hex>`).

**`to_check(arch, app)`**:
1. check_path; arch default auto_get_arch(); file_tree = com override or default; "" → `{code=1, error="Can't determine ARCH, or ARCH not supported."}`.
2. local_version = get_app_version(app); pattern = match_fmt_str % file_tree; json = get_api_json(get_url); if array → first element.
3. no `tag_name` → `{code=1, error="Get remote version info failed."}`.
4. remote_version = tag_name (with optional `remote_version_str_replace` gsub — unused now). `has_update = compare_versions(local:match("[^v]+"), "<", remote:match("[^v]+"))`.
5. asset = first in `json.assets` whose name matches pattern. None → `{code=1, local_version, remote_version, html_url, data=asset, error="New version found, but failed to get new version download url."}`.
6. cache_update_digests(app, {asset}); return `{code=0, has_update, local_version, remote_version, html_url, data=asset}` (data = full GitHub asset object: name, size, browser_download_url, digest, ...).

**`to_download(app, url, size, task_id, keep_files)`**:
1. For app≠"passwall2" → check_path. url required → `"Download url is required."`.
2. digest = `update_<app>.json`[url]; not string → `{code=1,error="File verification failed."}`.
3. Unless keep_files: `/bin/rm -f /tmp/<app>_download.*`.
4. tmp_file = `/tmp/<app>_download.<task_id>` if task_id matches `^[%w_-]+$` (pre-removed), else `mktemp -u -t <app>_download.XXXXXX`.
5. If size and size > free KB of /tmp → `"/tmp not enough space."` (note: compares bytes vs KB as given by caller).
6. args = curl_args + `"--speed-limit 51200 --speed-time 15 --max-time 300"`; gh_proxy → curl_direct(gh_proxy..url) else curl_auto.
7. rc≠0 → rm tmp, `"File download failed or timed out: <url>"`. SHA-256 mismatch → rm, `"File verification failed."`.
8. `{code=0, file=tmp_file, zip=com[app].zipped}`.

**`to_download_progress(app, task_id, total_size)`**: validate app in com and task_id `^[%w_-]+$` else `{code=1,error="Invalid download task."}`. downloaded = size of `/tmp/<app>_download.<task_id>`; for passwall2 sum sizes of `<tmp>1`..`<tmp>5` (main package + up to 4 i18n packages). percent = min(99, floor(downloaded*100/total)) if total>0 else nil. Return `{code=0, downloaded, total, percent}`.

**`to_extract(app, file, subfix)`**: check_path; file must exist → else `"File path required."`. If zipped: tool = `unzip` (no suffix or "zip") or `tar` ("tar.gz"); if `command -v tool` empty → rm file, `"Not installed %s, Can't unzip!"`. `rm -rf /tmp/<app>_extract.*`. If /tmp free KB <= 0 or <= file KB → `"/tmp not enough space."`. tmp_dir = `mktemp -d -t <app>_extract.XXXXXX`. unzip: `unzip -o <file> <app> -d <tmp_dir>` (extracts only member named `<app>`, e.g. `xray`); tar: `tar -zxf <file> -C <tmp_dir>` then `/bin/mv -f <tmp_dir>/*/<lower(name)> <tmp_dir>` (sing-box archives have a top-level dir). rm file. Return `{code=0, file=tmp_dir}`. (Non-zipped apps: no extraction, returns empty tmp_dir — but to_move is then called with the downloaded file directly by the controller.)

**`to_move(app, file)`**:
```
app_path = check_path
bin_path = file; cmd_rm_tmp = "/bin/rm -rf /tmp/<app>_download.*"
if file is dir: bin_path = file/<lower(com.name)>; cmd_rm_tmp = "/bin/rm -rf /tmp/<app>_extract.*"
file empty → rm tmp, "Client file is required."
new_version = get_app_version(app, bin_path); "" → rm tmp, "The client file is not suitable for current device." .. app .. "__" .. bin_path
space: free(get_final_dir(app_path)) + old size; if free>0 and new > that → "<dir> not enough space."
running = `busybox pgrep -af "passwall2/.*<app>" >/dev/null` == 0; if running → /etc/init.d/passwall2 stop
mv -f bin_path app_path (timeout 300s)
rm tmp; if running → "/etc/init.d/passwall2 restart >/dev/null 2>&1 &"
fail or app_path missing → "Can't move new file to path: <app_path>"
{code=0}
```

### 1.15 Self-update (luci-app-passwall2 package)
**`get_version()`**: cached in `CACHE_PATH/passwall2_version`; else `opkg list-installed luci-app-passwall2 2>/dev/null | awk '{print $3}'`, else `apk list luci-app-passwall2 2>/dev/null | awk '/installed/ {print $1}' | cut -d'-' -f4-`; cache non-empty. Return with trailing `-rN`/`-RN` → `-N` (e.g. `26.1.1-r1` → `26.1.1-1`).

**`self_update_languages()`** → list among `{"fa","ru","zh-cn","zh-tw"}` (in that order) where code == current UI lang OR `luci-i18n-passwall2-<code>` is installed.
current lang resolution: luci.main.lang; if "auto": dispatcher lang; else if in HTTP context: parse `HTTP_ACCEPT_LANGUAGE` items (`code;q=x`, q>0), `-`→`_`, aliases zh/zh_cn/zh_sg→zh_Hans, zh_tw/zh_hk/zh_mo→zh_Hant, ^zh_hans→zh_Hans, ^zh_hant→zh_Hant; candidates {code, lower, alias, primary-subtag} checked against `luci.languages.<candidate>`; first match wins; default "en". Outside HTTP → module `lang`. Normalize: lowercase, `_`→`-`; zh/zh-cn/zh-sg/zh-hans* → zh-cn; zh-tw/zh-hk/zh-mo/zh-hant* → zh-tw; fa-* → fa; ru-* → ru.

**`to_check_self()`**:
```
release = get_api_json(passwall2 release url); array → [1]; no tag_name → error "Get remote version info failed."
local = get_version()
remote = tag_name minus leading "v", "-rN" → "-N"
package_version = remote with trailing "-N" → "-rN"
language_version = remote ^(\d+.\d+.\d+) or remote
apk = `command -v apk` ok
main_name = apk ? "luci-app-passwall2-<package_version>.apk" : "luci-app-passwall2_<package_version>_all.ipk"
for each language: "luci-i18n-passwall2-<code>-<language_version>.apk" | "luci-i18n-passwall2-<code>_<language_version>_all.ipk"
all must be present in release.assets (else error), main must exist (else error)
cache_update_digests("passwall2", [main, i18n...])
return {code=0, has_update=compare_versions(local,"<",remote), local_version, remote_version, html_url, data=main, i18n=[assets], languages="fa,ru,..."}
```

**`to_install_self(id, force, languages)`**:
- validate id `^[%w_-]+$`; languages comma list of unique codes from {fa,ru,zh-cn,zh-tw}; else `{code=1}`.
- dir = `/tmp/passwall2_luci_update.<id>`; manager = apk if available else opkg; ext `.apk`/`.ipk`.
- status file = `/www/luci-static/resources/passwall2-update/<id>.json` (dir created).
- mv `/tmp/passwall2_download.<id>1` → `<dir>/luci-app-passwall2<ext>`; for language index k (1-based) mv `/tmp/passwall2_download.<id><k+1>` → `<dir>/luci-i18n-passwall2-<code><ext>`. Any fail → rm dir, `{code=1}`.
- cp `/usr/share/passwall2/luci_update.sh` → `<dir>/luci_update.sh`, chmod 755.
- write status `{"installing":true}`.
- `nohup <dir>/luci_update.sh <dir> <status> <manager> <1|0 (force=="1")> >/dev/null 2>&1 </dev/null &`; return `{code=0}`.

### 1.16 CBI helpers (Lua-LuCI only; rewrite in JS frontend)
These monkey-patch luci.cbi for the old Lua UI. The JS rewrite does not need them, but note behavior that affects stored config:
- `set_default_cbi()`:
  - `Map` default config = passwall2; `apply_on_parse=false` when JS-LuCI present; template paths prefixed `passwall2`.
  - If `luci.main.lang`=auto: iterate `HTTP_ACCEPT_LANGUAGE` tokens `[%w-]+` (`-`→`_`), first one that exists in `luci.languages` (as-is or lowercased) → **writes `passwall2.@global[0].auto_lang=<lang>` and commits** (`uci -q set ... ; uci -q commit passwall2`).
  - `DynamicList.write`: dedupe values (table_remove_duplicates), cast "string" → space-joined.
  - `TextValue` template → `passwall2/cbi/tvalue`; adds `HideValue` class.
- `set_type_cbi(s)`: options in a per-node-type sub-section are stored with `option_prefix` stripped (`config_option` = real UCI name) and only written/removed when the section's `type` field form value equals `s.type_name`. MultiValue/DynamicList deduped; cast string → space-joined. Dependencies auto-add `type=<type_name>`.
- `type_cbi_section(s, s2)`, `return_map(map)` (adds header/footer templates).

---

## 2. server_app.lua (passwall2_server)

Invoked by `/etc/init.d/passwall2_server`: `lua /usr/lib/lua/luci/passwall2/server_app.lua start|stop`.

Constants: `CONFIG="passwall2_server"`, `CONFIG_PATH="/tmp/etc/passwall2_server"`, `LOG_APP_FILE="/tmp/log/passwall2_server.log"`, `TMP_BIN_PATH="/tmp/etc/passwall2_server/bin"`.

`log(...)`: append `"%Y-%m-%d %H:%M:%S: " .. join(args," ")` to LOG_APP_FILE.

`ln_run(src, name, command, output="/dev/null")`: `d = TMP_BIN_PATH/name`; `[ ! -f "d" ] && ln -s src d 2>/dev/null`; returns command string `"<d> <command> ><output> 2>&1 &"` (symlink name gives a recognizable process path under CONFIG_PATH for kill).

### UCI (passwall2_server)
| Section | Option | Type/Default | Meaning |
|---|---|---|---|
| `@global[0]` | `enable` | "0" | master switch (tonumber; nil/0 → do nothing) |
| `server` | `enable` | "1" required | per-server enable |
| | `log` | "0" | "1" → log to `/tmp/etc/passwall2_server/<id>.log` |
| | `loglevel` | – | injected into custom configs |
| | `remarks` | – | for log line |
| | `port` | number | listen port; also firewall dest_port |
| | `type` | `SSR`/`SS-Rust`/`Xray`/`sing-box` | |
| | `custom` | "0" | "1" + `config_str` → use user JSON |
| | `config_str` | base64 JSON | custom config |
| | `udp_forward` | "1" | SSR: `-u` flag |
| | `firewall_allow` | "0" | open port in firewall |
| | `firewall_allow_src` | "wan" | firewall zone |
| | `user` | section id | (SS server) referenced user section with `password` |
| (others) | protocol options | | consumed by util_* gen_config_server |

### start()
```
if not tonumber(@global[0].enable) → return
mkdir -p CONFIG_PATH TMP_BIN_PATH ; touch LOG_APP_FILE
for each "server" section (id = .name) with tonumber(enable)==1:
  log_path = enable log=="1" ? CONFIG_PATH/<id>.log : nil
  config_file = CONFIG_PATH/<id>.json
  type = server.type or ""
  SSR:     config = custom ? json(b64dec(config_str)) : util_shadowsocks.gen_config_server(server)
           udp = (tonumber(udp_forward) or 1)==1 ? "-u" : ""
           bin = ln_run("/usr/bin/ssr-server", "ssr-server", "-c <config_file> <udp>", log_path)
  SS-Rust: config likewise; bin = ln_run("/usr/bin/ssserver","ssserver","-c <config_file>", log_path)
  Xray:    custom → parse; if log_path: config.log = config.log or {}; config.log.loglevel = server.loglevel
           else util_xray.gen_config_server(server)
           bin = ln_run(get_app_path("xray"), "xray", "run -c <config_file>", log_path)
  sing-box: custom → parse; if log_path: config.log={..., timestamp=true, disabled=false, level=loglevel, output=log_path}
           else util_sing-box.gen_config_server(server)
           bin = ln_run(get_app_path("sing-box"), "sing-box", "run -c <config_file>", log_path)
  if config non-empty: write jsonc.stringify(config, pretty) to config_file; log "<remarks> Generate configuration file and run - <config_file>"
  if bin: sh(bin)        -- e.g. "/tmp/etc/passwall2_server/bin/xray run -c /tmp/etc/passwall2_server/<id>.json >/dev/null 2>&1 &"
  if firewall_allow=="1":
     uid = "passwall2_server_<id>"
     firewall: section rule named uid; name=uid; src=firewall_allow_src or "wan"; dest_port=port; target=ACCEPT
if any firewall rule added: uci_save(firewall, commit=true, apply=true)  (commit firewall)
```
Note: unknown type → no bin, config `{}` → nothing written. The ssr log path for non-log is `/dev/null`.

### stop()
```
/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall2_server/' | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1
delete every firewall "rule" whose name starts with "passwall2_server" (find(...)==1); if any → commit firewall
rm -rf /tmp/etc/passwall2_server /tmp/log/passwall2_server.log
```
(Firewall reload is NOT triggered here explicitly — init script handles it.)

---

## 3. util_shadowsocks.lua

### gen_config_server(node) → table (server side, `node` = passwall2_server server section)
```
user = node.user ? uci_get_s(node.user) : nil
{
  server_port: tonumber(port),
  password: user.password or "",
  timeout: tonumber(timeout),
  fast_open: tcp_fast_open=="1",
  method: method,
  server: SS-Rust ? "::" : ["[::0]", "0.0.0.0"],
  mode: "tcp_and_udp"            (SS-Rust only)
  protocol, protocol_param, obfs, obfs_param   (SSR only)
}
```

### gen_config(var) (client; CLI `lua util_shadowsocks.lua gen_config '<json>'` → prints JSON)
Input JSON keys: `node` (required; else prints "node Cannot be empty!"), `server_host` (default lowercase node.address), `server_port` (default node.port), `local_addr`, `local_port`, `mode`, `local_socks_address` (default "0.0.0.0"), `local_socks_port`, `local_socks_username`, `local_socks_password`, `local_http_address` (default "0.0.0.0"), `local_http_port`, `local_http_username`, `local_http_password`, `plugin_sh`.
IPv6 server_host → strip brackets.
Plugin: if node.plugin non-empty and ≠ "none": plugin_sh = var.plugin_sh or ""; plugin_file = plugin_sh if non-empty else node.plugin; plugin_bin = node.plugin.

SSR output:
```
{ server, server_port, local_address: local_addr, local_port, password, method, timeout, fast_open, reuse_port: true,
  protocol, protocol_param, obfs, obfs_param }
```
SS-Rust output (replaces):
```
{ servers: [{ address, port, method, password, timeout, plugin: plugin_file?, plugin_opts: node.plugin_opts (only if plugin_file) }],
  locals: [ {local_address: local_socks_address, local_port, mode:"tcp_and_udp"} if socks port,
            {protocol:"http", local_address: local_http_address, local_port} if http port ],
  fast_open }
```
Node options read: `address, port, password, method, timeout, tcp_fast_open, plugin, plugin_opts, type, protocol, protocol_param, obfs, obfs_param`.

After printing, if plugin_sh non-empty and plugin_bin set, write wrapper script `plugin_sh`:
```
#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin:$PATH
<plugin_bin> $@ &
echo $! > <plugin_sh with .sh→.pid>
wait
```
then `chmod +x <plugin_sh>`. (ssserver/sslocal invokes it as the plugin; pid file used by socks_auto_switch to kill.)
Call site (app.sh): `plugin_sh="${config_file%.json}_plugin.sh"`, only when actually running.

---

## 4. helper_dnsmasq.lua

CLI: `lua /usr/share/passwall2/helper_dnsmasq.lua <func> ['<json object of string vars>']` with func ∈ `stretch | restart | logic_restart | copy_instance | add_rule`. `var` defaults to `{}`.

`tinsert(list, val)`: append only if not already present (per-list dedupe set).

### backup_servers() (internal)
If `dhcp.@dnsmasq[0].server` list non-empty → set `passwall2.@global[0].dnsmasq_servers` = that list (UCI list), commit passwall2.

### restore_servers() (internal)
dns_table = dedupe(current dhcp server list + `passwall2.@global[0].dnsmasq_servers`); if backup existed → delete `dnsmasq_servers`, commit passwall2. If dns_table non-empty → set dhcp server list = dns_table, commit dhcp.

### stretch()
```
servers = dhcp.@dnsmasq[0].server ; noresolv = dhcp.@dnsmasq[0].noresolv
flag = any server entry without "/"
if not flag and noresolv=="1":
   delete dhcp.@dnsmasq[0].noresolv
   RESOLVFILE = "/tmp/resolv.conf.d/resolv.conf.auto"; if missing or size 0 → "/tmp/resolv.conf.auto"
   set dhcp.@dnsmasq[0].resolvfile = RESOLVFILE ; commit dhcp
```
(Ensures default dnsmasq has an upstream when passwall2 rewrites it.)

### restart(var)
`/etc/init.d/dnsmasq restart >/dev/null 2>&1`; if `var.LOG=="1"` → `api.log(0, "Restart dnsmasq service.")`.

### logic_restart(var)
```
if cache DEFAULT_DNS set:
   backup_servers()
   keep only dhcp server entries containing "/" (domain-specific); set + commit dhcp (only if list non-empty)
   /etc/init.d/dnsmasq restart
   restore_servers()
else: /etc/init.d/dnsmasq restart
LOG=="1" → log
```
Purpose: restart dnsmasq without generic upstream servers (passwall's own `server=` lines take effect), then restore UCI so config is unchanged on disk.

### copy_instance(var)
Vars: `LISTEN_PORT`, `TMP_DNSMASQ_PATH` (optional), `DNSMASQ_CONF`, `return`.
```
cfgid = `uci -q show dhcp.@dnsmasq[0] | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}'`   -- e.g. "cfg01411c"
conf_file = "/var/etc/dnsmasq.conf.<cfgid>"
wait up to 5 × 1s for conf_file to exist
if exists: for each line:
   filter if contains "passwall2" | "ubus" | "dhcp" | starts "server=" | starts "port=" | starts "conf-dir="
   for conf-dir=: if TMP_DNSMASQ_PATH: sh "cp -r <dir>/* <TMP_DNSMASQ_PATH>/ 2>/dev/null"
   un-filter if starts "address=" OR (starts "server=" and contains "/")
   keep unfiltered (dedup)
else: logger -t passwall2 'ERROR: dnsmasq config <conf_file> not found after 5s wait! DNS hijacking will fail.'
append "port=<LISTEN_PORT>"
hosts = CACHE_PATH/dhcp-hosts ; touch ; append "addn-hosts=<hosts>"
if TMP_DNSMASQ_PATH: rm -rf <TMP_DNSMASQ_PATH>/*passwall2*
if var.return=="1": return lines (Lua only)
append lines joined "\n" + "\n" to DNSMASQ_CONF
```
Note: a line containing e.g. "dhcp" and starting with `address=` is kept (un-filter overrides).

### add_rule(var)
Vars: `FLAG`, `TMP_DNSMASQ_PATH`, `DNSMASQ_CONF_FILE` (may be literal `"nil"`), `DEFAULT_DNS`, `LOCAL_DNS`, `TUN_DNS`, `NFTFLAG` ("1"=nftables), `NO_LOGIC_LOG` (unused). All must be strings (concatenated).
```
CACHE_DNS_PATH = CACHE_PATH/dnsmasq_<FLAG>      (/tmp/etc/passwall2_tmp/dnsmasq_<FLAG>)
CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"
nodes_address_md5 = `echo -n $(uci show passwall2 | grep '\.address') | md5sum` (trailing ws stripped; contains "  -")
new_text = TMP_DNSMASQ_PATH .. DNSMASQ_CONF_FILE .. DEFAULT_DNS .. LOCAL_DNS .. TUN_DNS .. nodes_address_md5 .. NFTFLAG
cache_text = last line of CACHE_TEXT_FILE
if differs: rm -rf CACHE_DNS_PATH*    (dir and .txt)
setflag_4 = NFTFLAG=="1" ? "4#inet#passwall2#" : "" ; setflag_6 = "6#inet#passwall2#" or ""
if CACHE_DNS_PATH missing:
   mkdir
   for each "nodes" section, for address and download_address (lowercased):
      skip "engage.cloudflareclient.com"; if valid hostname (not IP):
         dns[domain] += split(LOCAL_DNS, ",") (dedupe)
         ipsets[domain] += [setflag_4.."psw2_vps", setflag_6.."psw2_vps6"]
   if any domains:
      001-server.conf: for each domain, each dns: "server=/.<domain>/<dns>"
      ipset.conf: "<ipset|nftset>=/.<domain>/<set1>,<set2>"
        e.g. nft: "nftset=/.example.com/4#inet#passwall2#psw2_vps,6#inet#passwall2#psw2_vps6"
        e.g. iptables: "ipset=/.example.com/psw2_vps,psw2_vps6"
   append new_text to CACHE_TEXT_FILE
rm -rf TMP_DNSMASQ_PATH ; symlink TMP_DNSMASQ_PATH -> CACHE_DNS_PATH
if DNSMASQ_CONF_FILE != "nil":
   lines: "conf-dir=<TMP_DNSMASQ_PATH>"
   if TUN_DNS: for each comma item: "server=<item>"; then "all-servers", "no-poll", "no-resolv"
               if FLAG=="acl_default": set_cache_var("DEFAULT_DNS", DEFAULT_DNS)
   append to DNSMASQ_CONF_FILE
```
Domain iteration order is Lua `pairs` (unordered) — order in output files is not significant.
Call-site values (app.sh): `TUN_DNS="127.0.0.1#<dns_listen_port>"`, `LOCAL_DNS` = direct DNS in dnsmasq syntax (e.g. `223.5.5.5#53`), files `/tmp/etc/passwall2/acl/<flag>_dnsmasq.conf` and `<flag>_dnsmasq.d`.

---

## 5. haproxy.lua

Invocation: `lua /usr/share/passwall2/haproxy.lua -path /tmp/etc/passwall2/haproxy -conf config.cfg` (only when `@global_haproxy[0].balancing_enable`=="1"); then app.sh runs `haproxy -f <path>/<conf>`.

### UCI read
| Section | Option | Default | Meaning |
|---|---|---|---|
| `@global_haproxy[0]` | `health_check_type` | "tcp" | `tcp` or `script_logic` (external check via proxy) |
| | `health_check_inter` | "60" | seconds (leading digits parsed) |
| | `balancingStrategy` | "roundrobin" | haproxy `balance` |
| | `console_port` | – | stats listen port |
| | `bind_local` | "0" | "1" → bind 127.0.0.1 else 0.0.0.0 |
| | `console_user`, `console_password` | – | stats auth if both non-empty |
| | `health_probe_url` | `https://www.google.com/generate_204` | stored in cache `HAPROXY_PROBE_URL` (script_logic) |
| `haproxy_config` (sections) | `enabled` | | "1" to include |
| | `lbss` | | node section id OR literal `host:port`/`host#port` |
| | `haproxy_port` | | listen port (number>0) |
| | `lbweight` | | weight (string, inserted raw) |
| | `backup` | | "1" → backup server |
| | `export` | | interface name for `add_ip2route`, "0" = none |

nbthread = `cat /proc/cpuinfo | grep "processor" | wc -l`. DNS resolver = fixed `127.0.0.1` → `nameserver dns1 127.0.0.1:53`.

Logs: `HAProxy: `, `  - Console Port: <p>`, `  - Entrance <bind>:<port>`, `    - Node: <addr>:<port>, Weight: <w>`, `  - Discard one obviously invalid node.`

`mkdir <path>`; file opened in **append** mode.

### Generated file (exact skeleton)
```
global
	daemon
	log 127.0.0.1 local2
	maxconn 60000
	stats socket <path>/haproxy.sock
	nbthread <cpus>
	external-check
	insecure-fork-wanted
	spread-checks 20
	tune.max-checks-per-thread 5

defaults
	mode tcp
	log global
	option tcplog
	option dontlognull
	option abortonclose
	#option forwardfor except 127.0.0.0/8
	option redispatch
	retries 2
	timeout http-request 10s
	timeout queue 1m
	timeout connect 10s
	timeout client 1m
	timeout server 1m
	timeout http-keep-alive 10s
	timeout check 10s
	maxconn 3000

resolvers mydns
	resolve_retries 1
	timeout resolve 5s
	hold valid 600s
	nameserver dns1 127.0.0.1:53
```
(indentation is a TAB; template ends with `\n` after dns line.)

### Backend collection
For each enabled `haproxy_config` t:
```
node = uci_get_c(lbss)
hop = (type==script_logic and node) ? (node.hysteria_hop or node.hysteria2_hop) with ':'→'-' : nil
if node and node.address and (node.port or hop):
   remark = address:(port or hop); server_address=address; server_port=port or hop; origin_* = same
   if script_logic and node.type != "Socks":
       port = cache node_<nodeid>_socks_port, else:
          new_port = get_new_port()   -- "auto"
          sh '/usr/share/passwall2/app.sh run_socks "flag=<new_port> node=<nodeid> bind=127.0.0.1 socks_port=<new_port> config_file=<t.name>_<new_port>.json"> /dev/null'
          set cache node_<nodeid>_socks_port=new_port
       server_address="127.0.0.1"; server_port=port
else:
   (server_address, server_port) = get_ip_port_from(lbss):
       port = `echo -n <str> | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p'`
       ip   = shell: ${__host%%${__varport:+[:#]${__varport}*}}   (strip ":port"/"#port" suffix)
   remark = ip:port; origin = same
if server_address and server_port and listen_port>0: listens[listen_port] += t (with server_remark/address/port)
else log "Discard one obviously invalid node."
```
NOTE: with script_logic (non-Socks nodes) the HAProxy server entry is `127.0.0.1:<local socks port>` of a dedicated per-node socks instance started via app.sh run_socks; haproxy_check.sh probes through it. Preserve as-is.

Timing: `inter = max(20, leading int of health_check_inter or 60)`; `fastinter = max(10, min(15, floor(inter/2)))`; `downinter = ceil(inter*1.5)`; `inter_arg = "inter <inter>s fastinter <f>s downinter <d>s"`.

`server_endpoint(o)`: strip `[]`, wrap in `[]` if contains `:`, append `:<port>`.

Shared checks (script_logic only): count endpoints whose server_address is an IP across all listeners; endpoints with count>1 get one shared check server.

### Per listen port (ascending)
```

listen <port>
	bind <bind_address>:<port>
	mode tcp
	balance <balancingStrategy>
[script_logic:]
	option external-check
	external-check command "/usr/share/passwall2/haproxy_check.sh"
```
For each backend (in insertion order), counters M/B start at 1:
- remark = server_remark with `[`/`]` removed, prefixed `M<n>-` (non-backup) or `B<n>-` (backup=="1").
- check_arg = `check <inter_arg> rise 2 fall 2`, or if shared: `track passwall2_health_checks/check_<k>` (k assigned in first-seen order).
- line = TAB + trim(`server <remark> <endpoint> weight <lbweight> <"resolvers mydns" unless IP> <check_arg> <"backup" or "">`) — note internal double spaces may remain when resolvers/backup empty (only outer trim).
- if `export != "0"` → `. /usr/share/passwall2/utils.sh ; add_ip2route <origin_address> <export>` (note: nil `export` also triggers, with empty arg).

Shared backend (if any):
```

backend passwall2_health_checks
	mode tcp
	option external-check
	external-check command "/usr/share/passwall2/haproxy_check.sh"
	server check_<k> <endpoint> check <inter_arg> rise 2 fall 2
```
Console:
```

listen console
	bind 0.0.0.0:<console_port>
	mode http
	stats refresh 30s
	stats uri /
	stats admin if TRUE
	stats auth <user>:<password>      (or empty line content when unset)
```
Finally (script_logic): set cache `HAPROXY_PROBE_URL` = trimmed health_probe_url or default.

---

## 6. socks_auto_switch.sh

Invocation (app.sh start_socks): `/usr/share/passwall2/socks_auto_switch.sh <socks_section_id> > /dev/null 2>&1 &` when socks `enable_autoswitch`=="1". Sources utils.sh (`config_n_get`, `get_cache_var`, `get_new_port`, `log_i18n`, `i18n`, `lua_api`, `LOCK_PATH=/var/lock`, `TMP_PATH`, `CONFIG=passwall2`). `APP_FILE=/usr/share/passwall2/app.sh`.

### UCI read (socks section `<id>`)
| Option | Default | Meaning |
|---|---|---|
| `node` | – | main node |
| `port` | 0 | socks port (also used for liveness test) |
| `autoswitch_testing_time` | 30 | loop delay (sleep arg; seconds) |
| `autoswitch_connect_timeout` | 3 | curl connect timeout |
| `autoswitch_retry_num` | 1 | curl retries |
| `autoswitch_restore_switch` | 0 | "1" → prefer switching back to main node when healthy |
| `autoswitch_probe_url` | `https://www.google.com/generate_204` | probe |
| backup nodes | via `lua_api get_socks_backup_nodes("<id>")` (see §1.9) | |

### Functions
- `check_process`: while `busybox pgrep -af "passwall2/"` matches `app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua` → `sleep 6s`. (Wait out start/stop/subscription.)
- `test_url(url, try=1, timeout=2, extra, repeat)`:
  - detect once whether `/usr/bin/curl --help all` lists `--retry-all-errors`; if so prepend it to extra.
  - max_time=timeout+3; retry_max_time = max_time*(try+1)+try.
  - `/usr/bin/curl -skIL -o /dev/null <extra> --max-time <max_time> --connect-timeout <timeout> --retry <try> --retry-delay 1 --retry-max-time <rmt> -w "%{http_code}" "<url>"`; failure → `000`; 204 → 200.
  - if 200 and repeat=="1": sleep 3s, retest. Print status.
- `test_proxy`: status via `-x socks5h://127.0.0.1:<socks_port>` on probe_url → 0 if 200. Else test `https://www.baidu.com` directly: 200 → 1 (proxy broken, network ok). Else `ping -c 3 -W 1 223.5.5.5` success → 1 else 2 (no network).
- `test_node(node_id)`: subshell holding exclusive flock on `/var/lock/passwall2_socks_auto_switch_test.lock` (fd 8; serializes tests across instances):
  ```
  test_flag = "test_node_<id>_<node_id>"
  type = lowercase(config node type); empty → exit 1
  check_process
  port = get_new_port 48800 tcp,udp
  NO_REC_PROCESS=1 app.sh run_socks flag=<test_flag> node=<node_id> bind=127.0.0.1 socks_port=<port> config_file=<test_flag>.json
  sleep 2s
  status = test_url(probe_url, retry_num, connect_timeout, "-x socks5h://127.0.0.1:<port>", repeat=1)
  kill -9 $(head -n1 $TMP_PATH/<test_flag>_plugin.pid) if exists
  pgrep -af "$TMP_PATH/<test_flag>[._]" excluding socks_auto_switch.sh → kill -9
  rm -f $TMP_PATH/<test_flag>*.*
  exit 0 if status==200 else 1
  ```
  (fds 8/9 closed for children: `8>&- 9>&-`.)
- `try_switch_backup(b_nodes, now_node)`:
  ```
  if backup_node_num==1: b_nodes += " <main_node>"   (alternate)
  total = word count; tried=0
  while tried<total:
     new_node = node after now_node in b_nodes (cyclic; if now_node not found → first)
     role = new_node==main ? "main node" : "next backup node"
     log "Socks switch detection: Port [%s] try %s [%s:%s]." port role type remarks
     if test_node(new_node):
         check_process; log "...[%s:[%s]] normal, switch to this node!"
         if NO_REC_PROCESS=1 app.sh socks_node_switch flag=<id> new_node=<new_node> → log "node switch complete!"; return 0
         log "node switch failed, continue trying other nodes!"
     else log "...[%s:[%s]] abnormal."
     now_node=new_node; tried++
  log "...all nodes are unavailable or switching failed!"; return 1
  ```
- `test_auto_switch(b_nodes, now_node)`:
  ```
  now_node = now_node or cache var "<id>" (current node of this socks instance); missing → return 1
  status = test_proxy
  status==2 → log "Unable to connect to the network..."; return 2
  if restore_switch==1 and main_node and now_node != main_node:
     if test_node(main_node)==0: check_process; log "Primary node [..] is normal. Switch to the primary node!"
        socks_node_switch flag=<id> new_node=<main> → success: log complete; return 0
        else log "failed to restore the primary node!"; status=1
  status==0 → return 0
  log "[type:[remarks]] abnormal."   (of now_node)
  try_switch_backup(b_nodes, now_node)
  ```
- `start(id)`:
  ```
  exec 9> /var/lock/passwall2_socks_auto_switch_<id>.lock ; flock -n 9 || return 0   (single instance per socks id)
  read options; backup_node = get_socks_backup_nodes(id)
  if backup_node non-empty:
     num = word count; log "Socks switch detection: Port [%s] Number of backup nodes: %s"
     num==1 and main==backup → return
     num>1 and restore_switch!="1" and main not in list → append main to list
  else log count 0; return
  loop forever: check_process; test_auto_switch "$backup_node"; sleep <delay>
  ```
All log messages go through `log_i18n 0 <fmt> args...` (translated, appended to `/tmp/log/passwall2.log` with date).

---

## 7. app_acl.lua

Invocation: `ACL_JSON=$(lua /usr/share/passwall2/app_acl.lua)` during start (after start_haproxy, start_socks). Then app.sh iterates `$.node_order[*]` and reads `$TMP_ACL_PATH/acl_node_<flag>`; if `acl_node_acl_default` missing → ENABLED_DEFAULT_ACL=0; if node_order empty → both ACL flags 0.

### Data model
```
D (default ACL) = {
  flag="acl_default", remarks=translatef("Default"),
  tcp_no_redir_ports, udp_no_redir_ports, tcp_redir_ports, udp_redir_ports  ← @global_forwarding[0]
  node ← @global[0].node, local_proxy ← @global[0].localhost_proxy, client_proxy ← @global[0].client_proxy,
  use = "acl_default" (only if node valid)
}
L = { acl = [ ...enabled acl_rules..., D ], node = { <flag>: N }, node_order = [flags] }
```
Default node record N (if `@global[0].node` refers to a section of type `nodes`):
| field | source | default |
|---|---|---|
| config | full node section table | |
| enabled | `@global[0].enabled` | "0" |
| log | `@global[0].log_node` | "0" |
| loglevel | `@global[0].loglevel` | "warn" |
| socks_listen | `@global[0].node_socks_bind_local`=="0" ? "0.0.0.0" : "127.0.0.1" | 127.0.0.1 |
| socks_port | `@global[0].node_socks_port` | nil |
| redir_port | get_new_port() (auto) | |
| dns_port | get_new_port() (auto) | |
| direct_dns_query_strategy | `@global[0]` | "UseIP" |
| remote_dns_protocol | | "tcp" |
| remote_dns_detour | | "remote" |
| remote_dns | | "1.1.1.1:53" |
| remote_dns_doh | | "https://1.1.1.1/dns-query" |
| remote_dns_client_ip | | nil |
| remote_dns_query_strategy | | "UseIPv4" |
| remote_rewrite_ttl | | nil |
| remote_fakedns | | "0" |
Added to node_order if enabled=="1".

ACL rules (only if `@global[0].acl_enable`=="1"): each `acl_rule` section with `enabled`=="1" (acl_num++):
```
a = { flag=.name, remarks, interface, sources (UCI list), tcp_no_redir_ports, udp_no_redir_ports, tcp_redir_ports, udp_redir_ports,
      client_proxy="1", local_proxy="0", node=o.node }
mode=="0": tcp_no_redir_ports = udp_no_redir_ports = "1:65535"      (direct: no proxy)
mode=="2": U = L.node["acl_default"]   (crashes if default node invalid — edge)
           if U.enabled=="0": U.enabled="1"; D.local_proxy="0"; D.client_proxy="0"   (start the default node for this ACL only, but don't proxy the default scope)
           a.use = "acl_default"
           NOTE: U enabled late is NOT appended to node_order here → it's appended only if it was enabled at init. (Edge: default node then has no acl_node_ file; preserve.)
if both no_redir == "1:65535": a.node = nil
if a.node and section type nodes:
   N = { config, enabled="1", log=o.log or "0", loglevel=o.loglevel or "warn", redir_port=new, dns_port=new,
         direct_dns_query_strategy, remote_dns_protocol, remote_dns_detour, remote_dns, remote_dns_doh,
         remote_dns_client_ip, remote_dns_query_strategy, remote_rewrite_ttl, remote_fakedns  (all from o, no defaults) }
   L.node[flag]=N; a.use=flag; node_order += flag
L.acl += a
```
(Other modes, e.g. "1" or unset: use own node.) After loop, D appended last. `VAR.ENABLED_ACLS = acl_num>0 ? 1 : 0`.

UCI read: `@global_forwarding[0]`: tcp_no_redir_ports, udp_no_redir_ports, tcp_redir_ports, udp_redir_ports; `@global[0]`: node, localhost_proxy, client_proxy, enabled, log_node, loglevel, node_socks_bind_local, node_socks_port, direct_dns_query_strategy, remote_dns_protocol, remote_dns_detour, remote_dns, remote_dns_doh, remote_dns_client_ip, remote_dns_query_strategy, remote_rewrite_ttl, remote_fakedns, acl_enable; `acl_rule`: enabled, remarks, interface, sources, tcp/udp(_no)_redir_ports, node, mode, log, loglevel, direct_dns_query_strategy, remote_dns_protocol, remote_dns_detour, remote_dns, remote_dns_doh, remote_dns_client_ip, remote_dns_query_strategy, remote_rewrite_ttl, remote_fakedns.

### acl_app() — files written (all append mode)
For each ACL entry v (rules then default):
1. `mkdir -p /tmp/etc/passwall2/acl/<flag>`
2. `/tmp/etc/passwall2/acl/<flag>/var`: one line `key="value"` for every **string-valued** field of v (so `flag, remarks, interface (if string), tcp_no_redir_ports, ..., client_proxy, local_proxy, node, use`; tables like `sources` skipped; order = Lua pairs, unordered). If v.use: append `node="<node section id>"`, `node_remarks="<remarks>"`, `redir_port="<port>"`.
3. `/tmp/etc/passwall2/acl/<flag>/source_list`: newline-joined (no trailing newline) list derived from `sources`:
   - `A-B` IPv4 range → `iprange:A-B`
   - starts with `ipset:` → `ipset:` + w (yields `ipset:ipset:name` — quirk, consumers must handle; preserve)
   - IPv4 (incl. CIDR? only if datatypes.ip4addr accepts it — LuCI ip4addr accepts `a.b.c.d/nn`) → `ip:<w>`
   - MAC → `mac:<w>`
   - other (IPv6, invalid) → dropped
   - nothing → `any`
4. For each flag in node_order with enabled=="1": `/tmp/etc/passwall2/acl/acl_node_<flag>` = single line of space-separated `key="value"` pairs (only non-nil), in this order:
   `flag, node(.name), redir_port, socks_address(socks_listen), socks_port, dns_listen_port(dns_port), direct_dns_query_strategy, remote_dns_protocol, remote_dns_tcp_server, remote_dns_tcp_port, remote_dns_udp_server, remote_dns_udp_port, remote_dns_doh, remote_dns_client_ip, remote_dns_detour, remote_dns_query_strategy, remote_fakedns, remote_rewrite_ttl, config_file, loglevel, log_file`
   where `(dns_server, dns_port) = parseDNS(remote_dns)` (used for both tcp & udp), `config_file=/tmp/etc/passwall2/acl/<flag>.json`, `log_file = log=="0" ? "/dev/null" : /tmp/etc/passwall2/acl/<flag>.log`.
   Note: for ACL rules `remote_dns` may be nil → parseDNS(nil)=nil → tcp/udp server/port omitted.
   app.sh `eval`s this line and passes it to `run_xray`/`run_singbox`.
5. `set_cache_var(k, v)` for VAR: `ENABLED_ACLS` = 1/0.

### stdout
`jsonc.stringify(L, pretty)`: `{ "acl": [ {flag, remarks, ..., sources:[...]} ...], "node": { "<flag>": {config:{...full UCI node incl. ".name", ".type", ".anonymous", ".index"}, enabled, log, ..., redir_port:<number>, dns_port:<number>} }, "node_order": ["<flag>", ...] }`. Shell only consumes `$.node_order[*]`. (redir_port/dns_port are numbers in JSON.)

---

## 8. External commands inventory (this file set)
`uci -q get/set/delete/add_list/del_list/commit`, `uci -q show dhcp.@dnsmasq[0]`, `uci show passwall2`, `md5sum`, `sha256sum`, `mktemp`, `busybox nslookup [-v]`, `curl` (see args), `openssl s_client/x509`, `timeout`, `wg genkey/pubkey`, `xray wg`, `sing-box generate wg-keypair`, `<bin> version`, `df -k`, `du -k`, `unzip -o`, `tar -zxf`, `/bin/mv -f`, `/bin/rm -f/-rf`, `/bin/cp`, `busybox pgrep -af`, `/bin/busybox top -bn1`, `kill -9`, `xargs`, `opkg list-installed`, `apk list`, `command -v`, `type -t -p`, `/etc/init.d/passwall2 stop|restart`, `/etc/init.d/dnsmasq restart`, `/etc/init.d/<config> reload`, `nohup luci_update.sh`, `logger -t passwall2`, `ln -s`, `ssr-server`, `ssserver`, `xray run -c`, `sing-box run -c`, `app.sh run_socks|socks_node_switch`, `utils.sh add_ip2route/get_new_port/*_cache_var`, `ping -c 3 -W 1 223.5.5.5`, `flock`, `cat /proc/cpuinfo`.

## 9. Generated paths inventory
- `/tmp/log/passwall2.log`, `/tmp/log/passwall2_server.log`
- `/tmp/etc/passwall2/var` (cache vars)
- `/tmp/etc/passwall2_tmp/binver_<dev>_<ino>_<size>_<mtime>_<ctime>`, `update_<app>.json`, `passwall2_version`, `dhcp-hosts`, `dnsmasq_<FLAG>/{001-server.conf,ipset.conf}`, `dnsmasq_<FLAG>.txt`
- `/tmp/<app>_download.<task_id|XXXXXX>[1..5]`, `/tmp/<app>_extract.XXXXXX/`, `/tmp/md5.XXXXXX`
- `/tmp/passwall2_luci_update.<id>/{luci-app-passwall2.<ext>, luci-i18n-passwall2-<code>.<ext>, luci_update.sh}`, `/www/luci-static/resources/passwall2-update/<id>.json`
- `/tmp/etc/passwall2_server/{<id>.json,<id>.log,bin/<name>}`; firewall rules `passwall2_server_<id>`
- `/tmp/etc/passwall2/haproxy/{config.cfg,haproxy.sock}`
- `/tmp/etc/passwall2/acl/<flag>/{var,source_list}`, `acl/acl_node_<flag>`, `acl/<flag>.json`, `acl/<flag>.log`, `acl/<flag>_dnsmasq.conf`, `acl/<flag>_dnsmasq.d -> /tmp/etc/passwall2_tmp/dnsmasq_<flag>`
- `/var/lock/passwall2_socks_auto_switch_<id>.lock`, `/var/lock/passwall2_socks_auto_switch_test.lock`
- `/tmp/etc/passwall2/test_node_<id>_<node>*.*` (temporary), `<config>_plugin.sh/.pid`
- UCI writes: `passwall2.@global[0].auto_lang`, `passwall2.@global[0].dnsmasq_servers` (list, transient backup), `dhcp.@dnsmasq[0].{server,noresolv,resolvfile}`, `firewall.passwall2_server_<id>`.
