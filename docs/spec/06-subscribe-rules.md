# 06 — Subscription engine, Clash converter, Geo rule updater

Source files (upstream `luci-app-passwall2`):

| File | Lines | Role |
|---|---|---|
| `root/usr/share/passwall2/subscribe.lua` | 2351 | CLI: fetch subscriptions, parse share links, write `nodes` sections, re-point references, truncate subscription nodes, manual import |
| `root/usr/share/passwall2/clash_subconverter.lua` | 787 | Library (loaded by subscribe.lua via `loadfile(...)()`): converts a Clash YAML document into share-link lines; parses the `Subscription-Userinfo` header; extracts a node-domain DNS resolver from the Clash `dns:` block |
| `root/usr/share/passwall2/rule_update.lua` | 341 | CLI: download/verify/install `geoip.dat` and `geosite.dat` |

Helpers from `luasrc/passwall2/api.lua` that change behaviour are specified inline (§0), so this document stands on its own.

> **Not supported by the subscription parser:** `socks://`, `http(s)://`, `wireguard://`/`wg://`, `ssh://`, `hysteria://` with non-udp transport (from Clash), TUIC v4. Any other scheme produces the log line "`%s type node subscriptions are not currently supported, skip this node.`" and the line is skipped. The full list of supported URI schemes is: `ssr`, `vmess`, `ss`, `trojan`, `vless`, `hysteria`, `hysteria2`, `hy2`, `tuic`, `anytls`, `naive+https`, `naive+quic`, `snell`, plus the whole-document `ssd://` format. Scheme matching is **case-sensitive**.

---

## 0. Shared primitives (exact semantics; the Rust port must match them)

### 0.1 Paths / constants
- `LOCK_PREFIX = /var/lock/passwall2`, so the lock file is `/var/lock/passwall2_sub_rule.lock`.
- `LOG_FILE = /tmp/log/passwall2.log`
- `CACHE_PATH = /tmp/etc/passwall2_tmp`
- The version cache is `CACHE_PATH/passwall2_version`.
- `DIRECT_GID = 9912`. Direct-mode curl runs as this GID, which the firewall bypasses.

### 0.2 Logging `log(level, ...)`
Each call appends one line to `/tmp/log/passwall2.log`:
- level 0: `"%Y-%m-%d %H:%M:%S: " .. table.concat(args, " ")`
- level n ≥ 1: `"%Y-%m-%d %H:%M:%S: " .. ("  " * n) .. "- " .. concat(args," ")`

All messages go through i18n `translate`/`translatef`. The English msgids are quoted in this spec.

### 0.3 `base64Decode(text)` (lenient, canonical-checking)
```
if text not string -> return ""
enc = text with NULs removed, all control chars removed, '_'->'/', '-'->'+', trailing '='* stripped
if enc == "" -> return text
if enc !~ ^[A-Za-z0-9+/]*$ -> return text         # NOT base64 -> returns the input unchanged
if len(enc) % 4 == 1 -> return text
decoded = b64decode(enc padded with '=' to a multiple of 4); on failure -> return text
if b64encode(decoded) with trailing '=' stripped != enc -> return text   # canonical check
return decoded with NUL bytes removed
```
Several parsers depend on this function giving back its input unchanged when that input is not base64. One example is the `ss://` plaintext userinfo.

### 0.4 `base64Encode(s)`
Standard alphabet with `=` padding (nixio). Returns nil if `s` is nil.

### 0.5 `UrlEncode(s)`
If `s` is not a string, returns `""`. Otherwise every byte outside `[A-Za-z0-9-_.~]` becomes `%XX` (uppercase hex).

### 0.6 `UrlDecode(s)`
If `s` is not a string, returns `""` (so nil becomes `""`). Otherwise `+` becomes space and `%XX` becomes a byte.

### 0.7 `split(full, sep)`
`sep` is a **Lua pattern**. The callers use `"%?"`, `"&"`, `"@"`, `":"`, `"://"` and `"\n"`.
- NUL bytes are removed first.
- Splits on every occurrence.
- Empty middle pieces are kept. The **trailing** piece is appended only if it is non-empty.
- `split(nil)` returns `{}`.

Consequence: in `split(node, "://")`, `dat[2]` is only the text between the first and the second `://`.

### 0.8 `trim(s)`
Strips bytes ≤ 0x20 from both ends. A non-string becomes `""`.

### 0.9 Query-string parsing (the same loop appears in every parser)
```
for piece in split(query, "&"):
    s = index of first '=' in piece (plain find)
    if s and s > 1: params[piece[0:s-1]] = VALUE(piece[s+1:])
```
`VALUE` is `UrlDecode` except for `ssr` (raw value, base64-decoded later) and `hysteria` (raw value, **never** URL-decoded). The key is lowercased for `hysteria2`/`hy2`, `tuic` and `anytls`. For `snell` the key is URL-decoded and then lowercased. When a key repeats, the last value wins.

### 0.10 `parse_host_port(host_port, default_port)`
```
authority = (host_port or "") with "/.*$" removed
if authority ~ ^\[([^\]]+)\]:(.*)$  -> address, port
elif authority ~ ^\[([^\]]+)\]$     -> address, port=nil
elif authority ~ ^([^:]+):(.*)$     -> address, port        # first ':' only
address = address or authority
port = (port and port ~= "") and port or default_port
```
IPv6 addresses are returned without brackets.

### 0.11 Datatypes
- `datatypes.hostname(v)`: `#v < 254` and (`v ~ ^[a-zA-Z_]+$` or (`v ~ ^[a-zA-Z0-9_][a-zA-Z0-9_%-%.]*[a-zA-Z0-9]$` and v contains a char other than digit/dot)). This is the LuCI CBI datatype.
- `api.is_ip(v)`: trim, lowercase, strip `[...]` brackets, then `ip4addr or ip6addr`.

### 0.12 `uci_set(section, option, value)` (in config `passwall2`)
- number: converted to a string.
- `#value == 0` (empty string or empty table): the **option is deleted**.
- table: `set_list`.
- otherwise: `set`.

Never call it with nil. The Lua code would crash, and every caller avoids nil.

`uci_save(true)`: on modern LuCI, `uci commit passwall2` (`uci -q commit passwall2`). On an old LuCI: `save` then `commit`. In Rust this means writing the staged changes and committing them.

### 0.13 `gen_random_char(n=8)`
`head /dev/urandom | tr -dc A-Za-z0-9 | head -c n`. New node section names are 8 random alphanumerics.

### 0.14 `md5_string(s)`
Writes `s` to `mktemp /tmp/md5.XXXXXX`, runs `md5sum`, returns the 32-character hex digest, and deletes the file. Returns `""` on failure.

### 0.15 `api.get_core(field, candidates)`
Reads `@global_subscribe[0].<field>`. If the value is set and equals the name of an *available* candidate, it is returned. Otherwise the first available candidate is returned (nil if none is available).

### 0.16 Binary detection
- `has_ss_rust = sslocal` found in `/bin` or `/usr/bin` or on PATH.
- `has_ssr = ssr-local && ssr-redir` found.
- `has_singbox` / `has_xray` = the configured app path (`@global_app[0].<name>_file`, default path) exists and is executable (`finded_com`).

### 0.17 `api.get_version()`
1. Reads `CACHE_PATH/passwall2_version`.
2. Falls back to `opkg list-installed luci-app-passwall2 | awk '{print $3}'`.
3. Falls back to `apk list luci-app-passwall2 | awk '/installed/{print $1}' | cut -d- -f4-`.
4. Caches the result in the file.
5. Finally rewrites `-rN` to `-N`.

### 0.18 curl wrappers (api)
- `curl_base(url, file, args, gid?)`: runs `curl <args joined by " "> [-o <file>] "<url>"`. stderr is merged into stdout (`exec_call`, `2>&1`) and the output is trimmed. Returns `(exit_code, output)`. With a `gid`, it forks, calls `setgid(gid)`, then runs `/bin/sh -c cmd`.
- `curl_proxy`: if the cache var `ACL_acl_default_node_socks_port` is set, appends `-x socks5h://127.0.0.1:<port>` and calls `curl_base`. Otherwise returns `(nil, nil)`, which callers treat as a failure.
- `curl_direct`:
  - If neither cache var `ENABLED_DEFAULT_ACL` nor `ENABLED_ACLS` equals `"1"`, it is a plain `curl_base`.
  - Otherwise it appends `--noproxy '*'`.
  - If the URL host is a domain (not an IP; default port 443 for https, 80 for http), it resolves the host with `busybox nslookup <domain> <dns>` running as GID 9912. The DNS server is the cache var `DIRECT_DNS` or `223.5.5.5`, tried in order as `host:port`, `host#port`, then `223.5.5.5`. On BusyBox < 1.35.0 the first two are swapped. The result is added as `--resolve 'domain:port:ip1,ip2'`, with IPv6 addresses bracketed. If resolution fails it returns `(6, err)`.
  - It runs `curl_base(..., gid=9912)`.
- `curl_auto`: if `@global[0].localhost_proxy` (default `"1"`) is `"1"`, it uses `curl_base` (transparent proxying of the router itself handles it). Otherwise it tries `curl_proxy` and falls back to `curl_direct`.
- Cache vars are read with `. /usr/share/passwall2/utils.sh ; echo -n $(get_cache_var "KEY")`. See the utils/app spec.

---

## 1. `subscribe.lua`

### 1.1 Command line
| Invocation | Who calls it | Meaning |
|---|---|---|
| `lua subscribe.lua start <cfgids\|all> [manual\|cron]` | LuCI "Manual subscription" (`start <section> manual`, `start all manual`). Cron (app.sh, `tasks.sh`): `start <cfgid,cfgid,...> cron` | Fetch and parse the listed `subscribe_list` sections (comma-separated section names) or all of them |
| `lua subscribe.lua add <group>` | LuCI link import. Links are uploaded in chunks to `/tmp/links.conf` | Import links manually (`add_mode=1`) into group `<group>` |
| `lua subscribe.lua truncate [remark]` | LuCI "delete subscription nodes" (remark shell-quoted) or "delete all" (no arg) | Delete the subscription nodes of one group (case-insensitive) or of all groups, and fix references |
| no `arg[1]` | — | `exit 0` immediately, before taking the lock |

### 1.2 Lock and startup sequence (runs for every mode)
1. Open `/var/lock/passwall2_sub_rule.lock` with flags `rdwr|creat`. If that fails, log level 0 "`Unable to open the subscription/rule update lock. Exiting.`" and `exit 1`.
2. Try a non-blocking `lockf(F_TLOCK)`. If the lock is busy:
   - If `arg[3] ~= "cron"`: log level 0 "`A subscription or rule update is already running. Skipping this request.`" and `exit 0`.
   - Otherwise, read 1 byte. `s` maps to "Subscription", `r` to "Rule Update", anything else to "Subscription/Rule Update". Seek to 0. Log level 0 "`[%s] is running; [%s] is queued and waiting...`" (running, "Subscription"). Then take a blocking `lockf(F_LOCK)`. If that fails, log "`Unable to acquire the update lock. Scheduled task failed.`" and `exit 1`.
3. Write the byte `s` at offset 0, then seek to 0. rule_update writes `r`.
4. `uci revert passwall2`. **This discards any staged, uncommitted changes** before work starts.
5. Detect binaries (§0.16).
6. Compute the defaults:
   - `DEFAULT_ALLOWINSECURE = true`
   - `DEFAULT_FILTER_KEYWORD = {mode = @global_subscribe[0].filter_keyword_mode or "0", discard_list = split_filter_keywords(@global_subscribe[0].filter_discard_list), keep_list = split_filter_keywords(@global_subscribe[0].filter_keep_list)}`
   - `DEFAULT_SS_TYPE = get_core("ss_type", [ss-rust→"shadowsocks-rust", singbox→"sing-box", xray→"xray"])`
   - `DEFAULT_TROJAN_TYPE = get_core("trojan_type", [sing-box, xray])`
   - `DEFAULT_VMESS_TYPE = get_core("vmess_type", [xray, sing-box])`
   - `DEFAULT_VLESS_TYPE = get_core("vless_type", [xray, sing-box])`
   - `DEFAULT_HYSTERIA2_TYPE = get_core("hysteria2_type", [sing-box, xray])`
   - `core_has = {xray=has_xray, "sing-box"=has_singbox, "shadowsocks-rust"=has_ss_rust}`
7. `nodes_table` = `api.get_valid_nodes()` filtered to `node_type == "normal"`. This snapshot is taken **at startup** and is used as the fallback node. Its order: nodes with an empty/absent `group` come first, then grouped nodes, each in UCI order. A node counts as "normal" when it has `type` and `remarks`, has `port` (or `hysteria_hop`, or `hysteria2_hop`) and `address` (or `protocol==hysteria2` with `hysteria2_realms`), its address is an IP or hostname, and its protocol is not one of `_balancing`, `_shunt`, `_iface`, `_urltest`.
8. Build `CONFIG` (§1.3). This happens in every mode, including add and truncate.
9. Dispatch on `arg[1]` (§1.12).
10. Close the lock. If `restart_required` (set only by `start`), run `/etc/init.d/passwall2 restart[ cron] > /dev/null 2>&1 &`. The ` cron` suffix is added when `arg[3]=="cron"`.

### 1.3 `CONFIG`: references to nodes that must be re-pointed after nodes are recreated
Each entry is either a *single* entry with `{log, id?, remarks, currentNode, set(o, server), delete?(o)}` or a *list* entry with `{remarks, currentNodes = [child...], newNodes = [], set(o, newNodes?)}`. Each child has `{log, node?, remarks, currentNode, set(o=parent, server)}`, and a child's `set` appends `server` to `parent.newNodes` when the server is not nil and not `"nil"`.

`currentNode` is the full UCI section table (`uci_get(id)` → all options plus `.name` and `.type`). It is nil when the referenced section does not exist.

Entries are built in this order:

1. **Global node**
   - `currentNode = uci_get(@global[0].node)`
   - `set`: `@global[0].node = server`. An empty string deletes the option (§0.12).
2. **Each `socks` section** (counter i=1..):
   - Single entry `"Socks node list [i]"`, using option `node`. `set(server)`: if the server is empty or nil and `#nodes_table > 0`, use `nodes_table[1][".name"]`. Then `uci_set(socks, "node", server)`.
   - If `autoswitch_backup_node` (list) is non-empty: a list entry `"Socks node list [i] Backup node list"`. It gets one child per id whose section `.type == "nodes"`; ids pointing to non-nodes are dropped. The list `set` writes `autoswitch_backup_node = newNodes or {}`, and an empty list deletes the option.
3. **Each `haproxy_config` section** (option `lbss`):
   - `set`: only when the current `lbss` is **not** `IPv4:port`. The check is `^([%d%.]+):(%d+)$`, IPv4 valid, port ≤ 65535. In that case set `lbss = server`.
   - `delete`: under the same condition, **delete the whole haproxy_config section**.
4. **Each `acl_rule` section** (option `node`): `set` writes `node = server`.
5. **Each `nodes` section:**
   - `protocol == "_shunt"`: build the rule keys.
     - For every `shunt_rules` section that has `.name` and `remarks`, add the keys `<name>` and `<name>_proxy_tag` (remarks + " Preproxy").
     - Then add `default_node` and `default_proxy_tag`.
     - For each key whose option value on this shunt node is set and refers to a section of type `nodes`, add a single entry with `log=false` and remarks `"Shunt [%s] node"`. Its `set(server)` writes `uci_set(shunt_id, key, server or "")`.
   - `protocol == "_balancing"`:
     - A list entry `"Xray Load Balancing node [<id>] list"` with children for every `balancing_node` id. A child whose section is of type `socks` gets `currentNode = {Socks = id}` (kept verbatim later). The list `set` writes `balancing_node`.
     - If `fallback_node` points to a `nodes` section: a single entry. `set` writes `fallback_node = server`. `delete` deletes the `fallback_node` option.
   - `protocol == "_urltest"`: the same as the balancing list, with option `urltest_node` and remarks `"Sing-Box URLTest node [%s] list"`. There is no fallback entry.
   - otherwise:
     - If `preproxy_node` points to a `nodes` section: a single entry (`set` writes preproxy_node; `delete` deletes the option).
     - If `to_node` points to a `nodes` section: a single entry (`set` writes to_node; `delete` deletes the option).

**Post-filter**, run immediately:
- List entries: drop children whose `currentNode == nil`. This leaves holes in the array. The Rust port should compact the array but keep the order.
- Single entries whose `currentNode == nil`: call `delete()` if it exists, then remove the entry. In practice this means:
  - a haproxy_config whose `lbss` points to a missing node and is not `ip:port` **gets deleted**;
  - a global node / socks / acl entry pointing to nothing is simply dropped.

These deletions are staged in the cursor and committed only if the run later commits.

### 1.4 Keyword filter
```
split_filter_keywords(list):            # list = UCI list or string
  for row in list: for kw in row split by '|' (non-empty pieces, spaces preserved): add if not seen
prepare_keyword_filter(sub_cfg):
  if sub_cfg.filter_keyword_mode in {"0","1","2","3","4"}:
      return {mode, split(sub_cfg.filter_discard_list), split(sub_cfg.filter_keep_list)}
  return DEFAULT_FILTER_KEYWORD          # "5" / unset => inherit global
match(value, kws) = any kw is a plain, case-sensitive substring of value
is_filter_keyword(f, remarks):          # true => discard
  "1": match(discard)
  "2": not match(keep)
  "3": match(discard) and not match(keep)
  "4": match(discard) or not match(keep)
  else false
```
The filter is applied only when `add_mode == "2"` (subscriptions).

### 1.5 Subscription info taken from node remarks: `get_subscribe_info(cfgid, remarks)`
This only runs when `add_mode=="2"` and the subscription has no header-derived info. It is called for **every** parsed node, including nodes that are later discarded.
```
v = remarks with all whitespace removed
expired_date = last match among patterns (applied in order, later wins):
   "套餐到期：(.+)", "过期时间：(.+)", "有效期至：(.+)", "到期时间：(.+)", "截止日期：(.+)"
rem_traffic = last match among: "剩余流量：(.+)", "流量剩余：(.+)", "可用流量：(.+)", "套餐剩余：(.+)"
subscribe_info[cfgid] ||= {expired_date="", rem_traffic=""}
overwrite each field only if matched
```
The colon in these patterns is the full-width `：` (U+FF1A). `(.+)` captures to the end of the string.

### 1.6 `processData(szType, content, add_mode, group, sub_cfg)`: link → node table

**Per-subscription overrides** (when `sub_cfg` is present):
- `sub_allowinsecure = true` unless `sub_cfg.allowInsecure` is set and `~= "1"`, in which case it is nil (false).
- For each of `ss_type`, `trojan_type`, `vmess_type`, `vless_type`, `hysteria2_type`: if the value is not `"global"` and `core_has[value]`, use it. Otherwise use the DEFAULT_*. The default value is `"global"`.
- `sub_hy_up_mbps = sub_cfg.hysteria_up_mbps`, `sub_hy_down_mbps = sub_cfg.hysteria_down_mbps`.

**Initial result:** `{timeout=60, add_mode=add_mode, group=group}`. These become UCI options `timeout="60"`, `add_mode`, `group`.

**`allowInsecure` resolution `INSECURE(x)`**, used by many parsers:
`x == "1" or x == "0" ? x : (sub_allowinsecure ? "1" : "0")`, written to `tls_allowInsecure`. Note that with no `sub_cfg` (the `add` mode) the default is `"1"`.

**Common transport normalisation `NET(t)`**, used by vmess, ss (when `type` is given), trojan and vless:
```
t = lower(t)
if core=="sing-box" and t=="raw": t="tcp"
elif core=="Xray" and t=="tcp": t="raw"
if t in {"h2","http"}: t="http"; transport = (core=="Xray") ? "xhttp" : "http"
else transport = t
```

**Common sing-box WS early data `WS_ED(path)`**, used by vmess, ss, trojan and vless when the core is sing-box and a path is present:
- Split the path at the first `?`. vmess uses the separator literal `"?"`, which as a Lua pattern means "optional any". In effect it behaves like `%?` for typical paths, but implement the split at a literal `?`.
- Parse `k=v&...` (split on `=`; `t[1]`, `t[2]`).
- If `ed` is numeric:
  - `ws_path` = the part before `?`
  - `ws_enableEarlyData = "1"`
  - `ws_maxEarlyData = tonumber(ed)`
  - `ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"`

**Common transport field mapping `TRANSPORT(params)`.** Used by ss (non-SS-Rust), trojan and vless. The source field names are the URL query keys.

| condition (after NET) | UCI options written |
|---|---|
| `ws` | `ws_host=host`, `ws_path=path`, plus WS_ED |
| `http`, core sing-box | `transport="http"`, `http_host={host}` (a list, only if host is non-empty), `http_path=path` |
| `http`, core Xray | `transport="xhttp"`, `xhttp_mode="stream-one"`, `xhttp_host=host`, `xhttp_path=path` |
| `raw` or `tcp` | `tcp_guise=headerType or "none"`, `tcp_guise_http_host={host}` (if non-empty), `tcp_guise_http_path={path}` (if non-empty) |
| `kcp` / `mkcp` | `transport="mkcp"`, `mkcp_guise=headerType or "none"`, `mkcp_seed=seed` |
| `quic` | `quic_guise=headerType or "none"`, `quic_key=key`, `quic_security=quicSecurity or "none"` |
| `grpc` | `grpc_serviceName = serviceName or path` (serviceName wins), `grpc_mode = mode or "gun"` |
| `xhttp` (vless: also `splithttp`) | ss/vless: `xhttp_host`, `xhttp_path`, `xhttp_mode = mode or "auto"`, `use_xhttp_extra="1"` (if extra is non-empty), `xhttp_extra = base64(extra)`, `download_address` = JSON(extra).`extra.downloadSettings.address` or `.downloadSettings.address`, non-empty, with a leading `[` and trailing `]` stripped. **Trojan:** only `xhttp_host`, `xhttp_path` |
| `httpupgrade` (trojan, vless; not ss) | `httpupgrade_host=host`, `httpupgrade_path=path` |

The `.transport` option is the NET value: for example `ws`, `raw`, `tcp`, `grpc`, `quic`, `mkcp` (after rewrite), `xhttp`, `http`, `httpupgrade`, or `splithttp`. Note that `splithttp` is stored verbatim for vless.

**Finalmask (`fm`)**, common to vmess/ss/trojan/vless/hysteria2: if `fm` is non-empty, `use_finalmask="1"` and `finalmask=base64(fm)`. For vmess, `fm` is first URL-decoded.

**sing-box rejection rule** (vmess/trojan/vless): if the core is sing-box and the transport is `mkcp` or `xhttp`, log "`Skip node: %s. Because Sing-Box does not support the %s protocol's %s transmission method, Xray needs to be used instead.`" and return nil.

**Core-incompatibility skip message:** "`Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.`" (log level 2).

**Fallback remarks** (applied at the very end for all types): if remarks are empty or nil, use `address .. ":" .. port` when both are known, else `"NULL"`. A `"NULL"` node is later discarded.

#### 1.6.1 `ssr` (content = base64-**decoded** body)
Format: `host:port:protocol:method:obfs:base64(pass)/?obfsparam=b64&protoparam=b64&remarks=b64&group=b64`
- Requires `has_ssr`, else skip with ("SSR", "shadowsocksr-libev").
- `type="SSR"`
- `dat = split(content with "/?" replaced by "?", "%?")`; `hostInfo = split(dat[1], ":")`. Index from the end: `n=#hostInfo`.
- `address`: if `dat[1]` contains `[...]`, the bracket contents. Otherwise `hostInfo[n-5]`.
- `port=hostInfo[n-4]`, `protocol=hostInfo[n-3]`, `method=hostInfo[n-2]`, `obfs=hostInfo[n-1]`, `password=base64Decode(hostInfo[n])`
- Query values are not URL-decoded:
  - `obfs_param=base64Decode(obfsparam)`
  - `protocol_param=base64Decode(protoparam)`
  - `remarks=base64Decode(remarks)`
  - A missing value decodes to `""`, which means the option is not written. `group` is ignored.

#### 1.6.2 `vmess` (content = base64-**decoded** body)
- Core: `sub_vmess_type=="sing-box" && has_singbox` → `type="sing-box"`. `=="xray" && has_xray` → `type="Xray"`. Otherwise skip.
- `info = jsonParse(content)`. If that is not JSON, the legacy Shadowrocket form applies:
  - Only if the content contains `?`; otherwise log "`Skipping %s node. This node URI format cannot be parsed.`" and return nil.
  - Format: `base64(security:uuid@host:port)?params`
  - Split on `?` (after replacing `/?` with `?`). `sp = split(base64Decode(part1), "@")`, `id = split(sp[1], ":")`.
  - `security = (#id>1 and id[1]~="") ? id[1] : "auto"`; `id = id[last]`
  - `add, port = parse_host_port(sp[2], "443")`
  - Params (URL-decoded):
    - `ps = remark or remarks`
    - `net = obfs=="websocket" ? "ws" : (obfs or "tcp")`
    - `path`
    - `aid = alterId or "0"`
    - `tls`
    - `sni = peer`
    - `tfo`
    - `obfsParam`: if it is JSON, `type = .header` and `host = .Host`; otherwise `host = obfsParam`.
    - `allowinsecure = allowInsecure`
- Mapping from JSON fields (standard v2rayN `v=2` object):
  - `address=add`, `port=port`, `protocol="vmess"`, `alter_id=aid`, `uuid=id`, `remarks=ps`
  - `path`: URL-decoded if non-empty, else nil
  - `net`: default `"tcp"`, lowercased, then the raw/tcp swap. `h2`/`http` → `net="http"`, `transport = Xray ? "xhttp" : "http"`; otherwise `transport = net`.
  - `ws`: `ws_host=host`, `ws_path=path`, plus WS_ED for sing-box
  - `http`, Xray: `xhttp_mode="stream-one"`, `xhttp_host=host`, `xhttp_path=path`. Otherwise `http_host={host}` (if non-empty) and `http_path=path`.
  - `raw`/`tcp`: if `type` is set and not `"http"`, it becomes `"none"`. `tcp_guise=type` (may be nil). `tcp_guise_http_host={host}`, `tcp_guise_http_path={path}` (each only if non-empty).
  - `kcp`/`mkcp`: `net="mkcp"`, `mkcp_guise=type`, `mkcp_seed=seed`. **Upstream quirk:** `transport` stays `"kcp"` when the source said `kcp`, because the transport was assigned before the rename.
  - `quic`: `quic_guise=type`, `quic_key=key`, `quic_security=info.securty`. The field name is misspelled upstream, so this is effectively always nil.
  - `grpc`: `grpc_serviceName=path`
  - `xhttp`/`splithttp`: `xhttp_host`, `xhttp_path`, `xhttp_mode = params.mode or "auto"`, `xhttp_extra = params.extra`, `download_address` from the extra JSON. **Upstream bug:** `params` is not in scope here (nil global), so this branch raises a Lua error and every vmess xhttp/splithttp link ends up "Parsing error, skip this node". Recommended for Rust: read `mode`/`extra` from the JSON object (`info.mode`, `info.extra`) and store `xhttp_extra` raw, as upstream intended. Alternatively, skip such links to stay bug-compatible. Note that this deviation is documented.
  - `httpupgrade`: `httpupgrade_host`, `httpupgrade_path`
  - `security = info.security or info.scy or "auto"`
  - TLS when `tls == "tls"` or `"1"`:
    - `tls="1"`, `alpn=alpn`
    - if `fp` is non-empty: `utls="1"`, `fingerprint=fp`
    - `tls_serverName = sni (if non-empty) or host`
    - `tls_pinSHA256=pcs`, `tls_CertByName=vcn`
    - `tls_allowInsecure=INSECURE(allowinsecure or allowInsecure or insecure)`
  - No TLS: `tls="0"`
  - `ech` non-empty: `ech="1"`, `ech_config=ech`. This applies regardless of TLS.
  - `tcp_fast_open=tfo`
  - finalmask from `fm` (URL-decoded first)
  - Then the sing-box mkcp/xhttp rejection.

#### 1.6.3 `ss` (content = text after `ss://`; `&amp;` already fixed)
Examples handled:
- SIP002 `ss://b64(method:pass)@host:port[/]?plugin=...#tag`
- Plain `ss://method:pass@host:port`
- Whole-base64 `ss://b64(method:pass@host:port)#tag`
- v2rayN-extended `?type=ws&path=...&security=tls...`

Steps:
1. `set_ss_implementation(sub_ss_type)`:
   - `shadowsocks-rust`+has → `type="SS-Rust"`
   - `xray`+has → `type="Xray"`, `protocol="shadowsocks"`, `transport="raw"`
   - `sing-box`+has → `type="sing-box"`, `protocol="shadowsocks"`
   - otherwise skip ("SS","SS")
2. `remarks = UrlDecode(text after first '#')`. `info` = the text before `#`, with `/?` replaced by `?`.
3. If `info` contains `?`, parse params from the part after the first `?` (URL-decoded values).
   - **plugin**: `plugin_info=params.plugin`. If it contains `;`: `plugin` = the text before it and `plugin_opts` = the text after it, with these rewrites:
     - `^password=` → `passwd=`
     - `;password=` → `;passwd=`
     - `^version=([123])` → `v%1=1`
     - `;version=([123])` → `;v%1=1`

     Otherwise `plugin = plugin_info`.
   - `plugin == "simple-obfs"` → `"obfs-local"`.
   - `info` = the part before `?`.
4. `hostInfo = split(base64Decode(UrlDecode(info)), "@")`. If it is non-empty:
   - `address, port = parse_host_port(hostInfo[last])`. There is **no default port**.
   - userinfo:
     - if `#hostInfo > 2`: `hostInfo[1..n-1]` joined with `@`, not decoded
     - otherwise `base64Decode(hostInfo[1])`
   - If userinfo contains `:`: `method` = before the first `:`, `password` = after it. Otherwise `password = hostInfo[1]` (raw) and `method = nil`.
   - `method = lower(method or "none")`. `chacha20-poly1305` → `chacha20-ietf-poly1305`. `xchacha20-poly1305` → `xchacha20-ietf-poly1305`.
   - Set `method=ss_method=method`, `password`, `tcp_fast_open=tfo`, finalmask(fm).
   - **Core upgrade:**
     - `need_upgrade = type∉{Xray,sing-box} and params.type and params.type~="tcp" and params.headerType and params.headerType~="none"`. All of these must hold, headerType included.
     - If `has_xray and (need_upgrade or params.type=="xhttp")`: `type="Xray"`, `protocol="shadowsocks"`.
     - Else if `has_singbox and need_upgrade`: `type="sing-box"`, `protocol="shadowsocks"`.
   - **Plugin handling** (if `plugin` is set):
     - Xray:
       - If the plugin is not `obfs-local`: `error_msg="Xray unsupport SS <plugin> plugin."`
       - Otherwise:
         - `obfs = match "obfs=([^;]+)"`, `obfs_host = match "obfs%-host=([^;]+)"`. If either is empty: `error_msg = "SS obfs-local Plugin options Incomplete."`.
         - `obfs=="http"`: `transport="raw"`, `tcp_guise="http"`, `tcp_guise_http_host={obfs_host}`, `tcp_guise_http_path={"/"}`
         - `obfs=="tls"`: `tls="1"`, `tls_serverName=obfs_host`, `tls_allowInsecure="1"`
         - Clear `plugin` and `plugin_opts`.
     - sing-box:
       - Only `obfs-local`, `v2ray-plugin` and `shadow-tls` are accepted; anything else sets `error_msg "Sing-Box unsupport SS %s plugin."`.
       - For accepted plugins, `plugin_enabled="1"`.
       - For `shadow-tls`, iterate the `;` items `k=v`:
         - `host` → `shadowtls_serverName`
         - `passwd` → `shadowtls_password`
         - key `v1|v2|v3` → `shadowtls_version = "1"|"2"|"3"`

         Then set `shadowtls="1"`, `plugin_opts=nil`, `plugin_enabled=nil`. `plugin` stays `"shadow-tls"`.
     - SS-Rust: `plugin_enabled="1"`
   - **If `params.type` is present:**
     - NET.
     - If the type is not SS-Rust: TRANSPORT (no httpupgrade). xhttp with a non-Xray core sets `error_msg "Please replace Xray to support xhttp transmission method."`. Then:
       - `tls="0"`
       - if `security ∈ {tls, reality}`:
         - `tls="1"`, `tls_serverName = sni (if non-empty) or host`, `alpn`
         - `fp` → `utls="1"`, `fingerprint`
         - `ech` → `ech="1"`, `ech_config`
         - `tls_pinSHA256=pcs`, `tls_CertByName=vcn`
         - reality: `reality="1"`, `reality_publicKey=pbk`, `reality_shortId=sid`, `reality_spiderX=spx`, `use_mldsa65Verify="1"` (if `pqv` is non-empty), `reality_mldsa65Verify=pqv`
       - `tls_allowInsecure = INSECURE(allowinsecure|allowInsecure|insecure)`. This is always written in this branch.
       - `uot = params.udp`
     - If the type is SS-Rust: `error_msg = "Please replace Xray or Sing-Box to support more transmission methods in Shadowsocks."`. **This applies even for `type=tcp`.** An SS-Rust node with any `type=` parameter is discarded.
   - **`params["shadow-tls"]`** (base64 JSON `{version,password,host,fingerprint?...}`):
     - If the type is not sing-box and not SS-Rust: `error_msg = sub_ss_type .. " unsupport shadow-tls plugin."`
     - `parseShadowTLSParams(b64)`: decode the JSON. If decoding fails, return `""`. Otherwise build the opts string: `v<version>=1`, then `passwd=<password>`, then the other `k=v` pairs (unordered), joined with `;`.
     - SS-Rust: `plugin_enabled="1"`, `plugin="shadow-tls"`, `plugin_opts=<opts string>`
     - sing-box: if the JSON is non-empty:
       - `shadowtls="1"`, `shadowtls_version = version or "1"`, `shadowtls_password=password`, `shadowtls_serverName=host`
       - if `fingerprint` is present: `shadowtls_utls="1"`, `shadowtls_fingerprint=fingerprint`

#### 1.6.4 `trojan`
- Core: sing-box or Xray per `sub_trojan_type`. `protocol="trojan"`.
- `remarks` = UrlDecode of the text after `#`.
- The rest applies only if the content contains `@`. `Info = split(content,"@")`. A password containing `@` therefore breaks parsing: only `Info[1]` and `Info[2]` are used.
- `password = UrlDecode(Info[1])`. `Info[2]` has `/?` replaced by `?` and is split on `?`. `address, port = parse_host_port(q[1], "443")`.
- `security` defaults to `"tls"`. If it is `tls` or `reality`:
  - `tls="1"`, `tls_serverName = peer or sni or ""`, `alpn`
  - `fp` → `utls`, `fingerprint`
  - reality: `reality="1"`, `reality_publicKey=pbk`, `reality_shortId=sid` (no spx/pqv)
  - `ech` → `ech`, `ech_config`
  - `tls_pinSHA256=pcs`, `tls_CertByName=vcn`, `tls_allowInsecure=INSECURE(...)`
  - Any other security (for example `none`): **no `tls` option is written at all**.
- `type` defaults to `"tcp"`. Then NET and TRANSPORT (trojan variant: xhttp gets host and path only; httpupgrade supported).
- `tcp_fast_open=tfo`, finalmask, sing-box rejection.

#### 1.6.5 `ssd` (whole-document format)
Detection happens in parse_link (§1.7).
- Each server object inherits `airport`, `port`, `encryption`, `password` from the root when they are missing.
- `set_ss_implementation`, then:
  - `address=server`, `port=port`, `password`, `method=ss_method=encryption`
  - `plugin`, `plugin_opts=plugin_options`
  - `group = airport` (**overrides** the subscription group)
  - `remarks`

#### 1.6.6 `vless`
- Core per `sub_vless_type` (sing-box or Xray). `protocol="vless"`. `remarks` from `#`.
- If the content contains `@`:
  - `uuid = UrlDecode(Info[1])`. Host and port as for trojan (default 443).
  - `type` defaults to `"tcp"`, lowercased.
  - **Auto-upgrade:** if the type is `xhttp`, `kcp` or `mkcp`, the core is not Xray, and has_xray: `type="Xray"`.
  - NET, then TRANSPORT (full xhttp with extra; `splithttp` handled like xhttp; httpupgrade supported).
  - `encryption = encryption or "none"`, `flow = flow`
  - If `security` is empty or absent and `flow` is set: `security="tls"`.
  - `tls="0"`. If `security` is `tls` or `reality`: the same fields as the ss TLS block (sni-or-host, alpn, utls/fingerprint, ech, pcs, vcn, reality with pbk/sid/spx/pqv), then `tls_allowInsecure=INSECURE(...)`. In vless, allowInsecure is written only inside the TLS block.
  - `port`, `tcp_fast_open=tfo`, finalmask, sing-box rejection.

#### 1.6.7 `hysteria` (v1)
- Requires has_singbox, else log "`Skip the %s node because the %s core program is not installed.`" ("Hysteria","Sing-Box"). `type="sing-box"`, `protocol="hysteria"`.
- `remarks` from `#`. Split the remainder on `?` (after replacing `/?`). **Param values are not URL-decoded.**
- Field mapping:
  - `address, port = parse_host_port(q[1], "443")`
  - `hysteria_obfs = obfsParam`
  - `hysteria_auth_type = "string"`, `hysteria_auth_password = auth`
  - `tls_serverName = peer or sni or ""`
  - `tls_pinSHA256 = pcs or pinSHA256`
  - `tls_allowInsecure = INSECURE(allowinsecure|allowInsecure|insecure)`
  - `alpn`
  - `hysteria_up_mbps = upmbps or sub_hy_up_mbps`, `hysteria_down_mbps = downmbps or sub_hy_down_mbps`
  - `hysteria_hop = mport`
- No `tls` option is written.

#### 1.6.8 `hysteria2` / `hy2`
- `remarks` from `#`. If the content contains `@`: `hysteria2_auth_password = UrlDecode(part1)` and the rest is `part2`. Param keys are lowercased and values URL-decoded.
- Field mapping:
  - `address, port = parse_host_port(q[1], "443")`
  - `tls_serverName = sni`
  - `tls_pinSHA256 = pcs or pinsha256`
  - `tls_CertByName = vcn`
  - `tls_allowInsecure = INSECURE(allowinsecure|insecure)`
  - `hysteria2_up_mbps = upmbps or sub_hy_up_mbps`, `hysteria2_down_mbps = downmbps or sub_hy_down_mbps`
  - `hysteria2_hop = mport`
  - if `obfs-password` or `obfs_password` is present: `hysteria2_obfs_type = obfs or "salamander"`, `hysteria2_obfs_password = that value`
  - if `obfs == "gecko"`: `hysteria2_obfs_MinPacketSize = minpacketsize or "512"`, `hysteria2_obfs_MaxPacketSize = maxpacketsize or "1200"`
- Core is decided last:
  - `sub_hysteria2_type=="sing-box"&&has_singbox` → `type="sing-box"`
  - `=="xray"&&has_xray` → `type="Xray"`
  - In both cases `protocol="hysteria2"` and finalmask(fm).
  - Otherwise skip ("Hysteria2","Hysteria2").
- Ignored params: `hopinterval`, `ech`, `alpn`.

#### 1.6.9 `tuic`
- Requires sing-box (`type="sing-box"`, `protocol="tuic"`).
- `remarks` from `#`.
- Userinfo `uuid:password` before `@`. If the raw part has no `:`, it is UrlDecoded first and searched again. If a `:` is found: `uuid = UrlDecode(before)`, `password = UrlDecode(after)`.
- Keys lowercased. Field mapping:
  - `address, port` (default "443")
  - `tls_serverName = sni`
  - `tls_disable_sni = disable_sni`
  - `tls_pinSHA256 = pcs or pinsha256`
  - `tuic_alpn = alpn or "h3"`
  - `tuic_congestion_control = congestion_control or "cubic"`
  - `tuic_udp_relay_mode = udp_relay_mode or "native"`
  - `tls_allowInsecure = INSECURE(allowinsecure|insecure|allow_insecure)`

#### 1.6.10 `anytls`
- Requires sing-box. Skip message args: ("AnyTLS","Sing-Box 1.12"). `type="sing-box"`, `protocol="anytls"`.
- If the content contains `@`: `password = UrlDecode(Info[1])`. Keys lowercased. `address, port` (default 443).
- `tls="0"`. `security` defaults to `"tls"` when empty or absent. If it is `tls` or `reality`:
  - `tls="1"`, `tls_serverName = sni or peer`, `tls_pinSHA256 = pcs or pinsha256`, `alpn`
  - `fp` → `utls`, `fingerprint`
  - reality: `reality="1"`, `reality_publicKey=pbk`, `reality_shortId=sid`
  - `ech` → `ech`, `ech_config`
- `port`. `tls_allowInsecure = INSECURE(allowinsecure|insecure)`, written always.

#### 1.6.11 `naive+https` / `naive+quic`
- Requires sing-box (`type="sing-box"`, `protocol="naive"`). Skip message args: ("NaïveProxy","Sing-Box").
- `remarks` from `#`.
- Userinfo, split at the literal `:` before decoding:
  - `user:pass` → `username=UrlDecode(user)`, `password=UrlDecode(pass)`
  - no colon → `username=""`, `password=UrlDecode(all)`
- Params are URL-decoded with case-sensitive keys. Field mapping:
  - `address, port` (default 443)
  - `tls_serverName = sni`
  - `uot = uot`
  - `naive_insecure_concurrency = insecure-concurrency or "0"`
  - `ech` → `ech="1"`, `ech_config`
  - `naive+quic` only: `naive_quic="1"`, `naive_congestion_control = congestion_control or "bbr"`

#### 1.6.12 `snell`
- Requires sing-box (`type="sing-box"`, `protocol="snell"`). Skip message args: ("Snell","Sing-Box 1.14").
- `remarks` from `#`.
- If the content contains `@`: `snell_psk = UrlDecode(part1)`. Keys are URL-decoded and lowercased.
- Field mapping:
  - `address, port` (default 443)
  - `snell_psk = psk or <userinfo psk>`
  - `password = userkey`
  - `snell_version = version or "4"`
  - if the version is `"4"`: `snell_obfs_mode = obfs or "none"`, `snell_obfs_host = obfs-host or obfs_host`
  - otherwise: `snell_mode = mode or "default"`
  - `snell_reuse = (reuse=="1") ? "1" : "0"`

### 1.7 `parse_link(raw, add_mode, group, sub_cfg)` → node_list
```
if raw empty:
    if add_mode=="2": log 2 "Get subscription content for [%s] is empty. This may be due to an invalid subscription address or a network problem. Please diagnose the issue!"
    return {}
cfgid = sub_cfg and sub_cfg[".name"]
keyword_filter = add_mode=="2" and prepare_keyword_filter(sub_cfg)
if raw contains "ssd://" (anywhere):
    szType="ssd"; json = jsonParse(base64Decode(raw after the first "ssd://"))
    nodes = json.servers, each inheriting {airport, port, encryption, password} from json
elif add_mode=="1": nodes = split(raw, "\n")                              # manual import: NOT base64-decoded
else:               nodes = split(base64Decode(raw) with "\r\n"->"\n", "\n")
for v in nodes:
    skip if v is nil, or (not ssd and v is whitespace-only)
    try:
        ssd: result = processData("ssd", v, ...)
        else: line = trim(v); dat = split(line, "://")
              if dat[1] and dat[2]:
                 if dat[1] in {vmess, ssr}: result = processData(dat[1], base64Decode(trim(dat[2] with "#.*$" removed)), ...)
                 else: link = dat[2] with "&amp;"->"&" and "%s*#%s*"->"#"; result = processData(dat[1], link, ...)
        nodeFilter(result)
    except: log 2 (v, "Parsing error, skip this node.")
if add_mode ~= "2" and #node_list>0: nodeResult.append({remark=group, list=node_list, sub_cfg=sub_cfg})
log 2 "Successfully resolved the [%s] node, number: %s" (group, #node_list)
return node_list
```
The text after `://` is cut at the next `://` (see §0.7). For example, a URL inside a vless `path` parameter that contains `://` truncates the link.

`nodeFilter(node)` (skipped when the node is nil), in order:
1. `error_msg` → log 2 "`Discard node: %s, Reason:` <error_msg>"
2. no `type` → "`Discard node: %s, Reason: No usable binary was found.`"
3. `(add_mode=="2" and is_filter_keyword(f, remarks))`, or no address, or `remarks=="NULL"`, or `address=="127.0.0.1"`, or (address not a hostname and not an IP) → log 2 "`Discard filter nodes: %s type node %s`"
4. otherwise keep the node.
5. Then, regardless of the outcome above: if `add_mode=="2"` and there is no header info for this cfgid, run `get_subscribe_info(cfgid, remarks)`.

### 1.8 Subscription download: `curl(url, file, ua, mode, hwid)`
```
if url empty: return 22, 404
args = ["-fskL", "--retry 3", "--connect-timeout 3", "-H 'Accept: */*'", "-H 'Accept-Encoding: identity'",
        "--dump-header -", "-w '\n%{http_code}'"]
if ua not in {nil, "", "curl"}:
    ua = (ua=="passwall2") ? "passwall2/" + (get_version() up to the first '-') : ua
    args += '--user-agent "' + ua + '"'                      # not escaped
if hwid=="1": args += get_headers()
cookie = "/tmp/cookie_" + random5
args += '-c "<cookie>" -b "<cookie>"'
mode "direct" -> curl_direct; "proxy" -> curl_proxy; else (nil/"auto") -> curl_auto  ; with -o <file>
rm -f cookie
parse output: ^(.-)%s*([0-9]+)$  -> headers = body with \r removed, http_code = number
return exit_code, http_code, headers
```
The resulting command is `curl -fskL --retry 3 ... -c "/tmp/cookie_ab12C" -b "/tmp/cookie_ab12C" [-x socks5h://127.0.0.1:P | --noproxy '*' --resolve 'd:p:ips'] -o /tmp/<cfgid> "<url>"`.

`get_headers()` (hwid):
- Cache file: `/tmp/etc/passwall2_tmp/sub_curl_headers`. If it exists, return its contents. It is never invalidated until reboot.
- Otherwise build the header lines:
  - `x-device-os: OpenWrt`
  - `x-ver-os: <DISTRIB_RELEASE from /etc/openwrt_release>`, if found
  - `x-device-model: <trim(/tmp/sysinfo/model)>`, if found
  - `x-hwid: <sha256 hex of "<trim(/sys/class/net/eth0/address)>-<model>">`, only if both the MAC and the model are present (`printf '%s' '...' | sha256sum`)
- Emit each line as `-H '<line>'`, with `'` escaped as `'\''`, joined by spaces. Write the string to the cache file and return it.

### 1.9 `execute()` (`start`)
```
subscribe_list = arg[2]=="all" ? all subscribe_list sections : [uci_get(id) or {} for id in arg[2] split by ',']
manual_sub = arg[3]=="manual"
for value in subscribe_list:
  cfgid=value[".name"]; remark=value.remark or ""; url=value.url or ""
  if fs.access(url):                         # a local file path (debug feature)
      log 1 "Start subscribing: 【remark】url"; tmp_file=url; url_is_local=true
  else:
      mode label: nil -> "Auto", "direct" -> "Direct", "proxy" -> "Proxy", other -> "Auto"
      log 1 "Start subscribing: 【remark】url [label]"
      tmp_file="/tmp/"+cfgid
      rc, value.http_code, headers = curl(url, tmp_file, value.user_agent, value.access_mode, value.hwid)
      if rc ~= 0: fail_list += value; rm -f tmp_file
  if tmp_file exists:
      if sh("[ -f F ] && sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' F") == 0:   # also edits a local file in place
          raw = trim(read F)
          auto_dns = value.domain_resolver is nil or ""
          raw, resolver = parseClashNode(raw, remark, auto_dns)
          if auto_dns and resolver: value.domain_resolver/_dns/_dns_https = resolver.*   # in memory only, not saved
          if headers non-empty and (info = parse_clash_sub_info(headers)):
              subscribe_info[cfgid] = info; subscribe_info_from_headers[cfgid] = true
          log_buffer = []                                   # buffer level-2 parse logs
          parsed = parse_link(raw, "2", remark, value)
          md5_content = jsonStringify(parsed)
          if value.domain_resolver not in {nil,"","disable"}:
              p = value.domain_resolver
              md5_content += jsonStringify([p, (p in udp/tcp) ? domain_resolver_dns or "" : "", p=="https" ? domain_resolver_dns_https or "" : ""])
          new_md5 = #parsed>0 ? md5_string(md5_content) : ""
          if not manual_sub and new_md5~="" and value.md5 == new_md5:
              drop log_buffer; log 1 "Subscription: [%s] No changes, no update required."
          else:
              flush log_buffer; if #parsed>0: nodeResult += {remark, list=parsed, sub_cfg=value, md5=new_md5}
      else: fail_list += value
      if url_is_local: value.http_code = 0 else rm -f tmp_file
for v in fail_list: log 1 "[%s] Subscription failed. This could be due to an invalid subscription address or a network issue. Please diagnose the problem! [%s]" (remark, http_code)
nodes_changed = update_node(0)
info_changed  = update_subscribe_info()
for r in nodeResult: uci_set(r.sub_cfg.name, "md5", r.md5)
if nodes_changed or info_changed non-empty:
    uci commit; restart_required = nodes_changed
    for each sub with info_changed: log 1 "Refresh subscription [%s] account usage and expiration information."
```
Notes:
- `tmp_file` is a global that persists across iterations. If a download failed and the file was removed, `fs.access` is false and nothing more happens for that subscription.
- The whole `execute` runs inside `xpcall`. On error it flushes the log buffer, logs the error and traceback, then logs "`An error occurred during subscription.`". Before the run it logs level 0 "`Start subscribing...`"; after it, "`Subscription complete...`" followed by `\n`.
- **MD5 compatibility:** upstream hashes `luci.jsonc.stringify` of Lua tables, whose key order is unspecified. A Rust port cannot reproduce those exact hashes. It should define a deterministic canonical serialization, such as sorted keys over the list of node maps. The only effect is that the first scheduled run after migration rewrites the nodes once.
- A subscription that yields 0 nodes adds nothing to nodeResult. Its old nodes are kept and its md5 is unchanged.

### 1.10 `update_node(manual)` (manual: 0 = subscription, 1 = import)
```
if nodeResult empty: log 1 "No node information updates are available."; return false
groups = { lower(r.remark) for r in nodeResult }
if manual==0: delete every `nodes` section with add_mode=="2" and lower(group) in groups
for r in nodeResult:
  sub = r.sub_cfg
  if sub:
    dr=sub.domain_resolver; drd=sub.domain_resolver_dns; drh=sub.domain_resolver_dns_https
    ds = sub.domain_strategy in {UseIPv4,UseIPv6} ? sub.domain_strategy : nil
    pre = sub.chain_proxy=="1" ? valid_chain_node(sub.preproxy_node) : ""
    to  = sub.chain_proxy=="2" ? valid_chain_node(sub.to_node) : ""
    ifc = sub.chain_proxy=="3" ? sub.outbound_iface : ""
    chain_node_type = ifc~="" ? "iface" : chain_node_type
  for node in r.list:
    id = new named section "nodes" with name gen_random_char(8)
    for k,v in node:                        # Lua pairs order
      if v is a non-empty table: set_list(id,k,v)
      else:
        if not (k=="group" and v=="default"): uci_set(id,k,v)     # an empty table/"" => no option
        if k=="type" and v in {Xray, sing-box}:
           if dr not in {nil,"","disable"}:
              set domain_resolver=dr
              if dr=="https" and drh: set domain_resolver_dns_https=drh
              elif dr in {udp,tcp} and drd: set domain_resolver_dns=drd
           if ds:
              if v=="sing-box": ds = (ds=="UseIPv4")?"ipv4_only":(ds=="UseIPv6")?"ipv6_only":ds   # mutates ds!
              set domain_strategy=ds
           if chain_node_type~="":
              if pre~="": chain_proxy="1", preproxy_node=pre
              elif to~="": chain_proxy="2", to_node=to
              elif ifc~="": chain_proxy="3", outbound_iface=ifc
valid_chain_node(n): if n is nil -> "" ;
   cp = n.chain_proxy or ""; am = n.add_mode or "0"
   chain_node_type = (cp=="" and am~="2") ? (n.type or "") : ""
   if chain_node_type not in {Xray, sing-box}: chain_node_type=""; return ""
   return n
```
**Upstream quirks:**
- `ds` is mutated in place. After the first sing-box node of a subscription, every later Xray node of the same subscription gets `domain_strategy = "ipv4_only"`/`"ipv6_only"` instead of `UseIPv4`/`UseIPv6`. A Rust port should use a per-node local value, which is the intended behaviour. This is a documented fix.
- `chain_node_type` is never reset between subscriptions.

**Re-pointing references.** After all nodes are written, if CONFIG is non-empty:
```
nodes = all `nodes` sections now present (in cursor order, including the new ones)
for config in CONFIG:
  if list entry with ≥1 child:
     if remarks and children[1].log ~= false: log 1 "Update [%s]"
     for child: select_node(nodes, child, parent=config)
     config.set(config)           # writes newNodes (an empty list deletes the option)
     if newNodes empty: log 1 "[%s] Unable to find a new node. Please confirm and process manually."
  else: select_node(nodes, config)
return true
```

### 1.11 `select_node(nodes, config, parent?)`
log_level = 1, or 2 when there is a parent. Logging happens if `config.log` is nil or true.

When `config.currentNode` is present (`cur`), try each step in order and stop at the first match:
0. If `cur.Socks` is set: `server = cur.Socks`. Socks references survive unchanged.
1. If `cur[".name"]` equals the `.name` of some node in `nodes` (the node still exists): use it. Log "`Matching node:`".
2. **First:** `type`, `remarks`, `address:port` and `group` are all equal. All four fields must be present on both sides, except group, which may be nil on both.
3. **Second:** `type`, `address:port` and `group` equal.
4. **Third:** `address:port` and `group` equal.
5. **Fourth:** `address` and `group` equal.
6. **Fifth:** `remarks` and `group` equal.
7. If there is no parent and still no match: if `#nodes_table>0`, use `nodes_table[1]` and log "`Unable to find the best matching node, now replaced with:` <remarks>". This snapshot was taken at startup, so it may point to a node that was just deleted.

Group comparison is exact and case-sensitive. The first match in `nodes` order wins.

If a server was found: call `config.set(parent or config, server)`.

When `currentNode` is nil and there is no parent: `config.set(config, "")`.

Log message formats: "`Update [%s]`" + " " + "`First Matching node:`" + " " + remarks, and likewise Second/Third/Fourth/Fifth.

### 1.12 Other modes
**`add <group>`:**
1. `raw = read /tmp/links.conf`. If the file is missing, `assert` aborts the script.
2. `raw = parseClashNode(raw, group)` (no auto DNS).
3. `parse_link(raw, "1", group)`, with no sub_cfg, so INSECURE defaults to `"1"` and the default cores apply.
4. If `update_node(1)` returns true, commit. Nothing is deleted. References are re-pointed with select_node; normally step 1 matches each node to itself.
5. `rm -f /tmp/links.conf`.

New nodes get `add_mode="1"` and `group=<group>`. The group option is omitted when it is `"default"`.

**`truncate [group]`:**
```
for config in CONFIG:
  list entry with children:
     remove = { child.currentNode.name : child.currentNode.add_mode=="2" and (no group or lower(group)==lower(child.currentNode.group or "")) }
     newNodes = [child.currentNode[".name"] for child in children (ipairs) if not in remove]
     config.set(config, newNodes)
  single: if currentNode.add_mode=="2" and group matches: config.delete() if exists else config.set(config,"")
delete all `nodes` with add_mode=="2" and group matches (case-insensitive; no arg = all)
for subscribe_list s with (no group or lower(group)==lower(s.remark or "")): delete option md5
commit
```
**Upstream quirks:**
- Socks children (`{Socks=id}`) have no `.name`, so truncate drops them from balancing/urltest lists.
- A socks entry set to `""` falls back to `nodes_table[1]`, which may itself be a node being deleted.
- The global node, ACL, and shunt options set to `""` are deleted.
- A haproxy_config entry whose `lbss` is not `ip:port` is deleted entirely.

No restart is triggered.

### 1.13 Subscription info write-back: `update_subscribe_info()`
For each `cfgid` in `subscribe_info` and each key in `{expired_date, rem_traffic}`: let `v = value~="" ? value : nil`. If `uci_get(cfgid,key) ~= v`, set the option (or delete it when `v` is nil) and mark the cfgid as changed. Returns the set of changed cfgids.

### 1.14 UCI options touched by subscribe.lua

**`global_subscribe` (`@global_subscribe[0]`), read-only:**

| option | type | default | meaning |
|---|---|---|---|
| filter_keyword_mode | enum "0".."4" | "0" | 0 off, 1 discard list, 2 keep list, 3 discard unless kept, 4 discard if in discard list or not in keep list |
| filter_discard_list | list of strings (each row may contain `\|`-separated keywords) | – | |
| filter_keep_list | list | – | |
| ss_type | shadowsocks-rust\|sing-box\|xray | first available | default core for SS links |
| trojan_type | sing-box\|xray | first available | |
| vmess_type | xray\|sing-box | first available | |
| vless_type | xray\|sing-box | first available | |
| hysteria2_type | sing-box\|xray | first available | |

**`subscribe_list` (one section per subscription):**

| option | rw | default | meaning |
|---|---|---|---|
| remark | r | "" | group name. It becomes the node `group` and is compared case-insensitively |
| url | r | "" | subscription URL or a local file path |
| user_agent | r | nil, meaning curl's default | "curl" means none; "passwall2" means `passwall2/<ver>`; anything else is literal |
| access_mode | r | nil (auto) | direct\|proxy\|other (auto) |
| hwid | r | – | "1" sends the x-device/x-hwid headers |
| allowInsecure | r | (default true) | any value other than "1" makes the default insecure value "0" |
| ss_type / trojan_type / vmess_type / vless_type / hysteria2_type | r | "global" | core override per subscription |
| hysteria_up_mbps / hysteria_down_mbps | r | – | fallback bandwidth for hysteria and hysteria2 nodes |
| filter_keyword_mode | r | (unset/"5" means global) | 0..4 as above |
| filter_discard_list / filter_keep_list | r | – | |
| domain_resolver | r | ""/nil means auto (taken from the Clash DNS block when available) | disable\|udp\|tcp\|https |
| domain_resolver_dns | r | – | `ip:port` for udp/tcp |
| domain_resolver_dns_https | r | – | DoH URL |
| domain_strategy | r | – | UseIPv4\|UseIPv6\|other (ignored) |
| chain_proxy | r | – | "1" preproxy, "2" landing (to_node), "3" outbound interface |
| preproxy_node / to_node | r | – | node id. It must be a non-subscription Xray/sing-box node with no chain of its own |
| outbound_iface | r | – | interface name |
| md5 | rw | – | content hash of the last applied update |
| expired_date | w | – | expiry date string |
| rem_traffic | w | – | remaining traffic string |

**`nodes`, written on creation:** `timeout`, `add_mode` ("1" import, "2" subscription; "0" means manual from the UI), `group`, `type`, `protocol`, `remarks`, `address`, `port`, plus every protocol option listed in §1.6. The following are list options: `tcp_guise_http_host`, `tcp_guise_http_path`, `http_host`. Chain and DNS options: `domain_resolver`, `domain_resolver_dns`, `domain_resolver_dns_https`, `domain_strategy`, `chain_proxy`, `preproxy_node`, `to_node`, `outbound_iface`.

**Reference options rewritten:**
- `@global[0].node`
- `socks.node`, `socks.autoswitch_backup_node` (list)
- `haproxy_config.lbss` (or the whole section is deleted)
- `acl_rule.node`
- shunt node options `<shunt_rule_name>`, `<shunt_rule_name>_proxy_tag`, `default_node`, `default_proxy_tag`
- `balancing_node` (list), `fallback_node`, `urltest_node` (list), `preproxy_node`, `to_node`

**Also read:** `shunt_rules.remarks`, `@global[0].localhost_proxy`, `@global_other[0].show_node_info`, and `@global_app[0].*_file`.

### 1.15 Files and commands used by subscribe.lua
- `/var/lock/passwall2_sub_rule.lock` (lockf, 1-byte task marker)
- `/tmp/<cfgid>`: downloaded body; blank lines removed with sed; deleted afterwards
- `/tmp/cookie_<5 random>`: curl cookie jar; deleted
- `/tmp/links.conf`: manual import input; deleted
- `/tmp/etc/passwall2_tmp/sub_curl_headers`: cached HWID header args
- `/tmp/md5.XXXXXX`: temp file for md5
- Commands: `curl ...`, `sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' <file>`, `rm -f`, `sha256sum`, `md5sum`, `busybox nslookup` (direct mode), `uci -q commit passwall2`, `/etc/init.d/passwall2 restart [cron] > /dev/null 2>&1 &`

---

## 2. `clash_subconverter.lua`

It exposes two globals: `parseClashNode(raw, remark, auto_dns)` and `parse_clash_sub_info(headers)`.

### 2.1 `parseClashNode(raw, remark, auto_dns)` → `(text, resolver?)`
```
if raw is nil -> return ""
domain_redir = {}
lyaml not installed -> return raw          (feature silently disabled)
parse YAML; on error -> log 1 "Subscription conversion: YAML parsing failed: %s" (remark); return ""
if the result is not a table (e.g. a scalar: base64 text, a list of links) -> return raw
if data.proxies is not a table -> return ""     # e.g. a YAML/JSON mapping without proxies => the subscription is empty
log 1 "Subscription conversion: Clash subscription detected, converting..."
for k,v in data.hosts (if a table): if both strings are valid hostnames: domain_redir[k]=v
links = []
for node in data.proxies (array order):
   ok, code, msg_or_link = pcall(encode_node, node)
   not ok        -> log 2 "Subscription conversion: discard node %s, conversion failed."
   code==1 & msg -> log 2 msg
   link          -> links.append(link)
resolver = (#links>0 and auto_dns) ? extract_clash_dns(data) : nil
return (#links>0 ? join(links,"\n") : ""), resolver
```
The returned text is plain links, one per line. parse_link then calls `base64Decode` on it, which returns it unchanged (§0.3).

**Rust note:** the port must treat these three outcomes differently, as described above: "YAML parse error" returns `""`, a "non-mapping document" returns raw, and a "mapping without proxies" returns `""`. A plain multi-line link list or a base64 blob normally parses as a YAML scalar. A list that YAML rejects, for example one with a line containing `: ` together with odd indentation, is lost upstream.

### 2.2 Helpers
- `add_param(p, key, value)`: skip nil and `""`. A boolean becomes `"1"`/`"0"`, so `false` **is** emitted as `0`. Appends `key=UrlEncode(tostring(value))`.
- `host_format(h)`: if the text inside `[...]` (or `h` itself) is IPv6, return `[addr]`; otherwise return `h` unchanged.
- `build_alpn(alpn)`: takes a string or a list. Keeps only `h3`, `h2` and `http/1.1`, in that fixed order, deduplicated, joined with `,`. Returns nil if nothing remains, so other ALPNs are dropped.
- `build_ech(node)`: requires `ech-opts.enable == true`.
  - If `config` is non-empty, return it.
  - Otherwise `name = query-server-name or servername or sni or server`, and return `name .. "+https://223.5.5.5/dns-query"`.
- `bandwidth_mbps(v)`:
  - nil → nil
  - numeric → that number
  - a string matching `^\s*(\d+)\s*([KMGT]?)([Bb])ps\s*$` → `amount * {1,1e3,1e6,1e9,1e12}[prefix] * (B?8:1) / 1e6`
  - anything else → nil, which makes the node invalid
- `inherit(base, overrides)`: a shallow merge.
- `build_xhttp_extra(opts)`: maps Clash keys to Xray keys.

  | Clash key | Xray key |
  |---|---|
  | headers | headers |
  | x-padding-bytes | xPaddingBytes |
  | no-grpc-header | noGRPCHeader |
  | x-padding-obfs-mode | xPaddingObfsMode |
  | x-padding-key | xPaddingKey |
  | x-padding-header | xPaddingHeader |
  | x-padding-placement | xPaddingPlacement |
  | x-padding-method | xPaddingMethod |
  | uplink-http-method | uplinkHTTPMethod |
  | session-placement | sessionIDPlacement |
  | session-key | sessionIDKey |
  | session-table | sessionIDTable |
  | session-length | sessionIDLength |
  | seq-placement | seqPlacement |
  | seq-key | seqKey |
  | uplink-data-placement | uplinkDataPlacement |
  | uplink-data-key | uplinkDataKey |
  | uplink-chunk-size | uplinkChunkSize |
  | sc-max-each-post-bytes | scMaxEachPostBytes |
  | sc-min-posts-interval-ms | scMinPostsIntervalMs |

  - `headers` is kept only when it is a non-empty map (it is copied).
  - `reuse-settings` maps to `xmux`:

    | Clash key | Xray key |
    |---|---|
    | max-concurrency | maxConcurrency |
    | max-connections | maxConnections |
    | c-max-reuse-times | cMaxReuseTimes |
    | h-max-request-times | hMaxRequestTimes |
    | h-max-reusable-secs | hMaxReusableSecs |

    Values are numeric when they parse as numbers; otherwise the string is kept (for example a range `"16-32"`). `hKeepAlivePeriod = tonumber(h-keep-alive-period)`. `xmux` is added only if it is non-empty.

### 2.3 `build_common(node)`
```
o.server=host_format(server); o.port=port; o.name=name
TLS: reality-opts -> security="reality", pbk=reality-opts.public-key, sid=reality-opts.short-id
     elif tls truthy -> security="tls"
     sni = servername or sni ; fp = client-fingerprint ; pcs = fingerprint ; vcn = name-cert-verify
     insecure = (skip-cert-verify == true) ; alpn = build_alpn(alpn) ; ech = build_ech(node)
transport: type = network or "tcp"
  ws:   path = ws-opts.path or "/"; if not v2ray-http-upgrade: append ?ed=<max-early-data> and ?eh=<early-data-header-name>
        (using '&' when the path already has '?'); host = ws-opts.headers.Host; v2ray-http-upgrade==true -> type="httpupgrade"
  grpc: serviceName = grpc-opts.grpc-service-name
  http: type="tcp", headerType="http", host=server, path="/"; http-opts: host = first(opts.host) or first(opts.headers.Host) or server; path = first(opts.path) or "/"
  h2:   host = first(h2-opts.host); path = h2-opts.path
  xhttp: host/path/mode from xhttp-opts; extra = build_xhttp_extra(opts)
     if opts.download-settings = d:
        eff = inherit(node, d)
        ds = {address = domain_redir[eff.server] or eff.server, port = eff.port, network="xhttp", security = eff.tls ? "tls" : "none"}
        sni = eff.servername or eff.sni or eff.server
        if eff.tls or eff.reality-opts:
           ds.tlsSettings = {serverName=sni, allowInsecure=(eff.skip-cert-verify==true), fingerprint=eff.client-fingerprint,
              pinnedPeerCertSha256 = eff.fingerprint ? sha256_sb_xray(eff.fingerprint) : nil,
              verifyPeerCertByName = eff.name-cert-verify, alpn = split(build_alpn(eff.alpn), ","), echConfigList = build_ech(eff)}
           if eff.reality-opts: ds.security="reality"; ds.realitySettings = {serverName=sni,
              fingerprint = eff.client-fingerprint or "chrome", publicKey = reality.public-key, shortId = reality.short-id or ""}; delete ds.tlsSettings
        xs = build_xhttp_extra(inherit(opts, d)); xs.path = d.path or opts.path or "/"; xs.host = d.host or opts.host or sni; xs.mode = opts.mode or "auto"
        ds.xhttpSettings = xs; extra.downloadSettings = ds
     if extra is non-empty: transport.extra = json.stringify(extra)
```
`sha256_sb_xray(s)`: if `s` base64-decodes to exactly 32 bytes, return the uppercase hex of those bytes. Otherwise return `s` unchanged.

### 2.4 `encode_node(node)`
1. If the node is not a table, or lacks `type` or `name`: return `1, "Subscription conversion: skip a malformed node."`.
2. If there is no `server`, or no `port` (hysteria2 may use `ports` instead): return `1, "Subscription conversion: discard node %s, node information is incomplete."`.
3. Shallow-copy the node.
4. hysteria/hysteria2: convert `up`/`down` with `bandwidth_mbps`. If a value is present but invalid: return `1, "...invalid bandwidth format."`.
5. `server = domain_redir[server] or server`.
6. Dispatch by `type`: `vless`, `trojan`, `vmess`, `ss`, `hysteria`, `hysteria2`, `tuic`, `anytls`, `ssr`, `snell`. Any other type: log 2 "`Subscription conversion: discard unsupported node %s, node type: %s`" and return nothing.

Every encoder returns `0, link` on success. The fragment is always `#UrlEncode(name or "")`, except vmess and ssr, which embed the name.

| Clash type | Output link | Query params, in order (via add_param) |
|---|---|---|
| vless | `vless://<uuid>@<host_fmt>:<port>` (uuid not encoded) | `flow` (only if it starts with `xtls-`), `encryption`, `security`, `pbk`, `sid`, `sni`, `fp`, `alpn`, `ech`, `pcs`, `vcn`, `allowInsecure` (always present, 0/1), `type`, `headerType`, `host`, `path`, `serviceName`, `mode`, `extra` |
| trojan | `trojan://<UrlEncode(password)>@host:port` | `security`, `pbk`, `sid`, `sni`, `fp`, `alpn`, `ech`, `pcs`, `vcn`, `allowInsecure`, `type`, `headerType`, `host`, `path`, `serviceName` |
| vmess | `vmess://` + base64(JSON) | JSON fields below |
| ss | `ss://` + base64(`cipher:password@host_fmt:port`) | `udp=1` (if udp), `uot=1` (if udp-over-tcp), `plugin` / `shadow-tls` (below) |
| hysteria | `hysteria://host:port` | `auth`=auth-str, `mport`=ports, `obfsParam`=obfs, `sni`, `upmbps`, `downmbps`, `insecure` (0/1), `vcn`, `pinSHA256`=fingerprint, `alpn` |
| hysteria2 | `hysteria2://<UrlEncode(password or "")>@host:<port or first number in ports>` | `mport`=ports, `hopInterval`=hop-interval, `obfs`, `obfs-password`, `minPacketSize`=obfs-min-packet-size, `maxPacketSize`=obfs-max-packet-size, `upmbps`, `downmbps`, `ech`=build_ech, `vcn`, `sni`, `insecure`, `pinSHA256`=fingerprint |
| tuic | `tuic://<enc uuid>:<enc password>@host:port` | `congestion_control`=congestion-controller, `alpn`, `sni`, `disable_sni=1` (if disable-sni), `allowInsecure`, `udp_relay_mode`=udp-relay-mode, `pcs`=fingerprint, `vcn` |
| anytls | `anytls://<enc password>@host:port` | `security`, `pbk`, `sid`, `sni`, `alpn`, `fp`, `ech`, `pcs`, `insecure` |
| ssr | `ssr://` + base64(`host:port:protocol:cipher:obfs:base64(password)?obfsparam=b64&protoparam=b64&remarks=b64(name)`) | – |
| snell | `snell://host:port` | `psk`, `version`, `obfs=http` and `obfs-host` (only for http obfs), `reuse` (1/0) |

Reject rules per type:
- **hysteria:** rejected when `protocol` is set and not `"udp"`.
- **tuic:** `token` present → "TUIC v4 is not supported". Missing uuid, or password nil → "authentication information is incomplete".
- **anytls:** rejected when `shadow-tls-opts`, `restls-opts` or `jls-opts` is present ("Sing-Box does not support AnyTLS + X").
- **snell:**
  - `obfs-opts.mode` other than http/none is rejected.
  - Version defaults to 4. Version 5 is treated as 4. Versions below 4 are rejected.
- **ss:** the cipher must be one of `none`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr`, `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `rc4-md5`, `chacha20-ietf`, `xchacha20`. Otherwise reject with "unsupported cipher".
- **ss plugin:**
  - `obfs` is renamed to `obfs-local`.
  - `shadow-tls` → param `shadow-tls = base64(json(plugin-opts or {}))`.
  - `obfs-local`: opts keys `mode` → `obfs`, `host` → `obfs-host`. Booleans become 1/0.
  - `v2ray-plugin`: `mode=websocket` is dropped. A boolean true becomes a bare key (e.g. `tls`); false is dropped. Other values become `k=v`.
  - Option order is unordered. The result is `plugin = "<plugin>;opt;opt"`.
  - Any other plugin is rejected ("unsupported plugin").

vmess JSON:
```
{v:"2", ps:name, add:server (no brackets), port:tostring(port), id:uuid, aid:tostring(alterId or 0),
 net:transport.type, security:cipher, scy:cipher, type:headerType or "none", host:transport.host or "",
 path:UrlEncode(transport.path or "")   (grpc: UrlEncode(serviceName or "")),
 tls: (security=="tls") ? "tls" : "", sni, alpn, fp, ech, pcs, vcn, insecure:"1"/"0", tfo: tfo?"1":"0"}
```
Note that because Clash conversion always emits an explicit `allowInsecure`/`insecure` value of `0` or `1`, the subscription's `allowInsecure` default never applies to Clash-converted nodes.

### 2.5 `extract_clash_dns(data)`: subscription-wide node-domain resolver
```
dns = data.dns; require table and dns["proxy-server-nameserver"]; else nil
if dns["proxy-server-nameserver-policy"] is a non-empty table -> nil
listener = parse_dns_endpoint(dns.listen)
has_policy = dns["nameserver-policy"] is a non-empty table
pick(cands, depth):
  depth>4 -> nil; string -> {string}; non-table -> nil
  for value in cands:
    e = parse_dns_endpoint(value); skip if nil or is_unspecified(e.host)
    if is_loopback(e.host):
       listen_matches = listener and listener.protocol~="https" and listener.port==e.port and (
            listener.host==e.host or (listener.host=="0.0.0.0" and e.host has no ':')
         or (is_unspecified(listener.host) and listener.host~="0.0.0.0" and e.host has ':')
         or (e.host=="localhost" and is_loopback(listener.host)))
       if e.protocol~="https" and dns.enable==true and listen_matches and not resolving[key] and not has_policy:
            resolving[key]=true; r = pick(dns.nameserver, depth+1); resolving[key]=nil; if r return r
    elif e.protocol=="https": return {domain_resolver="https", domain_resolver_dns_https=e.url}
    elif e.host is IPv4: return {domain_resolver=e.protocol, domain_resolver_dns=e.host..":"..e.port}
    (IPv6 or hostname udp/tcp servers are skipped)
r = pick(dns["proxy-server-nameserver"], 0); if r: log 1 "Subscription conversion: extracted node domain DNS: %s" (DoH url or "proto://ip:port")
```
- `key` is `protocol://host:port`.
- `is_loopback(h)`: `localhost`, or `127.*` IPv4, or matches `^[0:]+:0*1$`.
- `is_unspecified(h)`: `0.0.0.0` or matches `^[0:]+$`.

`parse_dns_endpoint(v)`:
```
v must be string; trim; reject "" or containing any of whitespace # ? @ ,
url = has "://" ? v : "udp://"+v ; parse with api.parseURL (scheme, authority, pathname, user:pass@, [v6]:port / host:port)
protocol must be udp|tcp|https ; hostname must be IP or hostname
bracketed (host starts with '[') must be IPv6 ; https+IPv6 must be bracketed
port = parsed port or (https?443:53), must be 1..65535 ; non-https with any pathname -> reject
return {protocol, host=lower(hostname) with trailing '.' removed, port, url}
```

### 2.6 `parse_clash_sub_info(headers)` → `{rem_traffic, expired_date}` or nil
- `userinfo` = the first match of `[Ss]ubscription%-userinfo:%s*([^\r\n]+)`. The rest of the header name is case-sensitive. A Rust port may match it case-insensitively.
- Parse `upload=`, `download=`, `total=` (digits, default 0) and `expire=`.
- `remain = max(0, total - upload - download)`.
- `format_size`: divide by 1024 while ≥1024, up to PB, with units `B, KB, MB, GB, TB, PB`. Format by value: ≥100 → `"%.0f%s"`, ≥10 → `"%.1f%s"`, otherwise `"%.2f%s"`. For example `"12.3GB"` or `"0.00B"`.
- `expired_date`: if expire > 0, format `"%d-%d-%d"` (year-month-day, local time, **no zero padding**, e.g. `2026-3-7`). Otherwise the translated string "`Never expires`".

---

## 3. `rule_update.lua`

### 3.1 Command line
- `lua rule_update.lua log <targets> [cron]`. `arg[1]` (`"log"`) is ignored.
- LuCI calls `rule_update.lua log '<update>'`, where `<update>` is comma-separated, e.g. `geoip,geosite`.
- Cron (app.sh) and `tasks.sh` call `rule_update.lua log all cron`.
- When `arg[3]=="cron"`, `arg[2]` is forced to nil, so the UCI flags decide.

### 3.2 Lock
The same file as §1.2 is used, with these differences:
- The "queued" message names "Rule Update".
- On the busy non-cron path it closes the lock and exits 0.
- It writes the marker byte `r`.
- Then `uci revert passwall2`.

### 3.3 UCI options

| section/option | rw | default | meaning |
|---|---|---|---|
| `@global_rules[0].geoip_url` | r | `https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat` | |
| `@global_rules[0].geosite_url` | r | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` | |
| `@global_rules[0].v2ray_location_asset` | r | `/usr/share/v2ray/` (a trailing `/` is added if missing) | install directory |
| `@global_rules[0].geoip_update` | rw | `"1"` | update geoip in cron mode |
| `@global_rules[0].geosite_update` | rw | `"1"` | |
| `@global[0].flush_set` | w | – | set to `"1"` after a successful replacement so the restart flushes ipsets/nftsets |

### 3.4 Main flow
```
if arg2 (manual): geoip_update = "1" if "geoip" in arg2 split ',' else "0"; same for geosite   # anything else, e.g. "all", => both "0"
else: geoip_update = uci geoip_update or "1"; geosite_update = uci geosite_update or "1"
if both "0": close lock; exit (nothing written)
log 0 "Start updating the rules..."
if geoip_update=="1":  log 1 "%s Start updating..." geoip;  safe_call(fetch_geofile("geoip.dat","geoip",geoip_url));  rm /tmp/geoip.dat /tmp/geoip.dat.sha256sum
if geosite_update=="1": same with geosite.dat
uci set @global_rules[0].geoip_update=geoip_update ; geosite_update=geosite_update
if reboot==1: log 1 "Restart the service and apply the new rules."; uci set @global[0].flush_set=1
uci commit passwall2
log 0 "The rules have been updated..."
close lock; if reboot==1: /etc/init.d/passwall2 restart[ cron] > /dev/null 2>&1 &
```
- **Quirk:** a manual run writes its selection back into the persistent flags. For example, a manual `geoip` sets `geosite_update="0"`, which disables geosite in later cron runs. To stay a drop-in replacement, keep this behaviour (the LuCI page presumably relies on these flags as its checkbox state).
- `safe_call` runs the function under xpcall. On error it logs the error, the traceback, and "`%s update error!`".

### 3.5 `curl(url, file)` for rules
The args are:
```
-skL --retry 3 --connect-timeout 3 --max-time 300 --speed-limit 51200 --speed-time 15 -H 'Accept: */*'
-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
--dump-header - -w '\n%{http_code}' -o <file>
```
- They are sent through `curl_auto(url, nil, args)` (§0.18).
- There is no `-f`, so success is decided by the HTTP code.
- Output parsing: `^(.-)%s*([0-9]+)$` gives `headers=body`, `code`. Otherwise code = trailing digits or 0. `\r` is stripped from the headers.
- Returns `(http_code, headers)`.

### 3.6 `non_file_check(path, headers)` → true means bad
- The local size is 0 → log 2 "`Downloaded file is empty or an error occurred while reading it.`" and return true.
- `remote_size` = the **last** `Content-Length: N` with N > 0 among all header blocks (there can be several because of redirects).
- If `remote_size` is present and differs from the local size → log 2 "`Download file size verification error. Original file size: %sB. Downloaded file size: %sB.`" and return true.

### 3.7 `fetch_geofile(name, type, url)`
```
tmp = "/tmp/"+name ; asset = asset_location+name
fname = url:match("^.*/([^/?#]+)") ; sha_url = url with EVERY literal occurrence of fname replaced by fname..".sha256sum"
sha_path = tmp..".sha256sum"
sha_verify = (curl(sha_url, sha_path) == 200)
if sha_verify:
   hash = first line of sha_path matching ^(%x+)%s with #hash==64 -> digest = "sha256:"..hash
   if no digest: log 1 "%s SHA256 verification information is invalid. Update failed."; return 1
   if asset exists and sha256sum(asset) == hash (case-insensitive): log 1 "%s version is the same and does not need to be updated."; return 0
code, hdr = curl(url, tmp)
if code==200 and non_file_check(tmp,hdr):
   log 1 "%s an error occurred during the file download process. Please try downloading again."; rm tmp; code,hdr = curl(url,tmp)
   if code==200 and non_file_check(tmp,hdr): code=0; log 1 "%s an error occurred while downloading the file. Please check your network or the download link and try again!"
if code==200:
   if sha_verify:
      if sha256(tmp)==digest: install(); log 1 "%s update success."
      else: log 1 "%s update failed, please try again later or change URL."; return 1
   else:
      if not validate_geo_file(tmp, type): log 1 "%s file format verification failed. Update failed."; return 1
      if asset exists and `cmp -s tmp asset` == 0: log 1 "%s version is the same and does not need to be updated."; return 0
      install(); log 1 "%s update success."
else: log 1 "%s update failed, please try again later or change URL."; return 1
install(): sh("mkdir -p /tmp/bak_v2ray/ && mv -f <asset> /tmp/bak_v2ray/")
           sh("mkdir -p <asset_location> && mv -f <tmp> <asset>"); reboot = 1
```
- The sha256 is computed with `sha256sum '<file>'`.
- The backup directory is `/tmp/bak_v2ray/`. A failed `mv` of a missing asset is ignored.

### 3.8 `validate_geo_file(path, "geoip"|"geosite")`: streaming protobuf sanity check
The check succeeds if parsing the whole file as message `list` raises no error.

Schema (`field#: {wire, child?, max?}`):
```
list    : 1:{2, geoip|geosite}                     # GeoIPList / GeoSiteList .entry
geoip   : 1:{2} code, 2:{2,"cidr"}, 3:{0} reverse_match
geosite : 1:{2} code, 2:{2,"domain"}
cidr    : 1:{2} ip, 2:{0, max 4294967295} prefix
domain  : 1:{0, max 3} type, 2:{2} value, 3:{2,"attribute"}
attribute: 1:{2} key, 2:{0}, 3:{0}
```
Parser:
- `parse(kind, limit)` loops while `pos < limit`:
  1. For an entry kind (geoip/geosite): if field 1 has already been seen with length > 0 **and** at least one child has been parsed, skip to `limit` and return. Only the first rule of each category is sampled; the rest is skipped by seeking.
  2. `tag = varint(max=2^32-1)`, `field = tag>>3`, `wire = tag&7`. Assert `field > 0`. If the field is in the schema, assert that the wire type matches.
  3. Wire 0: read a varint, overflow-checked against the field's max if it has one.
  4. Wire 2: `len = varint(max = limit-pos)`, assert `len ≤ limit-pos`.
     - If the field has a child type, and this is not (an entry kind that already has one child): recurse `parse(child, pos+len)`.
     - Otherwise seek past `len` bytes.
     - Fields that have a child type increment `entries`.
  5. Wire 1 or 5: skip 8 or 4 bytes.
  6. Any other wire type: error.
  7. Record `values[field] = value`. For wire 2 the value is the length.
- End-of-message assertions:
  - list: `entries > 0` and the global `rules > 0`
  - geoip/geosite/attribute: `values[1] > 0`
  - cidr: `values[1] ∈ {4,16}` and `(values[2] or 0) ≤ (4 → 32, 16 → 128)`; then `rules++`
  - domain: `values[2] > 0`; then `rules++`
- `varint`: at most 10 bytes. Each read asserts `pos < limit`. The 10th byte must be ≤ 1. With a max, each step asserts `digit ≤ floor((max-value)/factor)`. Without a max the value is not accumulated (it is returned as 0).
- An empty file or one that cannot be opened is invalid.

### 3.9 Files and commands used by rule_update.lua
- `/tmp/geoip.dat`, `/tmp/geosite.dat`, `/tmp/<name>.sha256sum`: removed after each type is processed
- `/tmp/bak_v2ray/`: backup of the previous asset
- `<asset_location>/geoip.dat`, `<asset_location>/geosite.dat`
- Commands: `curl`, `sha256sum`, `cmp -s`, `mkdir -p`, `mv -f`, `uci commit`, `/etc/init.d/passwall2 restart [cron] > /dev/null 2>&1 &`

---

## 4. Rust implementation checklist (behavioural contract)
1. **Lock file.** `/var/lock/passwall2_sub_rule.lock` is shared with any remaining shell or Lua tooling.
   - Use `lockf`/`fcntl` (F_TLOCK, then F_LOCK when in cron mode).
   - Write byte `s` or `r` at offset 0.
   - Manual requests skip a busy lock; cron requests queue behind it.
2. Run `uci revert passwall2` at startup. Commit once at the end, and only when something changed.
3. **Exact link parsing per §1.6.** In particular:
   - the lenient base64 rule (§0.3)
   - the raw/tcp swap per core
   - h2/http mapped to xhttp for Xray
   - the INSECURE default
   - SS-Rust with any `type=` being discarded
   - the vless auto-upgrade to Xray for xhttp/kcp
   - hysteria v1 params not being URL-decoded
4. Discard rules (§1.7) and keyword filter modes 0–4, with 5/unset inheriting the global setting (§1.4).
5. **MD5 skip logic:** scheduled runs skip unchanged subscriptions; manual runs always apply.
6. Clash YAML conversion (§2), followed by the normal link parser. Auto-DNS enrichment happens in memory only and is part of the hash.
7. Delete old `add_mode=2` nodes of the updated groups, create new sections with random 8-character names, then re-point every reference using the priority cascade (§1.11).
8. Write `expired_date`/`rem_traffic`. Header info takes precedence over info parsed from remarks.
9. Restart `/etc/init.d/passwall2 restart [cron]` in the background only when nodes changed (subscription), or when a geo file was replaced (rules, which also sets `flush_set=1`).
10. Decide each documented upstream bug explicitly:
    - the vmess xhttp `params` crash
    - the vmess kcp transport name
    - the `quic_security` typo
    - the `domain_strategy` mutation leaking to later nodes
    - truncate dropping Socks list members
    - the manual rule run overwriting the persistent flags

    Recommendation: fix the first, third and fourth, because they are clearly unintended; keep the others bit-compatible.
