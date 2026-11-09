# 04 — sing-box config generator (`luasrc/passwall2/util_sing-box.lua`)

Source: `luci-app-passwall2/luasrc/passwall2/util_sing-box.lua` (2500 lines, every line read).
Module name: `luci.passwall2.util_sing-box`. Depends on `luci.passwall2.api` (referred to as `api`).

Purpose: generate sing-box JSON configs for
1. **client mode** (`gen_config`): local socks/http/redirect/tproxy/dns inbounds, node outbounds, shunt routing, DNS, fakeip, rule-sets;
2. **server mode** (`gen_config_server`): one inbound/endpoint built from a `server` UCI section (called by `server_app.lua`);
3. **protocol bridge** (`gen_proto_config`): a minimal socks/http -> upstream socks/http config;
4. **geo conversion** (`geo_convert_srs`): convert V2Ray `geosite.dat`/`geoip.dat` categories to sing-box `.srs` rule-set files using `geoview`.

---

## 0. Invocation / CLI contract

```
lua /usr/lib/lua/luci/passwall2/util_sing-box.lua <func> '<json-object>'
```
- `<func>` ∈ `gen_config`, `gen_proto_config`, `geo_convert_srs` (the only functions exported to `_G` for CLI).
- `arg[2]` parsed with `jsonc.parse` into `var` (a table of **strings**; app.sh uses `json_add_string`, and `json_add_null` for removed keys).
- The return value is `print`ed to stdout (app.sh redirects it into the config file). `geo_convert_srs` returns nothing so prints an empty line.
- After printing: if `GEO_VAR.SITE_TAGS` or `GEO_VAR.IP_TAGS` is non-empty **and** `NO_RUN` is falsy → `convert_geofile()` (geo conversion happens *after* the JSON is written, synchronously, before the process exits; app.sh then launches sing-box).
- `gen_config_server(node)` is called as a Lua function from `server_app.lua` with a UCI section table (not via CLI).
- Output JSON: `jsonc.stringify(config, 1)` (pretty-printed). Lua `nil` fields are simply absent. Key order is irrelevant.

Callers in app.sh (for context): `run_singbox` builds JSON with keys listed in §3.1 and runs `lua $UTIL_SINGBOX gen_config "$json" > $config_file`; `run_socks` (type sing-box) passes `node, server_host, server_port (nulled when no relay_port), local_http_address/port, log/loglevel/logfile, no_run, flag, local_socks_address/port, direct_dns_<proto>_server/port, direct_dns_query_strategy`. The http-over-socks bridge passes `local_http_port, server_proto=socks, server_address=127.0.0.1, server_port, server_username, server_password` to `gen_proto_config`.

### Path constants (from api)
| Name | Value |
|---|---|
| `api.TMP_PATH` | `/tmp/etc/passwall2` |
| `api.CACHE_PATH` | `/tmp/etc/passwall2_tmp` |
| `api.TMP_IFACE_PATH` | `/tmp/etc/passwall2/iface` |
| `GEO_VAR.TO_SRS_PATH` | `/tmp/etc/passwall2_tmp/singbox_srss/` (trailing slash) |
| per-flag text cache | `/tmp/etc/passwall2_tmp/cache_<flag>.txt` |
| fakeip cache db | `/tmp/etc/passwall2_tmp/singbox_<flag'>.db` (`flag'` = flag with `acl_` stripped, see §3.7) |
| direct node list | `/tmp/etc/passwall2/direct_node_list` (appended) |

---

## 1. Module-level state & version detection

Executed at `require` time:
```
local_version = api.get_app_version("sing-box"):match("[^v]+")   -- strip leading 'v'; e.g. "1.12.3"
version_ge_1_14_0 = compare_versions(local_version, ">=", "1.14.0")
version_ge_1_15_0 = compare_versions(local_version, ">=", "1.15.0")
-- (also evaluated lazily inside anytls: compare_versions(local_version, ">=", "1.13.16"))
```
`get_app_version` runs the sing-box binary's version command (cached). Edge: if no sing-box binary, `match` on "" yields nil; compare then returns false (treat as "unknown/old"). Rust: detect version once, treat failure as `0.0.0`.

Module globals (persist across calls in one process):
- `ech_domain = {}` — set of domain names that need ECH config DNS lookup (filled by `gen_outbound`, consumed by `gen_config`).
- `GLOBAL.DNS_SERVER = {}` — map node_id → `{server = <dns server obj>, domain = <node address>}` for per-node domain resolvers.
- `GEO_VAR = {OK=nil, DIR=nil, SITE_PATH=nil, IP_PATH=nil, SITE_TAGS={}, IP_TAGS={}, TO_SRS_PATH=CACHE_PATH.."/singbox_srss/"}`.
- Lua globals leaked by `gen_config` (relevant because functions share them): `NO_RUN`, `TMP_PORT`, `default_node_address`, `default_node_port`, `inner_fakedns`, `rules`, `remote_strategy`, `remote_server_domain_resolver`, `fakedns_tag`, and global functions `add_rule_set`, `parse_rule_set`, `geo_rule_set`, `get_node_by_id`, `gen_urltest_outbound`, `set_outbound_detour`, `gen_outbound_get_tag`. In Rust put them in a per-generation context struct.

---

## 2. Geo / rule-set helpers

### 2.1 `check_geoview()` → 1 | 0
```
if GEO_VAR.OK == nil:
    GEO_VAR.OK = (finded_com("geoview") and compare_versions(get_app_version("geoview"), ">=", "0.1.10")) ? 1 : 0
if OK == 0:
    log(0, "!!! Note: Geo rules cannot be used if the Geoview component is missing or the version is too low.")
else:
    asset = uci_get("passwall2", "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
    GEO_VAR.DIR = asset:match("^(.*)/")       -- greedy: everything before the LAST "/"
        -- "/usr/share/v2ray/" -> "/usr/share/v2ray";  "/usr/share/v2ray" -> "/usr/share" (quirk, preserve)
    SITE_PATH = DIR.."/geosite.dat"; IP_PATH = DIR.."/geoip.dat"
    mkdir TO_SRS_PATH if not exists
return OK
```
(The warning is logged on every call while OK==0.)

### 2.2 `geo_convert_srs(var)` (exported)
Input keys: `geo_path`, `prefix` ("geosite"|"geoip"), `rule_name`.
```
if check_geoview() != 1: return
out = TO_SRS_PATH .. prefix .. "-" .. rule_name .. ".srs"
bin = finded_com("geoview")   -- path of binary
if !exists(out) and bin:
   cmd = "<bin>" -type "<prefix>" -action convert -input "<geo_path>" -list "<rule_name>" -output "<out>" -lowmem=true
         (each arg Lua %q-quoted = double-quoted with \" \\ escaping)
   code,out_text = exec_call(cmd)    -- captures stdout+stderr and exit code
   if code != 0 or !exists(out):
       log(0, "  - <prefix>:<rule_name> convert to srs failed! [<out_text>]")
```
Existing `.srs` files are never regenerated (cache in tmpfs).

### 2.3 `convert_geofile()` (local)
If `check_geoview()==1`: for each key in `SITE_TAGS` (if non-empty and `SITE_PATH` exists) → `geo_convert_srs{geo_path=SITE_PATH, prefix="geosite", rule_name=k}`; same for `IP_TAGS` with `IP_PATH`/"geoip".

### 2.4 `parse_rule_set(w, rs)` (inside gen_config)
Input forms: `local:/abs/path/name.srs|.json` or `remote:https://host/.../name.srs|.json`.
```
if w empty → nil
if w starts with "local:" or "remote:":
   _type = text before first ":"   ("local"/"remote")
   w = rest after first ":"
   filename = substring after the LAST "/" of w
   suffix = substring after the LAST "." of filename ("" if none)
   format = "binary" if suffix=="srs"; "source" if suffix=="json"; else → nil (rule ignored)
   tag = filename up to (not including) the FIRST "."      -- "geosite-a.b.srs" -> "geosite-a"
   if tag non-empty:
       if rs: tag = "rs_" .. tag
       return { type=_type, tag=tag, format=format,
                path = (_type=="local") ? w : nil,
                url  = (_type=="remote") ? w : nil }
return nil
```
### 2.5 `geo_rule_set(prefix, name)` → `parse_rule_set("local:" .. TO_SRS_PATH .. prefix .. "-" .. name .. ".srs")` (no `rs_` prefix) → tag `geosite-<name>` / `geoip-<name>`, type `local`, format `binary`, path `/tmp/etc/passwall2_tmp/singbox_srss/<prefix>-<name>.srs`. Note it is produced regardless of geoview availability.

### 2.6 `add_rule_set(tab)` — insert into `rule_set_table[tab.tag]` only if tab non-empty, has tag and tag not already present (first wins).

### 2.7 `get_log_level(s)` — `"warning"` → `"warn"`; anything else unchanged (nil stays nil).

---

## 3. `gen_outbound(flag, node, tag, proxy_table)` → outbound table | nil

`node` is a UCI `nodes` section table (or a synthesized one). Returns a sing-box outbound with internal fields `_id`, `_flag`, `_flag_proxy_tag` (stripped before output).

### 3.1 Prologue
```
if node == nil → return nil
node_id = node[".name"]; if tag == nil: tag = node_id
remarks = node.remarks
if proxy_table is table:
   proxy_tag = proxy_table.tag
   excluded = node.protocol in {"naive","masque"} or node.hysteria2_realms truthy
   fragment        = (proxy_table.fragment and !excluded) ? true : nil
   record_fragment = (proxy_table.record_fragment and !excluded) ? true : nil
```

### 3.2 Non-sing-box nodes (node.type != "sing-box") — run a separate core as local socks
```
run_socks_instance = true
if NO_RUN:
    TMP_PORT = TMP_PORT ? TMP_PORT+1 : 3001;  new_port = TMP_PORT; run_socks_instance = false
else:
    relay_port = (proxy_tag and node.port) ? tostring(node.port) : ""
    if relay_port == "":
        cache = get_cache_var("node_<node_id>_socks_port")       -- via utils.sh get_cache_var
        if cache: new_port = cache; run_socks_instance = false
    if run_socks_instance:
        new_port = api.get_new_port()       -- utils.sh get_new_port auto tcp,udp
        config_file = "nodesocks_<node_id>_<new_port>.json"
        if tag and node_id and tag does NOT contain node_id (Lua pattern find):
            config_file = "nodesocks_<tag>_<node_id>_<new_port>.json"
        sys.call('/usr/share/passwall2/app.sh run_socks "flag=<new_port> node=<node_id> bind=127.0.0.1 socks_port=<new_port> config_file=<config_file> relay_port=<relay_port>"> /dev/null')
        if relay_port == "": set_cache_var("node_<node_id>_socks_port", new_port)
if new_port:
    node = { protocol="socks", address="127.0.0.1", port=new_port }     -- replaces node entirely
    proxy_tag = "socks <- " .. node_id
```
(The replacement node has no tls/mux/transport, so result is a plain socks5 outbound to 127.0.0.1:new_port. `remarks` was captured earlier so the tag still gets `:remarks`.)

For sing-box nodes: `if proxy_tag: node.detour = proxy_tag`.

### 3.3 Base result
```
if remarks: tag = tag .. ":" .. remarks
node.address = lower(node.address or "")
result = {
  _id = node_id, _flag = flag, _flag_proxy_tag = proxy_tag,
  tag = tag, type = node.protocol, server = node.address, server_port = tonumber(node.port),
  domain_resolver = { server = "local", strategy = node.domain_strategy },
  detour = node.detour
}
```
UCI option `domain_strategy` (sing-box strategy string: `prefer_ipv4`/`prefer_ipv6`/`ipv4_only`/`ipv6_only`, nil = unset).

### 3.4 Per-node DNS resolver
Condition: `datatypes.hostname(node.address)` (luci hostname: not a pure IPv4/IPv6 literal) **and** `node.domain_resolver` set **and** (`node.domain_resolver_dns` or `node.domain_resolver_dns_https`).
```
dns_tag = node_id .. "_dns"; proto = node.domain_resolver     -- "udp" | "tcp" | "https" (any value passed through as type)
if proto == "https":
    u = parseURL(node.domain_resolver_dns_https)   -- {hostname, port(number|nil), pathname}
    if u: addr=u.hostname; port=u.port or 443; path=u.pathname
else:
    addr = node.domain_resolver_dns; port = 53
    parts = split(addr, ":"); if #parts > 1: addr = parts[1]; port = tonumber(parts[last])
GLOBAL.DNS_SERVER[node_id] = {
   server = { tag=dns_tag, type=proto, server=addr, server_port=port, path=path,
              domain_resolver="local", detour="direct" },
   domain = node.address }
result.domain_resolver.server = dns_tag
```

### 3.5 TLS block
Pre-processing:
- if protocol == `masque`: clear `alpn, utls, reality, transport, mux`.
- if protocol ∈ {`hysteria`,`hysteria2`,`tuic`,`naive`,`masque`}: force `node.tls = "1"`.

If `node.tls == "1"`:
```
alpn = (node.alpn and node.alpn != "default") ? split(node.alpn, ",") : nil
tls = {
  enabled = true,
  disable_sni = node.tls_disable_sni == "1",
  server_name = node.tls_serverName,
  insecure = node.tls_allowInsecure == "1",
  alpn = alpn,
  fragment = fragment, record_fragment = record_fragment,
  certificate = (node.tls_certificate=="1" and node.tls_certificate_pem != "")
                ? split(replace(node.tls_certificate_pem, "\\n"(literal backslash-n), "\n"), "\n") : nil,
  cipher_suites = (node.cipherSuites non-empty) ? (list as-is if UCI list, else split(str, ":")) : nil,
  ech = (node.ech == "1") ? ECH() : nil,
  utls = (node.utls=="1" or node.reality=="1") ? { enabled=true, fingerprint = node.fingerprint or "chrome" } : nil,
  reality = (node.reality=="1") ? { enabled=true, public_key=node.reality_publicKey, short_id=node.reality_shortId } : nil
}
if version_ge_1_15_0:
    if node.tls_pinSHA256 non-empty: tls.certificate_sha256 = [ sha256_xray_sb(node.tls_pinSHA256) ]
else:
    tls.insecure = (tls_allowInsecure=="1") or (tls_pinSHA256 non-empty)     -- pin unsupported → just insecure
```
`sha256_xray_sb(str)`: if base64-decoding str yields exactly 32 bytes (and differs from input) → return str unchanged; else strip `:`, if 64 hex chars → return base64(binary of hex); else return str.

Edge: `tls_certificate=="1"` with `tls_certificate_pem` nil crashes in Lua; Rust: treat nil as empty → no certificate.

ECH():
```
get_ech_domain(s):            -- xray compat "domain+DNS" format
    m = s =~ ^([^+]+)\+(.+)$ ; else nil
    dns must start with http:// https:// tcp:// udp:// h2c://  else nil
    domain must match ^[A-Za-z0-9.-]+\.[A-Za-z]+$  else nil
    return domain
ech = { enabled = true }
config = node.ech_config; qname = node.ech_query_server_name
if config and not qname:
    qname = get_ech_domain(config)
    if not qname and config lacks both a "-+\s*BEGIN" and "-+\s*END" marker:
        config = "-----BEGIN ECH CONFIGS-----\n" .. remove_all_whitespace(config) .. "\n-----END ECH CONFIGS-----"
if qname:        ech.query_server_name = qname; ech_domain[qname] = true
elif config:     ech.config = split(replace(config, "\\n", "\n"), "\n")
elif tls_serverName non-empty: ech_domain[tls_serverName] = true     -- ech fetched via DNS for SNI
return ech
```

### 3.6 Multiplex (client)
If `node.mux == "1"`:
```
{ enabled=true, protocol = node.mux_type or "h2mux",
  max_connections = (node.tcpbrutal=="1") ? 1 : (tonumber(node.mux_concurrency) or 4),
  padding = node.mux_padding == "1",
  brutal = { enabled = node.tcpbrutal=="1", up_mbps = tonumber(node.tcpbrutal_up_mbps) or 10,
             down_mbps = tonumber(node.tcpbrutal_down_mbps) or 50 } }
```

### 3.7 V2Ray transport (client) — option `transport`
| transport | JSON |
|---|---|
| `tcp` + `tcp_guise=="http"` + `tcp_guise_http_host` non-empty | `{type:"http", host: node.tcp_guise_http_host (list), path: first element of list tcp_guise_http_path, or "/" if missing/empty, headers: user_agent ? {"User-Agent": user_agent} : nil}` |
| `http` | `{type:"http", host: node.http_host or [] , path: node.http_path or "/", headers: UA as above, idle_timeout: http_h2_health_check=="1" ? format_go_time(http_h2_read_idle_timeout,"15s") : nil, ping_timeout: http_h2_health_check=="1" ? format_go_time(http_h2_health_check_timeout,"15s") : nil}` |
| `ws` | `{type:"ws", path: ws_path or "/", headers: (ws_host or user_agent) ? {Host: ws_host, "User-Agent": user_agent} : nil, max_early_data: tonumber(ws_maxEarlyData), early_data_header_name: ws_earlyDataHeaderName}` |
| `httpupgrade` | `{type:"httpupgrade", host: httpupgrade_host, path: httpupgrade_path or "/", headers: UA}` |
| `quic` | `{type:"quic"}` |
| `grpc` | `{type:"grpc", service_name: grpc_serviceName, idle_timeout: grpc_health_check=="1" ? format_go_time(grpc_idle_timeout,"15s"), ping_timeout: grpc_health_check=="1" ? format_go_time(grpc_health_check_timeout,"15s"), permit_without_stream: grpc_permit_without_stream=="1" ? true : nil}` |

`format_go_time(input, default)`: trim; pure digits → seconds; else sum all `(\d+)\s*([hms])`; if total ≤ 0 → default (or "0s"); render as `<h>h<m>m<s>s` omitting zero parts (seconds shown if nothing else).

### 3.8 Protocol-specific fields (merged into result, overwriting same keys)
`user+pass` below means: username/password emitted only when **both** `node.username` and `node.password` are set.

- **socks**: `version:"5"`, user+pass (`username`,`password`), `udp_over_tcp: uot=="1" ? {enabled:true, version:2} : nil`.
- **http**: user+pass, `path:nil`, `headers:nil`, `tls`.
- **shadowsocks**: `method: ss_method`, `password: password or ""`, `plugin: plugin_enabled ? plugin : nil`, `plugin_opts: plugin_enabled ? plugin_opts : nil` (note: truthiness of the option string, "0" is truthy in Lua — preserve: any non-nil `plugin_enabled` enables), `udp_over_tcp` as socks, `multiplex: mux`.
- **shadowsocksr**: `method: ssr_method`, `password: password or ""`, `obfs: ssr_obfs`, `obfs_param: ssr_obfs_param`, `protocol: ssr_protocol`, `protocol_param: ssr_protocol_param`.
- **trojan**: `password`, `tls`, `multiplex`, `transport`.
- **vmess**: `uuid`, `security`, `alter_id: tonumber(alter_id) or 0`, `global_padding: global_padding=="1"`, `authenticated_length: authenticated_length=="1"`, `tls`, `packet_encoding: ""`, `multiplex`, `transport`.
- **vless**: `uuid`, `flow: (tls=="1" and flow) ? flow : nil`, `tls`, `packet_encoding:"xudp"`, `multiplex`, `transport`.
- **wireguard**:
  - `wireguard_reserved`: if it contains only digits and commas → list of numbers (`"1,2,3"` → `[1,2,3]`); else base64-decode → list of byte values; empty → nil.
  - fields: `system_interface: wireguard_system_interface=="1"`, `interface_name: wireguard_interface_name`, `local_address: wireguard_local_address` (UCI list), `private_key: wireguard_secret_key`, `peer_public_key: wireguard_public_key`, `pre_shared_key: wireguard_preSharedKey`, `reserved`, `mtu: tonumber(wireguard_mtu)`. (Converted to an endpoint later, §4.10.)
- **hysteria** (v1):
  - if `hysteria_hop`: replace `-` with `:`, split on `,`, keep items matching `^\d+:\d+$` → `server_ports`; and set `result.server_port = nil` (even if no valid ranges).
  - `server_ports` (nil if empty), `hop_interval`: only if ports non-empty: `v = leading digits of (hysteria_hop_interval or "30")`; `v>=5 ? v.."s" : "30s"`.
  - `up_mbps: tonumber(hysteria_up_mbps)`, `down_mbps: tonumber(hysteria_down_mbps)`, `obfs: hysteria_obfs`, `auth: hysteria_auth_type=="base64" ? hysteria_auth_password`, `auth_str: hysteria_auth_type=="string" ? hysteria_auth_password`, `stream_receive_window: tonumber(hysteria_recv_window_conn)`, `connection_receive_window: tonumber(hysteria_recv_window)`, `disable_path_mtu_discovery: hysteria_disable_mtu_discovery=="1"`, `tls`.
- **shadowtls**: `version: tonumber(shadowtls_version)`, `password: version in {"2","3"} ? password : nil`, `tls`.
- **tuic**: `uuid`, `password`, `congestion_control: tuic_congestion_control or "cubic"`, `udp_relay_mode: tuic_udp_relay_mode or "native"`, `udp_over_stream:false`, `zero_rtt_handshake: tuic_zero_rtt_handshake=="1"`, `heartbeat: (tonumber(tuic_heartbeat) or 3).."s"`, `tls`. Then ALPN: `tuic_alpn` (if missing or "default" → `"h3"`) split by `,`; if non-empty → `tls.alpn = list` (overrides generic alpn).
- **hysteria2**:
  - hop parsing same as hysteria with `hysteria2_hop` (sets `result.server_port=nil` when option set). If `hysteria2_realms` truthy → `server_ports = {}`.
  - interval (only if server_ports non-empty): default `"30s"`; `t = hysteria2_hop_interval or "30s"`; if `t` contains `-`: match `^(\d+)-(\d+)$` → `min=max(min,5)`, `max = max>=min ? max : min` → `hop_interval=min.."s"`, `hop_interval_max=max.."s"` (no match → stays "30s"); else `t = leading digits`, `t>=5 ? t : 30` → `t.."s"`.
  - `up_mbps`/`down_mbps`: `tonumber(hysteria2_up_mbps|down_mbps)` or nil.
  - `obfs`: if `hysteria2_obfs_type` non-empty → `{type, password: hysteria2_obfs_password}`; if type == `gecko`: `min = tonumber(hysteria2_obfs_MinPacketSize) or 512`, `max = tonumber(hysteria2_obfs_MaxPacketSize) or 1200`; if `min<=0 or min>max or max>2048` → 512/1200; set `min_packet_size`, `max_packet_size`.
  - `password: hysteria2_auth_password`.
  - `idle_timeout` (≥1.14 only): `t = leading digits of (hysteria2_idle_timeout or "30")`; `4<=t<=120 ? t.."s" : "30s"`.
  - `keep_alive_period` (≥1.14 only): `t = leading digits of (hysteria2_keep_alive_period or "0")`; `2<=t<=60 ? t.."s" : nil`.
  - `stream_receive_window: tonumber(hysteria2_stream_recv_win) .. " MB"` (string, e.g. `"8 MB"`) or nil; `connection_receive_window` likewise from `hysteria2_conn_recv_win`.
  - `disable_path_mtu_discovery`: ≥1.14 → `hysteria2_disable_mtu_discovery=="1"` (bool); else nil.
  - `tls`.
  - `realm` (if `hysteria2_realms` truthy): set `result.server=nil`, `result.server_port=nil`; `r = parse_realm_uri(hysteria2_realm_url)`; if r: `server_url = (scheme=="realm+http" ? "http://" : "https://") .. r.server_url`; `stun_servers = r.stun_servers or node.hysteria2_realm_stun` (UCI list); delete `scheme,address,port`; `port_mapping = hysteria2_realm_upnp=="1" ? {enabled:true} : nil`. Output keys: `token, server_url, realm_id, stun_servers, port_mapping`.
  - `parse_realm_uri(uri)`: `realm[+http]://<token>@<host[:port]>/<realm_id>[?query]`; realm_id trailing `/` stripped; `stun=` (case-insensitive key) query params collected into `stun_servers` list; returns nil if scheme/token/host/realm_id missing.
- **anytls**: `password: password or ""`, `idle_session_check_interval:"30s"`, `idle_session_timeout:"30s"`, `min_idle_session:5`, `disable_reuse: anytls_disable_reuse=="1" ? true : nil`, `client_metadata: version>=1.13.16 ? "anytls/0.0.13" : nil`, `tls`.
- **ssh**: `user: username non-empty ? username : "root"`, `password: password or ""`, `private_key: ssh_priv_key`, `private_key_passphrase: ssh_priv_key_pp`, `host_key: ssh_host_key`, `host_key_algorithms: ssh_host_key_algo`, `client_version: ssh_client_version`.
- **naive**: `username: username or ""`, `password: password or ""`, `insecure_concurrency: tonumber(naive_insecure_concurrency or 0) > 0 ? that : 0`, `udp_over_tcp: uot=="1" ? {enabled:true,version:2} : false`, `extra_headers: user_agent ? {"User-Agent": ua} : nil`, `quic: naive_quic=="1"`, `quic_congestion_control: naive_quic=="1" ? naive_congestion_control : nil`, `tls`.
- **masque**: headers map (key → **array** of one string): if `user_agent` non-empty → `"user-agent": [ua]`; then each line of `masque_headers` (literal `\n` converted to newline; split on CR/LF), match `^\s*([^:]+):\s*(.-)\s*$` → `headers[lower(trim(key))] = [value]`. Fields: **`type: "masque-client"` (overrides type)**, `username`/`password`: only when no `authorization` header, `path: masque_path` non-empty or nil, `headers` (nil if empty), `tls`. (Moved to endpoints later.)
- **snell**: `version: tonumber(snell_version)`, `psk: snell_psk`, `userkey: password`, `reuse: snell_reuse=="1"`, `network: snell_network`, `obfs_mode`/`obfs_host`: only if `snell_version=="4"` (from `snell_obfs_mode`, `snell_obfs_host`), `mode: snell_version=="6" ? snell_mode : nil`.
- any other protocol: no extra fields.

---

## 4. `gen_config(var)` — client config

### 4.1 Input variables (`var`, all strings)
| key | default | meaning |
|---|---|---|
| `flag` | (required) | instance id: `"global"`, `"acl_<id>"`, socks flag etc. |
| `log` | `"0"` | `"0"` → log disabled |
| `loglevel` | `"warn"` | sing-box level (warning→warn) |
| `logfile` | `/dev/null` | log.output |
| `node` | — | node section id |
| `server_host`,`server_port` | — | override address/port of the outbound whose tag is `"default"` |
| `tcp_proxy_way` | — | `"tproxy"` or other (redirect) |
| `redir_port` | — | transparent inbound port |
| `local_socks_address` | `0.0.0.0` | |
| `local_socks_port`,`local_socks_username`,`local_socks_password` | — | |
| `local_http_address` | `0.0.0.0` | |
| `local_http_port`,`local_http_username`,`local_http_password` | — | |
| `dns_listen_port` | — | enables DNS inbound and full DNS logic |
| `direct_dns_udp_server`/`_port`, `direct_dns_tcp_server`/`_port` | port 53 | direct DNS |
| `direct_dns_query_strategy` | — | `UseIPv4`/`UseIPv6`/other |
| `direct_ipset`, `direct_nftset` | — | comma lists, flushed on route change |
| `remote_dns_udp_server`/`_port`, `remote_dns_quic` | | |
| `remote_dns_tcp_server`/`_port`, `remote_dns_tls` | | |
| `remote_dns_doh_url`, `remote_dns_doh_host`, `remote_dns_doh_ip`, `remote_dns_doh_port` (unused), `remote_dns_http3` | | |
| `remote_dns_detour` | — | `"direct"` to send remote DNS directly |
| `remote_dns_query_strategy` | — | `UseIPv4`/`UseIPv6`/other |
| `remote_dns_fake` | — | `"1"` enables fakeip |
| `remote_dns_client_ip` | — | EDNS client subnet |
| `remote_rewrite_ttl` | `"30"` | |
| `dns_cache` | — | `"0"` → dns.disable_cache true |
| `no_run` | — | sets global `NO_RUN` (dry run: no subprocesses, fake ports) |

UCI read: `@global_singbox[0]` options `fragment`, `record_fragment` ("1" → enable TLS fragment / record fragment on node outbounds built through shunt/urltest paths).

### 4.2 Inbounds and initial route rules (in this order)
1. If `local_socks_port`: `{type:"socks", tag:"socks-in", listen: local_socks_address, listen_port}`; `users:[{username,password}]` if both non-empty. Route rule `{action:"sniff", inbound:"socks-in"}`.
2. If `local_http_port`: `{type:"http", tag:"http-in", listen, listen_port}` + users likewise. **No sniff rule.**
3. If `redir_port`:
   - tproxy inbound `{type:"tproxy", tag:"tproxy", listen:"::", listen_port}`.
   - if `tcp_proxy_way != "tproxy"`: add `{type:"redirect", tag:"redirect_tcp", listen:"::", listen_port}` + sniff rule for it; and tproxy becomes `tag:"tproxy_udp", network:"udp"`.
   - add tproxy inbound + sniff rule for its tag.

### 4.3 Node normalization
`node = uci_get("passwall2", node_id)` if node_id.
If node exists and `node.protocol != "_shunt"`: wrap into synthetic shunt:
```
node = { remarks = node.remarks, type="sing-box", protocol="_shunt", default_node = <orig id>,
         fakedns = remote_dns_fake, default_fakedns = remote_dns_fake }
```
If `server_host` and `server_port` → globals `default_node_address/port`.

### 4.4 `get_node_by_id(id_or_table)`
- table → section = it; string "" or "nil" → nil; string → `uci_get(id) or {}`; other → nil.
- section `.type == "socks"` (a passwall2 socks instance) → synthesized `{".name"=id, remarks="socks[<port>]", type="sing-box", protocol="socks", address="127.0.0.1", port=section.port, uot="1"}`.
- `.type == "nodes"` → section; else nil.

### 4.5 `gen_urltest_outbound(_node)` → (outbound, exist)
```
tag = "urltest-" .. _node[".name"]
if an outbound with that tag already in outbounds → return it, true
ut_nodes = (node_add_mode == "batch") ? api.get_batch_nodes(_node) : _node.urltest_node (UCI list)
   -- get_batch_nodes: all valid "normal" nodes without chain_proxy whose group (default "default",
   --  case-insensitive, URL-decoded group names from space-separated node_group) matches and
   --  remarks match node_match_rule.
valid = []
for each id in ut_nodes:
    prefix = "ut-" .. id
    if some existing outbound.tag starts with prefix → valid += that tag
    else t = gen_outbound_get_tag(flag, id, prefix, {fragment: global_singbox.fragment=="1" or nil,
                                                    record_fragment: global_singbox.record_fragment=="1" or nil})
         if t → valid += t
if valid empty → return nil
return { type:"urltest", tag, outbounds: valid,
         url: urltest_url or "https://www.gstatic.com/generate_204",
         interval: format_go_time(urltest_interval) != "0s" ? that : "3m",
         tolerance: (urltest_tolerance and tonumber > 0) ? number : 50,
         idle_timeout: format_go_time(urltest_idle_timeout) != "0s" ? that : "30m",
         interrupt_exist_connections: urltest_interrupt_exist_connections in {"true","1"} }
```
(Not inserted here; caller inserts.)

### 4.6 `set_outbound_detour(node, outbound, outbounds_table)` → (default_tag, last_insert_outbound)
```
default_tag = outbound.tag; last = nil
-- ShadowTLS wrapper
if node.shadowtls == "1":
   st = gen_outbound(nil, {type:"sing-box", protocol:"shadowtls", shadowtls_version, 
          password: version in {"2","3"} ? node.shadowtls_password : nil,
          address: node.address, port: node.port, tls:"1", tls_serverName: node.shadowtls_serverName,
          utls: node.shadowtls_utls, fingerprint: node.shadowtls_fingerprint}, outbound.tag.."_shadowtls")
   if st: last = st; outbound.detour = outbound.tag.."_shadowtls"; outbound.server = nil; outbound.server_port = nil
-- chain_proxy "1": pre-proxy (front)
if node.chain_proxy == "1" and node.preproxy_node and not outbound._flag_proxy_tag:
   p = get_node_by_id(node.preproxy_node)
   if p:
      if p.protocol == "_urltest": po, exist = gen_urltest_outbound(p) else po = gen_outbound(node[".name"], p)
      if po: outbound.tag = po.tag .. " -> " .. outbound.tag; outbound.detour = po.tag
             if not exist: last = po          -- (overrides shadowtls 'last' if both — quirk)
             default_tag = outbound.tag
-- chain_proxy "2": landing node (to_node, back)
if node.chain_proxy == "2" and node.to_node:
   t = get_node_by_id(node.to_node); if t and t.protocol starts with "_": t = nil
   if t:
      chained = outbound.tag .. " -> " .. t[".name"] .. (t.remarks ? ":"..t.remarks : "")
      if any outbounds_table[i].tag == chained → return chained, last
      if t.type != "sing-box":
          tag = t[".name"]; p = get_new_port()
          inbounds += {type:"direct", tag, listen:"127.0.0.1", listen_port:p,
                       override_address: t.address, override_port: tonumber(t.port)}
          rules.insert(1, {action:"route", inbound:[tag], outbound: outbound.tag})   -- front of shunt rules
          if t.tls_serverName == nil: t.tls_serverName = t.address
          t.address = "127.0.0.1"; t.port = p
          to = gen_outbound(node[".name"], t, tag, {tag = tag})   -- external core relays via 127.0.0.1:p
      else:
          to = gen_outbound(node[".name"], t)
      if to: to.tag = outbound.tag .. " -> " .. to.tag
             if t.type == "sing-box": to.detour = outbound.tag
             outbounds_table.append(to); default_tag = to.tag
-- chain_proxy "3": bind interface
if node.chain_proxy == "3" and node.outbound_iface: outbound.detour = nil; outbound.bind_interface = node.outbound_iface
return default_tag, last
```

### 4.7 `gen_outbound_get_tag(flag, node_id, tag, proxy_table)` → tag | nil
```
if not node_id or node_id == "nil" → nil
node = get_node_by_id(node_id); if not tag: tag = node[".name"]
if node:
   if proxy_table.chain_proxy in {"1","2"}:   -- inject chain from shunt pre-proxy
       node.chain_proxy = proxy_table.chain_proxy
       node.preproxy_node = (cp=="1") and proxy_table.preproxy_node     -- false otherwise
       node.to_node      = (cp=="2") and proxy_table.to_node
       clear those three keys in proxy_table
   if node.protocol == "_urltest":
       outbound, exist = gen_urltest_outbound(node)
       if exist and not node.chain_proxy → return outbound.tag
   elif node.protocol == "_iface":
       if node.iface: outbound = {tag, type:"direct", bind_interface: node.iface, routing_mark:255}
                      sh: mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>
   else:
       if tag == "default" and default_node_address and default_node_port: node.address/port = those
       for o in outbounds: if o._flag_proxy_tag contains "socks <- "..node[".name"] (plain substring):
            outbound = deep_clone(o); outbound.tag = tag; break      -- reuse spawned socks instance
       if not outbound: outbound = gen_outbound(flag, node, tag, proxy_table)
   if outbound:
       dtag, last = set_outbound_detour(node, outbound, outbounds)
       if not exist: outbounds.append(outbound)
       if last: outbounds.append(last)
       return dtag
```
Note: insertion order: main outbound first, then shadowtls/preproxy outbound; landing outbound (chain 2) was appended inside set_outbound_detour **before** the main one.

### 4.8 Shunt processing (`node.protocol == "_shunt"`)
```
rules = []                         -- shunt rules, later appended to route.rules
inner_fakedns = node.fakedns or "0"
gen_shunt_node(rule_name, _node_id = node[rule_name]):
    nil rule_name → nil
    "_direct"    → "direct"
    "_blackhole" → "block"
    "_default" and rule_name != "default" → "default"
    other non-nil id:
        pt = { fragment: global_singbox.fragment=="1", record_fragment: global_singbox.record_fragment=="1" }
        pre = node[rule_name .. "_proxy_tag"]; if pre == _node_id: pre = nil
        if pre: pt.chain_proxy="2"; pt.to_node=_node_id; return gen_outbound_get_tag(flag, pre, rule_name, pt)
        else:   return gen_outbound_get_tag(flag, _node_id, rule_name, pt)
    nil → nil
COMMON.default_outbound_tag = gen_shunt_node("default", node.default_node or "_direct")
if inner_fakedns == "1" and node.default_fakedns == "1": remote_dns_fake = true
```
So the outbound tag for a shunt rule = `<rule_section_id>:<node remarks>` (or chained forms); default = `default:<remarks>`.

UCI options on the `_shunt` node: `default_node`, `shunt_group`, `fakedns`, `default_fakedns`, `<rule_id>` (node id / `_direct` / `_blackhole` / `_default`), `<rule_id>_proxy_tag` (pre-proxy node id), `<rule_id>_fakedns`.

For each `shunt_rules` section `e` (UCI order), only if `node.shunt_group == e.group` (nil==nil matches, but synthetic node has no `<rule_id>` options so yields nothing):
```
out = gen_shunt_node(e[".name"])
skip unless out and e.remarks
if out == "default": out = COMMON.default_outbound_tag
protocols = e.protocol non-empty ? split(e.protocol, " ") : nil       -- sniffed protocols: http tls quic bittorrent ...
inboundTag = nil
if e.inbound non-empty:
    inboundTag = []
    if e.inbound contains "tproxy" and redir_port:
        tcp_proxy_way=="tproxy" ? ["tproxy"] : ["redirect_tcp","tproxy_udp"]
    if e.inbound contains "socks" and local_socks_port: += "socks-in"
    -- may stay empty (emits empty table; Rust: emit [] — matches nothing in sing-box? see note)
rule = {action:"route", inbound: inboundTag, outbound: out, protocol: protocols}
if out == "block": rule.action = "reject"; rule.outbound = nil
if e.network: rule.network = split(e.network, ",")          -- "tcp","udp"
if e.source:  tokens split by " ": "geoip:private" → source_ip_is_private=true;
              other "geoip:*" tokens DROPPED; everything else → source_ip_cidr[]
if e.port:    split ","; numeric 1..65535 → port[] (numbers) else → port_range[] (string, as-is e.g. "1000:2000")
rule_set = []
if e.domain_list:  (lines split on CR/LF)
    dt = {shunt_tag: e[".name"], outboundTag: out, domain:[], domain_suffix:[], domain_keyword:[], domain_regex:[], rule_set:[],
          fakedns:nil, invert: e.invert=="1" or nil}
    per line w:
       starts "#"           → skip
       "geosite:<n>"        → t = geo_rule_set("geosite", n); if t: SITE_TAGS[n]=true; add_rule_set(t); rule_set+=t.tag; dt.rule_set+=t.tag
       "regexp:<x>"         → domain_regex
       "full:<x>"           → domain
       "domain:<x>"         → domain_suffix
       "rule-set:<spec>" | "rs:<spec>" → t = parse_rule_set(spec, rs=true) (tag "rs_<name>"); add; rule_set+=; dt.rule_set+=
       otherwise (incl. "keyword:..." which is NOT stripped) → domain_keyword (whole line)
    rule.domain/domain_suffix/domain_keyword/domain_regex/rule_set = non-empty lists or nil
    if inner_fakedns=="1" and node[e.name.."_fakedns"]=="1": dt.fakedns = true
    if any domain field non-empty: dns_domain_rules.append(clone(dt))
if e.ip_list: (lines)
    "#..." skip; "geoip:private" → ip_is_private=true; "geoip:<n>" → geo_rule_set("geoip", n), IP_TAGS[n]=true, add, rule_set+=;
    "rule-set:"/"rs:" → parse_rule_set(spec,true), add, rule_set+=; else → ip_cidr[]
    rule.ip_is_private = true|nil; rule.ip_cidr = list|nil
rule.rule_set = rule_set non-empty ? rule_set : nil     -- union of domain + ip rule-sets
rule.invert = e.invert=="1" or nil
rules.append(rule)
```
Afterwards: `route.rules += rules` (after sniff rules). `route.final = COMMON.default_outbound_tag` if set.

Shunt rule UCI options consumed: `group, remarks, protocol, inbound, network, source, port, domain_list, ip_list, invert` (`sourcePort` is commented out — not used).

Note: there is no `block` outbound. Rules to `_blackhole` become `action: reject`.

### 4.9 DNS
```
dns = { servers:[], rules:[], disable_cache: dns_cache=="0", disable_expire:false,
        independent_cache:false, reverse_mapping:true }
servers += {type:"local", tag:"local"}
route.default_domain_resolver = {server:"local"}
if direct_dns_udp_server: servers += {tag:"direct", type:"udp", server, server_port: tonumber(port) or 53, detour:"direct"}
elif direct_dns_tcp_server: same with type "tcp"
for each v in GLOBAL.DNS_SERVER (unordered):
    if direct dns configured: v.server.domain_resolver = "direct"
    servers += v.server
    rules += {action:"route", server: v.server.tag, domain: v.domain}      -- domain is a string
direct_strategy = UseIPv4 → "ipv4_only"; UseIPv6 → "ipv6_only"; else "prefer_ipv6"
```

**If `dns_listen_port`** (full DNS mode):

a) Hosts:
```
if flag == "global": text = uci @global[0].dns_hosts or ""
else: flag = flag without "acl_" (mutates flag for the rest of the function!)
      mode = uci <flag>.dns_hosts_mode or "default"   -- section is the ACL rule id
      default → @global[0].dns_hosts; disable → ""; custom → <flag>.dns_hosts
if text non-empty:
   hosts = {tag:"hosts", type:"hosts", predefined:{}}; domains=[]
   per line: host = 1st whitespace field, value = 2nd field (original uses shell echo|awk); if both non-empty:
        predefined[host] = value (single string); domains += host
   if remote_dns_doh_ip and remote_dns_doh_host != remote_dns_doh_ip and not is_ip(remote_dns_doh_host):
        predefined[doh_host] = doh_ip; domains += doh_host; remote_server_domain_resolver = "hosts"
   if predefined non-empty: servers += hosts; rules += {query_type:["A","AAAA"], domain: domains, server:"hosts"}
```
Quirk: DoH bootstrap IP is only applied when the hosts text is non-empty.

b) Node-domain direct resolution (if direct DNS configured): run
`uci show passwall2 | grep ".address=" | cut -d "'" -f 2 | grep "[a-zA-Z]$" | sort -u` — i.e. all `address` option values in the passwall2 config ending in a letter (domains), lowercased → `dns_domain_rules.insert(1, {domain: list, outboundTag:"direct"})`.

c) Remote server:
```
remote_strategy = UseIPv4→ipv4_only, UseIPv6→ipv6_only, else prefer_ipv6
remote = {tag:"remote", domain_resolver: remote_server_domain_resolver or "direct", detour: COMMON.default_outbound_tag}
if remote_dns_detour == "direct": remote.detour = "direct"
if remote_dns_udp_server: type "udp", server, port tonumber(udp_port) or 53; if remote_dns_quic: type "quic", port = 853 (forced)
elif remote_dns_tcp_server: type "tcp", port or 53; if remote_dns_tls: type "tls", port = 853 (forced)
elif remote_dns_doh_url: u=parseURL; type "https" (or "h3" if remote_dns_http3); server=u.hostname; server_port=u.port or 443; path=u.pathname
servers += remote
```
Quirks: if default outbound is `block` the detour is `"block"` (nonexistent outbound); if default tag is nil the detour is absent.

d) FakeIP: `fakedns_tag = "remote_fakeip"`; if `remote_dns_fake` or `inner_fakedns=="1"`: servers += `{tag:"remote_fakeip", type:"fakeip", inet4_range:"198.18.0.0/16", inet6_range:"2001:2::/48"}`; `experimental.cache_file = {enabled:true, store_fakeip:true, path: CACHE_PATH.."/singbox_"..flag..".db"}`.

e) Final:
```
default_dns_flag = "remote"
if node_id and redir_port:
    n = get_node_by_id(node_id)        -- raw UCI node
    if n.protocol == "_shunt" and n.default_node == "_direct": default_dns_flag = "direct"
else: default_dns_flag = "direct"
dns.final = default_dns_flag; dns.strategy = "prefer_ipv6"   (always dual stack; per-domain blocking instead)
```

f) Per-shunt DNS rules, in dns_domain_rules order (node-domain direct rule first, then shunt rules in UCI order):
```
for v in dns_domain_rules with v.outboundTag and any domain field:
  r = {action:"route", server: v.outboundTag, domain/domain_suffix/domain_keyword/domain_regex/rule_set (non-empty or nil),
       disable_cache:false, invert: v.invert}
  if v.outboundTag == "block": r.action="predefined"; r.rcode="NOERROR"; drop disable_cache & server
  if v.outboundTag == "direct":
       if direct_strategy single-stack: b = clone(r); b.query_type = ipv4_only ? ["AAAA"] : ["A"];
            b.action="predefined"; b.rcode="NOERROR"; drop disable_cache, server; rules += b
       (r.server stays "direct")
  if not block/direct (proxied):
       r.server = "remote"; r.rewrite_ttl = tonumber(remote_rewrite_ttl)
       if remote_strategy single-stack: b = clone(r) with query_type ["AAAA"] (ipv4_only) / ["A"] (ipv6_only),
            action predefined, rcode NOERROR, drop disable_cache/server/rewrite_ttl; rules += b
       r.client_subnet = remote_dns_client_ip
       if v.outboundTag != COMMON.default_outbound_tag and remote.server and remote_dns_detour != "direct":
            s = clone(remote); s.tag = v.shunt_tag; s.detour = v.outboundTag; servers += s; r.server = s.tag
       if v.fakedns:
            f = clone(r); f.query_type = ipv4_only ? ["A"] : ipv6_only ? ["AAAA"] : ["A","AAAA"]
            f.server = "remote_fakeip"; f.rewrite_ttl = 1; f.disable_cache = true; f.client_subnet = nil; rules += f
  rules += r
```
g) Default remote tail (if default_dns_flag == "remote"):
```
qt = ["A","AAAA"]
ipv4_only: rules += {query_type:["AAAA"], action:"predefined", rcode:"NOERROR"}; qt=["A"]
ipv6_only: rules += {query_type:["A"], action:"predefined", rcode:"NOERROR"}; qt=["AAAA"]
if remote_dns_fake: rules += {query_type: qt, server:"remote_fakeip", disable_cache:true, rewrite_ttl:1}
rules += {server:"remote", disable_cache:true, rewrite_ttl: tonumber(remote_rewrite_ttl)}   -- match-all
```
h) DNS inbound: `inbounds += {type:"direct", tag:"dns-in", listen:"127.0.0.1", listen_port: tonumber(dns_listen_port)}`; route.rules.insert(1, sniff dns-in) then insert(1, `{action:"hijack-dns", inbound:"dns-in"}`) ⇒ final order `[hijack-dns(dns-in), sniff(dns-in), ...]`.

i) ipset/nftset flush on route change:
```
content = flag .. node_id .. jsonc.stringify(route.rules)     -- compact JSON; flag possibly acl_-stripped
changed = cacheFileCompareToLogic(CACHE_TEXT_FILE, content) == false
   -- reads file (if exists), if different: rm file, result false; always rewrites file with content
if changed:
   if direct_ipset: for name in split(","): `ipset -q -F <name>`
        for name in `ipset list | grep 'Name: ' | grep 'psw2_<node_id>_' | awk '{print $2}'`: `ipset -q -F <name>`
   if direct_nftset: for item in split(","): parts = split(item,"#"); if #parts > 3:
            `nft flush set <parts[2]=family> <parts[3]=table> <parts[4]=set> 2>/dev/null`
        for set in `nft -a list sets | grep -E 'psw2_<node_id>_' | awk -F 'set ' '{print $2}' | awk '{print $1}'`:
            `nft flush set inet passwall2 <set> 2>/dev/null`
```
(CACHE_TEXT_FILE uses the original flag.)

### 4.10 Post-processing (always)
1. ECH: if `ech_domain` non-empty: servers += `{tag:"ech-dns", type:"https", server:"223.5.5.5"}`; `dns.rules.insert(1, {domain:[...ech domains], server:"ech-dns"})`. (Happens even without dns_listen_port.)
2. If `COMMON.default_outbound_tag == "block"`: `route.final = nil`; route.rules += `{action:"reject"}`.
3. If rule_set_table non-empty: `route.rule_set = values(rule_set_table)` (order unspecified).
4. Config:
```
config = { log:{disabled: log=="0", level: get_log_level(loglevel), timestamp:true, output: logfile},
           dns, inbounds, outbounds, route, experimental }
outbounds += {type:"direct", tag:"direct", routing_mark:255}         -- always LAST
for o in outbounds:
   if not o._flag_proxy_tag and not o.detour and o._id and o.server and o.server_port and not NO_RUN:
        sh: echo '<o._id>' >> /tmp/etc/passwall2/direct_node_list      -- nodes connecting directly (for firewall bypass)
   if not o.detour and not o.bind_interface and o.server: o.detour = "direct"
   if o.server and not hostname(o.server) and not o.realm: o.domain_resolver = nil     -- IP server: no resolver
   delete keys starting with "_"
```
5. Endpoint migration (iterate outbounds from last to first):
   - `type=="wireguard"` → endpoint
     ```
     {type:"wireguard", tag, system: o.system_interface, name: o.interface_name, mtu: o.mtu,
      address: o.local_address, private_key: o.private_key,
      peers:[{address: o.server, port: o.server_port, public_key: o.peer_public_key,
              pre_shared_key: o.pre_shared_key, allowed_ips:["0.0.0.0/0"], reserved: o.reserved}],
      domain_resolver: o.domain_resolver, detour: o.detour}
     ```
     remove from outbounds.
   - `type=="masque-client"` → moved as-is to endpoints.
   - endpoints list is in reverse outbound order; `config.endpoints` only set when non-empty.
6. Return `jsonc.stringify(config, 1)`.

Final route.rules order: `[hijack-dns dns-in, sniff dns-in]` (DNS mode) + `sniff socks-in` + `sniff redirect_tcp` + `sniff tproxy|tproxy_udp` + (chain-2 relay route rules at front of shunt list) + shunt rules + optional trailing `{action:"reject"}`.

### 4.11 Typical outbound tags
- `direct` (direct, routing_mark 255), no `block` outbound.
- `default:<remarks>` / `<rule_id>:<remarks>` for shunt targets; `urltest-<id>` with children `ut-<id>:<remarks>`.
- `<pre_tag> -> <tag>` (pre-proxy), `<tag> -> <to_id>:<to_remarks>` (landing), `<tag>_shadowtls[:remarks]`.
- `socks <- <id>` appears only in internal `_flag_proxy_tag`.

---

## 5. `gen_config_server(node)` — server inbound
`node` = UCI `server`-type section (passwall2_server config / server_app). Output:
```
{ log:{disabled: node.log=="0", level: get_log_level(node.loglevel) or "info", timestamp:true},
  dns:{servers:[{type:"local", tag:"local"}]},
  endpoints:[...], inbounds:[...], outbounds:[...], route }
```
Steps:
1. outbounds = `[{type:"direct", tag:"direct"}]`. If protocol `masque`: `tls="1"`, `reality=nil`.
2. tls:
```
{ enabled:true,
  certificate_path: tls_use_pem != "1" ? tls_certificateFile : nil,
  key_path:         tls_use_pem != "1" ? tls_keyFile : nil,
  certificate: tls_use_pem=="1" and tls_certificate ? lines(tls_certificate with literal "\n"→newline) : nil,
  key:         tls_use_pem=="1" and tls_key ? lines(tls_key) : nil,
  alpn: alpn non-"default" ? split(",") (nil if empty) : nil }
if tls=="1" and reality=="1": clear cert/key fields; server_name = reality_handshake_server;
   reality = {enabled:true, private_key: reality_private_key, short_id:[reality_shortId],
              handshake:{server: reality_handshake_server, server_port: tonumber(reality_handshake_server_port)}}
if tls=="1" and ech=="1": tls.ech = {enabled:true, key: ech_key ? lines(ech_key) : nil}
```
3. mux (if `mux=="1"`): `{enabled:true, padding: mux_padding=="1", brutal:{enabled: tcpbrutal=="1", up_mbps: tonumber(tcpbrutal_up_mbps) or 10, down_mbps: tonumber(tcpbrutal_down_mbps) or 50}}`.
4. transport: `http` → `{type:"http", host: http_host or [], path: http_path or "/"}`; `ws` → `{type:"ws", path: ws_path or "/", headers: ws_host ? {Host: ws_host} : nil, early_data_header_name: ws_earlyDataHeaderName}`; `httpupgrade` → `{type, host: httpupgrade_host, path or "/"}`; `quic` → `{type:"quic"}`; `grpc` → `{type:"grpc", service_name: grpc_serviceName}`.
5. inbound = `{type: protocol, tag:"inbound", listen:"::", listen_port: tonumber(port)}`.
6. users: from UCI list `users` (section ids); each `uci_get_s(id)` (any config — section lookup) with `.type=="user"`:
| protocol | user object |
|---|---|
| mixed, socks, http, naive, masque | `{username, password}` |
| shadowsocks, trojan, hysteria2, anytls | `{name: username, password}` |
| vmess | `{name: username, uuid, alterId: 0}` |
| vless | `{name: username, uuid, flow: node.flow}` |
| hysteria | `{name: username, auth_str: password}` |
| tuic | `{name: username, password, uuid}` |
| wireguard | `{public_key: wireguard_public_key, pre_shared_key: wireguard_pre_shared_key, allowed_ips: allowed_ips or [], persistent_keepalive_interval: 0}` |
| snell | `{name: username, userkey: password}` |
   Empty result → nil.
7. Protocol fields merged into inbound:
- masque: `tls.alpn=nil`; `{type:"masque-server", users, path: masque_path non-empty, address: masque_address, mtu: tonumber(masque_mtu or 1280), tls}`.
- mixed: `{users, set_system_proxy:false}`; socks: `{users}`; http: `{users, tls: tls=="1" ? tls}`.
- shadowsocks: `{method: ss_method, password: ss_password, users, multiplex: mux}` (note option name `ss_password`).
- vmess / vless: only if users: `{users, tls: tls=="1" ? tls, multiplex, transport}`.
- trojan: only if users: same + `fallback:nil, fallback_for_alpn:nil`.
- naive: only if users: `{users, tls}`.
- hysteria: `{up: hysteria_up_mbps.." Mbps", down: hysteria_down_mbps.." Mbps", up_mbps, down_mbps (numbers), obfs: hysteria_obfs, users, stream_receive_window: tonumber(hysteria_recv_window_conn), connection_receive_window: tonumber(hysteria_recv_window_client), max_concurrent_streams: tonumber(hysteria_max_conn_client), disable_path_mtu_discovery: hysteria_disable_mtu_discovery=="1", tls}` (missing up/down crashes Lua; Rust: omit).
- tuic: `tls.alpn = tuic_alpn non-default ? split : nil`; `{users, congestion_control: tuic_congestion_control or "cubic", zero_rtt_handshake, heartbeat: (tonumber(tuic_heartbeat) or 3).."s", tls}`.
- hysteria2: `{up_mbps/down_mbps: only if hysteria2_ignore_client_bandwidth != "1" and numeric, obfs (same as client incl. gecko clamp), users, ignore_client_bandwidth: =="1", tls, realm}`; realm as client but additionally `stun_domain_resolver:"direct"` (server/server_port untouched).
- anytls: only if users: `{users, tls}`.
- wireguard: `inbound.listen=nil; system: wireguard_system_interface=="1"; name: "sbwg_"..node[".name"]; mtu: tonumber(wireguard_mtu or 1408); address: wireguard_local_address; private_key: wireguard_private_key; peers = users (if any)`. (keeps listen_port, tag "inbound", type "wireguard")
- snell: `{users, version: tonumber(snell_version), psk: snell_psk, obfs_mode: snell_version=="5" ? snell_obfs_mode, mode: snell_version=="6" ? snell_mode}` (server uses v5 for obfs; client uses v4 — preserve).
- direct: `{network: d_protocol != "TCP,UDP" ? d_protocol : nil, override_address: d_address, override_port: tonumber(d_port)}`.
8. wireguard and masque → `endpoints`; others → `inbounds`.
9. route = `{rules:[{ip_is_private:true, action: accept_lan=="1" ? "route" : "reject", outbound: accept_lan=="1" ? "direct" : nil}]}`.
10. Outbound via `outbound_node`:
   - `"_iface"` + `outbound_node_iface`: `{type:"direct", tag:"outbound", bind_interface: iface, routing_mark:255}`; sh `mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>`.
   - `"_socks"`/`"_http"`: synth node `{type: node.type, protocol:"socks"|"http", address: outbound_node_address, port: tonumber(outbound_node_port), username/password (non-empty or nil)}` → `gen_outbound(nil, t, "outbound")`.
   - otherwise: `gen_outbound(nil, uci_get("passwall2", outbound_node), "outbound")` (tag becomes `outbound:<remarks>`; non-sing-box node types spawn `app.sh run_socks` as in §3.2).
   - if outbound: `route.final = outbound.tag`; insert at outbounds[1].
11. Strip `_`-prefixed keys from outbounds; move `masque-client` outbounds into endpoints. (No wireguard-endpoint conversion here, no default detour.)
Returns a Lua table (caller serializes).

---

## 6. `gen_proto_config(var)` — bridge
Inputs: `local_socks_address` (default `0.0.0.0`), `local_socks_port`, `local_socks_username/password`, `local_http_address` (default `0.0.0.0`), `local_http_port`, `local_http_username/password`, `server_proto`, `server_address`, `server_port`, `server_username`, `server_password`.
```
inbounds:
 if local_socks_port: {type:"socks", tag:"socks-in", listen, listen_port}
     users: {username, password}   -- BUG: object, not array (preserve or fix to array; sing-box expects array)
 if local_http_port: {type:"http", tag:"http-in", listen, listen_port, users:[{username,password}] if both non-empty}
outbounds:
 if server_proto != "nil" and server_address != "nil" and server_port != "nil":
     [{type: server_proto, tag:"out", server: server_address, server_port: tonumber(server_port),
       username/password only if both given}]
config = {log:{disabled:true, level:"warn", timestamp:true}, inbounds, outbounds}
```
Returns pretty JSON. (No route: default outbound is the first, `out`.)

---

## 7. External commands summary
| When | Command |
|---|---|
| geo conversion | `"<geoview>" -type "<geosite|geoip>" -action convert -input "<dat>" -list "<name>" -output "<TO_SRS_PATH><prefix>-<name>.srs" -lowmem=true` |
| non-sing-box node as outbound | `/usr/share/passwall2/app.sh run_socks "flag=<port> node=<id> bind=127.0.0.1 socks_port=<port> config_file=<file> relay_port=<rp>"> /dev/null` |
| port alloc | `. /usr/share/passwall2/utils.sh ; echo -n $(get_new_port 'auto' 'tcp,udp')` |
| socks port cache | `. /usr/share/passwall2/utils.sh ; get_cache_var/set_cache_var node_<id>_socks_port [<port>]` |
| iface outbound | `mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>` |
| direct node list | `echo '<id>' >> /tmp/etc/passwall2/direct_node_list` |
| node domains | `uci show passwall2 \| grep ".address=" \| cut -d "'" -f 2 \| grep "[a-zA-Z]$" \| sort -u` |
| hosts parsing | `echo -n $(echo <line> \| awk -F ' ' '{print $1}')` and `$2` (replace with native split) |
| ipset flush | `ipset -q -F <name>`; listing `ipset list \| grep 'Name: ' \| grep 'psw2_<node>_' \| awk '{print $2}'` |
| nft flush | `nft flush set <family> <table> <set> 2>/dev/null`; listing `nft -a list sets \| grep -E 'psw2_<node>_' \| awk -F 'set ' '{print $2}' \| awk '{print $1}'` |

## 8. Version-dependent branches
| Condition | Effect |
|---|---|
| sing-box ≥ 1.15.0 | `tls.certificate_sha256 = [pin]` from `tls_pinSHA256`; else pin ⇒ `tls.insecure = true` |
| sing-box ≥ 1.14.0 | hysteria2 client `idle_timeout`, `keep_alive_period`, `disable_path_mtu_discovery` emitted; else omitted |
| sing-box ≥ 1.13.16 | anytls `client_metadata: "anytls/0.0.13"` |
| geoview ≥ 0.1.10 present | geosite/geoip → srs conversion; else warning and srs files missing |
Always-new-style schema (sing-box ≥1.12): `domain_resolver`, typed DNS servers (`type`/`server`/`server_port`), `action` rules, endpoints for wireguard.

## 9. Edge cases / quirks to preserve (or consciously fix)
- Lua truthiness: any non-nil option string is true (e.g. `plugin_enabled="0"`, `hysteria2_realms="0"`, `remote_dns_quic="0"`) — app.sh only passes flags when set to 1; for UCI options, check what the CBI writes (Flag writes "1"/removes).
- `node.address` is lowercased in gen_outbound.
- Empty `inbound` match list for a shunt rule is emitted as an empty table (luci jsonc renders empty table as `[]`/`{}`); a rule with empty inbound in sing-box matches nothing — Rust should emit `[]` to keep "never matches" semantics.
- `http_host or {}` similarly emits an empty list.
- `remote_dns_quic`/`remote_dns_tls` force port 853 ignoring the user port.
- `flag` gets `acl_` stripped inside DNS-hosts logic; affects fakeip db path and cache content string, not CACHE_TEXT_FILE.
- `ech_domain`/`GLOBAL.DNS_SERVER` are module-global; in a single CLI run they accumulate across all generated outbounds.
- `TMP_PORT` dry-run ports start at 3001 and increment per non-sing-box outbound.
