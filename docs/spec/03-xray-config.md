# 03 — Xray config generator (`luasrc/passwall2/util_xray.lua`)

Source: `luci-app-passwall2/luasrc/passwall2/util_xray.lua` (2280 lines). Every line was read for this spec.
This module builds Xray JSON configs for the client (`gen_config`), for the server
(`gen_config_server`), and for a small socks/http relay (`gen_proto_config`). The emitted JSON uses the
**new Xray "flattened" outbound settings schema** (`settings.address/port/id/...` directly, not
`vnext`/`servers`). It also uses `streamSettings.method` (not `network`), `rawSettings`, and `finalmask`.
All of this needs **Xray >= 26.7.11**. Every config carries `"version": {"min": "26.7.11"}`.

Notation: `X ? a : b` is a ternary. "nil" means the key is left out of the JSON. A Lua table that ends up
empty is removed by `cleanEmptyTables` where noted. **Lua truthiness:** every string, `"0"` included, is
truthy. Only nil/false are falsy. When the source tests a bare option (`if node.hysteria2_realms`), it
means "the option is present".

---

## 0. Module constants, globals, helpers

| Item | Value |
|---|---|
| UCI client config | `passwall2` (`api.uci_get_c`, `api.uci_foreach_c`) |
| UCI server config | `passwall2_server` (`api.uci_get_s`) |
| `api.TMP_PATH` | `/tmp/etc/passwall2` |
| `api.CACHE_PATH` | `/tmp/etc/passwall2_tmp` |
| `api.TMP_IFACE_PATH` | `/tmp/etc/passwall2/iface` |
| `xray_min_version` | `"26.7.11"` |
| `xray_version` | `api.get_app_version("xray")`. Computed but **unused**. |
| `GLOBAL.DNS_SERVER` | map node_id → DNS server object (filled by `gen_outbound` domain resolver) |
| `GLOBAL.DNS_HOSTNAME` | set of DoH hostnames that need bootstrap resolution |
| Module-level mutable globals | `NO_RUN`, `TMP_PORT`, `fragment_table`, `noise_table`, `default_node_address`, `default_node_port`, `inner_fakedns`. These are set by `gen_config` and read by `gen_outbound`. In Rust, pass them in a context struct. |

### `get_domain_excluded()`
- Reads `/usr/share/passwall2/domains_excluded`. Returns nil if the file is missing.
- Splits on `\n` and trims each line. Skips empty lines and lines whose **first char is `#`**. Collects the rest.
- Returns nil if the list is empty, else the list. Used for `sniffing.domainsExcluded`.

### `get_log_level(s)`: maps `"warn"` → `"warning"`. Anything else passes through unchanged.

### Helper semantics from api.lua (used here)
- `cleanEmptyTables(t)`: recursively replaces empty sub-tables with nil. Returns nil if `t` itself ends up empty.
- `sha256_sb_xray(str)`: base64-decodes `str`. If the result is exactly 32 bytes (and differs from the input), returns the uppercase hex of those bytes. Otherwise returns `str` unchanged. (Lets the user enter the pin as base64 or hex.)
- `format_go_time(input)`: if the input is all digits it means seconds. Otherwise it sums `(\d+)\s*([hms])` matches. Returns a normalized `"1h2m3s"` (zero components omitted, `"Ns"` if only seconds), or `"0s"` if <=0 or nil.
- `parse_realm_uri(uri)`: parses `realm://token@server/realm_id?query` or `realm+http://...`. Returns `{scheme, token, server_url, address, port, realm_id, stun_servers}`. Port defaults to 443 (realm) or 80 (realm+http). Strips `[..]` from IPv6. Trailing `/` is removed from realm_id. `stun_servers` is the list of all `stun=` query values (case-insensitive key), or nil if there are none. Returns nil on parse failure.
- `get_ipv6_full(v)`: wraps an IPv6 address in `[...]` if it has no brackets. Returns `""` if the input is not IPv6.
- `get_new_port()`: allocates a free local port (tcp,udp).
- `get_socks_port_by_cache(id)` / `set_socks_port_to_cache(id, p)`: cache var `node_<id>_socks_port` (via `utils.sh get_cache_var/set_cache_var`).
- `cacheFileCompareToLogic(file, str)`: compares the file content to `str`. If they differ it deletes the file and returns false. If equal it returns true. **In both cases it then writes `str` to the file.**
- `get_batch_nodes(node)`: for each whitespace-separated, URL-decoded group in `node.node_group`, returns the ids of "normal" nodes (`node_type=="normal"`, no `chain_proxy`). The node's group (default `"default"`) must match case-insensitively, and its remarks must satisfy `match_node_rule(remarks, node.node_match_rule)`.

---

## 1. `gen_outbound(flag, node, tag, proxy_table)` → outbound table | nil

Inputs:
- `node`: a UCI `nodes` section table (or a synthesized table).
- `tag`: defaults to `node[".name"]`.
- `proxy_table`: optional `{tag, fragment, noise}`.

Returns nil if `node` is nil.

### 1.1 Preamble
```
node_id = node[".name"]; tag = tag or node_id; remarks = node.remarks
if proxy_table is table:
  proxy_tag = proxy_table.tag
  fragment  = proxy_table.fragment and not node.hysteria2_realms   (true|nil)
  noise     = proxy_table.noise    and not node.hysteria2_realms   (true|nil)
```

### 1.2 Non-Xray node (`node.type ~= "Xray"`), e.g. sing-box, ss-rust, hysteria
These nodes run in their own process as a local SOCKS server, and Xray chains to it.
```
run_socks_instance = true
if NO_RUN:
   TMP_PORT = (TMP_PORT or 3000) + 1  (first value 3001); new_port = TMP_PORT; run_socks_instance = false
else:
   relay_port = (proxy_tag and node.port) ? tostring(node.port) : ""
   if relay_port == "":
       cache = get_socks_port_by_cache(node_id); if cache: new_port = cache; run_socks_instance = false
   if run_socks_instance:
       new_port = get_new_port()
       config_file = "nodesocks_<node_id>_<new_port>.json"
       if tag and node_id and tag does NOT contain node_id (Lua pattern find):
            config_file = "nodesocks_<tag>_<node_id>_<new_port>.json"
       exec: /usr/share/passwall2/app.sh run_socks "flag=<new_port> node=<node_id> bind=127.0.0.1 socks_port=<new_port> config_file=<config_file> relay_port=<relay_port>" > /dev/null
       if relay_port == "": set_socks_port_to_cache(node_id, new_port)
if new_port:
   node = { protocol="socks", transport="raw", address="127.0.0.1", port=new_port, stream_security="none" }   (node.type now nil)
   proxy_tag = "socks <- " .. node_id
```
(`remarks` was captured earlier, so the tag still gets `:remarks`.)
**Xray node:** `dialer_proxy_tag = proxy_tag`.

### 1.3 Normalization
- For Xray nodes, `tls=="1"` sets `stream_security="tls"`. If `reality=="1"` as well, it becomes `"reality"` instead. Otherwise `stream_security` stays nil.
- `wireguard_reserved` (wireguard only):
  - If the value contains only digits and commas, each `\d+` becomes a number.
  - Otherwise it is base64-decoded and each byte becomes a number.
  - The result is an array of numbers, or nil if empty.
- `protocol=="hysteria2"` → protocol `"hysteria"`, transport `"hysteria"`, stream_security `"tls"`.
- `protocol=="masque"` → transport `"masque"`, stream_security `"tls"`, `utls=nil`.
- `protocol=="http"` with stream_security `"tls"` → transport `"raw"`.
- If `remarks` is set, `tag = tag .. ":" .. remarks`.
- `node.address = lower(node.address or "")`.

### 1.4 Result skeleton (exact field names)
```
{
 _id = node_id, _flag = flag, _flag_proxy_tag = proxy_tag,      -- internal, stripped before output
 tag, protocol = node.protocol,
 mux = protocol ~= "masque" ? {
     enabled = (mux=="1"),
     concurrency     = mux=="1" ? (tonumber(mux_concurrency) if set else -1) : nil,
     xudpConcurrency = mux=="1" ? (tonumber(xudp_concurrency) if set else 8) : nil } : nil,
 streamSettings = COND ? {...} : nil,
 settings = {...}
}
```
`COND` = `node.streamSettings` (never set from UCI) **or** `dialer_proxy_tag` **or** protocol is one of
`vmess, vless, socks, shadowsocks, trojan, hysteria, http, masque`. In practice wireguard (and other
protocols) get **no** streamSettings unless they have a dialer proxy.

#### streamSettings
```
sockopt = {
  mark = 255,
  domainStrategy = node.domain_strategy or "UseIP",
  tcpFastOpen = tcp_fast_open=="1" ? true : nil,
  tcpMptcp    = tcpMptcp=="1" ? true : nil,
  happyEyeballs = happy_eyeballs=="1" ? {TryDelayMs=250, PrioritizeIPv6=false, Interleave=1, MaxConcurrentTry=4} : nil,
  dialerProxy = dialer_proxy_tag },
method   = node.transport,
security = node.stream_security,
```
**tlsSettings** (when security=="tls"):
| JSON | From |
|---|---|
| serverName | `tls_serverName` |
| fingerprint | `type=="Xray" && utls=="1" && fingerprint!=""` ? `fingerprint` : nil |
| pinnedPeerCertSha256 | `tls_pinSHA256` non-empty ? `sha256_sb_xray(tls_pinSHA256)` : `""` (always present) |
| verifyPeerCertByName | `tls_CertByName or ""` (always present) |
| echConfigList | `ech=="1"` ? `ech_config` : nil |
| certificates | `tls_certificate=="1" && tls_certificate_pem!=""` ? `{certificate = split(pem with literal "\n" → newline, "\n") (array of lines), usage="verify"}` : nil. **Note:** this is a single object, not an array. It crashes if the pem is nil. |
| cipherSuites | list option `cipherSuites` non-empty ? joined with `":"` : nil |
| alpn | added later (§1.6) |

**realitySettings** (when security=="reality"):
`serverName=tls_serverName, publicKey=reality_publicKey, shortId=reality_shortId or "", spiderX=reality_spiderX or "/", fingerprint = (type=="Xray" && fingerprint!="") ? fingerprint : "chrome", mldsa65Verify = use_mldsa65Verify=="1" ? reality_mldsa65Verify : nil`.

**rawSettings** applies when transport is `raw` or `tcp`, protocol is not `socks`, and `tcp_guise` is set and not `"none"`:
```
header = { type = tcp_guise,
  request = tcp_guise=="http" ? {
     path = tcp_guise_http_path (list; "" items → "/") or ["/"],
     headers = (tcp_guise_http_host or user_agent) ? { Host = tcp_guise_http_host (list), "User-Agent" = user_agent ? [user_agent] : nil } : nil
  } : nil }
```
**kcpSettings** (transport `mkcp`): `mtu = tonumber(mkcp_mtu) if non-empty else 1350, tti=50, uplinkCapacity=12, downlinkCapacity=100, cwndMultiplier=1, maxSendingWindow=2097152`.

**wsSettings** (transport `ws`): `path = ws_path or "/", host = ws_host, headers = user_agent ? {"User-Agent": user_agent} : nil, maxEarlyData = tonumber(ws_maxEarlyData), earlyDataHeaderName = ws_earlyDataHeaderName, heartbeatPeriod = tonumber(ws_heartbeatPeriod)`.

**grpcSettings** (transport `grpc`):
- `serviceName = grpc_serviceName`
- `multiMode = (grpc_mode=="multi")`
- `idle_timeout = grpc_idle_timeout ? max(10, tonumber(it)) : nil`
- `health_check_timeout = tonumber(grpc_health_check_timeout)`
- `permit_without_stream = (grpc_permit_without_stream=="1")`
- `initial_windows_size = tonumber(grpc_initial_windows_size) or 0`
- `user_agent = user_agent`

**httpupgradeSettings** (transport `httpupgrade`): `path = httpupgrade_path or "/", host = httpupgrade_host, headers = user_agent ? {"User-Agent"} : nil`.

**xhttpSettings** (transport `xhttp`): `mode = xhttp_mode or "auto", path = xhttp_path or "/", host = xhttp_host, extra = E`, where E is built as follows:
```
E = {}
if xhttp_extra: parsed = json_parse(base64Decode(xhttp_extra)); if ok and table: E = parsed.extra or parsed
if user_agent non-empty: E.headers = E.headers or {}; if no "User-Agent" and no "user-agent" key: E.headers["User-Agent"] = user_agent
E = cleanEmptyTables(E)
```
**masqueSettings** (protocol `masque`):
```
path = masque_path non-empty ? masque_path : nil
warp = masque_warp=="1" ? { privateKey = masque_warp_private_key ("\\n"→"\n", default ""), publicKey = masque_warp_public_key (same), address = masque_warp_address } : nil
headers = H or nil (nil if empty):
   if masque_warp ~= "1" and (username non-empty or password non-empty): H.authorization = "Basic " + base64(username..":"..password)   (missing → "")
   if user_agent non-empty: H["user-agent"] = user_agent
   for each line of masque_headers (literal "\\n" → newline; split on \r\n): match "^\s*([^:]+):\s*(.-)\s*$" → H[lower(trim(key))] = value   (overrides the earlier keys)
```
**hysteriaSettings** (transport `hysteria`): `{version=2, auth=hysteria2_auth_password}`.

**finalmask** (always computed, then `cleanEmptyTables`). `TP = node.transport`:
- `TP=="mkcp"`:
  ```
  udp = [ {type="mkcp-legacy", settings = mkcp_seed non-empty ? {value=mkcp_seed} : nil} ]
  map = {none:"none", srtp:"srtp", utp:"utp", "wechat-video":"wechat", dtls:"dtls", wireguard:"wireguard", dns:"dns"}
  if mkcp_guise set and != "none": push {type="mkcp-legacy", settings={header=map[mkcp_guise], value = (guise=="dns" && mkcp_domain non-empty) ? mkcp_domain : nil}}
  finalmask.udp = udp
  ```
- `TP=="hysteria"`:
  ```
  udp = []
  if hysteria2_obfs_type non-empty:
     o = {type="salamander", settings = hysteria2_obfs_password ? {password} : nil}
     if obfs_type=="gecko": min=tonumber(hysteria2_obfs_MinPacketSize) or 512; max=tonumber(hysteria2_obfs_MaxPacketSize) or 1200
                            if min<=0 or min>max or max>2048: min=512,max=1200
                            o.settings.packetSize = "<min>-<max>"   (crashes if there is no password, because settings is nil)
     push o
  if hysteria2_realms:
     realm = parse_realm_uri(hysteria2_realm_url)
     url = realm ? "<scheme>://<token>@<server_url>/<realm_id>" : nil
     stun = realm ? (realm.stun_servers or hysteria2_realm_stun) : nil
     push {type="realm", settings={url, stunServers=stun, portMapping = hysteria2_realm_upnp=="1" ? {enabled=true} : nil}}
  finalmask.udp = udp
  up = tonumber(hysteria2_up_mbps) or 0; down = tonumber(hysteria2_down_mbps) or 0
  finalmask.quicParams = {
    congestion = (up<=0 and down<=0) ? "bbr" : "brutal",
    brutalUp = up>0 ? "<up>mbps" : nil, brutalDown = down>0 ? "<down>mbps" : nil,
    udpHop = hysteria2_hop ? { ports = hysteria2_hop with ":"→"-", interval = HI(hysteria2_hop_interval) } : nil,
    maxIdleTimeout = t=leading-int(hysteria2_idle_timeout or "30"); (4<=t<=120) ? t : 30,
    keepAlivePeriod = t=leading-int(hysteria2_keep_alive_period or "0"); (2<=t<=60) ? t : nil,
    disablePathMTUDiscovery = (hysteria2_disable_mtu_discovery=="1"),
    initStreamReceiveWindow = maxStreamReceiveWindow = tonumber(hysteria2_stream_recv_win)*1048576 or nil,
    initConnectionReceiveWindow = maxConnectionReceiveWindow = tonumber(hysteria2_conn_recv_win)*1048576 or nil }
  HI(v): nil → 30;
         contains "-": match ^(\d+)-(\d+)$ → min=max(min,5); max=max(max,min) → string "min-max"; no match → 30;
         else n = leading-int(v); n>=5 ? n : 30   (number)
  ```
- **Fragment:** if `fragment` and global `fragment_table` exist and TP ∈ {raw, ws, httpupgrade, grpc, xhttp}, push a clone of `fragment_table` onto `finalmask.tcp`. Note that `tcp` is not in the list.
- **Noise:** if `noise` and `noise_table` exist and (TP=="mkcp" or (TP=="xhttp" and alpn=="h3" exactly)), push a clone of `noise_table` onto `finalmask.udp`.
- **Override:** if `node.finalmask` is non-empty, `json_parse(base64Decode(finalmask))`. If that yields a table it **replaces** the whole finalmask, including fragment and noise.

#### settings (flattened outbound)
| JSON | Value |
|---|---|
| address | wireguard ? `wireguard_local_address` (list) : `node.address` |
| port | `tonumber(node.port)` |
| id | vmess/vless ? `uuid` |
| encryption | vless ? (`encryption` non-empty ? encryption : `"none"`) |
| flow | vless and (`tls=="1"` or encryption ∉ {"", "none", nil}) and `flow` non-empty ? flow |
| security | vmess ? `node.security` (vmess cipher) |
| user / pass | socks/http ? `username` / `password` |
| password | shadowsocks/trojan ? `password` |
| method | shadowsocks: `ss_method` with `chacha20-ietf-poly1305`→`chacha20-poly1305` and `xchacha20-ietf-poly1305`→`xchacha20-poly1305`. Other non-empty values pass through. Missing → nil |
| secretKey | wireguard ? `wireguard_secret_key` |
| peers | wireguard ? `[{publicKey=wireguard_public_key, endpoint=address..":"..port, preSharedKey=wireguard_preSharedKey, keepAlive=tonumber(wireguard_keepAlive)}]` |
| mtu | wireguard and `wireguard_mtu` ? number |
| reserved | wireguard ? byte array (§1.3) |
| version | hysteria ? 2 |
| level | 0 (always) |

### 1.5 Post-fixes
- When hysteria has `hysteria2_realms` and the realm URI parses, `settings.address = realm.address` and `settings.port = realm.port`.
- wireguard: sets `settings.noKernelTun = true`. If `finalmask` (base64 JSON) parses, `streamSettings = streamSettings or {}` and `streamSettings.finalmask = fm`.

### 1.6 ALPN
If `alpn` is set and not `"default"`, it is split on `,`. A non-empty result is written to `streamSettings.tlsSettings.alpn`, but only if tlsSettings exists. (If streamSettings is nil, e.g. wireguard with an alpn value, the Lua code crashes. Rust should guard against this.)

### 1.7 Per-node domain resolver (bootstrap DNS for the server hostname)
Condition: `address` is a hostname (`datatypes.hostname`), `domain_resolver` is set, and (`domain_resolver_dns` or `domain_resolver_dns_https`) is set.
```
dns_tag = node_id.."_dns"; proto = domain_resolver
if proto=="https":
   u = parseURL(domain_resolver_dns_https); if u: address = the full URL; port = u.port or 443
       if u.hostname is a hostname: GLOBAL.DNS_HOSTNAME[u.hostname] = true
else:
   s = domain_resolver_dns; p = 53; split on ":" → if >1 parts: s = part[1]; p = tonumber(last)
   address = s; if proto=="tcp": address = "tcp://s:p"
   (BUG: a local variable shadows `port`, so for udp/tcp the emitted port is nil. A udp custom port is lost (Xray then defaults to 53). For tcp the port is inside the URL.)
GLOBAL.DNS_SERVER[node_id] = { tag=dns_tag, queryStrategy = domain_strategy or "UseIP", address, port,
   domains = ["full:"..address(lowercased)], finalQuery=true, disableCache=false, serveStale=true }
```

---

## 2. `gen_config_server(node)` → config table (server side, `passwall2_server` UCI)

Called by `server_app.lua` with a `user`-type server section. Server node options used:
`protocol, port, users (list of user section ids), flow, decryption, udp_forward, ss_method, ss_password, ss_network, masque_address, masque_mtu, masque_path, d_protocol, d_address, d_port, wireguard_private_key, wireguard_mtu, fallback, fallback_list (list "dest,path,xver"), accept_lan, outbound_node, outbound_node_iface, outbound_node_address/port/username/password, type, log, loglevel, transport, tls, tls_use_pem, tls_certificateFile, tls_keyFile, tls_certificate, tls_key, ech, ech_key, tcp_guise, tcp_guise_http_path, tcp_guise_http_host, mkcp_*, ws_host, ws_path, grpc_serviceName, httpupgrade_path/host, xhttp_path/host/maxuploadsize/maxconcurrentuploads, hysteria2_* (obfs/realm/up/down/ignore_client_bandwidth), finalmask, tcp_fast_open, acceptProxyProtocol, alpn, reality, reality_dest, reality_serverNames (list), reality_private_key, reality_shortId, use_mldsa65Seed, reality_mldsa65Seed`.

User section (`passwall2_server`, type `user`) options: `username, password, uuid, wireguard_public_key, wireguard_pre_shared_key, allowed_ips`.

### 2.1 Users
For each id in `node.users`, `user = uci_get_s(id)`. Skip it unless `.type=="user"`.
| protocol | user object |
|---|---|
| socks, http | `{user=username, pass=password}` |
| masque | `{email=username, pass=password}` |
| shadowsocks, trojan | `{email=username, password=password}` |
| vmess | `{email=username, id=uuid, alterId=0}` |
| vless | `{email=username, id=uuid, flow=node.flow}` |
| hysteria2 | `{email=username, auth=password}` |
| wireguard | `{publicKey=wireguard_public_key, preSharedKey=wireguard_pre_shared_key, keepAlive=0, allowedIPs=allowed_ips}` |
An empty list becomes nil.

### 2.2 Inbound settings by protocol
- vless: `{users, decryption = decryption non-empty ? decryption : "none"}`
- vmess: `{users}` only if users exist, else settings is nil
- socks: `{udp = udp_forward=="1", auth = users ? "password" : "noauth", users}`
- http: `{allowTransparent=false, users}`. Also forces transport `"raw"` and tcp_guise `"none"`.
- shadowsocks: `{method=ss_method, password=ss_password, users, network = ss_network or "tcp,udp"}`
- trojan: `{users}` if users exist
- hysteria2: `{version=2, users}`
- masque: forces transport=masque, tls="1", and clears reality, alpn, fallback and finalmask. Settings: `{users, address=masque_address, mtu=tonumber(masque_mtu or 1280)}`
- tunnel: `{allowedNetwork=d_protocol, rewriteAddress=d_address, rewritePort=tonumber(d_port)}`
- wireguard: `{secretKey=wireguard_private_key, mtu=tonumber(wireguard_mtu or 1420), peers=users}`

**Fallbacks** (`fallback=="1"`): for each entry `"dest,path,xver"` in `fallback_list`, split on `,`.
- `dest = tmp[1] or ""`. If dest contains no `.`, it is converted to a number (a port).
- `path = tmp[2]`, `xver = tonumber(tmp[3])`.
- The entries go to `settings.fallbacks = [{path, dest, xver}]`.

### 2.3 Routing / outbounds
```
outbounds = [ {protocol="freedom", tag="direct", settings={finalRules=[{action="allow"}]}}, {protocol="blackhole", tag="blocked"} ]
routing = { domainStrategy="IPOnDemand", rules=[ {ip=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],
           outboundTag = (accept_lan nil or "0") ? "blocked" : "direct"} ] }
if outbound_node:
  "_iface" (+outbound_node_iface): {protocol="freedom", tag="outbound", streamSettings={sockopt={mark=255, interface=iface}}, settings={finalRules=[{action="allow"}]}}
                                   exec: mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>
  "_socks"/"_http": t = {type=node.type, protocol="socks"|"http", transport="raw", address=outbound_node_address, port=outbound_node_port,
                         username/password = non-empty or nil}; outbound = gen_outbound(nil, t, "outbound")
  else: outbound = gen_outbound(nil, uci_get_c(outbound_node) /* passwall2 nodes section */, "outbound")
  prepend the outbound at index 1 (it becomes the default)
```
After this, hysteria2 → protocol `hysteria`, transport `hysteria`, tls `"1"`.

### 2.4 Config
```
{ log = { loglevel = log=="1" ? get_log_level(loglevel) : "none" },
  inbounds = [ { listen="::", port=tonumber(port), protocol, settings,
     streamSettings = {
       method = transport, security = "none",
       masqueSettings = masque ? {path = masque_path non-empty or nil} : nil,
       tlsSettings = tls=="1" ? { disableSystemRoot=false,
           certificates=[{ certificateFile = tls_use_pem!="1" ? tls_certificateFile, keyFile = tls_use_pem!="1" ? tls_keyFile,
                           certificate = (tls_use_pem=="1" && tls_certificate) ? lines(tls_certificate with "\\n"→newline),
                           key = (tls_use_pem=="1" && tls_key) ? lines(tls_key) }],
           echServerKeys = ech=="1" ? ech_key } : nil,
       rawSettings = transport∈{raw,tcp} ? { header={ type=tcp_guise,
            request = tcp_guise=="http" ? {path = tcp_guise_http_path ("" items→"/") or ["/"], headers={Host = tcp_guise_http_host or []}} } } : nil,
       kcpSettings = mkcp ? (same constants as client) : nil,
       wsSettings = ws ? {host=ws_host, path=ws_path} : nil,
       grpcSettings = (grpc && grpc_serviceName) ? {serviceName} : nil,
       httpupgradeSettings = httpupgrade ? {path=httpupgrade_path or "/", host=httpupgrade_host} : nil,
       xhttpSettings = xhttp ? {path=xhttp_path or "/", host=xhttp_host, maxUploadSize=xhttp_maxuploadsize, maxConcurrentUploads=xhttp_maxconcurrentuploads} (strings as stored) : nil,
       hysteriaSettings = hysteria ? {version=2} : nil,
       finalmask = <same as client for mkcp; for hysteria the same obfs/realm udp list, but quicParams only {congestion, brutalUp, brutalDown}.
                    up/down are forced to 0 if tonumber(hysteria2_ignore_client_bandwidth)==1. There are no hop/idle/window params.
                    The base64 `finalmask` override applies. Then cleanEmptyTables>,
       sockopt = { tcpFastOpen = tcp_fast_open=="1" ? true : nil, acceptProxyProtocol = (acceptProxyProtocol=="1") } } } ],
  outbounds, routing, version={min="26.7.11"} }
```
Post:
- ALPN (split on `,`, unless `"default"`) goes to `tlsSettings.alpn` if tlsSettings exists.
- If `tls=="1"`, security becomes `"tls"`. If `reality=="1"` as well:
  - tlsSettings is removed and security becomes `"reality"`.
  - `realitySettings = {show=false, dest=reality_dest, serverNames=reality_serverNames or [], privateKey=reality_private_key, shortIds=reality_shortId or "", mldsa65Seed = use_mldsa65Seed=="1" ? reality_mldsa65Seed : nil, minClientVer="1.0.0"}`
- Finally, every outbound key starting with `_` is stripped.

---

## 3. `gen_config(var)` → JSON string (client)

### 3.1 Input `var` (JSON object from `app.sh`, all values strings; JSON null → nil)
`flag, loglevel (default "warning"), node, server_host, server_port, tcp_proxy_way, redir_port,
local_socks_address (default "0.0.0.0"), local_socks_port, local_socks_username, local_socks_password,
local_http_address (default "0.0.0.0"), local_http_port, local_http_username, local_http_password,
dns_listen_port, direct_dns_udp_server, direct_dns_udp_port, direct_dns_tcp_server, direct_dns_tcp_port,
direct_dns_query_strategy, direct_ipset, direct_nftset, remote_dns_udp_server, remote_dns_udp_port,
remote_dns_tcp_server, remote_dns_tcp_port, remote_dns_doh_url, remote_dns_doh_host, remote_dns_doh_ip,
remote_dns_doh_port, remote_dns_fake ("1" or absent), remote_dns_query_strategy, remote_dns_detour, dns_cache, no_run`.
(app.sh also sends `log`, `remote_dns_fake_strategy` and `remote_dns_client_ip`. These are **ignored** here.)
`NO_RUN = var.no_run`. `CACHE_TEXT_FILE = /tmp/etc/passwall2_tmp/cache_<flag>.txt`.

### 3.2 UCI read
- `@global_xray[0]` (`xray_settings`): `fragment, fragment_packets, fragment_lengths, fragment_delays, fragment_maxSplit, noise, sniffing_override_dest, buffer_size`.
- `xray_noise_packets` sections: `enabled, type, packet, delay`.
- `@global[0].dns_hosts`. ACL section `<flag without "acl_">`: `dns_hosts_mode` (default/disable/custom), `dns_hosts`.
- `@global_rules[0].v2ray_location_asset` (default `/usr/share/v2ray/`).
- `shunt_rules` sections: `group, remarks, protocol, inbound, domain_list, ip_list, source, network, port`.
- Node sections (type `nodes`), socks sections (type `socks`: `port`).

### 3.3 Fragment / noise tables
```
if fragment=="1":
  lengths = split(trim(fragment_lengths), ",") with whitespace removed, non-empty;  delays likewise from fragment_delays
  fragment_table = {type="fragment", settings={packets = fragment_packets or "tlshello",
                    lengths = lengths or ["3-5","6-8","10-20"], delays = delays or ["10-20"], maxSplit = fragment_maxSplit or "3-6"}}
  (trim(nil) may crash if lengths/delays are unset; treat nil as "")
if noise=="1":
  for each xray_noise_packets with enabled=="1":
     {rand = (type=="rand" && packet) ? (packet contains "-" ? packet(string) : tonumber(packet)) : nil,
      type = type!="rand" ? type : nil, packet = type!="rand" ? packet : nil,
      delay = delay ? (contains "-" ? delay string : tonumber(delay)) : nil}
  noise_table = non-empty ? {type="noise", settings={reset=0, noise=[...]}} : nil
```

### 3.4 Local inbounds (built first, in this order)
- **socks-in** (if `local_socks_port`):
  - Base: `{tag="socks-in", listen=local_socks_address, port, protocol="socks", settings={auth="noauth", udp=true}, sniffing={enabled = sniffing_override_dest=="1" or <raw UCI node>.protocol=="_shunt"}}`.
  - When enabled: `destOverride=["http","tls","quic"]`, `routeOnly = (override!="1") ? true : nil`, `domainsExcluded = override=="1" ? get_domain_excluded() : nil`.
  - If username and password are both non-empty: `auth="password"`, `users=[{user, pass}]`.
- **http** (if `local_http_port`): `{listen, port, protocol="http", settings={allowTransparent=false, users?=[{user,pass}]}}`. There is **no tag**.

### 3.5 Inner functions

**get_node_by_id(id_or_table)**:
- Accepts a table as-is. A string that is `""` or `"nil"` → nil. Otherwise `uci_get_c(id) or {}`.
- `.type=="socks"` → `{".name"=name, remarks="socks[<port>]", type="Xray", protocol="socks", address="127.0.0.1", port=section.port, transport="raw", stream_security="none"}`.
- `.type=="nodes"` → the section.
- Anything else → nil.

**gen_loopback(outbound_tag, loopback_dst)**:
- Returns nil if the tag is empty.
- `inbound_tag = loopback_dst ? "lo-to-"..loopback_dst : outbound_tag.."-lo"`.
- If an outbound already exists with the same tag, protocol loopback and the same inboundTag, returns it.
- Otherwise creates `{protocol="loopback", tag=outbound_tag, settings={inboundTag=inbound_tag}}`. It is inserted at index 1 if the tag is `"default"`, else appended. Returns it.

**gen_balancer(_node, loopback_tag)** → `(balancer_tag, loopback_outbound)`. Called for a `protocol=="_balancing"` node.
```
id=_node[".name"]; btag="balancer-"..id; loopback_dst=id; loopback_tag = loopback_tag non-empty or id
if balancers already has btag: return btag, gen_loopback(loopback_tag, id)
nodes = node_add_mode=="batch" ? get_batch_nodes(_node) : balancing_node (list)
valid=[]
for nid in nodes: t="blc-"..nid
   if some outbound.tag starts with t (prefix match): push that tag; continue
   tag = gen_outbound_get_tag(flag, nid, t, {fragment = xray.fragment=="1" or nil, noise = xray.noise=="1" or nil}); push if non-nil
   if _node.fallback_node == nid: _node.fallback_node = nil
if valid empty: return nil
fb = fallback_node (empty→nil); fbtag = fb=="_direct" ? "direct" : "blackhole"
if fb and fb!="_direct":
   if some outbound.tag starts with fb: fbtag = that tag
   else n = get_node_by_id(fb): if n.protocol!="_balancing": fbtag = gen_outbound_get_tag(flag, n, fb, {fragment,noise}) or fbtag
                                else if gen_balancer(n): fbtag = fb
strategy = balancingStrategy=="leastLoad" ? {type="leastLoad", settings={expected = tonumber(expected) or 2, maxRTT="1s",
              tolerance = t=tonumber(tolerance) or 0; t<1 ? nil : min(t,100)/100}}
           : {type = balancingStrategy or "random"}          (values: random, roundRobin, leastPing, leastLoad)
balancers.push({tag=btag, selector=clone(valid), fallbackTag=fbtag, strategy})
-- the condition includes fbtag, which is always set, so this ALWAYS runs:
t = format_go_time(probeInterval); if t=="0s": t="60s" elif t has no h/m and int(t)<10: t="10s"
if leastLoad: burstObservatory ||= {subjectSelector=["blc-"], pingConfig={destination = useCustomProbeUrl ? probeUrl : nil, interval=t, sampling=3, timeout="5s"}}
else:         observatory ||= {subjectSelector=["blc-"], probeUrl = useCustomProbeUrl ? probeUrl : nil, probeInterval=t, enableConcurrency=true}
lo = gen_loopback(loopback_tag, id)    -- inboundTag "lo-to-<id>"
rules.push({inboundTag=[lo.settings.inboundTag], balancerTag=btag})
return btag, lo
```
Only the first balancer's observatory settings win (`||=`). At output, `observatory` is dropped whenever a `burstObservatory` exists.

**set_outbound_detour(node, outbound, outbounds)** → `(default_outTag, last_insert_outbound)`:
```
default = outbound.tag
chain_proxy=="1" and preproxy_node and not outbound._flag_proxy_tag:
   p = get_node_by_id(preproxy_node)
   if p.protocol=="_balancing": _, lo = gen_balancer(p); pre = lo; exist=true
   else pre = gen_outbound(node[".name"], p)          -- tag = p id(+":remarks")
   if pre: outbound.tag = pre.tag.." -> "..outbound.tag; outbound.streamSettings.sockopt.dialerProxy = pre.tag (creating tables if needed)
           if not exist: last_insert = pre;  default = outbound.tag
chain_proxy=="2" and to_node:
   t = get_node_by_id(to_node); if t.protocol starts with "_": t=nil   (special nodes cannot be landing nodes)
   if t:
     if t.type!="Xray":
        in_tag = "inbound_"..t[".name"].."_"..outbound.tag; p = get_new_port()
        inbounds.push({tag=in_tag, listen="127.0.0.1", port=p, protocol="tunnel", settings={allowedNetwork="tcp,udp", rewriteAddress=t.address, rewritePort=tonumber(t.port)}})
        if t.tls_serverName==nil: t.tls_serverName = t.address
        t.address="127.0.0.1"; t.port=p
        rules.insert(1, {inboundTag=[in_tag], outboundTag=outbound.tag})
        to = gen_outbound(node[".name"], t, t[".name"], {tag=t[".name"]})   -- relay_port = p → external core dials 127.0.0.1:p
     else to = gen_outbound(node[".name"], t)
     if to: to.tag = outbound.tag.." -> "..to.tag; if t.type=="Xray": to.streamSettings.sockopt.dialerProxy = outbound.tag
            outbounds.push(to); default = to.tag
chain_proxy=="3" and outbound_iface: if outbound.streamSettings.sockopt exists: sockopt.interface = outbound_iface
return default, last_insert
```

**gen_outbound_get_tag(flag, node_id, tag, proxy_table)** → tag | nil:
```
nil/""/"nil" id → nil; node = get_node_by_id(node_id); tag = tag or node[".name"]; node nil → nil
if proxy_table.chain_proxy in {"1","2"}: copy chain_proxy / preproxy_node (only if "1") / to_node (only if "2") onto node; clear them from proxy_table
if tag=="default" and default_node_address and default_node_port: node.address/port = those   (from var server_host/server_port)
outbound = nil
for o in outbounds: if o._flag_proxy_tag contains "socks <- "..node[".name"] (plain find): outbound = clone(o); outbound.tag = tag; break   (dedup of external socks instances; no ":remarks")
if node.protocol=="_balancing": _, lo = gen_balancer(node, tag); if lo: outbound=lo; node[".name"]=lo.tag; has_add=true
elif node.protocol=="_iface" and node.iface:
     outbound = {tag, protocol="freedom", streamSettings={sockopt={mark=255, interface=iface}}, settings={finalRules=[{action="allow"}]}}
     exec: mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>
outbound = outbound or gen_outbound(flag, node, tag, proxy_table)
if outbound:
   default_tag, last = set_outbound_detour(node, outbound, outbounds)
   if not has_add: insert outbound at 1 if tag=="default" else append
   if last: append last
   return default_tag
```

### 3.6 Shunt / routing construction
```
node = var.node ? uci_get_c(var.node) : nil
if node:
  if node.protocol != "_shunt": node = {remarks=node.remarks, type="Xray", protocol="_shunt", default_node=<original id>, fakedns=remote_dns_fake, default_fakedns=remote_dns_fake}
  if server_host and server_port: default_node_address/port = those
  inner_fakedns = node.fakedns or "0"
  gen_shunt_node(rule_name, id = node[rule_name]):
     "_direct"→"direct"; "_blackhole"→"blackhole"; "_default" (rule_name!="default")→"default"
     else if id: pt={fragment = xray.fragment=="1", noise = xray.noise=="1"}
          pre = node[rule_name.."_proxy_tag"]; if pre==id: pre=nil
          pre ? (pt.chain_proxy="2", pt.to_node=id, gen_outbound_get_tag(flag, pre, rule_name, pt))
              : gen_outbound_get_tag(flag, id, rule_name, pt)
  default_outboundTag = gen_shunt_node("default", node.default_node or "_direct"); COMMON.default_outbound_tag = it
  if inner_fakedns=="1" and node.default_fakedns=="1": remote_dns_fake = true
  foreach shunt_rules e where e.group == node.shunt_group (nil==nil matches):
     ot = gen_shunt_node(e[".name"]); skip unless ot and e.remarks
     if ot=="default": ot = default_outboundTag
     protocols = e.protocol non-empty ? split on " " : nil
     inboundTag = e.inbound non-empty ? [] + (contains "tproxy" and redir_port ? ["tcp_redir","udp_redir"]) + (contains "socks" and local_socks_port ? ["socks-in"]) : nil
     domains: if e.domain_list: lines (split \r\n), skip lines starting "#", "rule-set:", "rs:", "ext:"; others kept verbatim (geosite:, domain:, full:, regexp:, keyword:, ...)
         if non-empty: dns_domain_rules.push({shunt_rule_name=e[".name"], outboundTag=ot, domain=list, fakedns = (inner_fakedns=="1" and node[e[".name"].."_fakedns"]=="1") ? true : nil})
         else domains=nil
     ip: e.ip_list lines with the same skip rules; nil if empty
     source: e.source split on " " (or nil)
     base = {ruleTag=e.remarks, inboundTag, outboundTag=ot, network = e.network or "tcp,udp", source, port = e.port!="" ? e.port : nil, protocol=protocols}
     if domains: rules.push(base + {ruleTag=remarks.." Domains", domains})
     if ip:      rules.push(base + {ruleTag=remarks.." IP", ip})
     if neither: rules.push(base)
  if default_outboundTag: rules.push({ruleTag="default", outboundTag=default_outboundTag, port="1-65535" if node.domainStrategy=="IPIfNonMatch" else network="tcp,udp"})
  routing = {domainStrategy = node.domainStrategy or "AsIs", domainMatcher = node.domainMatcher or "hybrid", balancers = non-empty or nil, rules}
```
Shunt node options: `default_node, shunt_group, domainStrategy (AsIs|IPIfNonMatch|IPOnDemand), domainMatcher (hybrid|linear), fakedns, default_fakedns, <rule>, <rule>_proxy_tag, <rule>_fakedns`.

Outbound tags have the form `<rule_name or "default">:<node remarks>`. With a pre-proxy they become `<pre> -> <...>`. Balancer member tags are `blc-<id>:<remarks>`.

Node options used for chaining: `chain_proxy` ("1" pre-proxy, "2" landing node, "3" bind interface), `preproxy_node`, `to_node`, `outbound_iface`. `_iface` nodes use `iface`. Balancer nodes use `node_add_mode, node_group, node_match_rule, balancing_node, fallback_node, balancingStrategy, expected, tolerance, probeInterval, useCustomProbeUrl, probeUrl`.

### 3.7 DNS
```
tags: direct="dns-in-direct", remote="dns-in-remote", fakedns="dns-in-remote-fakedns", default="dns-in-default"
dns = {tag="dns-global", hosts={}, disableCache = (dns_cache=="0"), disableFallback=true, disableFallbackIfMatch=true, servers=[], queryStrategy="UseIP"}
dns_servers = [ {server=v, outboundTag="direct"} for v in GLOBAL.DNS_SERVER ]   (map order is arbitrary)
_direct_dns:
  udp server: {tag=direct, address=server, port=tonumber(port) or 53, queryStrategy = direct_dns_query_strategy non-empty or "UseIP"}
  elif tcp:   server = get_ipv6_full(server) if IPv6; {tag, address="tcp://"..server..":"..port, port=tonumber(port) or 53, queryStrategy}
  pushed to dns_servers with outboundTag="direct"
if GLOBAL.DNS_HOSTNAME non-empty: s = clone(_direct_dns) or {address="localhost"}; s.tag="dns-in-bootstrap"; s.domains=[hostnames]
  insert at Lua index (#dns_servers - 1), i.e. before the second-to-last element (0-based index max(0, n-2)); push with outboundTag="direct"
```
**If `dns_listen_port`** (routing is created as `{domainStrategy="IPOnDemand", rules=[]}` if it is nil):
1. **Hosts**:
   - The source is chosen as follows:
     - `flag=="global"`: `@global[0].dns_hosts`.
     - Otherwise `flag = flag minus "acl_"`. The mode is `uci(flag).dns_hosts_mode`: default → global dns_hosts, disable → "", custom → `uci(flag).dns_hosts`.
   - For each line, first whitespace token = host and second = value. Set `dns.hosts[host]=value` when both are non-empty.
   - The original uses `echo|awk` for this. Implement it natively.
2. `_remote_dns = {tag=remote, queryStrategy = remote_dns_query_strategy non-empty or "UseIPv4"}`. `proto="tcp"`.
   - **udp**: `address=server`, `port=tonumber or 53`, `proto="udp"`.
   - **tcp**: IPv6 is bracketed. `address="tcp://s:p"`, `port`, `proto="tcp"`.
   - **DoH** (`url` and `host`): if `doh_ip` is set, differs from the host, and the host is not an IP, set `dns.hosts[host]=doh_ip`. Then `address=url`, `port=tonumber(doh_port) or 443`.
   - If `address` is set, push `{outboundTag = remote_dns_detour=="direct" ? "direct" : nil, server=_remote_dns}`.
3. **FakeDNS** (if `remote_dns_fake` or `inner_fakedns=="1"`):
   - `fakedns=[]`. Pools: v4 `{ipPool="198.18.0.0/16", poolSize=65535}`, v6 `{ipPool="2001:2::/48", poolSize=65535}`.
   - Query strategy UseIP → [v4,v6]. UseIPv4 → [v4]. UseIPv6 → [v6]. Anything else → [] (empty).
   - `_remote_fakedns={tag=fakedns, address="fakedns"}`, pushed without an outboundTag.
4. **VPS list** (if a direct udp/tcp server is set):
   - Run `uci show passwall2 | grep ".address=" | cut -d "'" -f 2 | grep "[a-zA-Z]$" | sort -u`. This means: every `.address` option value in passwall2 that ends in a letter, lowercased, as `full:<x>`.
   - If any are found, insert **directly into dns.servers at position 1**: `{tag="dns-in-vpslist", address="localhost", domains, finalQuery=true, disableCache=false, serveStale=true}`.
5. **DNS inbound/outbound**:
   - Inbound: `{listen="127.0.0.1", port=tonumber(dns_listen_port), protocol="tunnel", tag="dns-in", settings={allowedNetwork="tcp,udp"}}`.
   - Outbound `dns-out`:
     ```
     {tag="dns-out", protocol="dns", streamSettings={sockopt={dialerProxy="direct"}},
      settings={rewriteAddress=direct_dns_udp_server, rewritePort=tonumber(direct_dns_udp_port) or 53, rewriteNetwork="udp",
                rules=[{qType="1,28", action="hijack"}, {qType=65, action="return", rCode=0}, {action="direct"}]}}
     ```
     It is appended to outbounds. (A "remote_type_dns" variant is defined but unused.)
   - `routing.rules.insert(1, {inboundTag=["dns-in"], outboundTag="dns-out"})`.
6. **Default DNS**:
   - `name = (default_outbound_tag nil or "direct") ? direct : remote`.
   - Find the first dns_servers entry whose server.tag == name. Clone it and set its tag to `"dns-in-default"`.
   - If it was the remote entry: with `remote_dns_fake` truthy, the server becomes a clone of `_remote_fakedns` with tag default. Otherwise `outboundTag = entry.outboundTag or COMMON.default_outbound_tag`.
   - Insert at dns_servers[1].
7. **Per-shunt DNS** (for each dns_domain_rules entry):
   - The server depends on the rule's outboundTag:
     - outboundTag `"direct"` → clone `_direct_dns`.
     - fakedns flag → clone `_remote_fakedns`.
     - Otherwise → clone `_remote_dns`, with dns outboundTag = the rule's outboundTag (or `"direct"` if remote_dns_detour=="direct").
   - Blackhole rules: push the dns-out rule `{action="return", rCode=0, domain}` and use no server.
   - Otherwise push `{action="hijack", qType="1,28", domain}`.
   - When there is a server, set `finalQuery=true`, `domains=rule.domain`, `tag="dns-in-<shunt_rule_name>"`, and push `{outboundTag, server}`.
   - Afterwards, all the collected dns-out rules are prepended in order to `dns_outbound.settings.rules`.
8. Move the routing rule with `ruleTag=="default"` to the end of `routing.rules`.
9. **ipset/nftset flush**:
   - `content = flag(acl_-stripped) .. node_id .. json(routing.rules)`. If `cacheFileCompareToLogic(CACHE_TEXT_FILE, content)` returns false (i.e. the rules changed), flush the sets as follows.
   - `direct_ipset` (comma list): `ipset -q -F <name>` for each. Then for each set from `ipset list | grep 'Name: ' | grep 'psw2_<node_id>_' | awk '{print $2}'`, run `ipset -q -F <set>`.
   - `direct_nftset` (comma list of `ipType#family#table#set`): `nft flush set <family> <table> <set> 2>/dev/null`. Then for each set from `nft -a list sets | grep -E 'psw2_<node_id>_' | awk -F 'set ' '{print $2}' | awk '{print $1}'`, run `nft flush set inet passwall2 <set> 2>/dev/null`.

**Always after:**
- If `dns.hosts` is empty → nil.
- Iterate dns_servers **in reverse**, skipping tags `dns-in-direct` and `dns-in-remote`:
  - If it has an outboundTag and `address!="fakedns"`: `routing.rules.insert(1, {inboundTag=[server.tag], outboundTag})`. This crashes if routing is nil.
  - If `server.domains` is non-empty or the tag is `dns-in-default`: `dns.servers.insert(1, server)`.
  - The net effect is that the original order is kept, and these entries sit ahead of `dns-in-vpslist`.
- If `#dns.servers==0`: insert `{tag="local", address="localhost"}`. (The source also intends "no server without domains". It references an undefined variable, so only the empty case triggers.)

### 3.8 Transparent proxy inbounds (if `redir_port`)
```
base = {port=tonumber(redir_port), protocol="tunnel", settings={allowedNetwork="tcp,udp", followRedirect=true},
        streamSettings={sockopt={tproxy="tproxy"}},
        sniffing={enabled = sniffing_override_dest=="1" or node.protocol=="_shunt"}}   -- node is the wrapped shunt here, so true whenever a node exists
if enabled: destOverride=["http","tls","quic"], metadataOnly=false, routeOnly = override!="1" ? true : nil, domainsExcluded = override=="1" ? get_domain_excluded() : nil
if remote_dns_fake or inner_fakedns=="1": enabled=true; destOverride ? (append "fakedns", metadataOnly=false) : (destOverride=["fakedns"], metadataOnly=true)
tcp: clone, tag="tcp_redir", allowedNetwork="tcp", sockopt.tproxy = tcp_proxy_way ("redirect" | "tproxy")
udp: clone, tag="udp_redir", allowedNetwork="udp" (tproxy="tproxy")
```
Inbound order: socks-in, http, landing-node tunnel inbounds (`inbound_*`), dns-in, tcp_redir, udp_redir.

### 3.9 Final config
```
{ env = {XRAY_LOCATION_ASSET = @global_rules[0].v2ray_location_asset or "/usr/share/v2ray/"},
  log = {loglevel = get_log_level(loglevel)},
  dns, fakedns, inbounds, outbounds,
  observatory = burstObservatory ? nil : observatory, burstObservatory, routing,
  policy = {levels = {"0": {bufferSize = tonumber(buffer_size) or nil, statsUserUplink=false, statsUserDownlink=false}}},
  version = {min="26.7.11"} }
```
- The **direct** outbound is `{protocol="freedom", tag="direct", settings={finalRules=[{action="allow"}]}, streamSettings={sockopt={mark=255, domainStrategy = direct_dns_query_strategy non-empty or "UseIP"}}}`. It goes at index 1 if `default_outbound_tag=="direct"`, else it is appended.
- The **blackhole** outbound is `{protocol="blackhole", tag="blackhole"}`. It goes at index 1 if the default is `"blackhole"`, else it is appended.
- For each outbound: if it has no `_flag_proxy_tag`, has `_id` and settings, NO_RUN is not set, and settings has an address+port (or vnext/servers/peers endpoint), run `echo '<_id>' >> /tmp/etc/passwall2/direct_node_list`. Then strip every key starting with `_`.
- Returns `jsonc.stringify(config, pretty)`. It always returns, even when there is no node.
- Policy levels use the key `"0"` (an object, not an array).
- An empty `fakedns` table may serialize as `{}`/`[]`. Rust should emit nil for an empty fakedns.

---

## 4. `gen_proto_config(var)` → JSON string (local socks/http relay)
Vars: `local_socks_address/port/username/password, local_http_address/port/username/password` (address default `0.0.0.0`), `server_proto, server_address, server_port, server_username, server_password`.
- Inbounds:
  - socks: `{listen, port, protocol="socks", settings={udp=true, auth="noauth"}}`. With credentials: `auth="password"` and `users=[{user,pass}]`.
  - http: `{listen, port, protocol="http", settings={allowTransparent=false, users?}}`.
  - Neither has a tag.
- Upstream outbound, added if `server_proto`, `server_address` and `server_port` are each `!= "nil"`. This one uses the **old `servers` schema**:
  `{protocol=server_proto, streamSettings={method="raw", security="none"}, settings={servers=[{address, port=tonumber, users = (username and password) ? [{user, pass}] : nil}]}}`. It has no tag, so it is the default.
- Then `{protocol="freedom", tag="direct", settings={finalRules=[{action="allow"}]}, streamSettings={sockopt={mark=255}}}`.
- Config: `{log={loglevel="warning"}, inbounds, outbounds, version={min="26.7.11"}}`.

## 5. CLI entry
`lua util_xray.lua <func> '<json>'` calls `_G[func](json_parse(arg2))` and prints the result. Exported functions are `gen_config` and `gen_proto_config`; `gen_config_server` is used via `require`. app.sh runs `lua $UTIL_XRAY gen_config "$json" > $config_file`, then `xray run -c $config_file`.

## 6. Edge cases / known quirks to preserve or fix deliberately
- Prefix matching for existing `blc-<id>` and fallback outbound tags (`string.sub(tag,1,#prefix)==prefix`) can falsely match ids that share a prefix.
- The same node used in several shunt rules gets one outbound per rule (tag `<rule>:<remarks>`). The exception is external-core nodes, which reuse a single socks instance through a cloned outbound.
- In `gen_outbound_get_tag`, `node[".name"]` is read before the nil check, so an id for a missing section is unsafe.
- `"tcp://"..s..":"..tonumber(port) or 53` errors in Lua if the port is not numeric. Rust should default to 53.
- The non-https domain_resolver loses its port (shadowed local) and its `:` split breaks on IPv6.
- `useCustomProbeUrl` and `hysteria2_realms` are truthiness tests, so any stored value counts as enabled.
- socks-in sniffing uses the **unwrapped** node's protocol. redir sniffing is effectively always on.
- An empty `inboundTag` array is emitted when `inbound` is set but no matching inbound exists.
- `observatory` is always generated for any balancer, because `fallbackTag` is never nil.
