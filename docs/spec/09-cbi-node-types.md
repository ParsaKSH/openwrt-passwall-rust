# 09 — CBI node-type forms (client node types + server pages/types)

Source files covered (all read completely):

| File | Lines | Purpose |
|---|---|---|
| `luasrc/model/cbi/passwall2/client/type/1_sing-box.lua` | 1057 | client node form, type `sing-box` |
| `luasrc/model/cbi/passwall2/client/type/2_xray.lua` | 938 | client node form, type `Xray` |
| `luasrc/model/cbi/passwall2/client/type/3_ss-rust.lua` | 70 | client node form, type `SS-Rust` |
| `luasrc/model/cbi/passwall2/client/type/4_ssr.lua` | 68 | client node form, type `SSR` |
| `luasrc/model/cbi/passwall2/server/index.lua` | 141 | server-side list page (global enable, servers table, users table, log) |
| `luasrc/model/cbi/passwall2/server/server_config.lua` | 52 | single server edit page (loads server/type/*) |
| `luasrc/model/cbi/passwall2/server/user_config.lua` | 54 | single server-user edit page |
| `luasrc/model/cbi/passwall2/server/type/1_sing-box.lua` | 627 | server inbound form, type `sing-box` |
| `luasrc/model/cbi/passwall2/server/type/2_xray.lua` | 621 | server inbound form, type `Xray` |
| `luasrc/model/cbi/passwall2/server/type/3_ss-rust.lua` | 93 | server form, type `SS-Rust` |
| `luasrc/model/cbi/passwall2/server/type/4_ssr.lua` | 124 | server form, type `SSR` |

Supporting helpers that were read to define semantics (from `luasrc/passwall2/api.lua`, `client/node_config.lua`, `view/passwall2/server/*.htm`, `controller/passwall2.lua`) are summarised where needed; their full spec belongs to other spec files.

---

## 0. Configs and section types

| UCI config | Section type | Written by |
|---|---|---|
| `passwall2` (`api.c_config`, default Map config) | `nodes` (client nodes; named section id = random 8-char) | client/type/* via node_config.lua |
| `passwall2_server` (`api.s_config`) | `global` (named section `global`) | server/index.lua |
| `passwall2_server` | `server` (anonymous-style random id) | server/index.lua, server_config.lua, server/type/* |
| `passwall2_server` | `user` | server/index.lua, user_config.lua |

Also read (not written): `passwall2.@socks[*]` (for node lists), `passwall2.@global_app[0].<app>_file` (binary paths), `passwall2.@global_other[0].show_node_info`, `network.interface.*` (interface lists).

---

## 1. Common mechanism of every `type/*.lua` file (MUST replicate)

### 1.1 Loading
* Parent page (`client/node_config.lua` or `server/server_config.lua`) creates `s1 = NamedSection(arg[1], "nodes"|"server")`, adds `ListValue "type"`, then lists the `type/` directory, sorts filenames **lexicographically** (`1_sing-box`, `2_xray`, `3_ss-rust`, `4_ssr`) and executes each with `(m, s1)` in the page's environment (globals such as `groups`, `user_list`, `arg` are visible).
* Each type file:
  1. Returns early (adds nothing, not even a type choice) if its binary is missing:
     * client sing-box / server sing-box: `api.finded_com("sing-box")` (path from `passwall2.@global_app[0].sing_box_file`, else default path; checked with `type -t -p "<path>"`).
     * client/server Xray: `api.finded_com("xray")`.
     * client SS-Rust: `api.is_finded("sslocal")`; server SS-Rust: `api.is_finded("ssserver")`.
     * client SSR: `api.is_finded("ssr-local")`; server SSR: `api.is_finded("ssr-server")`.
     * `is_finded(e)` = `type -t -p "/bin/e" -p "/usr/bin/e" "e" | head -n1` non-empty.
  2. Adds its choice to `s1.fields.type`: value / label:
     * `sing-box` / "Sing-Box"; `Xray` / "Xray"; `SS-Rust` / "Shadowsocks Rust"; `SSR` / client "ShadowsocksR Libev", server "ShadowsocksR".
  3. sing-box and Xray (client and server) set `s1.fields.type.default = type_name` if no default yet (so the first available of sing-box → Xray becomes the default type).
  4. **Server only**: `if not s1.val.type then s1.val.type = type_name end` — i.e. a brand-new server with no `type` takes the first installed type in file order (sing-box, Xray, SS-Rust, SSR).
     **Client**: `s1.val.type` = UCI `type`, overridden by POSTed `cbid.passwall2.<id>.type` when `cbi.submit=1`. No fallback; if nil, no type-specific fields are built.
  5. Returns (builds no fields) unless `s1.val.type == type_name`. ⇒ **Only the selected type's fields are ever rendered.** Changing type in the browser triggers a reload (see §2.4/server footer and client footer).
  6. Builds a temporary `NamedSection(m, arg[1], "tmp_<sectiontype>")` with `type_name`, `option_prefix`, then `api.set_type_cbi(s)`; options are added; finally `api.type_cbi_section(s1, s)` moves all options into `s1`.

### 1.2 Option prefixing (`api.set_type_cbi`)
* Prefixes: sing-box `singbox_`, Xray `xray_`, SS-Rust `ssrust_`, SSR `ssr_`.
* Form field name = `cbid.<config>.<section>.<prefix><option>`; **UCI option name = unprefixed `<option>`**. All types share the same flat namespace in the UCI section (e.g. `protocol`, `port`, `tls` are the same UCI options regardless of type).
* `cfgvalue`: reads unprefixed UCI option. For `MultiValue` with `cast="table"` a UCI list is joined with spaces for display.
* `write(section, value)`: **only if the submitted `type` form value equals this file's `type_name`**:
  * DynamicList: de-duplicate (`table_remove_duplicates`, order kept); `cast=="string"` → join with " ", else list.
  * MultiValue: table → de-dup; string → split on spaces; `cast=="string"` → space-joined string, else UCI list.
  * `uci set <section>.<option>=value`.
* `remove(section)`: only if submitted type == type_name → `uci delete <section>.<option>`.
* Dependency serialisation (`deplist2json`):
  * Option with **no** depends gets `depends({type=type_name})`.
  * Every depends entry gets `type = type_name` added if absent.
  * Keys mapping: key containing `!` kept as-is; key starting `^` → strip `^` (raw id); key containing `.` → `cbid<key>`; key naming a sibling field in this type section → `cbid.<config>.<section>.<prefix><key>`; otherwise (e.g. `type`) → `cbid.<config>.<section>.<key>`.
  * Dependency values: `true` matches checkbox checked ("1"); `false` matches unchecked **or field absent/hidden** (JS loose compare `"" == false`); strings compare to the field's current value. A list of depends entries = OR; keys inside one entry = AND.
* `type_cbi_section`: re-parents every option to `s1` and registers `s1.fields[o.option]` (prefixed key).

### 1.3 CBI save semantics to reproduce in new frontend/backend
* An option that is hidden (dependencies unmet) is not submitted → removed from UCI on save (only when the selected type matches).
* `Flag`: enabled "1", disabled "0". If submitted value equals the Flag's `default` and `rmempty` (default true) → option deleted; otherwise written. `rmempty=false` flags are always written as "0"/"1".
* `Value`/`ListValue` empty → deleted (rmempty default true). `rmempty=false` → required when visible.
* `validate` functions may transform the stored value (documented per field).
* `Value` with `:value()` entries = combobox (free text + suggestions). `ListValue` = strict select.

### 1.4 Shared special encodings (UCI storage format)
| UCI option | Form field | Storage encoding |
|---|---|---|
| `config_str` | `custom_config` TextValue (server, all types) | **base64** of JSON text. Validation: must parse as JSON (`datatype json`), error "Custom Config Must be JSON text!". `custom_config` itself is never stored. |
| `finalmask` | TextValue (server Xray, client Xray) | base64 of JSON text |
| `xhttp_extra` | TextValue (client Xray) | base64 of JSON text; side effect sets/deletes `download_address` |
| `tls_certificate`, `tls_key` (server), `tls_certificate_pem` (client), `ech_key` (server sing-box), `ech_config` (client sing-box), `masque_headers`, `masque_warp_private_key`, `masque_warp_public_key` | TextValue | multi-line text stored as single line with literal two-char `\n` separators. Display: replace `\n` (backslash-n) → newline. |
| `ech_key` (server Xray), `ech_config` (client Xray), `reality_mldsa65Seed`, `reality_mldsa65Verify` | TextValue | CR/LF stripped, trimmed (single line) |
| `ssh_priv_key` (client sing-box) | TextValue | real newlines kept (normalised) |

PEM normalisation (used by every "`\n`-escaped" PEM field): `trim → \r\n→\n → \r→\n → strip spaces/tabs around each \n → collapse multiple \n → replace \n with literal "\n"`.

---

## 2. Server pages

### 2.1 `server/index.lua` (URL `admin/services/passwall2/server`)
Map `passwall2_server`, redirect to itself.

**Section `global` (NamedSection "global", type `global`)**, not removable:
* `enable` Flag, rmempty=false → `passwall2_server.global.enable` "0"/"1".

**TypedSection `server`** "Servers Manager": anonymous, addremove, sortable (drag order = UCI order, template `cbi/sortable`), table template, `extedit = <url>/server_config/%s`.
* create: `uid = gen_random_char(8)` (`head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8`), `uci add` named section of type `server` with that id, then HTTP redirect to `server_config/<uid>`.
* remove: delete section only if its `.type == "server"`.
* Columns:
  * `enable` Flag (rmempty=false, width 5%) — editable inline.
  * `status` DummyValue: placeholder "Collecting data..."; JS (server_list_status.htm) calls `server_status?index=i&id=<sid>` per row; backend: `/bin/busybox top -bn1 | grep -v grep | grep 'passwall2_server/bin/' | grep -i '<id>'` → `{index, status:bool}`; renders ✓ green / X red.
  * `remarks` DummyValue (15%).
  * `type` DummyValue (20%): if type is `sing-box` or `Xray` → `"<Type> <Proto>"` where Type `sing-box`→"Sing-Box", Proto map: vmess→VMess, vless→VLESS, shadowsocks→SS, shadowsocksr→SSR, wireguard→WG, hysteria→HY, hysteria2→HY2, anytls→AnyTLS, else capitalise first letter; if `custom=="1"` and proto not in map → "Custom Config". Otherwise raw type (`SS-Rust`, `SSR`).
  * `port` DummyValue.
  * `log` Flag default "1", rmempty=false — editable inline.
  * Each row also gets a "Log" button → opens `server_log?id=<sid>` (backend returns `/tmp/etc/passwall2_server/<id>.log` with `\n`→`<br />`, or alert "Not enabled log").

**TypedSection `user`** "Users Manager": anonymous, addremove, sortable, table, `extedit = server_user_config/%s`.
* create: random 8-char id, redirect to `server_user_config/<uid>`.
* remove (only if `.type=="user"`): for every `server` section: if `server.user == <id>` set `user=""`; remove `<id>` from list `server.users` (iterate from end) and write back if changed; delete the user; redirect to `server`.
* Columns (DummyValue, 25% each): `username`, `password`, `uuid`.

**Log panel** (server/log.htm): polls `server_get_log` every 3 s (backend `cat /tmp/log/passwall2_server.log` if exists); "Clear logs" → `server_clear_log` (`echo '' > /tmp/log/passwall2_server.log`). Auto-scroll if user was at bottom.

### 2.2 `server/server_config.lua` (URL `server_config/<id>`)
* Map `passwall2_server`, redirect `server`. If no `arg[1]` or section missing → redirect.
* Templates: `server/config_header` (defines JS `server_update_config(id, data, redirect)` → `GET server_update_config?id=&data=<json>`), `cbi/nodes_listvalue_com`.
* Global `user_list` = all `user` sections in order (used by type files for user selects; value = section id, label = `username`).
* NamedSection `<id>` type `server` "Server Config":
  * `enable` Flag default "1", rmempty=false.
  * `remarks` Value default translate("Remarks"), rmempty=false.
  * `type` ListValue — choices added by type files (§1.1).
* `s.val = m:get(id) or {}` (so `s.val.type` = UCI type).
* Loads `/usr/lib/lua/luci/model/cbi/passwall2/server/type/*` sorted.
* Footer (`server/config_footer`): on change of the `type` select → `server_update_config(node_id, {enable, remarks, type, protocol:''}, server_config/<id>)` then reloads page (so the new type's form renders; `protocol` reset to "").

### 2.3 `server/user_config.lua` (URL `server_user_config/<id>`)
NamedSection `<id>` type `user` "User Config" (no prefixing; plain options):

| option | widget | datatype / default | notes |
|---|---|---|---|
| `username` | Value | `and(uciname,maxlength(24))`, rmempty=false | validate: unique across `user` sections (other than self), error "This username already exists." |
| `password` | Value | rmempty=false | |
| `uuid` | Value | `uuid`, default = `cat /proc/sys/kernel/random/uuid`, rmempty=false | |
| `wireguard_public_key` | Value | `base64` | label "Wireguard Public Key" |
| `wireguard_private_key` | Value | `base64` | |
| `gen_wireguard_key` | DummyValue (button template `server/gen_wireguard_key`) | – | not stored. Button → `GET gen_wireguard_key` → JSON `{code:1,data:{private_key,public_key}}`; fills `wireguard_private_key` / `wireguard_public_key` (no prefix here). Backend: `wg genkey` + `echo <priv> | wg pubkey`; fallback `xray wg | awk -F ': ' '{print $2}'` (line1 priv, line2 pub); fallback `sing-box generate wg-keypair | awk '{print $2}'`. |
| `wireguard_pre_shared_key` | Value | `base64` | |
| `allowed_ips` | DynamicList | – | WireGuard allowed IPs (UCI list, de-duplicated) |

---

## 3. Server types (config `passwall2_server`, section type `server`)

Notation for "Depends": entries separated by ` | ` are OR; inside `{}` AND. `custom=0` means Flag `custom` unchecked/absent. Every option implicitly also requires `type == <type>`. Options with "—" have no extra dependency (always visible for that type).

### 3.1 Server `SSR` (prefix `ssr_`, requires `ssr-server`)
Lists:
* SSR_METHODS = `none, table, rc2-cfb, rc4, rc4-md5, rc4-md5-6, aes-128-cfb, aes-192-cfb, aes-256-cfb, aes-128-ctr, aes-192-ctr, aes-256-ctr, bf-cfb, camellia-128-cfb, camellia-192-cfb, camellia-256-cfb, cast5-cfb, des-cfb, idea-cfb, seed-cfb, salsa20, chacha20, chacha20-ietf`
* SSR_PROTOCOLS = `origin, verify_simple, verify_deflate, verify_sha1, auth_simple, auth_sha1, auth_sha1_v2, auth_sha1_v4, auth_aes128_md5, auth_aes128_sha1, auth_chain_a, auth_chain_b, auth_chain_c, auth_chain_d, auth_chain_e, auth_chain_f`
* SSR_OBFS = `plain, http_simple, http_post, random_head, tls_simple, tls1.0_session_auth, tls1.2_ticket_auth`

| option | widget | default | choices / datatype | depends |
|---|---|---|---|---|
| `custom` | Flag "Use Custom Config" | 0 | | — |
| `custom_config`→`config_str` | TextValue JSON rows=10 wrap=off | | base64 JSON (§1.4) | {custom=1} |
| `port` | Value "Listen Port" | | port | {custom=0} |
| `user` | ListValue "User" | | `user` section ids (label username) | {custom=0} |
| `method` | ListValue | (first) | SSR_METHODS | {custom=0} |
| `protocol` | ListValue | | SSR_PROTOCOLS | {custom=0} |
| `protocol_param` | Value | | | {custom=0} |
| `obfs` | ListValue | | SSR_OBFS | {custom=0} |
| `obfs_param` | Value | | | {custom=0} |
| `timeout` | Value "Connection Timeout" | 300 | uinteger | {custom=0} |
| `tcp_fast_open` | Flag | "0" | | {custom=0} |
| `udp_forward` | Flag | "1" | rmempty=false | — |
| `firewall_allow` | Flag | "0" | | {custom=0} |
| `firewall_allow_src` | Value (firewall zone list, nocreate, allowany) | "wan" | rmempty = not js-luci | {custom=0, firewall_allow=1} |
| `log` | Flag | "1" | rmempty=false | — |

Note: SSR server uses a single `user` (ListValue) not `users`.

### 3.2 Server `SS-Rust` (prefix `ssrust_`, requires `ssserver`)
SSRUST_SERVER_METHODS = `plain, none, aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha8-poly1305, 2022-blake3-chacha20-poly1305`

| option | widget | default | choices | depends |
|---|---|---|---|---|
| `custom` | Flag | 0 | | — |
| `custom_config`→`config_str` | TextValue JSON | | base64 | {custom=1} |
| `port` | Value | | port | {custom=0} |
| `user` | ListValue | | user ids | {custom=0} |
| `method` | ListValue | | SSRUST_SERVER_METHODS | {custom=0} |
| `timeout` | Value | 300 | uinteger | {custom=0} |
| `tcp_fast_open` | Flag | "0" | | {custom=0} |
| `firewall_allow` | Flag | "0" | | {custom=0} |
| `firewall_allow_src` | Value zone | "wan" | | {custom=0, firewall_allow=1} |
| `log` | Flag | "1" | rmempty=false | — |

(No `udp_forward` field for SS-Rust.)

### 3.3 Server `Xray` (prefix `xray_`, requires xray)
Lists: XRAY_SS_SERVER_METHODS = `aes-128-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305`; MKCP_HEADERS = `none, srtp, utp, wechat-video, dtls, wireguard, dns`.

| option | widget | default | choices / datatype | depends |
|---|---|---|---|---|
| `custom` | Flag | 0 | | — |
| `custom_config`→`config_str` | TextValue JSON | | base64 | {custom=1} |
| `protocol` | ListValue | (first: vmess) | `vmess`(Vmess), `vless`(VLESS), `http`(HTTP), `socks`(Socks), `shadowsocks`, `trojan`, `hysteria2`, `wireguard`(WireGuard), `masque`(MASQUE), `tunnel`(Tunnel) | {custom=0} |
| `port` | Value "Listen Port" | | port | {custom=0} |
| `users` | MultiValue cast=table (UCI list) | | user ids | protocol ∈ {http, socks, shadowsocks, vmess, vless, trojan, hysteria2, wireguard, masque} |
| `d_protocol` | ListValue "Destination protocol" | | `tcp`, `udp`, `tcp,udp` | {protocol=tunnel} |
| `d_address` | Value | | | {protocol=tunnel} |
| `d_port` | Value | | port | {protocol=tunnel} |
| `decryption` | Value "(decryption)" | "none", placeholder none | validate: trim, "" → "none" | {protocol=vless} |
| `ss_method` | ListValue | | XRAY_SS_SERVER_METHODS | {protocol=shadowsocks} |
| `ss_password` | Value | | | {protocol=shadowsocks} |
| `ss_network` | ListValue "Transport" | "tcp,udp" | `tcp`, `udp`, `tcp,udp` | {protocol=shadowsocks} |
| `udp_forward` | Flag | "1", rmempty=false | | {protocol=socks} |
| `flow` | ListValue | "" | ""(Disable), `xtls-rprx-vision` | {protocol=vless} |
| `hysteria2_realms` | Flag "Realms" | "0" | | {protocol=hysteria2} |
| `hysteria2_realm_url` | Value | | validate: trim; `api.parse_realm_uri` must succeed else "Invalid Realm URL." Example `realm://public@realm.hy2.io/your-realm-name` | {hysteria2_realms=1} |
| `hysteria2_realm_stun` | DynamicList | [`stun.sip.us:3478`, `stun.nextcloud.com:3478`, `global.stun.twilio.com:3478`] | | {hysteria2_realms=1} |
| `hysteria2_realm_upnp` | Flag "Enable UPnP/NAT-PMP" | "0" | | {hysteria2_realms=1} |
| `hysteria2_obfs_type` | ListValue | "" | ""(Disable), `salamander`, `gecko` | {protocol=hysteria2} |
| `hysteria2_obfs_password` | Value | | | {hysteria2_obfs_type=salamander} \| {hysteria2_obfs_type=gecko} |
| `hysteria2_obfs_MinPacketSize` | Value | "512" (placeholder 512) | uinteger | {hysteria2_obfs_type=gecko} |
| `hysteria2_obfs_MaxPacketSize` | Value | "1200" | uinteger | {hysteria2_obfs_type=gecko} |
| `hysteria2_ignore_client_bandwidth` | Flag "Client BBR Flow Control" | 0 | | {protocol=hysteria2} |
| `hysteria2_up_mbps` | Value | | | {protocol=hysteria2, hysteria2_ignore_client_bandwidth=0} |
| `hysteria2_down_mbps` | Value | | | same |
| `masque_path` | Value | | | {protocol=masque} |
| `masque_address` | DynamicList, rmempty=false | | | {protocol=masque} |
| `masque_mtu` | Value | "1280" | uinteger | {protocol=masque} |
| `tls` | Flag "TLS" | 0 | validate (below) | protocol ∈ {vmess, vless, http, socks, shadowsocks, trojan} |
| `reality` | Flag | 0 | | {tls=1, transport=raw} \| {tls=1,transport=ws} \| {tls=1,transport=grpc} \| {tls=1,transport=httpupgrade} \| {tls=1,transport=xhttp} |
| `reality_private_key` | Value | | | {reality=1} |
| `reality_shortId` | DynamicList | | | {reality=1} |
| `reality_dest` | Value "Dest" | "google.com:443" | | {reality=1} |
| `reality_serverNames` | DynamicList | | | {reality=1} |
| `alpn` | ListValue | "default" | `default`, `h3`, `h2`, `h3,h2`, `http/1.1`, `h2,http/1.1`, `h3,h2,http/1.1` | {tls=1, reality=0} |
| `use_mldsa65Seed` | Flag "ML-DSA-65" | "0" | | {reality=1} |
| `reality_mldsa65Seed` | TextValue rows=5 wrap=soft | "" | CR/LF stripped + trim | {use_mldsa65Seed=1} |
| `tls_use_pem` | Flag "Use PEM" | (0) | | {tls=1, reality=0} \| {protocol=hysteria2} \| {protocol=masque} |
| `tls_certificateFile` | FileUpload | UCI value or `/etc/config/ssl/<sid>.crt` (posted value overrides) | validate: if non-empty must exist (`fs.access`) else "Can't find this file!"; empty → nil | {tls=1, reality=0, tls_use_pem=0} \| {protocol=hysteria2, tls_use_pem=0} \| {protocol=masque, tls_use_pem=0} |
| `tls_keyFile` | FileUpload | UCI or `/etc/config/ssl/<sid>.key` | same | same as above |
| `tls_certificate` | TextValue PEM rows=5 | "" | `\n`-escaped PEM (§1.4) | {tls_use_pem=1} |
| `tls_key` | TextValue PEM | "" | `\n`-escaped | {tls_use_pem=1} |
| `ech` | Flag | "0" | | {tls=1, reality=0} \| {protocol=masque} |
| `ech_key` | TextValue wrap=soft | "" | CR/LF stripped + trim | {ech=1} |
| `transport` | ListValue | (first: raw) | `raw`(RAW), `mkcp`(mKCP), `ws`(WebSocket), `grpc`(gRPC), `httpupgrade`(HttpUpgrade), `xhttp`(XHTTP) | protocol ∈ {vmess, vless, socks, shadowsocks, trojan} |
| `ws_host` | Value | | | {transport=ws} |
| `ws_path` | Value | | | {transport=ws} |
| `httpupgrade_host` | Value | | | {transport=httpupgrade} |
| `httpupgrade_path` | Value | placeholder "/" | | {transport=httpupgrade} |
| `xhttp_host` | Value | | | {transport=xhttp} |
| `xhttp_path` | Value | placeholder "/" | | {transport=xhttp} |
| `xhttp_maxuploadsize` | Value | "1000000" | | {transport=xhttp} |
| `xhttp_maxconcurrentuploads` | Value | "10" | | {transport=xhttp} |
| `splithttp_maxuploadsize` | Value | "1000000" | | {transport=splithttp} — **dead** (no such transport choice; never visible) |
| `splithttp_maxconcurrentuploads` | Value | "10" | | {transport=splithttp} — dead |
| `tcp_guise` | ListValue "Camouflage Type" | (none) | `none`, `http` | {transport=raw} |
| `tcp_guise_http_host` | DynamicList | | | {tcp_guise=http} |
| `tcp_guise_http_path` | DynamicList | | | {tcp_guise=http} |
| `mkcp_guise` | ListValue | (none) | MKCP_HEADERS | {transport=mkcp} |
| `mkcp_domain` | Value | | | {mkcp_guise=dns} |
| `mkcp_mtu` | Value | 1350 | uinteger | {transport=mkcp} |
| `mkcp_seed` | Value | | | {transport=mkcp} |
| `grpc_serviceName` | Value | | | {transport=grpc} |
| `use_finalmask` | Flag "FinalMask" | "0" | | {custom=0,protocol=vmess} \| {custom=0,protocol=vless} \| {custom=0,protocol=trojan} \| {custom=0,protocol=shadowsocks} \| {custom=0,protocol=hysteria2,hysteria2_realms=0} |
| `finalmask` | TextValue JSON rows=10 | | datatype json; base64 stored | {use_finalmask=1} |
| `acceptProxyProtocol` | Flag | "0" | | {transport=raw} \| {transport=ws} |
| `tcp_fast_open` | Flag | "0" | | {protocol=vmess,custom=0} \| vless \| shadowsocks \| trojan (each with custom=0) |
| `fallback` | Flag | (0) | | {protocol=vless,transport=raw} \| {protocol=trojan,transport=raw} |
| `fallback_list` | DynamicList "Fallback" | | each entry format `dest,path,xver` | {fallback=1} |
| `wireguard_mtu` | Value | "1420" | | {protocol=wireguard} |
| `wireguard_private_key` | Value | | base64 | {protocol=wireguard} |
| `wireguard_public_key` | Value | | base64 | {protocol=wireguard} |
| `gen_wireguard_key` | button (not stored) | | fills `xray_wireguard_private_key`/`xray_wireguard_public_key` (prefix applied via `option_prefix`) | {protocol=wireguard} |
| `firewall_allow` | Flag | "0" | | {custom=0} |
| `firewall_allow_src` | Value zone | "wan" | rmempty = not js-luci | {custom=0, firewall_allow=1} |
| `accept_lan` | Flag "Accept LAN Access" | "0" | | {custom=0} |
| `outbound_node` | ListValue (template nodes_listvalue, grouped) | "" | ""(Close), `_socks`(Custom Socks), `_http`(Custom HTTP), `_iface`(Custom Interface), then every **client** node from `api.get_valid_nodes()` with `node_type=="normal"` and `type=="Xray"` (value = node id, label = remark, group = node.group or "default") | {custom=0} |
| `outbound_node_address` | Value | | | {outbound_node=_socks} \| {outbound_node=_http} |
| `outbound_node_port` | Value | | port | same |
| `outbound_node_username` | Value | | | same |
| `outbound_node_password` | Value password | | | same |
| `outbound_node_iface` | Value (combobox) | | choices from `api.get_network_devices()` (name / label) | {outbound_node=_iface} |
| `log` | Flag | "1" rmempty=false | | — |
| `loglevel` | ListValue | "warning" | `debug`, `info`, `warning`, `error` | {log=1} |

`tls` validate (server Xray and server sing-box identical):
```
if value present:
  if reality == "1": ok
  elif value=="1" and tls_use_pem != "1":
      if tls_certificateFile=="" or tls_keyFile=="": error "Certificate and Private key path can not be empty!"
  elif value=="1" and tls_use_pem=="1":
      if tls_certificate=="" or tls_key=="": error "Certificate and Private key PEM can not be empty!"
  return value
```
(field values read from the submitted form of the sibling prefixed fields.)

### 3.4 Server `sing-box` (prefix `singbox_`, requires sing-box)
Capability gates (computed at page build):
* `tags` = `sing-box version` output line `Tags: ...` (cached in `CACHE_PATH/binver_<dev>_<ino>_<size>_<mtime>_<ctime>`); `has(X)` = substring find.
* `ver` = version from `sing-box version` (`^sing-box version (\S+)`), strip leading `v`; `ge114 = ver >= 1.14.0`, `ge115 = ver >= 1.15.0` (`compare_versions`: split on `.`/`-`, numeric parts, `rN` → N, others 0).

SB_SS_SERVER_METHODS = `none, aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305`

Protocol choices (in this order): `direct`(Direct), `mixed`(Mixed), `socks`, `http`, `shadowsocks`, `vmess`, `vless`, `trojan`, `naive`(Naive), `anytls`(AnyTLS); then if has(with_quic): `hysteria`(Hysteria), `tuic`(TUIC), `hysteria2`(Hysteria2); if ge115 && with_quic: `masque`; if has(with_wireguard): `wireguard`; if ge114: `snell`(Snell).

`users` (MultiValue cast=table, user ids) depends: protocol ∈ {mixed, socks, http, shadowsocks, vmess, vless, trojan, naive, anytls} plus each gated protocol added (hysteria, tuic, hysteria2, masque, wireguard, snell).

| option | widget | default | choices / datatype | depends |
|---|---|---|---|---|
| `custom` | Flag | 0 | | — |
| `custom_config`→`config_str` | TextValue JSON | | base64 | {custom=1} |
| `protocol` | ListValue | (first: direct) | see above | {custom=0} |
| `port` | Value | | port | {custom=0} |
| `users` | MultiValue | | | see above |
| *with_quic:* `hysteria_obfs` | Value "Obfs Password" | | | {protocol=hysteria} |
| `hysteria_up_mbps` | Value | "100" | | {protocol=hysteria} |
| `hysteria_down_mbps` | Value | "100" | | {protocol=hysteria} |
| `hysteria_recv_window_conn` | Value | | | {protocol=hysteria} |
| `hysteria_recv_window_client` | Value | | | {protocol=hysteria} |
| `hysteria_max_conn_client` | Value | "1024" | | {protocol=hysteria} |
| `hysteria_disable_mtu_discovery` | Flag | | | {protocol=hysteria} |
| *with_quic:* `tuic_congestion_control` | ListValue | "cubic" | `bbr`, `cubic`, `new_reno` | {protocol=tuic} |
| `tuic_zero_rtt_handshake` | Flag | 0 | | {protocol=tuic} |
| `tuic_heartbeat` | Value | "3" | uinteger | {protocol=tuic} |
| `tuic_alpn` | ListValue | "default" | `default`, `h3`, `h2`, `h3,h2`, `http/1.1`, `h2,http/1.1`, `h3,h2,http/1.1`, `spdy/3.1`, `h3,spdy/3.1` | {protocol=tuic} |
| *with_quic:* `hysteria2_realms`, `hysteria2_realm_url`, `hysteria2_realm_stun`, `hysteria2_realm_upnp`, `hysteria2_obfs_type`, `hysteria2_obfs_password`, `hysteria2_obfs_MinPacketSize`, `hysteria2_obfs_MaxPacketSize`, `hysteria2_ignore_client_bandwidth`, `hysteria2_up_mbps`, `hysteria2_down_mbps` | identical to server Xray (§3.3) (Realms Flag depends {protocol=hysteria2}; no version gate on server) | | | |
| `d_protocol` | ListValue | | `tcp`, `udp`, `tcp,udp` | {protocol=direct} |
| `d_address` | Value | | | {protocol=direct} |
| `d_port` | Value | | port | {protocol=direct} |
| `decryption` | Value "Encrypt Method" | "none" | (no validate) | {protocol=vless} |
| `ss_method` | ListValue | | SB_SS_SERVER_METHODS | {protocol=shadowsocks} |
| `ss_password` | Value | | | {protocol=shadowsocks} |
| `flow` | ListValue | "" | ""(Disable), `xtls-rprx-vision` | {protocol=vless, tls=1} |
| *ge115 && with_quic:* `masque_path` | Value | | | {protocol=masque} |
| `masque_address` | DynamicList rmempty=false | | | {protocol=masque} |
| `masque_mtu` | Value | "1280" | uinteger | {protocol=masque} |
| `tls` | Flag | 0 | validate as §3.3 | protocol ∈ {http, vmess, vless, trojan, anytls} |
| *with_utls:* `reality` | Flag | 0 | | {protocol∈{http,vmess,vless,trojan,anytls}, tls=1} (5 OR entries) |
| `reality_private_key` | Value | | | {reality=1} |
| `reality_shortId` | Value (single!) | | | {reality=1} |
| `reality_handshake_server` | Value | "google.com" | | {reality=1} |
| `reality_handshake_server_port` | Value | "443" | port | {reality=1} |
| `alpn` | ListValue | "default" | `default`, `h3`, `h2`, `h3,h2`, `http/1.1`, `h2,http/1.1`, `h3,h2,http/1.1` | {tls=1, reality=0} \| {protocol=hysteria} |
| `tls_use_pem` | Flag | | | {tls=1,reality=0} \| protocol ∈ {naive, hysteria, tuic, hysteria2, masque} |
| `tls_certificateFile` | FileUpload | UCI or `/etc/config/ssl/<sid>.crt` | must exist if set | {tls=1,reality=0,tls_use_pem=0} \| {protocol=X, tls_use_pem=0} for X ∈ {naive, hysteria, tuic, hysteria2, masque} |
| `tls_keyFile` | FileUpload | UCI or `/etc/config/ssl/<sid>.key` | same | same |
| `tls_certificate` | TextValue PEM | "" | `\n`-escaped | {tls_use_pem=1} |
| `tls_key` | TextValue PEM | "" | `\n`-escaped | {tls_use_pem=1} |
| `ech` | Flag | "0" | | {tls=1, flow="", reality=0} \| {protocol=naive} \| {protocol=hysteria} \| {protocol=tuic} \| {protocol=hysteria2, hysteria2_realms=0} \| {protocol=masque} |
| `ech_key` | TextValue rows=5 wrap=off | "" | **`\n`-escaped PEM** (differs from Xray) | {ech=1} |
| `transport` | ListValue | (first: tcp) | `tcp`(TCP), `http`(HTTP), `ws`(WebSocket), `httpupgrade`(HTTPUpgrade), `quic`(QUIC), `grpc`(gRPC) — not tag-gated on server | protocol ∈ {shadowsocks, vmess, vless, trojan} |
| `http_host` | DynamicList | | | {transport=http} |
| `http_path` | Value | | | {transport=http} |
| `ws_host` / `ws_path` | Value | | | {transport=ws} |
| `httpupgrade_host` / `httpupgrade_path` | Value | | | {transport=httpupgrade} |
| `grpc_serviceName` | Value | | | {transport=grpc} |
| `mux` | Flag rmempty=false | | | {protocol=vmess} \| {protocol=vless, flow=""} \| {protocol=shadowsocks} \| {protocol=trojan} |
| `tcpbrutal` | Flag | 0 | | {mux=1} |
| `tcpbrutal_up_mbps` | Value | "10" | | {tcpbrutal=1} |
| `tcpbrutal_down_mbps` | Value | "50" | | {tcpbrutal=1} |
| *with_wireguard:* `wireguard_system_interface` | Flag | 0 | | {protocol=wireguard} |
| `wireguard_mtu` | Value | "1408" | | {protocol=wireguard} |
| `wireguard_local_address` | DynamicList | | | {protocol=wireguard} |
| `wireguard_private_key` / `wireguard_public_key` | Value | | base64 | {protocol=wireguard} |
| `gen_wireguard_key` | button | | fills `singbox_wireguard_*` | {protocol=wireguard} |
| *ge114:* `snell_version` | ListValue | (5) | `5`, `6` | {protocol=snell} |
| `snell_psk` | Value rmempty=false | | | {protocol=snell} |
| `snell_obfs_mode` | ListValue "Obfs" | (none) | `none`, `http` | {protocol=snell, snell_version=5} |
| `snell_mode` | ListValue | (default) | `default`, `unshaped`, `unsafe-raw` | {protocol=snell, snell_version=6} |
| `firewall_allow` | Flag | "0" | | {custom=0} |
| `firewall_allow_src` | Value zone | "wan" | | {custom=0, firewall_allow=1} |
| `accept_lan` | Flag | "0" | | {custom=0} |
| `outbound_node` | ListValue | "" | as §3.3 but client nodes with `type=="sing-box"` | {custom=0} |
| `outbound_node_address/_port/_username/_password` | Value | | port for _port; password masked | {outbound_node=_socks} \| {outbound_node=_http} |
| `outbound_node_iface` | Value | | network devices | {outbound_node=_iface} |
| `log` | Flag | "1" rmempty=false | | — |
| `loglevel` | ListValue | "info" | `debug`, `info`, `warn`, `error` | {log=1} |

Note: server sing-box has no `tls_*` fields for `naive/hysteria/tuic/hysteria2/masque` other than the PEM/file ones (they always use TLS).

---

## 4. Client types (config `passwall2`, section type `nodes`)

Global context from `client/node_config.lua` (used by type files):
* `groups` = set of `group` values of all other `nodes` sections (non-empty).
* Common (non-type) node fields defined there (other spec): `remarks`, `group`, `type`.
* `node_list = api.get_node_list()`:
  * `socks_list`: each `passwall2.@socks` with `node` set → `{id=<socks sid>, remark="Socks Config [<port>Port]", group="Socks"}`.
  * `normal_list`: valid nodes with `node_type=="normal"` (has address+port/hop, or hy2 realm) → `{id, remark, type, chain_proxy, group}`.
  * `<proto>_list` for special protocols (`_balancing`→`balancing_list`, `_shunt`→`shunt_list`, `_iface`→`iface_list`, `_urltest`→`urltest_list`): `{id, remark, group, o=<whole section>}`.
  * Remark format: `"<Type> <Proto>：[<remarks>]"` (+ ` <addr>:<port>` if `show_node_info=1`); special: `"<Type> <translated proto>：[<remarks>]"`.
* `netdev_list = api.get_network_devices()` → list of `{name, label}` (devices from /sys/class/net + UCI network interfaces).

Protocol-dependent loading (Xray & sing-box): `protocol_val` = POSTed `cbid.passwall2.<id>.<prefix>protocol` if present, else UCI `protocol`. Only the option groups for that kind are built:
* `_balancing` (Xray) / `_urltest` (sing-box) → balancer/urltest block.
* `_iface` → `iface` only.
* `_shunt` → loads `client/include/shunt_options.lua` (separate spec) with `{node={".name"=sid, type=type_name}, node_list}` **after** `type_cbi_section`; no chain-proxy fields.
* anything else → "normal" block.

### 4.1 Client `SSR` (prefix `ssr_`, requires `ssr-local`)
All always visible (only implicit type dep). Lists same as §3.1.

| option | widget | default | choices |
|---|---|---|---|
| `address` | Value "Address (Support Domain Name)" | | |
| `port` | Value | | port |
| `password` | Value (masked) | | |
| `method` | ListValue | | SSR_METHODS |
| `protocol` | ListValue | | SSR_PROTOCOLS |
| `protocol_param` | Value | | |
| `obfs` | ListValue | | SSR_OBFS |
| `obfs_param` | Value | | |
| `timeout` | Value | 300 | uinteger |
| `tcp_fast_open` | Flag "Need node support required" | 0 | |

### 4.2 Client `SS-Rust` (prefix `ssrust_`, requires `sslocal`)
SSRUST_CLIENT_METHODS = `none, plain, aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha8-poly1305, 2022-blake3-chacha20-poly1305`

| option | widget | default | choices / validate | depends |
|---|---|---|---|---|
| `address` | Value | | | — |
| `port` | Value | | port | — |
| `password` | Value masked | | | — |
| `method` | **Value** (combobox, free text) | | SSRUST_CLIENT_METHODS | — |
| `timeout` | Value | 300 | uinteger | — |
| `tcp_fast_open` | Flag | 0 | | — |
| `plugin_enabled` | Flag "plugin" | 0 | | — |
| `plugin` | Value "SIP003 plugin" | "none" | `none` + each of `xray-plugin`, `v2ray-plugin`, `obfs-local`, `shadow-tls` that `is_finded`. Validate: if value non-empty and ≠"none": must be findable binary else "<v>: Can't find this file!"; "none"/empty → nil (option removed) | {plugin_enabled=1} |
| `plugin_opts` | Value "opts" | | | {plugin_enabled=1} |

### 4.3 Client `Xray` (prefix `xray_`)
Lists:
* XRAY_SS_CLIENT_METHODS = `aes-128-gcm, aes-256-gcm, chacha20-poly1305, chacha20-ietf-poly1305, xchacha20-poly1305, xchacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305`
* XRAY_VMESS_SECURITY = `auto, aes-128-gcm, chacha20-poly1305`
* MKCP_HEADERS as §3.3.
* PROBE_URLS (value, label): `https://cp.cloudflare.com/` Cloudflare; `https://www.gstatic.com/generate_204` Gstatic; `https://www.google.com/generate_204` Google; `https://www.youtube.com/generate_204` YouTube; `https://connect.rom.miui.com/generate_204` MIUI (CN); `https://connectivitycheck.platform.hicloud.com/generate_204` HiCloud (CN); `https://wifi.vivo.com.cn/generate_204` VIVO (CN). Default = 3rd (`https://www.google.com/generate_204`).
* USER_AGENTS (value, label): "" default; `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36` chrome; `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0` firefox; `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15` safari; `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70` edge; `Go-http-client/1.1` golang; `curl/7.68.0` curl.
* CIPHER_SUITES: `TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
* FINGERPRINTS (Xray) = `chrome, firefox, edge, safari, 360, qq, ios, android, random, randomized, unsafe`.

`protocol` ListValue (always present): `vmess`, `vless`, `http`, `socks`, `shadowsocks`, `trojan`, `wireguard`, `hysteria2`, `masque`, `_balancing`(Balancing), `_shunt`(Shunt), `_iface`(Custom Interface). Default = first (`vmess`).

#### 4.3.1 Balancing block (`protocol=_balancing`)
`fallback_list` precomputation: every node in `node_list.balancing_list` except self → `{id, remark, group, fallback=o.fallback_node}`; `is_balancer` set if self found (unused).

| option | widget | default | choices | depends |
|---|---|---|---|---|
| `node_add_mode` | ListValue | "manual" | `manual`, `batch` | {protocol=_balancing} |
| `balancing_node` | MultiValue checkbox, cast=table (UCI list), template nodes_multivalue (grouped) | | all of `socks_list` + `normal_list` (id/remark, group=v.group or "") | {node_add_mode=manual} |
| `node_group` | MultiValue checkbox, cast not set (CBI default `"string"`) ⇒ stored as one **space-separated string** option | | `default` + `UrlEncode(g)` for each group g (label g) | {node_add_mode=batch} |
| `node_match_rule` | Value | | expression: `&&` AND, `||` OR, `^` prefix, `$` suffix, `!` exclude | {node_add_mode=batch} |
| `balancingStrategy` | ListValue | "random" | `random`, `roundRobin`, `leastPing`, `leastLoad` | {protocol=_balancing} |
| `fallback_node` | ListValue grouped | "" | ""(Close(Not use)), `_direct`(Direct Connection), then eligible balancers (see below), then all `socks_list`, `normal_list`, `urltest_list` nodes | {protocol=_balancing} |
| `useCustomProbeUrl` | Flag | | | {protocol=_balancing} |
| `probeUrl` | Value combobox | PROBE_URLS[3] | PROBE_URLS | {useCustomProbeUrl=1} |
| `probeInterval` | Value | "1m" | time `\d+[smh]...`, no unit = seconds | {protocol=_balancing} |
| `expected` | Value "Preferred Node Count" | "2" | uinteger | {balancingStrategy=leastLoad} |
| `tolerance` | Value "Failure Tolerance (%)" | "10" | uinteger | {balancingStrategy=leastLoad} |

Balancer eligibility for `fallback_node` (MAX_FALLBACK_DEPTH = 3):
```
depth(id, d=0): if d>=3 return d
   v = fallback_list[id]; if none return d
   fb = v.fallback; if fb in (nil,"","_direct") return d
   return depth(fb, d+1)
will_loop(start, target, d=0): if d>=3 return false
   v = fallback_list[target]; if none return false
   fb = v.fallback; if fb in (nil,"","_direct") return false
   if fb == start return true
   return will_loop(start, fb, d+1)
include balancer v iff depth(v.id) < 3 and not will_loop(self_id, v.id)
```

#### 4.3.2 Custom interface block (`protocol=_iface`)
* `iface` Value combobox, choices netdev_list (name/label), depends {protocol=_iface}.

#### 4.3.3 Normal block (any non-`_` protocol)
| option | widget | default | choices / datatype / validate | depends |
|---|---|---|---|---|
| `address` | Value | | | added at end: for each non-`_` protocol P: {protocol=P} (P=hysteria2 adds `hysteria2_realms=0`) |
| `port` | Value | | port | same as address |
| `uuid` | Value "ID" masked | | | {protocol=vmess} \| {protocol=vless} |
| `username` | Value | | | protocol ∈ {http, socks, masque} |
| `password` | Value masked | | | protocol ∈ {http, socks, shadowsocks, trojan, masque} |
| `masque_warp` | Flag "WARP" | "0" | | {protocol=masque} |
| `masque_warp_private_key` | TextValue rows=3 | | trim, CRLF/CR→LF, then `\n`-escaped (no space stripping) | {protocol=masque, masque_warp=1} |
| `masque_warp_public_key` | TextValue rows=3 | | same | same |
| `masque_warp_address` | DynamicList "WARP Local Address" | | | {protocol=masque, masque_warp=1} |
| `masque_path` | Value | | | {protocol=masque} |
| `masque_headers` | TextValue rows=5 | | validate below; `\n`-escaped | {protocol=masque} |
| `security` | ListValue | (auto) | XRAY_VMESS_SECURITY | {protocol=vmess} |
| `encryption` | Value | "none" | trim, ""→"none" | {protocol=vless} |
| `ss_method` | ListValue | | XRAY_SS_CLIENT_METHODS | {protocol=shadowsocks} |
| `flow` | ListValue | "" | ""(Disable), `xtls-rprx-vision`, `xtls-rprx-vision-udp443` | {protocol=vless} |
| `hysteria2_hop` | Value "Port hopping range" | | format `1000:2000` or `1000-2000`, comma separated groups | {protocol=hysteria2, hysteria2_realms=0} |
| `hysteria2_hop_interval` | Value | "30" | `or(uinteger,portrange)` (fixed or `5-30`, min 5) | {protocol=hysteria2, hysteria2_realms=0} |
| `hysteria2_realms` | Flag | "0" | | {protocol=hysteria2} |
| `hysteria2_realm_url` | Value | | parse_realm_uri must succeed | {hysteria2_realms=1} |
| `hysteria2_realm_stun` | DynamicList | 3 STUN defaults (§3.3) | | {hysteria2_realms=1} |
| `hysteria2_realm_upnp` | Flag | "0" | | {hysteria2_realms=1} |
| `hysteria2_auth_password` | Value masked | | | {protocol=hysteria2} |
| `hysteria2_obfs_type` | ListValue | "" | "", `salamander`, `gecko` | {protocol=hysteria2} |
| `hysteria2_obfs_password` | Value | | | {obfs_type=salamander} \| {obfs_type=gecko} |
| `hysteria2_obfs_MinPacketSize` | Value | "512" | uinteger | {hysteria2_obfs_type=gecko} |
| `hysteria2_obfs_MaxPacketSize` | Value | "1200" | uinteger | {hysteria2_obfs_type=gecko} |
| `hysteria2_up_mbps` | Value | | | {protocol=hysteria2} |
| `hysteria2_down_mbps` | Value | | | {protocol=hysteria2} |
| `hysteria2_stream_recv_win` | Value "(MB)" | placeholder 8 | range(1,1000) | {protocol=hysteria2} |
| `hysteria2_conn_recv_win` | Value "(MB)" | placeholder 20 | range(1,1000) | {protocol=hysteria2} |
| `hysteria2_idle_timeout` | Value (s) | | range(4,120) | {protocol=hysteria2} |
| `hysteria2_keep_alive_period` | Value (s) | | range(2,60) | {protocol=hysteria2} |
| `hysteria2_disable_mtu_discovery` | Flag | "0" | | {protocol=hysteria2} |
| `tls` | Flag | 0 | | protocol ∈ {vmess, vless, http, socks, trojan, shadowsocks} |
| `reality` | Flag | 0 | | {tls=1, transport ∈ raw/ws/grpc/httpupgrade/xhttp} (5 entries) |
| `alpn` | ListValue | "default" | `default`, `h3`, `h2`, `h3,h2`, `http/1.1`, `h2,http/1.1`, `h3,h2,http/1.1` | {tls=1, reality=0} \| {protocol=masque} |
| `tls_serverName` | Value "SNI Domain" | | | {tls=1} \| {protocol=hysteria2} \| {protocol=masque} |
| `tls_pinSHA256` | Value | | description has "Fetch Manually" link → JS `fetchCertSha256(this)` (defined elsewhere; backend uses `openssl s_client`) | {tls=1, reality=0} \| {protocol=hysteria2} \| {protocol=masque} |
| `tls_CertByName` | Value | | | same as tls_pinSHA256 |
| `tls_certificate` | **Flag** "TLS Certificate (PEM)" | "0" | | same as tls_pinSHA256 |
| `tls_certificate_pem` | TextValue | "" | `\n`-escaped PEM | {tls_certificate=1} |
| `ech` | Flag | "0" | | {tls=1, reality=0} \| {protocol=hysteria2, hysteria2_realms=0} \| {protocol=masque} |
| `ech_config` | TextValue wrap=soft | "" | CR/LF stripped + trim | {ech=1} |
| `reality_publicKey` | Value | | | {tls=1, reality=1} |
| `reality_shortId` | Value | | | {tls=1, reality=1} |
| `reality_spiderX` | Value | placeholder "/" | | {tls=1, reality=1} |
| `utls` | Flag | "0" | | {tls=1, reality=0} |
| `fingerprint` | ListValue | "chrome" | FINGERPRINTS (Xray) | {tls=1, utls=1} \| {tls=1, reality=1} |
| `use_mldsa65Verify` | Flag | "0" | | {tls=1, reality=1} |
| `cipherSuites` | DynamicList | | CIPHER_SUITES suggestions | {tls=1, reality=0} \| {protocol=masque} |
| `reality_mldsa65Verify` | TextValue wrap=soft | "" | CR/LF stripped + trim | {use_mldsa65Verify=1} |
| `transport` | ListValue | (raw) | `raw`(RAW (TCP)), `mkcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` | protocol ∈ {vmess, vless, socks, shadowsocks, trojan} |
| `wireguard_public_key` | Value | | | {protocol=wireguard} |
| `wireguard_secret_key` | Value "Private Key" | | | {protocol=wireguard} |
| `wireguard_preSharedKey` | Value | | | {protocol=wireguard} |
| `wireguard_local_address` | DynamicList | | | {protocol=wireguard} |
| `wireguard_mtu` | Value | "1420" | | {protocol=wireguard} |
| `wireguard_reserved` | Value | | decimal numbers separated by "," or base64 | {protocol=wireguard} |
| `wireguard_keepAlive` | Value | "0" | | {protocol=wireguard} |
| `tcp_guise` | ListValue | (none) | `none`, `http` | {transport=raw} |
| `tcp_guise_http_host` | DynamicList | | | {tcp_guise=http} |
| `tcp_guise_http_path` | DynamicList | placeholder "/" | | {tcp_guise=http} |
| `mkcp_guise` | ListValue | (none) | MKCP_HEADERS | {transport=mkcp} |
| `mkcp_domain` | Value | | | {mkcp_guise=dns} |
| `mkcp_mtu` | Value | 1350 | uinteger | {transport=mkcp} |
| `mkcp_seed` | Value | | | {transport=mkcp} |
| `ws_host` | Value | | | {transport=ws} |
| `ws_path` | Value | placeholder "/" | | {transport=ws} |
| `ws_heartbeatPeriod` | Value (s) | | integer | {transport=ws} |
| `grpc_serviceName` | Value | | | {transport=grpc} |
| `grpc_mode` | ListValue "gRPC Transfer mode" | (gun) | `gun`, `multi` | {transport=grpc} |
| `grpc_health_check` | Flag | | | {transport=grpc} |
| `grpc_idle_timeout` | Value | "10" | | {grpc_health_check=1} |
| `grpc_health_check_timeout` | Value | "20" | | {grpc_health_check=1} |
| `grpc_permit_without_stream` | Flag | "0" | | {grpc_health_check=1} |
| `grpc_initial_windows_size` | Value | "0" | | {transport=grpc} |
| `httpupgrade_host` | Value | | | {transport=httpupgrade} |
| `httpupgrade_path` | Value | placeholder "/" | | {transport=httpupgrade} |
| `xhttp_mode` | ListValue | "auto" | `auto`, `packet-up`, `stream-up`, `stream-one` | {transport=xhttp} |
| `xhttp_host` | Value | | | {transport=xhttp} |
| `xhttp_path` | Value | placeholder "/" | | {transport=xhttp} |
| `use_xhttp_extra` | Flag | "0" | | {transport=xhttp} |
| `xhttp_extra` | TextValue JSON rows=10 | | see below | {use_xhttp_extra=1} |
| `user_agent` | Value combobox | "" | USER_AGENTS | {tcp_guise=http} \| {transport=ws} \| {transport=httpupgrade} \| {transport=xhttp} \| {transport=grpc} \| {protocol=masque} |
| `mux` | Flag "Mux" (Enable Mux.Cool) | (0) | | {protocol=vmess} \| {protocol=vless, transport ∈ raw/ws/grpc/httpupgrade} (4 entries) \| {protocol=http} \| {protocol=socks} \| {protocol=shadowsocks} \| {protocol=trojan} |
| `mux_concurrency` | Value | -1 | | {mux=1} |
| `xudp_concurrency` | Value | 8 | | {mux=1} |
| `use_finalmask` | Flag | "0" | | protocol ∈ {vmess, vless, trojan, shadowsocks, wireguard, masque} \| {protocol=hysteria2, hysteria2_realms=0} |
| `finalmask` | TextValue JSON | | normalise (below) then JSON validate (error "FinalMask Must be JSON text!"); base64 stored. Overrides mkcp/hysteria2/fragment/noise settings | {use_finalmask=1} |
| `tcp_fast_open` | Flag | 0 | | added at end: {protocol=P} for every non-`_` P except hysteria2 |
| `tcpMptcp` | Flag | 0 | | same as tcp_fast_open |
| `domain_resolver` | ListValue "Domain DNS Resolve" | "" | ""(Auto), `tcp`, `udp`, `https` | same as address |
| `domain_resolver_dns` | Value combobox | "114.114.114.114" | `or(ipaddr,ipaddrport)`; suggestions `114.114.114.114`, `223.5.5.5:53` | {domain_resolver=tcp} \| {domain_resolver=udp} |
| `domain_resolver_dns_https` | Value combobox | `https://120.53.53.53/dns-query` | DNSPod `https://120.53.53.53/dns-query`, AliDNS `https://223.5.5.5/dns-query` | {domain_resolver=https} |
| `domain_strategy` | ListValue | "" | ""(Auto), `UseIPv4`(IPv4 Only), `UseIPv6`(IPv6 Only) | for each P: {protocol=P [,hysteria2_realms=0 if hy2], happy_eyeballs=0} |
| `happy_eyeballs` | Flag "Enable Happy Eyeballs" | 0 | | same as address |

`masque_headers` validate (client Xray):
```
v = trim(value) with CRLF/CR → LF
seen = {}
for each non-blank line:
  key = match ^\s*([^:]+):  -> trim, lowercase
  error "Not true format, please re-enter! (<line>)" if
     key missing, or key !~ ^[!#$%&'*+.^_`|~0-9A-Za-z-]+$, or key in seen,
     or key == "host" or key == "capsule-protocol"     (Xray only; sing-box omits these two)
  seen[key]=true
store v with \n → literal "\n"
```

`xhttp_extra` / `finalmask` normalisation before JSON validate: `trim → \r\n→\n → strip leading blank line → strip trailing blank line → collapse blank lines`.
`xhttp_extra.write`: store base64(value); parse JSON; `address = data.extra.downloadSettings.address or data.downloadSettings.address`; if non-empty: strip `[`/`]` and `uci set download_address=<addr>`; else (or parse failure) `uci delete download_address`. `remove`: delete both `xhttp_extra` and `download_address`.
(Note `download_address` is written directly with `m:set`, no type gating.)

Dependency post-pass (normal block, end of section) — for each protocol key P in `protocol` choices not starting with `_`:
```
cond = {protocol=P}; if P=="hysteria2": cond.hysteria2_realms=false
address.depends(cond); port.depends(cond); domain_resolver.depends(cond); happy_eyeballs.depends(cond)
domain_strategy.depends(cond + {happy_eyeballs=false})
if P != "hysteria2": tcp_fast_open.depends({protocol=P}); tcpMptcp.depends({protocol=P})
```
⇒ With hysteria2 Realm enabled the node has no address/port.

#### 4.3.4 Chain proxy block (Xray and sing-box, all kinds except `_shunt`)
| option | widget | default | choices | depends |
|---|---|---|---|---|
| `chain_proxy` | ListValue | "" | ""(Close(Not use)); if kind is normal: `1`(Preproxy Node), `3`(Outbound Interface); always `2`(Landing Node). Order: "", 1, 3, 2 | — (type only) |
| `preproxy_node` | ListValue grouped | | every node in every `node_list` key except `shunt_list`/`iface_list` (i.e. socks_list, normal_list, balancing_list/urltest_list), excluding self | {chain_proxy=1, hysteria2_realms=0} |
| `outbound_iface` | Value combobox | | ""(All) + netdev_list | {chain_proxy=3} |
| `to_node` | ListValue grouped | | only `normal_list` nodes excluding self | {chain_proxy=2, hysteria2_realms=0} |

Group label for these lists: node.group if non-empty else "default".

### 4.4 Client `sing-box` (prefix `singbox_`)
Gates: `tags`, `ge114`, `ge115` as §3.4.

Lists:
* SB_SS_NEW = `none, aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305`
* SB_SS_OLD = `aes-128-ctr, aes-192-ctr, aes-256-ctr, aes-128-cfb, aes-192-cfb, aes-256-cfb, rc4-md5, chacha20-ietf, xchacha20`
* SB_VMESS_SECURITY = `none, auto, aes-128-gcm, chacha20-poly1305, zero`
* FINGERPRINTS (sing-box) = `chrome, firefox, edge, safari, 360, qq, ios, android, random, randomized` (no `unsafe`).
* PROBE_URLS, USER_AGENTS, CIPHER_SUITES as §4.3.

`protocol` choices in order: `socks`, `http`, `shadowsocks`, [with_shadowsocksr: `shadowsocksr`], `vmess`, `trojan`, [with_wireguard: `wireguard`], [with_quic: `hysteria`], `vless`, [with_quic: `tuic`], [with_quic: `hysteria2`], `anytls`, `ssh`, [with_naive_outbound: `naive` "NaïveProxy"], [ge114: `snell`], [ge115 && with_quic: `masque`], `_urltest`(URLTest), `_shunt`(Shunt), `_iface`(Custom Interface). Default first (`socks`).

#### 4.4.1 URLTest block (`protocol=_urltest`)
| option | widget | default | choices | depends |
|---|---|---|---|---|
| `node_add_mode` | ListValue | "manual" | manual, batch | {protocol=_urltest} |
| `urltest_node` | MultiValue checkbox cast=table, grouped | | socks_list + normal_list | {node_add_mode=manual} |
| `node_group` | MultiValue checkbox | | `default` + UrlEncode(group) | {node_add_mode=batch} |
| `node_match_rule` | Value | | (same syntax as §4.3.1) | {node_add_mode=batch} |
| `urltest_url` | Value combobox | PROBE_URLS[3] (google generate_204) | PROBE_URLS | {protocol=_urltest} |
| `urltest_interval` | Value | "3m" | time string; must be ≤ idle timeout (doc only) | {protocol=_urltest} |
| `urltest_tolerance` | Value (ms) | "50" | uinteger | {protocol=_urltest} |
| `urltest_idle_timeout` | Value | "30m" | time string | {protocol=_urltest} |
| `urltest_interrupt_exist_connections` | Flag | "0" | | {protocol=_urltest} |

#### 4.4.2 `_iface`: `iface` Value combobox (netdev_list), depends {protocol=_iface}.

#### 4.4.3 Normal block
| option | widget | default | choices / datatype / validate | depends |
|---|---|---|---|---|
| `address` | Value | | | post-pass (below) |
| `port` | Value | | port | post-pass |
| `uuid` | Value "ID" masked | | | protocol ∈ {vmess, vless, tuic} |
| `username` | Value | | | protocol ∈ {http, socks, ssh, naive, masque} |
| `password` | Value masked | | | protocol ∈ {http, socks, shadowsocks, shadowsocksr, trojan, tuic, anytls, ssh, naive, masque} + (ge114) snell |
| `masque_path` | Value | | | {protocol=masque} (field built regardless of gate) |
| `masque_headers` | TextValue | | header validate (§4.3.3) **without** host/capsule-protocol ban; `\n`-escaped | {protocol=masque} |
| *ge114:* `snell_psk` | Value rmempty=false | | | {protocol=snell} |
| `snell_version` | ListValue | (4) | `4`, `6` | {protocol=snell} |
| `snell_reuse` | Flag "reuse" | | | {protocol=snell} |
| `snell_network` | ListValue | "" | ""("TCP UDP"), `tcp`, `udp` | {protocol=snell} |
| `snell_obfs_mode` | ListValue "Camouflage Type" | (none) | `none`, `http` | {protocol=snell, snell_version=4} |
| `snell_obfs_host` | Value "HTTP Host" | | | {protocol=snell, snell_version=4, snell_obfs_mode=http} |
| `snell_mode` | ListValue | (default) | `default`, `unshaped`, `unsafe-raw` | {protocol=snell, snell_version=6} |
| `security` | ListValue | (none) | SB_VMESS_SECURITY | {protocol=vmess} |
| `ss_method` | ListValue | | SB_SS_NEW then SB_SS_OLD | {protocol=shadowsocks} |
| *with_shadowsocksr:* `ssr_method` | ListValue | | SB_SS_OLD | {protocol=shadowsocksr} |
| `ssr_protocol` | ListValue | | SSR_PROTOCOLS | {protocol=shadowsocksr} |
| `ssr_protocol_param` | Value | | | {protocol=shadowsocksr} |
| `ssr_obfs` | ListValue | | SSR_OBFS | {protocol=shadowsocksr} |
| `ssr_obfs_param` | Value | | | {protocol=shadowsocksr} |
| `uot` | Flag "UDP over TCP" | | | protocol ∈ {socks, shadowsocks, naive} |
| `alter_id` | Value "Alter ID" | "0" | uinteger | {protocol=vmess} |
| `global_padding` | Flag | "0" | | {protocol=vmess} |
| `authenticated_length` | Flag | "0" | | {protocol=vmess} |
| `flow` | ListValue | "" | ""(Disable), `xtls-rprx-vision` | {protocol=vless, tls=1} |
| *with_quic:* `hysteria_hop` | Value | | port ranges | {protocol=hysteria} |
| `hysteria_hop_interval` | Value | "30" | uinteger (≥5) | {protocol=hysteria} |
| `hysteria_obfs` | Value | | | {protocol=hysteria} |
| `hysteria_auth_type` | ListValue | (disable) | `disable`, `string`, `base64` | {protocol=hysteria} |
| `hysteria_auth_password` | Value masked | | | {protocol=hysteria, hysteria_auth_type=string} \| {…=base64} |
| `hysteria_up_mbps` | Value | "10" | | {protocol=hysteria} |
| `hysteria_down_mbps` | Value | "50" | | {protocol=hysteria} |
| `hysteria_recv_window_conn` | Value | | | {protocol=hysteria} |
| `hysteria_recv_window` | Value | | | {protocol=hysteria} |
| `hysteria_disable_mtu_discovery` | Flag | | | {protocol=hysteria} |
| *with_quic:* `tuic_congestion_control` | ListValue | "cubic" | bbr, cubic, new_reno | {protocol=tuic} |
| `tuic_udp_relay_mode` | ListValue | "native" | `native`, `quic` | {protocol=tuic} |
| `tuic_zero_rtt_handshake` | Flag | 0 | | {protocol=tuic} |
| `tuic_heartbeat` | Value | "3" | uinteger | {protocol=tuic} |
| `tuic_alpn` | ListValue | "default" | default, h3, h2, h3,h2, http/1.1, h2,http/1.1, h3,h2,http/1.1, spdy/3.1, h3,spdy/3.1 | {protocol=tuic} |
| *with_quic:* `hysteria2_hop`, `hysteria2_hop_interval` | as §4.3.3 | "30" | | {protocol=hysteria2, hysteria2_realms=0} |
| `hysteria2_realms` | Flag | "0" | | ge114 ? {protocol=hysteria2} : {protocol=__hide} (never shown) |
| `hysteria2_realm_url`, `hysteria2_realm_stun`, `hysteria2_realm_upnp`, `hysteria2_auth_password`, `hysteria2_obfs_type`, `hysteria2_obfs_password`, `hysteria2_obfs_MinPacketSize`, `hysteria2_obfs_MaxPacketSize`, `hysteria2_up_mbps`, `hysteria2_down_mbps`, `hysteria2_stream_recv_win`, `hysteria2_conn_recv_win`, `hysteria2_idle_timeout`, `hysteria2_keep_alive_period`, `hysteria2_disable_mtu_discovery` | identical to client Xray §4.3.3 | | | |
| `ssh_priv_key` | TextValue rows=5 | | trim, CRLF→LF, strip spaces around LF, collapse LFs (stored with real newlines) | {protocol=ssh} |
| `ssh_priv_key_pp` | Value masked | | | {protocol=ssh} |
| `ssh_host_key` | DynamicList | | empty = accept any | {protocol=ssh} |
| `ssh_host_key_algo` | DynamicList | | | {protocol=ssh} |
| `ssh_client_version` | Value | | empty = random | {protocol=ssh} |
| `naive_insecure_concurrency` | Value "Concurrent Tunnels" | "0" | uinteger | {protocol=naive} |
| `naive_quic` | Flag | 0 | | {protocol=naive} |
| `naive_congestion_control` | ListValue | "bbr" | `bbr`, `bbr2`, `cubic`, `reno` | {naive_quic=1} |
| `tls` | Flag | 0 | | protocol ∈ {vmess, vless, http, trojan, shadowsocks, anytls} |
| `alpn` | ListValue | "default" | default, h3, h2, h3,h2, http/1.1, h2,http/1.1, h3,h2,http/1.1 | {tls=1} \| {protocol=hysteria} |
| `tls_disable_sni` | Flag | "0" | | {tls=1} \| protocol ∈ {hysteria, tuic, hysteria2, masque} |
| `tls_serverName` | Value | | | {tls=1} \| protocol ∈ {hysteria, tuic, hysteria2, naive, masque} |
| `tls_allowInsecure` | Flag | "0" | | {tls=1} \| protocol ∈ {hysteria, tuic, hysteria2, masque} |
| `tls_pinSHA256` | Value (+Fetch Manually link) | | | {tls=1} \| protocol ∈ {hysteria, tuic, hysteria2, masque} |
| `tls_certificate` | Flag | "0" | | {tls=1, reality=0} \| protocol ∈ {hysteria, tuic, hysteria2, naive, masque} |
| `tls_certificate_pem` | TextValue | "" | `\n`-escaped PEM | {tls_certificate=1} |
| `cipherSuites` | DynamicList | | CIPHER_SUITES | {tls=1} \| {protocol=masque} |
| `ech` | Flag | "0" | | {tls=1, flow="", reality=0} \| {protocol=tuic} \| {protocol=hysteria} \| {protocol=hysteria2, hysteria2_realms=0} \| {protocol=naive} \| {protocol=masque} |
| `ech_config` | TextValue wrap=off | "" | `\n`-escaped PEM | {ech=1} |
| `ech_query_server_name` | Value | | | {ech=1} |
| *with_utls:* `utls` | Flag | "0" | | {tls=1} |
| `fingerprint` | ListValue | "chrome" | FINGERPRINTS (sing-box) | {utls=1} |
| `reality` | Flag | 0 | | {protocol=P, tls=1} for P ∈ {vless, vmess, shadowsocks, socks, trojan, anytls, http} |
| `reality_publicKey` | Value | | | {reality=1} |
| `reality_shortId` | Value | | | {reality=1} |
| `anytls_disable_reuse` | Flag "Disable TLS Reuse" | 0 | | {protocol=anytls} |
| `transport` | ListValue | (tcp) | `tcp`, `http`, `ws`, `httpupgrade`, [with_quic `quic`], `grpc` (label "gRPC" if with_grpc else "gRPC-lite") | protocol ∈ {vmess, vless, socks, shadowsocks, trojan} |
| *with_wireguard:* `wireguard_public_key` | Value | | | {protocol=wireguard} |
| `wireguard_secret_key` | Value | | | {protocol=wireguard} |
| `wireguard_preSharedKey` | Value | | | {protocol=wireguard} |
| `wireguard_local_address` | DynamicList | | | {protocol=wireguard} |
| `wireguard_mtu` | Value | "1420" | | {protocol=wireguard} |
| `wireguard_system_interface` | Flag | 0 | | {protocol=wireguard} |
| `wireguard_interface_name` | Value | | | {protocol=wireguard} |
| `wireguard_reserved` | Value | | | {protocol=wireguard} |
| `tcp_guise` | ListValue | (none) | none, http | {transport=tcp} |
| `tcp_guise_http_host` | DynamicList | | | {tcp_guise=http} |
| `tcp_guise_http_path` | DynamicList | placeholder "/" | | {tcp_guise=http} |
| `http_host` | DynamicList | | | {transport=http} |
| `http_path` | Value | placeholder "/" | | {transport=http} |
| `http_h2_health_check` | Flag | | | {tls=1, transport=http} |
| `http_h2_read_idle_timeout` | Value | "15" | | {http_h2_health_check=1} |
| `http_h2_health_check_timeout` | Value | "15" | | {http_h2_health_check=1} |
| `ws_host` | Value | | | {transport=ws} |
| `ws_path` | Value | placeholder "/" | | {transport=ws} |
| `ws_enableEarlyData` | Flag | | | {transport=ws} |
| `ws_maxEarlyData` | Value | "1024" | | {ws_enableEarlyData=1} |
| `ws_earlyDataHeaderName` | Value (recommended `Sec-WebSocket-Protocol`) | | | {ws_enableEarlyData=1} |
| `httpupgrade_host` / `httpupgrade_path`(placeholder /) | Value | | | {transport=httpupgrade} |
| `grpc_serviceName` | Value | | | {transport=grpc} |
| `grpc_health_check` | Flag | | | {transport=grpc} |
| `grpc_idle_timeout` | Value | "15" | | {grpc_health_check=1} |
| `grpc_health_check_timeout` | Value | "15" | | {grpc_health_check=1} |
| `grpc_permit_without_stream` | Flag | "0" | | {grpc_health_check=1} |
| `user_agent` | Value combobox | "" | USER_AGENTS | {tcp_guise=http} \| {transport=http} \| {transport=ws} \| {transport=httpupgrade} \| {protocol=naive} \| {protocol=masque} |
| `mux` | Flag rmempty=false | | | {protocol=vmess} \| {protocol=vless, flow=""} \| {protocol=shadowsocks, uot=""} \| {protocol=trojan} |
| `mux_type` | ListValue | (smux) | `smux`, `yamux`, `h2mux` | {mux=1} |
| `mux_concurrency` | Value | 4 | | {mux=1, tcpbrutal=0} |
| `mux_padding` | Flag | 0 | | {mux=1} |
| `tcpbrutal` | Flag | 0 | | {mux=1} |
| `tcpbrutal_up_mbps` | Value | "10" | | {tcpbrutal=1} |
| `tcpbrutal_down_mbps` | Value | "50" | | {tcpbrutal=1} |
| `shadowtls` | Flag "ShadowTLS" | 0 | | {protocol=vmess, tls=0} \| {protocol=shadowsocks, tls=0} |
| `shadowtls_version` | ListValue | "1" | `1`(v1), `2`(v2), `3`(v3) | {shadowtls=1} |
| `shadowtls_password` | Value masked | | | {shadowtls=1, shadowtls_version=2} \| {…=3} |
| `shadowtls_serverName` | Value | | | {shadowtls=1} |
| *with_utls:* `shadowtls_utls` | Flag | "0" | | {shadowtls=1} |
| `shadowtls_fingerprint` | ListValue | "chrome" | `chrome, firefox, edge, safari, qq, ios, random` | {shadowtls=1, shadowtls_utls=1} |
| `plugin_enabled` | Flag "plugin" | 0 | | {protocol=shadowsocks} |
| `plugin` | ListValue "SIP003 plugin" | "obfs-local" | `obfs-local`, `v2ray-plugin` | {plugin_enabled=1} |
| `plugin_opts` | Value | | | {plugin_enabled=1} |
| `domain_resolver` | ListValue | "" | ""(Auto), tcp, udp, https | post-pass |
| `domain_resolver_dns` | Value | "114.114.114.114" | or(ipaddr,ipaddrport); suggestions 114.114.114.114, 223.5.5.5:53 | {domain_resolver=tcp} \| {domain_resolver=udp} |
| `domain_resolver_dns_https` | Value | `https://120.53.53.53/dns-query` | DNSPod / AliDNS | {domain_resolver=https} |
| `domain_strategy` | ListValue | "" | ""(Auto), `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only` | post-pass |

Post-pass (sing-box): for each non-`_` protocol P in choices: cond={protocol=P} (+`hysteria2_realms=false` for hysteria2); `address`, `port`, `domain_resolver`, `domain_strategy` depend on cond. (No happy_eyeballs / tcp_fast_open / tcpMptcp in sing-box client.)

Chain-proxy block: identical to §4.3.4 (the "special" check uses `_iface` / `_urltest`).

Note: sing-box `reality` field lives only in with_utls builds; `tls_certificate` depends on `reality=0` which is satisfied when the reality field is absent.

---

## 5. Implementation notes for the Rust/JS rewrite

1. UCI schema is flat per section; the JS form should render per-(type,protocol) field sets from the tables above and write unprefixed option names. When the user switches `type` (client or server), reproduce the original "save minimal + reload" behaviour: server writes `{enable, remarks, type, protocol:""}` (via `server_update_config`).
2. Deleting hidden options on save is part of the observable behaviour (configs generated later rely on absence). Apply "remove when hidden" only for the active type's fields (other types' leftover options are untouched, because write/remove are gated on the selected type).
3. Keep the exact encodings in §1.4 (base64 for `config_str`, `finalmask`, `xhttp_extra`; literal `\n` escapes for PEM-like fields; `download_address` side effect).
4. Capability gates must be computed from the installed binaries (sing-box tags/version; presence of xray, sslocal, ssserver, ssr-local, ssr-server, plugins) — not hard-coded.
5. Server user deletion cascades into `server.user` and `server.users` (§2.1).
6. Endpoints used by these pages: `server_status`, `server_log`, `server_get_log`, `server_clear_log`, `server_update_config`, `gen_wireguard_key`; logs at `/tmp/log/passwall2_server.log` and `/tmp/etc/passwall2_server/<id>.log`; default TLS paths `/etc/config/ssl/<sid>.crt|.key`.
