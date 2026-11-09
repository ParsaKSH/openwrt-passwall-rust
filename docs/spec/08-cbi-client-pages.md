# 08 — CBI client pages (`luasrc/model/cbi/passwall2/client/*.lua`, `client/include/*.lua`)

Scope: every client-side LuCI CBI page model except `client/type/*` (per-core node editors, covered elsewhere).
UCI config is always `passwall2` (Map() with no arg defaults to `c_config = "passwall2"`).

Files covered (line counts):

| File | Lines | URL (`admin/services/passwall2/...`) | Menu title / order |
|---|---|---|---|
| global.lua | 423 | `settings` (cbi, `.dependent`) | "Basic Settings", 1 |
| node_list.lua | 49 | `node_list` | "Node List", 2 |
| node_subscribe.lua | 222 | `node_subscribe` | "Node Subscribe", 3 |
| other.lua | 303 | `other` | "Other Settings", 92 |
| haproxy.lua | 181 | `haproxy` (only if `/usr/sbin/haproxy` exists) | "Load Balancing", 93 |
| app_update.lua | 37 | `app_update` | "App Update", 95 |
| rule.lua | 108 | `rule` | "Rule Manage", 96 |
| geoview.lua | 17 | `geoview` (SimpleForm; only if `finded_com("geoview")`) | "Geo View", 97 |
| acl.lua | 73 | `acl` | "Access control", 98 |
| node_subscribe_config.lua | 329 | `node_subscribe_config/<sid>` (hidden) | — |
| node_config.lua | 87 | `node_config/<sid>` (hidden) | — |
| shunt_rules.lua | 267 | `shunt_rules/<sid>` (hidden) | — |
| socks_config.lua | 182 | `socks_config/<sid>` (hidden) | — |
| acl_config.lua | 399 | `acl_config/<sid>` (hidden) | — |
| include/shunt_options.lua | 268 | included by global.lua & acl_config.lua | — |

---

## 0. Common framework behavior (from `api.set_default_cbi()` / `api.return_map()`)

Needed to understand every page; the Rust/JS rewrite must reproduce the *effective* semantics.

- `Map()` → config `passwall2`; `m.api = api`; if `/www/luci-static/resources/uci.js` is a regular file → `m.is_js_luci = true`, `apply_on_parse = false` (i.e. modern LuCI; in this case some option choices are computed server-side instead of via per-value dependencies — see Remote DNS Protocol).
- `Map.foreach(stype, fn)` = `uci:foreach("passwall2", stype, fn)`; `fn` returning `false` stops iteration.
- `m:get(sid)` returns the whole section table (with `.name`, `.type`); `m:get(sid, opt)`; `m:set`, `m:del`. Section ids like `@global[0]` are resolved by UCI (first section of type `global`).
- `appendTemplate(path, data)` inserts a template `passwall2<path>` with fields of `data` copied onto it (templates are covered in a separate spec; listed here per page).
- `return_map(m)` prepends template `passwall2/cbi/header` and appends `passwall2/cbi/footer` to every map.
- Language auto-detect side effect: when `luci.main.lang == "auto"`, parse `HTTP_ACCEPT_LANGUAGE` tokens (`[%w-]+`, `-`→`_`, try as-is then lowercase) against `luci.languages.<lang>`; first match is written (`sh_uci_set ... commit`) to `passwall2.@global[0].auto_lang`. Runs on every CBI page load.
- **TextValue** uses template `passwall2/cbi/tvalue`.
- **DynamicList.write** (overridden globally): de-duplicate values (preserving order); if `self.cast == "string"` store as single space-joined string option, else as UCI list.
- **HideValue** (custom class = DummyValue with template `passwall2/cbi/hidevalue`, value `"1"`): an invisible pseudo-field that never writes to UCI. Its *visibility* is used as a boolean in other options' `depends`: `depends("_x","1")` is satisfied iff the HideValue `_x` is itself visible (its deps satisfied). A HideValue with `depends("_hide","1")` (nonexistent field) is hidden unless other deps are added later; additional `depends({node=id})` entries make it an OR of "node == id".
- `depends({ opt = v, ['!reverse'] = true })` = "opt != v".
- Multiple `o:depends(a)`, `o:depends(b)` = OR; a single table `{a=1,b=2}` = AND.
- `Flag`: stores `"1"`/`"0"`. `rmempty=false` → always writes (also "0"); default `rmempty=true` → unchecked/empty deletes the option.
- Hidden (dependency-unsatisfied) fields get `remove()` called on save (deletes the UCI option) unless the option overrides `remove`.
- `ListValue`/`Value` with `o.default = o.keylist[N]` → default is the N-th added choice key.
- `api.url(a, b)` = `build_url("admin/services/passwall2/a/b")` (empty parts skipped).
- `api.gen_random_char(n)` = `head /dev/urandom | tr -dc A-Za-z0-9 | head -c n`.
- `api.TMP_PATH` = `/tmp/etc/passwall2`.
- `api.get_cache_var(key)` = shell `. /usr/share/passwall2/utils.sh ; echo -n $(get_cache_var "<key>")`, empty → nil.
- `api.finded_com(name)` = core binary found (path from `@global_app[0].<name>_file`); `api.is_finded(bin)` = binary in PATH/known dirs.

### 0.1 `api.get_valid_nodes()` (used for all node dropdowns)
Iterate `nodes` sections; for each `e` with both `type` and `remarks`:
- `type_name = e.type` (`"sing-box"` → `"Sing-Box"`).
- If `e.protocol ∈ {_balancing,_shunt,_iface,_urltest}`: `remark = trim("<type_name> <translatef(protocol)>：[<remarks>]")`, `node_type = "special"`, include.
- Else (also evaluated for special, but they lack address): `port = e.port or e.hysteria_hop or e.hysteria2_hop`; `is_realm = protocol=="hysteria2" and e.hysteria2_realms`. Include only if `(port and address) or is_realm` and `address` is IP or valid hostname (or is_realm). For Xray/sing-box with protocol append protocol label: vmess→VMess, vless→VLESS, shadowsocks→SS, shadowsocksr→SSR, wireguard→WG, hysteria→HY, hysteria2→HY2, anytls→AnyTLS, ssh→SSH, else capitalize first letter. IPv6 address expanded to full form. `" Realm"` suffix if realm. `remark = "<type_name>：[<remarks>]"`; if `@global_other[0].show_node_info == "1"` and not realm: append `" <address>:<port with ':'→'-'>"`. `node_type = "normal"`.
- `e.id = e[".name"]`. Output order: nodes with empty `group` first, then grouped nodes (each in UCI order).

### 0.2 `api.get_node_list()`
Returns `{ socks_list = [...], normal_list = [...], <proto>_list ... }`:
- `socks_list`: every `socks` section with `node` set → `{id, remark = "Socks Config [<port>Port]", group = "Socks"}`.
- `normal_list`: valid nodes with `node_type=="normal"` → `{id, remark, type, chain_proxy, group}`.
- For every valid node whose protocol starts with `_`: `<protocol without _>_list` (e.g. `shunt_list`, `balancing_list`, `urltest_list`, `iface_list`) → `{id, remark, group, o = <full section>}`.

### 0.3 Node dropdown widget (`nodes_listvalue` / `nodes_value` / `nodes_dynamiclist` templates)
Grouped select: every `o:value(id, remark)` is paired with `o.group[i]` = node's `group` or `translate("default")` when empty. Leading literal entries carry group `""`. Templates `*_com` (appended to map) contain the shared JS.

### 0.4 Shared helpers repeated in several pages
- `port_validate(value)` = `value.replace("-", ":")` (all occurrences) — accepts anything, normalizes ranges.
- `clean_text(text)`: `\t`→space; U+00A0 → space; U+3000 → space; strip leading whitespace; trailing whitespace run → single `"\n"`; `\r\n`→`\n`; `[ \t]*\n[ \t]*` → `\n`.
- `doh_validate(value)` (global variant): empty → error; split by `,`; first element = URL (not checked); every remaining element must be `ipmask4` or `ipmask6`; else error `"DoH request address Format must be: URL,IP"`. **acl_config variant accepts only `ipmask4`** for extra elements. Note: empty string → error (option effectively required when visible).
- Weekly schedule triplet (`<x>_week_mode`, `<x>_time_mode`, `<x>_interval_mode`): week_mode values `""`=Disable, `8`=Loop Mode (only where noted), `7`=Every day, `1..6`=Mon..Sat, `0`=Sunday. time_mode: Value, choices `0:00, 0:00..11:00, 12:30, 13:00..22:00, 23:59` (note: "0:00" appears twice in source, LuCI dedups), default `"0:00"`, datatype `timehhmm`, visible when week_mode ∈ {0..7}. interval_mode: ListValue `1..24` ("N Hour"), default `2`, visible when week_mode == `8`.
- Probe URL choice list (used in haproxy, socks_config, node_list): `https://cp.cloudflare.com/` (Cloudflare), `https://www.gstatic.com/generate_204` (Gstatic), `https://www.google.com/generate_204` (Google, **default = keylist[3]**), `https://www.youtube.com/generate_204` (YouTube), `https://connect.rom.miui.com/generate_204` (MIUI (CN)), `https://connectivitycheck.platform.hicloud.com/generate_204` (HiCloud (CN)), `https://wifi.vivo.com.cn/generate_204` (VIVO (CN)).
- Transparent-proxy capability check (global.lua, other.lua): run `lsmod`, capture stdout; `tproxy_ok = (contains "REDIRECT" and "TPROXY") or (contains "nft_redir" and "nft_tproxy")` (plain substring search).
- Core-type lists (node_subscribe, node_subscribe_config):
  - `ss_type`: `shadowsocks-rust` if `is_finded("sslocal")`; `sing-box` if has_singbox; `xray` if has_xray (order: shadowsocks-rust, sing-box, xray).
  - `trojan_type`, `vmess_type`, `vless_type`: sing-box (if present), xray (if present).
  - `hysteria2_type`: sing-box (if present); xray only if `compare_versions(get_app_version("xray"), ">=", "26.1.13")`.

---

## 1. global.lua — Basic Settings (`settings`)

### 1.1 Preliminary computation
- `has_singbox`, `has_xray`.
- `nodes_table = get_valid_nodes()`; partition: `normal_list` (node_type normal), `balancing_list` (`_balancing`), `urltest_list` (`_urltest`), `shunt_list` (`_shunt`), `iface_list` (`_iface`).
- `socks_list`: socks sections with `enabled=="1"` and `node` set (computed but unused afterwards).
- Templates appended in order: `/cbi/nodes_listvalue_com`, `/global/status`, (section), `/include/node_change` {verify_option = node field, shunt_list = JSON(shunt_list)}, …, `/global/footer`, `/cbi/sortable` {sectiontype="socks"}.

### 1.2 Section `@global[0]` (NamedSection, type `global`, no title), tabbed
Tabs in order: `Main`, (`Shunt` inserted at position 2 if a shunt node is current — see §1.3), `DNS`, `log` ("Log"), `faq` ("FAQ"), `maintain` ("Maintain").

**Tab Main**

| Option | Widget | Default | Notes |
|---|---|---|---|
| `enabled` | Flag "Main switch" | (0) | rmempty=false |
| `node` | ListValue (grouped node select), title in red "Node" | — | choices: `""`="Close" + all valid nodes (see below) |
| `_node` | HideValue | — | visible iff `node != ""` |
| `_is_singbox` | HideValue | — | visible iff `node` is one of sing-box nodes (`depends({node=id})` for each node with `type=="sing-box"`) |
| `node_save_before` | HideValue, `value = current_node[".name"]`, cbid literally `node_save_before` | — | posts the node id that the page was rendered with |
| `tips` | DummyValue rawhtml red "There are no available nodes, please add or subscribe nodes first." | — | only created when (has_singbox or has_xray) and nodes exist but `#normal_list==0 and #iface_list==0`; visible if `_node=="1"` OR node ∈ shunt_list OR node ∈ balancing_list |
| `localhost_proxy` | Flag "Localhost Proxy" | `1` | rmempty=false. Only if `tproxy_ok`; otherwise a DummyValue showing a disabled checkbox + red "Missing components, transparent proxy is unavailable." |
| `client_proxy` | Flag "Client Proxy" | `1` | same as above |
| `node_socks_port` | Value "Node Socks Listen Port" | `1070` | datatype `port`, visible `_node=="1"` |
| `node_socks_bind_local` | Flag "Node Socks Bind Local" | `1` | visible `_node=="1"`; rmempty default (true) |
| `socks_enabled` | Flag "Socks Main switch" | (0) | rmempty=false (added last in tab) |

`current_node_id` = POSTed `node` form value if present, else `@global[0].node`; `current_node = m:get(current_node_id) or {}`.

Node choices population (end of file): iterate `nodes_table`; **if `#normal_list==0 and #iface_list==0` break immediately** (dropdowns stay with only "Close"). For each node `v`:
- if `v.type=="sing-box"`: `_is_singbox` depends `{node=v.id}`.
- `node:value(v.id, v.remark)` (+group); socks section `node:value(v.id, v.remark)` (+group).
- if `v.node_type=="normal"` or protocol `_balancing`/`_urltest`: `remote_fakedns` depends `{node=v.id}` (so `remote_fakedns` is visible only when a non-shunt node is selected; shunt nodes have their own per-rule FakeDNS).

### 1.3 Shunt tab
If `(has_singbox or has_xray) and #nodes_table>0` and (`#normal_list>0 or #iface_list>0`) and `current_node.protocol == "_shunt"` → run `include/shunt_options.lua` with `{node=current_node, verify_option=<node field>, tab="Shunt", tab_desc="Shunt Rule"}` (§12).

**Tab DNS**

| Option | Widget | Default | Choices / validation / depends |
|---|---|---|---|
| `direct_dns_protocol` | ListValue "Direct DNS Protocol" | `""` | `""`=Auto, `udp`=UDP (tcp commented out) |
| `direct_dns` | Value "Direct DNS" | `223.5.5.5` | datatype `or(ipaddr,ipaddrport(1))`; suggestions 223.5.5.5, 223.6.6.6, 114.114.114.114, 119.29.29.29, 180.76.76.76; visible `direct_dns_protocol ∈ {tcp,udp}` (so hidden/removed on Auto) |
| `direct_dns_query_strategy` | ListValue "Direct Query Strategy" | `UseIP` | UseIP, UseIPv4, UseIPv6 |
| `remote_dns_protocol` | ListValue "Remote DNS Protocol" | (first = tcp) | `tcp`=TCP, `doh`=DoH, `udp`=UDP; plus `tls`="TLS(DoT)", `quic`="QUIC(DoQ)", `http3`="HTTP3(DoH3)": in JS LuCI added only if `current_node.type=="sing-box"`; in legacy LuCI added with per-value dependency `_is_singbox=="1"` |
| `remote_dns` | Value "Remote DNS" | `1.1.1.1` | datatype `or(ipaddr,ipaddrport(1))`; suggestions: 1.1.1.1 (CloudFlare), 1.1.1.2 (CloudFlare-Security), 8.8.4.4 (Google), 8.8.8.8 (Google), 9.9.9.9 (Quad9-Recommended), 149.112.112.112 (Quad9-Recommended), 208.67.220.220 (OpenDNS), 208.67.222.222 (OpenDNS); visible protocol ∈ {tcp,udp,quic,tls} |
| `remote_dns_doh` | Value "Remote DNS DoH" | `https://1.1.1.1/dns-query` | suggestions: `https://1.1.1.1/dns-query` CloudFlare; `https://1.1.1.2/dns-query` CloudFlare-Security; `https://8.8.4.4/dns-query` Google 8844; `https://8.8.8.8/dns-query` Google 8888; `https://9.9.9.9/dns-query` Quad9-Recommended 9.9.9.9; `https://149.112.112.112/dns-query` Quad9-Recommended 149.112.112.112; `https://208.67.222.222/dns-query` OpenDNS; `https://dns.adguard.com/dns-query,94.140.14.14` AdGuard; `https://doh.libredns.gr/dns-query,116.202.176.26` LibreDNS; `https://doh.libredns.gr/ads,116.202.176.26` LibreDNS (No Ads). validate = doh_validate (ipv4/ipv6 masks); visible protocol ∈ {doh,http3} |
| `remote_dns_client_ip` | Value "Remote DNS EDNS Client Subnet" | — | datatype `ipaddr`; always visible; description re RFC7871 / no private IP |
| `remote_dns_detour` | ListValue "Remote DNS Outbound" | `remote` | `remote`=Remote, `direct`=Direct |
| `remote_fakedns` | Flag "FakeDNS" | `0` | rmempty=false; visible only when a normal/balancing/urltest node is selected (§1.2) |
| `remote_dns_query_strategy` | ListValue "Remote Query Strategy" | `UseIPv4` | UseIP, UseIPv4, UseIPv6 |
| `remote_rewrite_ttl` | Value "Remote DNS TTL" | `30` | datatype `min(1)`; visible `_is_singbox=="1"` |
| `dns_hosts` | TextValue "Domain Override" rows=5 wrap=off | — | custom `remove`: only deletes the option when the POSTed `node` refers to a node whose `type` is `Xray` or `sing-box`; otherwise keeps the stored value (empty textarea with other nodes doesn't delete) |
| `dns_redirect` | Flag "DNS Redirect" ("Force special DNS server to need proxy devices.") | `1` | rmempty=false |
| `clear_ipset` | DummyValue button | — | title = "Clear NFTSET" if `@global_forwarding[0].prefer_nft=="1"` else "Clear IPSET"; button navigates to `api.url("flush_set") .. "?redirect=1&reload=1"` |

**Tab log**

| Option | Widget | Default | Notes |
|---|---|---|---|
| `log_node` | Flag "Enable Node Log" | `1` | rmempty=false |
| `loglevel` | ListValue "Log Level" | `warn` | debug, info, warn, error (always visible) |
| `_log` | DummyValue | — | shows `<code>/tmp/etc/passwall2/acl/acl_default.log</code>` + "View Log" button opening `api.url("get_redir_log") .. "?id=acl_default"` in new tab; visible `log_node=="1"` |

**Tab faq**: DummyValue (name `""`) with template `passwall2/global/faq`.
**Tab maintain**: DummyValue (name `""`) with template `passwall2/global/backup` (backup/restore UI).

### 1.4 Section `socks` (TypedSection, title "Socks Config")
Table layout (`cbi/tblsection`), sortable, anonymous, addremove; `extedit = url("socks_config", "%s")`.
- **create**: `uid = "socks_" .. gen_random_char(5)`; create section `socks` named uid; redirect to `socks_config/<uid>`.
- Columns:
  - `status` DummyValue: `<div class="_status" socks_id="<sid>"></div>` (filled by status JS).
  - `enabled` Flag "Enable", default `1`, rmempty=false.
  - `node` ListValue "Socks Node" (grouped; same node choices as global node, but no "Close" entry).
  - `now_node` DummyValue "Current Node": `cache = get_cache_var(<sid>)` (runtime current node id of the socks instance, set by auto-switch); if section exists → `get_node_remarks(node)` with `"："` followed by `[` → `"：<br>["`.
  - `port` Value "Socks Listen Port", datatype `port`, rmempty=false, default `n + 1080` where `n = 1 + count(socks sections)` (the loop compares against undefined global `section`, so it never stops early) → default = `#socks + 1081`.
  - (http_port commented out on this page.)
- Template `/cbi/sortable` {sectiontype="socks"} enables drag-reorder.

---

## 2. node_list.lua — Node List (`node_list`)

Section `@global_other[0]` (NamedSection type `global_other`, untitled):

| Option | Widget | Default | Choices |
|---|---|---|---|
| `auto_detection_time` | ListValue "Automatic detection delay" | (first = `0`) | `0`=Close, `icmp`=Ping, `tcping`=TCP Ping |
| `show_node_info` | Flag "Show server address and port" | `0` | affects remarks (§0.1) |
| `url_test_url` | Value "URL Test Address" | `https://www.google.com/generate_204` | Probe URL list (§0.4) |

Then appends template `/node_list/node_list` (the node table UI — separate spec).

On POST with `cbi.submit == "1"`: `group_order = formvaluetable("group.order")` (all form fields `group.order.<key>`). For each non-empty value: split by spaces into section names; for idx=1..n `uci:reorder("passwall2", name, idx-1)` (absolute position idx-1, applied per group sequentially in iteration order). Saved with the map.

---

## 3. node_config.lua — Node editor (`node_config/<sid>`)

- `m.redirect = url("node_list")`. If no `arg[1]` or section missing → HTTP redirect to node_list.
- `formvalue_key = "cbid.passwall2.<sid>."`.
- Templates: `/node_config/header` {section=sid}, `/cbi/nodes_multivalue_com`, `/cbi/nodes_listvalue_com`, … `/node_config/footer` {section=sid}.
- `groups` = set of non-empty `group` values from all OTHER `nodes` sections.
- NamedSection `<sid>` type `nodes`, title "Node Config", addremove=false, dynamic=false.

| Option | Widget | Default | Notes |
|---|---|---|---|
| `passwall2` | DummyValue, template `/node_config/link_share_man`, value=sid | — | share-link/QR UI |
| `remarks` | Value "Node Remarks" | `"Remarks"` (translated) | rmempty=false |
| `group` | Value "Group Name" | `""` | suggestions `""`="default" + existing groups. **write**: `v = trim(value)`; if `lower(v)` is `""` or `"default"` → delete option; else if any existing choice key equals case-insensitively → store that key's spelling; else store `v` |
| `type` | ListValue "Type" | — | choices are added by the type files |

- `s.val["type"] = uci type`; if `cbi.submit=="1"` and form field `cbid.passwall2.<sid>.type` present → `s.val.type` = that.
- Load every file in `/usr/lib/lua/luci/model/cbi/passwall2/client/type/` sorted by filename, each called with `(m, s)` (each adds its `type` choice and its own options; see type specs; `api.set_type_cbi` makes their options write only when the submitted `type` equals their type name).

---

## 4. node_subscribe.lua — Node Subscribe (`node_subscribe`)

`m.on_before_save`: for every `subscribe_list` section delete option `md5` (forces re-download/re-parse on next subscribe).

### 4.1 Section `@global_subscribe[0]` (type `global_subscribe`, untitled)

| Option | Widget | Default | Choices |
|---|---|---|---|
| `filter_keyword_mode` | ListValue "Filter keyword Mode" | (first=`0`) | `0`=Close, `1`=Discard List, `2`=Keep List, `3`=Discard List,But Keep List First, `4`=Keep List,But Discard List First |
| `filter_discard_list` | DynamicList "Discard List" | — | always visible |
| `filter_keep_list` | DynamicList "Keep List" | — | always visible |
| `ss_type` | ListValue "Shadowsocks Node Use Type" | `""` | only if ss_type non-empty; `""`=Auto + list |
| `trojan_type` | ListValue "Trojan Node Use Type" | `""` | likewise |
| `vmess_type` | ListValue "VMess Node Use Type" | `""` | likewise |
| `vless_type` | ListValue "VLESS Node Use Type" | `""` | likewise |
| `hysteria2_type` | ListValue "Hysteria2 Node Use Type" | `""` | likewise |
| `_stop` | DummyValue button "Delete All Subscribe Node" | — | `onclick="return confirmDeleteAll()"` |
| `_update` | DummyValue button "Manual subscription All" | — | `onclick="ManualSubscribeAll()"` |

The *last created* `*_type` option gets description (red) "The configured type also applies to the core specified when manually importing nodes." (Quirk: if no type lists exist, the description lands on `filter_keep_list`.)

### 4.2 Section `subscribe_list` (TypedSection, table, addremove, anonymous, sortable)
Description (red): "When adding a new subscription, please save and apply before manually subscribing. If you only change the subscription URL, you can subscribe manually, and the system will save it automatically."
`extedit = url("node_subscribe_config", "%s")`.
- **create**: `uid = "sub_" .. gen_random_char(5)`; create; set `hysteria_up_mbps="100"`, `hysteria_down_mbps="100"`; redirect to editor.
- Columns:
  - `remark` Value "Remarks" (width auto, rmempty=false). **validate**: trim; empty → "Remark cannot be empty."; duplicate (case-insensitive vs other `subscribe_list` remarks) or equals "default" (case-insensitive) → "This remark already exists, please change a new remark."; return trimmed. **write** = rename cascade (§4.3) then normal write.
  - `_node_count` DummyValue "Subscribe Info": `"Node num: <N>"` where N = count of `nodes` with `group` equal (case-insensitive) to remark; plus if `rem_traffic` and/or `expired_date` set: `"<br>" .. rem_traffic .. ("/" if both) .. expired_date`.
  - `url` Value "Subscribe URL" (width auto, rmempty=false).
  - `_remove` DummyValue button "Delete the subscribed node": `onclick="return confirmDeleteNode('<remark>')"`.
  - `_update` DummyValue button "Manual subscription": `onclick="ManualSubscribe('<sid>')"`.
- Templates: `/cbi/sortable` {sectiontype="subscribe_list"}, `/node_subscribe/js`.

### 4.3 Remark rename cascade (identical in node_subscribe and node_subscribe_config)
```
old = get(section,"remark") or ""
if old != value:
  for each nodes section e:
    if e.group and lower(e.group) == lower(old): set(e, "group", value)
    if e.protocol in {_balancing,_urltest} and e.node_group:
      gs = join(" ", [UrlEncode(value) if g == UrlEncode(old) else g for g in split_ws(e.node_group)])
      set(e, "node_group", trim(gs))
write(section, "remark", value)
```
(`node_group` stores URL-encoded group names, space separated.)

---

## 5. node_subscribe_config.lua — Subscription editor (`node_subscribe_config/<sid>`)

- `m.redirect = url("node_subscribe")`; missing sid → redirect.
- `on_before_save`: delete `<sid>.md5`.
- Template `/cbi/nodes_listvalue_com`.
- `nodes_table`: valid normal nodes → `{id, remark, type, add_mode, chain_proxy, group}`.
- NamedSection `<sid>` (type unspecified), addremove=false.

| Option | Widget | Default | Choices / depends / validation |
|---|---|---|---|
| `remark` | Value "Subscribe Remark" | — | rmempty=false; same validate & rename cascade as §4.2/§4.3 |
| `url` | TextValue "Subscribe URL" rows=5 | — | rmempty=false; validate: empty → "URL cannot be empty."; return value with all whitespace and NUL bytes removed (multiple URLs can be pasted, joined without separators? — whitespace incl. newlines is stripped) |
| `domain_resolver` | ListValue "Domain DNS Resolve" | `""` | `disable`=Disable, `""`=Auto, `tcp`=TCP, `udp`=UDP, `https`=DoH. Description: used to resolve domain node addresses; only Xray/Sing-box; Auto tries to extract DNS from Clash subscriptions, Disable skips |
| `domain_resolver_dns` | Value "DNS" | `114.114.114.114` | datatype `or(ipaddr,ipaddrport)`; suggestions 114.114.114.114, 223.5.5.5:53; visible resolver ∈ {tcp,udp} |
| `domain_resolver_dns_https` | Value "DNS" | `https://120.53.53.53/dns-query` | suggestions DNSPod `https://120.53.53.53/dns-query`, AliDNS `https://223.5.5.5/dns-query`; visible resolver == https |
| `domain_strategy` | ListValue "Domain Strategy" | `""` | `""`=Auto, `UseIPv4`=IPv4 Only, `UseIPv6`=IPv6 Only |
| `allowInsecure` | Flag "allowInsecure" | `0` | rmempty=false; used when link lacks the param |
| `filter_keyword_mode` | ListValue | `5` | 0..4 as §4.1 plus `5`="Use global config" |
| `filter_discard_list` | DynamicList "Discard List" | — | visible mode ∈ {1,3,4} |
| `filter_keep_list` | DynamicList "Keep List" | — | visible mode ∈ {2,3,4} |
| `ss_type`/`trojan_type`/`vmess_type`/`vless_type`/`hysteria2_type` | ListValue "<Proto> Node Use Type" | `global` | only if list non-empty; `global`="Use global config" + core names |
| `hysteria_up_mbps` | Value "Hy/Hy2 Max upload Mbps" | — | uinteger; only if hysteria2_type non-empty |
| `hysteria_down_mbps` | Value "Hy/Hy2 Max download Mbps" | — | uinteger; only if hysteria2_type non-empty |
| `boot_update` | Flag "Update Once on Boot" | `0` | |
| `update_week_mode` | ListValue "Auto Update Mode" | `""` | schedule list incl. `8`=Loop Mode (§0.4) |
| `update_time_mode` | Value "Update Time" | `0:00` | §0.4 |
| `update_interval_mode` | ListValue "Update Interval(hour)" | `2` | 1..24, visible week_mode==8, rmempty=true |
| `access_mode` | ListValue "Subscribe URL Access Method" | `""` | `""`=Auto, `direct`=Direct Connection, `proxy`=Proxy |
| `user_agent` | Value "User-Agent" | `v2rayN/9.99` | suggestions: `passwall2`(PassWall2), `v2rayN/9.99`(v2rayN), `clash.meta/v9.99.99`(Clash.Meta), `Shadowrocket/9999 CFNetwork/3896.100.1.2.1 Darwin/27.0.0 iPhone19,7`(Shadowrocket), `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0`(Edge for Linux), `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0`(Edge for Windows) |
| `chain_proxy` | ListValue "Chain Proxy" | `""` | `""`=Close(Not use), `1`=Preproxy Node, `2`=Landing Node, `3`=Outbound Interface |
| `preproxy_node` | ListValue (grouped) "Preproxy Node" | — | visible chain_proxy==1 |
| `to_node` | ListValue (grouped) "Landing Node" | — | visible chain_proxy==2 |
| `outbound_iface` | Value "Outbound Interface" | — | visible chain_proxy==3; `""`=All + `get_network_devices()` (name,label) |
| `hwid` | Flag "Send HWID" | `0` | sends hashed HWID on update |

Chain node choices: nodes where `type ∈ {Xray, sing-box}` AND `chain_proxy` empty/unset AND `add_mode != "2"` (i.e. not subscription-imported). Description: "Chained proxy works only with Xray or Sing-box nodes.<br>You can only use manual or imported nodes as chained nodes.<br>Only support a layer of proxy."

---

## 6. other.lua — Other Settings (`other`)

### 6.1 `@global_delay[0]` "Delay Settings" (type `global_delay`)

| Option | Widget | Default | Notes |
|---|---|---|---|
| `start_daemon` | Flag "Open and close Daemon" | `1` | rmempty=false |
| `start_delay` | Value "Delay Start" (Units: seconds) | `1` | rmempty=true, no datatype |
| for x in stop, start, restart: `<x>_week_mode` | ListValue "<x> automatically mode" | `""` | schedule (§0.4); `8`=Loop Mode **only for restart** |
| `<x>_time_mode` | Value "<x> Time" | `0:00` | §0.4 |
| `<x>_interval_mode` | ListValue "<x> Interval(Hour)" | `2` | visible week_mode==8 (only reachable for restart) |

### 6.2 `@global_forwarding[0]` "Forwarding Settings"

| Option | Widget | Default | Choices / validation |
|---|---|---|---|
| `tcp_no_redir_ports` | Value | — | `""`=No patterns are used, `1:65535`=All; port_validate |
| `udp_no_redir_ports` | Value | — | same; red description "Fill in the ports you don't want to be forwarded by the agent, with the highest priority." |
| `tcp_redir_ports` | Value | `1:65535` | `1:65535`=All, `22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418`=Common Use, `80,443`=Only Web; port_validate |
| `udp_redir_ports` | Value | `1:65535` | `1:65535`=All; port_validate |
| `tips` | DummyValue red text | — | "The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000." |
| `prefer_nft` | ListValue "Prefer firewall tools" | `1` | `0`=Iptables, `1`=Nftables |
| `tcp_proxy_way` | ListValue "TCP Proxy Way" | `redirect` | only if tproxy_ok; `redirect`=REDIRECT, `tproxy`=TPROXY; visible when ipv6_tproxy unchecked; **remove is a no-op** (never deleted when hidden) |
| `_tcp_proxy_way` | ListValue "TCP Proxy Way" | `tproxy` | only if tproxy_ok; single choice `tproxy`; visible when ipv6_tproxy checked; **write stores into `tcp_proxy_way`** (IPv6 TPROXY forces tproxy) |
| `ipv6_tproxy` | Flag "IPv6 TProxy" | `0` | only if tproxy_ok and lsmod contains `ip6table_mangle` or `nft_tproxy`; rmempty=false; red "Experimental feature..." |
| `accept_icmp` | Flag "Hijacking ICMP (PING)" | `0` | |
| `accept_icmpv6` | Flag "Hijacking ICMPv6 (IPv6 PING)" | `0` | visible ipv6_tproxy checked |
| `direct_ip` | TextValue "Direct IP List" rows=15 | — | **file-backed**, not UCI: cfgvalue = contents of `/usr/share/passwall2/direct_ip` (or ""); write = file ← value with `\r\n`→`\n`; remove (empty) = write empty file. validate: `clean_text`, split lines, trim; each non-empty line not starting with `#` or `geoip:` must be ipmask4/ipmask6 else "`<line>` Not valid IP format, please re-enter!"; returns cleaned text |

Edge: if `tproxy_ok` false, neither `tcp_proxy_way` nor `ipv6_tproxy` rendered; `accept_icmpv6` depends on missing field → hidden (and removed on save).

### 6.3 `@global_xray[0]` "Xray Settings" (only if has_xray)

| Option | Widget | Default | Notes |
|---|---|---|---|
| `fragment` | Flag "Fragment" | `0` | TCP fragments |
| `fragment_packets` | ListValue | `tlshello` | tlshello, 1-1, 1-2, 1-3, 1-5; visible fragment |
| `fragment_lengths` | Value "Fragment Length" (bytes) | `3-5,6-8,10-20` | visible fragment |
| `fragment_delays` | Value "Fragment Delay" (ms) | `10-20` | visible fragment |
| `fragment_maxSplit` | Value "Max Split" | `3-6` | datatype `or(uinteger,portrange)`; visible fragment |
| `noise` | Flag "Noise" | `0` | UDP noise; packets defined in §6.4 |
| `sniffing_override_dest` | Flag "Override the connection destination address" | `0` | |
| `route_only` | Flag "Sniffing Route Only" | `0` | depends `sniffing` (field doesn't exist on this page → effectively always hidden/removed) |
| `excluded_domains` | TextValue rows=15 | — | file-backed `/usr/share/passwall2/domains_excluded` (read/write, `\r\n`→`\n`); visible sniffing_override_dest; no custom remove (hidden → default remove deletes the nonexistent UCI option; file untouched) |
| `buffer_size` | Value "Buffer Size" (kB per connection) | — | uinteger |

### 6.4 `xray_noise_packets` TypedSection "Xray Noise Packets" (only if has_xray)
Table, sortable, anonymous, addremove. Description red: 'To send noise packets, select "Noise" in Xray Settings.'
- create: name `"xray_noise_" .. gen_random_char(5)` (no redirect).
- remove: if section's `.type` matches, disable validation/rmempty for all children, then delete section.
- Columns: `enabled` Flag default 1 rmempty=false; `type` ListValue rand/array/str/hex/base64 (default first = rand); `packet` Value "Packet | Rand Length" datatype `minlength(1)` rmempty=false; `delay` Value "Delay (ms)" datatype `or(uinteger,portrange)` rmempty=false.

### 6.5 `@global_singbox[0]` "Sing-Box Settings" (only if has_singbox)
- `record_fragment` Flag "TLS Record Fragment", default 0.
- `fragment` Flag "TLS TCP Fragment", default 0.

---

## 7. haproxy.lua — Load Balancing (`haproxy`)

`nodes_table` = valid normal nodes `{id, obj, remarks=remark, group}`. Template `/cbi/nodes_value_com`.

### 7.1 `@global_haproxy[0]` "Basic Settings" (template `/haproxy/status` appended inside section)

| Option | Widget | Default | Depends / notes |
|---|---|---|---|
| `balancing_enable` | Flag "Enable Load Balancing" | 0 | rmempty=false |
| `console_auth` | Flag "Console Login Auth" | 0 | balancing_enable |
| `console_user` | Value "Console Username" | `""` | console_auth |
| `console_password` | Value (password) "Console Password" | `""` | console_auth |
| `console_port` | Value "Console Port" | `1188` | port; balancing_enable; e.g. 192.168.1.1:1188 |
| `bind_local` | Flag "Haproxy Port Bind Local" | `0` | balancing_enable |
| `balancingStrategy` | ListValue | `roundrobin` | `roundrobin`(roundRobin), `random`, `leastconn`(leastConn), `source`; balancing_enable |
| `health_check_type` | ListValue | `script_logic` | `tcp`=TCP, `script_logic`="URL Test(passwall2 Inner implement)"; balancing_enable |
| `health_probe_url` | Value "Probe URL" | Google generate_204 | Probe URL list; visible health_check_type==script_logic |
| `health_check_inter` | Value "Health Check Inter" | `60` | datatype `min(20)`, seconds; balancing_enable |
| `health_check_tips` | DummyValue red text | — | visible script_logic: URL test converts LB nodes into Socks nodes; custom entries must be Socks nodes |

### 7.2 `haproxy_config` TypedSection "Node List"
Table, sortable, anonymous, addremove. Description (red) about Multi-WAN export, weight 1-256, primary/standby, groups share Haproxy port; TCP health check needs consistent node params.
- create: `"haproxy_" .. gen_random_char(5)`.
- remove: drop validation/rmempty on children then delete.

| Option | Widget | Default | Notes |
|---|---|---|---|
| `enabled` | Flag | 1 | rmempty=false |
| `lbss` | Value with node suggestions (template `/cbi/nodes_value`) "Node Address" | — | rmempty=false. validate: nil → "Node address cannot be empty."; valid if value is an existing section of type `nodes`; or `hostport` or `ip4addrport`; or `api.is_ipv6addrport`; else "Not valid IP format, please re-enter! (IP:Port)" |
| `haproxy_port` | Value | `1181` | port, rmempty=false |
| `lbweight` | Value "Node Weight" | `5` | `min(1)`, rmempty=false |
| `export` | ListValue "Export Of Multi WAN" | `0` | `0`=Auto + `luci.tools.webadmin.cbi_add_networks` (all `network` interface names except loopback); rmempty=false |
| `backup` | ListValue "Mode" | (first=0) | `0`=Primary, `1`=Standby; rmempty=false |

Templates: `/cbi/sortable` {sectiontype="haproxy_config"}, `/haproxy/js`.

---

## 8. app_update.lua — App Update (`app_update`)

Section `@global_app[0]` "App Update" (type `global_app`); template `/app_update/app_version` {com = luci.passwall2.com} inside section.
- `gh_proxy_url` ListValue "GitHub Proxy" default `""`: `""`=Close(Not use), `https://gh-proxy.org/`, `https://ghproxy.cc/`, `https://mirror.ghproxy.com/` (label ghproxy.com), `https://ghfast.top/`.
- For k in `com.order` = [`geoview`, `xray`, `sing-box`]: Value `<k with - → _>_file` → `geoview_file`, `xray_file`, `sing_box_file`; title "%s App Path" with names Geoview/Xray/Sing-Box; default & placeholder `com[k].default_path` (`/usr/bin/geoview`, `/usr/bin/xray`, `/usr/bin/sing-box`) or `/usr/bin/<k>`. **remove → writes the default** (field can never be empty in UCI after a save).
- `tips` DummyValue red: "if you want to run from memory, change the path, /tmp beginning then save the application and update it manually."

---

## 9. rule.lua — Rule Manage (`rule`)

Section `@global_rules[0]` "Rule status" (type `global_rules`):

| Option | Widget | Default | Choices |
|---|---|---|---|
| `geoip_url` | Value "GeoIP Update URL" | 1st | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat`; `https://gh-proxy.org/<that>`; `https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat`; `https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat`; `https://gh-proxy.org/<that>`; `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat`; `https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat` (IR); `https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat` (RU) |
| `geosite_url` | Value "Geosite Update URL" | 1st | identical list with `geosite.dat` |
| `v2ray_location_asset` | Value "Location of Geo rule files" | `/usr/share/v2ray/` | placeholder same; rmempty=false |
| `update_week_mode` | ListValue "Auto Update Mode" | `""` | schedule incl. `8` Loop |
| `update_time_mode` | Value "Update Time" | `0:00` | §0.4 |
| `update_interval_mode` | ListValue "Update Interval(hour)" | `2` | 1..24, visible week_mode==8, rmempty=true |
| `geoip_update`, `geosite_update` | Flag (no title) | — | rmempty=false; always hidden via JS (`rule_version` template toggles them as "update this" checkboxes) |

Templates: `/rule/rule_version` (in section), `/rule/shunt_rule_list` (list of `shunt_rules` sections — separate spec).
On POST `cbi.submit=="1"`: same `group.order.*` reorder logic as §2 (applied to shunt_rules sections).

---

## 10. geoview.lua — Geo View (`geoview`, SimpleForm)

- `geo_dir = (uci @global_rules[0].v2ray_location_asset or "/usr/share/v2ray/")` matched with `^(.*)/` → everything before the LAST `/` (`/usr/share/v2ray/` → `/usr/share/v2ray`; quirk: `/usr/share/v2ray` → `/usr/share`).
- If both `<geo_dir>/geosite.dat` and `<geo_dir>/geoip.dat` exist: SimpleForm("passwall2") with reset=false, submit=false, containing template `passwall2/rule/geoview` (with `obj.api = api`). Otherwise returns nil (empty page).
- No `set_default_cbi`/`return_map` (plain form).

---

## 11. acl.lua — Access control list (`acl`)

- Section `@global[0]` "ACLs", description red "ACLs is a tools which used to designate specific IP proxy mode.":
  - `acl_enable` Flag "Main switch", default 0, rmempty=false.
- TypedSection `acl_rule` (table, sortable, anonymous, addremove, `extedit = url("acl_config","%s")`).
  - create: `"acl_" .. gen_random_char(5)`; redirect to `acl_config/<uid>`.
  - `enabled` Flag default 1 rmempty=false.
  - `remarks` Value, rmempty=true.
  - `interface` DummyValue "Source Interface": value or "All" if empty.
  - `sources` DummyValue rawhtml: list joined with `<br/>` (nothing if not a list).
  - `mode` DummyValue: `"1"`→"Proxy", `"2"`→"Proxy Use global config", else (incl. unset → "0") "No Proxy".
  - (mac_hints collected but unused.)
- Template `/cbi/sortable` {sectiontype="acl_rule"}.

---

## 12. acl_config.lua — ACL rule editor (`acl_config/<sid>`)

- `m.redirect = url("acl")`; missing sid → redirect. Template `/cbi/nodes_listvalue_com`.
- NamedSection `<sid>` (title "ACLs"). Tabs: `Main`, `Proxy`, `DNS`, `Log` (+ `Shunt` inserted at index 2 if current node is shunt).

**Main**

| Option | Widget | Default | Notes |
|---|---|---|---|
| `enabled` | Flag | 1 | rmempty=false |
| `remarks` | Value | `<sid>` | rmempty=false |
| `interface` | Value "Source Interface" | `""` | `""`=All + `get_network_devices()` (name,label); validate: `""` or `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` else "Invalid interface name" |
| `sources` | DynamicList "Source" | — | suggestions: each `mac_hints` entry as value MAC, label "MAC (IP)", sorted by IP length then lexicographically. validate per item: ok if starts with `ipset:` and remainder non-empty; or `macaddr`; or `ip4addr` (includes CIDR in LuCI's ip4addr); or IP range `a.b.c.d-e.f.g.h` (both ip4addr, no `/`). Invalid items → add_error "Not true format, please re-enter!" plus one error per bad item. Saved deduplicated as UCI list |
| `mode` | ListValue "Mode" | (first=`0`) | `0`=No Proxy, `1`=Proxy, `2`="Proxy Use global config(<get_node_name(@global[0].node)>)" (get_node_name returns text only for balancing/shunt/iface nodes, else "") |
| `_show_tcp_redir` | HideValue | | visible iff `tcp_no_redir_ports != "1:65535"` |
| `_show_udp_redir` | HideValue | | visible iff `udp_no_redir_ports != "1:65535"` |
| `_no_proxy` | HideValue | | visible iff mode==0 OR (tcp_no_redir_ports=="1:65535" AND udp_no_redir_ports=="1:65535") |
| `_show_node_option` | HideValue | | visible iff mode==1 AND `_no_proxy==""` (i.e. `_no_proxy` hidden) |
| `node` | ListValue (grouped) "Node" (red) | — | visible `_show_node_option`; choices = all valid nodes (no "Close") |
| `node_save_before` | HideValue cbid `node_save_before`, value = current node id | | |
| `_node` | HideValue | | visible iff node != "" |
| `_is_singbox` | HideValue | | visible iff node is a sing-box node |
| `_is_xray` | HideValue | | never visible (deps commented out) |

`current_node_id` = POSTed `node` or `<sid>.node`.

**Proxy**

| Option | Widget | Default | Notes |
|---|---|---|---|
| `tcp_no_redir_ports` | Value | — | `""`=No patterns are used, `1:65535`=All; mode ∈{1,2}; port_validate |
| `udp_no_redir_ports` | Value | — | same |
| `tcp_redir_ports` | Value | `1:65535` | All / Common Use list (§6.2) / `80,443`; port_validate; visible (`_node` AND `_show_tcp_redir`) OR (mode==2 AND `_show_tcp_redir`) |
| `udp_redir_ports` | Value | `1:65535` | All; visible (`_node` AND `_show_udp_redir`) OR (mode==2 AND `_show_udp_redir`) |
| `tips` | DummyValue red port-syntax hint | | mode ∈{1,2} |

**Log**

| Option | Widget | Default | Notes |
|---|---|---|---|
| `log` | Flag "Enable Node Log" | (0) | visible `_node` |
| `loglevel` | ListValue | `warn` | debug(Debug), info(Info), warn(Warning), error(Error); visible log==1 |
| `_acl_log` | DummyValue | | `<code>/tmp/etc/passwall2/acl/<sid>.log</code>`; "View Log" button (opens `url("get_redir_log")?id=<sid>`) only if file exists; visible log==1 |

**DNS** (all gated by HideValue `_show_dns_option` = mode==1 AND `_node`)

| Option | Widget | Default | Notes |
|---|---|---|---|
| `direct_dns_query_strategy` | ListValue | `UseIP` | UseIP/UseIPv4/UseIPv6 |
| `remote_dns_protocol` | ListValue | (tcp) | same rules as global incl. JS-LuCI sing-box-only tls/quic/http3 |
| `remote_dns` | Value | `1.1.1.1` | same list/datatype; visible protocol ∈{tcp,udp,quic,tls} |
| `remote_dns_doh` | Value | `https://1.1.1.1/dns-query` | same list; doh_validate **IPv4 only**; visible protocol ∈{doh,http3} |
| `remote_dns_client_ip` | Value ECS | — | ipaddr |
| `remote_dns_detour` | ListValue | `remote` | remote/direct |
| `remote_fakedns` | Flag | `0` | rmempty=false; visible iff node ∈ (normal/balancing/urltest) AND `_show_dns_option` |
| `remote_dns_query_strategy` | ListValue | `UseIPv4` | |
| `remote_rewrite_ttl` | Value | `30` | min(1); `_show_dns_option` AND `_is_singbox` |
| `dns_hosts_mode` | ListValue "Domain Override" | (first=`default`) | `default`=Use global config, `disable`=No patterns are used, `custom`=-- custom -- |
| `dns_hosts` | TextValue rows=5 | — | visible dns_hosts_mode==custom; remove only if POSTed node type is Xray/sing-box (same as global) |

Note: ACL has no `direct_dns_protocol`/`direct_dns` options (direct DNS comes from global).

Shunt: if `current_node.protocol=="_shunt"` → shunt_options include with `{node, verify_option=node field, tab="Shunt", tab_desc="Shunt Rule"}`. Template `/include/node_change` {verify_option, shunt_list=JSON of shunt nodes}.

---

## 13. socks_config.lua — Socks instance editor (`socks_config/<sid>`)

- `m.redirect = url()` (passwall2 root); missing sid → redirect. Templates `/cbi/nodes_dynamiclist_com`, `/cbi/nodes_listvalue_com`.
- NamedSection `<sid>` "Socks Config".
- `auto_switch_tip`: if `get_cache_var(<sid>)` returns an existing node id AND `<sid>.enable_autoswitch == 1` → description on `node`: `Current node: <a href="url(node_config, id)">get_node_remarks(n)</a><br />`.

| Option | Widget | Default | Notes |
|---|---|---|---|
| `enabled` | Flag | 1 | rmempty=false |
| `node` | ListValue (grouped) "Node" | — | all valid nodes |
| `bind_local` | Flag "Bind Local" | `0` | |
| `port` | Value "Socks Listen Port" | `#socks + 1081` (same quirk as §1.4) | port, rmempty=false |
| `http_port` | Value "HTTP Listen Port 0 is not use" | `0` | port; only if has_singbox or has_xray |
| `log` | Flag "Enable Log" | `1` | rmempty=false |
| `_log` | DummyValue | | `<code>/tmp/etc/passwall2/<sid>.log</code>` + button to `url("get_socks_log")?name=<sid>`; visible log |
| `enable_autoswitch` | Flag "Auto Switch" | `0` | rmempty=false; visible only when `node` is a non-`_shunt` node (depends `{node=id}` per such node) |
| `backup_node_add_mode` | ListValue | `manual` | `manual`=Manual, `batch`=Batch; visible enable_autoswitch |
| `autoswitch_backup_node` | DynamicList (grouped node list, template `/cbi/nodes_dynamiclist`) | — | visible add_mode==manual; choices: non-`_shunt` valid nodes; **write removes the currently POSTed main `node` from the list**, then dedup & store as list |
| `backup_node_group` | MultiValue checkbox "Select Group" | — | visible add_mode==batch; values `default`="default" + for each distinct node group `UrlEncode(group)` labelled group. Stored as MultiValue (space-separated string by default LuCI MultiValue) |
| `backup_node_match_rule` | Value "Node Matching Rules" | — | visible batch; syntax: terms joined by `&&` (AND, order-independent), groups by `||` (OR); `^X` starts with, `X$` ends with, `!X` excludes, plain = contains (matched against node remarks) |
| `autoswitch_testing_time` | Value "How often to test" (s) | `30` | min(10); enable_autoswitch |
| `autoswitch_connect_timeout` | Value "Timeout seconds" | `3` | min(1); enable_autoswitch |
| `autoswitch_retry_num` | Value "Timeout retry num" | `1` | min(1); enable_autoswitch |
| `autoswitch_restore_switch` | Flag "Restore Switch" | (0) | switch back to main node when available; enable_autoswitch |
| `autoswitch_probe_url` | Value "Probe URL" | Google generate_204 | Probe list; enable_autoswitch |
| `btn` | DummyValue template `/socks_auto_switch/btn` | | visible add_mode==manual (buttons to add/reorder backup nodes) |

Note: dependency chains: hidden `enable_autoswitch` hides all autoswitch fields (and they are removed on save except Flags with rmempty=false which also get removed when hidden).

---

## 14. shunt_rules.lua — Shunt rule editor (`shunt_rules/<sid>`)

- `m.redirect = url("rule")`; missing sid → redirect.
- `on_before_save`: `@global[0].flush_set = "1"` (any shunt rule save flushes IP sets on next restart).
- `m.description` += inline `<style>` making `div[id^="cbid.passwall2."] .cbi-value-field` flex-wrap with gap 1em and `.cbi-checkbox` inline-flex (cosmetic).
- `remarks_lookup` (remark → sid) and `groups` from other `shunt_rules` sections.
- NamedSection `<sid>` type `shunt_rules`, title "Sing-Box/Xray Shunt Rule".

| Option | Widget | Default | Notes |
|---|---|---|---|
| `remarks` | Value | `<sid>` | rmempty=false; validate: trim; empty → "Remark cannot be empty."; exact (case-sensitive) duplicate of another rule's remarks → "This remark already exists, please change a new remark." |
| `group` | Value "Shunt Rule Group" | `""` | suggestions `""`=default + groups; write identical to node `group` write (§3) |
| `protocol` | MultiValue checkbox "Protocol" | none | http, tls, quic, bittorrent; optional=false |
| `inbound` | MultiValue checkbox "Inbound Tag" | none | `tproxy`=Transparent proxy, `socks`=Socks |
| `network` | ListValue "Network" | (first=`tcp,udp`) | `tcp,udp`="TCP UDP", `tcp`, `udp` |
| `source` | DynamicList "Source", **cast="string"** | — | stored as one space-separated string option; cfgvalue splits on spaces (on validation error shows form value). validate: each item `ip4addr` or starts with `geoip:`; invalid → add_error "Not true format, please re-enter!" + items |
| `port` | Value "Port" | — | no validation (sourcePort commented out) |
| `domain_list` | TextValue "Domain" rows=10 | — | validate (below) |
| `ip_list` | TextValue "IP" rows=10 | — | validate (below) |
| `invert` | Flag "invert" | (0) | "Invert match result. Only support Sing-Box." |

`domain_list` validate (after `clean_text`, per non-empty line `host`, `tmp=host`, `check=true`):
1. if host contains no `#` and contains whitespace → check hostname(tmp) (fails → error).
2. elif starts with `regexp:` → skip.
3. elif starts with `domain:` + ≥1 char → `tmp = host` with all `domain:` removed.
4. elif starts with `full:` + ≥1 char → `tmp` with all `full:` removed.
5. elif starts with `geosite:` → skip.
6. elif starts with `rule-set:` or `rs:` → rest after first `:`; if rest starts with `local:` or `remote:` → skip, else check hostname(host) (fails).
7. elif starts with `#` → skip.
8. check: `datatypes.hostname(tmp)` else error "`<tmp>` Not valid domain name, please re-enter!".
Returns cleaned text. Description documents plain substring, regexp:, domain:, full:, geosite:, `rule-set:remote:<url>` / `rule-set:local:<path>` (sing-box), `#` comments.

`ip_list` validate (after `clean_text`, per line):
- starts with `geoip:` and no whitespace → ok;
- starts with `rule-set:` or `rs:` → ok (any rest);
- starts with `#` → ok;
- else must be ipmask4 or ipmask6, else "`<line>` Not valid IP format, please re-enter!".

---

## 15. include/shunt_options.lua — Shunt node options (embedded editor)

Signature: `(m, s, data)` with `data = { node = <shunt node section table>, verify_option = <ListValue field or nil>, node_list = optional, tab = optional, tab_desc }`. Returns immediately if `data.node` / `.name` missing.
Used by global.lua (section `@global[0]`, verify field `node`) and acl_config.lua (section `<acl sid>`). (Also used elsewhere with verify_option nil — e.g. from the shunt node type editor.)

Variables: `current_node_id = node[".name"]`; `node_list = data.node_list or get_node_list()`; `shunt_section_type = "shunt_option_list"`.

Tab: if `data.tab` and the section already has tabs → insert tab name at **position 2** of `s.tab_names` with title `tab_desc`; else `s:tab(tab, tab_desc)`.

POST guards: `node_save_before = formvalue("node_save_before")`, `load_shunt = formvalue("load_shunt")`.

**Write/remove semantics for all options here** (options are stored ON THE SHUNT NODE section `current_node_id`, not on the host section):
```
cfgvalue = m:get(current_node_id, option)
write(v):  if node_save_before and node_save_before != current_node_id: return
           if load_shunt == "1": return
           if verify_option and verify_option.formvalue(section) != current_node_id: return
           m:set(current_node_id, option, v)
remove:    same guards, m:del(current_node_id, option)
```
(i.e. only persist when the user didn't switch the main node in the same submit, and when not a JS "load shunt" preview request.) Every `add_option` field also gets `depends(verify_option.option, current_node_id)` when verify_option given (visible only while the shunt node is selected).

Options (in order, all via add_option):

| Option (on shunt node) | Widget | Default | Notes |
|---|---|---|---|
| `domainStrategy` | ListValue "Domain Strategy" | `IPOnDemand` | **only if node.type=="Xray"**; AsIs, IPIfNonMatch, IPOnDemand; description bullets explaining each |
| `domainMatcher` | ListValue "Domain matcher" | (first=`hybrid`) | Xray only; hybrid, linear |
| `fakedns` | Flag "FakeDNS Main switch" | (0) | FakeDNS for proxied domains; description lists use cases |
| `write_ipset_direct` | Flag "Direct DNS result write to IPSet" | `1` | rmempty=false |
| `enable_geoview_ip` | Flag "Enable GeoIP Data Parsing" | `1` | rmempty=false; only if `is_finded("geoview")`. Extra write hook: `old = get(node,opt) or "0"`; do guarded write; if new value (or "0") != old → `m:set("@global[0]", "flush_set", "1")` |
| `shunt_group` | ListValue "Shunt Rule Group" | `""` | `""`=default + distinct non-empty `group` values of all `shunt_rules` |

Rule table: `shunt_group_val = lower(node.shunt_group or "")`. `shunt_rules` = every `shunt_rules` section whose `lower(group or "") == shunt_group_val` (UCI order), each with:
- `_node_option = <rule sid>`, `_node_default = ""`, `_fakedns_option = <rule sid>.."_fakedns"`, `_proxy_tag_option = <rule sid>.."_proxy_tag"`.
plus a final pseudo-row `{id=".default", remarks="Default", _node_option="default_node", _node_default="_direct", _fakedns_option="default_fakedns", _proxy_tag_option="default_proxy_tag"}`.

Rendered as `Table` section (`config="passwall2"`, `sectiontype="shunt_option_list"`, title " "), columns (all reading/writing **options of the shunt node** named by the row's option keys, with the same guards (no verify_option check for these, just node_save_before/load_shunt)):

| Column | Widget | Stored option | Values |
|---|---|---|---|
| `remarks` "Rule" | DummyValue | — | default row: red "Default"; others: link `<a href="url(shunt_rules, sid)" target=_blank>remarks</a>` |
| `_node` "Node" | Value w/ grouped node list | `<rule sid>` / `default_node` | `""`=Close (Not use), `_default`=Use default node, `_direct`=Direct Connection, `_blackhole`=Blackhole (Block), + nodes; cfgvalue default `""` (rules) / `_direct` (default row) |
| `_fakedns` "FakeDNS" | Flag | `<rule sid>_fakedns` / `default_fakedns` | |
| `_proxy_tag` "Preproxy" | ListValue grouped | `<rule sid>_proxy_tag` / `default_proxy_tag` | `""`=Close (Not use) + nodes. Meaning: node used as pre-proxy; each rule has its own switch |

Node choices for `_node` and `_proxy_tag`: for every key `k` of node_list except `shunt_list` (i.e. socks_list, normal_list, balancing_list, urltest_list, iface_list, …; Lua `pairs` order — unordered), add each `{id, remark}` with its group (Socks entries have group "Socks").

Template `/include/shunt_options` appended with `{node_id, section_id = s.section or node_id, section_type="shunt_option_list", tab_name=data.tab, normal_list=JSON(node_list.normal_list), shunt_list=JSON(node_list.shunt_list)}` (client JS hides FakeDNS/preproxy per selection etc.).

### 15.1 Node change flow (global/acl)
When the user changes the main `node` select to a node in `shunt_list`, the `/include/node_change` template JS appends a hidden input `node_save_before = <node value at page load>` and clicks the last `.cbi-button-save` (auto-save + re-render, so the Shunt tab for the new node appears). Because `node_save_before` (old id) != the new shunt node id, the shunt option writes/removes are skipped in that submit (the previously-rendered shunt fields belonged to a different node). Selecting a non-shunt node just calls `shunt.hide()` client-side. `load_shunt=1` is only honored as a "don't persist" guard; nothing in the client templates currently sends it (it's referenced by the type editors' own flow). On normal page render, the HideValue `node_save_before` with cbid `node_save_before` posts the current node id, so regular saves pass the guard.

---

## 16. Summary of UCI section types / options touched by these pages

- `global` (`@global[0]`): enabled, node, localhost_proxy, client_proxy, node_socks_port, node_socks_bind_local, socks_enabled, direct_dns_protocol, direct_dns, direct_dns_query_strategy, remote_dns_protocol, remote_dns, remote_dns_doh, remote_dns_client_ip, remote_dns_detour, remote_fakedns, remote_dns_query_strategy, remote_rewrite_ttl, dns_hosts, dns_redirect, log_node, loglevel, acl_enable, flush_set (written by hooks), auto_lang (side effect).
- `socks`: enabled, node, bind_local, port, http_port, log, enable_autoswitch, backup_node_add_mode, autoswitch_backup_node (list), backup_node_group, backup_node_match_rule, autoswitch_testing_time, autoswitch_connect_timeout, autoswitch_retry_num, autoswitch_restore_switch, autoswitch_probe_url. Section names `socks_XXXXX`.
- `global_other`: auto_detection_time, show_node_info, url_test_url.
- `nodes` (from these pages): remarks, group, type; shunt nodes: domainStrategy, domainMatcher, fakedns, write_ipset_direct, enable_geoview_ip, shunt_group, `<rule_sid>`, `<rule_sid>_fakedns`, `<rule_sid>_proxy_tag`, default_node, default_fakedns, default_proxy_tag; balancing/urltest: node_group (rename cascade).
- `global_subscribe`: filter_keyword_mode, filter_discard_list, filter_keep_list, ss_type, trojan_type, vmess_type, vless_type, hysteria2_type.
- `subscribe_list` (`sub_XXXXX`): remark, url, md5 (deleted on save), rem_traffic/expired_date (read), domain_resolver, domain_resolver_dns, domain_resolver_dns_https, domain_strategy, allowInsecure, filter_keyword_mode, filter_discard_list, filter_keep_list, *_type, hysteria_up_mbps, hysteria_down_mbps, boot_update, update_week_mode, update_time_mode, update_interval_mode, access_mode, user_agent, chain_proxy, preproxy_node, to_node, outbound_iface, hwid.
- `global_delay`: start_daemon, start_delay, {stop,start,restart}_{week,time,interval}_mode.
- `global_forwarding`: tcp_no_redir_ports, udp_no_redir_ports, tcp_redir_ports, udp_redir_ports, prefer_nft, tcp_proxy_way, ipv6_tproxy, accept_icmp, accept_icmpv6.
- `global_xray`: fragment, fragment_packets, fragment_lengths, fragment_delays, fragment_maxSplit, noise, sniffing_override_dest, route_only, buffer_size.
- `xray_noise_packets` (`xray_noise_XXXXX`): enabled, type, packet, delay.
- `global_singbox`: record_fragment, fragment.
- `global_haproxy`: balancing_enable, console_auth, console_user, console_password, console_port, bind_local, balancingStrategy, health_check_type, health_probe_url, health_check_inter.
- `haproxy_config` (`haproxy_XXXXX`): enabled, lbss, haproxy_port, lbweight, export, backup.
- `global_app`: gh_proxy_url, geoview_file, xray_file, sing_box_file.
- `global_rules`: geoip_url, geosite_url, v2ray_location_asset, update_week_mode, update_time_mode, update_interval_mode, geoip_update, geosite_update.
- `acl_rule` (`acl_XXXXX`): enabled, remarks, interface, sources (list), mode, tcp_no_redir_ports, udp_no_redir_ports, tcp_redir_ports, udp_redir_ports, node, log, loglevel, direct_dns_query_strategy, remote_dns_protocol, remote_dns, remote_dns_doh, remote_dns_client_ip, remote_dns_detour, remote_fakedns, remote_dns_query_strategy, remote_rewrite_ttl, dns_hosts_mode, dns_hosts.
- `shunt_rules`: remarks, group, protocol, inbound, network, source (space string), port, domain_list, ip_list, invert.

Files read/written directly: `/usr/share/passwall2/direct_ip` (rw), `/usr/share/passwall2/domains_excluded` (rw), `<geo_dir>/geoip.dat`, `<geo_dir>/geosite.dat` (existence), `/www/luci-static/resources/uci.js` (existence), `/usr/lib/lua/luci/model/cbi/passwall2/client/type/*` (loaded). Log paths shown: `/tmp/etc/passwall2/acl/acl_default.log`, `/tmp/etc/passwall2/acl/<acl_sid>.log`, `/tmp/etc/passwall2/<socks_sid>.log`.

External commands: `lsmod` (global, other); `head /dev/urandom | tr -dc A-Za-z0-9 | head -c 5` (section ids); `. /usr/share/passwall2/utils.sh ; echo -n $(get_cache_var "<sid>")` (socks current node).

Controller endpoints referenced from these pages: `flush_set?redirect=1&reload=1`, `get_redir_log?id=<id>`, `get_socks_log?name=<sid>`, `node_config/<id>`, `shunt_rules/<id>`, `socks_config/<id>`, `acl_config/<id>`, `node_subscribe_config/<id>`; JS functions in templates: `confirmDeleteAll()`, `ManualSubscribeAll()`, `confirmDeleteNode(remark)`, `ManualSubscribe(sid)`.
