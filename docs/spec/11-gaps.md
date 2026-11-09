# 11 — Completeness audit and gap fill (cross-cutting)

Scope: completeness check of specs `01`–`10` against the full upstream tree `luci-app-passwall2` (113 files, 46,128 lines,
version 26.11.3-1), plus the cross-cutting material that no other spec owns:

* §1: a file → spec coverage matrix for every upstream file.
* §2: the UCI section-type inventory for `/etc/config/passwall2` and `/etc/config/passwall2_server` (ids, cardinality, who creates the sections).
* §3: a consolidated UCI option index, built mechanically from every `:option(` / `:taboption(` / `add_option(` call in `luasrc/model/cbi/**`, with dynamically named options expanded by hand.
* §4: options that exist in UCI but have no CBI widget (runtime-only, written by scripts, or legacy). Also options that are commented out upstream.
* §5: third-party browser assets. §6: i18n catalogs.
* §7: cross-spec semantic notes that individual specs leave out (UI vs runtime differences).
* §8: remaining weaknesses that are still open.

How it was checked (repeatable):
1. Every upstream file basename was grepped in `docs/spec/*.md`. All 113 files are referenced by at least one spec.
2. All 358 literal option names declared in CBI models were grepped in the specs. Only commented-out options were missing (see §4.3).
3. Every option name read at runtime through `config_n_get` / `config_t_get` / `config_get`, `uci:get*`, and `node.<x>`-style field access in the generators was grepped. All are present in the specs.
4. Every LuCI route `entry({...,"<name>"})` in the controller (66 routes) has a heading in `07 Part A`.
5. Function names: every named function in the Lua, shell, htm and JS sources was grepped. Backend functions are all described, though a few only by behaviour and not by name (listed in §8). Frontend helper functions (`lv_*`, `v_*`, `dl_*`, `mv_*`, `node_list_sort.js` internals) are described only by behaviour, which is the intended level because the JS frontend is being rewritten.

---

## 1. File coverage matrix

The "Spec" column gives the owning spec and section (`NN §x`). In every case the file is covered at full depth (exact logic and branches) unless §8 says otherwise.

| File | Lines | Spec |
|---|---|---|
| `htdocs/luci-static/resources/view/passwall2/cbi.js` | 50 | 10 §1/§4; 07 (qrcode); 11 §5 |
| `htdocs/luci-static/resources/view/passwall2/func.js` | 73 | 10 §1/§4; 07 (qrcode); 11 §5 |
| `htdocs/luci-static/resources/view/passwall2/node_list_sort.js` | 775 | 10 §1/§4; 07 (qrcode); 11 §5 |
| `htdocs/luci-static/resources/view/passwall2/qrcode.min.js` | 1 | 10 §1/§4; 07 (qrcode); 11 §5 |
| `htdocs/luci-static/resources/view/passwall2/Sortable.min.js` | 1 | 10 §1/§4; 07 (qrcode); 11 §5 |
| `luasrc/controller/passwall2.lua` | 1082 | 07 Part A (all 66 routes) |
| `luasrc/model/cbi/passwall2/client/acl_config.lua` | 399 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/acl.lua` | 73 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/app_update.lua` | 37 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/geoview.lua` | 17 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/global.lua` | 423 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/haproxy.lua` | 181 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/include/shunt_options.lua` | 268 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/node_config.lua` | 87 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/node_list.lua` | 49 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/node_subscribe_config.lua` | 329 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/node_subscribe.lua` | 222 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/other.lua` | 303 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/rule.lua` | 108 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/shunt_rules.lua` | 267 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/socks_config.lua` | 182 | 08 (+ include/shunt_options also 03/04 runtime side) |
| `luasrc/model/cbi/passwall2/client/type/1_sing-box.lua` | 1057 | 09 |
| `luasrc/model/cbi/passwall2/client/type/2_xray.lua` | 938 | 09 |
| `luasrc/model/cbi/passwall2/client/type/3_ss-rust.lua` | 70 | 09 |
| `luasrc/model/cbi/passwall2/client/type/4_ssr.lua` | 68 | 09 |
| `luasrc/model/cbi/passwall2/server/index.lua` | 141 | 09 |
| `luasrc/model/cbi/passwall2/server/server_config.lua` | 52 | 09 |
| `luasrc/model/cbi/passwall2/server/type/1_sing-box.lua` | 627 | 09 |
| `luasrc/model/cbi/passwall2/server/type/2_xray.lua` | 621 | 09 |
| `luasrc/model/cbi/passwall2/server/type/3_ss-rust.lua` | 93 | 09 |
| `luasrc/model/cbi/passwall2/server/type/4_ssr.lua` | 124 | 09 |
| `luasrc/model/cbi/passwall2/server/user_config.lua` | 54 | 09 |
| `luasrc/passwall2/api.lua` | 2395 | 05 §1 (+ helper semantics re-stated in 03/04/06/08) |
| `luasrc/passwall2/com.lua` | 80 | 05 §1.12 |
| `luasrc/passwall2/server_app.lua` | 167 | 05 §2 |
| `luasrc/passwall2/util_shadowsocks.lua` | 143 | 05 §3 |
| `luasrc/passwall2/util_sing-box.lua` | 2500 | 04 |
| `luasrc/passwall2/util_xray.lua` | 2280 | 03 |
| `luasrc/view/passwall2/app_update/app_version.htm` | 417 | 10 |
| `luasrc/view/passwall2/cbi/footer.htm` | 65 | 10 |
| `luasrc/view/passwall2/cbi/header.htm` | 28 | 10 |
| `luasrc/view/passwall2/cbi/hidevalue.htm` | 3 | 10 |
| `luasrc/view/passwall2/cbi/nodes_dynamiclist_com.htm` | 663 | 10 |
| `luasrc/view/passwall2/cbi/nodes_dynamiclist.htm` | 149 | 10 |
| `luasrc/view/passwall2/cbi/nodes_listvalue_com.htm` | 765 | 10 |
| `luasrc/view/passwall2/cbi/nodes_listvalue.htm` | 184 | 10 |
| `luasrc/view/passwall2/cbi/nodes_multivalue_com.htm` | 466 | 10 |
| `luasrc/view/passwall2/cbi/nodes_multivalue.htm` | 134 | 10 |
| `luasrc/view/passwall2/cbi/nodes_value_com.htm` | 799 | 10 |
| `luasrc/view/passwall2/cbi/nodes_value.htm` | 198 | 10 |
| `luasrc/view/passwall2/cbi/sortable.htm` | 159 | 10 |
| `luasrc/view/passwall2/cbi/tvalue.htm` | 13 | 10 |
| `luasrc/view/passwall2/global/backup.htm` | 239 | 10 |
| `luasrc/view/passwall2/global/faq.htm` | 67 | 10 |
| `luasrc/view/passwall2/global/footer.htm` | 195 | 10 |
| `luasrc/view/passwall2/global/status.htm` | 198 | 10 |
| `luasrc/view/passwall2/haproxy/js.htm` | 77 | 10 |
| `luasrc/view/passwall2/haproxy/status.htm` | 31 | 10 |
| `luasrc/view/passwall2/include/node_change.htm` | 72 | 10 |
| `luasrc/view/passwall2/include/shunt_options.htm` | 146 | 10 |
| `luasrc/view/passwall2/log/log.htm` | 45 | 10 |
| `luasrc/view/passwall2/node_config/footer.htm` | 73 | 10 |
| `luasrc/view/passwall2/node_config/header.htm` | 32 | 10 |
| `luasrc/view/passwall2/node_config/link_share_man.htm` | 1949 | 07 Part B |
| `luasrc/view/passwall2/node_list/node_list.htm` | 1851 | 10 |
| `luasrc/view/passwall2/node_subscribe/js.htm` | 113 | 10 |
| `luasrc/view/passwall2/rule/geoview.htm` | 110 | 10 |
| `luasrc/view/passwall2/rule/rule_version.htm` | 130 | 10 |
| `luasrc/view/passwall2/rule/shunt_rule_list.htm` | 429 | 10 |
| `luasrc/view/passwall2/server/config_footer.htm` | 33 | 10 |
| `luasrc/view/passwall2/server/config_header.htm` | 25 | 10 |
| `luasrc/view/passwall2/server/gen_wireguard_key.htm` | 28 | 10 |
| `luasrc/view/passwall2/server/log.htm` | 47 | 10 |
| `luasrc/view/passwall2/server/server_list_status.htm` | 40 | 10 |
| `luasrc/view/passwall2/socks_auto_switch/btn.htm` | 46 | 10 |
| `Makefile` | 133 | 01 §16 |
| `po/fa/passwall2.po` | 2640 | 10 §7; 11 §6 |
| `po/ru/passwall2.po` | 2641 | 10 §7; 11 §6 |
| `po/zh-cn/passwall2.po` | 2626 | 10 §7; 11 §6 |
| `po/zh_Hans` | 0 | 10 §7; 11 §6 |
| `po/zh_Hant` | 0 | 10 §7; 11 §6 |
| `po/zh-tw/passwall2.po` | 2632 | 10 §7; 11 §6 |
| `root/etc/config/passwall2_server` | 4 | 01 §14 / 05 §2; 11 §2 |
| `root/etc/hotplug.d/iface/98-passwall2` | 39 | 01 §13 |
| `root/etc/hotplug.d/ntp/30-passwall2-resync` | 22 | 01 §13 |
| `root/etc/init.d/passwall2` | 98 | 01 §12 |
| `root/etc/init.d/passwall2_server` | 31 | 01 §12 |
| `root/etc/uci-defaults/luci-app-passwall2` | 43 | 01 §14 |
| `root/etc/uci-defaults/luci-app-passwall2_server` | 16 | 01 §14 |
| `root/usr/share/passwall2/0_default_config` | 228 | 01 §21 (verbatim) |
| `root/usr/share/passwall2/app_acl.lua` | 230 | 05 §7; 02 §0.4 |
| `root/usr/share/passwall2/app.sh` | 1105 | 01 §3–§11 |
| `root/usr/share/passwall2/clash_subconverter.lua` | 787 | 06 §2 |
| `root/usr/share/passwall2/direct_ip` | 12 | 01 §17 |
| `root/usr/share/passwall2/domains_excluded` | 26 | 01 §17 |
| `root/usr/share/passwall2/haproxy_check.sh` | 34 | 01 §17 |
| `root/usr/share/passwall2/haproxy.lua` | 288 | 05 §5 |
| `root/usr/share/passwall2/helper_dnsmasq.lua` | 374 | 05 §4 |
| `root/usr/share/passwall2/i18n.lua` | 6 | 01 §17 |
| `root/usr/share/passwall2/iptables.sh` | 1012 | 02 |
| `root/usr/share/passwall2/lease2hosts.sh` | 98 | 01 §17 |
| `root/usr/share/passwall2/luci_update.sh` | 43 | 01 §17 / 05 §1.15 |
| `root/usr/share/passwall2/monitor.sh` | 32 | 01 §8 |
| `root/usr/share/passwall2/nftables.sh` | 1009 | 02 |
| `root/usr/share/passwall2/rule_update.lua` | 341 | 06 §3 |
| `root/usr/share/passwall2/socks_auto_switch.sh` | 228 | 05 §6 |
| `root/usr/share/passwall2/subscribe.lua` | 2351 | 06 §1 |
| `root/usr/share/passwall2/tasks.sh` | 69 | 01 §8 |
| `root/usr/share/passwall2/test.sh` | 73 | 01 §17 |
| `root/usr/share/passwall2/utils.sh` | 482 | 01 §1–§2 |
| `root/usr/share/rpcd/acl.d/luci-app-passwall2.json` | 11 | 01 §15 |
| `root/usr/share/ucitrack/luci-app-passwall2.json` | 4 | 01 §15 |
| `root/usr/share/ucitrack/luci-app-passwall2-server.json` | 4 | 01 §15 |
`po/zh_Hans` → `zh-cn` and `po/zh_Hant` → `zh-tw` are **symlinks** in the repo. They are not real files, so the package must keep them as links or as copies under those names (luci.mk builds the `luci-i18n-passwall2-zh-cn`/`zh-tw` packages from them).

---

## 2. UCI section-type inventory

### 2.1 `/etc/config/passwall2`

| Section type | Cardinality | Section id(s) | Created by | Edited by (page) |
|---|---|---|---|---|
| `global` | exactly 1, anonymous; addressed as `@global[0]` | anon (`cfgXXXXXX`) | `0_default_config` | `settings` (global.lua), `acl` (only `acl_enable`) |
| `global_haproxy` | 1, anon `@global_haproxy[0]` | anon | default config | `haproxy` |
| `global_delay` | 1, anon | anon | default config | `other` |
| `global_forwarding` | 1, anon | anon | default config | `other` |
| `global_xray` | 1, anon | anon | default config | `other` (only if Xray is installed) |
| `global_singbox` | 1, anon | anon | default config | `other` (only if sing-box is installed) |
| `global_other` | 1, anon | anon | default config | `node_list` (+ `save_node_list_opt` endpoint) |
| `global_rules` | 1, anon | anon | default config | `rule` |
| `global_app` | 1, anon | anon | default config | `app_update` |
| `global_subscribe` | 1, anon | anon | default config | `node_subscribe` |
| `nodes` | 0..n, **named** | default `examplenode`, `rulenode`. New ids: `api.gen_random_char()` (16 chars `[A-Za-z0-9]`) from controller `add_node`/`copy_node` (lines 383/421) and subscribe.lua line 2029; link import also creates them (see 07/06) | user, subscribe | `node_config/<id>` |
| `shunt_rules` | 0..n, named | defaults `DirectFront, ProxyFront, DirectGame, ProxyGame, CN, Iran, Russia_Block, Russia`. New: `add_shunt_rule` uses `add_name` when it is a valid uciname and unused, else `gen_random_char()` (controller ~1038) | default config, user | `shunt_rules/<id>` |
| `socks` | 0..n, named `socks_<5 random>` | — | `settings` page "Add" | `socks_config/<id>` |
| `acl_rule` | 0..n, named `acl_<5 random>` | — | `acl` page "Add" | `acl_config/<id>` |
| `subscribe_list` | 0..n, named `sub_<5 random>` | — | `node_subscribe` page "Add" | `node_subscribe_config/<id>` |
| `haproxy_config` | 0..n, named `haproxy_<5 random>` | — | `haproxy` page "Add" (inline table) | inline |
| `xray_noise_packets` | 0..n, named `xray_noise_<5 random>` | — | `other` page "Add" (inline table) | inline |

Rules for the rewrite:
* Singleton sections are anonymous. The code must address them by type index (`@type[0]`) and must never rename them. The Rust backend should create a singleton when it is missing (the old code relies on uci-defaults restoring `0_default_config` when `/etc/config/passwall2` is empty, see 01 §14).
* `gen_random_char(n)` = `head /dev/urandom | tr -dc A-Za-z0-9 | head -c n`, default `n = 16`. Prefixed ids use n = 5.
* The order of `nodes`, `shunt_rules`, `socks`, `acl_rule`, `subscribe_list` and `haproxy_config` sections is significant: ACL priority, node list order, rule evaluation order, haproxy backend order. Reordering is done with `uci reorder` (see 07 `save_node_list_opt` and 10 §4.6, `cbi/sortable.htm`).

### 2.2 `/etc/config/passwall2_server`

| Section type | Cardinality | Id | Created by | Edited by |
|---|---|---|---|---|
| `global` | 1, **named `global`** | `global` | conffile default `config global 'global' / option enable '0'` | `server` (index.lua, `NamedSection("global","global")`) |
| `server` | 0..n named, `gen_random_char()` (16) | — | `server` page Add → redirect `server_config/<uid>` | `server_config/<id>` |
| `user` | 0..n named, `gen_random_char()` (16) | — | `server` page Add → redirect `server_user_config/<uid>` | `server_user_config/<id>` |

---

## 3. Consolidated UCI option index (generated from CBI sources)

Legend:
* **widget** is the CBI class. `Flag` stores `"1"`/`"0"`. `DynamicList` and `MultiValue` store UCI `list` values, unless `cast="string"`, in which case they store a space-joined option.
* **default** is the literal `o.default` expression from the source. `o.keylist[N]` means the N-th `:value()` added. Expressions such as `n + 1080` are computed at render time.
* `rmempty=false` means the option is always written when it is visible. A blank cell means the CBI default `rmempty=true`: an empty value, or a Flag equal to its default, deletes the option.
* **src** is `file:line` under `luasrc/model/cbi/passwall2/`. One UCI option can appear several times. This happens when several node types (sing-box/Xray/SS-Rust/SSR share one flat namespace, see 09 §1.2) or several pages declare it. The defaults and dependencies of the declaration whose type is active are the ones that apply.
* Options that `client/include/shunt_options.lua` declares through `add_option` are stored **on the `_shunt` node** (`nodes` section `data.node`), even when the page that renders them is `settings` (global) or `acl_config`. Those rows are listed under `nodes`.
* Dependencies (`depends`), value lists, validators and per-field encodings are **not repeated here**. They are in 08 (client pages) and 09 (node/server types).
* Pseudo-fields (DummyValue/HideValue/Button) are never stored. They are listed after each table only so that they are not mistaken for UCI options.

Dynamically named options (expanded by hand):
* `global_delay`: for `X ∈ {stop, start, restart}` → `X_week_mode` (ListValue: `""`=Disable, `0`=Sun … `6`=Sat, `7`=every day, `8`=loop mode (restart only)), `X_time_mode` (Value `H:MM`, default `"0:00"`, datatype `timehhmm`, visible when week_mode ∈ 0..7), `X_interval_mode` (ListValue 1..24 hours, default `2`, visible when week_mode = 8).
* `global_app`: for `k ∈ com.order = {geoview, xray, sing-box}` → `<k with - → _>_file`, which gives `geoview_file`, `xray_file`, `sing_box_file`. Defaults are `/usr/bin/geoview`, `/usr/bin/xray`, `/usr/bin/sing-box`. `remove()` is overridden to **write the default** instead of deleting, so these options always exist after a save.
* `global_rules`: `geoip_update`, `geosite_update` (Flag, rmempty=false, row always hidden by JS. The rule page JS sets them from checkboxes in `rule_version.htm`).
* `nodes` (client Xray `masque` + WARP): `masque_warp_private_key`, `masque_warp_public_key` (TextValue, rows 3, `\n`-escaped single line, visible when `protocol=masque` and `masque_warp=1`).
* `_shunt` node per-rule options: see §3.1.


#### `passwall2` / `global`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `acl_enable` | Flag | `false` |  | false | client/acl.lua:8 |
| `enabled` | Flag |  |  | false | client/global.lua:79 |
| `node` | ListValue |  |  |  | client/global.lua:83 |
| `localhost_proxy` | Flag | `"1"` |  | false | client/global.lua:142 |
| `client_proxy` | Flag | `"1"` |  | false | client/global.lua:146 |
| `node_socks_port` | Value | `1070` | port |  | client/global.lua:164 |
| `node_socks_bind_local` | Flag | `"1"` |  |  | client/global.lua:169 |
| `direct_dns_protocol` | ListValue |  |  |  | client/global.lua:175 |
| `direct_dns` | Value | `"223.5.5.5"` | or(ipaddr,ipaddrport(1)) |  | client/global.lua:180 |
| `direct_dns_query_strategy` | ListValue | `"UseIP"` |  |  | client/global.lua:191 |
| `remote_dns_protocol` | ListValue |  |  |  | client/global.lua:197 |
| `remote_dns` | Value | `"1.1.1.1"` | or(ipaddr,ipaddrport(1)) |  | client/global.lua:214 |
| `remote_dns_doh` | Value | `"https://1.1.1.1/dns-query"` |  |  | client/global.lua:231 |
| `remote_dns_client_ip` | Value |  | ipaddr |  | client/global.lua:247 |
| `remote_dns_detour` | ListValue | `"remote"` |  |  | client/global.lua:252 |
| `remote_fakedns` | Flag | `"0"` |  | false | client/global.lua:257 |
| `remote_dns_query_strategy` | ListValue | `"UseIPv4"` |  |  | client/global.lua:261 |
| `remote_rewrite_ttl` | Value | `"30"` | min(1) |  | client/global.lua:267 |
| `dns_hosts` | TextValue |  |  |  | client/global.lua:272 |
| `dns_redirect` | Flag | `"1"` |  | false | client/global.lua:285 |
| `log_node` | Flag | `"1"` |  | false | client/global.lua:300 |
| `loglevel` | ListValue | `"warn"` |  |  | client/global.lua:304 |
| `socks_enabled` | Flag |  |  | false | client/global.lua:337 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `<"">`, `_is_singbox`, `_log`, `_node`, `clear_ipset`, `client_proxy`, `localhost_proxy`, `node_save_before`, `tips`


#### `passwall2` / `acl_rule`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enabled` | Flag | `1` |  | false | client/acl.lua:26 |
| `remarks` | Value |  |  | true | client/acl.lua:31 |
| `enabled` | Flag | `1` |  | false | client/acl_config.lua:52 |
| `remarks` | Value | `arg[1]` |  | false | client/acl_config.lua:56 |
| `interface` | Value |  |  |  | client/acl_config.lua:60 |
| `sources` | DynamicList |  |  |  | client/acl_config.lua:94 |
| `mode` | ListValue |  |  |  | client/acl_config.lua:144 |
| `tcp_no_redir_ports` | Value |  |  |  | client/acl_config.lua:149 |
| `udp_no_redir_ports` | Value |  |  |  | client/acl_config.lua:156 |
| `tcp_redir_ports` | Value | `o.keylist[1]` |  |  | client/acl_config.lua:169 |
| `udp_redir_ports` | Value | `o.keylist[1]` |  |  | client/acl_config.lua:178 |
| `node` | ListValue |  |  |  | client/acl_config.lua:201 |
| `log` | Flag |  |  |  | client/acl_config.lua:226 |
| `loglevel` | ListValue | `"warn"` |  |  | client/acl_config.lua:229 |
| `direct_dns_query_strategy` | ListValue | `"UseIP"` |  |  | client/acl_config.lua:258 |
| `remote_dns_protocol` | ListValue |  |  |  | client/acl_config.lua:265 |
| `remote_dns` | Value | `"1.1.1.1"` | or(ipaddr,ipaddrport(1)) |  | client/acl_config.lua:283 |
| `remote_dns_doh` | Value | `"https://1.1.1.1/dns-query"` |  |  | client/acl_config.lua:300 |
| `remote_dns_client_ip` | Value |  | ipaddr |  | client/acl_config.lua:316 |
| `remote_dns_detour` | ListValue | `"remote"` |  |  | client/acl_config.lua:322 |
| `remote_fakedns` | Flag | `"0"` |  | false | client/acl_config.lua:328 |
| `remote_dns_query_strategy` | ListValue | `"UseIPv4"` |  |  | client/acl_config.lua:333 |
| `remote_rewrite_ttl` | Value | `"30"` | min(1) |  | client/acl_config.lua:340 |
| `dns_hosts_mode` | ListValue |  |  |  | client/acl_config.lua:345 |
| `dns_hosts` | TextValue |  |  |  | client/acl_config.lua:351 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `_acl_log`, `_is_singbox`, `_is_xray`, `_no_proxy`, `_node`, `_show_dns_option`, `_show_node_option`, `_show_tcp_redir`, `_show_udp_redir`, `interface`, `mode`, `node_save_before`, `sources`, `tips`


#### `passwall2` / `global_app`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `gh_proxy_url` | ListValue | `""` |  |  | client/app_update.lua:13 |
| `geoview_file` / `xray_file` / `sing_box_file` (loop over com.order, `-`→`_`) | Value | `/usr/bin/geoview` / `/usr/bin/xray` / `/usr/bin/sing-box`; `remove()` rewrites the default instead of deleting |  |  | client/app_update.lua:23 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `tips`


#### `passwall2` / `socks`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enabled` | Flag | `1` |  | false | client/global.lua:359 |
| `node` | ListValue |  |  |  | client/global.lua:363 |
| `port` | Value | `n + 1080` | port | false | client/global.lua:387 |
| `enabled` | Flag | `1` |  | false | client/socks_config.lua:27 |
| `node` | ListValue |  |  |  | client/socks_config.lua:46 |
| `bind_local` | Flag | `"0"` |  |  | client/socks_config.lua:53 |
| `port` | Value | `n + 1080` | port | false | client/socks_config.lua:64 |
| `http_port` | Value | `0` | port |  | client/socks_config.lua:70 |
| `log` | Flag | `1` |  | false | client/socks_config.lua:75 |
| `enable_autoswitch` | Flag | `0` |  | false | client/socks_config.lua:93 |
| `backup_node_add_mode` | ListValue | `"manual"` |  |  | client/socks_config.lua:97 |
| `autoswitch_backup_node` | DynamicList |  |  |  | client/socks_config.lua:103 |
| `backup_node_group` | MultiValue |  |  |  | client/socks_config.lua:126 |
| `backup_node_match_rule` | Value |  |  |  | client/socks_config.lua:140 |
| `autoswitch_testing_time` | Value | `30` | min(10) |  | client/socks_config.lua:149 |
| `autoswitch_connect_timeout` | Value | `3` | min(1) |  | client/socks_config.lua:154 |
| `autoswitch_retry_num` | Value | `1` | min(1) |  | client/socks_config.lua:159 |
| `autoswitch_restore_switch` | Flag |  |  |  | client/socks_config.lua:164 |
| `autoswitch_probe_url` | Value | `o.keylist[3]` |  |  | client/socks_config.lua:167 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `_log`, `btn`, `now_node`, `status`


#### `passwall2` / `global_haproxy`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `balancing_enable` | Flag | `false` |  | false | client/haproxy.lua:27 |
| `console_auth` | Flag | `false` |  |  | client/haproxy.lua:32 |
| `console_user` | Value | `""` |  |  | client/haproxy.lua:37 |
| `console_password` | Value | `""` |  |  | client/haproxy.lua:42 |
| `console_port` | Value | `1188` | port |  | client/haproxy.lua:48 |
| `bind_local` | Flag | `"0"` |  |  | client/haproxy.lua:53 |
| `balancingStrategy` | ListValue | `"roundrobin"` |  |  | client/haproxy.lua:57 |
| `health_check_type` | ListValue | `"script_logic"` |  |  | client/haproxy.lua:66 |
| `health_probe_url` | Value | `o.keylist[3]` |  |  | client/haproxy.lua:73 |
| `health_check_inter` | Value | `60` | min(20) |  | client/haproxy.lua:86 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `health_check_tips`


#### `passwall2` / `haproxy_config`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enabled` | Flag | `1` |  | false | client/haproxy.lua:123 |
| `lbss` | Value |  |  | false | client/haproxy.lua:128 |
| `haproxy_port` | Value | `1181` | port | false | client/haproxy.lua:152 |
| `lbweight` | Value | `5` | min(1) | false | client/haproxy.lua:158 |
| `export` | ListValue | `0` |  | false | client/haproxy.lua:164 |
| `backup` | ListValue |  |  | false | client/haproxy.lua:172 |

#### `passwall2` / `nodes`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `domainStrategy` | ListValue | `"IPOnDemand"` |  |  | client/include/shunt_options.lua:103 |
| `domainMatcher` | ListValue |  |  |  | client/include/shunt_options.lua:113 |
| `fakedns` | Flag |  |  |  | client/include/shunt_options.lua:118 |
| `write_ipset_direct` | Flag | `1` |  | false | client/include/shunt_options.lua:122 |
| `enable_geoview_ip` | Flag | `1` |  | false | client/include/shunt_options.lua:127 |
| `shunt_group` | ListValue |  |  |  | client/include/shunt_options.lua:146 |
| `remarks` | Value | `translate("Remarks")` |  | false | client/node_config.lua:35 |
| `group` | Value | `""` |  |  | client/node_config.lua:39 |
| `type` | ListValue |  |  |  | client/node_config.lua:72 |
| `protocol` | ListValue |  |  |  | client/type/1_sing-box.lua:42 |
| `node_add_mode` | ListValue | `"manual"` |  |  | client/type/1_sing-box.lua:97 |
| `urltest_node` | MultiValue |  |  |  | client/type/1_sing-box.lua:103 |
| `node_group` | MultiValue |  |  |  | client/type/1_sing-box.lua:118 |
| `node_match_rule` | Value |  |  |  | client/type/1_sing-box.lua:126 |
| `urltest_url` | Value | `o.keylist[3]` |  |  | client/type/1_sing-box.lua:135 |
| `urltest_interval` | Value | `"3m"` |  |  | client/type/1_sing-box.lua:147 |
| `urltest_tolerance` | Value | `"50"` | uinteger |  | client/type/1_sing-box.lua:156 |
| `urltest_idle_timeout` | Value | `"30m"` |  |  | client/type/1_sing-box.lua:162 |
| `urltest_interrupt_exist_connections` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:170 |
| `iface` | Value |  |  |  | client/type/1_sing-box.lua:177 |
| `address` | Value |  |  |  | client/type/1_sing-box.lua:188 |
| `port` | Value |  | port |  | client/type/1_sing-box.lua:190 |
| `uuid` | Value |  |  |  | client/type/1_sing-box.lua:193 |
| `username` | Value |  |  |  | client/type/1_sing-box.lua:199 |
| `password` | Value |  |  |  | client/type/1_sing-box.lua:206 |
| `masque_path` | Value |  |  |  | client/type/1_sing-box.lua:220 |
| `masque_headers` | TextValue |  |  |  | client/type/1_sing-box.lua:223 |
| `snell_psk` | Value |  |  | false | client/type/1_sing-box.lua:250 |
| `snell_version` | ListValue |  |  |  | client/type/1_sing-box.lua:254 |
| `snell_reuse` | Flag |  |  |  | client/type/1_sing-box.lua:259 |
| `snell_network` | ListValue |  |  |  | client/type/1_sing-box.lua:262 |
| `snell_obfs_mode` | ListValue |  |  |  | client/type/1_sing-box.lua:268 |
| `snell_obfs_host` | Value |  |  |  | client/type/1_sing-box.lua:273 |
| `snell_mode` | ListValue |  |  |  | client/type/1_sing-box.lua:276 |
| `security` | ListValue |  |  |  | client/type/1_sing-box.lua:283 |
| `ss_method` | ListValue |  |  |  | client/type/1_sing-box.lua:287 |
| `ssr_method` | ListValue |  |  |  | client/type/1_sing-box.lua:293 |
| `ssr_protocol` | ListValue |  |  |  | client/type/1_sing-box.lua:304 |
| `ssr_protocol_param` | Value |  |  |  | client/type/1_sing-box.lua:308 |
| `ssr_obfs` | ListValue |  |  |  | client/type/1_sing-box.lua:316 |
| `ssr_obfs_param` | Value |  |  |  | client/type/1_sing-box.lua:320 |
| `uot` | Flag |  |  |  | client/type/1_sing-box.lua:324 |
| `alter_id` | Value | `"0"` | uinteger |  | client/type/1_sing-box.lua:329 |
| `global_padding` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:334 |
| `authenticated_length` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:338 |
| `flow` | ListValue | `""` |  |  | client/type/1_sing-box.lua:342 |
| `hysteria_hop` | Value |  |  |  | client/type/1_sing-box.lua:349 |
| `hysteria_hop_interval` | Value | `"30"` | uinteger |  | client/type/1_sing-box.lua:353 |
| `hysteria_obfs` | Value |  |  |  | client/type/1_sing-box.lua:359 |
| `hysteria_auth_type` | ListValue |  |  |  | client/type/1_sing-box.lua:362 |
| `hysteria_auth_password` | Value |  |  |  | client/type/1_sing-box.lua:368 |
| `hysteria_up_mbps` | Value | `"10"` |  |  | client/type/1_sing-box.lua:373 |
| `hysteria_down_mbps` | Value | `"50"` |  |  | client/type/1_sing-box.lua:377 |
| `hysteria_recv_window_conn` | Value |  |  |  | client/type/1_sing-box.lua:381 |
| `hysteria_recv_window` | Value |  |  |  | client/type/1_sing-box.lua:384 |
| `hysteria_disable_mtu_discovery` | Flag |  |  |  | client/type/1_sing-box.lua:387 |
| `tuic_congestion_control` | ListValue | `"cubic"` |  |  | client/type/1_sing-box.lua:392 |
| `tuic_udp_relay_mode` | ListValue | `"native"` |  |  | client/type/1_sing-box.lua:399 |
| `tuic_zero_rtt_handshake` | Flag | `0` |  |  | client/type/1_sing-box.lua:410 |
| `tuic_heartbeat` | Value | `"3"` | uinteger |  | client/type/1_sing-box.lua:414 |
| `tuic_alpn` | ListValue | `"default"` |  |  | client/type/1_sing-box.lua:419 |
| `hysteria2_hop` | Value |  |  |  | client/type/1_sing-box.lua:434 |
| `hysteria2_hop_interval` | Value | `"30"` | or(uinteger,portrange) |  | client/type/1_sing-box.lua:438 |
| `hysteria2_realms` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:444 |
| `hysteria2_realm_url` | Value |  |  |  | client/type/1_sing-box.lua:452 |
| `hysteria2_realm_stun` | DynamicList | `{ "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }` |  |  | client/type/1_sing-box.lua:461 |
| `hysteria2_realm_upnp` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:465 |
| `hysteria2_auth_password` | Value |  |  |  | client/type/1_sing-box.lua:469 |
| `hysteria2_obfs_type` | ListValue |  |  |  | client/type/1_sing-box.lua:473 |
| `hysteria2_obfs_password` | Value |  |  |  | client/type/1_sing-box.lua:479 |
| `hysteria2_obfs_MinPacketSize` | Value | `"512"` | uinteger |  | client/type/1_sing-box.lua:483 |
| `hysteria2_obfs_MaxPacketSize` | Value | `"1200"` | uinteger |  | client/type/1_sing-box.lua:489 |
| `hysteria2_up_mbps` | Value |  |  |  | client/type/1_sing-box.lua:495 |
| `hysteria2_down_mbps` | Value |  |  |  | client/type/1_sing-box.lua:498 |
| `hysteria2_stream_recv_win` | Value |  | range(1,1000) |  | client/type/1_sing-box.lua:501 |
| `hysteria2_conn_recv_win` | Value |  | range(1,1000) |  | client/type/1_sing-box.lua:506 |
| `hysteria2_idle_timeout` | Value |  | range(4,120) |  | client/type/1_sing-box.lua:511 |
| `hysteria2_keep_alive_period` | Value |  | range(2,60) |  | client/type/1_sing-box.lua:515 |
| `hysteria2_disable_mtu_discovery` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:519 |
| `ssh_priv_key` | TextValue |  |  |  | client/type/1_sing-box.lua:525 |
| `ssh_priv_key_pp` | Value |  |  |  | client/type/1_sing-box.lua:534 |
| `ssh_host_key` | DynamicList |  |  |  | client/type/1_sing-box.lua:538 |
| `ssh_host_key_algo` | DynamicList |  |  |  | client/type/1_sing-box.lua:541 |
| `ssh_client_version` | Value |  |  |  | client/type/1_sing-box.lua:544 |
| `naive_insecure_concurrency` | Value | `"0"` | uinteger |  | client/type/1_sing-box.lua:549 |
| `naive_quic` | Flag | `0` |  |  | client/type/1_sing-box.lua:555 |
| `naive_congestion_control` | ListValue | `"bbr"` |  |  | client/type/1_sing-box.lua:559 |
| `tls` | Flag | `0` |  |  | client/type/1_sing-box.lua:568 |
| `alpn` | ListValue | `"default"` |  |  | client/type/1_sing-box.lua:577 |
| `tls_disable_sni` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:589 |
| `tls_serverName` | Value |  |  |  | client/type/1_sing-box.lua:597 |
| `tls_allowInsecure` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:605 |
| `tls_pinSHA256` | Value |  |  |  | client/type/1_sing-box.lua:613 |
| `tls_certificate` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:622 |
| `tls_certificate_pem` | TextValue | `""` |  |  | client/type/1_sing-box.lua:631 |
| `cipherSuites` | DynamicList |  |  |  | client/type/1_sing-box.lua:644 |
| `ech` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:661 |
| `ech_config` | TextValue | `""` |  |  | client/type/1_sing-box.lua:670 |
| `ech_query_server_name` | Value |  |  |  | client/type/1_sing-box.lua:683 |
| `utls` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:687 |
| `fingerprint` | ListValue | `"chrome"` |  |  | client/type/1_sing-box.lua:691 |
| `reality` | Flag | `0` |  |  | client/type/1_sing-box.lua:706 |
| `reality_publicKey` | Value |  |  |  | client/type/1_sing-box.lua:716 |
| `reality_shortId` | Value |  |  |  | client/type/1_sing-box.lua:719 |
| `anytls_disable_reuse` | Flag | `0` |  |  | client/type/1_sing-box.lua:723 |
| `transport` | ListValue |  |  |  | client/type/1_sing-box.lua:727 |
| `wireguard_public_key` | Value |  |  |  | client/type/1_sing-box.lua:746 |
| `wireguard_secret_key` | Value |  |  |  | client/type/1_sing-box.lua:749 |
| `wireguard_preSharedKey` | Value |  |  |  | client/type/1_sing-box.lua:752 |
| `wireguard_local_address` | DynamicList |  |  |  | client/type/1_sing-box.lua:755 |
| `wireguard_mtu` | Value | `"1420"` |  |  | client/type/1_sing-box.lua:758 |
| `wireguard_system_interface` | Flag | `0` |  |  | client/type/1_sing-box.lua:762 |
| `wireguard_interface_name` | Value |  |  |  | client/type/1_sing-box.lua:766 |
| `wireguard_reserved` | Value |  |  |  | client/type/1_sing-box.lua:769 |
| `tcp_guise` | ListValue |  |  |  | client/type/1_sing-box.lua:774 |
| `tcp_guise_http_host` | DynamicList |  |  |  | client/type/1_sing-box.lua:779 |
| `tcp_guise_http_path` | DynamicList |  |  |  | client/type/1_sing-box.lua:782 |
| `http_host` | DynamicList |  |  |  | client/type/1_sing-box.lua:787 |
| `http_path` | Value |  |  |  | client/type/1_sing-box.lua:790 |
| `http_h2_health_check` | Flag |  |  |  | client/type/1_sing-box.lua:794 |
| `http_h2_read_idle_timeout` | Value | `"15"` |  |  | client/type/1_sing-box.lua:797 |
| `http_h2_health_check_timeout` | Value | `"15"` |  |  | client/type/1_sing-box.lua:801 |
| `ws_host` | Value |  |  |  | client/type/1_sing-box.lua:806 |
| `ws_path` | Value |  |  |  | client/type/1_sing-box.lua:809 |
| `ws_enableEarlyData` | Flag |  |  |  | client/type/1_sing-box.lua:813 |
| `ws_maxEarlyData` | Value | `"1024"` |  |  | client/type/1_sing-box.lua:816 |
| `ws_earlyDataHeaderName` | Value |  |  |  | client/type/1_sing-box.lua:820 |
| `httpupgrade_host` | Value |  |  |  | client/type/1_sing-box.lua:824 |
| `httpupgrade_path` | Value |  |  |  | client/type/1_sing-box.lua:827 |
| `grpc_serviceName` | Value |  |  |  | client/type/1_sing-box.lua:832 |
| `grpc_health_check` | Flag |  |  |  | client/type/1_sing-box.lua:835 |
| `grpc_idle_timeout` | Value | `"15"` |  |  | client/type/1_sing-box.lua:838 |
| `grpc_health_check_timeout` | Value | `"15"` |  |  | client/type/1_sing-box.lua:842 |
| `grpc_permit_without_stream` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:846 |
| `user_agent` | Value | `""` |  |  | client/type/1_sing-box.lua:851 |
| `mux` | Flag |  |  | false | client/type/1_sing-box.lua:868 |
| `mux_type` | ListValue |  |  |  | client/type/1_sing-box.lua:875 |
| `mux_concurrency` | Value | `4` |  |  | client/type/1_sing-box.lua:881 |
| `mux_padding` | Flag | `0` |  |  | client/type/1_sing-box.lua:885 |
| `tcpbrutal` | Flag | `0` |  |  | client/type/1_sing-box.lua:890 |
| `tcpbrutal_up_mbps` | Value | `"10"` |  |  | client/type/1_sing-box.lua:894 |
| `tcpbrutal_down_mbps` | Value | `"50"` |  |  | client/type/1_sing-box.lua:898 |
| `shadowtls` | Flag | `0` |  |  | client/type/1_sing-box.lua:902 |
| `shadowtls_version` | ListValue | `"1"` |  |  | client/type/1_sing-box.lua:907 |
| `shadowtls_password` | Value |  |  |  | client/type/1_sing-box.lua:914 |
| `shadowtls_serverName` | Value |  |  |  | client/type/1_sing-box.lua:919 |
| `shadowtls_utls` | Flag | `"0"` |  |  | client/type/1_sing-box.lua:923 |
| `shadowtls_fingerprint` | ListValue | `"chrome"` |  |  | client/type/1_sing-box.lua:927 |
| `plugin_enabled` | Flag | `0` |  |  | client/type/1_sing-box.lua:943 |
| `plugin` | ListValue | `"obfs-local"` |  |  | client/type/1_sing-box.lua:947 |
| `plugin_opts` | Value |  |  |  | client/type/1_sing-box.lua:953 |
| `domain_resolver` | ListValue |  |  |  | client/type/1_sing-box.lua:956 |
| `domain_resolver_dns` | Value | `o.keylist[1]` | or(ipaddr,ipaddrport) |  | client/type/1_sing-box.lua:962 |
| `domain_resolver_dns_https` | Value | `o.keylist[1]` |  |  | client/type/1_sing-box.lua:970 |
| `domain_strategy` | ListValue | `""` |  |  | client/type/1_sing-box.lua:976 |
| `chain_proxy` | ListValue |  |  |  | client/type/1_sing-box.lua:1003 |
| `preproxy_node` | ListValue |  |  |  | client/type/1_sing-box.lua:1012 |
| `outbound_iface` | Value |  |  |  | client/type/1_sing-box.lua:1017 |
| `to_node` | ListValue |  |  |  | client/type/1_sing-box.lua:1024 |
| `protocol` | ListValue |  |  |  | client/type/2_xray.lua:34 |
| `node_add_mode` | ListValue | `"manual"` |  |  | client/type/2_xray.lua:80 |
| `balancing_node` | MultiValue |  |  |  | client/type/2_xray.lua:86 |
| `node_group` | MultiValue |  |  |  | client/type/2_xray.lua:101 |
| `node_match_rule` | Value |  |  |  | client/type/2_xray.lua:109 |
| `balancingStrategy` | ListValue | `"random"` |  |  | client/type/2_xray.lua:118 |
| `fallback_node` | ListValue |  |  |  | client/type/2_xray.lua:127 |
| `useCustomProbeUrl` | Flag |  |  |  | client/type/2_xray.lua:195 |
| `probeUrl` | Value | `o.keylist[3]` |  |  | client/type/2_xray.lua:198 |
| `probeInterval` | Value | `"1m"` |  |  | client/type/2_xray.lua:210 |
| `expected` | Value | `"2"` | uinteger |  | client/type/2_xray.lua:218 |
| `tolerance` | Value | `"10"` | uinteger |  | client/type/2_xray.lua:225 |
| `iface` | Value |  |  |  | client/type/2_xray.lua:234 |
| `address` | Value |  |  |  | client/type/2_xray.lua:245 |
| `port` | Value |  | port |  | client/type/2_xray.lua:247 |
| `uuid` | Value |  |  |  | client/type/2_xray.lua:250 |
| `username` | Value |  |  |  | client/type/2_xray.lua:255 |
| `password` | Value |  |  |  | client/type/2_xray.lua:260 |
| `masque_warp` | Flag | `"0"` |  |  | client/type/2_xray.lua:269 |
| `masque_warp_private_key`, `masque_warp_public_key` | TextValue (rows 3, `\n`-escaped) |  |  |  | client/type/2_xray.lua:277 |
| `masque_warp_address` | DynamicList |  |  |  | client/type/2_xray.lua:289 |
| `masque_path` | Value |  |  |  | client/type/2_xray.lua:292 |
| `masque_headers` | TextValue |  |  |  | client/type/2_xray.lua:295 |
| `security` | ListValue |  |  |  | client/type/2_xray.lua:318 |
| `encryption` | Value | `"none"` |  |  | client/type/2_xray.lua:322 |
| `ss_method` | ListValue |  |  |  | client/type/2_xray.lua:331 |
| `flow` | ListValue | `""` |  |  | client/type/2_xray.lua:335 |
| `hysteria2_hop` | Value |  |  |  | client/type/2_xray.lua:343 |
| `hysteria2_hop_interval` | Value | `"30"` | or(uinteger,portrange) |  | client/type/2_xray.lua:347 |
| `hysteria2_realms` | Flag | `"0"` |  |  | client/type/2_xray.lua:353 |
| `hysteria2_realm_url` | Value |  |  |  | client/type/2_xray.lua:357 |
| `hysteria2_realm_stun` | DynamicList | `{ "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }` |  |  | client/type/2_xray.lua:366 |
| `hysteria2_realm_upnp` | Flag | `"0"` |  |  | client/type/2_xray.lua:370 |
| `hysteria2_auth_password` | Value |  |  |  | client/type/2_xray.lua:374 |
| `hysteria2_obfs_type` | ListValue |  |  |  | client/type/2_xray.lua:378 |
| `hysteria2_obfs_password` | Value |  |  |  | client/type/2_xray.lua:384 |
| `hysteria2_obfs_MinPacketSize` | Value | `"512"` | uinteger |  | client/type/2_xray.lua:388 |
| `hysteria2_obfs_MaxPacketSize` | Value | `"1200"` | uinteger |  | client/type/2_xray.lua:394 |
| `hysteria2_up_mbps` | Value |  |  |  | client/type/2_xray.lua:400 |
| `hysteria2_down_mbps` | Value |  |  |  | client/type/2_xray.lua:403 |
| `hysteria2_stream_recv_win` | Value |  | range(1,1000) |  | client/type/2_xray.lua:406 |
| `hysteria2_conn_recv_win` | Value |  | range(1,1000) |  | client/type/2_xray.lua:411 |
| `hysteria2_idle_timeout` | Value |  | range(4,120) |  | client/type/2_xray.lua:416 |
| `hysteria2_keep_alive_period` | Value |  | range(2,60) |  | client/type/2_xray.lua:420 |
| `hysteria2_disable_mtu_discovery` | Flag | `"0"` |  |  | client/type/2_xray.lua:424 |
| `tls` | Flag | `0` |  |  | client/type/2_xray.lua:429 |
| `reality` | Flag | `0` |  |  | client/type/2_xray.lua:438 |
| `alpn` | ListValue | `"default"` |  |  | client/type/2_xray.lua:446 |
| `tls_serverName` | Value |  |  |  | client/type/2_xray.lua:463 |
| `tls_pinSHA256` | Value |  |  |  | client/type/2_xray.lua:468 |
| `tls_CertByName` | Value |  |  |  | client/type/2_xray.lua:475 |
| `tls_certificate` | Flag | `"0"` |  |  | client/type/2_xray.lua:480 |
| `tls_certificate_pem` | TextValue | `""` |  |  | client/type/2_xray.lua:486 |
| `ech` | Flag | `"0"` |  |  | client/type/2_xray.lua:499 |
| `ech_config` | TextValue | `""` |  |  | client/type/2_xray.lua:505 |
| `reality_publicKey` | Value |  |  |  | client/type/2_xray.lua:515 |
| `reality_shortId` | Value |  |  |  | client/type/2_xray.lua:518 |
| `reality_spiderX` | Value |  |  |  | client/type/2_xray.lua:521 |
| `utls` | Flag | `"0"` |  |  | client/type/2_xray.lua:525 |
| `fingerprint` | ListValue | `"chrome"` |  |  | client/type/2_xray.lua:529 |
| `use_mldsa65Verify` | Flag | `"0"` |  |  | client/type/2_xray.lua:545 |
| `cipherSuites` | DynamicList |  |  |  | client/type/2_xray.lua:549 |
| `reality_mldsa65Verify` | TextValue | `""` |  |  | client/type/2_xray.lua:566 |
| `transport` | ListValue |  |  |  | client/type/2_xray.lua:575 |
| `wireguard_public_key` | Value |  |  |  | client/type/2_xray.lua:588 |
| `wireguard_secret_key` | Value |  |  |  | client/type/2_xray.lua:591 |
| `wireguard_preSharedKey` | Value |  |  |  | client/type/2_xray.lua:594 |
| `wireguard_local_address` | DynamicList |  |  |  | client/type/2_xray.lua:597 |
| `wireguard_mtu` | Value | `"1420"` |  |  | client/type/2_xray.lua:600 |
| `wireguard_reserved` | Value |  |  |  | client/type/2_xray.lua:604 |
| `wireguard_keepAlive` | Value | `"0"` |  |  | client/type/2_xray.lua:607 |
| `tcp_guise` | ListValue |  |  |  | client/type/2_xray.lua:612 |
| `tcp_guise_http_host` | DynamicList |  |  |  | client/type/2_xray.lua:617 |
| `tcp_guise_http_path` | DynamicList |  |  |  | client/type/2_xray.lua:620 |
| `mkcp_guise` | ListValue |  |  |  | client/type/2_xray.lua:625 |
| `mkcp_domain` | Value |  |  |  | client/type/2_xray.lua:629 |
| `mkcp_mtu` | Value | `1350` | uinteger |  | client/type/2_xray.lua:632 |
| `mkcp_seed` | Value |  |  |  | client/type/2_xray.lua:637 |
| `ws_host` | Value |  |  |  | client/type/2_xray.lua:641 |
| `ws_path` | Value |  |  |  | client/type/2_xray.lua:644 |
| `ws_heartbeatPeriod` | Value |  | integer |  | client/type/2_xray.lua:648 |
| `grpc_serviceName` | Value |  |  |  | client/type/2_xray.lua:653 |
| `grpc_mode` | ListValue |  |  |  | client/type/2_xray.lua:656 |
| `grpc_health_check` | Flag |  |  |  | client/type/2_xray.lua:661 |
| `grpc_idle_timeout` | Value | `"10"` |  |  | client/type/2_xray.lua:664 |
| `grpc_health_check_timeout` | Value | `"20"` |  |  | client/type/2_xray.lua:668 |
| `grpc_permit_without_stream` | Flag | `"0"` |  |  | client/type/2_xray.lua:672 |
| `grpc_initial_windows_size` | Value | `"0"` |  |  | client/type/2_xray.lua:676 |
| `httpupgrade_host` | Value |  |  |  | client/type/2_xray.lua:681 |
| `httpupgrade_path` | Value |  |  |  | client/type/2_xray.lua:684 |
| `xhttp_mode` | ListValue | `"auto"` |  |  | client/type/2_xray.lua:689 |
| `xhttp_host` | Value |  |  |  | client/type/2_xray.lua:697 |
| `xhttp_path` | Value |  |  |  | client/type/2_xray.lua:700 |
| `use_xhttp_extra` | Flag | `"0"` |  |  | client/type/2_xray.lua:704 |
| `xhttp_extra` | TextValue |  | json |  | client/type/2_xray.lua:708 |
| `user_agent` | Value | `""` |  |  | client/type/2_xray.lua:748 |
| `mux` | Flag |  |  |  | client/type/2_xray.lua:765 |
| `mux_concurrency` | Value | `-1` |  |  | client/type/2_xray.lua:776 |
| `xudp_concurrency` | Value | `8` |  |  | client/type/2_xray.lua:780 |
| `use_finalmask` | Flag | `"0"` |  |  | client/type/2_xray.lua:785 |
| `finalmask` | TextValue |  | json |  | client/type/2_xray.lua:795 |
| `tcp_fast_open` | Flag | `0` |  |  | client/type/2_xray.lua:820 |
| `tcpMptcp` | Flag | `0` |  |  | client/type/2_xray.lua:824 |
| `domain_resolver` | ListValue |  |  |  | client/type/2_xray.lua:827 |
| `domain_resolver_dns` | Value | `o.keylist[1]` | or(ipaddr,ipaddrport) |  | client/type/2_xray.lua:833 |
| `domain_resolver_dns_https` | Value | `o.keylist[1]` |  |  | client/type/2_xray.lua:841 |
| `domain_strategy` | ListValue | `""` |  |  | client/type/2_xray.lua:847 |
| `happy_eyeballs` | Flag | `0` |  |  | client/type/2_xray.lua:853 |
| `chain_proxy` | ListValue |  |  |  | client/type/2_xray.lua:884 |
| `preproxy_node` | ListValue |  |  |  | client/type/2_xray.lua:893 |
| `outbound_iface` | Value |  |  |  | client/type/2_xray.lua:898 |
| `to_node` | ListValue |  |  |  | client/type/2_xray.lua:905 |
| `address` | Value |  |  |  | client/type/3_ss-rust.lua:27 |
| `port` | Value |  | port |  | client/type/3_ss-rust.lua:29 |
| `password` | Value |  |  |  | client/type/3_ss-rust.lua:32 |
| `method` | Value |  |  |  | client/type/3_ss-rust.lua:35 |
| `timeout` | Value | `300` | uinteger |  | client/type/3_ss-rust.lua:38 |
| `tcp_fast_open` | Flag | `0` |  |  | client/type/3_ss-rust.lua:42 |
| `plugin_enabled` | Flag | `0` |  |  | client/type/3_ss-rust.lua:45 |
| `plugin` | Value | `"none"` |  |  | client/type/3_ss-rust.lua:48 |
| `plugin_opts` | Value |  |  |  | client/type/3_ss-rust.lua:67 |
| `address` | Value |  |  |  | client/type/4_ssr.lua:40 |
| `port` | Value |  | port |  | client/type/4_ssr.lua:42 |
| `password` | Value |  |  |  | client/type/4_ssr.lua:45 |
| `method` | ListValue |  |  |  | client/type/4_ssr.lua:48 |
| `protocol` | ListValue |  |  |  | client/type/4_ssr.lua:51 |
| `protocol_param` | Value |  |  |  | client/type/4_ssr.lua:54 |
| `obfs` | ListValue |  |  |  | client/type/4_ssr.lua:56 |
| `obfs_param` | Value |  |  |  | client/type/4_ssr.lua:59 |
| `timeout` | Value | `300` | uinteger |  | client/type/4_ssr.lua:61 |
| `tcp_fast_open` | Flag | `0` |  |  | client/type/4_ssr.lua:65 |


Not stored (DummyValue/HideValue/Button pseudo-fields): `passwall2`


#### `passwall2` / `(Table:shunt_rules)` — virtual table rows; real storage described in §3.1

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `remarks` | DummyValue |  |  |  | client/include/shunt_options.lua:181 |
| `_node` | Value |  |  |  | client/include/shunt_options.lua:191 |
| `_fakedns` | Flag |  |  |  | client/include/shunt_options.lua:212 |
| `_proxy_tag` | ListValue |  |  |  | client/include/shunt_options.lua:229 |

#### `passwall2` / `global_other`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `auto_detection_time` | ListValue |  |  |  | client/node_list.lua:9 |
| `show_node_info` | Flag | `"0"` |  |  | client/node_list.lua:14 |
| `url_test_url` | Value | `o.keylist[3]` |  |  | client/node_list.lua:17 |

#### `passwall2` / `global_subscribe`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `filter_keyword_mode` | ListValue |  |  |  | client/node_subscribe.lua:47 |
| `filter_discard_list` | DynamicList |  |  |  | client/node_subscribe.lua:54 |
| `filter_keep_list` | DynamicList |  |  |  | client/node_subscribe.lua:56 |
| `ss_type` | ListValue |  |  |  | client/node_subscribe.lua:59 |
| `trojan_type` | ListValue |  |  |  | client/node_subscribe.lua:67 |
| `vmess_type` | ListValue |  |  |  | client/node_subscribe.lua:75 |
| `vless_type` | ListValue |  |  |  | client/node_subscribe.lua:83 |
| `hysteria2_type` | ListValue |  |  |  | client/node_subscribe.lua:91 |
| `_stop` | DummyValue |  |  |  | client/node_subscribe.lua:104 |
| `_update` | DummyValue |  |  |  | client/node_subscribe.lua:112 |

#### `passwall2` / `subscribe_list`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `remark` | Value |  |  | false | client/node_subscribe.lua:134 |
| `_node_count` | DummyValue |  |  |  | client/node_subscribe.lua:178 |
| `url` | Value |  |  | false | client/node_subscribe.lua:197 |
| `_remove` | DummyValue |  |  |  | client/node_subscribe.lua:201 |
| `_update` | DummyValue |  |  |  | client/node_subscribe.lua:210 |
| `remark` | Value |  |  | false | client/node_subscribe_config.lua:66 |
| `url` | TextValue |  |  | false | client/node_subscribe_config.lua:109 |
| `domain_resolver` | ListValue | `""` |  |  | client/node_subscribe_config.lua:119 |
| `domain_resolver_dns` | Value | `o.keylist[1]` | or(ipaddr,ipaddrport) |  | client/node_subscribe_config.lua:130 |
| `domain_resolver_dns_https` | Value | `o.keylist[1]` |  |  | client/node_subscribe_config.lua:138 |
| `domain_strategy` | ListValue | `""` |  |  | client/node_subscribe_config.lua:144 |
| `allowInsecure` | Flag | `"0"` |  | false | client/node_subscribe_config.lua:150 |
| `filter_keyword_mode` | ListValue | `"5"` |  |  | client/node_subscribe_config.lua:156 |
| `filter_discard_list` | DynamicList |  |  |  | client/node_subscribe_config.lua:165 |
| `filter_keep_list` | DynamicList |  |  |  | client/node_subscribe_config.lua:170 |
| `ss_type` | ListValue | `"global"` |  |  | client/node_subscribe_config.lua:176 |
| `trojan_type` | ListValue | `"global"` |  |  | client/node_subscribe_config.lua:185 |
| `vmess_type` | ListValue | `"global"` |  |  | client/node_subscribe_config.lua:194 |
| `vless_type` | ListValue | `"global"` |  |  | client/node_subscribe_config.lua:203 |
| `hysteria2_type` | ListValue | `"global"` |  |  | client/node_subscribe_config.lua:212 |
| `hysteria_up_mbps` | Value |  | uinteger |  | client/node_subscribe_config.lua:219 |
| `hysteria_down_mbps` | Value |  | uinteger |  | client/node_subscribe_config.lua:222 |
| `boot_update` | Flag | `0` |  |  | client/node_subscribe_config.lua:226 |
| `update_week_mode` | ListValue |  |  |  | client/node_subscribe_config.lua:229 |
| `update_time_mode` | Value | `"0:00"` | timehhmm |  | client/node_subscribe_config.lua:241 |
| `update_interval_mode` | ListValue | `2` |  | true | client/node_subscribe_config.lua:263 |
| `access_mode` | ListValue | `""` |  |  | client/node_subscribe_config.lua:269 |
| `user_agent` | Value | `"v2rayN/9.99"` |  |  | client/node_subscribe_config.lua:275 |
| `chain_proxy` | ListValue |  |  |  | client/node_subscribe_config.lua:284 |
| `preproxy_node` | ListValue |  |  |  | client/node_subscribe_config.lua:294 |
| `to_node` | ListValue |  |  |  | client/node_subscribe_config.lua:300 |
| `outbound_iface` | Value |  |  |  | client/node_subscribe_config.lua:306 |
| `hwid` | Flag | `0` |  |  | client/node_subscribe_config.lua:323 |

#### `passwall2` / `global_delay`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `start_daemon` | Flag | `1` |  | false | client/other.lua:18 |
| `start_delay` | Value | `"1"` |  | true | client/other.lua:23 |
| `stop_week_mode`, `start_week_mode`, `restart_week_mode` | ListValue (""=Disable, 0..6 weekday (0=Sun), 7=every day, 8=loop – restart only) |  |  |  | client/other.lua:28 |
| `stop_time_mode`, `start_time_mode`, `restart_time_mode` | Value (dep week_mode∈0..7) | `"0:00"` | timehhmm |  | client/other.lua:42 |
| `stop_interval_mode`, `start_interval_mode`, `restart_interval_mode` | ListValue 1..24 h (dep week_mode=8) | `2` |  |  | client/other.lua:64 |

#### `passwall2` / `global_forwarding`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `tcp_no_redir_ports` | Value |  |  |  | client/other.lua:74 |
| `udp_no_redir_ports` | Value |  |  |  | client/other.lua:80 |
| `tcp_redir_ports` | Value | `o.keylist[1]` |  |  | client/other.lua:89 |
| `udp_redir_ports` | Value | `o.keylist[1]` |  |  | client/other.lua:97 |
| `prefer_nft` | ListValue | `"1"` |  |  | client/other.lua:110 |
| `tcp_proxy_way` | ListValue | `"redirect"` |  |  | client/other.lua:124 |
| `_tcp_proxy_way` | ListValue | `"tproxy"` |  |  | client/other.lua:133 |
| `ipv6_tproxy` | Flag | `0` |  | false | client/other.lua:143 |
| `accept_icmp` | Flag | `0` |  |  | client/other.lua:152 |
| `accept_icmpv6` | Flag | `0` |  |  | client/other.lua:155 |
| `direct_ip` | TextValue |  |  |  | client/other.lua:173 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `tips`


#### `passwall2` / `global_xray`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `fragment` | Flag | `0` |  |  | client/other.lua:202 |
| `fragment_packets` | ListValue | `"tlshello"` |  |  | client/other.lua:205 |
| `fragment_lengths` | Value | `"3-5,6-8,10-20"` |  |  | client/other.lua:214 |
| `fragment_delays` | Value | `"10-20"` |  |  | client/other.lua:218 |
| `fragment_maxSplit` | Value | `"3-6"` | or(uinteger,portrange) |  | client/other.lua:222 |
| `noise` | Flag | `0` |  |  | client/other.lua:227 |
| `sniffing_override_dest` | Flag | `0` |  |  | client/other.lua:230 |
| `route_only` | Flag | `0` |  |  | client/other.lua:234 |
| `excluded_domains` | TextValue |  |  |  | client/other.lua:239 |
| `buffer_size` | Value |  | uinteger | true | client/other.lua:246 |

#### `passwall2` / `xray_noise_packets`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enabled` | Flag | `1` |  | false | client/other.lua:271 |
| `type` | ListValue |  |  |  | client/other.lua:275 |
| `packet` | Value |  | minlength(1) | false | client/other.lua:282 |
| `delay` | Value |  | or(uinteger,portrange) | false | client/other.lua:286 |

#### `passwall2` / `global_singbox`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `record_fragment` | Flag | `0` |  |  | client/other.lua:294 |
| `fragment` | Flag | `0` |  |  | client/other.lua:298 |

#### `passwall2` / `global_rules`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `geoip_url` | Value | `o.keylist[1]` |  |  | client/rule.lua:9 |
| `geosite_url` | Value | `o.keylist[1]` |  |  | client/rule.lua:20 |
| `v2ray_location_asset` | Value | `"/usr/share/v2ray/"` |  | false | client/rule.lua:31 |
| `update_week_mode` | ListValue |  |  |  | client/rule.lua:36 |
| `update_time_mode` | Value | `"0:00"` | timehhmm |  | client/rule.lua:48 |
| `update_interval_mode` | ListValue | `2` |  | true | client/rule.lua:70 |
| `geoip_update`, `geosite_update` | Flag (always hidden by JS; rmempty=false) |  |  | false | client/rule.lua:81 |

#### `passwall2` / `shunt_rules`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `remarks` | Value | `arg[1]` |  | false | client/shunt_rules.lua:63 |
| `group` | Value | `""` |  |  | client/shunt_rules.lua:77 |
| `protocol` | MultiValue | `nil` |  |  | client/shunt_rules.lua:99 |
| `inbound` | MultiValue | `nil` |  |  | client/shunt_rules.lua:108 |
| `network` | ListValue |  |  |  | client/shunt_rules.lua:115 |
| `source` | DynamicList |  |  |  | client/shunt_rules.lua:120 |
| `port` | Value |  |  |  | client/shunt_rules.lua:173 |
| `domain_list` | TextValue |  |  |  | client/shunt_rules.lua:175 |
| `ip_list` | TextValue |  |  |  | client/shunt_rules.lua:227 |
| `invert` | Flag |  |  |  | client/shunt_rules.lua:265 |

#### `passwall2_server` / `global`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enable` | Flag |  |  | false | server/index.lua:11 |

#### `passwall2_server` / `server`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `enable` | Flag |  |  | false | server/index.lua:32 |
| `log` | Flag | `"1"` |  | false | server/index.lua:85 |
| `enable` | Flag | `"1"` |  | false | server/server_config.lua:27 |
| `remarks` | Value | `translate("Remarks")` |  | false | server/server_config.lua:31 |
| `type` | ListValue |  |  |  | server/server_config.lua:35 |
| `custom` | Flag |  |  |  | server/type/1_sing-box.lua:41 |
| `custom_config` | TextValue |  | json |  | server/type/1_sing-box.lua:43 |
| `protocol` | ListValue |  |  |  | server/type/1_sing-box.lua:64 |
| `port` | Value |  | port |  | server/type/1_sing-box.lua:77 |
| `users` | MultiValue |  |  |  | server/type/1_sing-box.lua:81 |
| `hysteria_obfs` | Value |  |  |  | server/type/1_sing-box.lua:101 |
| `hysteria_up_mbps` | Value | `"100"` |  |  | server/type/1_sing-box.lua:104 |
| `hysteria_down_mbps` | Value | `"100"` |  |  | server/type/1_sing-box.lua:108 |
| `hysteria_recv_window_conn` | Value |  |  |  | server/type/1_sing-box.lua:112 |
| `hysteria_recv_window_client` | Value |  |  |  | server/type/1_sing-box.lua:115 |
| `hysteria_max_conn_client` | Value | `"1024"` |  |  | server/type/1_sing-box.lua:118 |
| `hysteria_disable_mtu_discovery` | Flag |  |  |  | server/type/1_sing-box.lua:122 |
| `tuic_congestion_control` | ListValue | `"cubic"` |  |  | server/type/1_sing-box.lua:131 |
| `tuic_zero_rtt_handshake` | Flag | `0` |  |  | server/type/1_sing-box.lua:138 |
| `tuic_heartbeat` | Value | `"3"` | uinteger |  | server/type/1_sing-box.lua:142 |
| `tuic_alpn` | ListValue | `"default"` |  |  | server/type/1_sing-box.lua:147 |
| `hysteria2_realms` | Flag | `"0"` |  |  | server/type/1_sing-box.lua:166 |
| `hysteria2_realm_url` | Value |  |  |  | server/type/1_sing-box.lua:170 |
| `hysteria2_realm_stun` | DynamicList | `{ "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }` |  |  | server/type/1_sing-box.lua:179 |
| `hysteria2_realm_upnp` | Flag | `"0"` |  |  | server/type/1_sing-box.lua:183 |
| `hysteria2_obfs_type` | ListValue |  |  |  | server/type/1_sing-box.lua:187 |
| `hysteria2_obfs_password` | Value |  |  |  | server/type/1_sing-box.lua:193 |
| `hysteria2_obfs_MinPacketSize` | Value | `"512"` | uinteger |  | server/type/1_sing-box.lua:197 |
| `hysteria2_obfs_MaxPacketSize` | Value | `"1200"` | uinteger |  | server/type/1_sing-box.lua:203 |
| `hysteria2_ignore_client_bandwidth` | Flag | `0` |  |  | server/type/1_sing-box.lua:209 |
| `hysteria2_up_mbps` | Value |  |  |  | server/type/1_sing-box.lua:213 |
| `hysteria2_down_mbps` | Value |  |  |  | server/type/1_sing-box.lua:216 |
| `d_protocol` | ListValue |  |  |  | server/type/1_sing-box.lua:220 |
| `d_address` | Value |  |  |  | server/type/1_sing-box.lua:226 |
| `d_port` | Value |  | port |  | server/type/1_sing-box.lua:229 |
| `decryption` | Value | `"none"` |  |  | server/type/1_sing-box.lua:233 |
| `ss_method` | ListValue |  |  |  | server/type/1_sing-box.lua:237 |
| `ss_password` | Value |  |  |  | server/type/1_sing-box.lua:241 |
| `flow` | ListValue | `""` |  |  | server/type/1_sing-box.lua:244 |
| `masque_path` | Value |  |  |  | server/type/1_sing-box.lua:255 |
| `masque_address` | DynamicList |  |  | false | server/type/1_sing-box.lua:258 |
| `masque_mtu` | Value | `"1280"` | uinteger |  | server/type/1_sing-box.lua:262 |
| `tls` | Flag | `0` |  |  | server/type/1_sing-box.lua:268 |
| `reality` | Flag | `0` |  |  | server/type/1_sing-box.lua:300 |
| `reality_private_key` | Value |  |  |  | server/type/1_sing-box.lua:308 |
| `reality_shortId` | Value |  |  |  | server/type/1_sing-box.lua:311 |
| `reality_handshake_server` | Value | `"google.com"` |  |  | server/type/1_sing-box.lua:314 |
| `reality_handshake_server_port` | Value | `"443"` | port |  | server/type/1_sing-box.lua:318 |
| `alpn` | ListValue | `"default"` |  |  | server/type/1_sing-box.lua:324 |
| `tls_use_pem` | Flag |  |  |  | server/type/1_sing-box.lua:338 |
| `tls_certificateFile` | FileUpload | `m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. s.section .. ".crt"` |  |  | server/type/1_sing-box.lua:346 |
| `tls_keyFile` | FileUpload | `m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. s.section .. ".key"` |  |  | server/type/1_sing-box.lua:366 |
| `tls_certificate` | TextValue | `""` |  |  | server/type/1_sing-box.lua:386 |
| `tls_key` | TextValue | `""` |  |  | server/type/1_sing-box.lua:399 |
| `ech` | Flag | `"0"` |  |  | server/type/1_sing-box.lua:412 |
| `ech_key` | TextValue | `""` |  |  | server/type/1_sing-box.lua:421 |
| `transport` | ListValue |  |  |  | server/type/1_sing-box.lua:434 |
| `http_host` | DynamicList |  |  |  | server/type/1_sing-box.lua:448 |
| `http_path` | Value |  |  |  | server/type/1_sing-box.lua:451 |
| `ws_host` | Value |  |  |  | server/type/1_sing-box.lua:456 |
| `ws_path` | Value |  |  |  | server/type/1_sing-box.lua:459 |
| `httpupgrade_host` | Value |  |  |  | server/type/1_sing-box.lua:464 |
| `httpupgrade_path` | Value |  |  |  | server/type/1_sing-box.lua:467 |
| `grpc_serviceName` | Value |  |  |  | server/type/1_sing-box.lua:471 |
| `mux` | Flag |  |  | false | server/type/1_sing-box.lua:475 |
| `tcpbrutal` | Flag | `0` |  |  | server/type/1_sing-box.lua:483 |
| `tcpbrutal_up_mbps` | Value | `"10"` |  |  | server/type/1_sing-box.lua:487 |
| `tcpbrutal_down_mbps` | Value | `"50"` |  |  | server/type/1_sing-box.lua:491 |
| `wireguard_system_interface` | Flag | `0` |  |  | server/type/1_sing-box.lua:500 |
| `wireguard_mtu` | Value | `"1408"` |  |  | server/type/1_sing-box.lua:504 |
| `wireguard_local_address` | DynamicList |  |  |  | server/type/1_sing-box.lua:508 |
| `wireguard_private_key` | Value |  | base64 |  | server/type/1_sing-box.lua:511 |
| `wireguard_public_key` | Value |  | base64 |  | server/type/1_sing-box.lua:515 |
| `snell_version` | ListValue |  |  |  | server/type/1_sing-box.lua:529 |
| `snell_psk` | Value |  |  | false | server/type/1_sing-box.lua:534 |
| `snell_obfs_mode` | ListValue |  |  |  | server/type/1_sing-box.lua:538 |
| `snell_mode` | ListValue |  |  |  | server/type/1_sing-box.lua:543 |
| `firewall_allow` | Flag | `"0"` |  |  | server/type/1_sing-box.lua:550 |
| `firewall_allow_src` | Value | `"wan"` |  | not | server/type/1_sing-box.lua:554 |
| `accept_lan` | Flag | `"0"` |  |  | server/type/1_sing-box.lua:562 |
| `outbound_node` | ListValue |  |  |  | server/type/1_sing-box.lua:577 |
| `outbound_node_address` | Value |  |  |  | server/type/1_sing-box.lua:590 |
| `outbound_node_port` | Value |  | port |  | server/type/1_sing-box.lua:594 |
| `outbound_node_username` | Value |  |  |  | server/type/1_sing-box.lua:599 |
| `outbound_node_password` | Value |  |  |  | server/type/1_sing-box.lua:603 |
| `outbound_node_iface` | Value |  |  |  | server/type/1_sing-box.lua:608 |
| `log` | Flag | `"1"` |  | false | server/type/1_sing-box.lua:615 |
| `loglevel` | ListValue | `"info"` |  |  | server/type/1_sing-box.lua:619 |
| `custom` | Flag |  |  |  | server/type/2_xray.lua:36 |
| `custom_config` | TextValue |  | json |  | server/type/2_xray.lua:38 |
| `protocol` | ListValue |  |  |  | server/type/2_xray.lua:59 |
| `port` | Value |  | port |  | server/type/2_xray.lua:72 |
| `users` | MultiValue |  |  |  | server/type/2_xray.lua:76 |
| `d_protocol` | ListValue |  |  |  | server/type/2_xray.lua:91 |
| `d_address` | Value |  |  |  | server/type/2_xray.lua:97 |
| `d_port` | Value |  | port |  | server/type/2_xray.lua:100 |
| `decryption` | Value | `"none"` |  |  | server/type/2_xray.lua:104 |
| `ss_method` | ListValue |  |  |  | server/type/2_xray.lua:113 |
| `ss_password` | Value |  |  |  | server/type/2_xray.lua:117 |
| `ss_network` | ListValue | `"tcp,udp"` |  |  | server/type/2_xray.lua:120 |
| `udp_forward` | Flag | `"1"` |  | false | server/type/2_xray.lua:127 |
| `flow` | ListValue | `""` |  |  | server/type/2_xray.lua:132 |
| `hysteria2_realms` | Flag | `"0"` |  |  | server/type/2_xray.lua:139 |
| `hysteria2_realm_url` | Value |  |  |  | server/type/2_xray.lua:143 |
| `hysteria2_realm_stun` | DynamicList | `{ "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }` |  |  | server/type/2_xray.lua:152 |
| `hysteria2_realm_upnp` | Flag | `"0"` |  |  | server/type/2_xray.lua:156 |
| `hysteria2_obfs_type` | ListValue |  |  |  | server/type/2_xray.lua:160 |
| `hysteria2_obfs_password` | Value |  |  |  | server/type/2_xray.lua:166 |
| `hysteria2_obfs_MinPacketSize` | Value | `"512"` | uinteger |  | server/type/2_xray.lua:170 |
| `hysteria2_obfs_MaxPacketSize` | Value | `"1200"` | uinteger |  | server/type/2_xray.lua:176 |
| `hysteria2_ignore_client_bandwidth` | Flag | `0` |  |  | server/type/2_xray.lua:182 |
| `hysteria2_up_mbps` | Value |  |  |  | server/type/2_xray.lua:186 |
| `hysteria2_down_mbps` | Value |  |  |  | server/type/2_xray.lua:189 |
| `masque_path` | Value |  |  |  | server/type/2_xray.lua:193 |
| `masque_address` | DynamicList |  |  | false | server/type/2_xray.lua:196 |
| `masque_mtu` | Value | `"1280"` | uinteger |  | server/type/2_xray.lua:200 |
| `tls` | Flag | `0` |  |  | server/type/2_xray.lua:206 |
| `reality` | Flag | `0` |  |  | server/type/2_xray.lua:237 |
| `reality_private_key` | Value |  |  |  | server/type/2_xray.lua:245 |
| `reality_shortId` | DynamicList |  |  |  | server/type/2_xray.lua:248 |
| `reality_dest` | Value | `"google.com:443"` |  |  | server/type/2_xray.lua:251 |
| `reality_serverNames` | DynamicList |  |  |  | server/type/2_xray.lua:255 |
| `alpn` | ListValue | `"default"` |  |  | server/type/2_xray.lua:258 |
| `use_mldsa65Seed` | Flag | `"0"` |  |  | server/type/2_xray.lua:269 |
| `reality_mldsa65Seed` | TextValue | `""` |  |  | server/type/2_xray.lua:273 |
| `tls_use_pem` | Flag |  |  |  | server/type/2_xray.lua:289 |
| `tls_certificateFile` | FileUpload | `m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. s.section .. ".crt"` |  |  | server/type/2_xray.lua:294 |
| `tls_keyFile` | FileUpload | `m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. s.section .. ".key"` |  |  | server/type/2_xray.lua:311 |
| `tls_certificate` | TextValue | `""` |  |  | server/type/2_xray.lua:328 |
| `tls_key` | TextValue | `""` |  |  | server/type/2_xray.lua:341 |
| `ech` | Flag | `"0"` |  |  | server/type/2_xray.lua:354 |
| `ech_key` | TextValue | `""` |  |  | server/type/2_xray.lua:359 |
| `transport` | ListValue |  |  |  | server/type/2_xray.lua:368 |
| `ws_host` | Value |  |  |  | server/type/2_xray.lua:382 |
| `ws_path` | Value |  |  |  | server/type/2_xray.lua:385 |
| `httpupgrade_host` | Value |  |  |  | server/type/2_xray.lua:389 |
| `httpupgrade_path` | Value |  |  |  | server/type/2_xray.lua:392 |
| `xhttp_host` | Value |  |  |  | server/type/2_xray.lua:397 |
| `xhttp_path` | Value |  |  |  | server/type/2_xray.lua:400 |
| `xhttp_maxuploadsize` | Value | `"1000000"` |  |  | server/type/2_xray.lua:404 |
| `xhttp_maxconcurrentuploads` | Value | `"10"` |  |  | server/type/2_xray.lua:408 |
| `splithttp_maxuploadsize` | Value | `"1000000"` |  |  | server/type/2_xray.lua:412 |
| `splithttp_maxconcurrentuploads` | Value | `"10"` |  |  | server/type/2_xray.lua:416 |
| `tcp_guise` | ListValue |  |  |  | server/type/2_xray.lua:422 |
| `tcp_guise_http_host` | DynamicList |  |  |  | server/type/2_xray.lua:427 |
| `tcp_guise_http_path` | DynamicList |  |  |  | server/type/2_xray.lua:430 |
| `mkcp_guise` | ListValue |  |  |  | server/type/2_xray.lua:435 |
| `mkcp_domain` | Value |  |  |  | server/type/2_xray.lua:439 |
| `mkcp_mtu` | Value | `1350` | uinteger |  | server/type/2_xray.lua:442 |
| `mkcp_seed` | Value |  |  |  | server/type/2_xray.lua:447 |
| `grpc_serviceName` | Value |  |  |  | server/type/2_xray.lua:451 |
| `use_finalmask` | Flag | `"0"` |  |  | server/type/2_xray.lua:455 |
| `finalmask` | TextValue |  | json |  | server/type/2_xray.lua:463 |
| `acceptProxyProtocol` | Flag | `"0"` |  |  | server/type/2_xray.lua:479 |
| `tcp_fast_open` | Flag | `"0"` |  |  | server/type/2_xray.lua:485 |
| `fallback` | Flag |  |  |  | server/type/2_xray.lua:493 |
| `fallback_list` | DynamicList |  |  |  | server/type/2_xray.lua:512 |
| `wireguard_mtu` | Value | `"1420"` |  |  | server/type/2_xray.lua:522 |
| `wireguard_private_key` | Value |  | base64 |  | server/type/2_xray.lua:532 |
| `wireguard_public_key` | Value |  | base64 |  | server/type/2_xray.lua:536 |
| `firewall_allow` | Flag | `"0"` |  |  | server/type/2_xray.lua:544 |
| `firewall_allow_src` | Value | `"wan"` |  | not | server/type/2_xray.lua:548 |
| `accept_lan` | Flag | `"0"` |  |  | server/type/2_xray.lua:556 |
| `outbound_node` | ListValue |  |  |  | server/type/2_xray.lua:571 |
| `outbound_node_address` | Value |  |  |  | server/type/2_xray.lua:584 |
| `outbound_node_port` | Value |  | port |  | server/type/2_xray.lua:588 |
| `outbound_node_username` | Value |  |  |  | server/type/2_xray.lua:593 |
| `outbound_node_password` | Value |  |  |  | server/type/2_xray.lua:597 |
| `outbound_node_iface` | Value |  |  |  | server/type/2_xray.lua:602 |
| `log` | Flag | `"1"` |  | false | server/type/2_xray.lua:609 |
| `loglevel` | ListValue | `"warning"` |  |  | server/type/2_xray.lua:613 |
| `custom` | Flag |  |  |  | server/type/3_ss-rust.lua:31 |
| `custom_config` | TextValue |  | json |  | server/type/3_ss-rust.lua:33 |
| `port` | Value |  | port |  | server/type/3_ss-rust.lua:54 |
| `user` | ListValue |  |  |  | server/type/3_ss-rust.lua:58 |
| `method` | ListValue |  |  |  | server/type/3_ss-rust.lua:64 |
| `timeout` | Value | `300` | uinteger |  | server/type/3_ss-rust.lua:68 |
| `tcp_fast_open` | Flag | `"0"` |  |  | server/type/3_ss-rust.lua:73 |
| `firewall_allow` | Flag | `"0"` |  |  | server/type/3_ss-rust.lua:77 |
| `firewall_allow_src` | Value | `"wan"` |  | not | server/type/3_ss-rust.lua:81 |
| `log` | Flag | `"1"` |  | false | server/type/3_ss-rust.lua:89 |
| `custom` | Flag |  |  |  | server/type/4_ssr.lua:44 |
| `custom_config` | TextValue |  | json |  | server/type/4_ssr.lua:46 |
| `port` | Value |  | port |  | server/type/4_ssr.lua:67 |
| `user` | ListValue |  |  |  | server/type/4_ssr.lua:71 |
| `method` | ListValue |  |  |  | server/type/4_ssr.lua:77 |
| `protocol` | ListValue |  |  |  | server/type/4_ssr.lua:81 |
| `protocol_param` | Value |  |  |  | server/type/4_ssr.lua:85 |
| `obfs` | ListValue |  |  |  | server/type/4_ssr.lua:88 |
| `obfs_param` | Value |  |  |  | server/type/4_ssr.lua:92 |
| `timeout` | Value | `300` | uinteger |  | server/type/4_ssr.lua:95 |
| `tcp_fast_open` | Flag | `"0"` |  |  | server/type/4_ssr.lua:100 |
| `udp_forward` | Flag | `"1"` |  | false | server/type/4_ssr.lua:104 |
| `firewall_allow` | Flag | `"0"` |  |  | server/type/4_ssr.lua:108 |
| `firewall_allow_src` | Value | `"wan"` |  | not | server/type/4_ssr.lua:112 |
| `log` | Flag | `"1"` |  | false | server/type/4_ssr.lua:120 |

Not stored (DummyValue/HideValue/Button pseudo-fields): `gen_wireguard_key`, `port`, `remarks`, `status`, `type`


#### `passwall2_server` / `user`

| option | widget | default | datatype | rmempty | src |
|---|---|---|---|---|---|
| `username` | Value |  | and(uciname,maxlength(24)) | false | server/user_config.lua:15 |
| `password` | Value |  |  | false | server/user_config.lua:32 |
| `uuid` | Value | `api.gen_uuid()` | uuid | false | server/user_config.lua:35 |
| `wireguard_public_key` | Value |  | base64 |  | server/user_config.lua:40 |
| `wireguard_private_key` | Value |  | base64 |  | server/user_config.lua:43 |
| `wireguard_pre_shared_key` | Value |  | base64 |  | server/user_config.lua:49 |
| `allowed_ips` | DynamicList |  |  |  | server/user_config.lua:52 |


Not stored (DummyValue/HideValue/Button pseudo-fields): `gen_wireguard_key`, `password`, `username`, `uuid`

### 3.1 Real storage of the shunt-rule table (`Table:shunt_rules` above)

The virtual table has one row per `shunt_rules` section `e` with `lower(e.group or "") == lower(node.shunt_group or "")` (UCI order), plus a final synthetic row `.default`. All values are stored **on the `_shunt` node section**:

| Row | Node option (`_node`) | default shown when unset | FakeDNS option (`_fakedns`) | Pre-proxy option (`_proxy_tag`) |
|---|---|---|---|---|
| rule `e` | `<e[".name"]>` (e.g. `CN`, `PrivateIP`) | `""` (= Close/not used) | `<e[".name"]>_fakedns` | `<e[".name"]>_proxy_tag` |
| `.default` | `default_node` | `_direct` | `default_fakedns` | `default_proxy_tag` |

* `_node` values: `""` Close (Not use), `_default` (use the default node), `_direct`, `_blackhole`, or any node id from `api.get_node_list()` except `shunt_list` (socks, normal, balancing and urltest nodes; grouped by node `group` or "default").
* `_proxy_tag` values: `""` (Close), or any node id (same candidate list).
* `_fakedns`: Flag `"1"` or deleted.
* Write guards (all three): skip the write/delete when the POST carries `node_save_before` ≠ this node id, or `load_shunt == "1"` (a reload triggered by changing the node select). When `verify_option` is given (global/ACL pages), write only if that select's posted value == this node id.
* `enable_geoview_ip` write side effect: if the stored value changes (old default treated as `"0"`), set `passwall2.@global[0].flush_set = "1"`. The next start flushes the preloaded GeoIP nft/ip sets (02).
* Option names equal shunt-rule section ids. Deleting or renaming a `shunt_rules` section leaves orphan options on `_shunt` nodes. Upstream never cleans them up. They are harmless, because generators iterate over `shunt_rules` and not over node options, and the rewrite should keep them.
* The default config ships `rulenode.PrivateIP = '_direct'` even though no `shunt_rules` section `PrivateIP` exists in that file. It is an orphan by design and is ignored at runtime.

---

## 4. Options that exist outside the CBI forms

### 4.1 Stored by scripts/controller and read at runtime (no widget)

| Section | Option | Writer | Reader / meaning |
|---|---|---|---|
| `global` | `auto_lang` | `api.set_default_cbi` on every page load when `luci.main.lang == auto` (08 §0) | i18n of backend logs (`i18n.lua`, 01 §17) |
| `global` | `flush_set` | `enable_geoview_ip` write (above); controller `flush_set` endpoint (07) | firewall start: flush sets, then delete (02) |
| `nodes` | `config_str` | server/client `custom_config` TextValue (base64 of JSON) | 09 §1.4. Only on `passwall2_server.server` with `custom=1` |
| `nodes` | `download_address` | `xhttp_extra.write` side effect (09) | nftables/iptables add it to the VPS direct set (02, `nftables.sh:753`) |
| `nodes` | `add_mode` | subscribe.lua / link import (source comment: `0` manual configuration, `1` import, `2` subscription; 06 §1.6/§1.10) | node list "subscription" badge, `subscribe_del_*`, `clear_all_nodes` scope (07) |
| `nodes` | `group` | subscribe (= subscription remark), node_config, `reassign_group` | grouping everywhere |
| `nodes` | `quic_guise`, `quic_key`, `quic_security` | subscribe.lua vmess/vless/trojan parsers when `type=quic` (06 §1.6) | **legacy**: no CBI field and no generator reads them. They only appear on share-link export (07 B.2.3/B.2.4). Keep them round-trippable and do not emit them into configs |
| `nodes` | `use_ipv6` | none in this tree (legacy configs only) | `utils.sh get_node_host_ip`: resolve the node address over IPv6 when `"1"` |
| `nodes` | `<shunt_id>`, `<shunt_id>_proxy_tag`, `<shunt_id>_fakedns`, `default_node`, `default_fakedns`, `default_proxy_tag` | shunt table (§3.1) | 03 §shunt, 04 §4.8, 02 (`default_node`) |
| `subscribe_list` | `rem_traffic`, `expired_date` (and the related info fields listed in 06 §1.13) | subscribe.lua `update_subscribe_info` | shown in the `_node_count` DummyValue (08) |
| `subscribe_list` / `socks` / `acl_rule` / `nodes` | node references (`preproxy_node`, `to_node`, `chain_proxy`, `fallback_node`, `balancing_node`, `urltest_node`, `autoswitch_backup_node`, `domain_resolver*`, `domain_strategy`, `outbound_iface`) | **re-pointed** by subscribe.lua after nodes are recreated (06 §1.3) | — |

### 4.2 Present in the default config but not declared with a literal option name

`global_app.{geoview_file,xray_file,sing_box_file}` and `global_rules.{geoip_update,geosite_update}` come from the dynamic loops in §3. `nodes.default_node` and `nodes.PrivateIP` come from §3.1.

### 4.3 Commented-out upstream options (must NOT be offered in the new UI or emitted)

| File:line (cbi/passwall2/) | Option | Notes |
|---|---|---|
| client/global.lua:392 | `socks.http_port` (inside the global socks table) | Commented out on the global page, but **still active** on `socks_config.lua:70`. Runtime uses it (app.sh `run_socks`, `http_port` 0 = off) |
| client/shunt_rules.lua:168 | `shunt_rules.sourcePort` | Generators also have the code commented out (04 §4.8). Ignore it |
| client/type/1_sing-box.lua:405 | `tuic_udp_over_stream` | Not read by util_sing-box |
| client/type/2_xray.lua:458, server/type/2_xray.lua:282 | `minversion` | Dead |
| server/type/2_xray.lua:497 | `fallback_alpn`, `fallback_path`, `fallback_dest`, `fallback_xver` | Replaced by `fallback_list` (`dest,path,xver` entries) |
| server/type/2_xray.lua:516/527 | `wireguard_system_interface`, `wireguard_local_address` (server) | Client-side `wireguard_local_address` IS active (util_xray.lua:427) |

If an existing config already contains these options, the rewrite must preserve them on load/save and ignore them otherwise (drop-in rule: never delete unknown options the user did not edit).

---

## 5. Third-party browser assets (`htdocs/luci-static/resources/view/passwall2/`)

| File | Identity | Used by | Rewrite note |
|---|---|---|---|
| `Sortable.min.js` | **SortableJS 1.15.7** (MIT, header `/*! Sortable 1.15.7 - MIT */`) | drag reorder: node list, shunt-rule list, `cbi/sortable.htm` tables, DynamicList chips | Reuse the same version, or provide equivalent drag ordering. Persisted order semantics are in 10 §4.6 |
| `qrcode.min.js` | davidshimjs **qrcodejs** (global `QRCode`, single-line minified, no version banner) | share-link QR popup (07 Part B, `link_share_man.htm`) | Any QR encoder will do. Options used upstream are in 07 |
| `cbi.js`, `func.js`, `node_list_sort.js` | project code | — | 10 §1, §4.9 |

---

## 6. i18n catalogs (`po/`)

| Catalog | msgid count | Untranslated (`msgstr ""`, incl. header) |
|---|---|---|
| fa | 873 | 5 |
| ru | 876 | 2 |
| zh-cn (`zh_Hans` symlink) | 871 | 2 |
| zh-tw (`zh_Hant` symlink) | 873 | 2 |

* There is no `templates/passwall2.pot` in the tree. Msgids are English source strings that are used verbatim in `translate()` / `translatef()` / `<%: %>` / JS `_()`. Several msgids are built dynamically (e.g. `translate(value .. " automatically mode")` → msgids `stop automatically mode`, `start automatically mode`, `restart automatically mode`, `stop Time`, …, and `translatef("%s App Path", name)`).
* Backend (non-LuCI) translation: `api.lua` selects the language when the module loads (`luci.main.lang`, then `@global[0].auto_lang` if that is `auto`, then the LuCI default; 05 "Language init"). Script log messages use `api.i18n.translate[f]` (subscribe.lua, rule_update.lua, …). Shell scripts call `lua i18n.lua "<msgid>" args…` (prints `translatef`). Together this means **log lines are localized**. A Rust backend that writes logs must either load the same `.lmo` (via `luci.i18n`-compatible lookup: hash of msgid, see LuCI `lmo` format) or accept English-only logs (this is a behaviour difference and must be documented).
* New JS frontend: keep **identical msgids** so that the existing four catalogs keep working through `luci.mk` po2lmo. Any new string adds msgids that need translations in all four catalogs.

---

## 7. Cross-spec semantic notes (not stated elsewhere)

1. **Shunt group matching differs between UI and runtime.**
   * CBI (`shunt_options.lua`) compares `lower(rule.group or "") == lower(node.shunt_group or "")`. This is case-insensitive, and nil equals `""`.
   * Generators (`util_xray.lua:1479`, `util_sing-box.lua:1698`) and `node_list.htm:13` compare `node.shunt_group == e.group` exactly. This is case-sensitive, and nil only equals nil.
   * The firewall scripts (`nftables.sh:218`, `iptables.sh:194`) compare shell strings, so empty and unset are equal and case matters.
   * In practice the stored values match exactly: `shunt_group` choices come from existing group names, the `shunt_rules.group` write normalises to an existing group's spelling (08), and `""` is never stored because rmempty is set. The rewrite should normalise once (exact match on the stored strings, unset ≡ `""`) and reproduce the UI filter the same way, so that every layer agrees.
2. **Hidden-field deletion is gated per node type.** Under CBI semantics, a field hidden by its dependencies is deleted on save. For per-type options this only happens when the posted `type` equals the option's type (09 §1.2). Switching a node from Xray to sing-box therefore leaves the Xray-only options in UCI. The runtime ignores them. The new frontend must not "clean up" these options, so that the UCI state stays identical to what users get today.
3. **Singleton sections and `@x[0]`.** Every backend path (shell `config_t_get <type> <opt>` → `uci -q get passwall2.@<type>[0].<opt>`) reads index 0 of the type. When several sections of a singleton type exist (for example after a manual edit), only the first is used.
4. **`Flag` default trap.** A Flag with `default="1"` and rmempty true that is unchecked is stored as `"0"`. A Flag that is checked and equals its default is **deleted**, and the runtime then falls back to its own default, which is the same value. Runtime defaults (`config_t_get x y <default>`) must therefore equal the CBI defaults. The index in §3 gives the CBI side, and 01 §18 / 02 §0 / 03 / 04 give the runtime defaults. Where the two differ, the runtime value wins for options that are absent.
5. **Restart trigger.** Saving through LuCI applies with `ucitrack` (`config passwall2` → `init passwall2`, which runs `/etc/init.d/passwall2 reload` = restart, 01 §12/§15). The JS frontend that uses `uci.apply()` triggers the same thing through rpcd/ucitrack. Endpoints that write UCI directly (`save_node_list_opt`, `set_node`, `reassign_group`, `add_node`, …) commit **without** restart unless 07 says otherwise.

---

## 8. Remaining weaknesses (open after this audit)

1. **Frontend widget internals** (`nodes_*_com.htm` ≈ 2,700 lines, `node_list.htm` 1,851, `node_list_sort.js` 775) are specified by behaviour (10 §3.3, §4), not function by function. This is enough for a JS rewrite. Pixel-level styling and theme-adaptive colour logic (`*_adaptiveStyle`, `*_getColorSchema`) are deliberately left out.
2. **Backend helpers described without their names** (behaviour present, name absent): `api.lua` `classify_sysfs`, `classify_uci`, `match_and_group`, `match_cond`, `split_and`, `split_or`, `version_part`, `uci_del_s`, `uci_foreach_s`; `helper_dnsmasq.lua` `check_dns`, `check_ipset`, `process_address`, `set_domain_dns`, `set_domain_ipset`; `lease2hosts.sh` `read_odhcpd_leases`, `read_static_host`, `reload_dnsmasq_pids`, `valid_name`; `subscribe.lua` `truncate_nodes`, `match_filter_keywords`, `is_ip_port`; `clash_subconverter.lua` `encode_*`; `rule_update.lua` `fetch_geoip`, `fetch_geosite`, `remove_tmp_geofile`. An engineer should check the relevant spec section against the source when porting these functions. `match_and_group`/`match_cond`/`split_and`/`split_or` (the node-group matching expression language used by `node_match_rule` and the balancer/urltest `node_add_mode`) are the riskiest.
3. **The §3 option index is mechanically extracted.** It shows the first `default`/`datatype`/`rmempty` after each declaration. Conditional defaults set inside `if` blocks (for example defaults that depend on `has_singbox`/`has_xray`), and defaults assigned later through `s.fields[...]`, are not reflected. Specs 08/09 are authoritative.
4. **Runtime default vs CBI default reconciliation** (§7.4) has not been tabulated option by option. A per-option "absent ⇒ value" table across app.sh, the firewall scripts and the generators would remove ambiguity.
5. **Lua-only LuCI behaviours** that the JS frontend must re-create are spread across 08 §0, 09 §1 and 10 §3, with no single checklist: HideValue-as-boolean dependencies, `!reverse` dependencies, `node_save_before`/`load_shunt` reload protocol, `is_js_luci` branches, and `apply_on_parse`.
6. **Localized backend logs** (§6) have no decided design for the Rust side.
7. **rpcd ACL for the new frontend** is undefined. The upstream ACL only grants `uci` read/write. The rewrite needs ubus/file/exec grants for its own RPC surface. This is a design item and not upstream behaviour.
8. **Version coupling.** All specs describe upstream 26.11.3-1 behaviour together with the Xray/sing-box JSON schemas that this release targets. Core version gates (`api.compare_versions` checks in 03/04) are listed per feature but not consolidated.
