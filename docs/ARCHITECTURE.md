# passwall2-rs — architecture & contracts

Drop-in replacement for `luci-app-passwall2` (upstream: Openwrt-Passwall/openwrt-passwall2).
Behavior specs of upstream, by subsystem: `docs/spec/01..11-*.md` (authoritative for behavior).

## Goals
* **Same UCI schema** (`/etc/config/passwall2`, `/etc/config/passwall2_server`) — an existing passwall2
  config keeps working unchanged after switching packages; all options/defaults identical.
* **Same features/behavior** as upstream (start/stop sequence, firewall, DNS, shunt, subscriptions,
  rule update, ACLs, SOCKS, HAProxy, server side, share links, backup/restore, logs, app/core update).
* **No Lua at runtime.** Backend = one Rust multicall binary `/usr/bin/passwall2`.
  Frontend = client-side LuCI JS views (no luci-compat / CBI Lua).
* **Modern UI** (cards, status dashboard, badges, responsive, dark-mode aware) but the same pages,
  same options, same workflow as upstream, so users feel at home.

## Package layout (installed files)
```
/usr/bin/passwall2                         Rust binary (all backend logic)
/usr/libexec/rpcd/luci.passwall2           sh: exec /usr/bin/passwall2 rpc "$@"   (rpcd exec plugin)
/etc/init.d/passwall2                      rc.common wrapper → passwall2 start|stop|boot (START=99 STOP=15)
/etc/init.d/passwall2_server               rc.common wrapper → passwall2 server start|stop
/etc/hotplug.d/iface/98-passwall2          → same logic as upstream (calls the binary)
/etc/hotplug.d/ntp/30-passwall2-resync
/etc/uci-defaults/luci-app-passwall2       (+ _server) first-install defaults, same as upstream
/usr/share/passwall2/                      0_default_config, 0_default_config_server(if any), direct_ip,
                                           domains_excluded, rules/*, and any other upstream data files
/usr/share/luci/menu.d/luci-app-passwall2.json
/usr/share/rpcd/acl.d/luci-app-passwall2.json
/usr/share/ucitrack/luci-app-passwall2.json
/www/luci-static/resources/view/passwall2/*.js      LuCI views (one per page)
/www/luci-static/resources/passwall2/*.js|css       shared frontend lib (pw.js, style css)
/usr/lib/lua/luci/i18n/passwall2.<lang>.lmo         translations (zh-cn, zh-tw, fa, ru) compiled from po/
```
Package name `luci-app-passwall2` is kept as a *provided* name: our package is
`luci-app-passwall2-rs` with `PROVIDES:=luci-app-passwall2` and `CONFLICTS:=luci-app-passwall2`.
The binary package is arch-specific (`passwall2-rs` core) — see `packaging/`.

## Repo layout
```
passwall2/            Rust crate (binary `passwall2`)
  src/main.rs         dispatcher (owner: lead)
  src/uci.rs          UCI read (native parser) / write (`uci batch`)   (lead)
  src/util.rs         utils.sh + generic helpers: paths, log, exec, cache var store, ports, ip, b64  (lead)
  src/api.rs          api.lua port (node helpers, versions, URL/curl, core detect, ...)
  src/xray.rs         util_xray.lua
  src/xray/compat.rs  Xray version gates: XrayCaps (detected once per run) + downgrade() of the finished
                      JSON to the legacy form (upstream 26.4.20) for cores older than 26.7.11
  src/migrate.rs      `passwall2 migrate`: 26.4-era UCI schema → current (non-destructive copies; runs from
                      uci-defaults, at service/server start, after subscriptions and restored backups)
  src/singbox.rs      util_sing-box.lua
  src/firewall/       nft.rs (nftables.sh), ipt.rs (iptables.sh), shared acl helpers (app_acl.lua) in mod.rs or acl.rs
  src/app.rs          app.sh start/stop/run_*, init boot logic, monitor.sh, tasks.sh, lease2hosts.sh, test.sh, cron
  src/dns.rs          helper_dnsmasq.lua + chinadns-ng / dnsmasq ipset helpers
  src/haproxy.rs      haproxy.lua + haproxy_check.sh
  src/socks_switch.rs socks_auto_switch.sh
  src/server.rs       server_app.lua
  src/subscribe/      mod.rs (subscribe.lua), links.rs (share link parsing), clash.rs (clash_subconverter.lua)
  src/rules.rs        rule_update.lua
  src/rpc.rs          rpcd plugin: all controller endpoints
luci-app-passwall2/   OpenWrt package (htdocs/, root/, po/, Makefile)
packaging/            build scripts producing .ipk/.apk for all arches
scripts/vm.sh         run a command on the build VM in a synced copy (cargo check/test/build)
```
Modules may add private submodules/files under their own path. **Only edit files you own.**
Shared helpers belong in `util.rs`/`api.rs`; if you need something there that's missing, implement
it privately in your module (don't edit others' files).

## Backend conventions
* Generators take `util::Args` (BTreeMap<String,String>) = exactly the jshn JSON fields upstream app.sh
  passes to the Lua generators (spec 01 §5 lists every field). They return `serde_json::Value`.
  CLI compatibility: `passwall2 xray gen_config '<json>'` prints the config (pretty, 1 tab or 2 spaces).
* UCI: `uci::Config::load("passwall2")`; sections by name or `@type[i]`; writes via `uci::Batch`.
  Env `PASSWALL2_UCI_DIR` points UCI at a test dir (used by unit tests).
* Never panic on bad config: log & skip. No `unwrap()` on user data.
* Upstream quirks/bugs listed in the specs: **keep behavior that users rely on**, fix obvious bugs
  (crashes, invalid rules) and add a `// upstream quirk:` comment where we deliberately differ.
* Logging via `util::log(level, msg)` to `/tmp/log/passwall2.log` with upstream's English messages.
* No async runtime. Use std threads where concurrency is needed. HTTP downloads use `curl`
  (dependency of the package, like upstream) via `api.rs` helpers.
* Unit tests (`#[cfg(test)]`) for parsers/generators; run with `scripts/vm.sh 'cargo test'`.
* Custom-JSON nodes (`protocol '_json'`, Xray or sing-box): option `custom_json` holds the outbound
  (base64 of the JSON text as the UI writes it, or plain JSON). `api::custom_outbound` picks the
  outbound (object / array / whole config → first proxy outbound); the generators' `gen_outbound`
  return it with passwall's tag, `_flag*` fields, chain dialer/detour, and for Xray
  `sockopt.mark 255` when unset. Invalid JSON is logged and becomes a blackhole/block outbound.
  `gen_node_json {node}` (rpc) renders a regular node's unsaved form values as outbound JSON
  for the editor's form → JSON switch.
* SOCKS-only mode (`@global[0].proxy_mode 'socks'`, default `tproxy`): `read_config_vars` clears
  `enabled_default_acl`/`enabled_acls` and `app_start` skips the firewall; `start_socks_mode` runs
  the main node through `run_socks` with flag/config `acl_default` on `node_socks_port`
  (`socks_mode_listen`, optional `socks_mode_http_port`), so status, current node and node log
  work unchanged.
* Status-card check targets: `@global_other[0]` list `connect_site` (`name|url`), written by the
  `save_connect_sites` rpc; unset = built-in Baidu/Google/GitHub.

## rpcd contract (`luci.passwall2` ubus object) — backend `rpc.rs` ⇄ frontend JS
* `passwall2 rpc list` prints `{ "<method>": { "<param>": "<example type>" , ...}, ... }`.
* `passwall2 rpc call <method>` reads JSON params on stdin, prints a JSON **object** on stdout.
* **Method names = upstream controller endpoint names** (spec 07 §A.3), params = same names as upstream
  HTTP params (strings unless noted), result = the same JSON upstream returns; if upstream returns a
  bare array/string/bool, wrap as `{"result": <value>}`. Text responses (logs) → `{"result": "<text>"}`.
  Component endpoints are generalized: `com_check {com}`, `com_update {com, url?, ...}`, `com_version {com}`
  with com ∈ geoview|xray|sing-box|passwall2 (`check_passwall2` → `com_check {com:"passwall2"}`).
* Long-running work (subscribe, rule update, app update) is started in the background exactly like upstream
  and progress is read via the log methods.
* File transfer (backup/restore): `create_backup` → `{"result": "<base64 tar.gz>", "filename": "..."}`;
  `restore_backup {chunk, chunk_index, total_chunks, file_name}` (same chunked protocol as upstream).
* JS calls: `rpc.declare({object:'luci.passwall2', method:'<m>', params:[...]})`, all declared once in
  `/www/luci-static/resources/passwall2/pw.js` (`pw.call('<m>', {...})` helper).
* ACL `/usr/share/rpcd/acl.d/luci-app-passwall2.json`: read+write access to `luci.passwall2` (all methods),
  uci `passwall2`, `passwall2_server`, file read on logs, and `file exec` not needed.

## Frontend conventions
* Menu (`menu.d`): same paths as upstream under `admin/services/passwall2/*` with same order/titles
  (spec 07 §A.2); hidden pages (node_config, shunt_rules, socks_config, acl_config, subscribe config,
  server_config, server_user_config) are reached through edit buttons (modal or `view` with sid in URL).
* Views use `form.Map('passwall2', ...)` for config forms (same option names, defaults, depends as specs 08/09),
  custom widgets for node pickers, status cards, node table, etc.
* Styling: one stylesheet `passwall2/pw.css` loaded by `pw.js`; must look good on the default bootstrap
  theme AND on argon/material; respects `prefers-color-scheme` / theme dark mode. Modern look: card
  sections, rounded corners, soft shadows, status pills, icons via inline SVG, responsive tables.
* All UI strings wrapped in `_('...')` using upstream's English msgids where the text is the same,
  so upstream translations (po/) apply. Translation domain: `passwall2`.
