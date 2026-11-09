# 07 — LuCI controller (`luasrc/controller/passwall2.lua`) and share-link import/export (`luasrc/view/passwall2/node_config/link_share_man.htm`)

Source: upstream `luci-app-passwall2` (Openwrt-Passwall org, 2026). This spec covers:

* Part A: every menu entry and HTTP endpoint the controller registers, with params, responses, UCI changes and shell commands.
* Part B: the share-link codec in the node-config page: export (`buildUrl`), QR code, import (`fromUrl`), with exact URL params and the form fields (UCI options) they map to.

Conventions:
* `C` = UCI config `passwall2` (client). `S` = UCI config `passwall2_server`.
* `appname` = `passwall2`.
* `TMP_PATH` = `/tmp/etc/passwall2`, `CACHE_PATH` = `/tmp/etc/passwall2_tmp`, `S_TMP_PATH` = `/tmp/etc/passwall2_server`.
* `api.url(a, b, ...)` = `build_url("admin/services/passwall2/a/b/...")`, skipping empty args. With LuCI's default prefix this is `/cgi-bin/luci/admin/services/passwall2/...`.
* Request params are read with `http.formvalue(name)`, so they can come from the GET query or the POST form body. None of the endpoints check the HTTP method, except `update_passwall2?task=install`, which calls `test_post_security()`.
* Every endpoint sits under the `luci-app-passwall2` ACL, which the root node declares in `acl_depends`. There is no other per-endpoint auth beyond the LuCI session.

---

## Part A — Controller

### A.1 Helper semantics the controller uses

| Helper | Behavior |
|---|---|
| `http_write_json(x)` | `Content-Type: application/json`, body = `json(x or {code=1})` (nil → `{"code":1}`) |
| `http_write_json_ok(d)` | `{"code":1,"data":d}` (`data` is left out when d is nil) |
| `http_write_json_error(d)` | `{"code":0,"data":d}` |
| `uci_get(sec[,opt])` | luci uci cursor get on config C. With no opt it returns the whole section table, including `.name`, `.type`, `.anonymous`, `.index`. List options are Lua arrays → JSON arrays. |
| `uci_set(sec,opt,val)` | Cursor set. A table value sets a list, and an empty table `{}` deletes or clears the list. |
| `uci_del(sec[,opt])` | Deletes the option, or the whole section when opt is nil |
| `uci_save(commit, apply)` → `api.uci_save(cursor, C, commit, apply)` | **Old UCI** (detected by `grep -E 'require[ \t]*"uci"' /usr/lib/lua/luci/model/uci.lua`): `cursor:save(C)`. If commit: `cursor:commit(C)`, and if apply also `/etc/init.d/passwall2 reload > /dev/null 2>&1 &`. **New UCI (ucode-based luci)**: commit is always forced. If apply, `cursor:commit(C)` (this triggers apply/reload through rpcd). Otherwise `uci -q commit passwall2`. **So with modern LuCI, every `uci_save()` commits.** |
| `api.uci_set_s` / `api.uci_save_s` | Same helpers, applied to config S |
| `sh_uci_get(cfg,sec,opt)` | Shell `uci -q get cfg.sec.opt` (trimmed stdout) |
| `sh_uci_set(cfg,sec,opt,val,commit)` | Shell `uci -q set cfg.sec.opt="val"`, then `uci -q commit cfg` if commit |
| `sh_uci_del(cfg,sec,opt,commit)` | Shell `uci -q delete cfg.sec.opt` (+ commit). Called with opt=nil, the string becomes `cfg.sec.nil`; see reassign_group. |
| `sh_uci_commit(cfg)` | `uci -q commit cfg` |
| `api.gen_random_char(n=8)` | `head /dev/urandom \| tr -dc A-Za-z0-9 \| head -c 8`, used as the new section name |
| `api.get_cache_var(key)` | `. /usr/share/passwall2/utils.sh ; echo -n $(get_cache_var "key")`; "" → nil |
| `api.finded_com(name)` | Resolves the binary path of component `name` (custom path from `@global_app[0].<name>_file`, or the default), then `type -t -p`. Returns the path or nil. |
| `api.is_finded(name)` | `type -t -p "/bin/x" -p "/usr/bin/x" "x"`, true when non-empty |
| `api.get_valid_nodes()` | Node list. Each element has `.id`, `remark` (display string) and `node_type` (`"special"` for protocol `_balancing`/`_shunt`/`_iface`/`_urltest`, otherwise `"normal"`). Default-group nodes come first. |
| `api.get_random_normal_node(exclude_ids)` | Picks a random normal valid node whose `.name` is not in the exclude list, or nil |
| `api.get_ipv6_full(addr)` | When the address is IPv6, returns it bracketed (`[..]`), otherwise "" |
| `api.get_ipv6_only(addr)` | Strips the brackets and returns the address if it is an IPv6 address, otherwise "" |

### A.2 `index()` — bootstrap and menu

Bootstrap: if `/etc/config/passwall2` does not exist:
* if `/usr/share/passwall2/0_default_config` exists → `cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2`
* otherwise → return without registering any menu.

Menu and page nodes (all under `admin/services/passwall2`):

| Path | Target | Title | Order | Flags / condition |
|---|---|---|---|---|
| `passwall2` | alias → `settings` | `PassWall 2` (title is nil, i.e. hidden, when `@global[0].hide_from_luci == "1"`) | 0 | dependent, acl_depends `luci-app-passwall2` |
| `show` | call show_menu | – | – | leaf |
| `hide` | call hide_menu | – | – | leaf |
| `settings` | cbi `passwall2/client/global` | Basic Settings | 1 | dependent |
| `node_list` | cbi `client/node_list` | Node List | 2 | dependent |
| `node_subscribe` | cbi `client/node_subscribe` | Node Subscribe | 3 | dependent |
| `other` | cbi `client/other` | Other Settings | 92 | leaf |
| `haproxy` | cbi `client/haproxy` | Load Balancing | 93 | leaf; only if `/usr/sbin/haproxy` exists |
| `app_update` | cbi `client/app_update` | App Update | 95 | leaf |
| `rule` | cbi `client/rule` | Rule Manage | 96 | leaf |
| `geoview` | form `client/geoview` | Geo View | 97 | leaf; only if `finded_com("geoview")` |
| `acl` | cbi `client/acl` | Access control | 98 | leaf |
| `server` | cbi `server/index` | Server-Side | 99 | leaf |
| `log` | template `passwall2/log/log` | Runtime Logs | 999 | leaf |
| `node_subscribe_config` | cbi `client/node_subscribe_config` | (hidden) | – | leaf |
| `node_config` | cbi `client/node_config` | (hidden) | – | leaf; URL `node_config/<sid>` |
| `shunt_rules` | cbi `client/shunt_rules` | (hidden) | – | leaf |
| `socks_config` | cbi `client/socks_config` | (hidden) | – | leaf |
| `acl_config` | cbi `client/acl_config` | (hidden) | – | leaf |
| `server_config` | cbi `server/server_config` | (hidden) | – | leaf |
| `server_user_config` | cbi `server/user_config` | (hidden) | – | leaf |

Visible tab order: Basic Settings(1), Node List(2), Node Subscribe(3), Other Settings(92), Load Balancing(93), App Update(95), Rule Manage(96), Geo View(97), Access control(98), Server-Side(99), Runtime Logs(999).

API endpoints (all `call(...)`, leaf): `server_update_config, server_status, server_log, server_get_log, server_clear_log, link_add_node, socks_autoswitch_add_node, socks_autoswitch_remove_node, gen_client_config, get_now_use_node, get_redir_log, get_socks_log, get_log, clear_log, index_status, haproxy_status, socks_status, connect_status, ping_node, urltest_node, update_config, add_node, set_node, copy_node, clear_all_nodes, delete_select_nodes, reassign_group, get_node, save_node_list_opt, update_rules, rollback_rules, subscribe_del_node, subscribe_del_all, subscribe_manual, subscribe_manual_all, flush_set, get_shunt_rules, add_shunt_rule, delete_select_shunt_rules, create_backup, restore_backup, reset_config, geo_view, fetch_certsha256, gen_wireguard_key`.

Component endpoints:
* `check_passwall2` → app_check, `update_passwall2` → app_update
* For each `com` in `com.order = {"geoview","xray","sing-box"}`: `check_<com>` → com_check(com), `update_<com>` → com_update(com), `version_<com>` → com_version(com). Concretely: `check_geoview, update_geoview, version_geoview, check_xray, update_xray, version_xray, check_sing-box, update_sing-box, version_sing-box`.

### A.3 Endpoints (exact logic)

Notation: `P(x)` = formvalue x.

#### reset_config
1. `uci:revert(C)` (drops unsaved changes)
2. `echo '' > /tmp/log/passwall2.log`
3. `/etc/init.d/passwall2 stop`
4. `[ -f "/usr/share/passwall2/0_default_config" ] && cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2`
5. Redirect → `api.url()` (the main page)

#### show_menu
`uci -q delete passwall2.@global[0].hide_from_luci` + commit; `rm -rf /tmp/luci-*`; `/etc/init.d/rpcd restart >/dev/null`; redirect → `api.url()`.

#### hide_menu
`uci -q set passwall2.@global[0].hide_from_luci="1"` + commit; `rm -rf /tmp/luci-*`; `/etc/init.d/rpcd restart >/dev/null`; redirect → `admin/status/overview`.

#### link_add_node (chunked import of share links)
Params: `chunk` (string), `chunk_index` (int), `total_chunks` (int), `group` (default `"default"`).
```
if chunk && chunk_index && total_chunks:
   open /tmp/links.conf, mode "w" if chunk_index==0 else "a"; write chunk
   if chunk_index+1 == total_chunks:
       sh: lua /usr/share/passwall2/subscribe.lua add <group>      (group not quoted, runs synchronously)
```
Response: empty body (no content type). subscribe.lua reads `/tmp/links.conf`; see the subscribe spec.

#### socks_autoswitch_add_node
Params `id` (socks section), `key` (substring). If both are non-empty:
* `C.<id>.enable_autoswitch = "1"`
* list = `C.<id>.autoswitch_backup_node` (list or {}). Remove each entry whose node `remarks` contains `key` (plain substring).
* For each valid node with `node_type=="normal"` whose `remark` (display string) contains key → append its id.
* Set the list, then `uci_save()` (commit).
Redirect → `api.url("socks_config", id)`.

#### socks_autoswitch_remove_node
Same as above without the append step: sets enable_autoswitch=1 and removes the entries whose remarks contain key. Saves and redirects the same way.

#### gen_client_config
Param `id` (node). `config_file = /tmp/etc/passwall2/config_<id>`.
Runs: `/usr/share/passwall2/app.sh run_socks flag=config_<id> node=<id> bind=127.0.0.1 socks_port=1080 config_file=<config_file> no_run=1`
If the file exists → `Content-Type: application/json`, body = its content (`cat`), then `rm -f` it. Otherwise → redirect to `node_list`.
(The node page opens it via `window.open(url("gen_client_config")+"?id="+sid)`.)

#### get_now_use_node
`node = get_cache_var("ACL_acl_default_node")`. Response `{ "global": node }`, or `{}` when unset.

#### get_redir_log
Param `id`. File `/tmp/etc/passwall2/acl/<id>.log`. If it exists → `tail -n 5000 '<file>'` with `\n` replaced by `<br />` (text/html). Otherwise → `<script>alert('Not enabled log');window.close();</script>` (translated).

#### get_socks_log
Param `name`. File `/tmp/etc/passwall2/<name>.log`. Same as above (`tail -n 5000 <path>`, unquoted).

#### get_log
Body = `cat /tmp/log/passwall2.log` (empty if missing). Plain write, no content type set.

#### clear_log
`echo '' > /tmp/log/passwall2.log`. Empty response.

#### index_status
`{ "global_status": bool }`, true if `/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall2/bin/' | grep '/acl_default\.json'` exits 0. In other words, a process launched from `TMP_PATH/bin/` whose cmdline contains `/acl_default.json`.

#### haproxy_status
`{ "status": bool }`: `top -bn1 | grep -v grep | grep 'passwall2/bin/' | grep haproxy`.

#### socks_status
Params `index`, `id`. Response:
```
{ index: P(index),
  socks_status: top -bn1 | grep -v -E 'grep|acl/|acl_' | grep 'passwall2/bin/' | grep '<id>'  == 0,
  use_http: 0|1,                    // 1 if tonumber(C.<id>.http_port or 0) > 0
  http_status: bool (only if use_http=1): same pipe + | grep -E '\+http|_http' }
```

#### connect_status
Param `url`. Runs `curl --connect-timeout 3 -o /dev/null -I -sk -w "%{http_code}:%{time_appconnect}" <url>` (url unquoted).
`code` = the part before `:`. If code ≠ 0: `t` = the part after `:`. If t contains "." (seconds, e.g. `0.123`) → `use_time = sprintf("%.2f", t*1000)` (ms). Otherwise → `sprintf("%.2f", t/1000)`. Also sets `ping_type="curl"`.
Response `{ "use_time": "" | "123.00", "ping_type"?: "curl" }`.

#### ping_node
Params `index`, `address`, `port`, `type` (default `icmp`). Response `{ index, ping }`, where ping is a string of integer ms, or "".
* If `type=="tcping"` and `command -v tcping` is non-empty: for IPv6 the address is unbracketed (`get_ipv6_only`). Runs `tcping -q -c 1 -i 1 -t 2 -p <port> <address> 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}'`.
* Otherwise: `ping -c 1 -W 1 "<address>" 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}'` (address `%q`-quoted).

#### urltest_node
Params `index`, `id`. Runs `/usr/share/passwall2/test.sh url_test_node <id> urltest_node`. It expects output `code:time` and parses it like connect_status (no ping_type). Response `{ index, use_time }` (use_time is "" on failure).

#### update_config
Params `id` (node), `data` (JSON object). If the parsed object is non-empty: for each k,v → `uci_set(id,k,v)` (an array value sets a list). Then `uci_save()` → `{"code":1}`. Otherwise → `{"code":0}`.

#### add_node
Params `redirect`, `group`.
* `uid = gen_random_char()`; create section `nodes` named uid.
* If group is set and ≠ "default" → `group=<group>`.
* `type` = first match: `finded_com("sing-box")` → `sing-box`; `finded_com("xray")` → `Xray`; `is_finded("sslocal")` → `SS-Rust`; `is_finded("ssr-local")` → `SSR`. If none matches, type is unset.
* redirect=="1": `uci_save()`, redirect → `node_config/<uid>`. Otherwise: `uci_save(true,true)` → `{"result":"<uid>"}`.

#### set_node
Params `type`, `config`, `section` → `uci_set(type, config, section)`. In other words, it sets option `config` of section `type` to value `section`. (The parameter names are misleading: the semantics are section=P(type), option=P(config), value=P(section).) Then `uci_save(true,true)`, redirect → `log`.

#### copy_node
Param `section`. New uid, section type `nodes`. Copies every option except those whose names start with `.` and `group`. `remarks` gets `(1)` appended. Sets `add_mode=1`, `uci_save()`, redirect → `node_config/<uid>`.

#### clear_all_nodes
```
@global[0].enabled=0; @global[0].socks_enabled=0; @global_haproxy[0].balancing_enable=0; delete @global[0].node
for each socks section: delete section (then sets autoswitch_backup_node={} on the deleted name, a no-op)
for each haproxy_config: delete section
for each acl_rule: delete option node
for each nodes: delete section
for each subscribe_list: delete md5, chain_proxy, preproxy_node, to_node
uci_save(true,true)        // commit + apply/reload
```
Empty response.

#### delete_select_nodes
Params `ids` (comma-separated), `redirect`. For each id `w`, in order, with `ids_t` holding the ids processed so far, including w:
1. If `@global[0].node == w` → delete `@global[0].node`.
2. For each `socks`: remove w from the `autoswitch_backup_node` list (and set it if it changed). If `socks.node == w`: `new = get_random_normal_node(ids_t)`; if found, set `node=new[".name"]`, else `enabled=0`.
3. For each `haproxy_config` with `lbss == w` → delete the section.
4. For each `acl_rule` with `node == w` → delete option node.
5. For each `nodes` t:
   * `preproxy_node == w` → delete preproxy_node and chain_proxy
   * `to_node == w` → delete to_node and chain_proxy
   * list_name = `urltest_node` if present, else `balancing_node` if present. Remove w from that list and set it if it changed.
   * `fallback_node == w` → delete fallback_node
6. For each `subscribe_list`: same preproxy_node/to_node handling (deletes chain_proxy too).
7. If `C.<w>.add_mode == "2"` (subscribed node) and its group ≠ "": for each subscribe_list with `remark == group` → delete `md5` (forces the next subscription to refresh).
8. Delete section w.

redirect=="1" → `uci_save()` + redirect `node_list`. Otherwise `uci_save(true,true)`, empty body.
(Note: shunt-node per-rule options that point at w are NOT cleaned here.)

#### get_node
Param `id` optional. `show_node_info = @global_other[0].show_node_info or "0"`.
* With id: the section table (`.name`, `.type`, options...).
* Without id: an array of all `nodes` sections. Nodes with an empty or missing group come first, then the rest, each in config order.
* For each returned object, when show_node_info=="1" and `address` is IPv6: adds `ipv6:true`, `full_address:"[addr]"`.
JSON response.

#### reassign_group
Params `ids` (comma list), `group` (default "default"). For each id: if group ≠ "" and ≠ "default" → `uci -q set passwall2.<id>.group="<group>"`. Otherwise `sh_uci_del(C,id,"group")`, i.e. `uci -q delete passwall2.<id>.group`. Then `uci -q commit passwall2`. Response `{"status":"ok"}`.

#### save_node_list_opt
Params `option`, `value`. If option ≠ "": `uci -q set passwall2.@global_other[0].<option>="<value>"` + commit. Response `{"status":"ok"}`. (Used by the node list UI for display prefs such as `show_node_info`.)

#### update_rules
Param `update`. If empty → `{"code":0,"data":{"message":"missing update target"}}`. Otherwise runs `lua /usr/share/passwall2/rule_update.lua log '<update>' > /dev/null 2>&1 &` (background) → `{"code":1}`.

#### rollback_rules
Param `type` must be `geoip` or `geosite`, else `{"code":0}`.
`geo_dir = @global_rules[0].v2ray_location_asset or "/usr/share/v2ray/"`. Moves `/tmp/bak_v2ray/<type>.dat` → `<geo_dir><type>.dat` (plain concatenation, so the asset path must end in `/`). Then `rmdir /tmp/bak_v2ray/`, `@global[0].flush_set=1`, `uci_save(true)` → `{"code":1}`.

#### server_update_config
Like update_config, but on config `passwall2_server` (`uci_set_s`, `uci_save_s()`).

#### server_status
Params `index`, `id`. `{index, status}`, where status = `top -bn1 | grep -v 'grep' | grep 'passwall2_server/bin/' | grep -i '<id>'` == 0.

#### server_log
Param `id`. File `/tmp/etc/passwall2_server/<id>.log`. If it exists → full `cat` with `\n`→`<br />`. Otherwise → the alert script ("Not enabled log").

#### server_get_log / server_clear_log
`cat /tmp/log/passwall2_server.log` / `echo '' > /tmp/log/passwall2_server.log`.

#### app_check (`check_passwall2`)
`http_write_json(api.to_check_self())` (self-update check; see the api spec).

#### app_update (`update_passwall2`)
* `id` must match `^[A-Za-z0-9_-]+$`, else `{"code":1,"error":"Invalid download task."}`.
* `task=="progress"` → `api.to_download_progress("passwall2", id, P(total_size))`
* `task=="install"` → requires `luci.dispatcher.test_post_security()` (POST plus a valid token; on failure it returns with no body) → `api.to_install_self(id, P(force), P(languages))`
* otherwise (download): `part = tonumber(P(part)) or 1`, which must be an integer 1..5, else the invalid-task error. → `api.to_download("passwall2", P(url), P(size), id..part, part>1)`
* JSON result.

#### com_check(com) / com_update(com) / com_version(com)
* check: `api.to_check("", com)`
* update by `task`: `progress` → `to_download_progress(com, P(id), P(total_size))`; `extract` → `to_extract(com, P(file), P(subfix))`; `move` → `to_move(com, P(file))`; otherwise `to_download(com, P(url), P(size), P(id))`
* version: `{"code":1,"data": api.get_app_version(com)}`

#### create_backup
Files: `/etc/config/passwall2`, `/etc/config/passwall2_server`, `/usr/share/passwall2/domains_excluded`.
`date = os.date("%y%m%d%H%M")` (e.g. `2611091530`). `tar -czf /tmp/passwall2-<date>-backup.tar.gz <files...>`. Response headers: `Content-Disposition: attachment; filename=passwall2-<date>-backup.tar.gz`, `X-Backup-Filename: passwall2-<date>-backup.tar.gz`, `Content-Type: application/octet-stream`. Body = the file, which is then removed.

#### restore_backup (chunked, base64)
Params `filename`, `chunk` (base64), `chunk_index` (default -1), `total_chunks` (default -1). Everything runs in a pcall; an error gives `{status:"error", message:<err>}`.
* Missing filename → `{status:"error",message:"Missing filename"}`. Missing chunk → `"Missing chunk data"`. b64 decode fails → `"Base64 decode failed"`.
* Appends the decoded bytes to `/tmp/<filename>` (mode `a+`; chunk 0 does NOT truncate). Open failure → `"Failed to open file: /tmp/<filename>"`.
* If `chunk_index+1 == total_chunks`:
  * `uci:revert(C)`; `echo '' > /tmp/log/passwall2.log`; log " * PassWall2 Configuration file uploaded successfully…"
  * `mkdir -p /tmp/passwall2_bak`; `tar -xzf /tmp/<filename> -C /tmp/passwall2_bak`
  * On success: for each backup file, if `/tmp/passwall2_bak<file>` exists → `cp -f` it to `<file>`. Log "Configuration restored successfully…" and "Service restarting…". Then `/etc/init.d/passwall2 restart > /dev/null 2>&1 &` and `/etc/init.d/passwall2_server restart > /dev/null 2>&1 &`. Result `{status:"success",message:"Upload completed",path:"/tmp/<filename>"}`.
  * On failure: log "Configuration file decompression failed, please try again!". Result `{status:"error",message:"Decompression failed"}`.
  * `rm -rf /tmp/passwall2_bak`; remove `/tmp/<filename>`.
* Otherwise → `{status:"success",message:"Chunk received"}`.
(`api.log(0, msg)` writes to /tmp/log/passwall2.log with a timestamp; see the api spec.)

#### geo_view
Params `action` (`lookup`|`extract`), `value`. Response is always `text/plain`.
* Empty value → "Please enter query content!".
* `geo_dir` = `(@global_rules[0].v2ray_location_asset or "/usr/share/v2ray/")` up to its last `/` (trailing slash stripped). `geosite=<dir>/geosite.dat`, `geoip=<dir>/geoip.dat`. `bin = finded_com("geoview")`.
* **lookup**: if value is IPv4/IPv6 → type geoip, otherwise geosite. Runs `"<bin>" -type "<type>" -action lookup -input "<file>" -value "<value>" -lowmem=true` and lowercases the output. If the output is non-empty:
  * Each output line L → `"<type>:L"`. Also collects the shunt_rules that contain L (see get_rules) and the rules that contain the raw value, deduped by section id, each formatted as `[<group or "default">]<id>`.
  * Output = the lines joined with `\n`. If there are rules: + `\n--------------------\n` + "Rules containing this value:" + `\n` + the rules joined with `\n`.
  * `get_rules(str,type)`: for each `shunt_rules` section, list = `ip_list` (geoip) or `domain_list` (geosite). Splits it into lines, skipping empty lines and lines containing `#`. `main` = the text after the first `:` if there is one, else the whole line. For geoip with str an IP: match if `main` contains str (substring). Otherwise: `main == str`.
* **extract**: value must be `geoip:<list>` or `geosite:<list>` with list non-empty. Runs `"<bin>" -type "<type>" -action extract -input "<file>" -list "<list>" -lowmem=true`, output raw.
* Empty result → "No results were found!".

#### subscribe_del_node
Param `remark`. If non-empty: `lua /usr/share/passwall2/subscribe.lua truncate '<remark>' > /dev/null 2>&1` (shell-quoted). Returns HTTP 200 "OK".

#### subscribe_del_all
`lua /usr/share/passwall2/subscribe.lua truncate > /dev/null 2>&1`; returns 200.

#### subscribe_manual
Params `section`, `url`.
* Either empty → `{success:false,msg:"Missing section or URL, skip."}`.
* `uci -q get passwall2.<section>.url` empty → `{success:false,msg:"Please save and apply before manually subscribing."}`.
* If it differs from url → `uci -q set ...url="<url>"` + commit.
* `lua /usr/share/passwall2/subscribe.lua start <section> manual >/dev/null 2>&1 &` → `{success:true,msg:"Subscribe triggered."}`.

#### subscribe_manual_all
Params `sections`, `urls` (comma-separated and index-aligned). Either empty → the "Missing" error. If any section has an empty stored url → the "Please save and apply..." error, and nothing is changed. Then, for each i, if `urls[i]` ≠ "" and differs from the stored url → set + commit. Runs `lua /usr/share/passwall2/subscribe.lua start all manual >/dev/null 2>&1 &` → success. (Splitting on "," means a URL that contains a comma breaks the alignment.)

#### flush_set
Params `redirect` (default "0"), `reload` (default "0").
* reload=="1": `@global[0].flush_set=1` via the cursor, then `uci_save(true,true)` (commit + reload).
* Otherwise: `uci -q set passwall2.@global[0].flush_set="1"` + commit (no reload).
* redirect=="1" → redirect `log`. Otherwise empty body.

#### fetch_certsha256
Param `id`. address = `C.<id>.address`, port = `C.<id>.port` (0 if no id), sni = `C.<id>.tls_serverName`, falling back to the address. If address=="" or port==0 → `{"code":0}`. Note: when id is set but the node has no address or port, the value is nil, not "", and the later concatenation errors. Then runs:
`timeout 5 openssl s_client -connect <host>:<port> -servername <sni> -showcerts </dev/null 2>/dev/null | awk 'BEGIN{c=0}/BEGIN CERT/{c++} c==1{print} /END CERT/{if(c==1)exit}' | openssl x509 -outform der 2>/dev/null | sha256sum 2>/dev/null`
fp = the leading hex. If missing, or it starts with `e3b0c44298fc1c149afbf4c8996fb924` (the hash of empty input) → "". Otherwise uppercase.
Response `{code:1,data:"<HEX64>"}` or `{code:0}`.

#### get_shunt_rules
Like get_node, for `shunt_rules`: id → that section. Otherwise the array of all sections, ungrouped first.

#### add_shunt_rule
Params `add_name`, `redirect`, `group`. If add_name is given: uid = add_name, and if the section already exists → `{"code":0,"data":{"message":"This ID already exists."}}`. Otherwise uid = random(8). Creates a `shunt_rules` section uid, sets `group` if it is not "default"/empty, then `uci_save()`. redirect=="1" → redirect `shunt_rules/<uid>`. Otherwise `{"code":1,"data":{"uid":uid,"redirect_url":"<url shunt_rules/uid>"}}`.

#### delete_select_shunt_rules
Params `ids` (comma), `redirect`. For each id w: for each node with `protocol=="_shunt"` → delete option `w` on that node (shunt nodes store per-rule outbound in an option named after the rule id). Then delete section w. redirect=="1" → `uci_save()` + redirect `rule`. Otherwise `uci_save(true,true)`.

#### gen_wireguard_key
If `command -v wg` exists: priv=`wg genkey`, pub=`echo "<priv>" | wg pubkey`. Else, if xray exists: `<xray> wg | awk -F ': ' '{print $2}'`, where line 1 = private and line 2 = public. Response `{code:1,data:{private_key,public_key}}`, or `{code:0}` if neither tool exists.

### A.4 Files / paths summary
`/etc/config/passwall2`, `/usr/share/passwall2/0_default_config`, `/tmp/links.conf`, `/tmp/log/passwall2.log`, `/tmp/log/passwall2_server.log`, `/tmp/etc/passwall2/config_<id>`, `/tmp/etc/passwall2/acl/<id>.log`, `/tmp/etc/passwall2/<name>.log`, `/tmp/etc/passwall2_server/<id>.log`, `/tmp/bak_v2ray/{geoip,geosite}.dat`, `/tmp/passwall2-<yymmddHHMM>-backup.tar.gz`, `/tmp/<filename>` (restore), `/tmp/passwall2_bak/`, `/usr/share/passwall2/domains_excluded`, `/tmp/luci-*` (cache purge). Scripts: `/usr/share/passwall2/{app.sh,test.sh,subscribe.lua,rule_update.lua,utils.sh}`, `/etc/init.d/{passwall2,passwall2_server,rpcd}`.

### A.5 Security notes for the rewrite (do not reproduce the injection)
Many params are interpolated into shell commands unquoted: `group` (link_add_node), `url` (connect_status), `port`/`address` (tcping), `id` (gen_client_config, urltest, socks_status grep, server_status), `name` (get_socks_log path traversal), `update`, `section` (subscribe_manual), `filename` (restore → `/tmp/<filename>`, path traversal), and sh_uci_set values (double-quoted only). The Rust rewrite should keep the same param names and semantics but validate them (section ids `^[A-Za-z0-9_]+$`, ports numeric, etc.) and use argv exec instead of a shell.

---

## Part B — Share link import/export (`link_share_man.htm`)

### B.0 Context
* The node page `client/node_config.lua` renders this template as a DummyValue option named `passwall2`, with `value = <section id>`. So in the template `self.option = "passwall2"`, `self.value = sid`, `config = "passwall2"`.
* Form fields have the name/id `cbid.passwall2.<sid>.<option>`. Every `opt.get("X")` below therefore reads or writes UCI option `X` of node `<sid>` (prefixed options such as `xray_address` are the per-core form fields of the CBI model; the node_config CBI maps them to the real UCI option, e.g. `address`; see the node_config spec). The new JS frontend should map the same keys directly.
* Server-side values injected:
  * `has_singbox` / `has_xray` = `"<%=finded_com(...)%>"`: the binary path string when the binary is present. When it is absent, the Lua value is nil, and the rendered text depends on the LuCI template engine (empty, or `"nil"`). The JS treats them as truthy/falsy flags only. The intended meaning is "core installed", so the rewrite should emit real booleans.
  * `has_ss_rust` = `is_finded("sslocal")` is used only for the ss_type computation.
  * `ss_type = get_core("ss_type", [[sslocal?,"shadowsocks-rust"],[singbox?,"sing-box"],[xray?,"xray"]])`
  * `trojan_type = get_core("trojan_type", [[singbox,"sing-box"],[xray,"xray"]])`
  * `vmess_type = get_core("vmess_type", [[xray,"xray"],[singbox,"sing-box"]])`
  * `vless_type = get_core("vless_type", [[xray,"xray"],[singbox,"sing-box"]])`
  * `hysteria2_type = get_core("hysteria2_type", [[singbox,"sing-box"],[xray,"xray"]])`
  * `get_core(field, cands)`: v = `@global_subscribe[0].<field>`. If v is non-empty and some candidate with value v is available → v. Otherwise → the first available candidate's value, or nil.
  * `current_node.type` (the saved type).
* Toolbar: if the node protocol does not start with `_` (i.e. it is not a shunt/balancing/urltest/iface node), the buttons "From Share URL" (`tofromUrl`), "Build Share URL" (`exportUrl`) and "Generate QRCode" (`genQrcode`) are shown. "Export Config File" is always shown and opens `<url gen_client_config>?id=<sid>` in a new tab. A status span has id `passwall2-status`. A QR container `#qrcode_div` > `#qrcode` (150x150, uses `/luci-static/resources/view/passwall2/qrcode.min.js`, QRCode.js API `new QRCode(el,{width:150,height:150}).makeCode(url)`).

### B.1 Encoding helpers (exact)
* `b64EncodeUnicode(s)` = `btoa(UTF-8 bytes of s)` (standard alphabet, padded).
* `b64encutf8safe(s)` = b64EncodeUnicode, then `+`→`-`, `/`→`_`, trailing `=` stripped.
* `b64encsafe(s)` = `btoa(s)` (Latin-1 only; throws on chars > 0xFF), then URL-safe with no padding.
* `b64DecodeUnicode(s)` = atob → UTF-8 decode. On any exception it returns the input unchanged.
* `b64decutf8safe(s)`: `-`→`+`, `_`→`/`, pad with `=` to a multiple of 4, then b64DecodeUnicode. If the result equals the padded string (failure), it returns the original input.
* `b64decsafe(s)`: URL-safe → std, pad, atob (binary string, no UTF-8 decode). On exception it returns the original.
* `dictvalue(d,k)` = "" if missing or empty, else `b64decsafe(d[k])`.
* `parseNodeUrl(url)`: replaces the scheme with `https` and parses with `URL`. Returns `{hash, host, hostname, port, search, passwd: username || password}`. The URL keeps percent-encoding in username, and port is "" when it is 443, which is why callers default to "443". hostname of an IPv6 address keeps its brackets, so callers apply `unbracketIP`.
* `unbracketIP(s)` strips one leading `[` and one trailing `]`.
* Export IPv6: if the address matches the full IPv6 regex (incl. `fe80::%iface` and v4-mapped forms), it is written as `[addr]` in the authority.
* `opt.query(param, field, default)`: if the field is missing → "". Checkbox → `&param=1|0` (always emitted when the field exists). Otherwise → `encodeURIComponent(value)`; if that is empty → `&param=<default>` when a default is given, else "". Otherwise `&param=<enc>`. (No current caller passes a default.)

### B.2 Export: `buildUrl(btn, "passwall2", sid)`
`v_type = type`. `v_alias = remarks`. dom_prefix/protocol by type:

| type | dom_prefix | initial protocol |
|---|---|---|
| SS-Rust | `ssrust_` | ss |
| SSR | `ssr_` | ssr |
| Hysteria2 | `hysteria2_` | hysteria2 |
| Xray | `xray_` | (from `<p>protocol`) |
| sing-box | `singbox_` | (from `<p>protocol`) |

`_address` = `<p>address` (bracketed if IPv6). Final URL = `protocol.toLowerCase() + "://" + body`. If no branch matched: `alert("Not a supported scheme: <type>")` and return false. (Note: type `Hysteria2` alone matches no branch, so it is unsupported. Hysteria2 export only works via Xray/sing-box protocol `hysteria2`.)

`exportUrl` copies the URL to the clipboard (temporary textarea + `execCommand("copy")`) and sets the status to "Share URL to clipboard successfully." (green) or "...unable." (red).

#### B.2.1 Shadowsocks — SS-Rust, or Xray/sing-box with protocol `shadowsocks`
```
method = <p>method || <p>ss_method   (first existing field)
body  = b64encsafe(method + ":" + password) + "@" + addr + ":" + port + "/?"
params = ""
if <p>tcp_fast_open checked: params += "&tfo=1"
if field <p>plugin exists (SS-Rust):
   plugin = value; if plugin && plugin!="none":
      if plugin in (simple-obfs, obfs-local): plugin="obfs-local"
      if <p>plugin_opts non-empty: plugin += ";" + plugin_opts
      params += "&plugin=" + encodeURIComponent(plugin)
      if original plugin=="shadow-tls" && plugin_opts non-empty:
           params = "shadow-tls=" + genST(plugin_opts); shadow_tls=1     // REPLACES params
else if type in (sing-box, Xray):
   transport = <p>transport
   ws:     host=<p>ws_host, path=<p>ws_path; sing-box && <p>ws_enableEarlyData checked → params += "?ed=" + <p>ws_maxEarlyData   (literal, appended raw)
   http:   host=http_host, path=http_path
   raw|tcp: transport="tcp"; headerType=tcp_guise, host=tcp_guise_http_host, path=tcp_guise_http_path
   mkcp:   transport="kcp"; headerType=mkcp_guise, seed=mkcp_seed
   quic:   headerType=quic_guise, key=quic_key, quicSecurity=quic_security
   grpc:   path=grpc_serviceName, serviceName=grpc_serviceName, mode=grpc_mode
   xhttp:  host=xhttp_host, path=xhttp_path, mode=xhttp_mode; if use_xhttp_extra checked: extra=xhttp_extra
   params += "&type=" + transport
   if <p>tls checked:
       sec="tls"; if <p>fingerprint non-empty: "&fp=<fp>"
       if <p>reality checked: sec="reality"; pbk=reality_publicKey, sid=reality_shortId, spx=reality_spiderX, pqv=reality_mldsa65Verify
       "&security=<sec>"; alpn=alpn, sni=tls_serverName, allowinsecure=tls_allowInsecure (checkbox → 1/0), pcs=tls_pinSHA256, vcn=tls_CertByName, ech=ech_config
   if <p>uot checked: "&udp=1"
   if <p>use_finalmask checked: fm=finalmask
   if <p>shadowtls checked:
       s = ""; if shadowtls_version: s+="v<ver>=1;"; if shadowtls_password: s+="passwd=<pw>;"; if shadowtls_serverName: s+="host=<h>;"
       if shadowtls_utls checked && shadowtls_fingerprint: s+="fingerprint=<fp>"
       params = "shadow-tls=" + genST(s); shadow_tls=1             // REPLACES params
if shadow_tls: body = b64encsafe(method:password@addr:port) + "?"   (legacy whole-base64 form)
else: params += "&group="
params += "#" + encodeURIComponent(remarks); strip a leading "&"; body += params
```
`genST(str)`: splits on `;` and then `=`, keeping only pairs with exactly 2 parts (trimmed). Key `v<N>` with value "1" → `version:"N"`. Key `passwd` → `password`. Any other key k → `obj[k]=v`. Result = `b64encsafe(JSON.stringify(obj))`, e.g. `{"version":"3","password":"x","host":"y","fingerprint":"chrome"}` (key order follows the input order).

Examples:
* `ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp&group=#name`
* `ss://<b64(method:pw@host:port)>?shadow-tls=<b64json>#name`

#### B.2.2 SSR
```
ssr_str = addr:port:protocol:method:obfs:b64encsafe(password)
        + "/?obfsparam=" + b64encsafe(obfs_param) + "&protoparam=" + b64encsafe(protocol_param)
        + "&remarks=" + b64encutf8safe(remarks)
url = "ssr://" + b64encsafe(ssr_str)
```
Fields: `ssr_address, ssr_port, ssr_protocol, ssr_method, ssr_obfs, ssr_password, ssr_obfs_param, ssr_protocol_param`.

#### B.2.3 VMess (Xray/sing-box protocol `vmess`): `vmess://` + b64EncodeUnicode(JSON)
JSON object, with keys in insertion order:
```
v:"2", ps:remarks, add:<p>address (raw, NOT bracketed), port:<p>port, id:<p>uuid,
transport-specific:
  ws:   host=ws_host, path=ws_path (+ "?ed=<maxEarlyData>" if sing-box && ws_enableEarlyData)
  http: host=http_host, path=http_path
  raw|tcp: net "tcp"; type=tcp_guise; if type=="http": host=tcp_guise_http_host, path=tcp_guise_http_path
  mkcp: net "kcp"; type=mkcp_guise, seed=mkcp_seed
  quic: type=quic_guise, key=quic_key, securty=quic_security   (sic: "securty")
  grpc: path=grpc_serviceName
net: transport,
security: <p>security || "auto",  scy: same,
if tls checked: tls:"tls", sni:tls_serverName, alpn:<p>alpn (omitted if "default" or missing), fp:fingerprint, pcs:tls_pinSHA256, insecure:"1" (only if tls_allowInsecure checked)
tfo:"1" if tcp_fast_open checked
fm: encodeURI(finalmask) if use_finalmask checked
```
Undefined values (missing fields) are dropped by JSON.stringify. There is no `aid` field on export.

#### B.2.4 VLESS (Xray/sing-box protocol `vless`)
```
body = encodeURIComponent(uuid) + "@" + addr + ":" + port + "?"
transport params as SS (ws/http/raw|tcp→tcp/mkcp→kcp/quic/grpc/xhttp), plus:
  ws early data (sing-box): params += encodeURIComponent("?ed=" + n)   → "%3Fed%3D2048" glued onto path value
  httpupgrade: host=httpupgrade_host, path=httpupgrade_path
"&type=<transport>"
sing-box: "&encryption=none"; Xray: encryption=<p>encryption (query)
if tls checked: fp, reality(pbk,sid,spx,pqv), "&flow=<flow>" if <p>flow non-empty, "&security=<tls|reality>", alpn, sni, allowinsecure, pcs, vcn, ech(=ech_config)
"&tfo=1" if tcp_fast_open checked; fm if use_finalmask
"#" + encodeURI(remarks); strip leading "&"
```
Note: when tls is unchecked, NO `security` param is emitted.

#### B.2.5 Trojan (Xray/sing-box protocol `trojan`)
`body = encodeURIComponent(password) + "@" + addr + ":" + port + "/?"`. Transports as VLESS, minus xhttp and httpupgrade (ws early data appended raw as `?ed=`). `&type=...`. security defaults to "none"; if tls is checked: fp, reality(pbk,sid,spx,pqv), alpn, sni, allowinsecure, pcs, vcn, ech. `&security=<none|tls|reality>` is always emitted after the TLS block. Then tfo and fm, `#encodeURI(remarks)`.

#### B.2.6 Hysteria2 (Xray/sing-box protocol `hysteria2`)
```
params = sni=tls_serverName, insecure=tls_allowInsecure(1/0), pinSHA256=tls_pinSHA256, pcs=tls_pinSHA256, vcn=tls_CertByName
if hysteria2_obfs_type non-empty: obfs=hysteria2_obfs_type, obfs-password=hysteria2_obfs_password;
     if obfs_type=="gecko": minPacketSize=hysteria2_obfs_MinPacketSize, maxPacketSize=hysteria2_obfs_MaxPacketSize
mport=hysteria2_hop; fm=finalmask if use_finalmask
strip leading &
url = [encodeURIComponent(hysteria2_auth_password) + "@"] + addr + ":" + port + "?" + params + "#" + encodeURI(remarks)
```
The scheme is `hysteria2://`.

#### B.2.7 TUIC (sing-box only, protocol `tuic`)
`encodeURIComponent(uuid) + ":" + encodeURIComponent(password) + "@" + addr:port + "?"`, followed by sni=tls_serverName, disable_sni=tls_disable_sni(1/0), alpn=tuic_alpn, congestion_control=tuic_congestion_control, udp_relay_mode=tuic_udp_relay_mode, allowinsecure=tls_allowInsecure, pcs=tls_pinSHA256, `#encodeURI(remarks)`.

#### B.2.8 AnyTLS (sing-box only)
`encodeURIComponent(password)@addr:port?`. If tls is checked: fp, reality → pbk, sid (no spx/pqv), `&security=<sec>`, alpn, sni, insecure=tls_allowInsecure, pcs. Then `#encodeURI(remarks)`.

#### B.2.9 Naive (sing-box only, protocol `naive`)
scheme `naive+https`; `encodeURIComponent(username):encodeURIComponent(password)@addr:port?security=tls` + sni=tls_serverName, insecure-concurrency=naive_insecure_concurrency, ech=ech_config, uot=uot(1/0). If `naive_quic` is checked: scheme `naive+quic` + congestion_control=naive_congestion_control. Then `#encodeURI(remarks)`.

#### B.2.10 Snell (sing-box only)
`body = encodeURIComponent(snell_psk) + "@" + addr:port + "?"`. params: `psk=<enc psk>`, `&userkey=<enc password>` if password ≠ "", version=snell_version. If version=='4': obfs=snell_obfs_mode, obfs-host=snell_obfs_host. Otherwise mode=snell_mode. Then reuse=snell_reuse(1/0), `#encodeURI(remarks)`.

Protocols with no export: Socks, HTTP, WireGuard, SSH, Hysteria (v1), and type `Hysteria2` (standalone binary) → "Not a supported scheme".

### B.3 Import: `fromUrl(link, from_cache)`
Pre-processing:
1. Take the first line only.
2. Replace `&amp;` → `&` (case-insensitive), collapse whitespace around the first `#` to a bare `#`, then trim.
3. `link_type` = text before the first `://`; `link_split[1]` = text after it (split on `://`, element 1).
4. Clear the status span.

**Type switching:** `opt.set("type", v)`. If v ≠ `current_node.type` (the saved type) and no switch is pending, it records `switch_type = v` and does NOT set the field yet. Later sets apply to the current form, which may have hidden fields. At the end, if switch_type is set: `sessionStorage.fromUrl = JSON {timestamp: now, savetime: 60000, link}`, then the `type` field is set (which fires change). `footer.htm`'s type-change handler calls `update_config` (saving remarks, group, type, protocol='') and reloads. On reload, footer.htm re-runs `fromUrl(cached.link, true)` if the cache is less than 60 s old, otherwise it removes the cache. On the second run the type matches, so all fields are applied. The new frontend can skip this two-pass dance and set everything directly.

**opt.set semantics:** checkbox → `checked = val` (truthy). Otherwise → value (+ combobox, + LuCI dropdown `li[data-value]` selection and hidden input), then dispatches `change` (bubbles). If the field is not found: dynamic-list fallback, where it finds `.cbi-dynlist` whose label `for` equals `cbid.passwall2.<sid>.<opt>`, types the value into its text input and clicks add.

At the end: if dom_prefix is unset → "Invalid Share URL Format" (red), clear the cache, return false. Otherwise focus/blur `<p>port` (to trigger validation), show "Import Finished" (green), clear the cache, return true.

Common TLS-insecure rule (written `INSECURE(...)` below): `tls_allowInsecure = NOT (allowinsecure ?? '0') === '0' AND allowInsecure... === '0' AND insecure... === '0'`, i.e. true if any listed key is present with a value other than `'0'` (including an empty value).

Common transport mapping (`TRANSPORT(q, prefix)`), used by ss (query form), trojan and vless, with `type` = q.type lowercased:
* kcp → mkcp. h2 → http.
* singbox_: raw → tcp. xray_: tcp → raw.
* xray_ with http → transport field `xhttp`, otherwise transport=type.
* raw/tcp: `tcp_guise = headerType || "none"`. If headerType is set and ≠ none: `tcp_guise_http_host=host||""`, `tcp_guise_http_path=path||""`.
* ws: `ws_host=host||""`, `ws_path=path||""`. If singbox_ and path.length>1: split the path at `?`, parse its query (lowercased keys). If `ed` is present: `ws_path=<path before ?>`, `ws_enableEarlyData=true`, `ws_maxEarlyData=ed`, `ws_earlyDataHeaderName="Sec-WebSocket-Protocol"`.
* http: xray_ → `xhttp_mode="stream-one"`, `xhttp_host`, `xhttp_path`. Otherwise `http_host`, `http_path`.
* quic: `quic_guise=headerType||"none"`, `quic_security=quicSecurity`, `quic_key=key`.
* mkcp: `mkcp_guise=headerType||"none"`, `mkcp_seed=seed||""`.
* grpc: `grpc_serviceName = serviceName || path || ""`, `grpc_mode = mode || "gun"`.
* xhttp (also `splithttp` in vless only): `xhttp_host`, `xhttp_path`, `xhttp_mode=mode||"auto"`, `use_xhttp_extra=!!extra`, `xhttp_extra=extra||""`. (Only ss and vless handle xhttp; trojan does not.)
* httpupgrade (vless only): `httpupgrade_host`, `httpupgrade_path`.

Common TLS block `TLS(q)` (ss query form, vless; trojan/anytls variants noted below):
* security=="tls": `tls=true, reality=false, alpn=q.alpn||'default', tls_serverName=q.sni||''`, `tls_allowInsecure=INSECURE(allowinsecure, allowInsecure, insecure)`. If fp is non-blank: `utls=true, fingerprint=fp`. Also `ech=!!q.ech, ech_config=q.ech||'', tls_pinSHA256=q.pcs||'', tls_CertByName=q.vcn||''`.
* security=="reality": `tls=true, reality=true, alpn, tls_serverName=sni`, fp → utls/fingerprint, `reality_publicKey=pbk||'', reality_shortId=sid||'', reality_spiderX=spx||'', use_mldsa65Verify=!!pqv, reality_mldsa65Verify=pqv||''`.

Query parsing used by the trojan/vless/hy2/anytls/snell/tuic/naive branches: `search.replace('/?','?').split('?')[1].split('&')`, each split on `=` with only the first two parts kept (so a value containing `=` is truncated after the second part). Both key and value go through `decodeURIComponent`. anytls, snell and tuic lowercase the keys. ss uses `URLSearchParams` (proper `+`→space, full value).

#### B.3.1 `ssr://`
* `sstr = b64decsafe(rest without "#..." , trimmed)`. Split at the first `/?` (only if its index > 0): url0 / param.
* url0 regex `^(.+):([^:]+):([^:]*):([^:]+):([^:]*):([^:]+)` → host, port, protocol, method, obfs, b64pass. No match → Invalid.
* param (if length > 2): split `&`/`=`, both decodeURIComponent.
* Sets: `type=SSR`, prefix `ssr_`: `address=unbracket(host), port, protocol, method, obfs, password=b64decsafe(b64pass), obfs_param=dictvalue(obfsparam), protocol_param=dictvalue(protoparam)`. If remarks is non-empty → `remarks=b64decutf8safe(remarks)`.

#### B.3.2 `ss://`
```
rest = link_split[1]; fragment after first "#" → param (else ""), removed from rest
rest = rest.replace('/?','?'); query after first "?" → URLSearchParams → queryParam
if rest contains "@":                                   // SIP002
    userInfo = b64decsafe(decodeURIComponent(before @)); server,port = (after @).split(":")[0..1]   // IPv6 hosts break here
    if userInfo has ":": method = before first ":", password = after
    else: password = raw before-@ text (plain UUID passwords, e.g. ss2022 with no method), method undefined
else:                                                   // legacy base64(method:pass@host:port)
    sstr = b64decsafe(decodeURIComponent(rest))
    m2022 /^([^:]+):([^:]+):([^@]+)@([^:]+):(\d+)$/ → method, password = g2+":"+g3, server, port
    else mNormal /^([^:]+):([^@]+)@([^:]+):(\d+)$/ → method, password, server, port
if queryParam.plugin: parts = decodeURIComponent(plugin).split(";"); plugin = parts[0]; pluginOpts = rest joined by ";"
needUpgrade = ss_type!=="Xray" && ss_type!=="sing-box" && q.type && q.type!=="tcp" && q.headerType && q.headerType!=="none"
   (note: compares against "Xray" with a capital X, so for ss_type "xray" this is effectively "ss_type!=='sing-box'")
core choice:
  has_xray && (ss_type=="xray" || needUpgrade || q.type=="xhttp") → prefix xray_, type=Xray, xray_protocol=shadowsocks
  else has_singbox && (ss_type=="sing-box" || needUpgrade)        → prefix singbox_, type=sing-box, singbox_protocol=shadowsocks
  else ss_type=="shadowsocks-rust"                                  → prefix ssrust_, type=SS-Rust
  (otherwise dom_prefix stays null → sets go to "nulladdress" etc. (ignored) → Invalid at end)
method = lower(method||"none"); map chacha20-poly1305→chacha20-ietf-poly1305, xchacha20-poly1305→xchacha20-ietf-poly1305
set address=unbracket(server), port, password||"", method, ss_method (both set; whichever field exists), tcp_fast_open=q.tfo (truthy string)
if plugin && plugin!="none":
   simple-obfs → obfs-local
   plugin_enabled=true, plugin, plugin_opts=pluginOpts||""
   if plugin==obfs-local && prefix==xray_:          // convert to native xray
      obfs = /obfs=([^;]+)/, obfs_host = /obfs-host=([^;]+)/
      obfs=="http": transport=raw, tcp_guise=http, tcp_guise_http_host=obfs_host, tcp_guise_http_path="/"
      obfs=="tls":  tls=true, tls_serverName=obfs_host, tls_allowInsecure=true
   if plugin=="shadow-tls":                         // SIP003 shadow-tls
      pluginOpts: (^|;)password= → passwd= ; (^|;)version=([123]) → v$2=1
      ssrust_: plugin_opts = converted string
      singbox_: parse k=v; shadowtls=true, shadowtls_version = N of key v1|v2|v3 (default "1"), shadowtls_password=passwd, shadowtls_serverName=host, plugin_enabled=false
else: plugin="none"
remarks = decodeURIComponent(param)   // always set (param "" → remarks "")
if queryParam non-empty && no plugin:
   TLS(q) (only when q.security present)
   TRANSPORT(q)  — note: if q.type is absent, transport is set to undefined
   uot = q.udp; use_finalmask=!!q.fm; finalmask=q.fm||""
   if q["shadow-tls"]:
      obj = JSON.parse(b64decsafe(v)); back-string = "v<version>=1;passwd=<password>;k=v..."
      ssrust_: plugin_enabled=true, plugin="shadow-tls", plugin_opts=back-string
      singbox_: if obj non-empty: shadowtls=true, shadowtls_version=obj.version||"1", shadowtls_password=obj.password||"", shadowtls_serverName=obj.host||"";
                if obj.fingerprint: shadowtls_utls=true, shadowtls_fingerprint=obj.fingerprint
```

#### B.3.3 `trojan://`
* Core: `trojan_type=="sing-box" && has_singbox` → singbox_/sing-box, otherwise xray_/Xray. protocol=trojan.
* `m=parseNodeUrl(link)`. passwd=="" → Invalid.
* Sets: `mux = (q.mux==='1')`, `address=unbracket(hostname)`, `port=m.port||"443"`, `password=decodeURIComponent(passwd)`.
* type = lower(q.type) or "tcp". kcp/mkcp → mkcp; h2/http → http. Then the TRANSPORT rules (no xhttp/httpupgrade).
* security = q.security || "tls". tls: as TLS but `tls_serverName = q.peer || q.sni || ""`, and with ech/pcs/vcn/INSECURE. reality: tls, reality, alpn, sni (peer||sni), fp, pbk, sid (no spx/pqv). "none" → nothing.
* `tcp_fast_open=q.tfo`, `use_finalmask=!!q.fm`, `finalmask=q.fm||""`, remarks = decodeURIComponent(hash without '#') if there is a hash.

#### B.3.4 `vmess://`
* `sstr = b64DecodeUnicode(rest without #fragment, trimmed)`.
* Core: `vmess_type=="sing-box" && has_singbox` → singbox_/sing-box; else if has_xray → xray_/Xray. protocol=vmess.
* If `is_json(sstr)` (parses to a non-null object) → ssm = the JSON (standard v2rayN fields: v, ps, add, port, id, aid, scy, net, type, host, path, tls, sni, alpn, fp, pcs, insecure/allowInsecure, tfo, fm, seed, key, securty).
* Else if it contains `?` at index > 0 (Shadowrocket style `base64(security:uuid@host:port)?params`): `/?`→`?`. url0 = before `?`. paramStr = `sstr.substr(ploc+2)` (it skips one extra char after `?`, presumably for the `?&`-style legacy form). Parses `https://` + b64decsafe(url0): username non-empty → `security=username, id=password||username`, else `security=auto`. add=unbracket(hostname), port=port||"443". Params split on the first `=` and value-decoded: `ps=remark||remarks`, `net = obfs=="websocket" ? "ws" : (obfs||"tcp")`, `path`, `aid=alterId||"0"`, `tls`, `sni=peer`, `tfo`. obfsParam: if JSON → `type=header`, `host=Host`; else `host=obfsParam`. `allowinsecure=allowInsecure`.
* Else → Invalid.
* Sets: `remarks=ps`, `address=unbracket(add)`, `port`, `uuid=id`, `security = ssm.security || ssm.scy || "auto"`, `tls = (tls=="tls"||tls=="1")`. If tls: `tls_serverName = sni || host`, `alpn = alpn||"default"`, fp → utls+fingerprint, `tls_pinSHA256=pcs||""`, `tls_allowInsecure=INSECURE(allowinsecure, allowInsecure, insecure)`.
* net lowercased (throws if net is missing). kcp/mkcp→mkcp; singbox raw→tcp; xray tcp→raw; h2/http→http; xray http → transport xhttp.
* raw/tcp: `tcp_guise = host? "http":"none"` (based on the presence of host, not on `type`); if host: `tcp_guise_http_host=host`, `tcp_guise_http_path=path||""`. ws: ws_host, ws_path + sing-box ed parsing. http: as in TRANSPORT. quic: `quic_security=securty`, `quic_key=key` (no guise). mkcp: `mkcp_guise=type||"none"`, `mkcp_seed=seed||""`. grpc: `grpc_serviceName=path`.
* `tcp_fast_open=tfo`, `use_finalmask=!!fm`, `finalmask=fm||""`. (`aid` is not stored.)

#### B.3.5 `vless://`
* prefix = `vless_type=="sing-box" && has_singbox` ? singbox_ : xray_.
* parseNodeUrl; passwd=="" → Invalid. Query parsed (throws if `type` is absent: `queryParam.type.toLowerCase()`).
* If type ∈ {xhttp, kcp, mkcp} and vless_type ≠ "xray" and has_xray → force xray_.
* `type` = sing-box or Xray per prefix; `protocol=vless`; `uuid=passwd` (NOT decoded); `address=unbracket(hostname)`; `port=port||"443"`; `encryption=q.encryption||"none"`.
* If security is empty and flow is set → security="tls". TLS(q), with `flow=q.flow||''` set in both the tls and reality branches.
* TRANSPORT (incl. xhttp/splithttp, httpupgrade). `tcp_fast_open=q.tfo`, fm, remarks from hash.

#### B.3.6 `hysteria2://` and `hy2://`
* parseNodeUrl; passwd=="" → Invalid. Query parsed (keys case-sensitive).
* Only if `(hysteria2_type=="sing-box" && has_singbox) || (hysteria2_type=="xray" && has_xray)`: type sing-box/Xray, prefix singbox_/xray_, protocol=hysteria2, `hysteria2_auth_password=decodeURIComponent(passwd)`. If `obfs-password` or `obfs_password` is present: `hysteria2_obfs_type = q.obfs || "salamander"`, `hysteria2_obfs_password`. If `obfs=="gecko"`: `hysteria2_obfs_MinPacketSize = minPacketSize||"512"`, `hysteria2_obfs_MaxPacketSize = maxPacketSize||"1200"`. `hysteria2_hop = mport||""`, use_finalmask/finalmask.
* Then always (prefix may be null → Invalid at the end): `address`, `port=port||"443"`, `tls_serverName=sni||""`, `tls_allowInsecure=INSECURE(allowinsecure, allowInsecure, insecure)`, `tls_pinSHA256 = pcs || pinSHA256 || ''`, `tls_CertByName=vcn||''`, remarks from hash.

#### B.3.7 `tuic://`
* has_singbox → singbox_/sing-box (otherwise prefix null → Invalid). protocol=tuic.
* Parses `https://`+rest. If username or password is empty: decode `username||password`; if it contains `:` → split it into uuid/password (handles an encoded `%3A`).
* `uuid=decode(username)`, `password=decode(password)`, address, `port||"443"`. Query keys lowercased.
* `tuic_congestion_control = congestion_control||'cubic'`, `tuic_udp_relay_mode = udp_relay_mode||'native'`, `tuic_alpn = alpn||'h3'`, `tls_serverName = sni||''`, `tls_disable_sni = (disable_sni==="1")`, `tls_allowInsecure=INSECURE(allowinsecure, insecure, allow_insecure)`, `tls_pinSHA256 = pcs||pinsha256` (keys are lowercased, so the `pinSHA256` lookup never matches). Remarks from hash.

#### B.3.8 `anytls://`
* has_singbox → singbox_. protocol=anytls. parseNodeUrl; passwd=="" → Invalid. `password=passwd` (not decoded), address, port||443. Keys lowercased.
* security = q.security||"tls" (always truthy): `tls=true`; tls → reality=false; reality → reality=true, reality_publicKey, reality_shortId. `alpn||'default'`, `tls_serverName = sni||peer||''`, fp → utls/fingerprint, `tls_allowInsecure=INSECURE(allowinsecure, insecure)`, `tls_pinSHA256 = pcs||pinSHA256`. Remarks.

#### B.3.9 `naive+https://` and `naive+quic://`
* has_singbox → singbox_. protocol=naive. Parses `https://`+rest. If the userinfo (before the first `@`) has no `:`, the whole userinfo is the password and username="".
* `username`, `password` (decoded), address, port||443. Query keys are case-sensitive.
* `naive_insecure_concurrency = q['insecure-concurrency']||'0'`, `uot = (uot??'0')==='1'`, `tls_serverName=sni||''`, `ech=!!q.ech`, `ech_config=ech||''`. naive+quic: `naive_quic=true`, `naive_congestion_control = congestion_control||'bbr'`. Remarks.

#### B.3.10 `snell://`
* has_singbox → singbox_. protocol=snell. parseNodeUrl (no passwd check). address, port||443. Keys lowercased.
* `password = userkey||''`, `snell_psk = psk || passwd || ''`, `snell_version = version||'4'`, `snell_reuse = reuse==='1'`, `snell_obfs_mode = obfs||'none'`, `snell_obfs_host = q['obfs-host']||obfs_host||''`, `snell_mode = mode||'default'`. Remarks.

Unrecognised schemes (socks, http, wireguard, hysteria v1, ...) → dom_prefix null → "Invalid Share URL Format".

### B.4 Round-trip parameter table (export key → import key → field)

| URL param | Field (`<p>` = core prefix) | Notes |
|---|---|---|
| type | transport | export kcp/tcp/ws/http/quic/grpc/xhttp/httpupgrade; import kcp→mkcp, h2→http, tcp↔raw by core, http→xhttp on xray |
| host / path | ws_*, http_*, tcp_guise_http_*, xhttp_*, httpupgrade_* | |
| headerType | tcp_guise / mkcp_guise / quic_guise | default none |
| seed | mkcp_seed | |
| key, quicSecurity | quic_key, quic_security | |
| serviceName (+path), mode | grpc_serviceName, grpc_mode (default gun) | |
| mode, extra | xhttp_mode (default auto), xhttp_extra + use_xhttp_extra | |
| security | tls, reality | tls/reality/none |
| fp | fingerprint (+utls=true) | |
| pbk, sid, spx, pqv | reality_publicKey, reality_shortId, reality_spiderX, reality_mldsa65Verify (+use_mldsa65Verify) | |
| alpn | alpn (default 'default') | tuic: tuic_alpn (default h3) |
| sni (peer for trojan/anytls) | tls_serverName | |
| allowinsecure / allowInsecure / insecure | tls_allowInsecure | |
| pcs (pinSHA256) | tls_pinSHA256 | |
| vcn | tls_CertByName | |
| ech | ech_config (+ech) | |
| flow | flow | vless |
| encryption | encryption | vless (default none) |
| tfo | tcp_fast_open | |
| udp | uot | ss only |
| fm | finalmask (+use_finalmask) | |
| mux | mux | trojan import only |
| plugin | plugin, plugin_opts, plugin_enabled | ss |
| shadow-tls | shadowtls_* (sing-box) / plugin shadow-tls (ss-rust) | b64 JSON {version,password,host,fingerprint} |
| obfs, obfs-password, minPacketSize, maxPacketSize, mport | hysteria2_obfs_type/_password/_MinPacketSize/_MaxPacketSize, hysteria2_hop | |
| congestion_control, udp_relay_mode, disable_sni | tuic_* / naive_congestion_control, tls_disable_sni | |
| insecure-concurrency, uot | naive_insecure_concurrency, uot | |
| psk, userkey, version, obfs, obfs-host, mode, reuse | snell_psk, password, snell_version, snell_obfs_mode, snell_obfs_host, snell_mode, snell_reuse | |
| #fragment | remarks | |

### B.5 Known quirks to preserve or decide
* SS export appends an empty `&group=` param, except in the shadow-tls form.
* VMess export key `securty` (typo) for quic security; import reads `securty` too.
* sing-box ws early data: ss/trojan export append a raw `?ed=N` after the path param, vless appends `%3Fed%3DN`. Import strips `?ed=` from the path into ws_maxEarlyData (sing-box only).
* VLESS uuid and anytls password are not percent-decoded on import. Trojan password is decoded.
* `has_singbox`/`has_xray` are binary path strings used as truthy flags (see B.0).
* The import fills the form only; nothing is saved until the user saves. Bulk import (many links) goes through `link_add_node` → `subscribe.lua add`, which has its own parser (see the subscribe spec).
