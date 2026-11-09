# 10 — Views (Lua templates), client JS, and i18n

Source scope: `luasrc/view/passwall2/**` (all templates except `node_config/link_share_man.htm`, documented elsewhere),
`htdocs/luci-static/resources/view/passwall2/*.js`, and `po/fa/passwall2.po` (structure only).

This spec describes **every UI behaviour** the legacy Lua/CBI frontend implements in the browser, together with
the exact controller endpoints (`api.url("<name>")`) each one calls, their query/body parameters, and the response
fields they read. The new JS LuCI frontend must reproduce these behaviours; the Rust backend must serve the
endpoints with the same parameter names and JSON field names (see controller spec for server logic).

Conventions used below:

* `appname` = `passwall2` (also UCI config name). `api.url("x")` = `/cgi-bin/luci/admin/services/passwall2/x`
  (built by `api.url`, i.e. `luci.dispatcher.build_url("admin","services",appname, ...)`).
* `XHR.get(url, params, cb)` = LuCI legacy XHR helper: GET with params URL-encoded, callback `(xhr, json)`;
  `json` is the parsed JSON body when `Content-Type: application/json`. `XHR.poll(sec, url, params, cb)` repeats
  every `sec` seconds.
* "cbid" = DOM id/name `cbid.<config>.<section>.<option>`; row ids are `cbi-<config>-<section>`.
* `is_js_luci` = `api.is_js_luci()` — true on LuCI with client-side rendering (luci2/JS CBI shim). Several templates
  branch on it (different widget helpers). The new frontend is JS-only, so only the JS branch semantics matter,
  but both are documented where they differ.
* `<%:text%>` = translated string (msgid `text`).

---------------------------------------------------------------------------------------------------------------

## 1. Shared client JS assets (`htdocs/luci-static/resources/view/passwall2/`)

| File | Lines | Purpose |
|---|---|---|
| `cbi.js` | 50 | Registers extra CBI validators: `base64`, `json`, `timehhmm`, `uuid` |
| `func.js` | 73 | Generic helpers (base64 decode, waitForElement, getOption, …) |
| `node_list_sort.js` | 775 | Click-to-sort headers + per-group filter bar on the node list |
| `Sortable.min.js` | 1 (minified) | Third-party **SortableJS 1.15.7** (MIT) – drag-and-drop row reordering |
| `qrcode.min.js` | 1 (minified) | Third-party **QRCode.js** (davidshimjs) – share-link QR codes (used by link_share_man) |

Both `cbi.js` and `func.js` are loaded on every passwall2 CBI map page by `cbi/header.htm` (see §3.1).

### 1.1 `cbi.js` – validators

```
is_json(str):     JSON.parse(str) succeeds AND result is a non-null object  (arrays count as object)
is_timehhmm(str): /^(\d?\d):(\d\d)$/ and 0<=hour<=23 and 0<=minute<=59
```
Registration:
* If global `cbi_validators` exists (Lua LuCI): `cbi_validators.base64/json/timehhmm/uuid = function(){ return X(this) }`
  (`this` = value string).
* Else (JS LuCI): `L.require('validation')` then `validation.types[name] = function(){ return this.assert(X(this.value), msg) }`
  with messages: base64 → `Must be Base64 text!`, json → `Must be JSON text!`, timehhmm → `valid time (hh:mm)`,
  uuid → `Must be UUID format!`.

Datatypes used by models: `"base64"`, `"json"`, `"timehhmm"`, `"uuid"` – new frontend must implement these 4 validators.

### 1.2 `func.js`

| Function | Exact logic |
|---|---|
| `arraysEqual(a,b)` | identity → true; either null → false; length differ → false; element-wise `!==` |
| `isBase64(str)` | regex `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$` (strict, padded, no URL-safe) |
| `decodeIfBase64(str)` | `s = str.replace(/-/g,'+').replace(/_/g,'/')`; pad with `=` to multiple of 4; `decoded = UTF8-decode(atob(s))`; return `decoded` **only if** `btoa(UTF8-encode(decoded))` with trailing `=` stripped equals `s` with trailing `=` stripped (round-trip check), else return original `str`. Any exception → original. |
| `isUUID(str)` | `/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i` (versions 1-5, RFC variant) |
| `waitForElement(selector, cb)` | if `querySelector(selector)` exists call cb immediately; else MutationObserver on `document.body` (childList+subtree) until it appears, disconnect, call cb once |
| `waitForElementId(id, cb)` | `waitForElement("#"+CSS.escape(id), cb)` |
| `get_current_url()` | `location.origin + location.pathname` (drops query/hash) |
| `getOption(config, section, opt)` | element by name or id `cbid.<config>.<section>.<opt>`; if a Lua combobox `cbi.combobox.<id>` exists attach it as `obj.combobox`; return element or null |

---------------------------------------------------------------------------------------------------------------

## 2. Page-level templates

### 2.1 Main status block – `global/status.htm` (top of "Basic Settings" page)

UI: 4 tiles (pure-css grid, inline base64 PNG icons, images get `oncontextmenu/ondragstart = return false`):

| Tile | DOM id | Click action |
|---|---|---|
| Core | `#status_node` text `Core<br><span class=red>NOT RUNNING</span>` | none |
| Baidu Connection | `#_baidu_status` initial `Touch Check` (red) | `check_connect('baidu','https://www.baidu.com')` |
| Google Connection | `#_google_status` | `check_connect('google','https://www.google.com/generate_204')` |
| GitHub Connection | `#_github_status` | `check_connect('github','https://github.com')` |

Status polling: `XHR.poll(5, url("index_status"), null, cb)` – every **5 s**. Response JSON field read:
`global_status` (bool). Truthy → `Core<br><span class="green">RUNNING</span>`, else red `NOT RUNNING`.

`check_connect(type,url)`:
1. Tile's outer div loses `onclick` (prevents double click); text → `Check...`.
2. `XHR.get(url("connect_status"), {type, url})`.
3. Response: if `rv.ping_type == "curl"` → read `rv.use_time` (ms number): class `green` if <1000, `yellow` if <2000,
   else `red`; text `"<use_time> ms"`. Else if `rv.status` truthy → green `Working...`. Else red `Problem detected!`.
4. Re-attach onclick.

Colors: green `#2dce89`, red `#fb6340`, yellow `#fb9a05`.

### 2.2 Global page footer – `global/footer.htm` (Basic settings page; `sid = "@global[0]"`)

CSS: in section `#cbi-passwall2-socks` (Socks table): no-wrap cells; ≥1152px width `.port` and `.http_port` inputs
fixed `100px` centered; <1152px hide table titles.

Behaviour (started when the count of elements matching `[id^="cbid.passwall2."][id$="node.main"]` is >0 and unchanged
for 5 consecutive animation frames → `go()`):

1. **Socks status**: for each element `._status` (rendered by the socks table model, attribute `socks_id`):
   `XHR.get(url("socks_status"), {index:i, id})`. Response fields: `index`, `socks_status` (bool), `use_http` (bool),
   `http_status` (bool). Render `✓` (bold green) / `X` (bold red) for socks, then a second mark for http if `use_http`.
2. **Edit/Log links next to node pickers of the global section** (`#cbi-passwall2-@global[0]` … actual DOM id of global
   section): for each `.td[data-widget="nodes_listvalue"][data-name="_node"] > div` (shunt rules table inside global)
   append a placeholder `div.shunt-node-placeholder` (40px) to keep alignment; wait 100ms; then for each element whose id
   matches `/^cbid\..*node\.main$/` (the visible nodes_listvalue widget display), take hidden select `id` without `.main`,
   its `options[0].value` = selected node id. Skip if empty or starts with `_default`, `_direct`, `_blackhole`.
   Otherwise insert `<div class="node-actions">` with link **Edit** (`to_edit_node(this, global_id)`) and, if cbid ends with
   `.node` (i.e. the main node option), also link **Log** opening `url("get_redir_log")?id=acl_default` in new tab.
3. **Socks rows**: move the DOM element `#cbi-passwall2-@global[0]-socks_enabled` (the "enable socks" flag) into the place
   of the socks section description. For each socks row `cbi-passwall2-<sid>`, the node picker
   `cbid.passwall2.<sid>.node.main` gets links **Edit** (`to_edit_node(this,'socks')`) and **Log** →
   `url("get_socks_log")?name=<sid>` (new tab).

`to_edit_node(btn, stype)`: inside `#cbi-passwall2-<stype>` find the **last** hidden (`display:none`) `select` whose id
matches `^cbid\..*\..*node$` and which precedes `btn` in document order; read `options[0].value`; skip special values as
above; navigate to `url("node_config")/<id>`, or `url("socks_config")/<id>` if the id starts with `socks_`.

### 2.3 FAQ – `global/faq.htm`

Static list (strings, translated):
* `DNS related issues:` with items: Chrome secure DNS note; "If you are unable to access the internet after reboot…"
  with sub-items Windows `ipconfig /flushdns`, Mac `sudo killall -HUP mDNSResponder`, mobile toggle airplane mode;
  item 3 "make sure your device's network settings point both the DNS server and default gateway to this router".
* `#faq_reset` filled by JS:
  * `hide_url = origin + url("hide")`, `show_url = origin + url("show")`.
  * Link " Hide in main menu:" → `hide()` → `confirm("Are you sure to hide?")` → navigate to `hide_url`.
  * Text " Browser access: " + link showing `hide_url`; same for " Show in main menu:" and `show_url` (no confirm).
  The `hide`/`show` endpoints toggle the passwall2 menu entry (controller spec).

### 2.4 Backup / Restore – `global/backup.htm`

Rows:
| Label | Button | Action |
|---|---|---|
| Create Backup File | `DL Backup` | `dl_backup()` |
| Restore Backup File | `RST Backup` | opens modal `#upload-modal` |
| Restore to default configuration | `Do Reset` | `do_reset()` |
Header: `Backup and Restore`, description `Backup or Restore Client and Server Configurations.` + red note
`Note: Restoring configurations across different versions may cause compatibility issues.`

`dl_backup()`: `fetch(url("create_backup"), {method:'POST'})`; non-OK → alert `Backup failed!`; read response header
**`X-Backup-Filename`**; if absent do nothing; else download blob with that filename (object URL + temporary `<a download>`).

`do_reset()`: `confirm(" Do you want to restore the client to default settings?")` → after **1000 ms** second
`confirm(" Are you sure you want to restore the client to default settings?")` → **synchronous** GET `url("reset_config")`
→ navigate to `url("log")`.

Upload modal: `<input type=file id=ulfile accept=".tar.gz">`, buttons `UL Restore` (`do_upload`) and `CLOSE WIN`
(clears input, hides). Modal background copied from `.cbi-section`/body via `getBg()` (computed background if it
has image or non-transparent color).

`do_upload()`:
1. No file → alert `Please select a file first.`; name not ending `.tar.gz` → alert
   `Invalid file type. Please upload a .tar.gz file.` and clear; size > **10 MiB** (10*1024*1024) → alert
   `File size exceeds 10MB limit.` and clear.
2. Read as ArrayBuffer → binary string → `btoa` → base64 string.
3. Chunk size: `floor(64*1024*4/3)` = 87381, rounded up to multiple of 4 → **87384** base64 chars per chunk.
   `totalChunks = ceil(len/chunkSize)`.
4. Sequentially POST `url("restore_backup")` as `multipart/form-data` with fields
   `filename` (original file name), `chunk` (base64 slice), `chunk_index` (0-based), `total_chunks`.
5. Response JSON `{status: "success"|..., message}`; on `success` → next chunk; button text
   `"Uploading... NN%"` (floor(current/total*100)). Non-success → alert `"Upload error: "+message`; HTTP≠200 →
   alert `"Upload failed with status <code>"`; restore button label.
6. After last chunk → button label reset, navigate to `url("log")`.

### 2.5 App / component update – `app_update/app_version.htm`

Template vars: `api.appname`, `token` (CSRF token `<%=token%>`), `com` = component table (`luci.passwall2.com`) with
`com.order` (ordered list of keys) and `com[k].name` (display name). Components rendered one row each; plus one row for
passwall2 itself: label `Passwall2 Version` + sub-label `api.get_version()`.

Per row: buttons `Check update` (id `<appname>-check_btn` for the app, `_<k>-check_btn` for components; attribute
`data-update-app=<k>`) and hidden `Force update` (`_<k>-force_btn`), and detail span `<btnid>-detail`.

Component version fill (DOMContentLoaded): each `.com_version[key=k]` shows `Collecting data...`, then
`XHR.get(url("version_"+k))`; if HTTP 200 and `result.code == 1` show `result.data` or `Null` if empty.

State: `appInfoList[app]` (check result), `inProgressCount`, `componentUpdates` (count), `luciUpdating` (bool).
`syncUpdateButtons()`: each button disabled iff `btn.updateDisabled || luciUpdating || (btn is app button && componentUpdates>0)`.
`addPageNotice()`: first in-progress op installs `onbeforeunload` returning `Updating, are you sure to close?`.
`removePageNotice(app)`: app==appname → luciUpdating=false; else if app → componentUpdates--; decrement count; when 0
remove `onbeforeunload`.

`onBtnClick(btn, app)`: if not checked yet → `checkUpdate`, else `doUpdate`.

`checkUpdate(btn, app)`:
* disable, text `Updating...`, add notice, clear detail.
* `XHR.get(url("check_"+app), {token, arch: ''}, cb, 300)` (timeout arg 300).
* Response failure (`!json || json.code`) → `onRequestError(btn, json.error, checking=true)`.
* Success: store json. Fields read: `has_update` (bool), `remote_version`, `html_url`, `data` (asset object),
  `i18n` (array of asset objects, app only), `type` (archive subfix, components), `languages` (app only).
  * `has_update` → enable, text `Click to update`; detail = `<em style=color:red>remote_version</em>` wrapped in
    `<a href=html_url target=_blank>` if `html_url`.
  * else → disable, text `It is the latest version`; show `Force update` button.

`doUpdate(btn, app)`:
1. Abort if `luciUpdating` or (app button and componentUpdates>0).
2. `downloadList = [appInfo.data]` + (app only) `appInfo.i18n[]`. Each must have `browser_download_url`, else
   `onRequestError(btn, "Update failed")`.
3. Mark updating; text `Downloading...`; add notice.
4. `appUpdateUrl = url("update_"+app)`; `downloadId = Date.now().toString(36) + random base36 (6 chars)`;
   `totalSize = Σ Number(asset.size)` (0 if non-finite/≤0).
5. Progress polling (only if totalSize>0): immediately and every **1 s**:
   `XHR.get(appUpdateUrl, {token, task:'progress', id: downloadId, total_size: totalSize})` → if `typeof json.percent=='number'`
   show `"Downloading... <percent>%"`. No overlapping requests.
6. `download(part)` (1-based): `XHR.get(appUpdateUrl, {token, url: asset.browser_download_url,
   size: (app && part==1 ? totalSize : asset.size)/1024  /*KiB*/, id: downloadId, part})`.
   * Success and app and more parts → `download(part+1)`.
   * stop progress. Failure → `onRequestError(btn, json.error || "Update failed")`.
   * app → `installLuci(btn, appUpdateUrl, downloadId)`.
   * component and `json.zip` → text `Unpacking...`; `XHR.get(appUpdateUrl, {token, task:'extract', file: json.file,
     subfix: appInfo.type || ''})` → then `move(...)` with returned `json.file`.
   * component otherwise → `move(btn, app, url, json.file)`.
7. `move`: text `Moving...`; `XHR.get(url, {token, task:'move', file})` → success → `onUpdateSuccess`.
8. `installLuci(btn, url, id)`: text `Installing...`; detail `Do not refresh or switch pages during installation.`
   * Every 1 s GET static file **`<resource>/passwall2-update/<id>.json?_=<now>`** (i.e.
     `/luci-static/resources/passwall2-update/<id>.json`, written by the backend) with 5 s timeout; when JSON has numeric
     `code` → finish: `code != 0` → error `Update failed`; `0` → reload page. (Polls a static file because rpcd restart
     can invalidate the session.)
   * Simultaneously raw XHR **POST** `url` with body
     `token=<t>&task=install&id=<id>&force=<has_update?0:1>&languages=<appInfo.languages||''>`
     (`application/x-www-form-urlencoded`, timeout 300000 ms). Error/timeout/non-2xx/invalid JSON/non-zero `code` → finish(1).
9. `onUpdateSuccess`: text `Update successful`, disabled; if no ops in progress → after 1 s reload (unless luciUpdating).
10. `onRequestError(btn, msg, checking)`: enable, text `Retry`; detail span gets msg; for app button when not checking and
    no msg → `Unknown error`.

### 2.6 Log viewer – `log/log.htm` (full page; includes LuCI header/footer)

* Button `Clear logs` → `XHR.get(url("clear_log"))` → on 200 clear textarea.
* `XHR.poll(5, url("get_log"))` every **5 s**; response is **plain text** (`x.responseText`) placed into
  `#log_textarea` (readonly, rows=40, wrap=off). Auto-scroll: first load → bottom; later only if the user was within 10px
  of bottom before update.

### 2.7 Server-side log viewer – `server/log.htm`

Same as 2.6 but: legend `Logs`, endpoints `server_clear_log` / `server_get_log`, poll **3 s**, rows=20.

### 2.8 Server list status – `server/server_list_status.htm`

* For each `._servers_status` element (in server user table rows): row id = ancestor×3 id, section id = substring after
  last `-`. `XHR.get(url("server_status"), {index:i, id})` → response `{index, status}` → set `✓` green or `X` red bold.
* For each `.cbi-button-edit` in `#cbi-passwall2-<sectiontype>`: parse section id from onclick (`…/<id>'`), prepend button
  `Log` opening `url("server_log")?id=<id>` in new tab.

### 2.9 Server user config header/footer – `server/config_header.htm`, `server/config_footer.htm`

* `server_update_config(cfgid, data, redirect_url)`: `XHR.get(url("server_update_config"), {id: cfgid, data: JSON.stringify(data)})`;
  success iff HTTP 200 and `data.code == 1` → redirect; else alert `Error`.
* Footer: when the `type` select (`select[name*=passwall2][name*=type]`) changes value, immediately call
  `server_update_config(node_id, {enable, remarks, type, protocol: ''}, url("server_config")/<node_id>)` (values read via
  `getOption`) – i.e. changing server type saves those 4 fields and reloads the edit page (other fields depend on type).

### 2.10 WireGuard key generator – `server/gen_wireguard_key.htm` (custom CBI value)

Renders a row `Generate key` with a button. Click → `XHR.get(url("gen_wireguard_key"), {})`; if `code==1` set
`<prefix>wireguard_private_key` ← `data.data.private_key` and `<prefix>wireguard_public_key` ← `data.data.public_key`
of the same section (`self.option_prefix` default `""`). Error → alert.

### 2.11 HAProxy – `haproxy/js.htm`, `haproxy/status.htm`

`js.htm` CSS (≥1152px): `haproxy_config` table inputs `.haproxy_port` & `.lbweight` 100px centered; selects `.export`
130px, `.backup` 100px.
JS (for **3 s** after DOMContentLoaded, every 300 ms): among non-placeholder `tr.cbi-section-table-row`, if ≥2 rows:
last row's `input[name$='.haproxy_port']` defaults to the previous row's value when: user hasn't typed in it
(tracked via `input` event → `dataset.userModified`), last row has no node selected (`input[type=text][name$='.lbss']`
empty), values differ, and previous value not `""`/`"0"`. (Convenience: new balancing entries inherit the listen port.)

`status.htm`: reads UCI `@global_haproxy[0].balancing_enable` (default `"0"`) and `.console_port` (default `""`).
If enabled: `XHR.poll(5, url("haproxy_status"))` → `result.status` truthy → show button `Enter interface` which opens
`http://<location.hostname>:<console_port>` in new window; else empty.

### 2.12 Socks auto-switch keyword buttons – `socks_auto_switch/btn.htm` (custom CBI value on socks config page)

`socks_id` = last path segment of `location.pathname`. Two buttons:
* `Add nodes to the standby node list by keywords` → `prompt("Please enter the node keyword, pay attention to distinguish between spaces, uppercase and lowercase.")`
  → navigate `url("socks_autoswitch_add_node")?id=<socks_id>&key=<key>` (both URI-encoded).
* `Delete nodes in the standby node list by keywords` → same prompt → `url("socks_autoswitch_remove_node")?id=..&key=..`.
(Backend adds/removes nodes whose remarks contain key to/from `socks.autoswitch_backup_node` list – controller spec.)

### 2.13 Subscription page JS – `node_subscribe/js.htm`

* `confirmDeleteNode(remark)`: `confirm("Delete the subscribed node: <remark> ?")` → `fetch GET url("subscribe_del_node")?remark=<enc>`
  → ok → reload; else alert `Failed to delete.`. (remark = subscription remark; deletes all nodes from that subscription.)
* `confirmDeleteAll()`: `confirm("Are you sure you want to delete all subscribed nodes?")` → `GET url("subscribe_del_all")`.
* `ManualSubscribe(sectionId)`: read `input[name='cbid.passwall2.<sid>.url']` (trimmed); empty → alert
  `Subscribe URL cannot be empty.`; `GET url("subscribe_manual")?section=<sid>&url=<url>` → JSON `{success, msg}`;
  failure → alert `msg || "Operation failed"`; success → navigate to `url("log")`. (Uses the current, possibly unsaved URL.)
* `ManualSubscribeAll()`: iterate `.cbi-button-edit` buttons of `#cbi-passwall2-subscribe_list`, parse section id from
  onclick; collect url inputs (any empty → alert & abort); POST `url("subscribe_manual_all")` body
  `URLSearchParams{sections: "id1,id2", urls: "u1,u2"}` (comma joined) → same JSON handling.

### 2.14 Rule management – `rule/rule_version.htm`

Server-side: shows rollback buttons only if `/tmp/bak_v2ray/geoip.dat` / `/tmp/bak_v2ray/geosite.dat` exist.
UI: hides the model's flag rows `*-geoip_update` / `*-geosite_update` and replaces them with two custom checkboxes
`geoip`, `geosite` bound **two-way** to the hidden flags `…​.geoip_update`/`…​.geosite_update` (dispatching `change`).
Binding retried via MutationObserver + 300 ms interval, given up after 5 s.

* `Manually update` → disable, text `Updating...`, collect checked custom checkbox names →
  `XHR.get(url("update_rules"), {update: "geoip,geosite"})` (comma list, order reversed DOM order) → 200 → navigate
  `url("log")`; else alert `Error` and restore.
* `Rollback GeoIP|Geosite` → text `Rollbacking...` → `XHR.get(url("rollback_rules"), {type:'geoip'|'geosite'})` →
  200 && `code==1` → alert `Success`, hide button; else alert `Error`, restore.

### 2.15 Geo view – `rule/geoview.htm`

Tips list (3 items). Two inputs + `Query` buttons:
* `Domain/IP Query` (`#geoview.lookup`) → action `lookup`.
* `GeoIP/Geosite Query` (`#geoview.extract`) → action `extract`; description `Format: geoip:cn or geosite:gfw`.
Enter key in an input triggers its button. `do_geoview(btn, action, value)`: trim; empty → alert
`Please enter query content!`; disable both buttons; label `Querying`; `fetch(url("geo_view")?action=<a>&value=<enc>)` →
**text** response put into `#geoview_textarea` (readonly, rows 25); re-enable, label `Query`.

### 2.16 Shunt rule list – `rule/shunt_rule_list.htm`

Section heading `Sing-Box/Xray Shunt Rule`, red description
`Please note attention to the priority, the higher the order, the higher the priority.`

Load: `XHR.get(url("get_shunt_rules"))` → JSON array of shunt_rules section objects (fields used: `.name`, `group`,
`remarks`). Group by `group` (empty → `"default"`); if list empty create empty `"default"` group. Tabs (one per group,
insertion order; label `default` translated; text `"<group> | <red count>"`, HTML-escaped). Each tab has table:
columns `ID` (bold section name), `Remarks`, actions: `To Top`, `Edit`, `Delete`, drag handle `⠿`
(title `Drag to reorder`). Hidden input `name="group.order.<group>"` — filled with space-separated section ids when the
order changes (drag end / To Top). It is submitted with the CBI form on Save; backend reorders sections accordingly.
Below table: text input `add_name_<group>` + `Add` button.

* Add: requires name length > 1 → `XHR.get(url("add_shunt_rule"), {add_name, group: current_group})` → `code==1` →
  navigate `result.data.redirect_url`; else alert `result.data.message`; HTTP fail → alert `Save failed!`.
  `current_group` = `group_name` attribute of the active tab (`.cbi-tab`) or `default`.
* Edit → `url("shunt_rules")/<id>`. Delete → `url("delete_select_shunt_rules")?redirect=1&ids=<id>` (no confirm).
* To Top → move row before first data row, then `set_order(group)`.
* `set_order(group)`: table `cbi-passwall2-shunt_rules-<group>-table` (alert `No table!`), rows (alert `No shunt_rules!`),
  write ids joined by space into `group.order.<group>`.
* Sortable: same options as §4.6.
* On JS-LuCI a local `cbi_t_add`/`cbi_t_switch` tab implementation is defined (tab element `tab.<section>.<tab>`,
  container `container.<section>.<tab>`, swaps classes `cbi-tab`/`cbi-tab-disabled`, display block/none).

---------------------------------------------------------------------------------------------------------------

## 3. CBI infrastructure templates and custom widgets (`cbi/*`, `include/*`, `node_config/header|footer`)

### 3.1 Map header/footer (`cbi/header.htm`, `cbi/footer.htm`)

`api.return_map(map)` inserts `passwall2/cbi/header` as the **first** child and `passwall2/cbi/footer` as the last child
of **every** passwall2 CBI map.

Header: loads `cbi.js` + `func.js`; defines
`update_config(cfgid, data, redirect_url)` → `XHR.get(url("update_config"), {id: cfgid, data: JSON.stringify(data)})`;
success iff HTTP 200 and `data.code == 1` → navigate to `redirect_url` if given; otherwise alert `Error`.
(Backend: applies each key/value of `data` to UCI section `<id>` and commits; returns `{code:1}` – exact rules in the controller spec.)

Footer:
* 200 ms after DOMContentLoaded remove a `<br>` that directly precedes each `div.cbi-value-description` (cosmetic).
* When the request has form value `cbi.apply == "1"` and `map.is_js_luci`: on `luci-loaded` show a fake apply countdown
  `Applying configuration changes… %ds` via `L.ui.changes.displayStatus('notice spinning', …)` ticking each second until
  `L.env.apply_rollback` seconds; after `(L.env.apply_display + L.env.apply_holdoff)` seconds clear status and redirect
  to `map.redirect` if set, otherwise to **`url("log")`** (i.e. after Save & Apply the user lands on the log page).

### 3.2 Small generic templates

* `cbi/hidevalue.htm`: hidden field wrapper `div#cbi-<config>-<section>-<option>` (display:none, keeps `data-index` and
  `data-depends`) with `<input type=hidden id=name=cbid value=cfgvalue|default|"">` – an option that is posted but never shown.
* `cbi/tvalue.htm`: textarea option (`cbi-input-textarea`, width 100% unless `size` → cols; attributes rows, wrap,
  readonly, `data-type=datatype`, `data-update=change`), content = cfgvalue or default.
* `cbi/sortable.htm` (appended with `{sectiontype}` to tables: server list `s_server`/`s_user`, ACL list, HAProxy
  `haproxy_config`, socks table on global page, subscribe list):
  * hides LuCI up/down buttons (`.cbi-button-up/.cbi-button-down`) and on Lua LuCI the whole sort column;
  * after rows count is stable for 5 frames (+200 ms): inserts a drag handle `⠿` (title `Drag to reorder`) after the last
    `.cbi-button-remove` of every row in `#cbi-passwall2-<sectiontype>`; Sortable on table tbody (same options as §4.6);
  * on drag end writes new order (row ids without `cbi-passwall2-` prefix, space separated) into the TypedSection's
    standard hidden input `input[type=hidden][id^="cbi.sts."]` **only if the order changed** (else empty string).
    This is LuCI's native "sortable TypedSection" mechanism: on save, LuCI reorders sections (`uci reorder`).
  * Table titles hidden <1152px.

### 3.3 Node picker widgets (custom CBI templates)

All four widgets are fed by the Lua option's `keylist[]`, `vallist[]` (labels) and optional `group[]` (group name per
entry; parallel arrays filled by the model: `o:value(key, label)` + `o.group[#o.group+1] = group_name`). Group name is
the node `group` (empty = ungrouped). Search placeholder: `🔍 Search nodes...`. Search matching = case-insensitive
substring on label. Panel is moved to `<body>`, `position:fixed`, z-index max, placed below the control (or above
when not enough space; max-height `min(50vh,550px)` (value widget `min(48vh,500px)`), min-width = control width,
repositioned on scroll/resize, closes on outside click, prevents scroll-chaining with wheel events). Panel styles are
copied from a hidden reference `<select>` to match the theme (colors, padding, border; group titles darker/lighter by
30 depending on YIQ brightness > 128). Only one panel open at a time.

Groups in the panel: collapsible (`▶`/`▼` arrows), initially collapsed; opening a group collapses others (unless
searching). While searching, groups with matches auto-expand, groups without matches hide. Group counters shown next
to group title.

Group ids in DOM are `idSafe(name)` = trim, whitespace runs→`-`, control chars removed.

| Widget | Template | Used by (option) | Value storage / submit |
|---|---|---|---|
| ListValue | `nodes_listvalue.htm` + `nodes_listvalue_com.htm` | global `node`, socks `node`, ACL `node`, shunt rule `_node` & `_proxy_tag` (shunt options table), node config `fallback_node` (xray balancing), `preproxy_node` / `to_node` (xray & sing-box), subscribe config `preproxy_node` / `to_node`, server config outbound node | hidden `<select id=name=cbid>` with a single `<option>` whose value is the selected key |
| Value (combo with custom) | `nodes_value.htm` + `nodes_value_com.htm` | HAProxy `lbss` (node or custom `address:port`) | hidden `<input type=text id=name=cbid>` |
| DynamicList | `nodes_dynamiclist.htm` + `nodes_dynamiclist_com.htm` | socks `autoswitch_backup_node` | one `<input type=hidden name=cbid>` per selected item, in displayed order |
| MultiValue | `nodes_multivalue.htm` + `nodes_multivalue_com.htm` | node config `balancing_node` (xray `_balancing`) / `urltest_node` (sing-box `_urltest`); `widget=checkbox`, `cast=table` | checkboxes `name=cbid value=key` |

**ListValue** semantics:
* Values: `keylist`/`vallist`/`group` (no implicit empty entry). Current key = first whitespace token of cfgvalue (or
  first element if a table). If unset → first ungrouped entry, else first entry of first group (so the widget always
  posts a value).
* Display label `( Not Set )` until JS sets it to the current label (truncated with "..." to fit width via canvas text
  measurement; full text in `title`; requires ≥15 chars to fit before truncating).
* Group lists are de-duplicated across widgets on the same page: identical (group name + ordered key/label list)
  payloads share one entry in `window.lv_groups_pool["passwall2"][ref]` (`ref = <cbid>.group.<i>`); per-widget data in
  `window.lv_dropdown_data[cbid] = {appname, current_key, current_label, ungrouped:[{key,label,group}], group_refs[],
  group_order[], cbid}`.
* Group counter (not searching): `(1/N)` blue bold if the selected key is in that group, else `(0/N)`; searching:
  `(matches/N)` green if >0 else red.
* Selecting an item (different from current): updates hidden select option value/text, label, highlight
  (`is-selected`, blue), closes panel, then dispatches a bubbling `change` event on the hidden select
  (other scripts – node_change, shunt_options, global footer – listen to it). On open, the group containing the current
  value is expanded and the item scrolled into view.
* Global function `lv_change(cbid, list, hiddenSelect, labelSpan, search, key, text)` is used by other templates to set
  a value programmatically (e.g. reset `_proxy_tag` to `""` with label `Close (Not use)`).

**Value** semantics (differences from ListValue): implicit first entry `{key:"", label:"-- Please choose --"}`
(always visible, centered, never filtered). Empty keys from keylist skipped. If the current value is not among the
entries it is appended to the ungrouped list as `{key: value, label: value}` (custom value). Bottom of panel has a
custom input (placeholder `-- custom --`): Enter → trimmed value; if not present as an item, an ungrouped item is added;
set as value; close. Selecting an item does **not** dispatch `change`. Pools in `window.v_groups_pool`, data in
`window.v_dropdown_data`, refs `<cbid>.v-group.<i>`; panel min-width ≥240px.

**DynamicList** semantics: current keys = cfgvalue list items, each also split on `,`. Selected items shown above the
picker as removable chips (`×`), reorderable by drag (Sortable, `animation:150`, `ghostClass:"dragging-row"`). Only keys
that exist in the candidates are shown at init (unknown keys silently dropped → removed on save). Clicking a candidate
appends it (duplicates ignored) and resets label to `-- Please choose --`. After every change hidden inputs are
regenerated in chip order. Group counter shows `(N)` (searching: `(matches/N)`). Data: `window.dl_dropdown_data[cbid] =
{current_key[], ungrouped[], groups{name:[items]}, group_order[], cbid}`.

**MultiValue** semantics: selected = cfgvalue list (or whitespace-split string). Ungrouped entries are put in group
named `default` (translated). Server renders group blocks with counts `(selected/total)`; items (checkboxes
`id=<cbid>.<key> name=<cbid> value=<key>`, label) are rendered lazily the first time the containing `.cbi-value` becomes
visible (MutationObserver on style/class). Search box above list filters items, auto-expands matching groups, collapses
all when cleared. Buttons `Select all` / `DeSelect all` toggle only **visible** checkboxes. Counter
`Selected: <red>checked/total</red>` (when searching counts only visible). Toggling a group closes the others and scrolls
list to top (when not searching).

### 3.4 Node change → shunt reload (`include/node_change.htm`)

Appended on global page and ACL config page with `verify_option = s.fields["node"]` and `shunt_list` (JSON array of
`{id, ...}` for nodes whose protocol is `_shunt`).
* Tracks the node ListValue hidden select (`verify_option:cbid(section_id)`); remembers its initial value.
* On change: if the new value is a shunt node → append hidden input `node_save_before=<old value>` to `#cbi-passwall2`
  form and click the last `.cbi-button-save` (save form so the server re-renders the shunt options of the new node;
  backend uses `node_save_before` to know the previous node). Otherwise → `shunt.hide()`.
* Observer: whenever the DOM changes, if the select is missing → `shunt.hide()`; if current value is a shunt node →
  `shunt.show()`.

### 3.5 Shunt options table (`include/shunt_options.htm`)

Appended by `client/include/shunt_options.lua` (loaded from global, ACL config and Xray/sing-box `_shunt` node pages) with `{node_id, verify_option, section_id, section_type, tab_name,
normal_list}` where the shunt option table section id is `cbi-passwall2-<section_type>` and DOM option ids are
`cbid.table.<row#>._node`, `._fakedns`, `._proxy_tag` (row number 1..n; the last row is the default node).
`normal_list` = JSON array of `{id}` for normal (non-special) nodes.
* `check_fakedns(i, val)`: when row node value is `""` or `_direct` → uncheck & hide `_fakedns`; else show.
* `check_proxy_tag(i, val)`: if value empty, starts with `_`, starts with `socks_`, or not in `normal_list` → reset
  `_proxy_tag` to `""` (`lv_change(..., "", "Close (Not use)")`) and hide it; else show.
* `shunt.tab()`: move the table into tab container `container.passwall2.<section_id>.<tab_name>` when `tab_name` set.
* `shunt.hide()/show()`: toggle class `shunt_hidden` on the table, on the tab header (`tab.passwall2.<sid>.<tab>` and
  `li[data-tab*=<tab>]`); hide also renames every `[name]` inside the tab container to `o-name` (so the hidden fields
  are **not submitted**); show restores `name`.
* On load: `shunt.tab()`; when `shunt_group` select changes → `update_config(node_id, {shunt_group: <new>},
  get_current_url())` (saves and reloads to show the rules of the new group). After 200 ms: `refresh_depends()` for all
  rows; bind change on `cbid.table.<i>._node.main` → re-check fakedns/proxy_tag; for the **last** row remove the
  `_default` choice from its ungrouped candidate list (the default rule cannot point to "default").

### 3.6 Node config header/footer (`node_config/header.htm`, `node_config/footer.htm`)

Header: `fetchCertSha256(el)` (link next to TLS pin option): guard with `data-loading`; red while loading;
`XHR.get(url("fetch_certsha256"), {id: <node section>})` → requires HTTP 200 and `res.code === 1 && res.data`; sets
**all** inputs whose id ends with `_tls_pinSHA256` to `res.data`; else alert `res.msg` or `Fetch Failed !`.

Footer (node edit page, `node_id = arg[1]`):
* When `type` select changes value → `update_config(node_id, {remarks, group, type: new, protocol: ''},
  url("node_config")/<node_id>)` (save minimal fields and reload with the new type's form).
* After the type select exists: if `sessionStorage.fromUrl` = `{link, timestamp, savetime}` is still valid
  (`now - timestamp < savetime`) call `fromUrl(link, true)` (import share link, defined in link_share_man) else remove it.
* When `protocol` select changes and either the new value starts with `_` (special: `_balancing`, `_urltest`,
  `_shunt`, `_iface`) or the old one did and the new doesn't: if new starts with `_` add hidden input
  `name="load<newvalue>" value=1` (e.g. `load_shunt=1`) to the form; then click the last `.cbi-button-save` (submit &
  re-render). Ordinary protocol switches are handled client-side by CBI depends.

### 3.7 Template ↔ model usage map

| Template | Appended/used by |
|---|---|
| `global/status`, `global/faq`, `global/backup`, `global/footer`, `include/node_change` | `client/global.lua` |
| `node_list/node_list` | `client/node_list.lua` |
| `node_config/header|footer`, `cbi/nodes_multivalue_com`, `cbi/nodes_listvalue_com` | `client/node_config.lua` |
| `node_subscribe/js`, `cbi/sortable` | `client/node_subscribe.lua` |
| `socks_auto_switch/btn`, `cbi/nodes_dynamiclist(_com)` | `client/socks_config.lua` |
| `haproxy/status`, `haproxy/js`, `cbi/nodes_value(_com)`, `cbi/sortable` | `client/haproxy.lua` |
| `rule/rule_version`, `rule/shunt_rule_list` | `client/rule.lua` |
| `rule/geoview` | `client/geoview.lua` (via `Template`) |
| `app_update/app_version` | `client/app_update.lua` (`{com = com}`) |
| `log/log` | controller `log` page (template page, not CBI) |
| `include/shunt_options` | `client/include/shunt_options.lua`, which is `loadfile`d by `global.lua`, `acl_config.lua`, `type/2_xray.lua`, `type/1_sing-box.lua` |
| `server/*` | `server/index.lua` (`server_list_status`, `log`, `sortable`), `server/server_config.lua` (`config_header|footer`), `server/type/*.lua` & `server/user_config.lua` (`gen_wireguard_key`) |
| `cbi/header`, `cbi/footer` | every map via `api.return_map()` |

---------------------------------------------------------------------------------------------------------------

## 4. Node list – `node_list/node_list.htm` + `node_list_sort.js`

Rendered inside the "Node List" CBI map (the map also contains the options `show_node_info`, `auto_detection_time`,
`url_test_url` of `@global_other[0]` which this template listens to).

### 4.1 Server-side template computation

```
node = uci get passwall2.@global[0].node
if node and uci(node).protocol == "_shunt":
    grp = uci(node).shunt_group
    shunt_rule_list = [ every shunt_rules section e with e[".name"] and e.remarks and e.group == grp ]  (UCI order)
    shunt_rule_list += { ".name": "default_node", remarks: "Default" }
```
Template JS globals from UCI: `auto_detection_time = @global_other[0].auto_detection_time or "0"` (values `"0"`,
`"icmp"`, `"tcping"`), `show_node_info = @global_other[0].show_node_info or "0"`.

### 4.2 Toolbar (`.pw-toolbar`)

Buttons in order: `Add` (`node_action('add')`), `Add the node via the link` (opens link modal), `Clear all nodes`,
`Delete select nodes`, `Select all` (`#select_all_btn`, only visible ≤1152px), `Reassign Group`, `Save & Apply`
(form submit `name="cbi.apply"`). Toolbar vertical padding equalised at runtime (`--pw-extra-top/bottom` CSS vars computed
from gap to preceding `.cbi-section` and to `#node_list`, recomputed on resize).

### 4.3 Loading & rendering (`loadNodeList()`)

1. `XHR.get(url("get_node"))` → JSON **array** of node objects (UCI `nodes` sections in UCI order, enriched by backend).
   Fields used: `.name`, `group`, `remarks`, `type`, `protocol`, `address`, `port`, `hysteria_hop`, `hysteria2_hop`,
   `hysteria2_realms`, `full_address` (backend-formatted address, e.g. bracketed IPv6).
2. Group by `group` (missing/empty → `"default"`), preserving order of first appearance; first group becomes active tab.
3. Per group: tab `<li group_name=G id="tab.passwall2.nodes.G" class="cbi-tab">` with link
   `href=REQUEST_URI?tab.passwall2.nodes=G` and text `escape_html(G or "default"(translated)) + " | " + <red count>`;
   container `div.cbi-tabcontainer#container.passwall2.nodes.G`. Wrapping: `<ul class=cbi-tabmenu>` +
   `<fieldset id="cbi-passwall2-nodes">`.
4. Table `#cbi-passwall2-nodes-G-table` columns: select-all checkbox (`.nodes_select_all`), `Remarks` (40%),
   `Ping` (8%), `TCPing` (8%), `URL Test` (8%), actions. Hidden input `name="group.order.G"`; footer `Add` button.
5. Row `tr#cbi-passwall2-<id>` (class `cbi-rowstyle-1/2` alternating) contains hidden inputs
   `cbid.passwall2.<id>.remarks|address|port` (raw values) and cells:
   * checkbox `.nodes_select[cbid=<id>]` (`onclick=update_select_state()`)
   * `td.pw-remark` = `get_remarks_name(o)` (+ `<br>address:port` when `show_node_info=="1"`, see below)
   * `td.pw-ping`: if `auto_detection_time != "icmp"` and address set → link `Test` → `ping_node(id,this,'icmp')`;
     else `<span class=ping_value cbiid=id><a>---</a></span>` (placeholder for auto ping).
   * `td.pw-tcping`: if `auto_detection_time != "tcping"` and address+port → `Test` link (`tcping`); else
     `<span class=tcping_value cbiid=id>---`.
   * `td.pw-urltest`: if address+port → `Test` → `urltest_node(id,this)`; else `---`.
   * actions: `To Top`, `Use` (`set_node_div.open(id)`), `Copy`, `Edit`, `Delete`, drag handle `⠿`.
6. After render: register tabs, switch to first group, record `origin_group_node_order[G]`, init Sortable per table,
   purge expired localStorage ping cache, `get_now_use_node()`, `pingAllNodes()`, `pw2NodeSort.enhanceAll()`.

`get_remarks_name(o)` (produces the Remarks cell HTML):
```
str = "<input type=hidden id='cbid.passwall2.<.name>.type' value='<type>'>"
type = o.type or ""
if type in ("sing-box","Xray"):
    p = protocol label: _balancing→"Balancing"(i18n), _urltest→"URLTest", _shunt→"Shunt"(i18n),
        _iface→"Interface"(i18n), vmess→"VMess", vless→"VLESS", shadowsocks→"SS", shadowsocksr→"SSR",
        wireguard→"WG", hysteria→"HY", hysteria2→"HY2", anytls→"AnyTLS", ssh→"SSH",
        else (len>1) capitalize first letter (e.g. trojan→"Trojan", socks→"Socks", http→"Http", tuic→"Tuic")
    if type=="sing-box": type="Sing-Box"
    type = type + " " + p
if (o.type=="Hysteria2" or o.protocol=="hysteria2") and o.hysteria2_realms:  str += type+" Realm："+remarks
else: str += type + "：" + remarks          # NOTE full-width colon U+FF1A
```
show_node_info: `_port = port || hysteria_hop || hysteria2_hop` with `:` replaced by `-`; if address and _port →
append `"<br>" + (full_address || address) + ":" + _port`.

### 4.4 Row/toolbar actions (`node_action(action, id, a)`) – every action first aborts pending ajax pings

| Action | Behaviour |
|---|---|
| `add` | navigate `url("add_node")?redirect=1&group=<active tab group_name or "default">` |
| `copy` | navigate `url("copy_node")?section=<id>` |
| `edit` | navigate `url("node_config")/<id>` |
| `del` | navigate `url("delete_select_nodes")?redirect=1&ids=<id>` (no confirm) |
| `row_top` | move row to first data row of its table; `set_order(group)` (unsaved until Save & Apply) |
| `del_all` | `confirm("Are you sure to clear all nodes?")` → `XHR.get(url("clear_all_nodes"))` → 200 → reload `url("node_list")`, else alert `Error` |

Delete selected (`delete_select_nodes()`): in visible tab container collect checked **and visible** (not filtered)
`.nodes_select` → `cbid` attr. None → alert `You no select nodes !`. Else `confirm("Are you sure to delete select nodes?")`
→ show `#modal-mask` with `Processing, please wait…` → `XHR.get(url("delete_select_nodes"), {ids: "id1,id2"})` →
200 → navigate `url("node_list")`, else alert `Error`.

Select-all (`checked_all_node`/`dechecked_all_node` → `set_select_all_state(bool)`): only visible rows of the visible
tab are (un)checked, hidden rows are forced unchecked; header checkbox and `#select_all_btn` toggle title/value between
`Select all` / `DeSelect all` and swap their onclick. `update_select_state()`: recompute "all checked" over visible rows.
Switching tabs (`cbi_t_switch` wrapper) first deselects all.

Reassign group modal (`#reassign_group_div`, title `Reassign Node Group`): requires ≥1 selected visible node (else alert
`You no select nodes !`). Group picker (see 4.8). `Save` → `XHR.get(url("reassign_group"), {group, ids:"a,b"})` → 200 →
reload `url("node_list")`; else alert `Error`.

"Use" modal (`#set_node_div`): header `You choose node is: <remarks>`, close X. Buttons:
* if `shunt_rule_list` non-empty (global node is a `_shunt` node): one button per rule (label = rule remarks, plus
  `Default`) → `set_node_div.set('<global node id>', '<rule .name or default_node>')`.
* else one button `Node` → `set('@global[0]', 'node')`.
`set(type, config)`: `confirm("Are you sure set this node?")` → navigate
`url("set_node")?type=<type>&config=<config>&section=<chosen node id>`. (Backend sets UCI `passwall2.<type>.<config>=<section>` and restarts – see controller spec.)

Currently used node (`get_now_use_node()`): `XHR.get(url("get_now_use_node"))` → `result.global` = node id; that row
gets title `Using...`, class `_now_use_bg` (background `#5e72e445`, dark mode `#4a90e2`) and red remarks text.

### 4.5 Latency tests

Address used for ping (`get_address_full(id)`): hidden `address`/`port` inputs; if address contains CJK
(`/[一-鿿]+/`) treat address as empty.

Manual ICMP/TCPing (`ping_node(id, dom, type)`): skip if `dom.dataset.busy=="1"`; requires address (icmp) or address+port
(tcping). Shows `Check...` → `XHR.get(url("ping_node"), {address, port, type})` → `result.ping` (string ms); empty/null →
`Timeout` red; else `"<ping> ms"` colored green <100, `#fb9a05` <200, else red. HTTP error → `Error` red.

URL test (`urltest_node(id, dom)`): `XHR.get(url("urltest_node"), {id})` → `result.use_time` (string ms); empty →
`Timeout`; green <1000, `#fb9a05` <2000, else red; HTTP failure → `Error`.

Auto ping (`pingAllNodes()`, only if `auto_detection_time` ∈ {`icmp`,`tcping`}):
1. Over all `.ping_value` (icmp) or `.tcping_value` (tcping) spans (by DOM index `i`), compute address/port; skip
   unusable. Deduplicate identical address+port: merge indexes into comma list.
2. Cache key in **localStorage**: `"<mode>:<address>:<port>"` → JSON `{dom_id, timestamp, savetime, value}`.
   If cache valid (`now - timestamp < savetime`) render cached value (`value>=0` → ms colored as ICMP thresholds; `-1`
   → `Timeout`) and make the cell clickable for manual re-test; else delete and queue.
3. Run queue with **20 concurrent workers**; each item POSTs (form-urlencoded, custom `ajax.post`, adds `_=<random>`)
   `url("ping_node")` with `{index: "<idx list>", address, port, type: mode}`, timeout **5000 ms**.
   * success, non-empty `ping` → cache `{savetime: 150000, value: ping}` (150 s); text ms + colors (<100 green, <200 orange).
   * empty `ping` → cache `{savetime: 60000, value: -1}`; `Timeout` red.
   * timeout → `Timeout` red (not cached). Every resolved cell becomes clickable → manual ping.
4. On page load all localStorage keys starting with `icmp`/`tcping` whose entries are expired are deleted.
`ajax.abortAll()` aborts all queued XHRs on: any node_action, link click (not `target=_blank`), `beforeunload`,
option change, modal submissions.

### 4.6 Drag reorder & order persistence

* Sortable on each group table body: `handle: ".drag-handle"`, `draggable: "tr.cbi-section-table-row"`,
  `animation: 150`, `ghostClass: "dragging-row"`, `fallbackOnBody: true`, `forceFallback: false`,
  `swapThreshold: 0.65`, `onEnd: set_order(group)`. If `Sortable` not loaded yet, retry every 200 ms up to 25 times.
* `set_order(group)`: write all row ids of `#cbi-passwall2-nodes-<group>-table` (DOM order, filtered rows included)
  joined by single space into hidden input `group.order.<group>` (alerts `No table!` / `No nodes!`).
* Persisted only when the form is submitted with **Save & Apply**: backend reads every form field `group.order.<G>` and
  reorders the `nodes` sections of that group in UCI to that order (other groups keep relative positions).

### 4.7 Options that save immediately (`save_node_list_opt`)

On DOMContentLoaded (and, on Lua LuCI, after every `cbi_d_update`), bind:
* checkbox `show_node_info` change → `show_node_info = checked?"1":"0"` → `XHR.get(url("save_node_list_opt"), {option:"show_node_info", value})` → 200 → clear and reload list.
* select `auto_detection_time` change → same with option `auto_detection_time` → reload list.
* `url_test_url` (JS LuCI: dropdown div `cbi-dropdown-change`; Lua: select/input `change`) → save option
  `url_test_url` **without** reload; only when value non-empty and different from last saved (`el.new_val`).
Failure → alert `Error`. (Backend stores the value in `passwall2.@global_other[0].<option>` – see controller spec.)

### 4.8 Add-node-by-link modal (`#add_link_div`)

Title `Add the node via the link`, textarea `#nodes_link` (monospace), hint (red)
`Enter share links, one per line. Subscription links are not supported!`, group picker `Group Name`, buttons `Add`/`Close`.
Modal mask `#modal-mask` (rgba black 0.4, z 999); `body.modal-open` disables pointer events outside the dialog.

`add_node()`:
```
s = textarea.value; remove \t; normalise CRLF/CR to \n; strip any <...> tags; trim
if s == "": focus; return
s = decodeIfBase64(s)
if "://" not in s: alert("Please enter the correct link."); return
close modal; ajax_add_node(s, group)
```
`ajax_add_node(link, group)`: show mask `Processing, please wait…`; split `link` into **1000-character** chunks
(to overcome uhttpd request limits); POST sequentially to `url("link_add_node")` multipart `FormData`
`{chunk, chunk_index (0-based), total_chunks, group}`; non-200 → alert `Error`; network error → alert `Network Error`;
after last chunk navigate `url("node_list")`. (Backend concatenates chunks and, at the last one, runs the subscribe
script in "add" mode on the full text with the group.)

Group picker (`init_group_dropdown(div)`; used by add-link and reassign modals): choices = `default` (label translated
`default`) + every existing tab `group_name` (excluding duplicates). JS LuCI: `ui.Dropdown("default", choices,
{create:true, sort: groups, custom_placeholder: "-- custom --"})`; Enter in the create-input normalises the typed name
case-insensitively to an existing group (`normalize_group_name`: trim, case-insensitive match → existing spelling) and
ignores empty names; IME composition respected. Lua LuCI: `cbi_combobox_init` with same choices, blur normalises
(empty → `default`). `get_group_value()` → selected value or `"default"`.

### 4.9 Sort & filter enhancement (`node_list_sort.js`, global `window.pw2NodeSort = {init, enhanceAll, rowVisible}`)

Translations come from hidden `#pw2-nodesort-i18n[data-app=passwall2]` spans `data-k=<key>`:
`hint, typeHint, addrHint, origHint, changed, restored, wait (contains %d), waitFail, filter, all, empty, type, addr,
fWord, search, searchHint, shown (contains %s and %t), reset, resetHint, filterHint` (texts listed in §7.3).

Sorting (click on a header):
* Header columns mapped by cell class: `pw-remark`→`name`, `pw-ping`→`ping`, `pw-tcping`→`tcping`, `pw-urltest`→`urltest`.
  Each sortable `th` gets `data-pw-sort`, title `hint`, an arrow span. The Remarks header also gets three sub-links:
  `Type` (`type`), `Address` (`addr`), `↺` (`orig`).
* Sort keys: `name` = hidden remarks (fallback cell text); `type` = text before first `：`/`:` in the remark cell with a
  trailing ` Realm` removed + `\0` + remarks; `addr` = address + `\0` + port left-padded to 5 digits (null if no address);
  latency columns = `parseLatency(cell text)`: matches `^(\d+(?:[.,]\d+)?)\s*(ms|s)?$`i, seconds ×1000; non-numeric
  (`Timeout`, `Error`, `---`, `Test`) → null.
* Clicking the same key toggles asc/desc (first click asc). Empty/null keys always last; stable (original index tie-break);
  numbers numeric, strings via `Intl.Collator(lang, {numeric:true, sensitivity:'base'})`.
* `orig` restores the order captured at enhance time (`table.__pwOrig`).
* After sort: rows re-appended, rowstyle classes recomputed, `set_order(group)` called (so Save & Apply persists it),
  filter refreshed, indicator ▲/▼ on the main header (or `pw-sort-active` on sub link), note above table:
  `changed` or (orig) `restored`.
* If automatic ping is still running (`mode` icmp/tcping and either in-flight XHRs in `window.ajax.list` or cells still
  `---` that have usable address), show note `wait` with `%d` = cells left (or in-flight), poll every 500 ms; run the sort
  when done or after 6 consecutive polls with no in-flight request; give up after **120 s** with note `waitFail`.

Filter bar (`div.pw-filter#pw-filter-<tableid>` inserted above each table; only for tables with ≥2 rows):
* `Type` select (single value): options = distinct row types (label most common spelling, `(empty)` for blank) with
  counts, shown only if ≥2 distinct values; sorted by label.
* `Word in remarks` select: words from remarks split on non-letter/digit (Unicode), length ≥2, not purely digits,
  case-insensitive dedup; option shown when word occurs in ≥2 rows and fewer than all rows; sorted by count desc then
  label; max 40 options.
* Search input (`search...`, 150 ms debounce): case-insensitive substring of `type + " " + remarks + " " + address:port`.
* Count `Shown X of Y`; `Reset` button clears filters. Bar gets class `pw-filter-on` when any filter active.
* Filtering only toggles class `pw-row-hidden` (rows remain in DOM/form). Hidden rows get unchecked; select-all and
  delete/reassign skip hidden rows. Bar rebuilt only if a signature of options changes.

---------------------------------------------------------------------------------------------------------------

## 5. Endpoints called from the views (summary for backend parity)

All under `/cgi-bin/luci/admin/services/passwall2/`. "GET" = LuCI `XHR.get` (query string); responses JSON unless noted.

| Endpoint | Caller | Params | Response fields used |
|---|---|---|---|
| `index_status` | status.htm (poll 5s) | – | `global_status` |
| `connect_status` | status.htm | `type` (baidu/google/github), `url` | `ping_type` ("curl"), `use_time`, `status` |
| `socks_status` | global/footer | `index`, `id` | `index`, `socks_status`, `use_http`, `http_status` |
| `get_redir_log` | global/footer | `id=acl_default` | plain text page (new tab) |
| `get_socks_log` | global/footer | `name=<socks sid>` | plain text page |
| `hide` / `show` | faq | – | navigation |
| `create_backup` | backup (POST) | – | binary tar.gz, header `X-Backup-Filename` |
| `restore_backup` | backup (POST multipart) | `filename`, `chunk`(base64), `chunk_index`, `total_chunks` | `status` ("success"), `message` |
| `reset_config` | backup (sync GET) | – | ignored |
| `version_<k>` | app_version | – | `code` (1 ok), `data` (version string) |
| `check_<app>` | app_version | `token`, `arch=''` | `code` (non-zero=error), `error`, `has_update`, `remote_version`, `html_url`, `data{browser_download_url,size}`, `i18n[]`, `type`, `languages` |
| `update_<app>` | app_version | download: `token,url,size(KiB),id,part`; `task=progress&id&total_size`; `task=extract&file&subfix`; `task=move&file`; POST `task=install&id&force&languages` | `code`, `error`, `file`, `zip`, `percent` |
| static `/luci-static/resources/passwall2-update/<id>.json` | app_version | – | `code` (number) |
| `get_log` / `clear_log` | log.htm | – | **text** / ignored |
| `server_get_log` / `server_clear_log` | server/log | – | text |
| `server_status` | server_list_status | `index`, `id` | `index`, `status` |
| `server_log` | server_list_status | `id` | text page |
| `server_update_config` | server/config_* | `id`, `data`(JSON object) | `code` |
| `gen_wireguard_key` | gen_wireguard_key | – | `code`, `data.private_key`, `data.public_key` |
| `haproxy_status` | haproxy/status (poll 5s) | – | `status` |
| `socks_autoswitch_add_node` / `socks_autoswitch_remove_node` | socks btn (navigation) | `id`, `key` | redirect |
| `subscribe_del_node` | node_subscribe/js | `remark` | HTTP status only |
| `subscribe_del_all` | node_subscribe/js | – | HTTP status only |
| `subscribe_manual` | node_subscribe/js | `section`, `url` | `success`, `msg` |
| `subscribe_manual_all` | node_subscribe/js (POST urlencoded) | `sections` (csv), `urls` (csv) | `success`, `msg` |
| `update_rules` | rule_version | `update` = csv of `geoip`,`geosite` | HTTP status |
| `rollback_rules` | rule_version | `type` = geoip/geosite | `code` |
| `geo_view` | geoview | `action` = lookup/extract, `value` | **text** |
| `get_shunt_rules` | shunt_rule_list | – | array of shunt_rules objects (`.name`, `group`, `remarks`) |
| `add_shunt_rule` | shunt_rule_list | `add_name`, `group` | `code`, `data.redirect_url` / `data.message` |
| `shunt_rules/<id>` | shunt_rule_list | – | edit page |
| `delete_select_shunt_rules` | shunt_rule_list | `redirect=1`, `ids` | redirect |
| `get_node` | node_list | – | array of node objects (see §4.3) |
| `get_now_use_node` | node_list | – | `global` (node id) |
| `ping_node` | node_list | `address`, `port`, `type` (icmp/tcping) [+`index`] | `ping` (string ms or empty) |
| `urltest_node` | node_list | `id` | `use_time` (string ms or empty) |
| `add_node` | node_list (navigation) | `redirect=1`, `group` | redirect to new node config |
| `copy_node` | node_list | `section` | redirect |
| `node_config/<id>` | node_list, global footer | – | edit page |
| `socks_config/<id>` | global footer | – | edit page |
| `delete_select_nodes` | node_list | `ids` (csv) [+`redirect=1`] | HTTP status / redirect |
| `clear_all_nodes` | node_list | – | HTTP status |
| `reassign_group` | node_list | `group`, `ids` (csv) | HTTP status |
| `set_node` | node_list (navigation) | `type` (UCI section e.g. `@global[0]` or shunt node id), `config` (option e.g. `node` or rule name / `default_node`), `section` (node id) | redirect |
| `save_node_list_opt` | node_list | `option` ∈ {show_node_info, auto_detection_time, url_test_url}, `value` | HTTP status |
| `link_add_node` | node_list (POST multipart chunks) | `chunk`, `chunk_index`, `total_chunks`, `group` | HTTP status |
| `update_config` | cbi/header (`update_config()`) | `id`, `data` (JSON) | `code` |
| `fetch_certsha256` | node_config/header | `id` | `code`, `data` (pin string), `msg` |
| `log` | many (redirect target after actions) | – | log page |

Form fields consumed by the backend on CBI submit (added by these views):
* `group.order.<group>` (node list & shunt rule list) – space-separated section ids in desired order.
* `cbi.sts.<config>.<sectiontype>` (LuCI standard; filled by sortable.htm only when order changed).
* `node_save_before` (node_change.htm) – previous node id before switching to a shunt node.
* `load_<special>` e.g. `load_shunt`, `load_balancing`, `load_urltest`, `load_iface` (node_config/footer) = `1`.
* Fields renamed `o-name` by `shunt.hide()` are intentionally *not* submitted.

---------------------------------------------------------------------------------------------------------------

## 6. Browser-side storage

| Store | Key | Value | TTL / cleanup |
|---|---|---|---|
| localStorage | `icmp:<address>:<port>` / `tcping:<address>:<port>` | `{"dom_id":"<idx>","timestamp":<ms>,"savetime":150000|60000,"value":<ms>|-1}` | 150 s success, 60 s timeout; expired keys purged on every node list load |
| sessionStorage | `fromUrl` | `{link, timestamp, savetime}` (written by link_share_man import flow) | consumed by node_config/footer if fresh, else removed |
| window globals | `lv_dropdown_data`, `lv_groups_pool`, `v_dropdown_data`, `v_groups_pool`, `dl_dropdown_data`, `mv_nodeitem_rendered`, `pw2NodeSort`, `ajax` | widget state | page lifetime |

---------------------------------------------------------------------------------------------------------------

## 7. i18n – `po/`

### 7.1 Structure

* `po/<lang>/passwall2.po` for `fa`, `ru`, `zh-cn`, `zh-tw`; symlinks `po/zh_Hans -> zh-cn`, `po/zh_Hant -> zh-tw`.
* Compiled by the standard `luci.mk` (`include $(TOPDIR)/feeds/luci/luci.mk`) via `po2lmo` into
  `/usr/lib/lua/luci/i18n/passwall2.<lang>.lmo` (Lua `translate()` and JS `_()` both read the LMO catalog `passwall2`).
  `LUCI_LANG.*` packages `luci-i18n-passwall2-<lang>` are produced automatically.
* Files have **no PO header** entry (first entry is `msgid "Auto"`), no `msgctxt`, no plurals, no comments. Two
  entries use multi-line msgid continuation. Placeholders used: `%s` (352 occurrences in fa), `%d` (2), `%t` (2,
  custom: total count in "Shown %s of %t"). zh-tw starts with a UTF-8 BOM.

| Language | Lines | Entries (msgid) | Untranslated |
|---|---|---|---|
| fa | 2640 | 873 | 0 |
| ru | 2641 | 876 | 0 |
| zh-cn | 2626 | 871 | 0 |
| zh-tw | 2632 | 873 | 0 |

fa contains every zh-cn msgid plus 2 extra (`ECH Query Policy`, `Controls the policy used when performing DNS
queries for ECH configuration.`). msgids `PassWall 2` and `default` are **not** in any catalog (menu title stays
`PassWall 2`; tab label `default` untranslated). The new frontend can reuse these .po files as-is (JS `_()`), keeping
msgids byte-identical (including the full-width colon in UI strings, typos such as `You no select nodes !`,
`Please note attention to the priority…`, leading spaces in ` Hide in main menu:` / ` Browser access: ` /
` Do you want to restore the client to default settings?`).

### 7.2 Persian (fa) translations of menu entries and page titles

| msgid (English) | Persian | Menu order / route |
|---|---|---|
| PassWall 2 | *(no translation – shown as "PassWall 2")* | `admin/services/passwall2` (order 0) |
| Basic Settings | تنظیمات پایه | `settings` (1) |
| Node List | لیست گره‌ها | `node_list` (2) |
| Node Subscribe | اشتراک گره | `node_subscribe` (3) |
| Other Settings | تنظیمات دیگر | `other` (92) |
| Load Balancing | توزیع بار | `haproxy` (93, only if haproxy installed) |
| App Update | به‌روزرسانی برنامه | `app_update` (95) |
| Rule Manage | مدیریت قوانین | `rule` (96) |
| Geo View | نمای Geo | `geoview` (97, conditional) |
| Access control | کنترل دسترسی | `acl` (98) |
| Server-Side | سمت سرور | `server` (99) |
| Runtime Logs | گزارش‌های زمان اجرا | `log` (999) |
| Node Config | پیکربندی گره | `node_config/<id>` (hidden) |
| Socks Config | پیکربندی Socks | `socks_config/<id>` (hidden) |
| Shunt Rule | قانون شنت | `shunt_rules/<id>` (hidden) |
| Server Config | پیکربندی سرور | `server_config/<id>` (hidden) |
| User Config | پیکربندی کاربر | `server_user_config/<id>` (hidden) |
| Logs | گزارش‌ها (Logs) | server log legend |
| Main switch | سوئیچ اصلی | global enable option |
| Node | گره | |
| RUNNING / NOT RUNNING | در حال اجرا / متوقف شده | status tile |
| Working... / Problem detected! / Touch Check | در حال کار... / مشکل شناسایی شد! / بررسی اتصال | connection tiles |
| Backup and Restore | پشتیبان‌گیری و بازیابی | backup block |
| Check update | بررسی به‌روزرسانی | app update |
| Clear logs | پاک کردن گزارش‌ها | log page |
| Add the node via the link | افزودن گره از طریق لینک | node list |
| Reassign Group | تغییر گروه | node list |
| Use / Using... | استفاده / در حال استفاده... | node list |
| Drag to reorder | برای تغییر ترتیب بکشید | tables |
| Search nodes... | جستجوی گره‌ها... | node pickers |

### 7.3 Node-list sort/filter strings (`#pw2-nodesort-i18n`, key → msgid)

| key | msgid |
|---|---|
| hint | Click to sort; click again to reverse. Press Save & Apply to keep the order. |
| typeHint | Sort by type or protocol, then by name |
| addrHint | Sort by server address and port |
| origHint | Restore the saved order |
| changed | The order changed on this page only. Press Save & Apply to store it on the router. |
| restored | Saved order restored. |
| wait | Automatic ping is still running (%d left). Sorting will run when it finishes. |
| waitFail | Automatic ping did not finish within 2 minutes. Sorting was cancelled. Reload the page and try again. |
| filter | Filter: |
| all | All |
| empty | (empty) |
| type | Type |
| addr | Address |
| fWord | Word in remarks |
| search | search... |
| searchHint | Show only rows that contain this text |
| shown | Shown %s of %t |
| reset | Reset |
| resetHint | Show all rows |
| filterHint | The filter only hides rows on this page and changes nothing on the router. Select all skips hidden rows. |

---------------------------------------------------------------------------------------------------------------

## 8. Re-implementation notes for the JS frontend

1. Keep every endpoint/param name in §5 and the form-field conventions (`group.order.*`, `node_save_before`,
   `load_*`) or provide equivalent rpcd/ubus calls with the same semantics.
2. Polling intervals: status 5 s, haproxy 5 s, client log 5 s, server log 3 s, app-update download progress 1 s,
   install result file 1 s.
3. Latency color thresholds: ICMP/TCPing green <100 ms, orange (`#fb9a05`) <200 ms, red otherwise; URL test / connect
   test green <1000 ms, orange/yellow <2000 ms, red otherwise.
4. Chunked uploads: share-links 1000 chars per chunk; backup 87384 base64 chars per chunk, 10 MiB file limit, `.tar.gz` only.
5. Auto ping concurrency 20, per-request timeout 5 s, dedup by address:port, cache 150 s / 60 s.
6. Node ordering and group reassignment are only persisted on Save & Apply (order) or immediately (reassign, delete,
   clear, copy, add, set node, list options).
7. After Save & Apply (JS LuCI) the UI redirects to the Runtime Logs page unless the map sets `redirect`.
8. Node pickers must support: grouped candidates (by node `group`), search, single/multi/ordered-multi/custom-value
   modes, and must always post a value for ListValue (first candidate if unset).
