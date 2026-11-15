//! HeshmatWall: a phone-friendly web app (PWA) for passwall2 with its own login, separate
//! from LuCI.
//!
//! * Static app: `/www/heshmatwall/` (from `luci-app-passwall2/htdocs/heshmatwall`).
//! * API: `/www/cgi-bin/heshmatwall` → `passwall2 heshmatwall cgi` (uhttpd CGI). Every request
//!   is `POST` with a JSON object `{action, token?, ...}`; the answer is
//!   `{"ok": true, ...}` or `{"ok": false, "error": "<code>"}`.
//! * Settings (LuCI → PassWall 2 → HeshmatWall), section `passwall2.heshmatwall`:
//!   `enabled`, `username`, `password_hash` (PBKDF2-HMAC-SHA256, set through the
//!   `heshmatwall_set_password` rpc), `link_key` (part of the link LuCI shows; required to log
//!   in), `session_hours`.
//! * Sessions: random 256-bit tokens; only their SHA-256 is stored, in `/tmp/heshmatwall/s/`.
//!   A session is tied to the current password and link key, so changing either (or
//!   "log out everywhere") ends all sessions. Five failed logins from one address lock it out
//!   for 10 minutes.
//! * Tokens travel in the JSON body (no cookies), so cross-site requests cannot use them.

mod crypto;

use crate::api;
use crate::rpc::{self, is_sid, Params, Store};
use crate::uci::Config;
use crate::util;
use serde_json::{json, Map, Value};

const SEC: &str = "heshmatwall";
const STATE_DIR: &str = "/tmp/heshmatwall";
const PBKDF2_ITER: u32 = 20_000;
const MAX_BODY: usize = 256 * 1024;
const MAX_FAILS: u32 = 5;
const LOCK_SECS: u64 = 600;
const MIN_PASSWORD: usize = 8;
const REPO_URL: &str = "https://github.com/ParsaKSH/openwrt-passwall-rust";

// ---------------------------------------------------------------- passwords / link / sessions

/// `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`.
pub fn hash_password(pw: &str) -> Option<String> {
    let salt = crypto::random_bytes(16)?;
    let h = crypto::pbkdf2_sha256(pw.as_bytes(), &salt, PBKDF2_ITER);
    Some(format!("pbkdf2-sha256${}${}${}", PBKDF2_ITER, crypto::hex(&salt), crypto::hex(&h)))
}

pub fn verify_password(pw: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
        return false;
    }
    let (Ok(iter), Some(salt), Some(want)) = (parts[1].parse::<u32>(), crypto::unhex(parts[2]), crypto::unhex(parts[3])) else { return false };
    if !(1..=1_000_000).contains(&iter) {
        return false;
    }
    crypto::ct_eq(&crypto::pbkdf2_sha256(pw.as_bytes(), &salt, iter), &want)
}

fn new_link_key() -> Option<String> {
    crypto::random_bytes(12).map(|b| crypto::hex(&b))
}

/// What a session is bound to: changes when the password or the link key changes.
fn generation(cfg: &Config) -> String {
    let src = format!("{}\n{}", cfg.s(SEC, "password_hash"), cfg.s(SEC, "link_key"));
    crypto::hex(&crypto::sha256(src.as_bytes()))[..16].to_string()
}

fn session_dir() -> String {
    format!("{}/s", STATE_DIR)
}

fn session_file(token: &str) -> Option<String> {
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{}/{}", session_dir(), crypto::hex(&crypto::sha256(token.as_bytes()))))
}

fn session_hours(cfg: &Config) -> u64 {
    cfg.get(SEC, "session_hours").and_then(|v| v.parse::<u64>().ok()).filter(|h| (1..=8760).contains(h)).unwrap_or(168)
}

fn create_session(cfg: &Config) -> Option<(String, u64)> {
    let token = crypto::hex(&crypto::random_bytes(32)?);
    let exp = util::epoch() + session_hours(cfg) * 3600;
    util::mkdir(&session_dir());
    let _ = std::fs::set_permissions(STATE_DIR, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    std::fs::write(session_file(&token)?, format!("{}\n{}\n", exp, generation(cfg))).ok()?;
    Some((token, exp))
}

fn session_valid(cfg: &Config, token: &str) -> bool {
    let Some(f) = session_file(token) else { return false };
    let text = util::read(&f);
    let mut it = text.lines();
    let exp = it.next().and_then(|e| e.parse::<u64>().ok()).unwrap_or(0);
    let gen = it.next().unwrap_or("");
    if exp <= util::epoch() || gen != generation(cfg) {
        let _ = std::fs::remove_file(&f);
        return false;
    }
    true
}

pub fn clear_sessions() {
    let _ = std::fs::remove_dir_all(session_dir());
}

fn session_count() -> usize {
    std::fs::read_dir(session_dir()).map(|d| d.count()).unwrap_or(0)
}

// ---------------------------------------------------------------- login rate limit

fn fail_file(ip: &str) -> String {
    format!("{}/f/{}", STATE_DIR, &crypto::hex(&crypto::sha256(ip.as_bytes()))[..20])
}

/// (failures, first failure time) inside the lock window.
fn fail_state(ip: &str) -> (u32, u64) {
    let t = util::read(&fail_file(ip));
    let mut it = t.split_whitespace();
    let n = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let first = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    if util::epoch().saturating_sub(first) > LOCK_SECS {
        (0, 0)
    } else {
        (n, first)
    }
}

fn record_fail(ip: &str) {
    let (n, first) = fail_state(ip);
    let first = if n == 0 { util::epoch() } else { first };
    util::mkdir(&format!("{}/f", STATE_DIR));
    let _ = std::fs::write(fail_file(ip), format!("{} {}", n + 1, first));
}

// ---------------------------------------------------------------- helpers

fn cfg() -> Config {
    Config::load(util::CONFIG)
}

fn err(code: &str) -> Value {
    json!({"ok": false, "error": code})
}

fn rpc_call(method: &str, params: Value) -> Value {
    let p = match params {
        Value::Object(m) => Params(m),
        _ => Params::default(),
    };
    rpc::call_sync(method, &p).unwrap_or(Value::Null)
}

fn restart_service(stop: bool) {
    let _ = util::spawn_bg("/etc/init.d/passwall2", &[if stop { "stop" } else { "restart" }.to_string()], "/dev/null");
}

fn is_port(v: &str) -> bool {
    v.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

fn type_label(t: &str, proto: &str) -> String {
    match proto {
        "_shunt" => "Shunt".into(),
        "_balancing" => "Balancing".into(),
        "_urltest" => "URLTest".into(),
        "_iface" => "Interface".into(),
        "_json" => "JSON".into(),
        _ if t == "Xray" || t == "sing-box" => api::protocol_display(proto).to_uppercase(),
        _ if t == "SS-Rust" => "SS".into(),
        _ => t.to_uppercase(),
    }
}

/// Connectivity check URL: first user-defined check site, else Google's 204.
fn check_url(c: &Config) -> String {
    c.list("@global_other[0]", "connect_site")
        .iter()
        .find_map(|v| v.split_once('|').map(|(_, u)| u.to_string()).filter(|u| u.starts_with("http")))
        .unwrap_or_else(|| "https://www.google.com/generate_204".into())
}

// ---------------------------------------------------------------- actions

fn overview() -> Value {
    let c = cfg();
    let g = |k: &str, d: &str| c.get_or("@global[0]", k, d);
    let running = rpc_call("index_status", json!({}))["global_status"].as_bool().unwrap_or(false);
    let now_use = rpc_call("get_now_use_node", json!({}))["global"].as_str().map(|s| s.to_string());
    let mut seen = std::collections::HashSet::new();
    let mut nodes = vec![];
    let mut groups: Vec<String> = vec![];
    for vn in api::get_valid_nodes(&c) {
        let s = &vn.section;
        if !seen.insert(s.name.clone()) {
            continue;
        }
        let group = s.get("group").filter(|g| !g.is_empty()).unwrap_or_default();
        if !groups.contains(&group) {
            groups.push(group.clone());
        }
        let t = s.s("type");
        let p = s.s("protocol");
        nodes.push(json!({
            "id": s.name,
            "remarks": s.s("remarks"),
            "type": type_label(&t, &p),
            "core": api::type_display(&t),
            "address": if p.starts_with('_') { String::new() } else { s.s("address") },
            "port": if p.starts_with('_') { String::new() } else { s.s("port") },
            "group": group,
            "special": p.starts_with('_') && p != "_json",
        }));
    }
    let subs: Vec<Value> = c
        .sections_of("subscribe_list")
        .map(|s| json!({"id": s.name, "remark": s.s("remark"), "url": s.s("url")}))
        .collect();
    json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "repo": REPO_URL,
        "running": running,
        "enabled": g("enabled", "0") == "1",
        "node": g("node", ""),
        "now_use": now_use,
        "groups": groups,
        "nodes": nodes,
        "subscriptions": subs,
        "settings": settings_of(&c),
    })
}

/// Settings the app may read and change (all under `@global[0]`).
const SETTING_KEYS: [(&str, &str); 11] = [
    ("proxy_mode", "tproxy"),
    ("node_socks_port", "1070"),
    ("socks_mode_listen", "0.0.0.0"),
    ("socks_mode_http_port", ""),
    ("localhost_proxy", "1"),
    ("client_proxy", "1"),
    ("remote_dns_protocol", "tcp"),
    ("remote_dns", "1.1.1.1"),
    ("remote_dns_doh", "https://1.1.1.1/dns-query"),
    ("direct_dns_protocol", ""),
    ("direct_dns", ""),
];

fn settings_of(c: &Config) -> Value {
    let mut m = Map::new();
    for (k, d) in SETTING_KEYS {
        m.insert(k.into(), c.get_or("@global[0]", k, d).into());
    }
    Value::Object(m)
}

fn host_port_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 255 && v.bytes().all(|c| c.is_ascii_alphanumeric() || b".:-[]_#".contains(&c))
}

/// Validate one setting; `Some(None)` = unset, `Some(Some(v))` = set, `None` = invalid.
fn check_setting(k: &str, v: &str) -> Option<Option<String>> {
    let v = v.trim();
    let ok = match k {
        "proxy_mode" => matches!(v, "tproxy" | "socks"),
        "node_socks_port" => is_port(v),
        "socks_mode_listen" => matches!(v, "0.0.0.0" | "127.0.0.1"),
        "socks_mode_http_port" => v.is_empty() || is_port(v),
        "localhost_proxy" | "client_proxy" => matches!(v, "0" | "1"),
        "remote_dns_protocol" => matches!(v, "tcp" | "udp" | "doh"),
        "remote_dns" => host_port_ok(v),
        "remote_dns_doh" => v.starts_with("https://") && v.len() <= 512 && v.bytes().all(|c| c.is_ascii_graphic()),
        "direct_dns_protocol" => matches!(v, "" | "udp" | "tcp" | "dot" | "doh"),
        "direct_dns" => v.is_empty() || v.len() <= 512 && v.bytes().all(|c| c.is_ascii_graphic()),
        _ => false,
    };
    ok.then(|| (!v.is_empty()).then(|| v.to_string()))
}

fn settings_set(req: &Map<String, Value>) -> Value {
    let Some(Value::Object(s)) = req.get("settings") else { return err("bad_request") };
    let mut st = Store::load(util::CONFIG);
    for (k, v) in s {
        let v = match v {
            Value::String(x) => x.clone(),
            Value::Bool(b) => if *b { "1" } else { "0" }.into(),
            Value::Number(n) => n.to_string(),
            _ => return err("bad_value"),
        };
        match check_setting(k, &v) {
            Some(Some(v)) => st.set("@global[0]", k, &v),
            Some(None) => st.del("@global[0]", k),
            None => return json!({"ok": false, "error": "bad_value", "field": k}),
        }
    }
    st.save(false);
    if cfg().get_or("@global[0]", "enabled", "0") == "1" {
        restart_service(false);
    }
    json!({"ok": true})
}

fn select_node(id: &str) -> Value {
    let c = cfg();
    if !is_sid(id) || c.stype(id).as_deref() != Some("nodes") {
        return err("no_such_node");
    }
    let mut st = Store::load(util::CONFIG);
    st.set("@global[0]", "node", id);
    st.save(false);
    if c.get_or("@global[0]", "enabled", "0") == "1" {
        restart_service(false);
    }
    json!({"ok": true})
}

fn toggle(on: bool) -> Value {
    let c = cfg();
    if on && c.s("@global[0]", "node").is_empty() {
        return err("no_node_selected");
    }
    let mut st = Store::load(util::CONFIG);
    st.set("@global[0]", "enabled", if on { "1" } else { "0" });
    st.save(false);
    restart_service(!on);
    json!({"ok": true})
}

fn test_node(id: &str, kind: &str) -> Value {
    let c = cfg();
    if !is_sid(id) || c.stype(id).as_deref() != Some("nodes") {
        return err("no_such_node");
    }
    let ms = if kind == "tcp" {
        let (a, p) = (c.s(id, "address"), c.s(id, "port"));
        if a.is_empty() || !is_port(&p) {
            None
        } else {
            rpc_call("ping_node", json!({"address": a, "port": p, "type": "tcping"}))["ping"].as_str().and_then(|v| v.parse::<i64>().ok())
        }
    } else {
        rpc_call("urltest_node", json!({"id": id}))["use_time"].as_str().and_then(|v| v.parse::<f64>().ok()).map(|v| v as i64)
    };
    json!({"ok": true, "id": id, "ms": ms.filter(|m| *m > 0).unwrap_or(-1)})
}

/// Through the running proxy: the SOCKS port in SOCKS-only mode, else the router itself
/// (transparently proxied).
fn check_connection() -> Value {
    let c = cfg();
    let url = check_url(&c);
    let mut args: Vec<String> = ["--connect-timeout", "5", "-m", "10", "-o", "/dev/null", "-sk", "-w", "%{http_code} %{time_total}"].iter().map(|s| s.to_string()).collect();
    if c.get_or("@global[0]", "proxy_mode", "tproxy") == "socks" {
        args.push("-x".into());
        args.push(format!("socks5h://127.0.0.1:{}", c.get_or("@global[0]", "node_socks_port", "1070")));
    }
    args.push(url.clone());
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = util::cmd_out("curl", &a);
    let mut it = out.split_whitespace();
    let code = it.next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
    let secs = it.next().and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    if (200..400).contains(&code) {
        json!({"ok": true, "url": url, "code": code, "ms": (secs * 1000.0).round() as i64})
    } else {
        json!({"ok": true, "url": url, "code": code, "ms": -1})
    }
}

fn node_count() -> usize {
    cfg().sections_of("nodes").count()
}

fn import_links(text: &str) -> Value {
    let text = text.trim();
    if text.is_empty() || text.len() > 200_000 {
        return err("bad_request");
    }
    let before = node_count();
    rpc_call("link_add_node", json!({"chunk": text, "chunk_index": 0, "total_chunks": 1}));
    json!({"ok": true, "added": node_count().saturating_sub(before)})
}

fn delete_nodes(ids: &[Value]) -> Value {
    let ids: Vec<&str> = ids.iter().filter_map(|v| v.as_str()).filter(|s| is_sid(s)).collect();
    if ids.is_empty() {
        return err("bad_request");
    }
    rpc_call("delete_select_nodes", json!({"ids": ids.join(",")}));
    json!({"ok": true})
}

fn sub_add(remark: &str, url: &str) -> Value {
    let remark = remark.trim();
    let url = url.trim();
    if remark.is_empty() || remark.chars().count() > 64 || remark.chars().any(|c| c.is_control()) {
        return err("bad_remark");
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.len() > 2048 || !api::curl_url_ok(url) {
        return err("bad_url");
    }
    let c = cfg();
    if c.sections_of("subscribe_list").any(|s| s.s("remark") == remark || s.s("url") == url) {
        return err("duplicate");
    }
    let id = format!("sub_{}", api::gen_random_char(5));
    let mut st = Store::load(util::CONFIG);
    st.add_section(&id, "subscribe_list");
    st.set(&id, "remark", remark);
    st.set(&id, "url", url);
    st.save(false);
    json!({"ok": true, "id": id})
}

fn sub_delete(id: &str) -> Value {
    if !is_sid(id) || cfg().stype(id).as_deref() != Some("subscribe_list") {
        return err("no_such_subscription");
    }
    let mut st = Store::load(util::CONFIG);
    st.del_section(id);
    st.save(false);
    json!({"ok": true})
}

fn sub_update(id: &str) -> Value {
    let target = if id.is_empty() { "all".to_string() } else { id.to_string() };
    if target != "all" && (!is_sid(&target) || cfg().stype(&target).as_deref() != Some("subscribe_list")) {
        return err("no_such_subscription");
    }
    let _ = util::spawn_bg(util::SELF_BIN, &["subscribe".into(), "start".into(), target, "manual".into()], "/dev/null");
    json!({"ok": true})
}

fn get_log() -> Value {
    let text = util::read(util::LOG_FILE);
    let lines: Vec<&str> = text.lines().collect();
    let tail = lines[lines.len().saturating_sub(500)..].join("\n");
    json!({"ok": true, "log": tail})
}

fn s<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// Handle one API request (already parsed); `ip` = client address for the rate limit.
pub fn handle(req: &Map<String, Value>, ip: &str) -> (u16, Value) {
    let c = cfg();
    if c.get_or(SEC, "enabled", "0") != "1" {
        return (403, err("disabled"));
    }
    let action = s(req, "action");
    match action {
        "hello" => return (200, json!({"ok": true, "app": "HeshmatWall", "version": env!("CARGO_PKG_VERSION")})),
        "login" => {
            let (fails, first) = fail_state(ip);
            if fails >= MAX_FAILS {
                let wait = LOCK_SECS.saturating_sub(util::epoch().saturating_sub(first));
                return (429, json!({"ok": false, "error": "locked", "retry_after": wait}));
            }
            let link = s(req, "link");
            let key = c.s(SEC, "link_key");
            let hash = c.s(SEC, "password_hash");
            let user_ok = crypto::ct_eq(s(req, "username").as_bytes(), c.get_or(SEC, "username", "admin").as_bytes());
            let link_ok = !key.is_empty() && crypto::ct_eq(link.as_bytes(), key.as_bytes());
            // always run the KDF so timing does not reveal which part was wrong
            let pw_ok = verify_password(s(req, "password"), if hash.is_empty() { "pbkdf2-sha256$1$00$00" } else { &hash });
            if hash.is_empty() {
                return (403, err("no_password"));
            }
            if !(user_ok && link_ok && pw_ok) {
                record_fail(ip);
                return (401, err(if link_ok { "bad_credentials" } else { "bad_link" }));
            }
            let _ = std::fs::remove_file(fail_file(ip));
            return match create_session(&c) {
                Some((token, exp)) => (200, json!({"ok": true, "token": token, "expires": exp})),
                None => (500, err("session")),
            };
        }
        _ => {}
    }
    let token = s(req, "token");
    if !session_valid(&c, token) {
        return (401, err("auth"));
    }
    let v = match action {
        "logout" => {
            if let Some(f) = session_file(token) {
                let _ = std::fs::remove_file(f);
            }
            json!({"ok": true})
        }
        "overview" => overview(),
        "select" => select_node(s(req, "id")),
        "toggle" => toggle(req.get("on").and_then(|v| v.as_bool()).unwrap_or(false)),
        "restart" => {
            restart_service(false);
            json!({"ok": true})
        }
        "test" => test_node(s(req, "id"), s(req, "kind")),
        "check" => check_connection(),
        "import" => import_links(s(req, "text")),
        "delete" => delete_nodes(req.get("ids").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[])),
        "sub_add" => sub_add(s(req, "remark"), s(req, "url")),
        "sub_delete" => sub_delete(s(req, "id")),
        "sub_update" => sub_update(s(req, "id")),
        "settings" => settings_set(req),
        "log" => get_log(),
        "clear_log" => {
            rpc_call("clear_log", json!({}));
            json!({"ok": true})
        }
        _ => return (400, err("unknown_action")),
    };
    (200, v)
}

// ---------------------------------------------------------------- CGI

fn reply(status: u16, body: &Value) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    print!(
        "Status: {} {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\r\n{}",
        status, reason, body
    );
}

/// `passwall2 heshmatwall cgi`: one uhttpd CGI request.
pub fn cgi() -> i32 {
    use std::io::Read;
    if std::env::var("REQUEST_METHOD").as_deref() != Ok("POST") {
        reply(405, &err("post_only"));
        return 0;
    }
    let len = std::env::var("CONTENT_LENGTH").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    if len == 0 || len > MAX_BODY {
        reply(413, &err("bad_size"));
        return 0;
    }
    let mut body = vec![0u8; len];
    if std::io::stdin().read_exact(&mut body).is_err() {
        reply(400, &err("bad_request"));
        return 0;
    }
    let Ok(Value::Object(req)) = serde_json::from_slice::<Value>(&body) else {
        reply(400, &err("bad_json"));
        return 0;
    };
    let ip = std::env::var("REMOTE_ADDR").unwrap_or_default();
    let (status, v) = handle(&req, &ip);
    reply(status, &v);
    0
}

// ---------------------------------------------------------------- LuCI-side admin (rpc)

/// `heshmatwall_info`: state for the LuCI settings page (never the hash).
pub fn admin_info() -> Value {
    let c = cfg();
    json!({
        "enabled": c.get_or(SEC, "enabled", "0") == "1",
        "username": c.get_or(SEC, "username", "admin"),
        "has_password": !c.s(SEC, "password_hash").is_empty(),
        "link_key": c.s(SEC, "link_key"),
        "sessions": session_count(),
    })
}

fn ensure_section(st: &mut Store) {
    if !st.exists(SEC) {
        st.add_section(SEC, SEC);
        st.set(SEC, "enabled", "0");
        st.set(SEC, "username", "admin");
    }
}

/// `heshmatwall_set_password {username, password}`: store the hash, create a link key if
/// there is none, end all sessions.
pub fn admin_set_password(p: &Params) -> Value {
    let pw = p.s("password");
    let user = p.get("username").map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    if pw.chars().count() < MIN_PASSWORD || pw.len() > 256 {
        return json!({"code": 0, "msg": format!("The password must be at least {} characters.", MIN_PASSWORD)});
    }
    if let Some(u) = &user {
        if u.len() > 64 || !u.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-@".contains(&c)) {
            return json!({"code": 0, "msg": "Invalid username."});
        }
    }
    let Some(hash) = hash_password(&pw) else { return json!({"code": 0, "msg": "No random source."}) };
    let mut st = Store::load(util::CONFIG);
    ensure_section(&mut st);
    st.set(SEC, "password_hash", &hash);
    if let Some(u) = user {
        st.set(SEC, "username", &u);
    }
    if st.get(SEC, "link_key").unwrap_or_default().is_empty() {
        match new_link_key() {
            Some(k) => st.set(SEC, "link_key", &k),
            None => return json!({"code": 0, "msg": "No random source."}),
        }
    }
    st.save(false);
    clear_sessions();
    json!({"code": 1})
}

/// `heshmatwall_regen_link`: new link key (old links and all sessions stop working).
pub fn admin_regen_link() -> Value {
    let Some(k) = new_link_key() else { return json!({"code": 0, "msg": "No random source."}) };
    let mut st = Store::load(util::CONFIG);
    ensure_section(&mut st);
    st.set(SEC, "link_key", &k);
    st.save(false);
    clear_sessions();
    json!({"code": 1, "link_key": k})
}

/// `heshmatwall_logout_all`.
pub fn admin_logout_all() -> Value {
    clear_sessions();
    json!({"code": 1})
}

pub fn cli(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        Some("cgi") => cgi(),
        Some("logout-all") => {
            clear_sessions();
            0
        }
        _ => {
            eprintln!("usage: passwall2 heshmatwall cgi|logout-all");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("pbkdf2-sha256$20000$"));
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("correct horsE", &h));
        assert!(!verify_password("x", "plain"));
        assert!(!verify_password("x", "pbkdf2-sha256$0$00$00"));
        assert_ne!(hash_password("a").unwrap(), hash_password("a").unwrap(), "salted");
    }
    #[test]
    fn settings_validation() {
        assert_eq!(check_setting("proxy_mode", "socks"), Some(Some("socks".into())));
        assert_eq!(check_setting("proxy_mode", "x"), None);
        assert_eq!(check_setting("node_socks_port", "70000"), None);
        assert_eq!(check_setting("socks_mode_http_port", ""), Some(None));
        assert_eq!(check_setting("remote_dns", "8.8.8.8:53"), Some(Some("8.8.8.8:53".into())));
        assert_eq!(check_setting("remote_dns", "1.1.1.1;reboot"), None);
        assert_eq!(check_setting("remote_dns_doh", "http://x"), None);
        assert_eq!(check_setting("enabled", "1"), None, "not in the whitelist");
    }
    #[test]
    fn session_file_rejects_bad_tokens() {
        assert!(session_file("../../etc/passwd").is_none());
        assert!(session_file(&"a".repeat(64)).is_some());
        assert!(session_file(&"g".repeat(64)).is_none());
    }
}
