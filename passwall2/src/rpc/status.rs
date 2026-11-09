//! Status, connectivity tests and log endpoints (controller spec 07 §A.3).

use super::params::{is_safe_name, is_sid, Params};
use crate::api;
use crate::uci::Config;
use crate::util;
use serde_json::{json, Map, Value};

/// Command lines of all processes (like `busybox top -bn1`, without ourselves).
fn proc_cmdlines() -> Vec<String> {
    let me = std::process::id();
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        if raw.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(&raw).replace('\0', " ");
        out.push(s.trim_end().to_string());
    }
    out
}

/// `index_status` predicate: a process from `TMP_PATH/bin/` whose cmdline has `/acl_default.json`.
pub fn is_global_running(cmds: &[String]) -> bool {
    let bin = format!("{}/bin/", util::TMP_PATH);
    cmds.iter().any(|c| !c.contains("grep") && c.contains(&bin) && c.contains("/acl_default.json"))
}

/// `haproxy_status` predicate: `grep 'passwall2/bin/' | grep haproxy`.
pub fn is_haproxy_running(cmds: &[String]) -> bool {
    cmds.iter().any(|c| !c.contains("grep") && c.contains("passwall2/bin/") && c.contains("haproxy"))
}

/// `socks_status` predicates: `grep -v -E 'grep|acl/|acl_' | grep 'passwall2/bin/' | grep '<id>'`
/// (+ `grep -E '\+http|_http'` for the HTTP part) → (socks, http).
pub fn socks_running(cmds: &[String], id: &str) -> (bool, bool) {
    let mut socks = false;
    let mut http = false;
    for c in cmds {
        if c.contains("grep") || c.contains("acl/") || c.contains("acl_") {
            continue;
        }
        if c.contains("passwall2/bin/") && c.contains(id) {
            socks = true;
            if c.contains("+http") || c.contains("_http") {
                http = true;
            }
        }
    }
    (socks, http)
}

pub fn index_status() -> Value {
    json!({"global_status": is_global_running(&proc_cmdlines())})
}

pub fn haproxy_status() -> Value {
    json!({"status": is_haproxy_running(&proc_cmdlines())})
}

fn put_index(m: &mut Map<String, Value>, p: &Params) {
    if let Some(v) = p.raw("index") {
        m.insert("index".into(), v.clone());
    }
}

pub fn socks_status(p: &Params) -> Value {
    let id = p.s("id");
    let mut m = Map::new();
    put_index(&mut m, p);
    let (socks, http) = if is_sid(&id) { socks_running(&proc_cmdlines(), &id) } else { (false, false) };
    m.insert("socks_status".into(), socks.into());
    let cfg = Config::load(util::CONFIG);
    // upstream: tonumber(http_port or 0) > 0 (a non-numeric value would raise; treated as 0)
    let http_port = if is_sid(&id) { cfg.get(&id, "http_port").and_then(|v| api::lua_tonumber(&v)).unwrap_or(0.0) } else { 0.0 };
    if http_port > 0.0 {
        m.insert("use_http".into(), 1.into());
        m.insert("http_status".into(), http.into());
    } else {
        m.insert("use_http".into(), 0.into());
    }
    Value::Object(m)
}

pub fn server_status(p: &Params) -> Value {
    let id = p.s("id");
    let mut m = Map::new();
    put_index(&mut m, p);
    m.insert("status".into(), (is_sid(&id) && crate::server::is_running(&id)).into());
    Value::Object(m)
}

/// `connect_status`: `{use_time: ""}` or `{use_time: "123.45", ping_type: "curl"}`.
pub fn connect_status(p: &Params) -> Value {
    let url = p.s("url");
    // upstream passes url unquoted to the shell; we use argv and refuse option-like values
    let t = if url.is_empty() || url.starts_with('-') { None } else { api::connect_status(&url) };
    match t {
        Some(t) => json!({"use_time": t, "ping_type": "curl"}),
        None => json!({"use_time": ""}),
    }
}

pub fn ping_node(p: &Params) -> Value {
    let address = p.s("address");
    let port = p.s("port");
    let typ = p.or("type", "icmp");
    let mut m = Map::new();
    put_index(&mut m, p);
    let ping = if address.is_empty() || address.starts_with('-') || port.starts_with('-') { String::new() } else { api::ping_node(&address, &port, &typ) };
    m.insert("ping".into(), ping.into());
    Value::Object(m)
}

/// `urltest_node`: `{index, use_time}` (use_time absent on failure, like upstream).
pub fn urltest_node(p: &Params) -> Value {
    let mut m = Map::new();
    put_index(&mut m, p);
    if let Some(t) = api::urltest_node(&p.s("id")) {
        m.insert("use_time".into(), t.into());
    }
    Value::Object(m)
}

pub fn get_now_use_node() -> Value {
    match api::get_cache_var("ACL_acl_default_node") {
        Some(n) => json!({"global": n}),
        None => json!({}),
    }
}

/// `tail -n <n>` of a text.
pub fn tail_lines(text: &str, n: usize) -> String {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() <= n {
        return text.to_string();
    }
    let mut s = lines[lines.len() - n..].join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn log_result(path: Option<String>, tail: bool) -> Value {
    match path {
        Some(p) if util::exists(&p) => {
            let t = String::from_utf8_lossy(&std::fs::read(&p).unwrap_or_default()).to_string();
            json!({"result": if tail { tail_lines(&t, 5000) } else { t }})
        }
        _ => json!({"error": api::translate("Not enabled log")}),
    }
}

/// `get_redir_log {id}`: `TMP_PATH/acl/<id>.log` (last 5000 lines).
pub fn get_redir_log(p: &Params) -> Value {
    let id = p.s("id");
    log_result(if is_safe_name(&id) { Some(format!("{}/acl/{}.log", util::TMP_PATH, id)) } else { None }, true)
}

/// `get_socks_log {name}`: `TMP_PATH/<name>.log` (last 5000 lines).
pub fn get_socks_log(p: &Params) -> Value {
    let name = p.s("name");
    log_result(if is_safe_name(&name) { Some(format!("{}/{}.log", util::TMP_PATH, name)) } else { None }, true)
}

pub fn get_log() -> Value {
    json!({"result": util::read(util::LOG_FILE)})
}

pub fn clear_log() -> Value {
    let _ = std::fs::write(util::LOG_FILE, "\n");
    json!({})
}

/// `server_log {id}`: whole `/tmp/etc/passwall2_server/<id>.log`.
pub fn server_log(p: &Params) -> Value {
    let id = p.s("id");
    if !is_safe_name(&id) {
        return log_result(None, false);
    }
    match crate::server::read_server_log(&id) {
        Some(t) => json!({"result": t}),
        None => log_result(None, false),
    }
}

pub fn server_get_log() -> Value {
    json!({"result": crate::server::read_log()})
}

pub fn server_clear_log() -> Value {
    crate::server::clear_log();
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn process_predicates() {
        let cmds = v(&[
            "/tmp/etc/passwall2/bin/xray run -c /tmp/etc/passwall2/acl/default/acl_default.json",
            "/tmp/etc/passwall2/bin/haproxy -f /tmp/etc/passwall2/haproxy.cfg",
            "/tmp/etc/passwall2/bin/xray run -c /tmp/etc/passwall2/SOCKS_socks_a.json",
            "/tmp/etc/passwall2/bin/xray run -c /tmp/etc/passwall2/SOCKS_socks_b_http.json",
        ]);
        assert!(is_global_running(&cmds));
        assert!(is_haproxy_running(&cmds));
        assert_eq!(socks_running(&cmds, "socks_a"), (true, false));
        assert_eq!(socks_running(&cmds, "socks_b"), (true, true));
        assert_eq!(socks_running(&cmds, "socks_c"), (false, false));
        assert!(!is_global_running(&v(&["/usr/bin/xray run -c /tmp/acl_default.json"])));
        // ACL processes are excluded from socks status
        assert_eq!(socks_running(&v(&["/tmp/etc/passwall2/bin/x acl_socks_a"]), "socks_a"), (false, false));
    }

    #[test]
    fn tail() {
        assert_eq!(tail_lines("a\nb\nc\n", 2), "b\nc\n");
        assert_eq!(tail_lines("a\nb\nc", 2), "b\nc");
        assert_eq!(tail_lines("a\n", 5), "a\n");
        assert_eq!(tail_lines("", 5), "");
    }

    #[test]
    fn index_echo() {
        let p = Params::from_json(r#"{"index":3,"address":"-x"}"#);
        let r = ping_node(&p);
        assert_eq!(r["index"], json!(3));
        assert_eq!(r["ping"], json!(""));
        let r = ping_node(&Params::from_json(r#"{"address":""}"#));
        assert!(r.get("index").is_none());
        assert_eq!(connect_status(&Params::from_json(r#"{"url":"--help"}"#)), json!({"use_time": ""}));
        assert!(get_redir_log(&Params::from_json(r#"{"id":"../../etc/passwd"}"#))["error"].is_string());
        assert!(get_socks_log(&Params::default())["error"].is_string());
    }
}
