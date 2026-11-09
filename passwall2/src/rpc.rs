//! rpcd exec plugin `luci.passwall2`: every upstream controller endpoint.
//! Spec: docs/spec/07-controller-sharelink.md §A, contract: docs/ARCHITECTURE.md "rpcd contract".
//!
//! Installed as `/usr/libexec/rpcd/luci.passwall2` (`exec /usr/bin/passwall2 rpc "$@"`):
//! * `passwall2 rpc list`             → `{ "<method>": { "<param>": <example>, ... }, ... }`
//! * `passwall2 rpc call <method>`    → JSON params on stdin, one JSON object on stdout.
//!   (For debugging a JSON argument may follow the method instead of stdin.)
//! * `passwall2 rpc job <id>`         → internal: runs a queued asynchronous call (see below).
//!
//! Method names / params / results are upstream's (`luasrc/controller/passwall2.lua`). Bare
//! upstream results (arrays, text, redirects) are wrapped as `{"result": ...}`; endpoints that
//! upstream answers with an HTTP redirect also return `"redirect": "<page under
//! admin/services/passwall2>"` so the JS frontend can navigate the same way.
//!
//! Component endpoints are generalized: `com_check {com}`, `com_update {com, task, ...}`,
//! `com_version {com}` with com ∈ geoview | xray | sing-box | passwall2. The upstream route
//! names (`check_xray`, `update_sing-box`, `version_geoview`, `check_passwall2`,
//! `update_passwall2`, ...) are also accepted as aliases.
//!
//! **Asynchronous calls.** LuCI's JS rpc gives up after 20 s and uhttpd after 60 s, while
//! upstream's XHRs for downloads/checks may run for minutes. Any method accepts the extra
//! param `async: "1"`: the call is then run detached (`/usr/bin/passwall2 rpc job <id>`) and
//! `{"job": "<id>"}` is returned at once; `job_status {job}` returns `{"done": false}` while it
//! runs and `{"done": true, "result": <the method's normal result>}` when finished.
//!
//! Extra methods (no upstream endpoint; replace server-side rendering of the Lua CBI pages):
//! `job_status`, `get_env`, `get_valid_nodes`, `get_node_list`, `set_auto_lang`,
//! `reorder_sections`, `rule_status`.

mod env;
mod jobs;
mod nodes;
mod params;
mod status;
mod store;
mod system;

pub use params::{is_safe_name, is_sid, is_sref, split_keep_empty, split_nonempty, Params};
pub use store::{section_json, Store};

use serde_json::{json, Map, Value};
use std::io::Read;

/// Example value kind of a parameter in `rpc list` (rpcd derives the blobmsg type from it).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// string (`"String"`)
    S,
    /// integer (`0`)
    I,
}

/// One rpc method: name + parameter signature.
pub struct Method {
    pub name: &'static str,
    pub params: &'static [(&'static str, Kind)],
}

use Kind::{I, S};

macro_rules! m {
    ($name:expr) => {
        Method { name: $name, params: &[] }
    };
    ($name:expr, $($p:expr => $k:expr),+ $(,)?) => {
        Method { name: $name, params: &[$(($p, $k)),+] }
    };
}

/// Every method served by `luci.passwall2` (order = `rpc list` order).
pub static METHODS: &[Method] = &[
    // ---- status
    m!("index_status"),
    m!("haproxy_status"),
    m!("socks_status", "index" => S, "id" => S),
    m!("connect_status", "type" => S, "url" => S, "async" => S),
    m!("ping_node", "index" => S, "address" => S, "port" => S, "type" => S),
    m!("urltest_node", "index" => S, "id" => S, "async" => S),
    m!("get_now_use_node"),
    // ---- logs
    m!("get_redir_log", "id" => S),
    m!("get_socks_log", "name" => S),
    m!("get_log"),
    m!("clear_log"),
    // ---- server side
    m!("server_update_config", "id" => S, "data" => S),
    m!("server_status", "index" => S, "id" => S),
    m!("server_log", "id" => S),
    m!("server_get_log"),
    m!("server_clear_log"),
    // ---- nodes
    m!("link_add_node", "chunk" => S, "chunk_index" => I, "total_chunks" => I, "group" => S, "async" => S),
    m!("socks_autoswitch_add_node", "id" => S, "key" => S),
    m!("socks_autoswitch_remove_node", "id" => S, "key" => S),
    m!("gen_client_config", "id" => S),
    m!("update_config", "id" => S, "data" => S),
    m!("add_node", "redirect" => S, "group" => S),
    m!("set_node", "type" => S, "config" => S, "section" => S),
    m!("copy_node", "section" => S),
    m!("clear_all_nodes"),
    m!("delete_select_nodes", "ids" => S, "redirect" => S),
    m!("reassign_group", "ids" => S, "group" => S),
    m!("get_node", "id" => S),
    m!("save_node_list_opt", "option" => S, "value" => S),
    // ---- rules
    m!("update_rules", "update" => S),
    m!("rollback_rules", "type" => S),
    m!("get_shunt_rules", "id" => S),
    m!("add_shunt_rule", "add_name" => S, "redirect" => S, "group" => S),
    m!("delete_select_shunt_rules", "ids" => S, "redirect" => S),
    m!("geo_view", "action" => S, "value" => S, "async" => S),
    m!("flush_set", "redirect" => S, "reload" => S),
    // ---- subscribe
    m!("subscribe_del_node", "remark" => S, "async" => S),
    m!("subscribe_del_all", "async" => S),
    m!("subscribe_manual", "section" => S, "url" => S),
    m!("subscribe_manual_all", "sections" => S, "urls" => S),
    // ---- components / self update
    m!("com_check", "com" => S, "arch" => S, "accept_language" => S, "async" => S),
    m!(
        "com_update",
        "com" => S, "task" => S, "url" => S, "size" => S, "id" => S, "part" => S, "total_size" => S,
        "file" => S, "subfix" => S, "force" => S, "languages" => S, "async" => S
    ),
    m!("com_version", "com" => S),
    // ---- backup / misc
    m!("create_backup"),
    m!("restore_backup", "filename" => S, "chunk" => S, "chunk_index" => I, "total_chunks" => I),
    m!("reset_config", "async" => S),
    m!("show"),
    m!("hide"),
    m!("show_menu"),
    m!("hide_menu"),
    m!("fetch_certsha256", "id" => S, "async" => S),
    m!("gen_wireguard_key"),
    // ---- extras (no upstream endpoint)
    m!("job_status", "job" => S),
    m!("get_env"),
    m!("get_valid_nodes"),
    m!("get_node_list"),
    m!("set_auto_lang", "accept_language" => S),
    m!("reorder_sections", "config" => S, "ids" => S),
    m!("rule_status"),
];

/// Upstream per-component route aliases → (generic method, com).
fn com_alias(method: &str) -> Option<(&'static str, String)> {
    for (pfx, generic) in [("check_", "com_check"), ("update_", "com_update"), ("version_", "com_version")] {
        if let Some(c) = method.strip_prefix(pfx) {
            if c == "passwall2" && generic != "com_version" {
                return Some((generic, c.to_string()));
            }
            if api_com_order().contains(&c) {
                return Some((generic, c.to_string()));
            }
        }
    }
    None
}

fn api_com_order() -> &'static [&'static str] {
    &crate::api::COM_ORDER
}

/// Signature of the generic com methods, reused for the aliases.
fn method_params(name: &str) -> Option<&'static [(&'static str, Kind)]> {
    METHODS.iter().find(|m| m.name == name).map(|m| m.params)
}

fn sig_json(params: &[(&str, Kind)], skip: &[&str]) -> Value {
    let mut o = Map::new();
    for (p, k) in params {
        if skip.contains(p) {
            continue;
        }
        o.insert((*p).to_string(), match k {
            Kind::S => json!("String"),
            Kind::I => json!(0),
        });
    }
    Value::Object(o)
}

/// `rpc list` output.
pub fn list_json() -> Value {
    let mut out = Map::new();
    for m in METHODS {
        out.insert(m.name.to_string(), sig_json(m.params, &[]));
    }
    // upstream route names of the component endpoints
    let mut aliases: Vec<String> = vec!["check_passwall2".into(), "update_passwall2".into()];
    for c in api_com_order() {
        for p in ["check_", "update_", "version_"] {
            aliases.push(format!("{}{}", p, c));
        }
    }
    for a in aliases {
        if let Some((g, _)) = com_alias(&a) {
            if let Some(p) = method_params(g) {
                out.insert(a, sig_json(p, &["com"]));
            }
        }
    }
    Value::Object(out)
}

/// true if `method` is served (directly or as an alias).
pub fn has_method(method: &str) -> bool {
    METHODS.iter().any(|m| m.name == method) || com_alias(method).is_some()
}

/// Dispatch one call. `async: "1"` queues it as a background job (except `job_status`).
/// None = unknown method.
pub fn call(method: &str, params: &Params) -> Option<Value> {
    if !has_method(method) {
        return None;
    }
    if method != "job_status" && params.get("async").as_deref() == Some("1") {
        return Some(jobs::spawn(method, params));
    }
    call_sync(method, params)
}

/// Run a method in this process (no async handling). None = unknown method.
pub fn call_sync(method: &str, p: &Params) -> Option<Value> {
    if let Some((generic, com)) = com_alias(method) {
        let mut p2 = p.clone();
        p2.set("com", &com);
        return call_sync(generic, &p2);
    }
    let v = match method {
        "index_status" => status::index_status(),
        "haproxy_status" => status::haproxy_status(),
        "socks_status" => status::socks_status(p),
        "connect_status" => status::connect_status(p),
        "ping_node" => status::ping_node(p),
        "urltest_node" => status::urltest_node(p),
        "get_now_use_node" => status::get_now_use_node(),
        "get_redir_log" => status::get_redir_log(p),
        "get_socks_log" => status::get_socks_log(p),
        "get_log" => status::get_log(),
        "clear_log" => status::clear_log(),
        "server_update_config" => nodes::server_update_config(p),
        "server_status" => status::server_status(p),
        "server_log" => status::server_log(p),
        "server_get_log" => status::server_get_log(),
        "server_clear_log" => status::server_clear_log(),
        "link_add_node" => system::link_add_node(p),
        "socks_autoswitch_add_node" => nodes::socks_autoswitch(p, true),
        "socks_autoswitch_remove_node" => nodes::socks_autoswitch(p, false),
        "gen_client_config" => system::gen_client_config(p),
        "update_config" => nodes::update_config(p),
        "add_node" => nodes::add_node(p),
        "set_node" => nodes::set_node(p),
        "copy_node" => nodes::copy_node(p),
        "clear_all_nodes" => nodes::clear_all_nodes(),
        "delete_select_nodes" => nodes::delete_select_nodes(p),
        "reassign_group" => nodes::reassign_group(p),
        "get_node" => nodes::get_node(p),
        "save_node_list_opt" => nodes::save_node_list_opt(p),
        "update_rules" => system::update_rules(p),
        "rollback_rules" => system::rollback_rules(p),
        "get_shunt_rules" => nodes::get_shunt_rules(p),
        "add_shunt_rule" => nodes::add_shunt_rule(p),
        "delete_select_shunt_rules" => nodes::delete_select_shunt_rules(p),
        "geo_view" => system::geo_view(p),
        "flush_set" => system::flush_set(p),
        "subscribe_del_node" => system::subscribe_del_node(p),
        "subscribe_del_all" => system::subscribe_del_all(),
        "subscribe_manual" => system::subscribe_manual(p),
        "subscribe_manual_all" => system::subscribe_manual_all(p),
        "com_check" => system::com_check(p),
        "com_update" => system::com_update(p),
        "com_version" => system::com_version(p),
        "create_backup" => system::create_backup(),
        "restore_backup" => system::restore_backup(p),
        "reset_config" => system::reset_config(),
        "show" | "show_menu" => system::show_menu(),
        "hide" | "hide_menu" => system::hide_menu(),
        "fetch_certsha256" => system::fetch_certsha256(p),
        "gen_wireguard_key" => system::gen_wireguard_key(),
        "job_status" => jobs::status(p),
        "get_env" => env::get_env(),
        "get_valid_nodes" => env::get_valid_nodes(),
        "get_node_list" => env::get_node_list(),
        "set_auto_lang" => system::set_auto_lang(p),
        "reorder_sections" => nodes::reorder_sections(p),
        "rule_status" => crate::rules::status_json(),
        _ => return None,
    };
    Some(v)
}

/// Path of our own binary for re-invocation (background jobs, subscribe, app).
pub(crate) fn self_bin() -> String {
    if crate::util::is_executable(crate::util::SELF_BIN) {
        return crate::util::SELF_BIN.to_string();
    }
    std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| crate::util::SELF_BIN.to_string())
}

/// Run `passwall2 <args>` synchronously with all stdio detached (so that no grandchild can
/// keep rpcd's stdout pipe open). Returns the exit code (-1 if it could not run).
pub(crate) fn run_self(args: &[&str]) -> i32 {
    use std::process::{Command, Stdio};
    Command::new(self_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(-1)
}

/// Start `passwall2 <args>` detached in the background (setsid, stdio → /dev/null).
pub(crate) fn spawn_self(args: &[&str]) {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    crate::util::spawn_bg(&self_bin(), &a, "/dev/null");
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string(v).unwrap_or_else(|_| "{}".into()));
}

/// `passwall2 rpc <list|call <method>|job <id>>`
pub fn cli(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        Some("list") => {
            print_json(&list_json());
            0
        }
        Some("call") => {
            let Some(method) = args.get(1) else {
                print_json(&json!({"error": "Missing method"}));
                return 1;
            };
            let input = match args.get(2) {
                Some(a) => a.clone(),
                None => {
                    let mut s = String::new();
                    let _ = std::io::stdin().read_to_string(&mut s);
                    s
                }
            };
            let params = Params::from_json(&input);
            match call(method, &params) {
                Some(v) => {
                    print_json(&v);
                    0
                }
                None => {
                    print_json(&json!({"error": "Method not found"}));
                    1
                }
            }
        }
        Some("job") => match args.get(1) {
            Some(id) => jobs::run(id),
            None => 1,
        },
        _ => {
            eprintln!("usage: passwall2 rpc list | call <method> [json] | job <id>");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_object_of_objects() {
        let v = list_json();
        let o = v.as_object().unwrap();
        assert!(o.len() > 60);
        for (k, sig) in o {
            assert!(sig.is_object(), "{}", k);
        }
        assert_eq!(o["restore_backup"]["chunk_index"], json!(0));
        assert_eq!(o["socks_status"]["id"], json!("String"));
        // aliases do not advertise `com`
        assert!(o.contains_key("check_sing-box"));
        assert!(o.contains_key("update_passwall2"));
        assert!(o.contains_key("version_geoview"));
        assert!(!o.contains_key("version_passwall2"));
        assert!(o["update_xray"].get("com").is_none());
        assert!(o["update_xray"].get("task").is_some());
    }

    #[test]
    fn every_listed_method_dispatches() {
        // names must be unique and known to has_method
        let mut seen = std::collections::HashSet::new();
        for m in METHODS {
            assert!(seen.insert(m.name), "duplicate {}", m.name);
            assert!(has_method(m.name));
        }
        assert!(!has_method("nope"));
        assert!(!has_method("check_nope"));
        assert_eq!(com_alias("check_xray"), Some(("com_check", "xray".to_string())));
        assert_eq!(com_alias("update_sing-box"), Some(("com_update", "sing-box".to_string())));
        assert_eq!(com_alias("check_passwall2"), Some(("com_check", "passwall2".to_string())));
        assert_eq!(com_alias("version_passwall2"), None);
        assert_eq!(com_alias("clear_log"), None);
    }

    #[test]
    fn unknown_method_is_none() {
        assert!(call("does_not_exist", &Params::default()).is_none());
        assert!(call_sync("does_not_exist", &Params::default()).is_none());
    }

    #[test]
    fn job_status_invalid() {
        let v = call("job_status", &Params::from_json(r#"{"job":"../x"}"#)).unwrap();
        assert_eq!(v["done"], json!(true));
        assert!(v["error"].is_string());
    }
}
