//! Server side: port of upstream `luasrc/passwall2/server_app.lua` (+ the server part of
//! `util_shadowsocks.lua`) driven by `/etc/init.d/passwall2_server`.
//! Spec: docs/spec/05-api-helpers.md §2, §3 (gen_config_server); 01-runtime-app.md (init.d).
//!
//! CLI: `passwall2 server <start|stop|restart|reload|status [id]|gen_config <id>|log [id]|clear_log>`

use crate::api;
use crate::uci::{Batch, Config, Section};
use crate::util;
use serde_json::{Map, Value};

/// `api.s_config`
pub const CONFIG: &str = util::CONFIG_SERVER;
/// `api.S_TMP_PATH`
pub const CONFIG_PATH: &str = "/tmp/etc/passwall2_server";
/// `"/tmp/log/" .. CONFIG .. ".log"`
pub const LOG_APP_FILE: &str = util::SERVER_LOG_FILE;
/// `CONFIG_PATH .. "/bin"`
pub const TMP_BIN_PATH: &str = "/tmp/etc/passwall2_server/bin";

/// Per-server core log (`log=1`): `/tmp/etc/passwall2_server/<id>.log` (read by `server_log`).
pub fn server_log_path(id: &str) -> String {
    format!("{}/{}.log", CONFIG_PATH, id)
}
/// Generated config file of a server instance.
pub fn server_config_path(id: &str) -> String {
    format!("{}/{}.json", CONFIG_PATH, id)
}

/// `log(...)` of server_app.lua: `"%Y-%m-%d %H:%M:%S: " .. msg` appended to LOG_APP_FILE.
fn log(msg: &str) {
    util::log_server(0, msg);
}

/// Lua `tonumber(v) == 1`
fn tonumber_is_1(v: Option<&str>) -> bool {
    v.and_then(api::lua_tonumber) == Some(1.0)
}

/// Lua `tonumber(s)` as a JSON number (integral values become JSON integers like Lua 5.1 prints them).
fn lua_num(s: Option<String>) -> Option<Value> {
    let f = api::lua_tonumber(&s?)?;
    if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
        Some(Value::from(f as i64))
    } else {
        serde_json::Number::from_f64(f).map(Value::Number)
    }
}

fn put_opt(m: &mut Map<String, Value>, k: &str, v: Option<String>) {
    if let Some(v) = v {
        m.insert(k.into(), Value::String(v));
    }
}

/// `util_shadowsocks.gen_config_server(node)` — SSR / SS-Rust server config.
/// `scfg` is the loaded `passwall2_server` config (to resolve `node.user`).
pub fn gen_config_server_ss(scfg: &Config, node: &Section) -> Value {
    let user = node.get("user").and_then(|u| scfg.section(&u));
    let mut c = Map::new();
    if let Some(p) = lua_num(node.get("port")) {
        c.insert("server_port".into(), p);
    }
    c.insert("password".into(), Value::String(user.and_then(|u| u.get("password")).unwrap_or_default()));
    if let Some(t) = lua_num(node.get("timeout")) {
        c.insert("timeout".into(), t);
    }
    c.insert("fast_open".into(), Value::Bool(node.flag("tcp_fast_open")));
    put_opt(&mut c, "method", node.get("method"));
    let typ = node.s("type");
    if typ == "SS-Rust" {
        c.insert("server".into(), Value::String("::".into()));
        c.insert("mode".into(), Value::String("tcp_and_udp".into()));
    } else {
        c.insert("server".into(), serde_json::json!(["[::0]", "0.0.0.0"]));
    }
    if typ == "SSR" {
        for k in ["protocol", "protocol_param", "obfs", "obfs_param"] {
            put_opt(&mut c, k, node.get(k));
        }
    }
    Value::Object(c)
}

/// `jsonc.parse(api.base64Decode(config_str))` — None when not valid JSON.
fn parse_custom(config_str: &str) -> Option<Value> {
    serde_json::from_str::<Value>(&api::base64_decode(config_str)).ok()
}

/// `config.log = config.log or {}` and return it as a mutable object.
fn log_obj(config: &mut Value) -> Option<&mut Map<String, Value>> {
    let obj = config.as_object_mut()?;
    let entry = obj.entry("log").or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        // upstream quirk: Lua would error indexing a non-table `log`; replace it instead
        *entry = Value::Object(Map::new());
    }
    entry.as_object_mut()
}

/// Lua `t.k = v` (nil removes the key).
fn lua_assign(m: &mut Map<String, Value>, k: &str, v: Option<Value>) {
    match v {
        Some(v) => {
            m.insert(k.into(), v);
        }
        None => {
            m.shift_remove(k);
        }
    }
}

/// How one server instance is started.
#[derive(Debug, Clone, PartialEq)]
pub struct Launch {
    /// symlink source (real binary)
    pub src: String,
    /// symlink name under TMP_BIN_PATH
    pub name: String,
    /// arguments after the binary
    pub args: Vec<String>,
    /// stdout/stderr target (`/dev/null` when logging is off)
    pub output: String,
}

impl Launch {
    pub fn bin_path(&self) -> String {
        format!("{}/{}", TMP_BIN_PATH, self.name)
    }
    /// The shell command upstream's `ln_run` returns (informational / debugging).
    pub fn command_line(&self) -> String {
        format!("{} {} >{} 2>&1 &", self.bin_path(), self.args.join(" "), self.output)
    }
}

/// Result of building one server instance (everything `start()` does except side effects).
#[derive(Debug, Clone)]
pub struct Instance {
    pub id: String,
    pub remarks: String,
    pub config_file: String,
    /// Some(config) → written to `config_file` when non-empty. None = invalid custom config.
    pub config: Option<Value>,
    pub launch: Option<Launch>,
    /// `firewall_allow == "1"` → (src zone, port)
    pub firewall: Option<(String, Option<String>)>,
}

fn ln_run(src: &str, name: &str, args: Vec<String>, output: Option<&str>) -> Launch {
    Launch { src: src.into(), name: name.into(), args, output: output.unwrap_or("/dev/null").into() }
}

/// Build the instance of one enabled `server` section (pure except for calling the
/// xray / sing-box generators, which read UCI).
pub fn build_instance(scfg: &Config, server: &Section) -> Instance {
    let id = server.name.clone();
    let log_path = if server.is("log", "1") { Some(server_log_path(&id)) } else { None };
    let config_file = server_config_path(&id);
    let typ = server.get("type").unwrap_or_default();
    let custom = if server.is("custom", "1") { server.get("config_str") } else { None };
    let loglevel = server.get("loglevel").map(Value::String);
    let mut launch = None;
    let config: Option<Value> = match typ.as_str() {
        "SSR" | "SS-Rust" => {
            let cfg = match &custom {
                Some(s) => parse_custom(s),
                None => Some(gen_config_server_ss(scfg, server)),
            };
            if typ == "SSR" {
                let udp_forward = server.get("udp_forward").and_then(|v| api::lua_tonumber(&v)).unwrap_or(1.0);
                let udp_param = if udp_forward == 1.0 { "-u" } else { "" };
                let t = typ.to_lowercase();
                let mut args = vec!["-c".to_string(), config_file.clone()];
                if !udp_param.is_empty() {
                    args.push(udp_param.into());
                }
                launch = Some(ln_run(&format!("/usr/bin/{}-server", t), &format!("{}-server", t), args, log_path.as_deref()));
            } else {
                launch = Some(ln_run("/usr/bin/ssserver", "ssserver", vec!["-c".into(), config_file.clone()], log_path.as_deref()));
            }
            cfg
        }
        "Xray" => {
            let cfg = match &custom {
                Some(s) => parse_custom(s).map(|mut c| {
                    if log_path.is_some() {
                        if let Some(l) = log_obj(&mut c) {
                            lua_assign(l, "loglevel", loglevel.clone());
                        }
                    }
                    c
                }),
                None => crate::xray::gen_config_server(&id),
            };
            let bin = api::get_app_path("xray").unwrap_or_else(|| "/usr/bin/xray".into());
            launch = Some(ln_run(&bin, "xray", vec!["run".into(), "-c".into(), config_file.clone()], log_path.as_deref()));
            cfg
        }
        "sing-box" => {
            let cfg = match &custom {
                Some(s) => parse_custom(s).map(|mut c| {
                    if let Some(lp) = &log_path {
                        if let Some(l) = log_obj(&mut c) {
                            l.insert("timestamp".into(), Value::Bool(true));
                            l.insert("disabled".into(), Value::Bool(false));
                            lua_assign(l, "level", loglevel.clone());
                            l.insert("output".into(), Value::String(lp.clone()));
                        }
                    }
                    c
                }),
                None => crate::singbox::gen_config_server(&id),
            };
            let bin = api::get_app_path("sing-box").unwrap_or_else(|| "/usr/bin/sing-box".into());
            launch = Some(ln_run(&bin, "sing-box", vec!["run".into(), "-c".into(), config_file.clone()], log_path.as_deref()));
            cfg
        }
        // unknown type: config stays `{}`, nothing written, nothing run
        _ => Some(Value::Object(Map::new())),
    };
    let firewall = if server.is("firewall_allow", "1") {
        Some((server.get("firewall_allow_src").unwrap_or_else(|| "wan".into()), server.get("port").filter(|p| api::lua_tonumber(p).is_some())))
    } else {
        None
    };
    Instance { id, remarks: server.s("remarks"), config_file, config, launch, firewall }
}

/// Lua `next(config)` — non-empty table.
fn is_nonempty(v: &Value) -> bool {
    match v {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Null => false,
        _ => true,
    }
}

/// `ln_run`: `[ ! -f d ] && ln -s src d`, then run `d args >output 2>&1 &`.
fn run_launch(l: &Launch) {
    let d = l.bin_path();
    if !std::path::Path::new(&d).is_file() {
        let _ = std::os::unix::fs::symlink(&l.src, &d);
    }
    if l.output != "/dev/null" {
        // `>output` truncates
        let _ = std::fs::write(&l.output, "");
    }
    let _ = util::spawn_bg(&d, &l.args, &l.output);
}

/// `api.uci_save(uci, "firewall", true, true)`: commit, then let procd reload the
/// firewall like a LuCI (rpcd/ubus) commit does (old-uci path: `/etc/init.d/firewall reload &`).
fn commit_firewall() {
    crate::uci::commit("firewall");
    if std::env::var("PASSWALL2_UCI_DIR").is_ok() {
        return;
    }
    let ok = util::cmd_ok("ubus", &["call", "service", "event", r#"{"type":"config.change","data":{"package":"firewall"}}"#]);
    if !ok {
        util::sh("/etc/init.d/firewall reload >/dev/null 2>&1 &");
    }
}

/// Firewall rule commands for one instance (`uci:section("firewall","rule",uid)` ...).
pub fn firewall_rule_batch(b: &mut Batch, id: &str, src: &str, port: Option<&str>) {
    let uid = format!("{}_{}", CONFIG, id);
    b.section("firewall", &uid, "rule");
    b.set(&format!("firewall.{}.name", uid), &uid);
    b.set(&format!("firewall.{}.src", uid), src);
    if let Some(p) = port.and_then(api::lua_tonumber) {
        // uci:set(..., tonumber(port)) stores the number's string form
        let v = if p.fract() == 0.0 { format!("{}", p as i64) } else { format!("{}", p) };
        b.set(&format!("firewall.{}.dest_port", uid), &v);
    }
    b.set(&format!("firewall.{}.target", uid), "ACCEPT");
}

/// Enabled server sections (`tonumber(enable) == 1`) in config order.
pub fn enabled_servers(scfg: &Config) -> Vec<&Section> {
    scfg.sections_of("server").filter(|s| tonumber_is_1(s.get("enable").as_deref())).collect()
}

/// Master switch: `tonumber(@global[0].enable or 0)` non-nil and non-zero.
pub fn is_enabled(scfg: &Config) -> bool {
    let v = scfg.get("@global[0]", "enable").unwrap_or_else(|| "0".into());
    matches!(api::lua_tonumber(&v), Some(n) if n != 0.0)
}

/// `start()` of server_app.lua.
pub fn start() -> i32 {
    // 26.4-era server sections (`config user` instances) → current schema
    crate::migrate::run("server start");
    let scfg = Config::load(CONFIG);
    if !is_enabled(&scfg) {
        return 0;
    }
    util::mkdir(CONFIG_PATH);
    util::mkdir(TMP_BIN_PATH);
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(LOG_APP_FILE) {
        drop(f);
    } else {
        util::mkdir("/tmp/log");
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(LOG_APP_FILE);
    }
    let mut fw = Batch::new();
    let mut firewall_num = 0;
    for server in enabled_servers(&scfg) {
        let inst = build_instance(&scfg, server);
        let Some(config) = &inst.config else {
            // upstream quirk: Lua crashes here (jsonc.parse → nil, next(nil)) and aborts every
            // following server; we log and skip only this one.
            log(&format!("{} - {}: invalid custom config (config_str is not valid JSON)", inst.remarks, inst.id));
            continue;
        };
        if is_nonempty(config) {
            let text = serde_json::to_string_pretty(config).unwrap_or_default();
            let _ = std::fs::write(&inst.config_file, text);
            log(&format!("{} {} - {}", inst.remarks, api::translate("Generate configuration file and run"), inst.config_file));
        }
        if let Some(l) = &inst.launch {
            run_launch(l);
        }
        if let Some((src, port)) = &inst.firewall {
            firewall_num += 1;
            firewall_rule_batch(&mut fw, &inst.id, src, port.as_deref());
        }
    }
    if firewall_num > 0 {
        let _ = fw.apply();
        commit_firewall();
    }
    0
}

/// Firewall rule sections created by us: `rule[".name"]:find("passwall2_server") == 1`.
pub fn our_firewall_rules(fw: &Config) -> Vec<String> {
    fw.sections_of("rule").filter(|r| r.name.starts_with(CONFIG)).map(|r| r.name.clone()).collect()
}

/// `stop()` of server_app.lua.
pub fn stop() -> i32 {
    // busybox top | grep '/tmp/etc/passwall2_server/' | kill -9
    let pids = util::pgrep_f(&format!("{}/", CONFIG_PATH));
    util::kill_pids(&pids, 9);
    let fw = Config::load("firewall");
    let rules = our_firewall_rules(&fw);
    if !rules.is_empty() {
        let mut b = Batch::new();
        for r in &rules {
            b.delete(&format!("firewall.{}", r));
        }
        let _ = b.apply();
        commit_firewall();
    }
    util::rm_rf(CONFIG_PATH);
    util::rm_rf(LOG_APP_FILE);
    0
}

pub fn restart() -> i32 {
    stop();
    start()
}

/// Controller `server_status`: `top -bn1 | grep 'passwall2_server/bin/' | grep -i '<id>'`.
pub fn is_running(id: &str) -> bool {
    let id = id.to_lowercase();
    let Ok(rd) = std::fs::read_dir("/proc") else { return false };
    let me = std::process::id();
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        let cmd = String::from_utf8_lossy(&raw).replace('\0', " ");
        if cmd.contains("passwall2_server/bin/") && cmd.to_lowercase().contains(&id) {
            return true;
        }
    }
    false
}

/// Controller `server_log`: per-server core log or None when logging is not enabled.
pub fn read_server_log(id: &str) -> Option<String> {
    let p = server_log_path(id);
    if util::exists(&p) {
        Some(util::read(&p))
    } else {
        None
    }
}
/// Controller `server_get_log`.
pub fn read_log() -> String {
    util::read(LOG_APP_FILE)
}
/// Controller `server_clear_log` (`echo '' > file`).
pub fn clear_log() {
    let _ = std::fs::write(LOG_APP_FILE, "\n");
}

/// Config that `start()` would write for server `id` (for debugging / CLI).
pub fn gen_config(id: &str) -> Option<Value> {
    let scfg = Config::load(CONFIG);
    let s = scfg.section(id)?;
    build_instance(&scfg, s).config
}

pub fn cli(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "start" => start(),
        "stop" => stop(),
        "restart" => restart(),
        "reload" => {
            println!("Warning: This service does not support configuration reloading");
            println!("Performing full restart instead...");
            restart()
        }
        "status" => match args.get(1) {
            Some(id) => {
                let r = is_running(id);
                println!("{}", r);
                if r { 0 } else { 1 }
            }
            None => {
                let scfg = Config::load(CONFIG);
                let m: Map<String, Value> = scfg.sections_of("server").map(|s| (s.name.clone(), Value::Bool(is_running(&s.name)))).collect();
                println!("{}", Value::Object(m));
                0
            }
        },
        "gen_config" | "gen_config_server" => match args.get(1).and_then(|id| gen_config(id)) {
            Some(v) => {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                0
            }
            None => 1,
        },
        "log" => match args.get(1) {
            Some(id) => match read_server_log(id) {
                Some(t) => {
                    print!("{}", t);
                    0
                }
                None => 1,
            },
            None => {
                print!("{}", read_log());
                0
            }
        },
        "clear_log" => {
            clear_log();
            0
        }
        _ => {
            eprintln!("usage: passwall2 server <start|stop|restart|reload|status [id]|gen_config <id>|log [id]|clear_log>");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const CFG: &str = "config global 'global'\n\toption enable '1'\n\n\
config user 'u1'\n\toption password 'pw'\n\n\
config server 'ssr1'\n\toption enable '1'\n\toption remarks 'R1'\n\toption type 'SSR'\n\toption port '8388'\n\toption user 'u1'\n\toption method 'aes-256-cfb'\n\toption timeout '300'\n\toption protocol 'origin'\n\toption obfs 'plain'\n\toption tcp_fast_open '1'\n\toption firewall_allow '1'\n\n\
config server 'ssr2'\n\toption enable '1'\n\toption type 'SS-Rust'\n\toption port '9000'\n\toption udp_forward '0'\n\toption log '1'\n\toption firewall_allow '1'\n\toption firewall_allow_src 'lan'\n\n\
config server 'off'\n\toption enable '0'\n\toption type 'SSR'\n\n\
config server 'unk'\n\toption enable '1'\n\toption type 'Foo'\n";

    fn cfg() -> Config {
        Config::parse(CONFIG, CFG)
    }

    #[test]
    fn enabled_filtering() {
        let c = cfg();
        assert!(is_enabled(&c));
        let ids: Vec<_> = enabled_servers(&c).iter().map(|s| s.name.clone()).collect();
        assert_eq!(ids, vec!["ssr1", "ssr2", "unk"]);
        assert!(!is_enabled(&Config::parse(CONFIG, "config global 'global'\n\toption enable '0'\n")));
        assert!(!is_enabled(&Config::parse(CONFIG, "config global 'global'\n")));
        assert!(!is_enabled(&Config::parse(CONFIG, "config global 'global'\n\toption enable 'x'\n")));
    }

    #[test]
    fn ss_config() {
        let c = cfg();
        let v = gen_config_server_ss(&c, c.section("ssr1").unwrap());
        assert_eq!(v["server_port"], 8388);
        assert_eq!(v["password"], "pw");
        assert_eq!(v["timeout"], 300);
        assert_eq!(v["fast_open"], true);
        assert_eq!(v["server"], serde_json::json!(["[::0]", "0.0.0.0"]));
        assert_eq!(v["protocol"], "origin");
        assert!(v.get("protocol_param").is_none());
        assert!(v.get("mode").is_none());
        let v = gen_config_server_ss(&c, c.section("ssr2").unwrap());
        assert_eq!(v["server"], "::");
        assert_eq!(v["mode"], "tcp_and_udp");
        assert_eq!(v["password"], "");
        assert_eq!(v["fast_open"], false);
        assert!(v.get("timeout").is_none());
        assert!(v.get("protocol").is_none());
    }

    #[test]
    fn launches() {
        let c = cfg();
        let i = build_instance(&c, c.section("ssr1").unwrap());
        let l = i.launch.unwrap();
        assert_eq!(l.src, "/usr/bin/ssr-server");
        assert_eq!(l.bin_path(), "/tmp/etc/passwall2_server/bin/ssr-server");
        assert_eq!(l.args, vec!["-c", "/tmp/etc/passwall2_server/ssr1.json", "-u"]);
        assert_eq!(l.output, "/dev/null");
        assert_eq!(i.firewall, Some(("wan".to_string(), Some("8388".to_string()))));
        let i = build_instance(&c, c.section("ssr2").unwrap());
        let l = i.launch.unwrap();
        assert_eq!(l.src, "/usr/bin/ssserver");
        assert_eq!(l.output, "/tmp/etc/passwall2_server/ssr2.log");
        assert_eq!(l.command_line(), "/tmp/etc/passwall2_server/bin/ssserver -c /tmp/etc/passwall2_server/ssr2.json >/tmp/etc/passwall2_server/ssr2.log 2>&1 &");
        assert_eq!(i.firewall, Some(("lan".to_string(), Some("9000".to_string()))));
        let i = build_instance(&c, c.section("unk").unwrap());
        assert!(i.launch.is_none());
        assert!(!is_nonempty(i.config.as_ref().unwrap()));
        assert!(i.firewall.is_none());
    }

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn custom_configs() {
        let x = b64(r#"{"inbounds":[],"log":{"loglevel":"debug","access":"a"}}"#);
        let t = format!(
            "config server 'x'\n\toption enable '1'\n\toption type 'Xray'\n\toption custom '1'\n\toption log '1'\n\toption loglevel 'warning'\n\toption config_str '{}'\n\n\
config server 'y'\n\toption enable '1'\n\toption type 'Xray'\n\toption custom '1'\n\toption log '1'\n\toption config_str '{}'\n\n\
config server 's'\n\toption enable '1'\n\toption type 'sing-box'\n\toption custom '1'\n\toption log '1'\n\toption loglevel 'info'\n\toption config_str '{}'\n\n\
config server 'bad'\n\toption enable '1'\n\toption type 'sing-box'\n\toption custom '1'\n\toption config_str 'notjson'\n\n\
config server 'nolog'\n\toption enable '1'\n\toption type 'SS-Rust'\n\toption custom '1'\n\toption config_str '{}'\n",
            x,
            x,
            b64(r#"{"inbounds":[]}"#),
            b64(r#"{"server":"::","log":"x"}"#)
        );
        let c = Config::parse(CONFIG, &t);
        let v = build_instance(&c, c.section("x").unwrap()).config.unwrap();
        assert_eq!(v["log"]["loglevel"], "warning");
        assert_eq!(v["log"]["access"], "a");
        // loglevel unset → Lua assigns nil → key removed
        let v = build_instance(&c, c.section("y").unwrap()).config.unwrap();
        assert!(v["log"].get("loglevel").is_none());
        let i = build_instance(&c, c.section("s").unwrap());
        let v = i.config.unwrap();
        assert_eq!(v["log"], serde_json::json!({"timestamp": true, "disabled": false, "level": "info", "output": "/tmp/etc/passwall2_server/s.log"}));
        assert_eq!(i.launch.unwrap().args, vec!["run", "-c", "/tmp/etc/passwall2_server/s.json"]);
        assert!(build_instance(&c, c.section("bad").unwrap()).config.is_none());
        // no log → custom config left untouched
        let v = build_instance(&c, c.section("nolog").unwrap()).config.unwrap();
        assert_eq!(v["log"], "x");
    }

    #[test]
    fn firewall_rules() {
        let fw = Config::parse("firewall", "config rule 'passwall2_server_a'\n\toption name 'x'\n\nconfig rule\n\toption name 'passwall2_server_b'\n\nconfig rule 'passwall2_serverX'\n\nconfig rule 'my_passwall2_server'\n\nconfig redirect 'passwall2_server_r'\n");
        assert_eq!(our_firewall_rules(&fw), vec!["passwall2_server_a", "passwall2_serverX"]);
        let mut b = Batch::new();
        firewall_rule_batch(&mut b, "abc", "wan", Some("443"));
        assert!(!b.is_empty());
        assert_eq!(lua_num(Some("1.5".into())), Some(serde_json::json!(1.5)));
        assert_eq!(lua_num(Some("0x10".into())), Some(serde_json::json!(16)));
        assert_eq!(lua_num(Some("abc".into())), None);
    }
}
