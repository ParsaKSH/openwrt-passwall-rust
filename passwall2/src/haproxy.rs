//! HAProxy load balancing: config generation (upstream `haproxy.lua`), the launch done by
//! app.sh `start_haproxy`, and the external health check (`haproxy_check.sh`).
//! Spec: docs/spec/05-api-helpers.md §5, docs/spec/01-runtime-app.md §5 (start_haproxy), §17.
//!
//! Public API for app.rs:
//! * [`gen_config`]`(path, conf) -> bool` — `lua haproxy.lua -path <path> -conf <conf>`.
//! * [`prepare_start`]`() -> Option<(String, Vec<String>)>` — start_haproxy without the launch:
//!   returns `None` when `@global_haproxy[0].balancing_enable != 1`, otherwise generates
//!   `/tmp/etc/passwall2/haproxy/config.cfg` and returns `(haproxy binary or "", args)` for
//!   `ln_run 0 <bin> haproxy /dev/null -f <cfg>`.
//! * [`start_haproxy`]`()` — the same plus a stand-alone launch (symlink in `$TMP_BIN_PATH`,
//!   background spawn, `script_func` record) for callers that do not have their own `ln_run`.
//! * [`check`]`(saddr, sport) -> i32` — `haproxy_check.sh` (exit code 0 = healthy).
//! * CLI: `passwall2 haproxy -path DIR -conf FILE` | `passwall2 haproxy start` |
//!   `passwall2 haproxy-check <laddr> <lport> <saddr> <sport>`.
//!
//! HAProxy runs the external check as `"<HAPROXY_CHECK_CMD>" <laddr> <lport> <saddr> <sport>`;
//! the package must install that path as `exec /usr/bin/passwall2 haproxy-check "$@"`.

use crate::api;
use crate::uci::{Config, Section};
use crate::util;

/// Path written into `external-check command` (same as upstream).
pub const HAPROXY_CHECK_CMD: &str = "/usr/share/passwall2/haproxy_check.sh";
pub const HAPROXY_PATH: &str = "/tmp/etc/passwall2/haproxy";
pub const HAPROXY_CONF: &str = "config.cfg";
const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";
const HAPROXY_DNS: &str = "127.0.0.1";

/// `@global_haproxy[0]` options used by the generator.
#[derive(Debug, Clone)]
pub struct Global {
    pub health_check_type: String,
    pub health_check_inter: String,
    pub balancing_strategy: String,
    pub console_port: Option<String>,
    pub bind_local: String,
    pub console_user: Option<String>,
    pub console_password: Option<String>,
    pub health_probe_url: Option<String>,
}

impl Global {
    pub fn from_config(cfg: &Config) -> Global {
        let g = |o: &str| cfg.get("@global_haproxy[0]", o);
        Global {
            health_check_type: g("health_check_type").unwrap_or_else(|| "tcp".into()),
            health_check_inter: g("health_check_inter").unwrap_or_else(|| "60".into()),
            balancing_strategy: g("balancingStrategy").unwrap_or_else(|| "roundrobin".into()),
            console_port: g("console_port"),
            bind_local: g("bind_local").unwrap_or_else(|| "0".into()),
            console_user: g("console_user"),
            console_password: g("console_password"),
            health_probe_url: g("health_probe_url"),
        }
    }
    pub fn script_logic(&self) -> bool {
        self.health_check_type == "script_logic"
    }
    pub fn bind_address(&self) -> &'static str {
        if self.bind_local == "1" {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        }
    }
}

/// One `server` line of a `listen` block (an enabled `haproxy_config` section).
#[derive(Debug, Clone, PartialEq)]
pub struct Backend {
    /// `haproxy_config` section id
    pub name: String,
    pub server_remark: String,
    pub server_address: String,
    pub server_port: String,
    pub origin_address: String,
    pub origin_port: String,
    pub lbweight: String,
    pub backup: bool,
    /// `export` option (multi-WAN interface); `None` when unset.
    pub export: Option<String>,
}

/// Listen ports (ascending) with their backends in configuration order.
pub type Listens = Vec<(u32, Vec<Backend>)>;

/// `get_ip_port_from(str)` of haproxy.lua: port = digits after the last `:`/`#` at the end,
/// ip = string without the `[:#]<port>...` suffix (shell `${host%%[:#]port*}`).
pub fn get_ip_port_from(s: &str) -> (String, String) {
    // `echo -n <str>` unquoted: whitespace collapses
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let port = match s.rfind([':', '#']) {
        Some(i) if s[i + 1..].bytes().all(|c| c.is_ascii_digit()) => s[i + 1..].to_string(),
        _ => String::new(),
    };
    if port.is_empty() {
        return (s, port);
    }
    let b = s.as_bytes();
    for i in 0..b.len() {
        if (b[i] == b':' || b[i] == b'#') && s[i + 1..].starts_with(&port) {
            return (s[..i].to_string(), port);
        }
    }
    (s, port)
}

/// Lua `tostring(tonumber(x))` for a listen port; only positive values are used.
fn listen_port_of(v: &str) -> Option<u32> {
    let n = api::lua_tonumber(v)?;
    if n > 0.0 && n.fract() == 0.0 && n <= u32::MAX as f64 {
        Some(n as u32)
    } else {
        None
    }
}

/// Backend collection of haproxy.lua. `ensure_socks(node_section, haproxy_section_name)`
/// returns the local socks port for a non-Socks node in `script_logic` mode (cache
/// `node_<id>_socks_port`, else starting a dedicated instance). Returns the listens and the
/// number of discarded entries (each logged by the caller as "Discard one obviously invalid node.").
pub fn collect(cfg: &Config, g: &Global, ensure_socks: &mut dyn FnMut(&Section, &str) -> String, mut discard: impl FnMut()) -> Listens {
    let mut listens: Listens = vec![];
    for t in cfg.sections_of("haproxy_config") {
        if !t.is("enabled", "1") {
            continue;
        }
        let lbss = t.get("lbss");
        let listen_port = t.get("haproxy_port").and_then(|p| listen_port_of(&p));
        let server_node = lbss.as_deref().and_then(|l| cfg.section(l));
        let hop = if g.script_logic() {
            server_node.and_then(|n| n.get("hysteria_hop").or_else(|| n.get("hysteria2_hop"))).map(|h| h.replace(':', "-"))
        } else {
            None
        };
        let node_ok = server_node.and_then(|n| n.get("address").map(|a| (n, a))).and_then(|(n, a)| n.get("port").or_else(|| hop.clone()).map(|p| (n, a, p)));
        let (remark, mut address, mut port, origin_address, origin_port);
        if let Some((n, a, p)) = node_ok {
            remark = format!("{}:{}", a, p);
            address = a.clone();
            port = p.clone();
            origin_address = a;
            origin_port = p;
            if g.script_logic() && n.get("type").as_deref() != Some("Socks") {
                port = ensure_socks(n, &t.name);
                address = "127.0.0.1".into();
            }
        } else {
            let Some(l) = lbss.as_deref() else {
                // upstream quirk: Lua crashes on a missing lbss; we discard the entry.
                discard();
                continue;
            };
            let (ip, p) = get_ip_port_from(l);
            remark = format!("{}:{}", ip, p);
            address = ip.clone();
            port = p.clone();
            origin_address = ip;
            origin_port = p;
        }
        // upstream quirk: an empty port (lbss without ":port") is accepted by Lua and produces an
        // invalid `server x host:` line that makes haproxy refuse the whole config; we discard it.
        match listen_port {
            Some(lp) if !address.is_empty() && !port.is_empty() => {
                let b = Backend {
                    name: t.name.clone(),
                    server_remark: remark,
                    server_address: address,
                    server_port: port,
                    origin_address,
                    origin_port,
                    lbweight: t.s("lbweight"),
                    backup: t.is("backup", "1"),
                    export: t.get("export"),
                };
                match listens.iter_mut().find(|(p, _)| *p == lp) {
                    Some((_, v)) => v.push(b),
                    None => listens.push((lp, vec![b])),
                }
            }
            _ => discard(),
        }
    }
    listens.sort_by_key(|(p, _)| *p);
    listens
}

/// Health check timing: `(inter, fastinter, downinter)`.
pub fn check_timing(health_check_inter: &str) -> (u64, u64, u64) {
    let digits: String = health_check_inter.chars().take_while(|c| c.is_ascii_digit()).collect();
    let inter = digits.parse::<u64>().unwrap_or(60).max(20);
    let fastinter = (inter / 2).clamp(10, 15);
    let downinter = (inter * 3).div_ceil(2);
    (inter, fastinter, downinter)
}

/// `server_endpoint(o)`: brackets around IPv6, `:port` appended.
pub fn server_endpoint(address: &str, port: &str) -> String {
    let a = address.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(address);
    if a.contains(':') {
        format!("[{}]:{}", a, port)
    } else {
        format!("{}:{}", a, port)
    }
}

/// Number of CPUs for `nbthread` (`grep processor /proc/cpuinfo | wc -l`).
pub fn cpu_threads() -> usize {
    // upstream quirk: a cpuinfo without "processor" lines yields `nbthread 0`, which haproxy
    // rejects; we use at least 1.
    util::read("/proc/cpuinfo").lines().filter(|l| l.contains("processor")).count().max(1)
}

/// Render the full haproxy config (pure; the file content written by haproxy.lua).
pub fn render(path: &str, nbthread: usize, g: &Global, listens: &Listens) -> String {
    let mut mydns = String::new();
    for (i, w) in HAPROXY_DNS.split(',').filter(|s| !s.is_empty()).enumerate() {
        let mut s = w.replace('#', ":");
        if !s.contains(':') {
            s.push_str(":53");
        }
        if i > 0 {
            mydns.push('\n');
        }
        mydns.push_str(&format!("\tnameserver dns{} {}", i + 1, s));
    }
    let mut out = format!(
        "global\n\tdaemon\n\tlog 127.0.0.1 local2\n\tmaxconn 60000\n\tstats socket {path}/haproxy.sock\n\tnbthread {nb}\n\texternal-check\n\tinsecure-fork-wanted\n\tspread-checks 20\n\ttune.max-checks-per-thread 5\n\n\
defaults\n\tmode tcp\n\tlog global\n\toption tcplog\n\toption dontlognull\n\toption abortonclose\n\t#option forwardfor except 127.0.0.0/8\n\toption redispatch\n\tretries 2\n\ttimeout http-request 10s\n\ttimeout queue 1m\n\ttimeout connect 10s\n\ttimeout client 1m\n\ttimeout server 1m\n\ttimeout http-keep-alive 10s\n\ttimeout check 10s\n\tmaxconn 3000\n\n\
resolvers mydns\n\tresolve_retries 1\n\ttimeout resolve 5s\n\thold valid 600s\n{dns}\n",
        path = path,
        nb = nbthread,
        dns = mydns
    );

    let (inter, fastinter, downinter) = check_timing(&g.health_check_inter);
    let inter_arg = format!("inter {}s fastinter {}s downinter {}s", inter, fastinter, downinter);
    let script_logic = g.script_logic();
    let bind = g.bind_address();

    let mut check_counts: std::collections::HashMap<String, usize> = Default::default();
    if script_logic {
        for (_, list) in listens {
            for o in list {
                if api::is_ip(&o.server_address) {
                    *check_counts.entry(server_endpoint(&o.server_address, &o.server_port)).or_default() += 1;
                }
            }
        }
    }
    let mut shared_checks: Vec<(String, String)> = vec![];

    for (port, list) in listens {
        out.push_str(&format!("\nlisten {p}\n\tbind {b}:{p}\n\tmode tcp\n\tbalance {s}\n", p = port, b = bind, s = g.balancing_strategy));
        if script_logic {
            out.push_str(&format!("\toption external-check\n\texternal-check command \"{}\"\n", HAPROXY_CHECK_CMD));
        }
        let (mut count_m, mut count_b) = (1, 1);
        for o in list {
            let mut remark: String = o.server_remark.chars().filter(|c| *c != '[' && *c != ']').collect();
            if !o.backup {
                remark = format!("M{}-{}", count_m, remark);
                count_m += 1;
            } else {
                remark = format!("B{}-{}", count_b, remark);
                count_b += 1;
            }
            let server = server_endpoint(&o.server_address, &o.server_port);
            let mut check_arg = format!("check {} rise 2 fall 2", inter_arg);
            if check_counts.get(&server).copied().unwrap_or(0) > 1 {
                let name = match shared_checks.iter().find(|(_, s)| *s == server) {
                    Some((n, _)) => n.clone(),
                    None => {
                        let n = format!("check_{}", shared_checks.len() + 1);
                        shared_checks.push((n.clone(), server.clone()));
                        n
                    }
                };
                check_arg = format!("track passwall2_health_checks/{}", name);
            }
            let resolvers = if api::is_ip(&o.server_address) { "" } else { "resolvers mydns" };
            let line = format!(
                "server {} {} weight {} {} {} {}",
                remark,
                server,
                o.lbweight,
                resolvers,
                check_arg,
                if o.backup { "backup" } else { "" }
            );
            out.push_str(&format!("\t{}\n", api::trim(&line)));
        }
    }

    if !shared_checks.is_empty() {
        out.push_str(&format!(
            "\nbackend passwall2_health_checks\n\tmode tcp\n\toption external-check\n\texternal-check command \"{}\"\n",
            HAPROXY_CHECK_CMD
        ));
        for (name, server) in &shared_checks {
            out.push_str(&format!("\tserver {} {} check {} rise 2 fall 2\n", name, server, inter_arg));
        }
    }

    // upstream quirk: without console_port Lua crashes before writing anything (haproxy then
    // fails to start); we just leave the stats listener out.
    if let Some(cp) = g.console_port.as_deref().filter(|p| !p.is_empty()) {
        let auth = match (g.console_user.as_deref(), g.console_password.as_deref()) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => format!("stats auth {}:{}", u, p),
            _ => String::new(),
        };
        out.push_str(&format!(
            "\nlisten console\n\tbind 0.0.0.0:{}\n\tmode http\n\tstats refresh 30s\n\tstats uri /\n\tstats admin if TRUE\n\t{}\n",
            cp, auth
        ));
    }
    out
}

/// Start (or reuse) the dedicated local socks instance for a node in `script_logic` mode.
fn ensure_socks_instance(node: &Section, hname: &str) -> String {
    if let Some(p) = api::get_socks_port_by_cache(&node.name) {
        return p;
    }
    let new_port = api::get_new_port(None, "").to_string();
    let config_file = format!("{}_{}.json", hname, new_port);
    let args: Vec<String> = vec![
        "app".into(),
        "run_socks".into(),
        format!("flag={}", new_port),
        format!("node={}", node.name),
        "bind=127.0.0.1".into(),
        format!("socks_port={}", new_port),
        format!("config_file={}", config_file),
    ];
    let _ = std::process::Command::new(util::SELF_BIN).args(&args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).status();
    api::set_socks_port_to_cache(&node.name, &new_port);
    new_port
}

/// `utils.sh add_ip2route HOST IFACE`: host route for `host` via the gateway of `iface`.
pub fn add_ip2route(host: &str, iface: &str) -> bool {
    let Some(ip) = util::get_host_ip("ipv4", host, 3) else {
        api::log(1, &api::translatef("Unable to resolve [%s], route table addition failed!", &[host]));
        return false;
    };
    let remarks = if ip != host { format!("{}({})", host, ip) } else { host.to_string() };
    let q = util::shq(iface);
    let gateway = util::sh(&format!(". /lib/functions/network.sh; network_get_gateway __gw {q}; echo -n \"$__gw\"")).trim().to_string();
    let mut device = util::sh(&format!(". /lib/functions/network.sh; network_get_device __dev {q}; echo -n \"$__dev\"")).trim().to_string();
    if device.is_empty() {
        let st = util::cmd_out("ubus", &["call", &format!("network.interface.{}", iface), "status"]);
        device = serde_json::from_str::<serde_json::Value>(&st).ok().and_then(|v| v["device"].as_str().map(String::from)).unwrap_or_default();
    }
    if device.is_empty() {
        device = iface.to_string();
    }
    if !gateway.is_empty() {
        util::cmd_ok("route", &["add", "-host", &ip, "gw", &gateway, "dev", &device]);
        util::append_file(&format!("{}/{}", util::TMP_ROUTE_PATH, device), &ip);
        api::log(1, &api::translatef("[%s] was successfully added to the routing table of interface [%s]!", &[&remarks, &device]));
        true
    } else {
        api::log(
            1,
            &api::translatef("Adding [%s] to the [%s] routing table failed! The reason is that the [%s] gateway cannot be found.", &[&remarks, &device, &device]),
        );
        false
    }
}

/// haproxy.lua: generate `<path>/<conf>` (append mode, like upstream), log, add multi-WAN
/// routes, and set cache `HAPROXY_PROBE_URL` in `script_logic` mode.
pub fn gen_config(path: &str, conf: &str) -> bool {
    let cfg = Config::load(util::CONFIG);
    let g = Global::from_config(&cfg);
    let console = g.console_port.clone().unwrap_or_default();
    api::log(0, "HAProxy: ");
    api::log(1, &api::translatef("Console Port: %s", &[&console]));
    util::mkdir(path);
    let file = format!("{}/{}", path, conf);

    let listens = collect(&cfg, &g, &mut ensure_socks_instance, || api::log(1, &api::translate("Discard one obviously invalid node.")));
    let text = render(path, cpu_threads(), &g, &listens);
    let ok = {
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(&file).and_then(|mut f| f.write_all(text.as_bytes())).is_ok()
    };

    for (port, list) in &listens {
        api::log(1, &api::translatef("Entrance %s:%s", &[g.bind_address(), &port.to_string()]));
        for o in list {
            if o.export.as_deref() != Some("0") {
                add_ip2route(&o.origin_address, o.export.as_deref().unwrap_or(""));
            }
            api::log(2, &api::translatef("Node: %s:%s, Weight: %s", &[&o.origin_address, &o.origin_port, &o.lbweight]));
        }
    }

    if g.script_logic() {
        let mut probe = api::trim(g.health_probe_url.as_deref().unwrap_or(""));
        if probe.is_empty() {
            probe = DEFAULT_PROBE_URL.into();
        }
        api::set_cache_var("HAPROXY_PROBE_URL", &probe);
    }
    ok
}

/// app.sh `start_haproxy` minus the launch. `None` = load balancing disabled.
/// `Some((bin, args))`: `bin` is "" when no haproxy binary is installed.
pub fn prepare_start() -> Option<(String, Vec<String>)> {
    let cfg = Config::load(util::CONFIG);
    if cfg.get_or("@global_haproxy[0]", "balancing_enable", "0") != "1" {
        return None;
    }
    gen_config(HAPROXY_PATH, HAPROXY_CONF);
    let bin = util::first_type("haproxy", "").unwrap_or_default();
    Some((bin, vec!["-f".into(), format!("{}/{}", HAPROXY_PATH, HAPROXY_CONF)]))
}

/// app.sh `start_haproxy` including the launch (equivalent of `ln_run 0 <bin> haproxy /dev/null -f <cfg>`).
pub fn start_haproxy() -> bool {
    let Some((bin, args)) = prepare_start() else { return true };
    if bin.is_empty() {
        api::log(1, &api::translatef("%s not found, unable to start...", &["haproxy"]));
        return false;
    }
    util::mkdir(util::TMP_BIN_PATH);
    let link = format!("{}/haproxy", util::TMP_BIN_PATH);
    let is_link = std::fs::symlink_metadata(&bin).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    let exe = if is_link {
        bin.clone()
    } else {
        let _ = std::os::unix::fs::symlink(&bin, &link);
        link
    };
    if !util::is_executable(&exe) {
        api::log(1, &api::translatef("%s does not have execute permissions and cannot be started: %s %s", &["haproxy", &exe, &args.join(" ")]));
    }
    if util::spawn_bg(&exe, &args, "/dev/null").is_none() {
        return false;
    }
    if std::env::var("NO_REC_PROCESS").map(|v| v.is_empty()).unwrap_or(true) {
        util::mkdir(util::TMP_SCRIPT_FUNC_PATH);
        let n = std::fs::read_dir(util::TMP_SCRIPT_FUNC_PATH)
            .map(|rd| rd.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('_')).count())
            .unwrap_or(0)
            + 1;
        util::write(&format!("{}/{}", util::TMP_SCRIPT_FUNC_PATH, n), &format!("{} {} >/dev/null\n", exe, args.join(" ")));
    }
    true
}

/// `haproxy_check.sh`: probe the probe URL through `socks5h://<saddr>:<sport>`. 0 = healthy.
pub fn check(server_address: &str, server_port: &str) -> i32 {
    if crate::socks_switch::busy_task_running() {
        // No detection during specific task execution
        return 0;
    }
    let probe = api::get_cache_var("HAPROXY_PROBE_URL").unwrap_or_else(|| DEFAULT_PROBE_URL.into());
    let addr = bracket_v6(server_address);
    let out = std::process::Command::new("/usr/bin/curl")
        .args([
            "-q",
            "-I",
            "-o",
            "/dev/null",
            "-sk",
            "--noproxy",
            "",
            "-x",
            &format!("socks5h://{}:{}", addr, server_port),
            "--connect-timeout",
            "3",
            "--max-time",
            "6",
            "-w",
            "%{http_code}",
            &probe,
        ])
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin:/root/bin")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => match String::from_utf8_lossy(&o.stdout).trim() {
            "200" | "204" => 0,
            _ => 1,
        },
        _ => 1,
    }
}

/// `case "$a" in \[*\]) ;; *:*) a="[$a]" ;; esac`
fn bracket_v6(a: &str) -> String {
    if a.starts_with('[') && a.ends_with(']') && a.len() >= 2 {
        a.to_string()
    } else if a.contains(':') {
        format!("[{}]", a)
    } else {
        a.to_string()
    }
}

/// `passwall2 haproxy -path DIR -conf FILE` | `passwall2 haproxy start` |
/// `passwall2 haproxy-check LADDR LPORT SADDR SPORT`.
pub fn cli(cmd: &str, args: &[String]) -> i32 {
    if cmd == "haproxy-check" {
        let a = |i: usize| args.get(i).map(|s| s.as_str()).unwrap_or("");
        return check(a(2), a(3));
    }
    match args.first().map(|s| s.as_str()) {
        Some("start") => {
            if start_haproxy() {
                0
            } else {
                1
            }
        }
        Some("check") => {
            let a = |i: usize| args.get(i).map(|s| s.as_str()).unwrap_or("");
            check(a(3), a(4))
        }
        _ => {
            let var = api::get_args(args);
            let path = var.get("-path").cloned().unwrap_or_else(|| HAPROXY_PATH.into());
            let conf = var.get("-conf").cloned().unwrap_or_else(|| HAPROXY_CONF.into());
            if gen_config(&path, &conf) {
                0
            } else {
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_ip_port_from() {
        assert_eq!(get_ip_port_from("1.2.3.4:80"), ("1.2.3.4".into(), "80".into()));
        assert_eq!(get_ip_port_from("example.com#443"), ("example.com".into(), "443".into()));
        assert_eq!(get_ip_port_from("[2001:db8::1]:443"), ("[2001:db8::1]".into(), "443".into()));
        assert_eq!(get_ip_port_from("example.com"), ("example.com".into(), "".into()));
        assert_eq!(get_ip_port_from("host:"), ("host:".into(), "".into()));
    }

    #[test]
    fn t_timing() {
        assert_eq!(check_timing("60"), (60, 15, 90));
        assert_eq!(check_timing("5"), (20, 10, 30));
        assert_eq!(check_timing("25s"), (25, 12, 38));
        assert_eq!(check_timing("abc"), (60, 15, 90));
    }

    #[test]
    fn t_endpoint() {
        assert_eq!(server_endpoint("::1", "1"), "[::1]:1");
        assert_eq!(server_endpoint("[::1]", "1"), "[::1]:1");
        assert_eq!(server_endpoint("a.b", "2"), "a.b:2");
        assert_eq!(bracket_v6("::1"), "[::1]");
        assert_eq!(bracket_v6("[::1]"), "[::1]");
        assert_eq!(bracket_v6("1.2.3.4"), "1.2.3.4");
    }

    const CFG: &str = "config global_haproxy\n\toption balancing_enable '1'\n\toption console_port '1188'\n\toption console_user 'admin'\n\toption console_password 'pw'\n\toption health_check_type 'tcp'\n\toption health_check_inter '60'\n\n\
config nodes 'n1'\n\toption type 'Xray'\n\toption address 'a.example.com'\n\toption port '443'\n\n\
config nodes 'n2'\n\toption type 'Socks'\n\toption address '10.0.0.2'\n\toption port '1080'\n\n\
config nodes 'n3'\n\toption type 'sing-box'\n\toption address '2001:db8::3'\n\toption hysteria2_hop '20000:30000'\n\n\
config haproxy_config 'h1'\n\toption enabled '1'\n\toption lbss 'n1'\n\toption haproxy_port '1181'\n\toption lbweight '5'\n\toption export '0'\n\toption backup '0'\n\n\
config haproxy_config 'h2'\n\toption enabled '1'\n\toption lbss '1.2.3.4:8080'\n\toption haproxy_port '1181'\n\toption lbweight '3'\n\toption export '0'\n\toption backup '1'\n\n\
config haproxy_config 'h3'\n\toption enabled '1'\n\toption lbss 'n2'\n\toption haproxy_port '1080'\n\toption lbweight '1'\n\toption export '0'\n\toption backup '0'\n\n\
config haproxy_config 'h4'\n\toption enabled '0'\n\toption lbss 'n2'\n\toption haproxy_port '1090'\n\n\
config haproxy_config 'h5'\n\toption enabled '1'\n\toption lbss 'bad'\n\toption haproxy_port '1181'\n\n\
config haproxy_config 'h6'\n\toption enabled '1'\n\toption lbss 'n3'\n\toption haproxy_port '1181'\n\toption lbweight '2'\n\toption export 'wan2'\n\toption backup '0'\n";

    #[test]
    fn t_render_tcp() {
        let cfg = Config::parse("passwall2", CFG);
        let g = Global::from_config(&cfg);
        let mut discarded = 0;
        let listens = collect(&cfg, &g, &mut |_, _| panic!("no socks in tcp mode"), || discarded += 1);
        // h5 has no port, h6 has no port in tcp mode (hop only used for script_logic)
        assert_eq!(discarded, 2);
        assert_eq!(listens.iter().map(|(p, v)| (*p, v.len())).collect::<Vec<_>>(), vec![(1080, 1), (1181, 2)]);
        let text = render("/tmp/etc/passwall2/haproxy", 4, &g, &listens);
        let expected = "global\n\tdaemon\n\tlog 127.0.0.1 local2\n\tmaxconn 60000\n\tstats socket /tmp/etc/passwall2/haproxy/haproxy.sock\n\tnbthread 4\n\texternal-check\n\tinsecure-fork-wanted\n\tspread-checks 20\n\ttune.max-checks-per-thread 5\n\n\
defaults\n\tmode tcp\n\tlog global\n\toption tcplog\n\toption dontlognull\n\toption abortonclose\n\t#option forwardfor except 127.0.0.0/8\n\toption redispatch\n\tretries 2\n\ttimeout http-request 10s\n\ttimeout queue 1m\n\ttimeout connect 10s\n\ttimeout client 1m\n\ttimeout server 1m\n\ttimeout http-keep-alive 10s\n\ttimeout check 10s\n\tmaxconn 3000\n\n\
resolvers mydns\n\tresolve_retries 1\n\ttimeout resolve 5s\n\thold valid 600s\n\tnameserver dns1 127.0.0.1:53\n\n\
listen 1080\n\tbind 0.0.0.0:1080\n\tmode tcp\n\tbalance roundrobin\n\tserver M1-10.0.0.2:1080 10.0.0.2:1080 weight 1  check inter 60s fastinter 15s downinter 90s rise 2 fall 2\n\n\
listen 1181\n\tbind 0.0.0.0:1181\n\tmode tcp\n\tbalance roundrobin\n\tserver M1-a.example.com:443 a.example.com:443 weight 5 resolvers mydns check inter 60s fastinter 15s downinter 90s rise 2 fall 2\n\tserver B1-1.2.3.4:8080 1.2.3.4:8080 weight 3  check inter 60s fastinter 15s downinter 90s rise 2 fall 2 backup\n\n\
listen console\n\tbind 0.0.0.0:1188\n\tmode http\n\tstats refresh 30s\n\tstats uri /\n\tstats admin if TRUE\n\tstats auth admin:pw\n";
        assert_eq!(text, expected);
    }

    #[test]
    fn t_render_script_logic() {
        let text = CFG.replace("option health_check_type 'tcp'", "option health_check_type 'script_logic'") + "\nconfig haproxy_config 'h7'\n\toption enabled '1'\n\toption lbss 'n1'\n\toption haproxy_port '1182'\n\toption lbweight '5'\n\toption export '0'\n";
        let cfg = Config::parse("passwall2", &text);
        let mut g = Global::from_config(&cfg);
        g.console_user = None;
        let mut started: Vec<(String, String)> = vec![];
        let mut ports: std::collections::HashMap<String, String> = Default::default();
        let mut next = 2001;
        let mut ensure = |n: &Section, h: &str| {
            started.push((n.name.clone(), h.to_string()));
            ports
                .entry(n.name.clone())
                .or_insert_with(|| {
                    next += 1;
                    (next - 1).to_string()
                })
                .clone()
        };
        let mut discarded = 0;
        let listens = collect(&cfg, &g, &mut ensure, || discarded += 1);
        assert_eq!(discarded, 1);
        assert_eq!(started, vec![("n1".into(), "h1".into()), ("n3".into(), "h6".into()), ("n1".into(), "h7".into())]);
        let l1181 = &listens.iter().find(|(p, _)| *p == 1181).unwrap().1;
        assert_eq!(l1181[2].origin_address, "2001:db8::3");
        assert_eq!(l1181[2].origin_port, "20000-30000");
        assert_eq!(l1181[2].server_remark, "2001:db8::3:20000-30000");
        let out = render("/p", 1, &g, &listens);
        assert!(out.contains("\nlisten 1080\n\tbind 0.0.0.0:1080\n\tmode tcp\n\tbalance roundrobin\n\toption external-check\n\texternal-check command \"/usr/share/passwall2/haproxy_check.sh\"\n\tserver M1-10.0.0.2:1080 10.0.0.2:1080 weight 1  check inter 60s fastinter 15s downinter 90s rise 2 fall 2\n"));
        assert!(out.contains("\tserver M1-a.example.com:443 127.0.0.1:2001 weight 5  track passwall2_health_checks/check_1\n"));
        assert!(out.contains("\tserver M2-2001:db8::3:20000-30000 127.0.0.1:2002 weight 2  check inter 60s fastinter 15s downinter 90s rise 2 fall 2\n"));
        assert!(out.contains("\nlisten 1182\n"));
        assert!(out.ends_with(
            "\n\nbackend passwall2_health_checks\n\tmode tcp\n\toption external-check\n\texternal-check command \"/usr/share/passwall2/haproxy_check.sh\"\n\tserver check_1 127.0.0.1:2001 check inter 60s fastinter 15s downinter 90s rise 2 fall 2\n\nlisten console\n\tbind 0.0.0.0:1188\n\tmode http\n\tstats refresh 30s\n\tstats uri /\n\tstats admin if TRUE\n\t\n"
        ));
    }
}
