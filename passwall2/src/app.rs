//! Runtime orchestration: port of upstream `app.sh` (start/stop, core launchers, socks,
//! haproxy, DNS helper instances, `acl_node`, cron), the process helpers of `utils.sh`
//! (`ln_run`, process queue, routes, geoip, ...), `/etc/init.d/passwall2` (locks, boot delay,
//! waiting for subscription/rule updates), `monitor.sh`, `tasks.sh`, `lease2hosts.sh` and
//! `test.sh`. Spec: docs/spec/01-runtime-app.md.
//!
//! CLI (dispatched from main.rs):
//! * `passwall2 start|stop|restart [boot|cron]`, `passwall2 boot`   — init semantics (locks).
//!   When the lock is already held by an ancestor process (the rc.common wrapper took it and
//!   then runs us), the lock is not taken again and the call behaves like `app.sh start|stop`.
//! * `passwall2 app <fn> k=v ...` — `app.sh` entry points (`run_socks`, `socks_node_switch`,
//!   `start`, `stop`) plus helpers (`acl_node`, `run_xray`, `run_singbox`, `get_new_port`, ...).
//!   Arguments may also be one quoted string of space separated `k=v` pairs (Lua callers).
//! * `passwall2 monitor | tasks | lease2hosts` — daemons; `passwall2 test ...` — test.sh.
//!
//! Every core process is executed through a symlink in `/tmp/etc/passwall2/bin/<name>` and
//! its command line is recorded in `script_func/` (monitor respawn) exactly like upstream.

pub mod daemons;
pub mod ss;
pub mod test;

use crate::api;
use crate::firewall::acl;
use crate::uci::{Batch, Config};
use crate::util::{self, Args, ArgsExt, LOCK_PATH, TMP_ACL_PATH, TMP_BIN_PATH, TMP_PATH, TMP_PATH2, TMP_PROCESS_LIST_PATH, TMP_ROUTE_PATH, TMP_SCRIPT_FUNC_PATH};
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// true when nftables (fw4) backend should be used (check_run_environment).
/// Uses the backend chosen by the running instance (cache `USE_TABLES`) when known.
pub fn use_nft() -> bool {
    match util::get_cache_var("USE_TABLES").as_deref() {
        Some("nftables") => true,
        Some("iptables") => false,
        _ => crate::util::exists("/usr/sbin/fw4") || command_v("fw4").is_some(),
    }
}

// ====================================================================== logging

/// `LOG_FILE=/dev/null` override used by `socks_node_switch` (only affects this module's logs).
static LOG_SUPPRESS: AtomicBool = AtomicBool::new(false);
/// Set once `acl_node` ran during the current `start` (fallback when the firewall backend
/// does not call it).
static ACL_NODE_RAN: AtomicBool = AtomicBool::new(false);

fn log(level: usize, msg: &str) {
    if !LOG_SUPPRESS.load(Ordering::Relaxed) {
        util::log(level, msg);
    }
}
fn i18n(fmt: &str, args: &[&str]) -> String {
    api::translatef(fmt, args)
}
fn logi(level: usize, fmt: &str, args: &[&str]) {
    log(level, &i18n(fmt, args));
}

pub(crate) fn sleep_s(s: u64) {
    std::thread::sleep(std::time::Duration::from_secs(s));
}

// ====================================================================== processes

/// A running process (`/proc/<pid>/cmdline`).
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: u32,
    pub argv: Vec<String>,
    /// argv joined by single spaces (what `busybox pgrep -f` matches)
    pub cmdline: String,
}

impl Proc {
    /// true when this is our own multicall binary running subcommand `sub`.
    pub fn is_self_cmd(&self, sub: &str) -> bool {
        self.is_self_bin() && self.argv.get(1).map(|s| s.as_str()) == Some(sub)
    }
    pub fn is_self_bin(&self) -> bool {
        self.argv.first().map(|a| a.rsplit('/').next().unwrap_or(a) == "passwall2").unwrap_or(false)
    }
}

fn ppid_of(pid: u32) -> Option<u32> {
    let st = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rest = &st[st.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// pid of this process and all its ancestors.
pub fn ancestors() -> Vec<u32> {
    let mut v = vec![std::process::id()];
    let mut p = std::process::id();
    for _ in 0..64 {
        match ppid_of(p) {
            Some(pp) if pp > 1 && !v.contains(&pp) => {
                v.push(pp);
                p = pp;
            }
            _ => break,
        }
    }
    v
}

/// All processes except this one and its ancestors.
pub fn list_procs() -> Vec<Proc> {
    let skip = ancestors();
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if skip.contains(&pid) {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        if raw.is_empty() {
            continue;
        }
        let argv: Vec<String> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).to_string()).collect();
        let cmdline = argv.join(" ");
        out.push(Proc { pid, argv, cmdline });
    }
    out.sort_by_key(|p| p.pid);
    out
}

/// `busybox pgrep -af PATTERN` (substring match on the command line).
pub fn pgrep_af(pat: &str) -> Vec<Proc> {
    list_procs().into_iter().filter(|p| p.cmdline.contains(pat)).collect()
}

pub(crate) fn kill_pids_excluding(pids: &[u32]) {
    let anc = ancestors();
    let v: Vec<u32> = pids.iter().copied().filter(|p| !anc.contains(p)).collect();
    util::kill_pids(&v, 9);
}

/// `pgrep -af $TMP_BIN_PATH | awk 'BEGIN{IGNORECASE=1} $0~flag'` → kill -9
/// (optionally excluding ACL instances: `!/acl\/|acl_/`).
pub fn kill_flag(flag: &str, exclude_acl: bool) {
    if flag.is_empty() {
        return;
    }
    let f = flag.to_lowercase();
    let pids: Vec<u32> = pgrep_af(TMP_BIN_PATH)
        .into_iter()
        .filter(|p| {
            let line = format!("{} {}", p.pid, p.cmdline);
            line.to_lowercase().contains(&f) && !(exclude_acl && (line.contains("acl/") || line.contains("acl_")))
        })
        .map(|p| p.pid)
        .collect();
    kill_pids_excluding(&pids);
}

/// `kill_all NAMES...` → `kill -9 $(pidof NAMES)`.
pub fn kill_all(names: &[&str]) {
    let pids: Vec<u32> = list_procs()
        .into_iter()
        .filter(|p| p.argv.first().map(|a| names.contains(&a.rsplit('/').next().unwrap_or(a))).unwrap_or(false))
        .map(|p| p.pid)
        .collect();
    kill_pids_excluding(&pids);
}

/// Path of our own binary (for re-invoking subcommands).
pub fn self_bin() -> String {
    if util::is_executable(util::SELF_BIN) {
        return util::SELF_BIN.to_string();
    }
    std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| util::SELF_BIN.to_string())
}

/// `command -v NAME`: first executable in `$PATH` (plus the standard dirs).
pub fn command_v(name: &str) -> Option<String> {
    if name.contains('/') {
        return if util::is_executable(name) { Some(name.to_string()) } else { None };
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':').filter(|d| !d.is_empty()).chain(["/usr/sbin", "/usr/bin", "/sbin", "/bin"]) {
        let p = format!("{}/{}", dir, name);
        if util::is_executable(&p) {
            return Some(p);
        }
    }
    None
}

fn new_session_cmd(prog: &str) -> Command {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(prog);
    unsafe {
        c.pre_exec(|| {
            extern "C" {
                fn setsid() -> i32;
            }
            setsid();
            Ok(())
        });
    }
    c
}

/// Start `prog args >output 2>&1 &` (truncating output, own session). Returns the pid.
pub fn spawn_out(prog: &str, args: &[String], output: &str) -> Option<u32> {
    let out = std::fs::OpenOptions::new().create(true).write(true).truncate(output != "/dev/null").open(output).ok()?;
    let err = out.try_clone().ok()?;
    new_session_cmd(prog).args(args).stdin(Stdio::null()).stdout(out).stderr(err).spawn().ok().map(|c| c.id())
}

/// `eval "nohup <cmd> 2>&1 &"` for a recorded command line (`<file> <args> ><output>`).
pub fn spawn_shell(cmd: &str) -> Option<u32> {
    new_session_cmd("/bin/sh")
        .arg("-c")
        .arg(format!("exec {} 2>&1", cmd))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .map(|c| c.id())
}

/// The part of a recorded command used to find its process: text before the first `>`,
/// whitespace collapsed (`echo $cmd | awk -F '>' '{print $1}'`).
pub fn cmd_check(cmd: &str) -> String {
    cmd.split('>').next().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Recursive file search (`find DIR -type f -name ...`).
pub(crate) fn find_files(dir: &str, pred: &dyn Fn(&str) -> bool, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let ps = p.to_string_lossy().to_string();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            find_files(&ps, pred, out);
        } else if ft.is_file() && pred(&e.file_name().to_string_lossy()) {
            out.push(ps);
        }
    }
}

fn count_entries(dir: &str) -> usize {
    std::fs::read_dir(dir).map(|rd| rd.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('_')).count()).unwrap_or(0)
}

/// Next free record number in DIR (`ls | grep -v '^_' | wc -l` + 1).
fn next_record(dir: &str) -> String {
    let mut n = count_entries(dir) + 1;
    // upstream quirk: the count can collide with an existing entry after deletions
    // (socks_node_switch) and silently overwrite it; we skip to the next free number.
    while util::exists(&format!("{}/{}", dir, n)) {
        n += 1;
    }
    n.to_string()
}

/// `ln_run QUEUE FILE_FUNC LN_NAME OUTPUT ARGS...` (utils.sh).
pub fn ln_run(ctx: &Ctx, queue: bool, file_func: Option<&str>, ln_name: &str, output: &str, args: &[String]) -> i32 {
    let mut file_func = file_func.unwrap_or("").to_string();
    if file_func.contains('/') {
        let link = format!("{}/{}", TMP_BIN_PATH, ln_name);
        // A symlink that already lives in TMP_BIN_PATH (first_type found e.g. bin/dnsmasq
        // made by an earlier launch) is run directly, like upstream.
        let in_bin = file_func.starts_with(&format!("{}/", TMP_BIN_PATH))
            && std::fs::symlink_metadata(&file_func).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        if file_func != link && !in_bin {
            util::mkdir(TMP_BIN_PATH);
            // upstream quirk: when the binary itself is a symlink upstream runs it directly,
            // so `pgrep $TMP_BIN_PATH` (stop, monitor, kill-by-flag) cannot find it. We always
            // go through our own symlink.
            let cur = std::fs::read_link(&link).ok().map(|p| p.to_string_lossy().to_string());
            if cur.as_deref() != Some(file_func.as_str()) {
                let _ = std::fs::remove_file(&link);
                let _ = std::os::unix::fs::symlink(&file_func, &link);
            }
            file_func = link;
        }
        if !util::is_executable(&file_func) {
            let target = std::fs::read_link(&file_func).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            logi(1, "%s does not have execute permissions and cannot be started: %s %s", &[&target, &file_func, &args.join(" ")]);
        }
    }
    if file_func.is_empty() {
        logi(1, "%s not found, unable to start...", &[ln_name]);
        return 1;
    }
    let record = format!("{} {} >{}", file_func, args.join(" "), output);
    if queue {
        util::mkdir(TMP_PROCESS_LIST_PATH);
        let n = next_record(TMP_PROCESS_LIST_PATH);
        util::write(&format!("{}/{}", TMP_PROCESS_LIST_PATH, n), &format!("{}\n", record));
        return 0;
    }
    if spawn_out(&file_func, args, output).is_none() {
        return 1;
    }
    if ctx.no_rec_process {
        return 0;
    }
    util::mkdir(TMP_SCRIPT_FUNC_PATH);
    let n = next_record(TMP_SCRIPT_FUNC_PATH);
    util::write(&format!("{}/{}", TMP_SCRIPT_FUNC_PATH, n), &format!("{}\n", record));
    0
}

/// `run_process_queue`: start every queued command not already running (ls order), move the
/// entries to `script_func/queued_<n>`.
pub fn run_process_queue() {
    if std::path::Path::new(TMP_PROCESS_LIST_PATH).is_dir() {
        util::mkdir(TMP_SCRIPT_FUNC_PATH);
        let mut names: Vec<String> = std::fs::read_dir(TMP_PROCESS_LIST_PATH)
            .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
            .unwrap_or_default();
        names.sort();
        for n in names {
            let src = format!("{}/{}", TMP_PROCESS_LIST_PATH, n);
            let cmd = util::read(&src).trim().to_string();
            let check = cmd_check(&cmd);
            if !cmd.is_empty() && !list_procs().iter().any(|p| p.cmdline.contains(&check)) {
                spawn_shell(&cmd);
            }
            let dst = format!("{}/queued_{}", TMP_SCRIPT_FUNC_PATH, n);
            if std::fs::rename(&src, &dst).is_err() {
                util::write(&dst, &util::read(&src));
            }
        }
    }
    util::rm_rf(TMP_PROCESS_LIST_PATH);
}

// ====================================================================== small utils.sh helpers

/// `has_1_65535 VAL`
pub fn has_1_65535(val: &str) -> bool {
    format!(",{},", val.replace(':', "-")).contains(",1-65535,")
}

/// `get_ip_port_from HOST` → (ip, port) — port = digits after the last `:`/`#` at the end.
/// With `uci` (UCIPRIORITY), HOST is a section id whose `address`/`port` take priority.
pub fn get_ip_port_from(host: &str, uci: Option<&Config>) -> (String, String) {
    let parse = |h: &str| -> (String, String) {
        let b = h.as_bytes();
        let mut i = b.len();
        while i > 0 && b[i - 1].is_ascii_digit() {
            i -= 1;
        }
        if i > 0 && (b[i - 1] == b':' || b[i - 1] == b'#') && i > 1 {
            let port = h[i..].to_string();
            if port.is_empty() {
                // `[:#]` followed by nothing: sed prints an empty port; the ip keeps the separator
                return (h.to_string(), String::new());
            }
            // ip = "${host%%[:#]port*}" (shortest-from-left match of the first "[:#]port")
            let pat1 = format!(":{}", port);
            let pat2 = format!("#{}", port);
            let cut = [h.find(&pat1), h.find(&pat2)].into_iter().flatten().min().unwrap_or(i - 1);
            return (h[..cut].to_string(), port);
        }
        (h.to_string(), String::new())
    };
    let (ip, port) = parse(host);
    match uci {
        Some(cfg) => {
            let p = cfg.get_or(host, "port", &port);
            let ip2 = if p.is_empty() {
                host.to_string()
            } else {
                let cut = [host.find(&format!(":{}", p)), host.find(&format!("#{}", p))].into_iter().flatten().min();
                match cut {
                    Some(c) => host[..c].to_string(),
                    None => host.to_string(),
                }
            };
            (cfg.get_or(host, "address", &ip2), p)
        }
        None => (ip, port),
    }
}

/// `hosts_foreach` splitting: hosts separated by spaces or commas.
pub fn split_hosts(s: &str) -> Vec<String> {
    s.split([' ', ',', '\n', '\t']).filter(|x| !x.is_empty()).map(|x| x.to_string()).collect()
}

/// `get_enabled_anonymous_secs TYPE` → `@TYPE[n]` refs whose `enabled == '1'`.
pub fn get_enabled_anonymous_secs(cfg: &Config, stype: &str) -> Vec<String> {
    cfg.sections_of(stype).filter(|s| s.is("enabled", "1")).map(|s| format!("@{}[{}]", stype, s.index)).collect()
}

/// `get_node_host_ip NODE`
pub fn get_node_host_ip(cfg: &Config, node: &str) -> String {
    let address = cfg.s(node, "address");
    if address.is_empty() {
        return String::new();
    }
    let fam = if cfg.s(node, "use_ipv6") == "1" { "ipv6" } else { "ipv4" };
    util::get_host_ip(fam, &address, 3).unwrap_or_default()
}

/// `get_geoip CODE ipv4|ipv6|other` → newline separated CIDRs (cached in
/// `$TMP_PATH2/geo_output/geoip-<CODE>-<type>`).
pub fn get_geoip(cfg: &Config, code: &str, typ: &str) -> String {
    let out_dir = format!("{}/geo_output", TMP_PATH2);
    util::mkdir(&out_dir);
    let output = format!("{}/geoip-{}-{}", out_dir, code, typ);
    let non_empty = |p: &str| std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false);
    if !non_empty(&output) {
        let asset = cfg.s("@global_rules[0]", "v2ray_location_asset");
        let geoip = format!("{}/geoip.dat", asset.strip_suffix('/').unwrap_or(&asset));
        let bin = util::first_type(&cfg.s("@global_app[0]", "geoview_file"), "geoview");
        let Some(bin) = bin.filter(|_| non_empty(&geoip)) else { return String::new() };
        let mut args: Vec<&str> = vec!["-input", &geoip, "-list", code];
        match typ {
            "ipv4" => args.push("-ipv6=false"),
            "ipv6" => args.push("-ipv4=false"),
            _ => {}
        }
        args.extend(["-lowmem=true", "-output", &output]);
        let _ = Command::new(&bin).args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    if non_empty(&output) {
        util::read(&output)
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------- routes (network.sh)

fn ifstatus(iface: &str) -> Value {
    serde_json::from_str(&util::cmd_out("ubus", &["call", &format!("network.interface.{}", iface), "status"])).unwrap_or(Value::Null)
}

/// `network_get_gateway VAR IFACE` (active default route nexthop, without table).
pub fn network_get_gateway(iface: &str) -> Option<String> {
    let st = ifstatus(iface);
    st["route"].as_array()?.iter().find(|r| r["target"] == "0.0.0.0" && r.get("table").is_none()).and_then(|r| r["nexthop"].as_str()).map(|s| s.to_string())
}
/// `network_get_device VAR IFACE` (`l3_device`).
pub fn network_get_device(iface: &str) -> Option<String> {
    ifstatus(iface)["l3_device"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// `add_ip2route HOST IFACE`
pub fn add_ip2route(host: &str, iface: &str) -> bool {
    let Some(ip) = util::get_host_ip("ipv4", host, 3) else {
        logi(1, "Unable to resolve [%s], route table addition failed!", &[host]);
        return false;
    };
    let remarks = if ip != host { format!("{}({})", host, ip) } else { host.to_string() };
    let gateway = network_get_gateway(iface);
    let device = network_get_device(iface)
        .or_else(|| ifstatus(iface)["device"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()))
        .unwrap_or_else(|| iface.to_string());
    match gateway {
        Some(gw) => {
            let _ = Command::new("route").args(["add", "-host", &ip, "gw", &gw, "dev", &device]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            util::append_file(&format!("{}/{}", TMP_ROUTE_PATH, device), &ip);
            logi(1, "[%s] was successfully added to the routing table of interface [%s]!", &[&remarks, &device]);
            true
        }
        None => {
            logi(1, "Adding [%s] to the [%s] routing table failed! The reason is that the [%s] gateway cannot be found.", &[&remarks, &device, &device]);
            false
        }
    }
}

/// `delete_ip2route`
pub fn delete_ip2route() {
    let Ok(rd) = std::fs::read_dir(TMP_ROUTE_PATH) else { return };
    for e in rd.flatten() {
        let dev = e.file_name().to_string_lossy().to_string();
        for ip in util::read(&e.path().to_string_lossy()).split_whitespace() {
            let _ = Command::new("route").args(["del", "-host", ip, "dev", &dev]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
}

// ====================================================================== runtime context

/// Direct DNS information (`get_direct_dns`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DirectDns {
    /// `ISP_DNS`
    pub isp_dns: Vec<String>,
    /// `ISP_DNS6`
    pub isp_dns6: Vec<String>,
    /// `DEFAULT_DNS`
    pub default_dns: String,
    /// `AUTO_DNS` (comma list `ip[#port]`)
    pub auto_dns: String,
    /// `RETURN_DNS` (comma list `ip[#port[#proto]]`)
    pub return_dns: String,
    /// `DIRECT_DNS_PROTO` / `_SERVER` / `_PORT`
    pub proto: String,
    pub server: String,
    pub port: String,
    /// `DIRECT_DNS_DNSMASQ_SERVER` (only for udp direct DNS from `@global[0].direct_dns`)
    pub dnsmasq_server: String,
}

/// Shell globals of app.sh (what the sourced firewall scripts and the launchers see).
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub enabled: String,
    pub node: String,
    pub enabled_default_acl: bool,
    pub enabled_acls: bool,
    pub socks_enabled: bool,
    pub tcp_proxy_way: String,
    pub proxy_ipv6: bool,
    /// `DIRECT_DNS_QUERY_STRATEGY` (empty unless `get_config` ran, like upstream CLI calls)
    pub direct_dns_query_strategy: String,
    pub dns: DirectDns,
    pub default_dnsmasq_conf: String,
    pub default_dnsmasq_conf_path: String,
    /// `QUEUE_RUN`
    pub queue_run: bool,
    /// `nftflag`
    pub nftflag: bool,
    /// `USE_TABLES` (`nftables` | `iptables` | "")
    pub use_tables: String,
    /// `NO_REC_PROCESS`
    pub no_rec_process: bool,
    pub xray_bin: Option<String>,
    pub singbox_bin: Option<String>,
    /// `$.node_order[*]` of the ACL JSON
    pub acl_node_order: Vec<String>,
}

static CTX: Mutex<Option<Ctx>> = Mutex::new(None);

fn set_global_ctx(c: Option<Ctx>) {
    if let Ok(mut g) = CTX.lock() {
        *g = c;
    }
}

/// The context of the running `start` (for the firewall backend), or a standalone one
/// rebuilt from UCI / cache when called from another process.
pub fn current_ctx() -> Ctx {
    if let Ok(g) = CTX.lock() {
        if let Some(c) = g.as_ref() {
            return c.clone();
        }
    }
    let cfg = Config::load(util::CONFIG);
    let mut c = Ctx::cli(&cfg);
    read_config_vars(&mut c, &cfg);
    c.queue_run = std::env::var("QUEUE_RUN").map(|v| v == "1").unwrap_or(false);
    match util::get_cache_var("USE_TABLES") {
        Some(t) if !t.is_empty() => {
            c.nftflag = t == "nftables";
            c.use_tables = t;
        }
        _ => {
            let (t, nf) = check_run_environment(&cfg, true);
            c.use_tables = t;
            c.nftflag = nf;
        }
    }
    c.default_dnsmasq_conf = util::get_cache_var("DEFAULT_DNSMASQ_CONF").unwrap_or_default();
    c.default_dnsmasq_conf_path = util::get_cache_var("DEFAULT_DNSMASQ_CONF_PATH").unwrap_or_else(|| format!("{}/acl_default_dnsmasq.d", TMP_ACL_PATH));
    c.acl_node_order = acl::saved_node_order();
    c
}

impl Ctx {
    /// What a fresh `app.sh run_socks|socks_node_switch` sees: binaries + `get_direct_dns`,
    /// `QUEUE_RUN=0`, `NO_REC_PROCESS` from the environment.
    pub fn cli(cfg: &Config) -> Ctx {
        Ctx {
            dns: get_direct_dns(cfg),
            queue_run: false,
            no_rec_process: std::env::var("NO_REC_PROCESS").map(|v| !v.is_empty()).unwrap_or(false),
            xray_bin: util::app_bin(cfg, "xray_file", "xray"),
            singbox_bin: util::app_bin(cfg, "sing_box_file", "sing-box"),
            nftflag: std::env::var("nftflag").map(|v| v == "1").unwrap_or(false),
            ..Default::default()
        }
    }
}

fn read_config_vars(c: &mut Ctx, cfg: &Config) {
    c.enabled = cfg.get_or("@global[0]", "enabled", "0");
    c.node = cfg.s("@global[0]", "node");
    c.enabled_default_acl = c.enabled == "1" && !c.node.is_empty() && cfg.stype(&c.node).as_deref() == Some("nodes");
    c.enabled_acls = cfg.get_or("@global[0]", "acl_enable", "0") == "1";
    c.socks_enabled = cfg.get_or("@global[0]", "socks_enabled", "0") == "1";
    c.tcp_proxy_way = cfg.get_or("@global_forwarding[0]", "tcp_proxy_way", "redirect");
    c.proxy_ipv6 = cfg.get_or("@global_forwarding[0]", "ipv6_tproxy", "0") == "1";
    c.direct_dns_query_strategy = cfg.get_or("@global[0]", "direct_dns_query_strategy", "UseIP");
}

/// Does `s` contain a match of `([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}`?
/// (Equivalent to: a hex digit, `:` or `::`, then a hex digit.)
pub fn has_ipv6_like(s: &str) -> bool {
    let b = s.as_bytes();
    let hx = |i: usize| i < b.len() && b[i].is_ascii_hexdigit();
    (1..b.len()).any(|j| b[j] == b':' && hx(j - 1) && (hx(j + 1) || (j + 1 < b.len() && b[j + 1] == b':' && hx(j + 2))))
}

/// Parse a resolv.conf → (`ISP_DNS`, `ISP_DNS6`).
pub fn parse_resolv(text: &str) -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = vec![];
    for line in text.lines() {
        // grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if !b[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let start = i;
            let mut parts = 0;
            let mut j = i;
            let mut end_ok = None;
            loop {
                let ds = j;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j == ds {
                    break;
                }
                parts += 1;
                if parts == 4 {
                    end_ok = Some(j);
                    break;
                }
                if j < b.len() && b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit() {
                    j += 1;
                } else {
                    break;
                }
            }
            match end_ok {
                Some(e) => {
                    let ip = &line[start..e];
                    if ip != "0.0.0.0" && ip != "127.0.0.1" && !v4.iter().any(|x| x == ip) {
                        v4.push(ip.to_string());
                    }
                    i = e;
                }
                None => {
                    // leftmost-longest: no match starting here; skip this digit run
                    while i < b.len() && b[i].is_ascii_digit() {
                        i += 1;
                    }
                }
            }
        }
    }
    let mut v6: Vec<String> = vec![];
    for line in text.lines() {
        if !has_ipv6_like(line) {
            continue;
        }
        let first = line.split('%').next().unwrap_or("");
        let Some(f2) = first.split(' ').filter(|s| !s.is_empty()).nth(1) else { continue };
        if f2 == "::1" || f2 == "::" || v6.iter().any(|x| x == f2) {
            continue;
        }
        v6.push(f2.to_string());
    }
    (v4, v6)
}

/// `DNSMASQ_UPSTREAM_DNS` from the `dhcp.@dnsmasq[0].server` list.
pub fn dnsmasq_upstream_dns(servers: &[String]) -> String {
    servers
        .iter()
        .flat_map(|s| s.split_whitespace())
        .filter(|s| !s.contains('/'))
        .map(|s| if s.contains('#') { s.to_string() } else { format!("{}#53", s) })
        .take(2)
        .collect::<Vec<_>>()
        .join(",")
}

/// Pure part of `get_direct_dns`.
pub fn compute_direct_dns(resolv: &str, dnsmasq_servers: &[String], direct_dns_protocol: &str, direct_dns: &str) -> DirectDns {
    let (isp, isp6) = parse_resolv(resolv);
    let up = dnsmasq_upstream_dns(dnsmasq_servers);
    let default_dns = if !up.is_empty() { up } else { isp.iter().take(2).cloned().collect::<Vec<_>>().join(",") };
    let auto_dns = if default_dns.is_empty() { "119.29.29.29".to_string() } else { default_dns.clone() };
    let mut d = DirectDns { isp_dns: isp, isp_dns6: isp6, default_dns, auto_dns: auto_dns.clone(), return_dns: auto_dns.clone(), proto: "udp".into(), ..Default::default() };
    let first = auto_dns.split(',').next().unwrap_or("");
    let mut it = first.split('#');
    d.server = it.next().unwrap_or("").to_string();
    d.port = it.next().filter(|s| !s.is_empty()).unwrap_or("53").to_string();
    if direct_dns_protocol == "tcp" || direct_dns_protocol == "udp" {
        let (a, p) = api::parse_dns(direct_dns);
        // `echo $(lua_api ...)` word splitting, then awk $1 / $2
        let joined = format!("{} {}", a, p);
        let mut w = joined.split_whitespace();
        d.proto = direct_dns_protocol.to_string();
        d.server = w.next().unwrap_or("").to_string();
        d.port = w.next().unwrap_or("").to_string();
        if d.proto == "udp" {
            d.dnsmasq_server = format!("{}#{}", d.server, d.port);
        }
        d.return_dns = format!("{},{}#{}#{}", d.return_dns, d.server, d.port, d.proto);
    }
    d
}

/// `get_direct_dns`
pub fn get_direct_dns(cfg: &Config) -> DirectDns {
    let mut rf = "/tmp/resolv.conf.d/resolv.conf.auto";
    if !std::fs::metadata(rf).map(|m| m.is_file() && m.len() > 0).unwrap_or(false) {
        rf = "/tmp/resolv.conf.auto";
    }
    let dhcp = Config::load("dhcp");
    let servers = dhcp.list_raw("@dnsmasq[0]", "server");
    compute_direct_dns(&util::read(rf), &servers, &cfg.s("@global[0]", "direct_dns_protocol"), &cfg.s("@global[0]", "direct_dns"))
}

/// `get_config` (start only): globals + caches DIRECT_DNS / DEFAULT_DNSMASQ_CONF[_PATH].
pub fn get_config(cfg: &Config) -> Ctx {
    let mut c = Ctx::cli(cfg);
    c.no_rec_process = std::env::var("NO_REC_PROCESS").map(|v| !v.is_empty()).unwrap_or(false);
    read_config_vars(&mut c, cfg);
    if c.dns.proto == "udp" {
        util::set_cache_var("DIRECT_DNS", &format!("{}#{}", c.dns.server, c.dns.port));
    } else {
        util::set_cache_var("DIRECT_DNS", c.dns.auto_dns.split(',').next().unwrap_or(""));
    }
    let mut conf_dir = "/tmp/dnsmasq.d".to_string();
    let dhcp = Config::load("dhcp");
    if let Some(sec) = dhcp.section("@dnsmasq[0]") {
        let f = format!("/var/etc/dnsmasq.conf.{}", sec.name);
        if util::exists(&f) {
            let d = util::read(&f).lines().find_map(|l| l.strip_prefix("conf-dir=").map(|v| v.split('=').next().unwrap_or("").to_string())).unwrap_or_default();
            if !d.is_empty() {
                conf_dir = d.strip_suffix('/').unwrap_or(&d).to_string();
            }
        }
    }
    c.default_dnsmasq_conf = format!("{}/dnsmasq-passwall2.conf", conf_dir);
    c.default_dnsmasq_conf_path = format!("{}/acl_default_dnsmasq.d", TMP_ACL_PATH);
    util::set_cache_var("DEFAULT_DNSMASQ_CONF", &c.default_dnsmasq_conf);
    util::set_cache_var("DEFAULT_DNSMASQ_CONF_PATH", &c.default_dnsmasq_conf_path);
    c.queue_run = true;
    c
}

/// `grep -qw WORD` (word = `[A-Za-z0-9_]+`).
/// `dnsmasq -v` lists compile options as whitespace-separated tokens (`nftset` / `no-nftset`).
pub fn dnsmasq_has_opt(info: &str, opt: &str) -> bool {
    info.split_whitespace().any(|t| t == opt)
}

pub fn has_word(text: &str, w: &str) -> bool {
    let wc = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = text.as_bytes();
    let mut start = 0;
    while let Some(off) = text[start..].find(w) {
        let i = start + off;
        let j = i + w.len();
        if (i == 0 || !wc(b[i - 1])) && (j >= b.len() || !wc(b[j])) {
            return true;
        }
        start = i + 1;
    }
    false
}

/// `check_run_environment` → (`USE_TABLES`, `nftflag`). `quiet` suppresses the log lines.
pub fn check_run_environment(cfg: &Config, quiet: bool) -> (String, bool) {
    let prefer_nft = cfg.get_or("@global_forwarding[0]", "prefer_nft", "1");
    let info = util::cmd_out("dnsmasq", &["-v"]);
    let ver = info.lines().next().and_then(|l| l.rfind("version ").map(|i| l[i + 8..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect::<String>())).unwrap_or_default();
    // upstream quirk: `grep -w nftset` also matches "no-nftset" in the compile options, so a
    // stock dnsmasq (no-ipset no-nftset) was taken as nftset-capable and the generated
    // nftset directives made the ACL dnsmasq fail to start; match the exact option instead.
    let dnsmasq_ipset = dnsmasq_has_opt(&info, "ipset") as u8;
    let dnsmasq_nftset = dnsmasq_has_opt(&info, "nftset") as u8;
    let has_ipt = (command_v("iptables-legacy").is_some() || command_v("iptables").is_some()) as u8;
    let has_ipset = command_v("ipset").is_some() as u8;
    let has_fw4 = command_v("fw4").is_some() as u8;
    let lg = |fmt: &str, args: &[&str]| {
        if !quiet {
            logi(0, fmt, args)
        }
    };
    let mut use_tables = String::new();
    if prefer_nft == "1" {
        if dnsmasq_nftset == 1 && has_fw4 == 1 {
            use_tables = "nftables".into();
        } else if has_ipset == 1 && has_ipt == 1 && dnsmasq_ipset == 1 {
            lg("Warning: The %s application environment is incomplete. Switch to %s. (%s)", &["nftables (fw4)", "iptables", &format!("has_fw4:{}/dnsmasq_nftset:{}", has_fw4, dnsmasq_nftset)]);
            use_tables = "iptables".into();
        }
    } else if has_ipset == 1 && has_ipt == 1 && dnsmasq_ipset == 1 {
        use_tables = "iptables".into();
    } else if dnsmasq_nftset == 1 && has_fw4 == 1 {
        lg("Warning: The %s application environment is incomplete. Switch to %s. (%s)", &["iptables (fw3)", "nftables", &format!("has_ipt:{}/has_ipset:{}/dnsmasq_ipset:{}", has_ipt, has_ipset, dnsmasq_ipset)]);
        use_tables = "nftables".into();
    }
    let mut nftflag = false;
    if !use_tables.is_empty() {
        let (path, ext) = if std::path::Path::new("/lib/apk/packages").is_dir() { ("/lib/apk/packages", ".list") } else { ("/usr/lib/opkg/info", ".control") };
        let deps: &[&str] = if use_tables == "iptables" {
            &["iptables-mod-tproxy", "iptables-mod-socket", "iptables-mod-iprange", "iptables-mod-conntrack-extra", "iptables-mod-extra", "kmod-ipt-nat"]
        } else {
            nftflag = true;
            let vnum: String = ver.chars().filter(|c| c.is_ascii_digit()).collect();
            if vnum.parse::<u64>().unwrap_or(0) < 290 {
                lg("Note: Dnsmasq (%s) is below 2.90. Upgrading is recommended to improve stability.", &[&ver]);
            }
            &["kmod-nft-socket", "kmod-nft-tproxy", "kmod-nft-nat"]
        };
        for d in deps {
            let f = format!("{}/{}{}", path, d, ext);
            if !std::fs::metadata(&f).map(|m| m.len() > 0).unwrap_or(false) {
                lg("Warning: %s transparent proxy is missing basic dependency %s!", &[&use_tables, d]);
            }
        }
    } else if !quiet {
        log(
            0,
            &format!(
                "{} (has_fw4:{}/has_ipt:{}/has_ipset:{}/dnsmasq_nftset:{}/dnsmasq_ipset:{})",
                i18n("Warning: Not compatible with any transparent proxy system environment.", &[]),
                has_fw4,
                has_ipt,
                has_ipset,
                dnsmasq_nftset,
                dnsmasq_ipset
            ),
        );
    }
    (use_tables, nftflag)
}

// ====================================================================== generators

/// `print(jsonc.stringify(cfg, 1))` into a file (tab indented). None → empty file.
pub fn write_json(path: &str, v: Option<&Value>) -> bool {
    let s = match v {
        Some(v) => {
            use serde::Serialize;
            let mut buf = Vec::new();
            let fmt = serde_json::ser::PrettyFormatter::with_indent(b"\t");
            let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
            if v.serialize(&mut ser).is_err() {
                return false;
            }
            buf.push(b'\n');
            String::from_utf8_lossy(&buf).to_string()
        }
        None => String::new(),
    };
    util::write(path, &s)
}

/// Non-empty arg value (`[ -n "$k" ]`).
fn nz<'a>(a: &'a Args, k: &str) -> Option<&'a str> {
    a.get(k).map(|s| s.as_str()).filter(|s| !s.is_empty())
}

fn put(j: &mut Args, k: &str, v: &str) {
    j.insert(k.to_string(), v.to_string());
}

/// The DoH part shared by run_xray / run_singbox: (url, host, port, bootstrap).
pub fn doh_parts(remote_dns_doh: &str) -> (String, String, String, String) {
    let url = remote_dns_doh.split(',').next().unwrap_or("").trim().to_string();
    let host_port = api::get_domain_from_url(&url);
    let mut hp = host_port.split(':');
    let host = hp.next().unwrap_or("").to_string();
    let port = hp.next().filter(|s| !s.is_empty()).unwrap_or("443").to_string();
    let mut bootstrap = match remote_dns_doh.split_once(',') {
        Some((_, rest)) => rest.to_string(),
        None => String::new(),
    };
    if api::is_ip(&host) {
        bootstrap = host.clone();
    }
    (url, host, port, bootstrap)
}

/// Shared head of run_xray/run_singbox: socks/http inbounds, direct DNS (+ direct ipset DNS
/// server), returns (json, dns_msg or None).
fn core_common(ctx: &Ctx, cfg: &Config, a: &Args, j: &mut Args, singbox: bool) -> Option<String> {
    let node = a.s("node");
    let flag = a.s("flag");
    if !flag.is_empty() {
        kill_flag(&flag, false);
        put(j, "flag", &flag);
    }
    if let (Some(addr), Some(port)) = (nz(a, "socks_address"), nz(a, "socks_port")) {
        put(j, "local_socks_address", addr);
        put(j, "local_socks_port", port);
        if let (Some(u), Some(p)) = (nz(a, "socks_username"), nz(a, "socks_password")) {
            put(j, "local_socks_username", u);
            put(j, "local_socks_password", p);
        }
    }
    if let (Some(addr), Some(port)) = (nz(a, "http_address"), nz(a, "http_port")) {
        put(j, "local_http_address", addr);
        put(j, "local_http_port", port);
        if let (Some(u), Some(p)) = (nz(a, "http_username"), nz(a, "http_password")) {
            put(j, "local_http_username", u);
            put(j, "local_http_password", p);
        }
    }
    let mut d_proto = ctx.dns.proto.clone();
    let mut d_server = ctx.dns.server.clone();
    let mut d_port = ctx.dns.port.clone();
    let mut log_out = None;
    if let Some(dns_listen_port) = nz(a, "dns_listen_port") {
        let mut dns_msg = format!("DNS[{}]:({}", dns_listen_port, i18n("Direct DNS: %s", &[&format!("{}://{}:{}", d_proto, d_server, d_port)]));
        put(j, "dns_listen_port", dns_listen_port);
        if let Some(c) = nz(a, "dns_cache") {
            put(j, "dns_cache", c);
        }
        let write_ipset_direct = cfg.s(&node, "protocol") == "_shunt" && cfg.get_or(&node, "write_ipset_direct", "0") == "1";
        if write_ipset_direct {
            let port = util::get_new_port("auto", "");
            let conf = format!("{}/dns_{}_direct.conf", TMP_ACL_PATH, flag);
            let set4 = format!("psw2_{}_white", node);
            let set6 = format!("psw2_{}_white6", node);
            let (ipset, nftset) = if ctx.nftflag {
                (String::new(), format!("4#inet#passwall2#{},6#inet#passwall2#{}", set4, set6))
            } else {
                (format!("{},{}", set4, set6), String::new())
            };
            run_ipset_dns_server(ctx, &port.to_string(), &d_proto, &format!("{}#{}", d_server, d_port), &ipset, &nftset, &conf);
            d_proto = "udp".into();
            d_server = "127.0.0.1".into();
            d_port = port.to_string();
            if !ipset.is_empty() {
                put(j, "direct_ipset", &ipset);
                util::set_cache_var(&format!("node_{}_direct_ipset4", node), &set4);
                util::set_cache_var(&format!("node_{}_direct_ipset6", node), &set6);
            }
            if !nftset.is_empty() {
                put(j, "direct_nftset", &nftset);
                util::set_cache_var(&format!("node_{}_direct_nftset4", node), &set4);
                util::set_cache_var(&format!("node_{}_direct_nftset6", node), &set6);
            }
        }
        let proto = a.s("remote_dns_protocol");
        let udp_like = if singbox { proto == "udp" || proto == "quic" } else { proto == "udp" };
        let tcp_like = if singbox { proto == "tcp" || proto == "tls" } else { proto == "tcp" };
        let doh_like = if singbox { proto == "doh" || proto == "http3" } else { proto == "doh" };
        if udp_like {
            put(j, "remote_dns_udp_server", &a.s("remote_dns_udp_server"));
            put(j, "remote_dns_udp_port", &a.s("remote_dns_udp_port"));
            if proto == "quic" {
                put(j, "remote_dns_quic", "1");
            }
            dns_msg = format!("{} {}", dns_msg, i18n("Remote DNS: %s", &[&format!("{}://{}:{}", proto, a.s("remote_dns_udp_server"), a.s("remote_dns_udp_port"))]));
        } else if tcp_like {
            put(j, "remote_dns_tcp_server", &a.s("remote_dns_tcp_server"));
            put(j, "remote_dns_tcp_port", &a.s("remote_dns_tcp_port"));
            if proto == "tls" {
                put(j, "remote_dns_tls", "1");
            }
            dns_msg = format!("{} {}", dns_msg, i18n("Remote DNS: %s", &[&format!("{}://{}:{}", proto, a.s("remote_dns_tcp_server"), a.s("remote_dns_tcp_port"))]));
        } else if doh_like {
            let (url, host, port, bootstrap) = doh_parts(&a.s("remote_dns_doh"));
            if !bootstrap.is_empty() {
                put(j, "remote_dns_doh_ip", &bootstrap);
            }
            put(j, "remote_dns_doh_port", &port);
            put(j, "remote_dns_doh_url", &url);
            put(j, "remote_dns_doh_host", &host);
            if proto == "http3" {
                put(j, "remote_dns_http3", "1");
            }
            dns_msg = format!("{} {}", dns_msg, i18n("Remote DNS: %s", &[&url]));
        }
        if a.g("remote_fakedns") == Some("1") {
            put(j, "remote_dns_fake", "1");
            if !singbox {
                put(j, "remote_dns_fake_strategy", &a.s("remote_dns_query_strategy"));
            }
            dns_msg = format!("{} + FakeDNS ", dns_msg);
        }
        for k in ["remote_dns_detour", "remote_dns_query_strategy", "remote_dns_client_ip"] {
            if let Some(v) = nz(a, k) {
                put(j, k, v);
            }
        }
        if singbox {
            if let Some(v) = nz(a, "remote_rewrite_ttl") {
                put(j, "remote_rewrite_ttl", v);
            }
        }
        log_out = Some(format!("{})", dns_msg));
    }
    put(j, &format!("direct_dns_{}_server", d_proto), &d_server);
    put(j, &format!("direct_dns_{}_port", d_proto), &d_port);
    put(j, "direct_dns_query_strategy", &a.s("direct_dns_query_strategy"));
    if let Some(rp) = nz(a, "redir_port") {
        put(j, "redir_port", rp);
        util::set_cache_var(&format!("node_{}_redir_port", node), rp);
        put(j, "tcp_proxy_way", &ctx.tcp_proxy_way);
        log_out = log_out.map(|l| format!("{}[{}] {}", if singbox { "Sing-Box" } else { "Xray" }, rp, l));
    }
    put(j, "node", &node);
    log_out
}

/// Result of a core launch: `Err(test_log_file)` (upstream `_error_log_file`) on failure.
pub type CoreResult = Result<(), (i32, String)>;

/// `run_xray k=v...`
pub fn run_xray(ctx: &Ctx, cfg: &Config, a: &Args) -> CoreResult {
    let log_file = nz(a, "log_file").unwrap_or("/dev/null").to_string();
    let loglevel = nz(a, "loglevel").map(|s| s.to_string()).unwrap_or_else(|| cfg.get_or("@global[0]", "loglevel", "warning"));
    let mut j = Args::new();
    put(&mut j, "loglevel", &loglevel);
    let log_out = core_common(ctx, cfg, a, &mut j, false);
    let config_file = a.s("config_file");
    write_json(&config_file, crate::xray::gen_config(&j).as_ref());
    let test_log = if log_file == "/dev/null" { format!("{}/test.log", TMP_PATH) } else { log_file.clone() };
    let status = match &ctx.xray_bin {
        Some(bin) => {
            let out = std::fs::File::create(&test_log).map(Stdio::from).unwrap_or_else(|_| Stdio::null());
            Command::new(bin).args(["run", "-test", "-c", &config_file]).stdin(Stdio::null()).stdout(out).stderr(Stdio::null()).status().map(|s| s.code().unwrap_or(1)).unwrap_or(127)
        }
        None => 127,
    };
    if status != 0 {
        return Err((status, test_log));
    }
    ln_run(ctx, ctx.queue_run, ctx.xray_bin.as_deref(), "xray", &log_file, &["run".into(), "-c".into(), config_file]);
    if let Some(l) = log_out {
        log(2, &l.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Ok(())
}

/// `sing-box version` → the `Tags:` value.
pub fn singbox_tags(bin: &str) -> String {
    util::cmd_out(bin, &["version"]).lines().find(|l| l.contains("Tags:")).and_then(|l| l.split_whitespace().nth(1)).unwrap_or("").to_string()
}

/// `run_singbox k=v...`
pub fn run_singbox(ctx: &Ctx, cfg: &Config, a: &Args) -> CoreResult {
    let node = a.s("node");
    if cfg.s(&node, "type").is_empty() {
        return Err((1, String::new()));
    }
    let log_file = nz(a, "log_file").unwrap_or("/dev/null").to_string();
    let loglevel = nz(a, "loglevel").map(|s| s.to_string()).unwrap_or_else(|| cfg.get_or("@global[0]", "loglevel", "warn"));
    let mut j = Args::new();
    put(&mut j, "tags", &ctx.singbox_bin.as_deref().map(singbox_tags).unwrap_or_default());
    if log_file == "/dev/null" {
        put(&mut j, "log", "0");
    } else {
        put(&mut j, "log", "1");
        put(&mut j, "logfile", &log_file);
    }
    put(&mut j, "loglevel", &loglevel);
    let log_out = core_common(ctx, cfg, a, &mut j, true);
    let config_file = a.s("config_file");
    write_json(&config_file, crate::singbox::gen_config(&j).as_ref());
    let test_log = if log_file == "/dev/null" { format!("{}/test.log", TMP_PATH) } else { log_file.clone() };
    let status = match &ctx.singbox_bin {
        Some(bin) => {
            let out = std::fs::File::create(&test_log).ok();
            let err = out.as_ref().and_then(|f| f.try_clone().ok());
            Command::new(bin)
                .args(["check", "-c", &config_file])
                .stdin(Stdio::null())
                .stdout(out.map(Stdio::from).unwrap_or_else(Stdio::null))
                .stderr(err.map(Stdio::from).unwrap_or_else(Stdio::null))
                .status()
                .map(|s| s.code().unwrap_or(1))
                .unwrap_or(127)
        }
        None => 127,
    };
    if status != 0 {
        return Err((status, test_log));
    }
    ln_run(ctx, ctx.queue_run, ctx.singbox_bin.as_deref(), "sing-box", &log_file, &["run".into(), "-c".into(), config_file]);
    if let Some(l) = log_out {
        log(2, &l.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Ok(())
}

/// `${f%%.*}+http${f#${f%%.*}}`: insert `+http` before the first dot.
pub fn plus_http(f: &str) -> String {
    match f.find('.') {
        Some(i) => format!("{}+http{}", &f[..i], &f[i..]),
        None => format!("{}+http", f),
    }
}

/// `run_socks k=v...` (flag node bind socks_port config_file http_port http_config_file
/// relay_port log_file no_run). Returns 1 when the node cannot be started.
pub fn run_socks(ctx: &Ctx, cfg: &Config, a: &Args) -> i32 {
    let flag = a.s("flag");
    let node = a.s("node");
    let bind = a.s("bind");
    let socks_port = a.s("socks_port");
    let relay_port = a.s("relay_port");
    let no_run = nz(a, "no_run").is_some();
    let mut config_file = a.s("config_file");
    if !config_file.is_empty() && !config_file.contains(TMP_PATH) {
        config_file = format!("{}/{}", TMP_PATH, config_file);
    }
    let http_port = nz(a, "http_port").unwrap_or("0").to_string();
    let mut http_config_file = a.s("http_config_file");
    if !http_config_file.is_empty() && !http_config_file.contains(TMP_PATH) {
        http_config_file = format!("{}/{}", TMP_PATH, http_config_file);
    }
    let lf = a.s("log_file");
    // upstream quirk kept: a log_file already under TMP_PATH is also forced to /dev/null
    let log_file = if !lf.is_empty() && lf != "/dev/null" && !lf.contains(TMP_PATH) { format!("{}/{}", TMP_PATH, lf) } else { "/dev/null".to_string() };
    let typ = cfg.s(&node, "type").to_lowercase();
    let remarks = cfg.s(&node, "remarks");
    let mut server_host = cfg.s(&node, "address");
    let mut server_port = cfg.s(&node, "port");
    if !relay_port.is_empty() {
        server_host = "127.0.0.1".into();
        server_port = relay_port.clone();
    }
    let mut error_msg = None;
    let mut tmp = String::new();
    if !server_host.is_empty() && !server_port.is_empty() {
        if !util::check_host(&server_host) {
            logi(1, "Socks node: [%s]%s is an invalid server address and cannot be started!", &[&remarks, &server_host]);
            return 1;
        }
        tmp = format!("{}:{}", server_host, server_port);
    } else {
        error_msg = Some(i18n("For some reason, the configuration for this Socks service has been lost, and its startup has been aborted!", &[]));
    }
    if (typ == "sing-box" || typ == "xray") && ["_balancing", "_shunt", "_iface", "_urltest"].contains(&cfg.s(&node, "protocol").as_str()) {
        error_msg = None;
    }
    if error_msg.is_some() && (!cfg.s(&node, "hysteria_hop").is_empty() || !cfg.s(&node, "hysteria2_hop").is_empty() || cfg.s(&node, "hysteria2_realms") == "1") {
        error_msg = None;
    }
    if let Some(e) = error_msg {
        if bind != "127.0.0.1" {
            logi(1, "Socks node: [%s]%s, start failed %s:%s %s", &[&remarks, &tmp, &bind, &socks_port, &e]);
        }
        return 1;
    }
    if bind != "127.0.0.1" {
        logi(1, "Socks node: [%s]%s, starting %s:%s", &[&remarks, &tmp, &bind, &socks_port]);
    }

    let mut j = Args::new();
    put(&mut j, "node", &node);
    put(&mut j, "server_host", &server_host);
    put(&mut j, "server_port", &server_port);
    let mut http_flag = false;
    match typ.as_str() {
        "sing-box" | "xray" => {
            let sb = typ == "sing-box";
            if http_port != "0" {
                http_flag = true;
                config_file = plus_http(&config_file);
                put(&mut j, "local_http_address", &bind);
                put(&mut j, "local_http_port", &http_port);
            }
            if relay_port.is_empty() {
                // json_add_null server_host/server_port
                j.remove("server_host");
                j.remove("server_port");
            }
            if log_file != "/dev/null" {
                put(&mut j, "log", "1");
                put(&mut j, "loglevel", &cfg.get_or("@global[0]", "loglevel", "warn"));
                if sb {
                    put(&mut j, "logfile", &log_file);
                }
            }
            if no_run {
                put(&mut j, "no_run", "1");
            }
            put(&mut j, "flag", &flag);
            put(&mut j, "local_socks_address", &bind);
            put(&mut j, "local_socks_port", &socks_port);
            put(&mut j, &format!("direct_dns_{}_server", ctx.dns.proto), &ctx.dns.server);
            put(&mut j, &format!("direct_dns_{}_port", ctx.dns.proto), &ctx.dns.port);
            put(&mut j, "direct_dns_query_strategy", &ctx.direct_dns_query_strategy);
            if sb {
                write_json(&config_file, crate::singbox::gen_config(&j).as_ref());
                if !no_run {
                    ln_run(ctx, ctx.queue_run, ctx.singbox_bin.as_deref(), "sing-box", "/dev/null", &["run".into(), "-c".into(), config_file.clone()]);
                }
            } else {
                write_json(&config_file, crate::xray::gen_config(&j).as_ref());
                if !no_run {
                    ln_run(ctx, ctx.queue_run, ctx.xray_bin.as_deref(), "xray", &log_file, &["run".into(), "-c".into(), config_file.clone()]);
                }
            }
        }
        "ssr" => {
            put(&mut j, "local_addr", &bind);
            put(&mut j, "local_port", &socks_port);
            let r = ss::gen_config(cfg.section(&node), &j);
            write_json(&config_file, r.config.as_ref());
            ss::write_plugin(&r.plugin);
            if !no_run {
                ln_run(ctx, ctx.queue_run, util::first_type("ssr-local", "").as_deref(), "ssr-local", &log_file, &["-c".into(), config_file.clone(), "-v".into(), "-u".into()]);
            }
        }
        "ss-rust" => {
            put(&mut j, "local_socks_address", &bind);
            put(&mut j, "local_socks_port", &socks_port);
            if http_port != "0" {
                http_flag = true;
                config_file = plus_http(&config_file);
                put(&mut j, "local_http_address", &bind);
                put(&mut j, "local_http_port", &http_port);
            }
            if !no_run {
                let base = config_file.strip_suffix(".json").unwrap_or(&config_file);
                put(&mut j, "plugin_sh", &format!("{}_plugin.sh", base));
            }
            let r = ss::gen_config(cfg.section(&node), &j);
            write_json(&config_file, r.config.as_ref());
            ss::write_plugin(&r.plugin);
            if !no_run {
                ln_run(ctx, ctx.queue_run, util::first_type("sslocal", "").as_deref(), "sslocal", &log_file, &["-c".into(), config_file.clone(), "-v".into()]);
            }
        }
        _ => {}
    }

    // http to socks
    if !http_flag && http_port != "0" && !http_config_file.is_empty() && typ != "sing-box" && typ != "xray" && typ != "socks" {
        let mut j2 = Args::new();
        put(&mut j2, "local_http_port", &http_port);
        put(&mut j2, "server_proto", "socks");
        put(&mut j2, "server_address", "127.0.0.1");
        put(&mut j2, "server_port", &socks_port);
        // upstream passes the (normally empty) globals $_username / $_password
        put(&mut j2, "server_username", "");
        put(&mut j2, "server_password", "");
        let pick = if ctx.singbox_bin.is_some() {
            Some(("sing-box", ctx.singbox_bin.clone(), crate::singbox::gen_proto_config(&j2)))
        } else if ctx.xray_bin.is_some() {
            Some(("xray", ctx.xray_bin.clone(), crate::xray::gen_proto_config(&j2)))
        } else {
            None
        };
        if let Some((name, bin, conf)) = pick {
            write_json(&http_config_file, conf.as_ref());
            if !no_run {
                ln_run(ctx, ctx.queue_run, bin.as_deref(), name, "/dev/null", &["run".into(), "-c".into(), http_config_file.clone()]);
            }
        }
    }

    // upstream quirk: upstream compares the type *after* the http bridge renamed it to
    // sing-box/xray, so SS/SSR servers with an http port were never whitelisted. We use the
    // node's real type.
    if !no_run && server_host != "127.0.0.1" && typ != "sing-box" && typ != "xray" {
        util::append_file(&format!("{}/direct_node_list", TMP_PATH), &node);
    }
    0
}

/// Map `USE_TABLES` to the firewall CLI name.
fn fw_cmd(use_tables: &str) -> &'static str {
    if use_tables == "iptables" {
        "ipt"
    } else {
        "nft"
    }
}

/// `socks_node_switch flag=<socks_id> new_node=<node>`
pub fn socks_node_switch(ctx: &Ctx, cfg: &Config, a: &Args) -> i32 {
    let (Some(flag), Some(new_node)) = (nz(a, "flag"), nz(a, "new_node")) else { return 1 };
    for suffix in ["", "+http"] {
        let pf = format!("{}/{}{}_plugin.pid", TMP_PATH, flag, suffix);
        if let Some(pid) = util::read(&pf).lines().next().and_then(|l| l.trim().parse::<u32>().ok()) {
            util::kill_pids(&[pid], 9);
        }
    }
    kill_flag(flag, true);
    if let Ok(rd) = std::fs::read_dir(TMP_PATH) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if ["", "+http", "_http"].iter().any(|s| n.starts_with(&format!("{}{}", flag, s))) {
                util::rm_rf(&e.path().to_string_lossy());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(TMP_SCRIPT_FUNC_PATH) {
        for e in rd.flatten() {
            if util::read(&e.path().to_string_lossy()).contains(flag) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let bind = if cfg.get_or(flag, "bind_local", "0") == "1" { "127.0.0.1" } else { "0.0.0.0" };
    let port = cfg.s(flag, "port");
    let log_file = if cfg.get_or(flag, "log", "1") == "0" { String::new() } else { format!("{}.log", flag) };
    let mut r = Args::new();
    put(&mut r, "flag", flag);
    put(&mut r, "node", new_node);
    put(&mut r, "bind", bind);
    put(&mut r, "socks_port", &port);
    put(&mut r, "config_file", &format!("{}.json", flag));
    put(&mut r, "http_port", &cfg.get_or(flag, "http_port", "0"));
    put(&mut r, "http_config_file", &format!("{}_http.json", flag));
    put(&mut r, "log_file", &log_file);
    LOG_SUPPRESS.store(true, Ordering::Relaxed);
    run_socks(ctx, cfg, &r);
    sleep_s(2);
    let ok = port.parse::<u16>().map(|p| util::check_port_exists(p, "tcp") != 0).unwrap_or(false);
    if !ok {
        LOG_SUPPRESS.store(false, Ordering::Relaxed);
        return 1;
    }
    util::set_cache_var(flag, new_node);
    if let Some(t) = util::get_cache_var("USE_TABLES").filter(|t| !t.is_empty()) {
        crate::firewall::cli(fw_cmd(&t), &["filter_direct_node_list".to_string()]);
    }
    LOG_SUPPRESS.store(false, Ordering::Relaxed);
    0
}

/// `start_socks`
pub fn start_socks(ctx: &Ctx, cfg: &Config) {
    if !ctx.socks_enabled {
        return;
    }
    let ids: Vec<String> = cfg.sections_of("socks").map(|s| s.name.clone()).collect();
    if ids.is_empty() {
        return;
    }
    logi(0, "Analyzing the node configuration of the Socks service...", &[]);
    for id in ids {
        if cfg.get_or(&id, "enabled", "0") == "0" {
            continue;
        }
        let node = cfg.s(&id, "node");
        if node.is_empty() {
            continue;
        }
        let bind = if cfg.get_or(&id, "bind_local", "0") == "1" { "127.0.0.1" } else { "0.0.0.0" };
        let log_file = if cfg.get_or(&id, "log", "1") == "0" { String::new() } else { format!("{}.log", id) };
        let autoswitch = cfg.get_or(&id, "enable_autoswitch", "0") == "1";
        let mut r = Args::new();
        put(&mut r, "flag", &id);
        put(&mut r, "node", &node);
        put(&mut r, "bind", bind);
        put(&mut r, "socks_port", &cfg.s(&id, "port"));
        put(&mut r, "config_file", &format!("{}.json", id));
        put(&mut r, "http_port", &cfg.get_or(&id, "http_port", "0"));
        put(&mut r, "http_config_file", &format!("{}_http.json", id));
        put(&mut r, "log_file", &log_file);
        if autoswitch {
            // upstream: `NO_REC_PROCESS=1 app.sh run_socks ...` — a separate app.sh: direct DNS
            // only, immediate start, not recorded for the monitor.
            let mut c2 = Ctx::cli(cfg);
            c2.no_rec_process = true;
            run_socks(&c2, cfg, &r);
        } else {
            run_socks(ctx, cfg, &r);
        }
        util::set_cache_var(&id, &node);
        if autoswitch {
            let _ = util::spawn_bg(&self_bin(), &["socks-auto-switch".into(), id.clone()], "/dev/null");
        }
    }
}

// ====================================================================== cron

/// cron time spec `"<mm> <hh> * * <week|*>"` from week mode and `HH:MM`.
pub fn cron_time(week: &str, time: &str) -> String {
    let mut it = time.split(':');
    let hh = it.next().unwrap_or("");
    let mm = it.next().unwrap_or("");
    let w = if week == "7" { "*" } else { week };
    format!("{} {} * * {}", mm, hh, w)
}

const CRONTAB: &str = "/etc/crontabs/root";

/// Lines removed by `clean_crontab` (upstream patterns + ours).
fn cron_patterns() -> Vec<String> {
    vec![
        "/etc/init.d/passwall2".into(),
        "lua /usr/share/passwall2/rule_update.lua log".into(),
        "lua /usr/share/passwall2/subscribe.lua start".into(),
        format!("{} rule-update log", util::SELF_BIN),
        format!("{} subscribe start", util::SELF_BIN),
    ]
}

/// `clean_crontab`
pub fn clean_crontab() {
    let text = util::read(CRONTAB);
    if !util::exists(CRONTAB) {
        util::write(CRONTAB, "");
    }
    let pats = cron_patterns();
    let kept: Vec<&str> = text.lines().filter(|l| !pats.iter().any(|p| l.contains(p.as_str()))).collect();
    let mut s = kept.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    if s != text {
        util::write(CRONTAB, &s);
    }
    let pids: Vec<u32> = list_procs().into_iter().filter(|p| (p.cmdline.contains("passwall2/") && p.cmdline.contains("tasks.sh")) || p.is_self_cmd("tasks")).map(|p| p.pid).collect();
    kill_pids_excluding(&pids);
    let _ = std::fs::remove_file(format!("{}/passwall2_tasks.lock", LOCK_PATH));
}

fn cron_restart() {
    let _ = Command::new("/etc/init.d/cron").arg("restart").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// `(msgid, args)` of a log line to emit.
pub type LogMsg = (String, Vec<String>);

/// Cron lines written by `start_crontab` (pure; returns (lines, update_loop, log msgs)).
pub fn crontab_entries(cfg: &Config, setsid: bool) -> (Vec<String>, bool, Vec<LogMsg>) {
    let ss = if setsid { "setsid " } else { "" };
    let me = util::SELF_BIN;
    let mut lines = vec![];
    let mut logs: Vec<LogMsg> = vec![];
    let mut update_loop = false;
    let d = "@global_delay[0]";
    let stop_w = cfg.s(d, "stop_week_mode");
    if !stop_w.is_empty() {
        lines.push(format!("{} {}/etc/init.d/passwall2 stop cron > /dev/null 2>&1 &", cron_time(&stop_w, &cfg.s(d, "stop_time_mode")), ss));
        logs.push(("Scheduled tasks: Auto stop service.".into(), vec![]));
    }
    let start_w = cfg.s(d, "start_week_mode");
    if !start_w.is_empty() {
        lines.push(format!("{} {}/etc/init.d/passwall2 start cron > /dev/null 2>&1 &", cron_time(&start_w, &cfg.s(d, "start_time_mode")), ss));
        logs.push(("Scheduled tasks: Auto start service.".into(), vec![]));
    }
    let restart_w = cfg.s(d, "restart_week_mode");
    if !restart_w.is_empty() {
        if restart_w == "8" {
            update_loop = true;
        } else {
            lines.push(format!("{} {}/etc/init.d/passwall2 restart cron > /dev/null 2>&1 &", cron_time(&restart_w, &cfg.s(d, "restart_time_mode")), ss));
        }
        logs.push(("Scheduled tasks: Auto restart service.".into(), vec![]));
    }
    let r = "@global_rules[0]";
    let rules_w = cfg.s(r, "update_week_mode");
    if !rules_w.is_empty() {
        if rules_w == "8" {
            update_loop = true;
        } else {
            lines.push(format!("{} {}{} rule-update log all cron > /dev/null 2>&1 &", cron_time(&rules_w, &cfg.s(r, "update_time_mode")), ss, me));
        }
        logs.push(("Scheduled tasks: Auto update rules.".into(), vec![]));
    }
    let mut groups: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for s in cfg.sections_of("subscribe_list") {
        let w = s.s("update_week_mode");
        if !w.is_empty() {
            groups.entry(format!("{}_{}", w, s.s("update_time_mode"))).or_default().push(s.name.clone());
            logs.push(("Scheduled tasks: Auto update [%s] subscription.".into(), vec![s.s("remark")]));
        }
    }
    for (name, ids) in groups {
        let mut it = name.split('_');
        let w = it.next().unwrap_or("");
        let t = it.next().unwrap_or("");
        if w == "8" {
            update_loop = true;
        } else {
            lines.push(format!("{} {}{} subscribe start {} cron > /dev/null 2>&1 &", cron_time(w, t), ss, me, ids.join(",")));
        }
    }
    (lines, update_loop, logs)
}

/// `start_crontab ACTION`
pub fn start_crontab(ctx: &Ctx, cfg: &Config, action: &str) {
    let proxy = ctx.enabled_default_acl || ctx.enabled_acls;
    if proxy && cfg.get_or("@global_delay[0]", "start_daemon", "0") == "1" {
        let _ = util::spawn_bg(&self_bin(), &["monitor".into()], "/dev/null");
    }
    if action == "cron" {
        logi(0, "The task is currently running automatically as a scheduled task; no reconfiguration of the scheduled task is required.", &[]);
        return;
    }
    clean_crontab();
    if ctx.enabled != "1" {
        cron_restart();
        return;
    }
    let (lines, update_loop, logs) = crontab_entries(cfg, command_v("setsid").is_some());
    for (fmt, args) in &logs {
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        logi(0, fmt, &a);
    }
    if !lines.is_empty() {
        for l in &lines {
            util::append_file(CRONTAB, l);
        }
    }
    if proxy {
        if update_loop {
            let _ = util::spawn_bg(&self_bin(), &["tasks".into()], "/dev/null");
            logi(0, "Auto updates: Starts a cyclical update process.", &[]);
        }
    } else {
        logi(0, "Running in no proxy mode, it only allows scheduled tasks for starting and stopping services.", &[]);
    }
    cron_restart();
}

/// `stop_crontab ACTION`
pub fn stop_crontab(action: &str) {
    if action == "cron" {
        return;
    }
    clean_crontab();
    cron_restart();
}

// ====================================================================== haproxy / DNS helpers

/// `start_haproxy`
pub fn start_haproxy(ctx: &Ctx, cfg: &Config) {
    if cfg.get_or("@global_haproxy[0]", "balancing_enable", "0") != "1" {
        return;
    }
    let path = format!("{}/haproxy", TMP_PATH);
    let conf = "config.cfg";
    crate::haproxy::cli("haproxy", &["-path".into(), path.clone(), "-conf".into(), conf.into()]);
    let c0 = Ctx { queue_run: false, ..ctx.clone() };
    ln_run(&c0, false, util::first_type("haproxy", "").as_deref(), "haproxy", "/dev/null", &["-f".into(), format!("{}/{}", path, conf)]);
}

fn dns_helper(args: &[&str]) -> i32 {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    crate::dns::cli(&a)
}

/// `run_copy_dnsmasq flag listen_port local_dns tun_dns default_dns`
pub fn run_copy_dnsmasq(ctx: &Ctx, flag: &str, listen_port: &str, local_dns: &str, tun_dns: &str, default_dns: &str) {
    let conf = format!("{}/{}_dnsmasq.conf", TMP_ACL_PATH, flag);
    let conf_path = format!("{}/{}_dnsmasq.d", TMP_ACL_PATH, flag);
    let pid = format!("{}/{}_dnsmasq.pid", TMP_ACL_PATH, flag);
    util::mkdir(&conf_path);
    dns_helper(&["copy_instance", &json!({"LISTEN_PORT": listen_port, "DNSMASQ_CONF": conf}).to_string()]);
    dns_helper(&[
        "add_rule",
        &json!({
            "FLAG": flag, "TMP_DNSMASQ_PATH": conf_path, "DNSMASQ_CONF_FILE": conf, "DEFAULT_DNS": default_dns,
            "LOCAL_DNS": local_dns, "TUN_DNS": tun_dns, "NFTFLAG": if ctx.nftflag { "1" } else { "0" },
            "NO_LOGIC_LOG": std::env::var("NO_LOGIC_LOG").unwrap_or_else(|_| "0".into())
        })
        .to_string(),
    ]);
    let c0 = Ctx { queue_run: false, ..ctx.clone() };
    ln_run(&c0, false, util::first_type("dnsmasq", "").as_deref(), &format!("dnsmasq_{}", flag), "/dev/null", &["-C".into(), conf, "-x".into(), pid]);
    util::set_cache_var(&format!("ACL_{}_dns_port", flag), listen_port);
}

/// `run_ipset_dns_server`: chinadns-ng when available, else dnsmasq.
pub fn run_ipset_dns_server(ctx: &Ctx, listen_port: &str, proto: &str, server_dns: &str, ipset: &str, nftset: &str, config_file: &str) {
    let c0 = Ctx { queue_run: false, ..ctx.clone() };
    if let Some(bin) = util::first_type("chinadns-ng", "") {
        let vps = format!("{}/vpslist", TMP_ACL_PATH);
        if !std::fs::metadata(&vps).map(|m| m.len() > 0).unwrap_or(false) {
            util::write(&vps, &vpslist(&Config::load(util::CONFIG)));
        }
        util::write(config_file, &chinadns_ng_conf(listen_port, proto, server_dns, ipset, nftset));
        ln_run(&c0, false, Some(&bin), "chinadns-ng", "/dev/null", &["-C".into(), config_file.into(), "-v".into()]);
    } else {
        util::write(config_file, &ipset_dnsmasq_conf(listen_port, server_dns, ipset, nftset, "", ""));
        ln_run(&c0, false, util::first_type("dnsmasq", "").as_deref(), "dnsmasq", "/dev/null", &["-C".into(), config_file.into()]);
    }
}

/// Content of `$TMP_ACL_PATH/vpslist`: domains of every `*address` option.
pub fn vpslist(cfg: &Config) -> String {
    let mut out: Vec<String> = vec![];
    for s in &cfg.sections {
        for (k, v) in &s.options {
            // grep -E "(.address=|.download_address=)" on `uci show` lines
            if k.ends_with("address") {
                // `cut -d "'" -f 2` keeps the first element of a list
                let first = match v {
                    crate::uci::Value::Single(x) => x.clone(),
                    crate::uci::Value::List(l) => l.first().cloned().unwrap_or_default(),
                };
                for h in split_hosts(&first) {
                    let d = util::host_from_url(&h);
                    if d.chars().last().is_some_and(|c| c.is_ascii_alphabetic()) && !d.contains("engage.cloudflareclient.com") {
                        out.push(d);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        String::new()
    } else {
        format!("{}\n", out.join("\n"))
    }
}

/// chinadns-ng config of `run_ipset_chinadns_ng`.
pub fn chinadns_ng_conf(listen_port: &str, proto: &str, server_dns: &str, ipset: &str, nftset: &str) -> String {
    let mut set_names = String::new();
    let mut vps_set_names = String::new();
    if !ipset.is_empty() {
        set_names = ipset.to_string();
        vps_set_names = "psw2_vps,psw2_vps6".into();
    }
    if !nftset.is_empty() {
        let f: Vec<&str> = nftset.split(',').collect();
        let sub = |s: Option<&&str>| s.map(|x| x.get(2..).unwrap_or("").to_string()).unwrap_or_default();
        set_names = format!("{},{}", sub(f.first()), sub(f.get(1))).replace('#', "@");
        vps_set_names = "inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6".into();
    }
    format!(
        "bind-addr 127.0.0.1\nbind-port {lp}\nchina-dns {p}://{s}\ntrust-dns {p}://{s}\nfilter-qtype 65\nadd-tagchn-ip {sn}\ndefault-tag chn\ngroup vpslist\ngroup-dnl {acl}/vpslist\ngroup-upstream {p}://{s}\ngroup-ipset {vps}\n",
        lp = listen_port,
        p = proto,
        s = server_dns,
        sn = set_names,
        acl = TMP_ACL_PATH,
        vps = vps_set_names
    )
}

/// dnsmasq config of `run_ipset_dnsmasq`.
pub fn ipset_dnsmasq_conf(listen_port: &str, server_dns: &str, ipset: &str, nftset: &str, cache_size: &str, dns_forward_max: &str) -> String {
    let mut s = format!(
        "port={}\nno-poll\nno-resolv\nstrict-order\ncache-size={}\ndns-forward-max={}\n",
        listen_port,
        if cache_size.is_empty() { "0" } else { cache_size },
        if dns_forward_max.is_empty() { "1000" } else { dns_forward_max }
    );
    for i in server_dns.split(',').filter(|x| !x.is_empty()) {
        s.push_str(&format!("server={}\n", i));
    }
    if !ipset.is_empty() {
        s.push_str(&format!("ipset={}\n", ipset));
    }
    if !nftset.is_empty() {
        s.push_str(&format!("nftset={}\n", nftset));
    }
    s
}

// ====================================================================== acl_node

/// `acl_node`: start the core + DNS instance of every ACL node (`$.node_order[*]`). Called
/// by the firewall backend while it loads the ACLs (upstream: nftables/iptables.sh `start`).
pub fn acl_node() {
    ACL_NODE_RAN.store(true, Ordering::Relaxed);
    let ctx = current_ctx();
    let cfg = Config::load(util::CONFIG);
    let dhcp = Config::load("dhcp");
    if dhcp.s("@dnsmasq[0]", "dns_redirect") == "1" {
        let mut b = Batch::new();
        b.set("passwall2.@global[0].dnsmasq_dns_redirect", "1");
        let _ = b.commit();
        let mut b = Batch::new();
        b.set("dhcp.@dnsmasq[0].dns_redirect", "0");
        let _ = b.commit();
        dns_helper(&["restart", &json!({"LOG": "0"}).to_string()]);
    }
    let mut use_singbox = if ctx.singbox_bin.is_some() { Some(true) } else if ctx.xray_bin.is_some() { Some(false) } else { None };
    for nid in &ctx.acl_node_order {
        let file = format!("{}/acl_node_{}", TMP_ACL_PATH, nid);
        let Some(a) = acl::read_acl_node_args(nid) else { continue };
        let node = a.s("node");
        let flag = a.s("flag");
        let config_file = a.s("config_file");
        let typ = cfg.s(&node, "type").to_lowercase();
        if typ.is_empty() {
            continue;
        }
        if typ == "xray" && ctx.xray_bin.is_some() {
            use_singbox = Some(false);
        } else if typ == "sing-box" && ctx.singbox_bin.is_some() {
            use_singbox = Some(true);
        }
        let r = match use_singbox {
            Some(true) => run_singbox(&ctx, &cfg, &a),
            Some(false) => run_xray(&ctx, &cfg, &a),
            // upstream runs an empty $run_func (a no-op that "succeeds"); treat as failure
            None => Err((127, String::new())),
        };
        if let Err((_, errlog)) = r {
            logi(2, "[%s] process %s error, skip this transparent proxy!", &[&node, &config_file]);
            if !errlog.is_empty() {
                let t = util::read(&errlog);
                if !t.is_empty() {
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(util::LOG_FILE) {
                        use std::io::Write;
                        let _ = f.write_all(t.as_bytes());
                    }
                }
            }
            continue;
        }
        let dns_listen_port = a.s("dns_listen_port");
        let tun_dns = format!("127.0.0.1#{}", dns_listen_port);
        let default_dns = ctx.dns.auto_dns.clone();
        let local_dns = if !ctx.dns.dnsmasq_server.is_empty() { ctx.dns.dnsmasq_server.clone() } else { ctx.dns.auto_dns.clone() };
        let mut run_new_dnsmasq = "1".to_string();
        if flag == "acl_default" {
            util::set_cache_var(&format!("ACL_{}_node", flag), &node);
            util::set_cache_var(&format!("ACL_{}_node_socks_port", flag), &a.s("socks_port"));
            run_new_dnsmasq = cfg.get_or("@global[0]", "dns_redirect", "1");
            if run_new_dnsmasq != "1" {
                dns_helper(&["stretch"]);
                dns_helper(&[
                    "add_rule",
                    &json!({
                        "FLAG": flag, "TMP_DNSMASQ_PATH": ctx.default_dnsmasq_conf_path, "DNSMASQ_CONF_FILE": ctx.default_dnsmasq_conf,
                        "DEFAULT_DNS": default_dns, "LOCAL_DNS": local_dns, "TUN_DNS": tun_dns, "NFTFLAG": if ctx.nftflag { "1" } else { "0" },
                        "NO_LOGIC_LOG": std::env::var("NO_LOGIC_LOG").unwrap_or_else(|_| "0".into())
                    })
                    .to_string(),
                ]);
                let mut b = Batch::new();
                b.add_list("dhcp.@dnsmasq[0].addnmount", &ctx.default_dnsmasq_conf_path);
                let _ = b.commit();
                dns_helper(&["logic_restart"]);
            }
        }
        if run_new_dnsmasq == "1" {
            let port = util::get_new_port("auto", "").to_string();
            run_copy_dnsmasq(&ctx, &flag, &port, &local_dns, &tun_dns, &default_dns);
            let _ = util::spawn_bg(&self_bin(), &["lease2hosts".into()], "/dev/null");
            log(2, &format!("Dnsmasq[{}]:(127.0.0.1:{})", port, dns_listen_port));
        }
        let _ = std::fs::remove_file(&file);
    }
}

// ====================================================================== start / stop

fn set_rlimit_nofile(n: u64) {
    #[repr(C)]
    struct Rlimit {
        cur: u64,
        max: u64,
    }
    extern "C" {
        fn setrlimit(res: i32, rl: *const Rlimit) -> i32;
    }
    // RLIMIT_NOFILE = 7 on Linux (all arches but alpha/mips/sparc, where it is 5 on mips)
    #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
    const RLIMIT_NOFILE: i32 = 5;
    #[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
    const RLIMIT_NOFILE: i32 = 7;
    let rl = Rlimit { cur: n, max: n };
    unsafe {
        setrlimit(RLIMIT_NOFILE, &rl);
    }
}

fn sysctl_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}
fn sysctl_get(key: &str) -> String {
    util::read(&sysctl_path(key)).trim().to_string()
}
fn sysctl_set(key: &str, v: &str) {
    let _ = std::fs::write(sysctl_path(key), v);
}

fn logger(tag: &str, msg: &str) {
    let _ = Command::new("logger").args(["-t", tag, msg]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// `app.sh start ACTION` (no locking).
pub fn app_start(action: &str) -> i32 {
    if !pgrep_af(&format!("{}/bin", TMP_PATH)).is_empty() {
        logger("PW2-RESTART", "Upgrade or overload residue is detected, and the subprocess is being called to perform complete cleaning...");
        app_stop(action);
        sleep_s(2);
    }
    for d in ["/tmp/etc", "/tmp/log", TMP_PATH, TMP_BIN_PATH, TMP_SCRIPT_FUNC_PATH, TMP_ROUTE_PATH, TMP_ACL_PATH, TMP_PATH2] {
        util::mkdir(d);
    }
    let cfg = Config::load(util::CONFIG);
    let mut ctx = get_config(&cfg);
    let asset = cfg.get_or("@global_rules[0]", "v2ray_location_asset", "/usr/share/v2ray/");
    std::env::set_var("V2RAY_LOCATION_ASSET", &asset);
    std::env::set_var("XRAY_LOCATION_ASSET", &asset);
    std::env::set_var("ENABLE_DEPRECATED_GEOSITE", "true");
    std::env::set_var("ENABLE_DEPRECATED_GEOIP", "true");
    std::env::set_var("SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN", "1");
    set_rlimit_nofile(65535);
    start_haproxy(&ctx, &cfg);
    start_socks(&ctx, &cfg);
    let (use_tables, nftflag) = check_run_environment(&cfg, false);
    ctx.use_tables = use_tables;
    ctx.nftflag = nftflag;
    if !ctx.use_tables.is_empty() {
        let st = acl::run();
        ctx.acl_node_order = st.node_order.clone();
        if !util::exists(&format!("{}/acl_node_acl_default", TMP_ACL_PATH)) {
            ctx.enabled_default_acl = false;
        }
        if st.node_order.is_empty() {
            ctx.enabled_default_acl = false;
            ctx.enabled_acls = false;
        } else {
            ACL_NODE_RAN.store(false, Ordering::Relaxed);
            set_global_ctx(Some(ctx.clone()));
            std::env::set_var("nftflag", if ctx.nftflag { "1" } else { "0" });
            std::env::set_var("QUEUE_RUN", "1");
            crate::firewall::cli(fw_cmd(&ctx.use_tables), &["start".to_string()]);
            if !ACL_NODE_RAN.load(Ordering::Relaxed) {
                // the firewall backend must call app::acl_node() while loading the ACLs; make
                // sure the cores are started even if it did not.
                acl_node();
            }
            std::env::remove_var("QUEUE_RUN");
            util::set_cache_var("USE_TABLES", &ctx.use_tables);
        }
    }
    util::set_cache_var("ENABLED_DEFAULT_ACL", if ctx.enabled_default_acl { "1" } else { "0" });
    util::set_cache_var("ENABLED_ACLS", if ctx.enabled_acls { "1" } else { "0" });
    set_global_ctx(Some(ctx.clone()));
    if ctx.enabled_default_acl || ctx.enabled_acls {
        let v = sysctl_get("net.bridge.bridge-nf-call-iptables");
        util::set_cache_var("bak_bridge_nf_ipt", &v);
        sysctl_set("net.bridge.bridge-nf-call-iptables", "0");
        if ctx.proxy_ipv6 {
            let v = sysctl_get("net.bridge.bridge-nf-call-ip6tables");
            util::set_cache_var("bak_bridge_nf_ip6t", &v);
            sysctl_set("net.bridge.bridge-nf-call-ip6tables", "0");
        }
    }
    run_process_queue();
    start_crontab(&ctx, &cfg, action);
    logi(0, "Running complete!", &[]);
    util::echolog("\n");
    if ctx.enabled == "1" && action == "boot" {
        let ids: Vec<String> = cfg.sections_of("subscribe_list").filter(|s| s.get_or("boot_update", "0") == "1").map(|s| s.name.clone()).collect();
        if !ids.is_empty() {
            sleep_s(5);
            let _ = util::spawn_bg(&self_bin(), &["subscribe".into(), "start".into(), ids.join(","), "cron".into()], "/dev/null");
        }
    }
    set_global_ctx(None);
    0
}

/// Load every cache var (`eval_cache_var`).
pub fn eval_cache_var() -> Args {
    acl::parse_assignments(&util::read(&format!("{}/var", TMP_PATH)))
}

/// Subcommands of our own binary that `stop` kills (upstream: every `passwall2/` script
/// except app.sh, subscribe.lua, rule_update.lua, tasks.sh, server_app.lua).
const KILL_SELF_SUBCMDS: [&str; 10] = ["monitor", "lease2hosts", "socks-auto-switch", "haproxy-check", "haproxy", "dns-helper", "test", "nft", "ipt", "firewall"];

fn excluded_on_stop(cmd: &str) -> bool {
    ["app.sh", "subscribe.lua", "rule_update.lua", "tasks.sh", "server_app.lua", "ujail"].iter().any(|p| cmd.contains(p))
}

/// `sleep.*(6s|9s|58s)`
fn is_our_sleep(cmd: &str) -> bool {
    match cmd.find("sleep") {
        Some(i) => {
            let rest = &cmd[i + 5..];
            rest.contains("6s") || rest.contains("9s") || rest.contains("58s")
        }
        None => false,
    }
}

/// `app.sh stop ACTION` (no locking; upstream always exits 0).
pub fn app_stop(action: &str) -> i32 {
    util::clean_log();
    let cache = eval_cache_var();
    let use_tables = cache.s("USE_TABLES");
    if !use_tables.is_empty() {
        crate::firewall::cli(fw_cmd(&use_tables), &["stop".to_string()]);
    }
    delete_ip2route();
    let mut pid_files = vec![];
    find_files(TMP_PATH, &|n| n.ends_with("_plugin.pid"), &mut pid_files);
    for f in pid_files {
        if let Some(pid) = util::read(&f).lines().next().and_then(|l| l.trim().parse::<u32>().ok()) {
            util::kill_pids(&[pid], 9);
        }
    }
    let procs = list_procs();
    let mon: Vec<u32> = procs.iter().filter(|p| p.cmdline.contains("passwall2/monitor.sh") || p.is_self_cmd("monitor")).map(|p| p.pid).collect();
    kill_pids_excluding(&mon);
    let sl: Vec<u32> = procs.iter().filter(|p| is_our_sleep(&p.cmdline)).map(|p| p.pid).collect();
    kill_pids_excluding(&sl);
    let rest: Vec<u32> = list_procs()
        .into_iter()
        .filter(|p| (p.cmdline.contains("passwall2/") && !excluded_on_stop(&p.cmdline)) || KILL_SELF_SUBCMDS.iter().any(|s| p.is_self_cmd(s)))
        .map(|p| p.pid)
        .collect();
    kill_pids_excluding(&rest);
    std::env::remove_var("V2RAY_LOCATION_ASSET");
    std::env::remove_var("XRAY_LOCATION_ASSET");
    std::env::remove_var("SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN");
    stop_crontab(action);
    let conf = cache.s("DEFAULT_DNSMASQ_CONF");
    let conf_path = cache.s("DEFAULT_DNSMASQ_CONF_PATH");
    if !conf.is_empty() {
        util::rm_rf(&conf);
    }
    if !conf_path.is_empty() {
        util::rm_rf(&conf_path);
    }
    // restore logic
    let cfg = Config::load(util::CONFIG);
    let bak = cfg.s("@global[0]", "dnsmasq_dns_redirect");
    if !bak.is_empty() {
        let mut b = Batch::new();
        b.set("dhcp.@dnsmasq[0].dns_redirect", &bak);
        let _ = b.commit();
        let mut b = Batch::new();
        b.delete("passwall2.@global[0].dnsmasq_dns_redirect");
        let _ = b.commit();
    }
    // upstream quirk kept: upstream tests `$ACL_default_dns_port`, a variable that never
    // exists (the cache key is ACL_acl_default_dns_port), so this branch always runs.
    {
        let mut b = Batch::new();
        if !conf_path.is_empty() {
            b.del_list("dhcp.@dnsmasq[0].addnmount", &conf_path);
        }
        if b.is_empty() {
            crate::uci::commit("dhcp");
        } else {
            let _ = b.commit();
        }
        dns_helper(&["restart", &json!({"LOG": "0"}).to_string()]);
    }
    if let Some(v) = nz(&cache, "bak_bridge_nf_ipt") {
        sysctl_set("net.bridge.bridge-nf-call-iptables", v);
    }
    if let Some(v) = nz(&cache, "bak_bridge_nf_ip6t") {
        sysctl_set("net.bridge.bridge-nf-call-ip6tables", v);
    }
    util::rm_rf(TMP_PATH);
    if let Ok(rd) = std::fs::read_dir(LOCK_PATH) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("passwall2_monitor") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    logi(0, "Clearing and closing related programs and cache complete.", &[]);
    0
}

// ====================================================================== init.d logic

const MAIN_LOCK: &str = "/var/lock/passwall2.lock";
const READY_LOCK: &str = "/var/lock/passwall2_ready.lock";
const SUB_RULE_LOCK: &str = "/var/lock/passwall2_sub_rule.lock";

/// true when one of our ancestors (not us) has `path` open — the rc.common wrapper keeps
/// the lock file open on fd 9 while it runs `passwall2 start|stop` with `9>&-`.
fn ancestor_has_open(path: &str) -> bool {
    let me = std::process::id();
    for pid in ancestors().into_iter().filter(|p| *p != me) {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else { continue };
        for e in rd.flatten() {
            if std::fs::read_link(e.path()).map(|t| t.to_string_lossy() == path).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Lock guard (None = lock owned by an ancestor, i.e. the rc.common wrapper).
pub struct InitLock(#[allow(dead_code)] Option<std::fs::File>);

fn take_lock(blocking: bool) -> Option<InitLock> {
    if let Some(f) = util::try_lock(MAIN_LOCK) {
        return Some(InitLock(Some(f)));
    }
    if ancestor_has_open(MAIN_LOCK) {
        // called by the init script, which already holds the lock
        return Some(InitLock(None));
    }
    if blocking {
        return util::lock(MAIN_LOCK).map(|f| InitLock(Some(f)));
    }
    None
}

/// Whether the subscription/rule update lock is free: 0 free, 1 busy, 2 cannot open
/// (upstream: nixio `tlock` test; we test both flock and POSIX locks).
pub fn test_update_lock() -> i32 {
    use std::os::unix::io::AsRawFd;
    util::mkdir(LOCK_PATH);
    let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(SUB_RULE_LOCK) else { return 2 };
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
        fn lockf(fd: i32, cmd: i32, len: i64) -> i32;
    }
    let fd = f.as_raw_fd();
    // F_TEST = 3
    if unsafe { lockf(fd, 3, 0) } != 0 {
        return 1;
    }
    if unsafe { flock(fd, 2 | 4) } != 0 {
        return 1;
    }
    unsafe {
        flock(fd, 8);
    }
    0
}

/// `/etc/init.d/passwall2 start [ACTION]`
pub fn init_start(action: &str) -> i32 {
    let Some(_l) = take_lock(false) else {
        logi(0, "The script is already running, do not run it again. Exit.", &[]);
        return 0;
    };
    app_start(action)
}

/// `/etc/init.d/passwall2 stop [ACTION]`
pub fn init_stop(action: &str) -> i32 {
    let Some(_l) = take_lock(true) else {
        logi(0, "Unable to acquire the stop lock. Exiting.", &[]);
        return 1;
    };
    app_stop(action)
}

/// `/etc/init.d/passwall2 restart [ACTION]` (waits up to 600 s for subscription/rule updates).
pub fn init_restart(action: &str) -> i32 {
    let Some(_l) = take_lock(false) else {
        logi(0, "The script is already running, do not run it again. Exit.", &[]);
        return if action == "boot" { 1 } else { 0 };
    };
    let mut st = 1;
    for _ in 0..300 {
        st = test_update_lock();
        if st != 1 {
            break;
        }
        sleep_s(2);
    }
    if st != 0 {
        logi(0, "Failed or timed out waiting for subscription/rule updates. Restart cancelled.", &[]);
        return 1;
    }
    app_stop(action);
    app_start(action)
}

/// `boot_func`: wait `start_delay` seconds, `restart boot`, then mark the boot ready.
pub fn boot_func() -> i32 {
    let _ = std::fs::remove_file(READY_LOCK);
    let cfg = Config::load(util::CONFIG);
    let delay = cfg.get("@global_delay[0]", "start_delay").unwrap_or_else(|| "1".into());
    if let Ok(d) = delay.trim().parse::<i64>() {
        if d > 0 {
            logi(0, "Start after a delay of %s seconds!", &[&delay]);
            sleep_s(d as u64);
        }
    }
    if init_restart("boot") != 0 {
        return 1;
    }
    util::write(READY_LOCK, "");
    0
}

/// `boot()`: run boot_func in the background.
pub fn init_boot() -> i32 {
    let _ = util::spawn_bg(&self_bin(), &["app".into(), "boot_func".into()], "/dev/null");
    0
}

// ====================================================================== CLI

/// `eval_set_val` over all words (each argument may hold several `k=v` pairs).
pub fn parse_words(words: &[String]) -> Args {
    acl::parse_assignments(&words.join(" "))
}

/// `app.sh run_socks ...` from another component (fresh context: direct DNS only,
/// immediate start, `NO_REC_PROCESS` from the environment).
pub fn run_socks_cmd(words: &[String]) -> i32 {
    let cfg = Config::load(util::CONFIG);
    let ctx = Ctx::cli(&cfg);
    run_socks(&ctx, &cfg, &parse_words(words))
}

/// `app.sh socks_node_switch flag=.. new_node=..`
pub fn socks_node_switch_cmd(words: &[String]) -> i32 {
    let cfg = Config::load(util::CONFIG);
    let ctx = Ctx::cli(&cfg);
    socks_node_switch(&ctx, &cfg, &parse_words(words))
}

fn action_arg(args: &[String], verb: &str) -> String {
    match args.first().map(|s| s.as_str()) {
        Some(a) if a != verb => a.to_string(),
        _ => String::new(),
    }
}

fn app_cli(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    match sub {
        "run_socks" => run_socks_cmd(rest),
        "socks_node_switch" => socks_node_switch_cmd(rest),
        "start" => app_start(&action_arg(rest, "start")),
        "stop" => app_stop(&action_arg(rest, "stop")),
        "boot_func" => boot_func(),
        "acl_node" => {
            acl_node();
            0
        }
        "run_xray" | "run_singbox" => {
            let cfg = Config::load(util::CONFIG);
            let ctx = current_ctx();
            let a = parse_words(rest);
            let r = if sub == "run_xray" { run_xray(&ctx, &cfg, &a) } else { run_singbox(&ctx, &cfg, &a) };
            match r {
                Ok(()) => 0,
                Err((c, f)) => {
                    if !f.is_empty() {
                        eprint!("{}", util::read(&f));
                    }
                    if c == 0 {
                        1
                    } else {
                        c
                    }
                }
            }
        }
        "run_process_queue" => {
            run_process_queue();
            0
        }
        "get_new_port" => {
            println!("{}", util::get_new_port(rest.first().map(|s| s.as_str()).unwrap_or("auto"), rest.get(1).map(|s| s.as_str()).unwrap_or("")));
            0
        }
        "get_geoip" => {
            let cfg = Config::load(util::CONFIG);
            print!("{}", get_geoip(&cfg, rest.first().map(|s| s.as_str()).unwrap_or(""), rest.get(1).map(|s| s.as_str()).unwrap_or("")));
            0
        }
        "add_ip2route" => {
            if add_ip2route(rest.first().map(|s| s.as_str()).unwrap_or(""), rest.get(1).map(|s| s.as_str()).unwrap_or("")) {
                0
            } else {
                1
            }
        }
        "delete_ip2route" => {
            delete_ip2route();
            0
        }
        "clean_crontab" => {
            clean_crontab();
            0
        }
        "check_run_environment" => {
            let cfg = Config::load(util::CONFIG);
            let (t, nf) = check_run_environment(&cfg, true);
            println!("USE_TABLES={}\nnftflag={}", t, if nf { 1 } else { 0 });
            0
        }
        "get_direct_dns" => {
            let cfg = Config::load(util::CONFIG);
            let d = get_direct_dns(&cfg);
            println!("ISP_DNS=\"{}\"", d.isp_dns.join(" "));
            println!("ISP_DNS6=\"{}\"", d.isp_dns6.join(" "));
            println!("DEFAULT_DNS=\"{}\"", d.default_dns);
            println!("AUTO_DNS=\"{}\"", d.auto_dns);
            println!("RETURN_DNS=\"{}\"", d.return_dns);
            println!("DIRECT_DNS_PROTO=\"{}\"", d.proto);
            println!("DIRECT_DNS_SERVER=\"{}\"", d.server);
            println!("DIRECT_DNS_PORT=\"{}\"", d.port);
            println!("DIRECT_DNS_DNSMASQ_SERVER=\"{}\"", d.dnsmasq_server);
            0
        }
        _ => {
            eprintln!("usage: passwall2 app <run_socks|socks_node_switch|start|stop|boot_func|acl_node|run_xray|run_singbox|run_process_queue|get_new_port|get_geoip|add_ip2route|delete_ip2route|clean_crontab|check_run_environment|get_direct_dns> [k=v...]");
            1
        }
    }
}

pub fn cli(cmd: &str, args: &[String]) -> i32 {
    match cmd {
        "start" => init_start(&action_arg(args, "start")),
        "stop" => init_stop(&action_arg(args, "stop")),
        "restart" => init_restart(&action_arg(args, "restart")),
        "boot" => init_boot(),
        "app" => app_cli(args),
        "monitor" => daemons::monitor(),
        "tasks" => daemons::tasks(),
        "lease2hosts" => daemons::lease2hosts(),
        "test" => test::cli(args),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_plus_http() {
        assert_eq!(plus_http("/tmp/etc/passwall2/abc.json"), "/tmp/etc/passwall2/abc+http.json");
        assert_eq!(plus_http("/tmp/etc/passwall2/abc"), "/tmp/etc/passwall2/abc+http");
    }

    #[test]
    fn t_resolv() {
        let t = "# Interface wan\nnameserver 192.168.1.1\nnameserver 0.0.0.0\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver fe80::1%eth0\nnameserver ::1\nnameserver 2001:db8::53\nsearch lan\n";
        let (v4, v6) = parse_resolv(t);
        assert_eq!(v4, vec!["192.168.1.1", "8.8.8.8"]);
        assert_eq!(v6, vec!["fe80::1", "2001:db8::53"]);
    }

    #[test]
    fn t_ipv6_like() {
        assert!(has_ipv6_like("nameserver 2001:db8::1"));
        assert!(has_ipv6_like("fe80::1"));
        assert!(!has_ipv6_like("nameserver 1.2.3.4"));
        assert!(!has_ipv6_like("abc"));
        assert!(!has_ipv6_like("::1"));
    }

    #[test]
    fn t_direct_dns() {
        let d = compute_direct_dns("nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n", &[], "auto", "");
        assert_eq!(d.auto_dns, "10.0.0.1,10.0.0.2");
        assert_eq!((d.proto.as_str(), d.server.as_str(), d.port.as_str()), ("udp", "10.0.0.1", "53"));
        assert_eq!(d.return_dns, "10.0.0.1,10.0.0.2");
        let d = compute_direct_dns("", &["/lan/127.0.0.1".into(), "223.5.5.5".into(), "1.1.1.1#5353".into(), "9.9.9.9".into()], "udp", "8.8.8.8:5353");
        assert_eq!(d.default_dns, "223.5.5.5#53,1.1.1.1#5353");
        assert_eq!((d.server.as_str(), d.port.as_str()), ("8.8.8.8", "5353"));
        assert_eq!(d.dnsmasq_server, "8.8.8.8#5353");
        assert_eq!(d.return_dns, "223.5.5.5#53,1.1.1.1#5353,8.8.8.8#5353#udp");
        let d = compute_direct_dns("", &[], "tcp", "1.0.0.1");
        assert_eq!(d.auto_dns, "119.29.29.29");
        assert_eq!((d.proto.as_str(), d.server.as_str(), d.port.as_str()), ("tcp", "1.0.0.1", "53"));
        assert_eq!(d.dnsmasq_server, "");
    }

    #[test]
    fn t_words() {
        let a = parse_words(&["flag=1081 node=abc bind=127.0.0.1 relay_port=".into(), "config_file=\"x.json\"".into()]);
        assert_eq!(a.s("flag"), "1081");
        assert_eq!(a.s("node"), "abc");
        assert_eq!(a.s("config_file"), "x.json");
        assert_eq!(a.g("relay_port"), Some(""));
    }

    #[test]
    fn t_cron() {
        assert_eq!(cron_time("7", "04:30"), "30 04 * * *");
        assert_eq!(cron_time("1", "4:05"), "05 4 * * 1");
        let c = Config::parse(
            "passwall2",
            "config global_delay\n\toption stop_week_mode '7'\n\toption stop_time_mode '1:00'\n\toption restart_week_mode '8'\nconfig global_rules\n\toption update_week_mode '2'\n\toption update_time_mode '3:15'\nconfig subscribe_list 's1'\n\toption remark 'A'\n\toption update_week_mode '7'\n\toption update_time_mode '5:00'\nconfig subscribe_list 's2'\n\toption remark 'B'\n\toption update_week_mode '7'\n\toption update_time_mode '5:00'\n",
        );
        let (lines, loop_, logs) = crontab_entries(&c, true);
        assert!(loop_);
        assert_eq!(lines[0], "00 1 * * * setsid /etc/init.d/passwall2 stop cron > /dev/null 2>&1 &");
        assert_eq!(lines[1], "15 3 * * 2 setsid /usr/bin/passwall2 rule-update log all cron > /dev/null 2>&1 &");
        assert_eq!(lines[2], "00 5 * * * setsid /usr/bin/passwall2 subscribe start s1,s2 cron > /dev/null 2>&1 &");
        assert_eq!(lines.len(), 3);
        assert_eq!(logs.len(), 5);
    }

    #[test]
    fn t_chinadns() {
        let s = chinadns_ng_conf("2005", "udp", "223.5.5.5#53", "", "4#inet#passwall2#psw2_n_white,6#inet#passwall2#psw2_n_white6");
        assert!(s.contains("add-tagchn-ip inet@passwall2@psw2_n_white,inet@passwall2@psw2_n_white6\n"));
        assert!(s.contains("china-dns udp://223.5.5.5#53\n"));
        assert!(s.contains("group-ipset inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6\n"));
        let s = chinadns_ng_conf("2005", "tcp", "1.1.1.1#53", "psw2_n_white,psw2_n_white6", "");
        assert!(s.contains("add-tagchn-ip psw2_n_white,psw2_n_white6\n"));
        assert!(s.contains("group-ipset psw2_vps,psw2_vps6\n"));
        let d = ipset_dnsmasq_conf("2006", "1.1.1.1#53,8.8.8.8", "a,b", "", "", "");
        assert_eq!(d, "port=2006\nno-poll\nno-resolv\nstrict-order\ncache-size=0\ndns-forward-max=1000\nserver=1.1.1.1#53\nserver=8.8.8.8\nipset=a,b\n");
    }

    #[test]
    fn t_vpslist() {
        let c = Config::parse(
            "passwall2",
            "config nodes 'a'\n\toption address 'Example.com'\n\toption download_address 'dl.example.org'\nconfig nodes 'b'\n\toption address '1.2.3.4'\nconfig nodes 'c'\n\toption address 'engage.cloudflareclient.com'\nconfig nodes 'd'\n\toption address 'example.com'\n\toption remarks 'x.com'\n",
        );
        assert_eq!(vpslist(&c), "Example.com\ndl.example.org\nexample.com\n");
    }

    #[test]
    fn t_misc() {
        assert!(has_1_65535("1:65535"));
        assert!(has_1_65535("80,1-65535"));
        assert!(!has_1_65535("1:6553"));
        assert!(has_word("Compile time options: IPv6 no-ipset nftset", "nftset"));
        assert!(dnsmasq_has_opt("Compile time options: IPv6 no-ipset nftset", "nftset"));
        assert!(!dnsmasq_has_opt("Compile time options: IPv6 no-ipset no-nftset auth", "nftset"));
        assert!(!dnsmasq_has_opt("Compile time options: IPv6 no-ipset nftset", "ipset"));
        assert!(has_word("no-ipset", "ipset"));
        assert!(!has_word("ipsets", "ipset"));
        assert_eq!(cmd_check("/tmp/etc/passwall2/bin/xray  run -c /a.json >/dev/null"), "/tmp/etc/passwall2/bin/xray run -c /a.json");
        assert_eq!(get_ip_port_from("1.2.3.4:53", None), ("1.2.3.4".into(), "53".into()));
        assert_eq!(get_ip_port_from("8.8.8.8#5353", None), ("8.8.8.8".into(), "5353".into()));
        assert_eq!(get_ip_port_from("example.com", None), ("example.com".into(), "".into()));
        assert!(is_our_sleep("sleep 58s"));
        assert!(!is_our_sleep("sleep 60"));
        let (u, h, p, b) = doh_parts("https://1.1.1.1/dns-query");
        assert_eq!((u.as_str(), h.as_str(), p.as_str(), b.as_str()), ("https://1.1.1.1/dns-query", "1.1.1.1", "443", "1.1.1.1"));
        let (_, h, p, b) = doh_parts("https://dns.google:8443/dns-query,8.8.8.8");
        assert_eq!((h.as_str(), p.as_str(), b.as_str()), ("dns.google", "8443", "8.8.8.8"));
    }

    #[test]
    fn t_write_json() {
        let dir = std::env::temp_dir().join(format!("pw2app{}", std::process::id()));
        let p = dir.join("a.json");
        assert!(write_json(&p.to_string_lossy(), Some(&json!({"a": {"b": 1}}))));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\n\t\"a\": {\n\t\t\"b\": 1\n\t}\n}\n");
        let _ = std::fs::remove_dir_all(dir);
    }
}
