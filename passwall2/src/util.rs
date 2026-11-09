//! Shared runtime helpers (port of upstream `utils.sh` and the generic parts of `api.lua`).
//! Every module uses these instead of re-implementing paths, logging, exec or caches.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub const CONFIG: &str = "passwall2";
pub const CONFIG_SERVER: &str = "passwall2_server";
pub const DIRECT_GID: u32 = 9912;
pub const APP_PATH: &str = "/usr/share/passwall2";
pub const TMP_PATH: &str = "/tmp/etc/passwall2";
pub const TMP_PATH2: &str = "/tmp/etc/passwall2_tmp";
pub const LOCK_PATH: &str = "/var/lock";
pub const LOG_FILE: &str = "/tmp/log/passwall2.log";
pub const SERVER_LOG_FILE: &str = "/tmp/log/passwall2_server.log";
pub const TMP_ACL_PATH: &str = "/tmp/etc/passwall2/acl";
pub const TMP_BIN_PATH: &str = "/tmp/etc/passwall2/bin";
pub const TMP_IFACE_PATH: &str = "/tmp/etc/passwall2/iface";
pub const TMP_ROUTE_PATH: &str = "/tmp/etc/passwall2/route";
pub const TMP_SCRIPT_FUNC_PATH: &str = "/tmp/etc/passwall2/script_func";
pub const TMP_PROCESS_LIST_PATH: &str = "/tmp/etc/passwall2/process_list";
/// Our own binary (multicall). Used when re-invoking ourselves from cron, monitor, haproxy external-check...
pub const SELF_BIN: &str = "/usr/bin/passwall2";

/// String→string argument map: the exact equivalent of the jshn JSON objects that
/// upstream app.sh passes to the Lua generators (all values are strings).
pub type Args = BTreeMap<String, String>;

pub trait ArgsExt {
    fn g(&self, k: &str) -> Option<&str>;
    /// non-empty value
    fn ne(&self, k: &str) -> Option<&str>;
    fn s(&self, k: &str) -> String;
    fn is1(&self, k: &str) -> bool;
}
impl ArgsExt for Args {
    fn g(&self, k: &str) -> Option<&str> {
        self.get(k).map(|s| s.as_str())
    }
    fn ne(&self, k: &str) -> Option<&str> {
        self.get(k).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
    fn s(&self, k: &str) -> String {
        self.get(k).cloned().unwrap_or_default()
    }
    fn is1(&self, k: &str) -> bool {
        self.g(k) == Some("1")
    }
}

/// Parse `k=v` words (upstream `eval_set_val`) into Args.
pub fn parse_kv_args(words: &[String]) -> Args {
    let mut a = Args::new();
    for w in words {
        if let Some((k, v)) = w.split_once('=') {
            a.insert(k.to_string(), v.to_string());
        }
    }
    a
}

/// Parse a JSON object whose values are strings/numbers/bools/null into Args
/// (upstream generator CLI: `gen_config '<json>'`). null values are dropped.
pub fn args_from_json(s: &str) -> Args {
    let mut a = Args::new();
    if let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(s) {
        for (k, v) in m {
            match v {
                serde_json::Value::String(x) => {
                    a.insert(k, x);
                }
                serde_json::Value::Null => {}
                other => {
                    a.insert(k, other.to_string());
                }
            }
        }
    }
    a
}

// ---------------------------------------------------------------- logging

pub fn now_str() -> String {
    // date '+%Y-%m-%d %H:%M:%S' (local time) — use busybox date to honor TZ
    cmd_out("date", &["+%Y-%m-%d %H:%M:%S"]).trim().to_string()
}

pub fn append_file(path: &str, line: &str) {
    if let Some(p) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(p);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", line);
    }
}

/// `echolog`
pub fn echolog(msg: &str) {
    append_file(LOG_FILE, msg);
}
/// `echolog_date`
pub fn echolog_date(msg: &str) {
    append_file(LOG_FILE, &format!("{}: {}", now_str(), msg));
}
/// `log N MSG`
pub fn log(level: usize, msg: &str) {
    if level == 0 {
        append_file(LOG_FILE, &format!("{}: {}", now_str(), msg));
    } else {
        append_file(LOG_FILE, &format!("{}: {}- {}", now_str(), "  ".repeat(level), msg));
    }
}
/// Server log variant.
pub fn log_server(level: usize, msg: &str) {
    let ind = if level == 0 { String::new() } else { format!("{}- ", "  ".repeat(level)) };
    append_file(SERVER_LOG_FILE, &format!("{}: {}{}", now_str(), ind, msg));
}
/// `clean_log`: truncate when > 1000 lines.
pub fn clean_log() {
    if let Ok(t) = std::fs::read_to_string(LOG_FILE) {
        if t.lines().count() > 1000 {
            let _ = std::fs::write(LOG_FILE, "");
            log(0, &i18n("Log file is too long, clear it!", &[]));
        }
    }
}

/// i18n: backend log messages are English (upstream source strings); `%s` placeholders
/// are substituted in order. (Translations of log lines are done in the UI layer.)
pub fn i18n(fmt: &str, args: &[&str]) -> String {
    let mut out = String::new();
    let mut it = args.iter();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.peek() {
                Some('s') | Some('d') => {
                    chars.next();
                    out.push_str(it.next().copied().unwrap_or(""));
                    continue;
                }
                Some('%') => {
                    chars.next();
                    out.push('%');
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------- exec

/// Run a command, return stdout (empty on failure). stderr discarded.
pub fn cmd_out(prog: &str, args: &[&str]) -> String {
    Command::new(prog)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}
/// Run a command; true if exit status 0. Output discarded.
pub fn cmd_ok(prog: &str, args: &[&str]) -> bool {
    Command::new(prog).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}
/// `sh -c` returning stdout (for pipelines that are much simpler in shell).
pub fn sh(script: &str) -> String {
    cmd_out("/bin/sh", &["-c", script])
}
pub fn sh_ok(script: &str) -> bool {
    cmd_ok("/bin/sh", &["-c", script])
}
/// Run with data on stdin; returns (success, stdout+stderr).
pub fn cmd_stdin(prog: &str, args: &[&str], input: &str) -> (bool, String) {
    let child = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let Ok(mut child) = child else { return (false, String::new()) };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(input.as_bytes());
    }
    match child.wait_with_output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s)
        }
        Err(_) => (false, String::new()),
    }
}
/// Shell-quote a single argument.
pub fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn is_executable(p: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// `first_type PATH_OR_NAME [ALT]`
pub fn first_type(a: &str, alt: &str) -> Option<String> {
    if a.starts_with('/') && is_executable(a) {
        return Some(a.to_string());
    }
    for name in [a, alt] {
        if name.is_empty() {
            continue;
        }
        let base = name.rsplit('/').next().unwrap_or(name);
        for dir in ["/bin", "/usr/bin", TMP_BIN_PATH, "/usr/sbin", "/sbin"] {
            let p = format!("{}/{}", dir, base);
            if is_executable(&p) {
                return Some(p);
            }
        }
        if let Ok(path) = std::env::var("PATH") {
            for dir in path.split(':') {
                let p = format!("{}/{}", dir, base);
                if is_executable(&p) {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Resolve a core binary path from `@global_app[0].<opt>` with fallback name.
pub fn app_bin(cfg: &crate::uci::Config, opt: &str, name: &str) -> Option<String> {
    first_type(&cfg.t_get("global_app", opt, ""), name)
}

/// Read a whole file, "" if missing.
pub fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}
pub fn write(p: &str, data: &str) -> bool {
    if let Some(d) = Path::new(p).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    std::fs::write(p, data).is_ok()
}
pub fn mkdir(p: &str) {
    let _ = std::fs::create_dir_all(p);
}
pub fn exists(p: &str) -> bool {
    Path::new(p).exists()
}
pub fn rm_rf(p: &str) {
    let path = Path::new(p);
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

// ---------------------------------------------------------------- cache var store ($TMP_PATH/var)

fn var_file() -> String {
    format!("{}/var", TMP_PATH)
}
/// Lock serializing every read-modify-write of the var file across processes. It lives in
/// LOCK_PATH (not next to the var file) so an `rm -rf $TMP_PATH` cannot unlink a held lock.
fn var_lock_file() -> String {
    format!("{}/passwall2_var.lock", LOCK_PATH)
}

/// Value of `KEY="VALUE"` in var-file text (last definition wins).
fn var_lookup(text: &str, key: &str) -> Option<String> {
    let pfx = format!("{}=", key);
    let line = text.lines().rev().find(|l| l.starts_with(&pfx))?;
    let rest = &line[pfx.len()..];
    let v = rest.strip_prefix('"').unwrap_or(rest);
    let v = v.split('"').next().unwrap_or("");
    Some(v.to_string())
}
/// Var-file text with every `KEY=` line removed and, for a non-empty value, `KEY="VALUE"`
/// appended (anchored match — upstream's unanchored `sed /KEY/d` was a bug).
fn var_apply(text: &str, key: &str, value: &str) -> String {
    let pfx = format!("{}=", key);
    let mut s = String::with_capacity(text.len() + key.len() + value.len() + 4);
    for l in text.lines().filter(|l| !l.starts_with(&pfx)) {
        s.push_str(l);
        s.push('\n');
    }
    if !value.is_empty() {
        s.push_str(&format!("{}=\"{}\"\n", key, value));
    }
    s
}
/// Replace `path` atomically (temp file + rename) so readers never see a truncated file.
fn write_atomic(path: &str, data: &str) -> bool {
    if let Some(d) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = format!("{}.tmp.{}", path, std::process::id());
    if std::fs::write(&tmp, data).is_ok() && std::fs::rename(&tmp, path).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&tmp);
    false
}
fn flock_file(path: &str) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    if let Some(d) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path).ok()?;
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
    }
    loop {
        if unsafe { flock(f.as_raw_fd(), 2) } == 0 {
            return Some(f);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(4) {
            return None; // not EINTR
        }
    }
}
/// Run a read-modify-write of the var file `file` under `lock`: `f` gets the current text
/// and returns the new text (None = leave unchanged) plus a result.
fn var_update_at<R>(file: &str, lock: &str, f: impl FnOnce(&str) -> (Option<String>, R)) -> R {
    // If the lock cannot be taken (e.g. read-only /tmp/lock) still proceed: no worse than before.
    let _guard = flock_file(lock);
    let text = read(file);
    let (new, r) = f(&text);
    if let Some(new) = new {
        if new != text {
            write_atomic(file, &new);
        }
    }
    r
}
fn var_set_at(file: &str, lock: &str, key: &str, value: &str) {
    var_update_at(file, lock, |t| (Some(var_apply(t, key, value)), ()))
}

/// `get_cache_var KEY` (lock-free: writers replace the file atomically)
pub fn get_cache_var(key: &str) -> Option<String> {
    var_lookup(&read(&var_file()), key)
}
/// `del_cache_var KEY`
pub fn del_cache_var(key: &str) {
    var_set_at(&var_file(), &var_lock_file(), key, "");
}
/// `set_cache_var KEY VALUE` (empty value just deletes)
pub fn set_cache_var(key: &str, value: &str) {
    var_set_at(&var_file(), &var_lock_file(), key, value);
}

// ---------------------------------------------------------------- ports

/// Number of listening (tcp LISTEN / bound udp) sockets per local port.
fn listening_ports(proto: &str) -> std::collections::HashMap<u16, usize> {
    let proto = if proto.is_empty() { "tcp,udp" } else { proto };
    let mut files = vec![];
    if proto.contains("tcp") {
        files.extend(["/proc/net/tcp", "/proc/net/tcp6"]);
    }
    if proto.contains("udp") {
        files.extend(["/proc/net/udp", "/proc/net/udp6"]);
    }
    let mut m = std::collections::HashMap::new();
    for f in files {
        let is_tcp = f.contains("tcp");
        for l in read(f).lines().skip(1) {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            // tcp: state 0A == LISTEN ; udp: state 07 (unconnected) counts as bound
            if is_tcp && cols[3] != "0A" {
                continue;
            }
            let Some((_, hex)) = cols[1].rsplit_once(':') else { continue };
            if let Ok(p) = u16::from_str_radix(hex, 16) {
                *m.entry(p).or_insert(0) += 1;
            }
        }
    }
    m
}

/// `check_port_exists PORT [proto]` → number of listening sockets on port.
pub fn check_port_exists(port: u16, proto: &str) -> usize {
    listening_ports(proto).get(&port).copied().unwrap_or(0)
}

const PORT_MIN: u32 = 1025;
const PORT_MAX: u32 = 49151;

/// Pick the first port from `start` (wrapping PORT_MAX → PORT_MIN) that is neither busy nor
/// reserved. Visits every port of the range at most once; None when all are taken.
// upstream quirk: utils.sh stepped back down (`p-1`) at 49151 and then bounced between 49150
// and 49151 forever once the top of the range was used up; we wrap to the bottom instead.
fn pick_port(start: u32, busy: &dyn Fn(u32) -> bool) -> Option<u32> {
    let mut p = if (PORT_MIN..=PORT_MAX).contains(&start) { start } else { 2001 };
    for _ in PORT_MIN..=PORT_MAX {
        if !busy(p) {
            return Some(p);
        }
        p = if p < PORT_MAX { p + 1 } else { PORT_MIN };
    }
    None
}

/// `get_new_port PORT|auto [PROTO]`
pub fn get_new_port(port: &str, proto: &str) -> u16 {
    get_new_port_at(&var_file(), &var_lock_file(), port, &listening_ports(&proto.to_lowercase()))
}
fn get_new_port_at(file: &str, lock: &str, port: &str, listening: &std::collections::HashMap<u16, usize>) -> u16 {
    // The check and the reservation happen under the var lock, so two processes allocating
    // at the same time cannot both get the same port.
    var_update_at(file, lock, |text| {
        let auto = port == "auto";
        let start: u32 = if auto {
            var_lookup(text, "last_get_new_port_auto").and_then(|v| v.parse::<u32>().ok()).map(|v| v + 1).unwrap_or(2001)
        } else {
            port.parse().unwrap_or(2001)
        };
        let reserved: std::collections::HashSet<u32> = text
            .lines()
            .filter_map(|l| {
                let (k, v) = l.strip_prefix("get_port_")?.split_once('=')?;
                (!v.trim_matches('"').is_empty()).then(|| k.parse().ok()).flatten()
            })
            .collect();
        let busy = |p: u32| listening.get(&(p as u16)).copied().unwrap_or(0) != 0 || reserved.contains(&p);
        match pick_port(start, &busy) {
            Some(p) => {
                let mut t = var_apply(text, &format!("get_port_{}", p), "1");
                if auto {
                    t = var_apply(&t, "last_get_new_port_auto", &p.to_string());
                }
                (Some(t), p as u16)
            }
            None => {
                log(0, "get_new_port: no free port left in 1025-49151");
                let p = if (PORT_MIN..=PORT_MAX).contains(&start) { start } else { 2001 };
                (None, p as u16)
            }
        }
    })
}

/// Reap every exited child without blocking (`waitpid(-1, WNOHANG)` loop). Long-running
/// single-threaded daemons call this each iteration so the processes they spawn and drop
/// (`spawn_bg` / `spawn_shell`) do not linger as zombies. Must not run concurrently with a
/// `Command::output()/status()` in another thread of the same process (it could reap that
/// child first). Returns the number reaped.
pub fn reap_children() -> usize {
    extern "C" {
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    }
    const WNOHANG: i32 = 1;
    let mut n = 0;
    let mut st: i32 = 0;
    while unsafe { waitpid(-1, &mut st, WNOHANG) } > 0 {
        n += 1;
    }
    n
}

// ---------------------------------------------------------------- host / ip helpers

pub fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}
pub fn is_ipv6(s: &str) -> bool {
    s.trim_start_matches('[').trim_end_matches(']').parse::<std::net::Ipv6Addr>().is_ok()
}
pub fn is_ip(s: &str) -> bool {
    is_ipv4(s) || is_ipv6(s)
}
/// CIDR or plain ip
pub fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, m)) => {
            let Ok(m) = m.parse::<u8>() else { return false };
            (is_ipv4(ip) && m <= 32) || (is_ipv6(ip) && m <= 128)
        }
        None => is_ip(s),
    }
}
/// `check_host`: false if contains '/' or non printable-ASCII / space.
pub fn check_host(h: &str) -> bool {
    !h.is_empty() && !h.contains('/') && h.chars().all(|c| ('!'..='~').contains(&c))
}
/// `get_host_ip ipv4|ipv6 HOST [COUNT]`
pub fn get_host_ip(family: &str, host: &str, count: u32) -> Option<String> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if family == "ipv6" && is_ipv6(h) {
        return Some(h.to_string());
    }
    if family != "ipv6" && is_ipv4(h) {
        return Some(h.to_string());
    }
    let fam = if family == "ipv6" { "-6" } else { "-4" };
    let out = cmd_out("resolveip", &[fam, "-t", &count.to_string(), h]);
    out.lines().next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
/// `host_from_url`
pub fn host_from_url(url: &str) -> String {
    let mut u = url;
    for p in ["http://", "https://", "ftp://", "sftp://"] {
        if let Some(r) = u.strip_prefix(p) {
            u = r;
            break;
        }
    }
    let u = u.split('/').next().unwrap_or("");
    let u = match u.rfind('@') {
        Some(i) => &u[i + 1..],
        None => u,
    };
    u.split(':').next().unwrap_or("").to_string()
}
/// `get_ip_port_from`: split "host:port" / "host#port" / "[v6]:port".
pub fn split_host_port(s: &str) -> (String, Option<String>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']') {
            let p = p.trim_start_matches([':', '#']);
            return (h.to_string(), if p.is_empty() { None } else { Some(p.to_string()) });
        }
    }
    if let Some(i) = s.rfind(['#', ':']) {
        let (h, p) = (&s[..i], &s[i + 1..]);
        // bare IPv6 without brackets: only treat as port when '#' or a single ':'
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (s.as_bytes()[i] == b'#' || !h.contains(':')) {
            return (h.to_string(), Some(p.to_string()));
        }
    }
    (s.to_string(), None)
}
/// `api.get_domain_from_url` → host[:port] part of an URL.
pub fn domain_from_url(url: &str) -> String {
    let u = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let u = u.split(['/', '?', '#']).next().unwrap_or("");
    match u.rfind('@') {
        Some(i) => u[i + 1..].to_string(),
        None => u.to_string(),
    }
}

/// `get_wan_ips ip4|ip6`
pub fn get_wan_ips(fam: &str) -> Vec<String> {
    let dump = cmd_out("ubus", &["call", "network.interface", "dump"]);
    let mut out = vec![];
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&dump) else { return out };
    for itf in v["interface"].as_array().cloned().unwrap_or_default() {
        let name = itf["interface"].as_str().unwrap_or("");
        let l3 = itf["l3_device"].as_str().unwrap_or("");
        if name.contains("lan") || l3.contains('.') || itf["route"].as_array().is_none_or(|r| r.is_empty()) {
            continue;
        }
        let key = if fam == "ip6" { "ipv6-address" } else { "ipv4-address" };
        for a in itf[key].as_array().cloned().unwrap_or_default() {
            if let Some(ip) = a["address"].as_str() {
                if ip.is_empty() || ip == "0.0.0.0" || ip.starts_with("fe80") {
                    continue;
                }
                if !out.contains(&ip.to_string()) {
                    out.push(ip.to_string());
                }
            }
        }
    }
    out
}
/// `get_local_ips ip4|ip6`
pub fn get_local_ips(fam: &str) -> Vec<String> {
    let f = if fam == "ip6" { "-6" } else { "-4" };
    let wan = get_wan_ips(fam);
    let mut out: Vec<String> = vec![];
    let text = cmd_out("ip", &["-o", f, "addr", "show", "scope", "global"]);
    let mut all: Vec<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3).map(|a| a.split('/').next().unwrap_or("").to_string()))
        .collect();
    all.push(if fam == "ip6" { "::1".into() } else { "127.0.0.1".into() });
    for ip in all {
        if ip.is_empty() || ip == "0.0.0.0" || ip == "::" || wan.contains(&ip) || out.contains(&ip) {
            continue;
        }
        out.push(ip);
    }
    out
}

// ---------------------------------------------------------------- misc

/// Lua-style truthy test used everywhere in upstream: value present and == "1".
pub fn b(v: &Option<String>) -> bool {
    v.as_deref() == Some("1")
}

/// Lowercase hex md5 of a string via busybox `md5sum` (rarely needed; avoids a crate).
pub fn md5_hex(s: &str) -> String {
    let (_, out) = cmd_stdin("md5sum", &[], s);
    out.split_whitespace().next().unwrap_or("").to_string()
}

/// Exclusive non-blocking file lock (flock). Returns the file handle; lock held while alive.
pub fn try_lock(path: &str) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    mkdir(LOCK_PATH);
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path).ok()?;
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    let r = unsafe { flock(f.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if r == 0 {
        Some(f)
    } else {
        None
    }
}
/// Blocking exclusive lock.
pub fn lock(path: &str) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    mkdir(LOCK_PATH);
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path).ok()?;
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
    }
    let r = unsafe { flock(f.as_raw_fd(), 2) };
    if r == 0 {
        Some(f)
    } else {
        None
    }
}

/// Spawn a detached background process (nohup-like), stdout/stderr to `output` file
/// ("/dev/null" allowed). Returns pid.
pub fn spawn_bg(prog: &str, args: &[String], output: &str) -> Option<u32> {
    let out = std::fs::OpenOptions::new().create(true).append(true).open(output).ok()?;
    let err = out.try_clone().ok()?;
    use std::os::unix::process::CommandExt;
    let child = unsafe {
        Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .pre_exec(|| {
                extern "C" {
                    fn setsid() -> i32;
                }
                setsid();
                Ok(())
            })
            .spawn()
            .ok()?
    };
    Some(child.id())
}

/// Find pids whose /proc/<pid>/cmdline contains `pat` (like `busybox pgrep -f`).
pub fn pgrep_f(pat: &str) -> Vec<u32> {
    let me = std::process::id();
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        let cmd: String = String::from_utf8_lossy(&raw).replace('\0', " ");
        if cmd.contains(pat) {
            out.push(pid);
        }
    }
    out
}
pub fn kill_pids(pids: &[u32], sig: i32) {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    for p in pids {
        unsafe {
            kill(*p as i32, sig);
        }
    }
}

/// Seconds since epoch.
pub fn epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Base64 decode tolerant of url-safe alphabet and missing padding (upstream `api.base64Decode`).
pub fn b64_decode(s: &str) -> Option<String> {
    use base64::Engine;
    let t: String = s.trim().chars().filter(|c| !c.is_whitespace()).map(|c| match c {
        '-' => '+',
        '_' => '/',
        x => x,
    }).collect();
    let t = t.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(t).ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}
pub fn b64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Percent-decode (`+` kept as is) / encode (RFC3986 unreserved kept).
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t_i18n() {
        assert_eq!(i18n("a %s b %s", &["1", "2"]), "a 1 b 2");
    }
    #[test]
    fn t_split() {
        assert_eq!(split_host_port("1.2.3.4:53"), ("1.2.3.4".into(), Some("53".into())));
        assert_eq!(split_host_port("[::1]:53"), ("::1".into(), Some("53".into())));
        assert_eq!(split_host_port("8.8.8.8#5353"), ("8.8.8.8".into(), Some("5353".into())));
        assert_eq!(split_host_port("2001:db8::1"), ("2001:db8::1".into(), None));
    }
    #[test]
    fn t_b64() {
        assert_eq!(b64_decode("aGVsbG8").unwrap(), "hello");
        assert_eq!(url_decode("a%20b"), "a b");
    }

    fn tdir(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("pw2-util-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    #[test]
    fn t_var_apply_lookup() {
        let t = var_apply("", "A", "1");
        let t = var_apply(&t, "AB", "2");
        let t = var_apply(&t, "A", "3");
        assert_eq!(t, "AB=\"2\"\nA=\"3\"\n");
        assert_eq!(var_lookup(&t, "A").as_deref(), Some("3"));
        assert_eq!(var_lookup(&t, "AB").as_deref(), Some("2"));
        assert_eq!(var_lookup(&t, "B"), None);
        assert_eq!(var_apply(&t, "A", ""), "AB=\"2\"\n");
        assert_eq!(var_apply("", "X", ""), "");
    }

    #[test]
    fn t_var_concurrent_writers_keep_all_keys() {
        let d = tdir("var");
        let (f, l) = (format!("{}/var", d), format!("{}/var.lock", d));
        let hs: Vec<_> = (0..8)
            .map(|t| {
                let (f, l) = (f.clone(), l.clone());
                std::thread::spawn(move || {
                    for i in 0..40 {
                        var_set_at(&f, &l, &format!("K{}_{}", t, i), "v");
                        if i % 2 == 1 {
                            var_set_at(&f, &l, &format!("K{}_{}", t, i - 1), "");
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let text = read(&f);
        for t in 0..8 {
            for i in 0..40 {
                assert_eq!(var_lookup(&text, &format!("K{}_{}", t, i)).is_some(), i % 2 == 1, "K{}_{}", t, i);
            }
        }
        assert_eq!(text.lines().count(), 8 * 20);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn t_pick_port_wraps_and_terminates() {
        assert_eq!(pick_port(48900, &|_| false), Some(48900));
        // top of the range used up: wrap to the bottom instead of bouncing 49150<->49151
        assert_eq!(pick_port(48900, &|p| p >= 48900), Some(PORT_MIN));
        assert_eq!(pick_port(49151, &|p| p == 49151 || p == PORT_MIN), Some(PORT_MIN + 1));
        assert_eq!(pick_port(80, &|_| false), Some(2001));
        assert_eq!(pick_port(48900, &|_| true), None);
    }

    #[test]
    fn t_get_new_port_unique_across_threads() {
        let d = tdir("port");
        let (f, l) = (format!("{}/var", d), format!("{}/var.lock", d));
        let mut listening = std::collections::HashMap::new();
        listening.insert(48901u16, 1usize);
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let (f, l, ls) = (f.clone(), l.clone(), listening.clone());
                std::thread::spawn(move || (0..30).map(|_| get_new_port_at(&f, &l, "48900", &ls)).collect::<Vec<u16>>())
            })
            .collect();
        let mut all: Vec<u16> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort();
        let n = all.len();
        all.dedup();
        assert_eq!(all.len(), n, "duplicate port handed out");
        assert!(!all.contains(&48901));
        // releasing a reservation makes the port available again
        var_set_at(&f, &l, "get_port_48900", "");
        assert_eq!(get_new_port_at(&f, &l, "48900", &listening), 48900);
        // auto mode continues after the last auto port
        let a = get_new_port_at(&f, &l, "auto", &listening);
        assert_eq!(a, 2001);
        assert_eq!(get_new_port_at(&f, &l, "auto", &listening), 2002);
        let _ = std::fs::remove_dir_all(&d);
    }
}
