//! Port of `luasrc/passwall2/api.lua` (+ `com.lua`): shared node / URL / version / curl /
//! updater helpers used by every backend module. Spec: docs/spec/05-api-helpers.md §0–§1.
//!
//! Conventions:
//! * Functions keep the upstream (Lua) names in snake_case so callers can map 1:1
//!   (`get_node_remarks`, `parse_dns`, `compare_versions`, `curl_auto`, `to_check`, ...).
//! * Lua `nil` is `Option::None`. LuCI `datatypes.*` validators are re-implemented with the
//!   exact LuCI semantics (`dt_ip4addr` accepts CIDR / netmask like `luci.ip.IPv4`).
//! * Node sections are plain [`crate::uci::Section`]s of `/etc/config/passwall2`.
//! * Translation (`translate`/`translatef`) reads LuCI `.lmo` catalogs exactly like
//!   `luci.i18n`, so backend log lines are localized like upstream.

use crate::uci::{Config, Section};
use crate::util;
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// ====================================================================== constants

pub const APPNAME: &str = "passwall2";
pub const C_CONFIG: &str = "passwall2";
pub const S_CONFIG: &str = "passwall2_server";
/// Upstream `curl_args` (shell fragments, joined with spaces into the curl command line).
pub const CURL_ARGS: [&str; 4] = ["-skfL", "--connect-timeout 3", "--retry 3", "-H 'Accept: */*'"];
/// Seconds (used by `to_move`'s `mv`).
pub const COMMAND_TIMEOUT: u64 = 300;
pub const DIRECT_GID: u32 = util::DIRECT_GID;
pub const LOCK_PREFIX: &str = "/var/lock/passwall2";
pub const LOG_FILE: &str = util::LOG_FILE;
pub const TMP_PATH: &str = util::TMP_PATH;
pub const CACHE_PATH: &str = "/tmp/etc/passwall2_tmp";
pub const S_TMP_PATH: &str = "/tmp/etc/passwall2_server";
pub const TMP_IFACE_PATH: &str = util::TMP_IFACE_PATH;
pub const TMP_ACL_PATH: &str = util::TMP_ACL_PATH;

/// `curl_args` as owned strings (convenience for the curl wrappers).
pub fn curl_args() -> Vec<String> {
    CURL_ARGS.iter().map(|s| s.to_string()).collect()
}

// ====================================================================== logging

/// `api.echolog(...)`: append one line to `/tmp/log/passwall2.log`.
pub fn echolog(msg: &str) {
    util::echolog(msg)
}
/// `api.echolog_date(...)`: `YYYY-mm-dd HH:MM:SS: msg`.
pub fn echolog_date(msg: &str) {
    util::echolog_date(msg)
}
/// `api.log(level, ...)`: level ≥ 1 indents with `"  "×level .. "- "`.
pub fn log(level: usize, msg: &str) {
    util::log(level, msg)
}

// ====================================================================== i18n (luci.i18n + lmo)

struct Catalog {
    archives: Vec<Vec<u8>>,
}

fn i18n_dir() -> String {
    std::env::var("PASSWALL2_I18N_DIR").unwrap_or_else(|_| "/usr/lib/lua/luci/i18n".to_string())
}

/// SuperFastHash as used by LuCI's lmo (`sfh_hash`, little-endian 16-bit reads).
pub fn sfh_hash(data: &[u8], init: u32) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let get16 = |d: &[u8], i: usize| -> u32 { ((d[i + 1] as u32) << 8) + d[i] as u32 };
    let mut hash = init;
    let rem = data.len() & 3;
    let mut i = 0;
    for _ in 0..(data.len() >> 2) {
        hash = hash.wrapping_add(get16(data, i));
        let tmp = (get16(data, i + 2) << 11) ^ hash;
        hash = (hash << 16) ^ tmp;
        i += 4;
        hash = hash.wrapping_add(hash >> 11);
    }
    match rem {
        3 => {
            hash = hash.wrapping_add(get16(data, i));
            hash ^= hash << 16;
            hash ^= ((data[i + 2] as i8 as i32) << 18) as u32;
            hash = hash.wrapping_add(hash >> 11);
        }
        2 => {
            hash = hash.wrapping_add(get16(data, i));
            hash ^= hash << 11;
            hash = hash.wrapping_add(hash >> 17);
        }
        1 => {
            hash = hash.wrapping_add(data[i] as i8 as i32 as u32);
            hash ^= hash << 10;
            hash = hash.wrapping_add(hash >> 1);
        }
        _ => {}
    }
    hash ^= hash << 3;
    hash = hash.wrapping_add(hash >> 5);
    hash ^= hash << 4;
    hash = hash.wrapping_add(hash >> 17);
    hash ^= hash << 25;
    hash = hash.wrapping_add(hash >> 6);
    hash
}

/// `lmo_canon_hash(key, NULL ctx, plural=-1)`: whitespace runs collapsed, ends trimmed.
pub fn lmo_canon_hash(key: &str) -> u32 {
    let is_sp = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let mut res: Vec<u8> = Vec::with_capacity(key.len());
    let mut prev = b' ';
    for &c in key.as_bytes() {
        if res.len() >= 4096 {
            return 0;
        }
        if is_sp(c) {
            if !is_sp(prev) {
                res.push(b' ');
            }
        } else {
            res.push(c);
        }
        prev = c;
    }
    if res.last().is_some_and(|c| is_sp(*c)) {
        res.pop();
    }
    sfh_hash(&res, res.len() as u32)
}

fn lmo_lookup(ar: &[u8], hash: u32) -> Option<&[u8]> {
    if ar.len() < 4 {
        return None;
    }
    let be = |i: usize| -> Option<u32> { ar.get(i..i + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])) };
    let idx_off = be(ar.len() - 4)? as usize;
    if idx_off >= ar.len() {
        return None;
    }
    let n = (ar.len() - idx_off - 4) / 16;
    if n == 0 {
        return None;
    }
    let (mut l, mut r) = (0i64, n as i64 - 1);
    while l <= r {
        let m = l + (r - l) / 2;
        let e = idx_off + m as usize * 16;
        let k = be(e)?;
        if k == hash {
            let off = be(e + 8)? as usize;
            let len = be(e + 12)? as usize;
            return ar.get(off..off + len);
        }
        if k > hash {
            r = m - 1;
        } else {
            l = m + 1;
        }
    }
    None
}

fn load_catalog(lang: &str) -> Option<Catalog> {
    let dir = i18n_dir();
    let suffix = format!(".{}.lmo", lang);
    let mut archives = vec![];
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(&suffix) && n.len() > suffix.len())
        .collect();
    names.sort();
    // our own catalog first so its strings win over other domains
    names.sort_by_key(|n| !n.starts_with("passwall2."));
    for n in names {
        if let Ok(b) = std::fs::read(format!("{}/{}", dir, n)) {
            archives.push(b);
        }
    }
    if archives.is_empty() {
        None
    } else {
        Some(Catalog { archives })
    }
}

/// Current backend language (upstream module-init logic): `luci.main.lang`, if `auto` then
/// `passwall2.@global[0].auto_lang`, if still `auto` then `en` (`i18n.default`).
pub fn current_lang() -> String {
    let luci = Config::load("luci");
    let mut lang = luci.get("main", "lang").unwrap_or_else(|| "auto".into());
    if lang == "auto" {
        if let Some(a) = Config::load(C_CONFIG).get("@global[0]", "auto_lang") {
            lang = a;
        }
    }
    if lang == "auto" {
        lang = "en".into();
    }
    lang
}

/// `luci.i18n.setlanguage` candidate list: `xx[-_]yy` → [`xx-yy`, `xx`]; `xx` → [`xx`]; else none.
pub fn lang_candidates(lang: &str) -> Vec<String> {
    let b = lang.as_bytes();
    let alpha = |c: u8| c.is_ascii_alphabetic();
    if b.len() == 5 && alpha(b[0]) && alpha(b[1]) && (b[2] == b'-' || b[2] == b'_') && alpha(b[3]) && alpha(b[4]) {
        let parent = lang[..2].to_lowercase();
        return vec![format!("{}-{}", parent, lang[3..].to_lowercase()), parent];
    }
    if b.len() == 2 && alpha(b[0]) && alpha(b[1]) {
        return vec![lang.to_lowercase()];
    }
    vec![]
}

fn catalog() -> &'static Option<Catalog> {
    static CAT: OnceLock<Option<Catalog>> = OnceLock::new();
    CAT.get_or_init(|| {
        for l in lang_candidates(&current_lang()) {
            if let Some(c) = load_catalog(&l) {
                return Some(c);
            }
        }
        None
    })
}

/// `i18n.translate(msgid)`: translated string from the active lmo catalog, or msgid itself.
pub fn translate(msgid: &str) -> String {
    if let Some(cat) = catalog() {
        let h = lmo_canon_hash(msgid);
        for ar in &cat.archives {
            if let Some(v) = lmo_lookup(ar, h) {
                return String::from_utf8_lossy(v).to_string();
            }
        }
    }
    msgid.to_string()
}

/// `i18n.translatef(fmt, ...)`: translate then substitute `%s`/`%d` in order (`%%` → `%`).
pub fn translatef(fmt: &str, args: &[&str]) -> String {
    util::i18n(&translate(fmt), args)
}

/// Localized `log(level, translatef(fmt, args))` (upstream `log_i18n`).
pub fn log_i18n(level: usize, fmt: &str, args: &[&str]) {
    util::log(level, &translatef(fmt, args))
}

// ====================================================================== UCI wrappers

fn uci_cmd() -> Command {
    let mut c = Command::new("uci");
    if let Ok(d) = std::env::var("PASSWALL2_UCI_DIR") {
        c.arg("-c").arg(d);
    }
    c
}
fn uci_run(args: &[&str]) -> (bool, String) {
    match uci_cmd().args(args).stderr(Stdio::null()).output() {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string()),
        Err(_) => (false, String::new()),
    }
}

/// `sh_uci_get(c,s,o)` → `uci -q get c.s.o` (trimmed; "" when missing).
pub fn sh_uci_get(config: &str, section: &str, option: &str) -> String {
    trim(&uci_run(&["-q", "get", &format!("{}.{}.{}", config, section, option)]).1)
}
/// `sh_uci_set(c,s,o,val,commit)` → `uci -q set c.s.o=val` (+ commit).
pub fn sh_uci_set(config: &str, section: &str, option: &str, val: &str, commit: bool) {
    uci_run(&["-q", "set", &format!("{}.{}.{}={}", config, section, option, val)]);
    if commit {
        sh_uci_commit(config);
    }
}
/// `sh_uci_del(c,s,o,commit)` → `uci -q delete c.s.o`.
pub fn sh_uci_del(config: &str, section: &str, option: &str, commit: bool) {
    uci_run(&["-q", "delete", &format!("{}.{}.{}", config, section, option)]);
    if commit {
        sh_uci_commit(config);
    }
}
/// `sh_uci_add_list` → `del_list` then `add_list` (dedupe-append).
pub fn sh_uci_add_list(config: &str, section: &str, option: &str, val: &str, commit: bool) {
    let p = format!("{}.{}.{}={}", config, section, option, val);
    uci_run(&["-q", "del_list", &p]);
    uci_run(&["-q", "add_list", &p]);
    if commit {
        sh_uci_commit(config);
    }
}
/// `sh_uci_commit(c)` → `uci -q commit c`.
pub fn sh_uci_commit(config: &str) {
    uci_run(&["-q", "commit", config]);
}

/// `api.uci_set(config, section, option, value)` semantics on a [`crate::uci::Batch`] for a
/// JSON value: numbers/bools → string; non-empty array → `set_list`; non-empty string → `set`;
/// empty string / empty array / null → delete the option.
pub fn uci_set_json(b: &mut crate::uci::Batch, config: &str, section: &str, option: &str, value: &Value) {
    let path = format!("{}.{}.{}", config, section, option);
    match value {
        Value::Array(a) if !a.is_empty() => {
            let l: Vec<String> = a.iter().map(json_to_plain).collect();
            b.set_list(&path, &l);
        }
        Value::Null | Value::Array(_) => {
            b.delete(&path);
        }
        v => {
            let s = json_to_plain(v);
            if s.is_empty() {
                b.delete(&path);
            } else {
                b.set(&path, &s);
            }
        }
    }
}
fn json_to_plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }
}

// ====================================================================== cache vars

/// `api.get_cache_var(key)` (None for missing or empty).
pub fn get_cache_var(key: &str) -> Option<String> {
    util::get_cache_var(key).filter(|v| !v.is_empty())
}
/// `api.set_cache_var(key, val)` (empty val just deletes).
pub fn set_cache_var(key: &str, val: &str) {
    util::set_cache_var(key, val)
}
/// `api.del_cache_var(key)`.
pub fn del_cache_var(key: &str) {
    util::del_cache_var(key)
}
/// `api.get_new_port(start_port, protocol)`: `None` start = `auto`; protocol other than
/// `tcp`/`udp` means `tcp,udp`.
pub fn get_new_port(start_port: Option<u16>, protocol: &str) -> u16 {
    let proto = if protocol == "tcp" || protocol == "udp" { protocol } else { "tcp,udp" };
    match start_port {
        Some(p) => util::get_new_port(&p.to_string(), proto),
        None => util::get_new_port("auto", proto),
    }
}
/// `get_socks_port_by_cache(node_id)` = cache `node_<id>_socks_port`.
pub fn get_socks_port_by_cache(node_id: &str) -> Option<String> {
    get_cache_var(&format!("node_{}_socks_port", node_id))
}
/// `set_socks_port_to_cache(node_id, v)`.
pub fn set_socks_port_to_cache(node_id: &str, v: &str) {
    set_cache_var(&format!("node_{}_socks_port", node_id), v)
}

// ====================================================================== process execution

/// `api.exec_call(cmd)`: run `cmd` with `/bin/sh`, stdout+stderr merged → `(rc, trim(out))`.
/// rc is 255 when the shell could not be run or was killed by a signal.
pub fn exec_call(cmd: &str) -> (i32, String) {
    match Command::new("/bin/sh").arg("-c").arg(format!("({}) 2>&1", cmd)).stdin(Stdio::null()).stderr(Stdio::null()).output() {
        Ok(o) => (o.status.code().unwrap_or(255), trim(&String::from_utf8_lossy(&o.stdout))),
        Err(_) => (255, String::new()),
    }
}

/// `api.exec_call_as_gid(cmd, gid)`: like [`exec_call`] but the shell runs with group id
/// `gid` (processes with GID 9912 bypass the transparent proxy). setgid failure → rc 1.
pub fn exec_call_as_gid(cmd: &str, gid: u32) -> (i32, String) {
    use std::os::unix::process::CommandExt;
    let r = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("({}) 2>&1", cmd))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .gid(gid)
        .output();
    match r {
        Ok(o) => (o.status.code().unwrap_or(255), trim(&String::from_utf8_lossy(&o.stdout))),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (1, String::new()),
        Err(_) => (255, "Unable to fork command".into()),
    }
}

/// `api.exec(cmd, args, nil, timeout)`: run program directly (no shell), stdout discarded;
/// with `timeout` (seconds) the child is SIGTERM'ed and `Some(1)` returned when it expires.
/// Returns the exit code (`None` when it could not start or died by a signal).
pub fn exec(prog: &str, args: &[&str], timeout: Option<u64>) -> Option<i32> {
    let mut child = Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()?;
    match timeout {
        None => child.wait().ok()?.code(),
        Some(t) => {
            let start = std::time::Instant::now();
            loop {
                if let Ok(Some(st)) = child.try_wait() {
                    return st.code();
                }
                if start.elapsed().as_secs() >= t {
                    util::kill_pids(&[child.id()], 15);
                    let _ = child.wait();
                    return Some(1);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}

/// `api.remove(...)`: `rm -rf -- <path>` for each non-empty path ≠ "/" (globs are expanded on
/// purpose, e.g. `/tmp/xray_download.*`).
pub fn remove(paths: &[&str]) {
    for p in paths {
        if !p.is_empty() && *p != "/" {
            util::sh_ok(&format!("rm -rf -- {}", p));
        }
    }
}

/// `api.is_install(pkg)`: opkg (`/usr/lib/opkg/info/<pkg>.control`) or apk
/// (`/lib/apk/packages/<pkg>.list`) non-empty file exists.
pub fn is_install(pkg: &str) -> bool {
    if pkg.is_empty() {
        return false;
    }
    let p = if std::path::Path::new("/usr/lib/opkg/info").is_dir() {
        format!("/usr/lib/opkg/info/{}.control", pkg)
    } else {
        format!("/lib/apk/packages/{}.list", pkg)
    };
    std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false)
}

fn which(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    if name.contains('/') {
        return if util::is_executable(name) { Some(name.to_string()) } else { None };
    }
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    for d in path.split(':') {
        let p = format!("{}/{}", if d.is_empty() { "." } else { d }, name);
        if util::is_executable(&p) {
            return Some(p);
        }
    }
    None
}

/// `api.finded(e)`: path of `e` looked up in `/bin`, `/usr/bin`, then `$PATH` ("" if none).
pub fn finded(e: &str) -> String {
    if e.is_empty() {
        return String::new();
    }
    for p in [format!("/bin/{}", e), format!("/usr/bin/{}", e)] {
        if util::is_executable(&p) {
            return p;
        }
    }
    which(e).unwrap_or_default()
}
/// `api.is_finded(e)`.
pub fn is_finded(e: &str) -> bool {
    !finded(e).is_empty()
}
/// `api.finded_com(app)`: executable path of a com.lua component (`xray`, `sing-box`,
/// `geoview`) from `@global_app[0].<app>_file` or its default path; None if not executable.
pub fn finded_com(app: &str) -> Option<String> {
    let bin = get_app_path(app)?;
    which(&bin)
}

/// `api.chmod_755(file)`: make the file executable (0755) if it is not.
pub fn chmod_755(file: &str) {
    if file.is_empty() {
        return;
    }
    if let Ok(m) = std::fs::metadata(file) {
        if m.permissions().mode() & 0o111 == 0 {
            let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// `api.gen_uuid()`: `/proc/sys/kernel/random/uuid`.
pub fn gen_uuid() -> String {
    trim(&util::read("/proc/sys/kernel/random/uuid"))
}

/// `api.gen_random_char(len)`: `len` (default 8) random chars of `[A-Za-z0-9]`.
pub fn gen_random_char(len: usize) -> String {
    use std::io::Read;
    let mut out = String::with_capacity(len);
    let mut f = std::fs::File::open("/dev/urandom").ok();
    let mut seed = util::epoch() ^ (std::process::id() as u64) << 20;
    while out.len() < len {
        let mut buf = [0u8; 64];
        let ok = f.as_mut().map(|f| f.read_exact(&mut buf).is_ok()).unwrap_or(false);
        if !ok {
            for b in buf.iter_mut() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
        }
        for b in buf {
            if b.is_ascii_alphanumeric() && out.len() < len {
                out.push(b as char);
            }
        }
    }
    out
}

/// `api.get_customed_path(e)` → `@global_app[0].<e>_file`.
pub fn get_customed_path(e: &str) -> Option<String> {
    Config::load(C_CONFIG).get("@global_app[0]", &format!("{}_file", e))
}

// ====================================================================== encoding / hashing

/// `api.base64Decode` core: decoded bytes, or None when `text` is not canonical base64
/// (upstream then returns the input unchanged). Control chars are ignored, url-safe alphabet
/// and missing padding accepted. NUL bytes are kept (see [`base64_decode`]).
pub fn base64_decode_bytes(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let mut enc: String = text
        .chars()
        .filter(|c| !((*c as u32) < 32 || *c as u32 == 127))
        .map(|c| match c {
            '_' => '/',
            '-' => '+',
            x => x,
        })
        .collect();
    while enc.ends_with('=') {
        enc.pop();
    }
    if enc.is_empty() || !enc.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') || enc.len() % 4 == 1 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(enc.as_bytes()).ok()?;
    let re = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&bytes);
    if re != enc {
        return None;
    }
    Some(bytes)
}

/// `api.base64Decode(text)`: decoded text (NULs removed) or `text` unchanged if it is not
/// base64 — so `base64_decode(x) == x` means "not base64".
pub fn base64_decode(text: &str) -> String {
    match base64_decode_bytes(text) {
        Some(b) => {
            let b: Vec<u8> = b.into_iter().filter(|c| *c != 0).collect();
            String::from_utf8_lossy(&b).to_string()
        }
        None => text.to_string(),
    }
}

/// `api.base64Encode(text)`: standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// `api.UrlEncode(s)`: every byte outside `[A-Za-z0-9-_.~]` → `%XX`.
pub fn url_encode(s: &str) -> String {
    util::url_encode(s)
}

/// `api.UrlDecode(s)`: `+` → space, `%XX` → byte.
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let hex = |c: u8| (c as char).to_digit(16);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// `api.md5_file(path)`: md5 hex of a file ("" on error).
pub fn md5_file(path: &str) -> String {
    let out = util::cmd_out("md5sum", &[path]);
    let h = out.split_whitespace().next().unwrap_or("");
    if h.len() == 32 { h.to_string() } else { String::new() }
}
/// `api.md5_string(str)`: md5 hex of a string.
pub fn md5_string(s: &str) -> String {
    util::md5_hex(s)
}

/// `api.verify_sha256(file, digest)`: digest must be `sha256:<64 hex>`; true iff the file's
/// sha256 matches (case-insensitive).
pub fn verify_sha256(file: &str, digest: &str) -> bool {
    let Some(exp) = digest.strip_prefix("sha256:") else { return false };
    if exp.len() != 64 || !exp.bytes().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let (rc, out) = exec_call(&format!("sha256sum {}", util::shq(file)));
    let actual: String = out.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    rc == 0 && !actual.is_empty() && out[actual.len()..].starts_with(char::is_whitespace) && actual.eq_ignore_ascii_case(exp)
}

/// `api.sha256_xray_sb(str)`: hex fingerprint (colons allowed) → base64 (sing-box format);
/// already-base64 32-byte values and anything else are returned unchanged.
pub fn sha256_xray_sb(s: &str) -> String {
    // upstream quirk: upstream strips NUL bytes before the 32-byte length check, which fails
    // for hashes containing a 0x00 byte; we check the raw decoded length.
    if let Some(d) = base64_decode_bytes(s) {
        if d.len() == 32 && base64_decode(s) != s {
            return s.to_string();
        }
    }
    let hex: String = s.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return s.to_string();
    }
    let bytes: Vec<u8> = (0..32).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
    base64_encode(&bytes)
}

/// `api.sha256_sb_xray(str)`: base64 32-byte fingerprint → uppercase hex (Xray format);
/// otherwise unchanged.
pub fn sha256_sb_xray(s: &str) -> String {
    match base64_decode_bytes(s) {
        Some(b) if b.len() == 32 => b.iter().map(|x| format!("{:02X}", x)).collect(),
        _ => s.to_string(),
    }
}

/// `api.fetch_cert_sha256(host, port=443, sni=host, timeout=5)`: SHA-256 of the leaf
/// certificate (DER) as UPPERCASE hex, "" on failure.
pub fn fetch_cert_sha256(host: &str, port: Option<u16>, sni: Option<&str>, timeout: Option<u32>) -> String {
    if host.is_empty() {
        return String::new();
    }
    let port = port.unwrap_or(443);
    let sni = sni.filter(|s| !s.is_empty()).unwrap_or(host);
    let timeout = timeout.unwrap_or(5);
    let h = if is_ipv6(host) && !host.starts_with('[') { format!("[{}]", host) } else { host.to_string() };
    let cmd = format!(
        "timeout {} openssl s_client -connect {} -servername {} -showcerts </dev/null 2>/dev/null \
         | awk 'BEGIN{{c=0}}/BEGIN CERT/{{c++}} c==1{{print}} /END CERT/{{if(c==1)exit}}' \
         | openssl x509 -outform der 2>/dev/null | sha256sum 2>/dev/null",
        timeout,
        util::shq(&format!("{}:{}", h, port)),
        util::shq(sni)
    );
    let out = trim(&util::sh(&cmd));
    let fp: String = out.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if fp.is_empty() || fp.to_lowercase().starts_with("e3b0c44298fc1c149afbf4c8996fb924") {
        return String::new();
    }
    fp.to_uppercase()
}

// ====================================================================== LuCI datatypes

/// Lua `tonumber(s)` for decimal ints/floats and `0x` hex (leading/trailing spaces allowed).
pub fn lua_tonumber(s: &str) -> Option<f64> {
    let t = s.trim_matches(|c: char| c.is_ascii_whitespace());
    if t.is_empty() {
        return None;
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        let v = u64::from_str_radix(h, 16).ok()? as f64;
        return Some(if neg { -v } else { v });
    }
    if !body.bytes().all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-')) || !body.bytes().any(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<f64>().ok()
}

/// `datatypes.ip4addr` (`luci.ip.IPv4`): `a.b.c.d`, `a.b.c.d/N` (0..32) or `a.b.c.d/m.m.m.m`.
pub fn dt_ip4addr(v: &str) -> bool {
    match v.split_once('/') {
        Some((ip, m)) => {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
                && (m.parse::<std::net::Ipv4Addr>().is_ok() || (!m.is_empty() && m.bytes().all(|c| c.is_ascii_digit()) && m.parse::<u32>().is_ok_and(|n| n <= 32)))
        }
        None => v.parse::<std::net::Ipv4Addr>().is_ok(),
    }
}
/// `datatypes.ip6addr` (`luci.ip.IPv6`): IPv6 with optional `%zone` and `/N` (0..128).
pub fn dt_ip6addr(v: &str) -> bool {
    let (addr, pfx) = match v.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (v, None),
    };
    let addr = match addr.split_once('%') {
        Some((a, z)) if !z.is_empty() => a,
        Some(_) => return false,
        None => addr,
    };
    if addr.parse::<std::net::Ipv6Addr>().is_err() {
        return false;
    }
    match pfx {
        None => true,
        Some(p) => !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| n <= 128),
    }
}
/// `datatypes.ipaddr`.
pub fn dt_ipaddr(v: &str) -> bool {
    dt_ip4addr(v) || dt_ip6addr(v)
}
/// `datatypes.port`: `tonumber(v)` in 0..=65535.
pub fn dt_port(v: &str) -> bool {
    lua_tonumber(v).is_some_and(|n| (0.0..=65535.0).contains(&n))
}
/// `datatypes.macaddr` (`luci.ip.checkmac`): 6 groups of 1–2 hex digits separated by `:` or `-`.
pub fn dt_macaddr(v: &str) -> bool {
    let parts: Vec<&str> = v.split([':', '-']).collect();
    parts.len() == 6 && parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.bytes().all(|c| c.is_ascii_hexdigit()))
}
/// `datatypes.hostname(v)` (non-strict).
pub fn dt_hostname(v: &str) -> bool {
    let b = v.as_bytes();
    if b.is_empty() || b.len() >= 254 {
        return false;
    }
    if b.iter().all(|c| c.is_ascii_alphabetic() || *c == b'_') {
        return true;
    }
    let first_ok = b[0].is_ascii_alphanumeric() || b[0] == b'_';
    let last_ok = b.len() >= 2 && b[b.len() - 1].is_ascii_alphanumeric();
    let mid_ok = b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'));
    first_ok && last_ok && mid_ok && b.iter().any(|c| !(c.is_ascii_digit() || *c == b'.'))
}

/// Lua `val:match("%[(.-)%]")`: content of the first `[...]`.
fn bracket_inner(v: &str) -> Option<&str> {
    let i = v.find('[')?;
    let j = v[i + 1..].find(']')?;
    Some(&v[i + 1..i + 1 + j])
}

/// `api.is_ip(val)`: trimmed, lowercased, inner of `[...]` if present → IPv4 or IPv6.
pub fn is_ip(val: &str) -> bool {
    let v = trim(val).to_lowercase();
    dt_ipaddr(bracket_inner(&v).unwrap_or(&v))
}
/// `api.is_ipv6(val)`: like [`is_ip`] but IPv6 only (brackets allowed).
pub fn is_ipv6(val: &str) -> bool {
    let v = trim(val).to_lowercase();
    dt_ip6addr(bracket_inner(&v).unwrap_or(&v))
}
/// `api.is_ipv6addrport(val)`: `[v6]:port`.
pub fn is_ipv6addrport(val: &str) -> bool {
    match ipv6_port_split(val) {
        Some((a, p)) => dt_ip6addr(a) && dt_port(p),
        None => false,
    }
}
/// Lua `val:match("%[(.-)%]:([0-9]+)$")`.
fn ipv6_port_split(val: &str) -> Option<(&str, &str)> {
    let mut from = 0;
    while let Some(off) = val[from..].find('[') {
        let i = from + off;
        let inner_start = i + 1;
        let mut k = inner_start;
        while let Some(o2) = val[k..].find(']') {
            let j = k + o2;
            let rest = &val[j + 1..];
            if let Some(p) = rest.strip_prefix(':') {
                if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) {
                    return Some((&val[inner_start..j], p));
                }
            }
            k = j + 1;
        }
        from = i + 1;
    }
    None
}
/// `api.get_ipv6_only(val)`: IPv6 without brackets, or "".
pub fn get_ipv6_only(val: &str) -> String {
    let inner = bracket_inner(val).unwrap_or(val);
    if dt_ip6addr(inner) { inner.to_string() } else { String::new() }
}
/// `api.get_ipv6_full(val)`: `[v6]`, or "".
pub fn get_ipv6_full(val: &str) -> String {
    if is_ipv6(val) {
        if bracket_inner(val).is_some() { val.to_string() } else { format!("[{}]", val) }
    } else {
        String::new()
    }
}
/// `api.get_ip_type(val)` → "6" / "4" / "".
pub fn get_ip_type(val: &str) -> &'static str {
    if is_ipv6(val) {
        "6"
    } else if dt_ip4addr(val) {
        "4"
    } else {
        ""
    }
}
/// `api.is_mac(val)`.
pub fn is_mac(val: &str) -> bool {
    dt_macaddr(val)
}
/// `api.ip_or_mac(val)` → "ip" (IPv4 incl. CIDR) / "mac" / "".
pub fn ip_or_mac(val: &str) -> &'static str {
    if get_ip_type(val) == "4" {
        "ip"
    } else if is_mac(val) {
        "mac"
    } else {
        ""
    }
}
/// `api.iprange(val)`: `A-B` with both IPv4 (no `/`).
pub fn iprange(val: &str) -> bool {
    if val.contains('/') {
        return false;
    }
    // Lua `^([^/]+)-([^/]+)$`: greedy first part → split at the last '-'
    match val.rfind('-') {
        Some(i) if i > 0 && i + 1 < val.len() => dt_ip4addr(&val[..i]) && dt_ip4addr(&val[i + 1..]),
        _ => false,
    }
}

// ====================================================================== string / table helpers

/// `api.trim(s)`: strip bytes ≤ 32 from both ends.
pub fn trim(s: &str) -> String {
    s.trim_matches(|c: char| (c as u32) <= 32).to_string()
}

/// `api.split(full, sep)` with a literal separator: NULs removed, inner empty pieces kept,
/// trailing empty piece dropped.
pub fn split(full: &str, sep: &str) -> Vec<String> {
    let full: String = full.chars().filter(|c| *c != '\0').collect();
    if sep.is_empty() {
        return if full.is_empty() { vec![] } else { vec![full] };
    }
    let mut v: Vec<String> = full.split(sep).map(|s| s.to_string()).collect();
    if v.last().is_some_and(|s| s.is_empty()) {
        v.pop();
    }
    v
}

/// `api.is_exist(t, v)`.
pub fn is_exist<T: AsRef<str>>(t: &[T], v: &str) -> bool {
    t.iter().any(|x| x.as_ref() == v)
}
/// `api.repeat_exist(t, v)`: more than one entry containing `-` equals v.
pub fn repeat_exist<T: AsRef<str>>(t: &[T], v: &str) -> bool {
    t.iter().filter(|x| x.as_ref().contains('-') && x.as_ref() == v).count() > 1
}
/// `api.get_args(arg)`: `{arg[i] = arg[i+1]}` unless arg[i+1] is a repeated `-`-value.
pub fn get_args(args: &[String]) -> IndexMap<String, String> {
    let mut m = IndexMap::new();
    for i in 0..args.len() {
        if let Some(v) = args.get(i + 1) {
            if !repeat_exist(args, v) {
                m.insert(args[i].clone(), v.clone());
            }
        }
    }
    m
}
/// `api.is_json(str)`.
pub fn is_json(s: &str) -> bool {
    serde_json::from_str::<Value>(s).is_ok()
}
/// `api.is_timehhmm(str)`: `H:MM` / `HH:MM`, 0-23 / 0-59.
pub fn is_timehhmm(s: &str) -> bool {
    let Some((h, m)) = s.split_once(':') else { return false };
    if h.is_empty() || h.len() > 2 || m.len() != 2 || !h.bytes().chain(m.bytes()).all(|c| c.is_ascii_digit()) {
        return false;
    }
    h.parse::<u32>().is_ok_and(|x| x <= 23) && m.parse::<u32>().is_ok_and(|x| x <= 59)
}
/// `api.is_uuid(str)`: 8-4-4-4-12 hex.
pub fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, x)| x.len() == *n && x.bytes().all(|c| c.is_ascii_hexdigit()))
}
/// `api.table_remove_duplicates(t)`: None if empty; keep first occurrences, drop "".
pub fn table_remove_duplicates(t: &[String]) -> Option<Vec<String>> {
    if t.is_empty() {
        return None;
    }
    let mut out: Vec<String> = vec![];
    for x in t {
        if !x.is_empty() && !out.contains(x) {
            out.push(x.clone());
        }
    }
    Some(out)
}
/// `api.table_join(t, sep=" ")`.
pub fn table_join<T: AsRef<str>>(t: &[T], sep: &str) -> String {
    t.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(sep)
}
/// `api.cleanEmptyTables(t)`: recursively removes empty objects/arrays; None if `t` ends empty
/// (or is not an object/array).
pub fn clean_empty_tables(t: Value) -> Option<Value> {
    match t {
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, v) in m {
                match v {
                    Value::Object(_) | Value::Array(_) => {
                        if let Some(c) = clean_empty_tables(v) {
                            out.insert(k, c);
                        }
                    }
                    other => {
                        out.insert(k, other);
                    }
                }
            }
            if out.is_empty() { None } else { Some(Value::Object(out)) }
        }
        Value::Array(a) => {
            let mut out = vec![];
            for v in a {
                match v {
                    Value::Object(_) | Value::Array(_) => {
                        if let Some(c) = clean_empty_tables(v) {
                            out.push(c);
                        }
                    }
                    other => out.push(other),
                }
            }
            if out.is_empty() { None } else { Some(Value::Array(out)) }
        }
        _ => None,
    }
}
/// `api.cacheFileCompareToLogic(file, str)`: true if the file already held `s`; the file is
/// (re)written with `s` in any case.
pub fn cache_file_compare_to_logic(file: &str, s: &str) -> bool {
    let cur = util::read(file);
    let same = cur == s;
    if !same {
        let _ = std::fs::remove_file(file);
    }
    let _ = std::fs::write(file, s);
    same
}

/// `api.format_go_time(input, default="0s")`: seconds or `1h2m3s` style → normalized Go
/// duration (`3600`→`1h`, `90`→`1m30s`); ≤0 → default.
pub fn format_go_time(input: Option<&str>, default: Option<&str>) -> String {
    let def = default.unwrap_or("0s").to_string();
    let Some(input) = input else { return def };
    let input = trim(input);
    let mut n: u64 = 0;
    if !input.is_empty() && input.bytes().all(|c| c.is_ascii_digit()) {
        n = input.parse::<u64>().unwrap_or(u64::MAX);
    } else if !input.is_empty() {
        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_digit() {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                let mut k = j;
                while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
                    k += 1;
                }
                if k < b.len() && matches!(b[k], b'h' | b'm' | b's') {
                    let v: u64 = input[i..j].parse().unwrap_or(0);
                    let mul = match b[k] {
                        b'h' => 3600,
                        b'm' => 60,
                        _ => 1,
                    };
                    n = n.saturating_add(v.saturating_mul(mul));
                    i = k + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
    if n == 0 {
        return def;
    }
    let (h, m, s) = (n / 3600, n % 3600 / 60, n % 60);
    let mut r = String::new();
    if h > 0 {
        r.push_str(&format!("{}h", h));
    }
    if m > 0 {
        r.push_str(&format!("{}m", m));
    }
    if s > 0 || r.is_empty() {
        r.push_str(&format!("{}s", s));
    }
    r
}

/// `api.compare_versions(v1, comp, v2)`: comp ∈ `<`,`<=`,`>`,`>=`,`~=`,`==`. Parts split on
/// `.`/`-`; numeric, `rN`/`RN` → N, else 0. Upstream quirk kept: equal versions return true
/// for every comp except `<` and `>` (including `~=`).
pub fn compare_versions(v1: &str, comp: &str, v2: &str) -> bool {
    fn part(v: Option<&&str>) -> f64 {
        let Some(v) = v else { return 0.0 };
        if let Some(n) = lua_tonumber(v) {
            return n;
        }
        if let Some(r) = v.strip_prefix('r').or_else(|| v.strip_prefix('R')) {
            if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) {
                return r.parse::<f64>().unwrap_or(0.0);
            }
        }
        0.0
    }
    let a1: Vec<&str> = v1.split(['.', '-']).collect();
    let a2: Vec<&str> = v2.split(['.', '-']).collect();
    let max = a1.len().max(a2.len());
    for i in 0..max {
        let s1 = part(a1.get(i));
        let s2 = part(a2.get(i));
        if comp == "~=" && s1 != s2 {
            return true;
        }
        if (comp == "<" || comp == "<=") && s1 < s2 {
            return true;
        }
        if (comp == ">" || comp == ">=") && s1 > s2 {
            return true;
        }
        if s1 != s2 {
            return false;
        }
    }
    !(comp == "<" || comp == ">")
}

/// `api.gen_wireguard_key()` → `(private_key, public_key)` using `wg`, else `xray wg`, else
/// `sing-box generate wg-keypair`; None if no tool is available.
pub fn gen_wireguard_key() -> Option<(String, String)> {
    if util::sh_ok("command -v wg >/dev/null") {
        let private = echo_n(&util::cmd_out("wg", &["genkey"]));
        let (_, pubk) = util::cmd_stdin("wg", &["pubkey"], &format!("{}\n", private));
        return Some((private, echo_n(&pubk)));
    }
    if let Some(x) = finded_com("xray") {
        let out = util::cmd_out(&x, &["wg"]);
        let v: Vec<String> = out.lines().map(|l| l.split_once(": ").map(|x| x.1.to_string()).unwrap_or_default()).collect();
        return Some((v.first().cloned().unwrap_or_default(), v.get(1).cloned().unwrap_or_default()));
    }
    if let Some(sb) = finded_com("sing-box") {
        let out = util::cmd_out(&sb, &["generate", "wg-keypair"]);
        let v: Vec<String> = out.lines().map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string()).collect();
        return Some((v.first().cloned().unwrap_or_default(), v.get(1).cloned().unwrap_or_default()));
    }
    None
}

/// Shell `echo -n $(...)` normalization: words joined by single spaces.
pub fn echo_n(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ====================================================================== Lua patterns

/// Minimal Lua pattern `string.find(s, pat) ~= nil` (classes `%a %d %l %s %u %w %x %p %c`,
/// sets `[...]`, `.`, quantifiers `* + - ?`, anchors `^ $`; no captures). Used for the
/// com.lua asset-name patterns (e.g. `linux%-arm.*6[^4]*`).
pub fn lua_find(s: &str, pat: &str) -> bool {
    let s = s.as_bytes();
    let p = pat.as_bytes();
    if let Some(rest) = p.strip_prefix(b"^") {
        return lp_match(s, 0, rest, 0).is_some();
    }
    (0..=s.len()).any(|i| lp_match(s, i, p, 0).is_some())
}
fn lp_class(c: u8, cl: u8) -> bool {
    let r = match cl.to_ascii_lowercase() {
        b'a' => c.is_ascii_alphabetic(),
        b'd' => c.is_ascii_digit(),
        b'l' => c.is_ascii_lowercase(),
        b's' => matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c),
        b'u' => c.is_ascii_uppercase(),
        b'w' => c.is_ascii_alphanumeric(),
        b'x' => c.is_ascii_hexdigit(),
        b'p' => c.is_ascii_punctuation(),
        b'c' => c.is_ascii_control(),
        _ => return cl == c,
    };
    if cl.is_ascii_uppercase() { !r } else { r }
}
fn lp_class_end(p: &[u8], mut i: usize) -> usize {
    let c = p[i];
    i += 1;
    if c == b'%' {
        return (i + 1).min(p.len());
    }
    if c == b'[' {
        if i < p.len() && p[i] == b'^' {
            i += 1;
        }
        loop {
            if i >= p.len() {
                return p.len();
            }
            let cc = p[i];
            i += 1;
            if cc == b'%' && i < p.len() {
                i += 1;
            }
            if i < p.len() && p[i] == b']' {
                return i + 1;
            }
            if i >= p.len() {
                return p.len();
            }
        }
    }
    i
}
fn lp_bracket(c: u8, p: &[u8], start: usize, ec: usize) -> bool {
    let mut i = start + 1;
    let mut sig = true;
    if i < ec && p[i] == b'^' {
        sig = false;
        i += 1;
    }
    while i < ec {
        if p[i] == b'%' && i + 1 < ec {
            i += 1;
            if lp_class(c, p[i]) {
                return sig;
            }
        } else if i + 2 < ec && p[i + 1] == b'-' {
            if p[i] <= c && c <= p[i + 2] {
                return sig;
            }
            i += 2;
        } else if p[i] == c {
            return sig;
        }
        i += 1;
    }
    !sig
}
fn lp_single(c: u8, p: &[u8], pi: usize, ep: usize) -> bool {
    match p[pi] {
        b'.' => true,
        b'%' if pi + 1 < p.len() => lp_class(c, p[pi + 1]),
        b'[' => lp_bracket(c, p, pi, ep.saturating_sub(1)),
        x => x == c,
    }
}
fn lp_match(s: &[u8], si: usize, p: &[u8], pi: usize) -> Option<usize> {
    if pi >= p.len() {
        return Some(si);
    }
    if p[pi] == b'$' && pi + 1 == p.len() {
        return if si == s.len() { Some(si) } else { None };
    }
    let ep = lp_class_end(p, pi);
    let m = si < s.len() && lp_single(s[si], p, pi, ep);
    if ep < p.len() {
        match p[ep] {
            b'?' => {
                if m {
                    if let Some(r) = lp_match(s, si + 1, p, ep + 1) {
                        return Some(r);
                    }
                }
                return lp_match(s, si, p, ep + 1);
            }
            b'*' | b'+' => {
                let mut n = 0;
                if p[ep] == b'+' && !m {
                    return None;
                }
                while si + n < s.len() && lp_single(s[si + n], p, pi, ep) {
                    n += 1;
                }
                let min = if p[ep] == b'+' { 1 } else { 0 };
                loop {
                    if let Some(r) = lp_match(s, si + n, p, ep + 1) {
                        return Some(r);
                    }
                    if n == min {
                        return None;
                    }
                    n -= 1;
                }
            }
            b'-' => {
                let mut k = si;
                loop {
                    if let Some(r) = lp_match(s, k, p, ep + 1) {
                        return Some(r);
                    }
                    if k < s.len() && lp_single(s[k], p, pi, ep) {
                        k += 1;
                    } else {
                        return None;
                    }
                }
            }
            _ => {}
        }
    }
    if m { lp_match(s, si + 1, p, ep) } else { None }
}

// ====================================================================== filesystem helpers

/// `api.is_file(path)`: regular file (path length > 1).
pub fn is_file(path: &str) -> bool {
    path.len() > 1 && std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
/// `api.is_dir(path)`: directory (path length > 1).
pub fn is_dir(path: &str) -> bool {
    path.len() > 1 && std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}
/// `api.get_final_dir(path)`: nearest existing ancestor directory (stops at `/`; upstream
/// would recurse forever there).
pub fn get_final_dir(path: &str) -> String {
    let mut p = path.to_string();
    loop {
        if is_dir(&p) || p == "/" || p.is_empty() {
            return if p.is_empty() { "/".into() } else { p };
        }
        p = match std::path::Path::new(&p).parent() {
            Some(x) => {
                let s = x.to_string_lossy().to_string();
                if s.is_empty() { ".".into() } else { s }
            }
            None => "/".into(),
        };
        if p == "." {
            return p;
        }
    }
}
/// `api.get_free_space(dir="/")` → available KB (`df -k`), 0 on failure.
pub fn get_free_space(dir: &str) -> u64 {
    let dir = if dir.is_empty() { "/" } else { dir };
    let o = Command::new("df").args(["-k", dir]).stderr(Stdio::null()).output();
    let Ok(o) = o else { return 0 };
    if !o.status.success() {
        return 0;
    }
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let toks: Vec<&str> = text.lines().skip(1).flat_map(|l| l.split_whitespace()).collect();
    toks.get(3).and_then(|v| v.parse().ok()).unwrap_or(0)
}
/// `api.get_file_space(file)` → size in KB (`du -k`), 0 if missing.
pub fn get_file_space(file: &str) -> u64 {
    if file.is_empty() || !util::exists(file) {
        return 0;
    }
    util::cmd_out("du", &["-k", file]).split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0)
}
/// `api.is_js_luci()`.
pub fn is_js_luci() -> bool {
    std::fs::metadata("/www/luci-static/resources/uci.js").map(|m| m.is_file()).unwrap_or(false)
}
/// `api.url(...)`: LuCI URL `/cgi-bin/luci/admin/services/passwall2/<non-empty parts>`.
pub fn url(parts: &[&str]) -> String {
    let mut u = format!("/cgi-bin/luci/admin/services/{}", APPNAME);
    for p in parts {
        if !p.is_empty() {
            u.push('/');
            u.push_str(p);
        }
    }
    u
}

// ====================================================================== URL / DNS parsing

/// `api.get_domain_from_url(url)`: text after the first `//` up to the next `/` (port
/// included), or the url itself.
pub fn get_domain_from_url(url: &str) -> String {
    let b = url.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'/' && b[i + 1] == b'/' && i + 2 < b.len() && b[i + 2] != b'/' {
            let rest = &url[i + 2..];
            return rest.split('/').next().unwrap_or("").to_string();
        }
        i += 1;
    }
    url.to_string()
}

/// `api.get_domain_port_from_url(url)`: `(domain, port)` for `http(s)://` urls whose host is
/// a domain (None for IP hosts / other schemes). Port defaults 443/80.
pub fn get_domain_port_from_url(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else {
        ("http", url.strip_prefix("http://")?)
    };
    let defport = if scheme == "https" { 443 } else { 80 };
    let b = rest.as_bytes();
    let n = b.iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'.' || **c == b'-').count();
    let (domain, port_s): (String, String) = if n > 0 {
        let mut r = &rest[n..];
        if let Some(x) = r.strip_prefix(':') {
            r = x;
        }
        (rest[..n].to_string(), r.bytes().take_while(|c| c.is_ascii_digit()).map(|c| c as char).collect())
    } else if rest.starts_with('[') {
        let j = rest.find(']')?;
        let after = &rest[j + 1..];
        (rest[1..j].to_string(), after.chars().take_while(|c| *c != ':' && *c != '/').collect())
    } else {
        return None;
    };
    let port = if port_s.is_empty() { defport } else { lua_tonumber(&port_s).map(|p| p as u16).unwrap_or(defport) };
    if dt_ipaddr(&domain) {
        return None;
    }
    Some((domain, port))
}

/// Result of [`parse_url`] (`api.parseURL`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedUrl {
    pub protocol: Option<String>,
    pub pathname: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hostname: String,
    pub port: Option<u32>,
    /// raw `host[:port]`
    pub host: String,
}

/// `api.parseURL(url)`: scheme, path (without `?`/`#`), `user[:pass]@`, host/port (IPv6 ok).
/// None when there is no authority part (upstream would error).
pub fn parse_url(url_str: &str) -> Option<ParsedUrl> {
    let mut res = ParsedUrl::default();
    let mut rest = url_str;
    if let Some(i) = url_str.find("://") {
        let scheme = &url_str[..i];
        if !scheme.is_empty() && scheme.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'+')) && url_str.len() > i + 3 {
            res.protocol = Some(scheme.to_string());
            rest = &url_str[i + 3..];
        }
    }
    let alen = rest.find('/').unwrap_or(rest.len());
    if alen == 0 {
        return None;
    }
    let authority = &rest[..alen];
    let path = &rest[alen..];
    if !path.is_empty() {
        res.pathname = Some(path.split(['?', '#']).next().unwrap_or("").to_string());
    }
    let host_port = match authority.find('@') {
        Some(i) if i > 0 && i + 1 < authority.len() => {
            let ui = &authority[..i];
            if ui.starts_with(':') {
                res.username = Some(String::new());
                res.password = Some(String::new());
            } else {
                let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
                res.username = Some(u.to_string());
                res.password = Some(p.to_string());
            }
            &authority[i + 1..]
        }
        _ => authority,
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    if let Some(inner) = host_port.strip_prefix('[') {
        if let Some(j) = inner.rfind("]:") {
            if digits(&inner[j + 2..]) && j > 0 {
                res.hostname = inner[..j].to_string();
                res.port = inner[j + 2..].parse().ok();
                res.host = host_port.to_string();
                return Some(res);
            }
        }
        if let Some(h) = inner.strip_suffix(']') {
            if !h.is_empty() {
                res.hostname = h.to_string();
                res.host = host_port.to_string();
                return Some(res);
            }
        }
    }
    match host_port.split_once(':') {
        Some((h, p)) if !h.is_empty() && digits(p) => {
            res.hostname = h.to_string();
            res.port = p.parse().ok();
        }
        _ => res.hostname = host_port.to_string(),
    }
    res.host = host_port.to_string();
    Some(res)
}

/// `api.parseDNS(dns)` → `(address, port)`: `[v6]:port`, bare/bracketed v6 (port 53),
/// `ipv4:port`, else `(dns, 53)`.
pub fn parse_dns(dns: &str) -> (String, String) {
    if let Some((a, p)) = ipv6_port_split(dns) {
        if dt_ip6addr(a) && dt_port(p) {
            return (a.to_string(), p.to_string());
        }
    }
    if is_ipv6(dns) {
        return (get_ipv6_only(dns), "53".into());
    }
    if let Some((h, p)) = dns.split_once(':') {
        if !h.is_empty() && !p.is_empty() && !p.contains(':') && dt_ip4addr(h) && dt_port(p) {
            return (h.to_string(), p.to_string());
        }
    }
    (dns.to_string(), "53".into())
}

/// One `server=/domain/upstream` entry of dnsmasq (see [`get_dnsmasq_server_domain`]).
#[derive(Debug, Clone, PartialEq)]
pub struct DnsmasqServer {
    pub dnsmasq_dns: String,
    pub server: String,
    pub port: Option<u32>,
}

/// `api.get_dnsmasq_server_domain()`: `dhcp.@dnsmasq[0].server` entries `/domain/.../up#port`
/// → `{domain: {dnsmasq_dns, server, port}}`.
pub fn get_dnsmasq_server_domain() -> IndexMap<String, DnsmasqServer> {
    parse_dnsmasq_servers(&Config::load("dhcp").list_raw("@dnsmasq[0]", "server"))
}
/// Pure part of [`get_dnsmasq_server_domain`].
pub fn parse_dnsmasq_servers(list: &[String]) -> IndexMap<String, DnsmasqServer> {
    let mut m = IndexMap::new();
    for v in list {
        if !v.contains('/') {
            continue;
        }
        let s = split(v, "/");
        if s.len() > 2 {
            let domain = s[1].clone();
            let up = s[s.len() - 1].clone();
            let ds = split(&up, "#");
            let (server, port) = if ds.len() > 1 { (ds[0].clone(), ds[ds.len() - 1].clone()) } else { (up.clone(), "53".to_string()) };
            m.insert(domain, DnsmasqServer { dnsmasq_dns: up, server, port: lua_tonumber(&port).map(|p| p as u32) });
        }
    }
    m
}

/// Error of [`resolve_domain`]: last nslookup output and rc.
#[derive(Debug, Clone)]
pub struct ResolveError {
    pub output: String,
    pub rc: i32,
}

/// Parse busybox nslookup output (addresses after the first `Name:` line).
pub fn parse_nslookup(out: &str) -> Vec<String> {
    let mut ips: Vec<String> = vec![];
    let mut answer = false;
    for line in out.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        let t = line.trim_start();
        if t.starts_with("Name:") {
            answer = true;
        }
        if !answer {
            continue;
        }
        if let Some(r) = t.strip_prefix("Address") {
            let r = r.trim_start().trim_start_matches(|c: char| c.is_ascii_digit()).trim_start();
            if let Some(r) = r.strip_prefix(':') {
                let ip = r.split_whitespace().next().unwrap_or("");
                if !ip.is_empty() && (dt_ip4addr(ip) || dt_ip6addr(ip)) && !ips.iter().any(|x| x == ip) {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    ips
}

/// `api.resolve_domain(domain, dns)`: resolve with busybox nslookup run as DIRECT_GID
/// (bypassing the proxy). dns default: cache `DIRECT_DNS` or `223.5.5.5`
/// (`addr#port` / `[v6]:port` / `host:port` / bare).
pub fn resolve_domain(domain: &str, dns: Option<&str>) -> Result<Vec<String>, ResolveError> {
    let dns = dns.map(|s| s.to_string()).or_else(|| get_cache_var("DIRECT_DNS")).unwrap_or_else(|| "223.5.5.5".into());
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let mut parsed: Option<(String, String)> = None;
    if let Some((a, p)) = dns.rsplit_once('#') {
        if digits(p) {
            parsed = Some((a.to_string(), p.to_string()));
        }
    }
    if parsed.is_none() && dns.starts_with('[') {
        if let Some((a, p)) = dns[1..].rsplit_once("]:") {
            if digits(p) {
                parsed = Some((a.to_string(), p.to_string()));
            }
        }
    }
    if parsed.is_none() {
        if let Some((a, p)) = dns.split_once(':') {
            if !a.is_empty() && digits(p) {
                parsed = Some((a.to_string(), p.to_string()));
            }
        }
    }
    let (mut address, port) = parsed.unwrap_or((dns.clone(), "53".into()));
    if address.starts_with('[') && address.ends_with(']') && address.len() >= 2 {
        address = address[1..address.len() - 1].to_string();
    }
    let server = if dt_ip6addr(&address) { format!("[{}]", address) } else { address.clone() };
    let mut servers = vec![format!("{}:{}", server, port), format!("{}#{}", address, port), "223.5.5.5".to_string()];
    let ver = util::sh("LC_ALL=C busybox nslookup -v 2>&1");
    if let Some(i) = ver.find("BusyBox v") {
        let v: String = ver[i + 9..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        if v.split('.').filter(|x| !x.is_empty()).count() >= 3 && compare_versions(&v, "<", "1.35.0") {
            servers.swap(0, 1);
        }
    }
    let mut last = ResolveError { output: String::new(), rc: 0 };
    for s in servers {
        let (rc, out) = exec_call_as_gid(&format!("LC_ALL=C busybox nslookup {} {}", util::shq(domain), util::shq(&s)), DIRECT_GID);
        let ips = parse_nslookup(&out);
        if !ips.is_empty() {
            return Ok(ips);
        }
        last = ResolveError { output: out, rc };
    }
    Err(last)
}

// ====================================================================== curl wrappers

/// `api.curl_base(url, file, args, gid)`: `curl <args> [-o file] '<url>'` → `(rc, output)`
/// (stdout+stderr, trimmed). `args` are shell fragments (see [`CURL_ARGS`]).
pub fn curl_base(url: &str, file: Option<&str>, args: &[String], gid: Option<u32>) -> (i32, String) {
    let mut a: Vec<String> = args.to_vec();
    if let Some(f) = file {
        a.push(format!("-o {}", util::shq(f)));
    }
    // upstream double-quotes the url; single-quote it so `$`/backticks stay literal
    let cmd = format!("curl {} {}", a.join(" "), util::shq(url));
    match gid {
        Some(g) => exec_call_as_gid(&cmd, g),
        None => exec_call(&cmd),
    }
}

/// `api.curl_proxy(url, file, args)`: through the default node's SOCKS port
/// (cache `ACL_acl_default_node_socks_port`); None when that port is unknown.
pub fn curl_proxy(url: &str, file: Option<&str>, args: &[String]) -> Option<(i32, String)> {
    let port = get_cache_var("ACL_acl_default_node_socks_port")?;
    let mut a = args.to_vec();
    a.push(format!("-x socks5h://127.0.0.1:{}", port));
    Some(curl_base(url, file, &a, None))
}

/// `api.curl_direct(url, file, args)`: bypass the proxy (`--noproxy '*'`, pre-resolved via
/// direct DNS with `--resolve`, run as DIRECT_GID) when passwall2 is active; rc 6 if the
/// domain cannot be resolved.
pub fn curl_direct(url: &str, file: Option<&str>, args: &[String]) -> (i32, String) {
    if get_cache_var("ENABLED_DEFAULT_ACL").as_deref() != Some("1") && get_cache_var("ENABLED_ACLS").as_deref() != Some("1") {
        return curl_base(url, file, args, None);
    }
    let mut a = args.to_vec();
    a.push("--noproxy '*'".into());
    if let Some((domain, port)) = get_domain_port_from_url(url) {
        match resolve_domain(&domain, None) {
            Ok(ips) => {
                let ips: Vec<String> = ips.into_iter().map(|ip| if dt_ip6addr(&ip) { format!("[{}]", ip) } else { ip }).collect();
                a.push(format!("--resolve {}", util::shq(&format!("{}:{}:{}", domain, port, ips.join(",")))));
            }
            Err(e) => return (6, e.output),
        }
    }
    curl_base(url, file, &a, Some(DIRECT_GID))
}

/// `api.curl_logic(url, file, args)`: proxy first, direct on failure.
pub fn curl_logic(url: &str, file: Option<&str>, args: &[String]) -> (i32, String) {
    match curl_proxy(url, file, args) {
        Some((0, out)) => (0, out),
        _ => curl_direct(url, file, args),
    }
}

/// `api.curl_auto(url, file, args)`: plain curl when `@global[0].localhost_proxy` (default 1)
/// is 1 (router traffic is proxied transparently anyway), else [`curl_logic`].
pub fn curl_auto(url: &str, file: Option<&str>, args: &[String]) -> (i32, String) {
    if Config::load(C_CONFIG).get("@global[0]", "localhost_proxy").unwrap_or_else(|| "1".into()) == "1" {
        return curl_base(url, file, args, None);
    }
    curl_logic(url, file, args)
}

// ====================================================================== connectivity tests (controller helpers)

/// Parse `code:time` output of `curl -w "%{http_code}:%{time_appconnect}"` / `test.sh
/// url_test_node` like the controller: code 0 → None; time with `.` (seconds) → ms
/// `"%.2f"`, else value/1000.
pub fn parse_code_time(result: &str) -> Option<String> {
    let r = echo_n(result);
    let mut it = r.split(':');
    let code = lua_tonumber(it.next().unwrap_or("")).unwrap_or(0.0);
    if code == 0.0 {
        return None;
    }
    let t = it.next().unwrap_or("").split_whitespace().next().unwrap_or("").to_string();
    // upstream errors on a non-numeric time; we report failure instead
    let v = lua_tonumber(&t)?;
    Some(if t.contains('.') { format!("{:.2}", v * 1000.0) } else { format!("{:.2}", v / 1000.0) })
}

/// Controller `connect_status`: `curl --connect-timeout 3 -o /dev/null -I -sk -w
/// "%{http_code}:%{time_appconnect}" <url>` → use_time in ms ("123.45") or None.
pub fn connect_status(url: &str) -> Option<String> {
    let out = util::cmd_out("curl", &["--connect-timeout", "3", "-o", "/dev/null", "-I", "-sk", "-w", "%{http_code}:%{time_appconnect}", url]);
    parse_code_time(&out)
}

fn extract_time_ms(out: &str) -> String {
    // grep -o 'time=[0-9]*' | awk -F '=' '{print $2}' then echo -n $(...)
    let mut v = vec![];
    let mut s = out;
    while let Some(i) = s.find("time=") {
        let r = &s[i + 5..];
        let d: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        v.push(d);
        s = r;
    }
    echo_n(&v.join("\n"))
}

/// Controller `ping_node` ICMP: `ping -c 1 -W 1 <address>` → integer ms string or "".
pub fn ping_icmp(address: &str) -> String {
    let o = Command::new("ping").args(["-c", "1", "-W", "1", address]).stdin(Stdio::null()).output();
    match o {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            extract_time_ms(&s)
        }
        Err(_) => String::new(),
    }
}

/// Controller `ping_node` tcping: `tcping -q -c 1 -i 1 -t 2 -p <port> <address>` (IPv6
/// unbracketed) → integer ms string or "".
pub fn tcping(address: &str, port: &str) -> String {
    let addr = if is_ipv6(address) { get_ipv6_only(address) } else { address.to_string() };
    let o = Command::new("tcping").args(["-q", "-c", "1", "-i", "1", "-t", "2", "-p", port, &addr]).stdin(Stdio::null()).output();
    match o {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            extract_time_ms(&s)
        }
        Err(_) => String::new(),
    }
}

/// Controller `ping_node(address, port, type)`: tcping when `type=="tcping"` and tcping is
/// installed, otherwise ICMP ping.
pub fn ping_node(address: &str, port: &str, typ: &str) -> String {
    if typ == "tcping" && which("tcping").is_some() {
        tcping(address, port)
    } else {
        ping_icmp(address)
    }
}

/// Controller `urltest_node`: `test.sh url_test_node <id> urltest_node` → use_time or None.
/// The test itself is implemented by `app` (`passwall2 test url_test_node <id> urltest_node`).
pub fn urltest_node(id: &str) -> Option<String> {
    if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return None;
    }
    parse_code_time(&util::cmd_out(util::SELF_BIN, &["test", "url_test_node", id, "urltest_node"]))
}

// ====================================================================== nodes

const SPECIAL_PROTOCOLS: [&str; 4] = ["_balancing", "_shunt", "_iface", "_urltest"];

/// `api.is_normal_node(e)`: false iff the node has a type and a special protocol
/// (`_balancing`, `_shunt`, `_iface`, `_urltest`).
pub fn is_normal_node(e: &Section) -> bool {
    !(e.has("type") && e.get("protocol").is_some_and(|p| SPECIAL_PROTOCOLS.contains(&p.as_str())))
}
/// `api.is_special_node(e)`.
pub fn is_special_node(e: &Section) -> bool {
    !is_normal_node(e)
}

/// Type display name: `sing-box` → `Sing-Box`.
pub fn type_display(t: &str) -> String {
    if t == "sing-box" { "Sing-Box".into() } else { t.to_string() }
}
/// Protocol display (Xray / sing-box nodes): vmess→VMess, vless→VLESS, ... else first
/// lowercase letter uppercased.
pub fn protocol_display(p: &str) -> String {
    match p {
        "vmess" => "VMess".into(),
        "vless" => "VLESS".into(),
        "shadowsocks" => "SS".into(),
        "shadowsocksr" => "SSR".into(),
        "wireguard" => "WG".into(),
        "hysteria" => "HY".into(),
        "hysteria2" => "HY2".into(),
        "anytls" => "AnyTLS".into(),
        "ssh" => "SSH".into(),
        o => {
            let mut c = o.chars();
            match c.next() {
                Some(f) if f.is_ascii_lowercase() => f.to_ascii_uppercase().to_string() + c.as_str(),
                _ => o.to_string(),
            }
        }
    }
}

/// `api.get_node_name(node)`: for `_balancing`/`_shunt`/`_iface` nodes
/// `"<Type> <tr(protocol)>：[<remarks>] "` (trailing space); "" otherwise.
pub fn get_node_name(e: &Section) -> String {
    let (Some(t), Some(r)) = (e.get("type"), e.get("remarks")) else { return String::new() };
    match e.get("protocol") {
        Some(p) if p == "_balancing" || p == "_shunt" || p == "_iface" => format!("{} {}：[{}] ", type_display(&t), translate(&p), r),
        _ => String::new(),
    }
}
/// [`get_node_name`] by node id.
pub fn get_node_name_by_id(cfg: &Config, id: &str) -> String {
    cfg.section(id).map(get_node_name).unwrap_or_default()
}

/// One entry of [`get_valid_nodes`].
#[derive(Debug, Clone)]
pub struct ValidNode {
    pub section: Section,
    /// display remark (`Xray VLESS：[name]` ...)
    pub remark: String,
    /// "special" or "normal"
    pub node_type: String,
}
impl ValidNode {
    pub fn id(&self) -> &str {
        &self.section.name
    }
    /// Node as LuCI-like JSON (`.name`, options, plus `id`, `remark`, `node_type`).
    pub fn to_json(&self) -> Value {
        let mut v = self.section.to_json();
        if let Value::Object(m) = &mut v {
            m.insert("id".into(), self.section.name.clone().into());
            m.insert("remark".into(), self.remark.clone().into());
            m.insert("node_type".into(), self.node_type.clone().into());
        }
        v
    }
}

/// `api.get_valid_nodes()`: nodes with `type` and `remarks`, ungrouped first then grouped
/// (UCI order inside), with display remarks; special nodes and normal nodes whose address is
/// an IP/hostname (or Hysteria2 realm). `show_node_info=1` appends ` addr:port`.
pub fn get_valid_nodes(cfg: &Config) -> Vec<ValidNode> {
    let show_info = cfg.get("@global_other[0]", "show_node_info").unwrap_or_else(|| "0".into()) == "1";
    let mut default_nodes = vec![];
    let mut other_nodes = vec![];
    for e in cfg.sections_of("nodes") {
        let (Some(t), Some(remarks)) = (e.get("type"), e.get("remarks")) else { continue };
        let tn = type_display(&t);
        let proto = e.get("protocol");
        let grouped = e.get("group").is_some_and(|g| !g.is_empty());
        let mut entries: Vec<(String, &str)> = vec![];
        if let Some(p) = proto.as_deref().filter(|p| SPECIAL_PROTOCOLS.contains(p)) {
            entries.push((trim(&format!("{} {}：[{}]", tn, translate(p), remarks)), "special"));
        }
        let port = e.get("port").or_else(|| e.get("hysteria_hop")).or_else(|| e.get("hysteria2_hop"));
        let is_realm = proto.as_deref() == Some("hysteria2") && e.get("hysteria2_realms").is_some();
        let address = e.get("address");
        if (port.is_some() && address.is_some()) || is_realm {
            let mut addr = address.clone().unwrap_or_default();
            if is_ip(&addr) || dt_hostname(&addr) || is_realm {
                let mut type_name = tn.clone();
                if (t == "sing-box" || t == "Xray") && proto.is_some() {
                    type_name = format!("{} {}", type_name, protocol_display(proto.as_deref().unwrap_or("")));
                }
                if is_ipv6(&addr) {
                    addr = get_ipv6_full(&addr);
                }
                if is_realm {
                    type_name.push_str(" Realm");
                }
                let mut remark = trim(&format!("{}：[{}]", type_name, remarks));
                if show_info && !is_realm {
                    let p = port.clone().unwrap_or_default().replace(':', "-");
                    remark = trim(&format!("{}：[{}] {}:{}", type_name, remarks, addr, p));
                }
                // upstream mutates the same table: an earlier "special" entry becomes "normal" too
                for en in entries.iter_mut() {
                    *en = (remark.clone(), "normal");
                }
                entries.push((remark, "normal"));
            }
        }
        for (remark, nt) in entries {
            let vn = ValidNode { section: e.clone(), remark, node_type: nt.to_string() };
            if grouped {
                other_nodes.push(vn);
            } else {
                default_nodes.push(vn);
            }
        }
    }
    default_nodes.extend(other_nodes);
    default_nodes
}

/// `api.get_node_list()` as JSON: `{socks_list, normal_list, <proto>_list...}` (see spec 05
/// §1.9); `<proto>_list` entries carry the full node as `o`.
pub fn get_node_list(cfg: &Config) -> Value {
    let mut m = serde_json::Map::new();
    let mut socks = vec![];
    for s in cfg.sections_of("socks") {
        if s.has("node") {
            socks.push(json!({
                "id": s.name,
                "remark": format!("{} [{}{}]", translate("Socks Config"), s.s("port"), translate("Port")),
                "group": "Socks"
            }));
        }
    }
    m.insert("socks_list".into(), Value::Array(socks));
    m.insert("normal_list".into(), Value::Array(vec![]));
    for e in get_valid_nodes(cfg) {
        if e.node_type == "normal" {
            let mut o = serde_json::Map::new();
            o.insert("id".into(), e.section.name.clone().into());
            o.insert("remark".into(), e.remark.clone().into());
            for k in ["type", "chain_proxy", "group"] {
                if let Some(v) = e.section.get(k) {
                    o.insert(k.into(), v.into());
                }
            }
            if let Some(Value::Array(a)) = m.get_mut("normal_list") {
                a.push(Value::Object(o));
            }
        }
        if let Some(p) = e.section.get("protocol").filter(|p| p.starts_with('_')) {
            let key = format!("{}_list", &p[1..]);
            let mut o = serde_json::Map::new();
            o.insert("id".into(), e.section.name.clone().into());
            o.insert("remark".into(), e.remark.clone().into());
            if let Some(g) = e.section.get("group") {
                o.insert("group".into(), g.into());
            }
            o.insert("o".into(), e.to_json());
            let entry = m.entry(key).or_insert_with(|| Value::Array(vec![]));
            if let Value::Array(a) = entry {
                a.push(Value::Object(o));
            }
        }
    }
    Value::Object(m)
}

/// `api.get_node_remarks(n)`: display remark without address info / validation.
pub fn get_node_remarks(n: &Section) -> String {
    let t = n.s("type");
    let mut type_name = type_display(&t);
    let remarks = n.s("remarks");
    let proto = n.get("protocol");
    if let Some(p) = proto.as_deref().filter(|p| SPECIAL_PROTOCOLS.contains(p)) {
        return trim(&format!("{} {}：[{}]", type_name, translate(p), remarks));
    }
    if (t == "sing-box" || t == "Xray") && proto.is_some() {
        type_name = format!("{} {}", type_name, protocol_display(proto.as_deref().unwrap_or("")));
    }
    if proto.as_deref() == Some("hysteria2") && n.get("hysteria2_realms").is_some() {
        type_name.push_str(" Realm");
    }
    trim(&format!("{}：[{}]", type_name, remarks))
}
/// `api.get_full_node_remarks(n)`: remarks + ` <address>:<port with ':'→'-'>`.
pub fn get_full_node_remarks(n: &Section) -> String {
    let mut r = get_node_remarks(n);
    if !r.is_empty() {
        let port = n.get("port").or_else(|| n.get("hysteria_hop")).or_else(|| n.get("hysteria2_hop"));
        if let (Some(a), Some(p)) = (n.get("address"), port) {
            r = format!("{} {}:{}", r, a, p.replace(':', "-"));
        }
    }
    r
}

fn rand_u64() -> u64 {
    use std::io::Read;
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok() {
        return u64::from_le_bytes(b);
    }
    util::epoch() ^ std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0)
}

/// `api.get_random_normal_node(exclude)`: random normal valid node not in `exclude`.
pub fn get_random_normal_node(cfg: &Config, exclude: &[String]) -> Option<ValidNode> {
    let list: Vec<ValidNode> = get_valid_nodes(cfg).into_iter().filter(|e| e.node_type == "normal" && !exclude.contains(&e.section.name)).collect();
    if list.is_empty() {
        return None;
    }
    let i = (rand_u64() % list.len() as u64) as usize;
    list.into_iter().nth(i)
}

/// `api.match_node_rule(name, rule)`: `||` = OR groups, `&&` = AND; conditions `!k` (not
/// contains), `^k` (prefix), `k$` (suffix), else contains. Empty rule matches everything.
pub fn match_node_rule(name: &str, rule: Option<&str>) -> bool {
    let Some(rule) = rule.filter(|r| !r.is_empty()) else { return true };
    fn cond(s: &str, c: &str) -> bool {
        if c.is_empty() {
            return true;
        }
        if let Some(k) = c.strip_prefix('!') {
            return k.is_empty() || !s.contains(k);
        }
        if let Some(k) = c.strip_prefix('^') {
            return s.as_bytes().starts_with(k.as_bytes());
        }
        if let Some(k) = c.strip_suffix('$') {
            // Lua str:sub(-0) is the whole string
            return if k.is_empty() { s.is_empty() } else { s.as_bytes().ends_with(k.as_bytes()) };
        }
        s.contains(c)
    }
    rule.split("||")
        .map(trim)
        .filter(|g| !g.is_empty())
        .any(|g| g.split("&&").map(trim).filter(|c| !c.is_empty()).all(|c| cond(name, &c)))
}

/// `api.get_batch_nodes({node_group, node_match_rule})`: ids of normal nodes without
/// `chain_proxy` whose group (default `default`, case-insensitive, url-decoded tokens of the
/// space-separated `node_group`) matches and whose remarks match `node_match_rule`.
pub fn get_batch_nodes(cfg: &Config, node_group: Option<&str>, node_match_rule: Option<&str>) -> Vec<String> {
    let Some(groups) = node_group.filter(|g| !g.is_empty()) else { return vec![] };
    let normal: Vec<(String, String, String)> = get_valid_nodes(cfg)
        .into_iter()
        .filter(|e| e.node_type == "normal" && e.section.get("chain_proxy").is_none_or(|c| c.is_empty()))
        .map(|e| {
            let g = e.section.get("group").filter(|g| !g.is_empty()).unwrap_or_else(|| "default".into());
            (e.section.name.clone(), e.section.s("remarks"), g)
        })
        .collect();
    let mut out = vec![];
    for g in groups.split_whitespace() {
        let g = url_decode(g).to_lowercase();
        for (id, remarks, gn) in &normal {
            if gn.to_lowercase() == g && match_node_rule(remarks, node_match_rule) {
                out.push(id.clone());
            }
        }
    }
    out
}

/// `api.get_socks_backup_nodes(id)`: space-joined backup node ids of a `socks` section
/// (batch mode via [`get_batch_nodes`] or the `autoswitch_backup_node` list), without the
/// current `node`, deduplicated.
pub fn get_socks_backup_nodes(cfg: &Config, id: &str) -> String {
    let id = trim(id);
    if id.is_empty() {
        return String::new();
    }
    let Some(socks) = cfg.section(&id) else { return String::new() };
    let nodes = if socks.get("backup_node_add_mode").as_deref() == Some("batch") {
        get_batch_nodes(cfg, socks.get("backup_node_group").as_deref(), socks.get("backup_node_match_rule").as_deref())
    } else {
        socks.list_raw("autoswitch_backup_node")
    };
    let cur = socks.get("node");
    let mut out: Vec<String> = vec![];
    for v in nodes {
        if Some(&v) != cur.as_ref() && !out.contains(&v) {
            out.push(v);
        }
    }
    out.join(" ")
}

/// `api.get_core(field, candidates)`: `@global_subscribe[0].<field>` if it names an
/// available candidate, else the first available candidate.
pub fn get_core(cfg: &Config, field: &str, candidates: &[(bool, &str)]) -> Option<String> {
    if let Some(v) = cfg.get("@global_subscribe[0]", field).filter(|v| !v.is_empty()) {
        if candidates.iter().any(|(ok, n)| *ok && *n == v) {
            return Some(v);
        }
    }
    candidates.iter().find(|(ok, _)| *ok).map(|(_, n)| n.to_string())
}

/// Result of [`parse_realm_uri`].
#[derive(Debug, Clone, PartialEq)]
pub struct RealmUri {
    /// "realm" or "realm+http"
    pub scheme: String,
    pub token: String,
    pub server_url: String,
    pub address: String,
    pub port: u32,
    pub realm_id: String,
    pub stun_servers: Option<Vec<String>>,
}

/// `api.parse_realm_uri(uri)`: `realm[+http]://token@server/realm_id?stun=...`.
pub fn parse_realm_uri(uri: &str) -> Option<RealmUri> {
    let uri = trim(uri);
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("realm+http://") {
        ("realm+http", r)
    } else {
        ("realm", uri.strip_prefix("realm://")?)
    };
    let at = rest.find('@')?;
    if at == 0 {
        return None;
    }
    let token = &rest[..at];
    let after = &rest[at + 1..];
    let slash = after.find('/')?;
    if slash == 0 {
        return None;
    }
    let server_url = &after[..slash];
    let tail = &after[slash + 1..];
    let (realm_id, query) = match tail.find('?') {
        Some(q) => (&tail[..q], &tail[q + 1..]),
        None => (tail, ""),
    };
    let realm_id = realm_id.trim_end_matches('/');
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let mut address: Option<String> = None;
    let mut port: Option<String> = None;
    if let Some(inner) = server_url.strip_prefix('[') {
        if let Some((a, p)) = inner.split_once("]:") {
            if !a.is_empty() && !a.contains(']') && digits(p) {
                address = Some(a.into());
                port = Some(p.into());
            }
        }
    }
    if address.is_none() {
        if let Some((a, p)) = server_url.split_once(':') {
            if !a.is_empty() && digits(p) {
                address = Some(a.into());
                port = Some(p.into());
            }
        }
    }
    let address = address.unwrap_or_else(|| {
        server_url
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .filter(|x| !x.is_empty() && !x.contains(']'))
            .unwrap_or(server_url)
            .to_string()
    });
    let port = port.and_then(|p| p.parse().ok()).unwrap_or(if scheme == "realm+http" { 80 } else { 443 });
    let mut stun: Option<Vec<String>> = None;
    let lq = query.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lq[from..].find("stun=") {
        let st = from + i + 5;
        let v: String = query[st..].chars().take_while(|c| *c != '&').collect();
        if !v.is_empty() {
            stun.get_or_insert_with(Vec::new).push(v.clone());
            from = st + v.len();
        } else {
            from = from + i + 1;
        }
    }
    Some(RealmUri {
        scheme: scheme.into(),
        token: token.into(),
        server_url: server_url.into(),
        address,
        port,
        realm_id: realm_id.into(),
        stun_servers: stun,
    })
}

/// One entry of [`get_network_devices`].
#[derive(Debug, Clone, PartialEq)]
pub struct NetDevice {
    pub name: String,
    pub label: String,
    pub sort: String,
}

/// `api.get_network_devices()`: kernel devices from `/sys/class/net` (no lo/veth/ifb/gre/
/// sit/ip6tnl/erspan, no bridge ports / DSA masters) labelled by type plus offline UCI
/// interfaces; sorted by `sort`.
pub fn get_network_devices() -> Vec<NetDevice> {
    let net = Config::load("network");
    let sysnet = "/sys/class/net/";
    let mut iface_to_dev: Vec<(String, String)> = vec![];
    let mut dev_to_ifaces: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut iface_proto: IndexMap<String, Option<String>> = IndexMap::new();
    for s in net.sections_of("interface") {
        if s.name == "loopback" {
            continue;
        }
        iface_proto.insert(s.name.clone(), s.get("proto"));
        if let Some(d) = s.get("device") {
            iface_to_dev.push((s.name.clone(), d.clone()));
            dev_to_ifaces.entry(d).or_default().push(s.name.clone());
        }
    }
    let is_dir = |p: String| std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false);
    let mut seen: Vec<String> = vec![];
    let mut devs = vec![];
    let mut names: Vec<String> = std::fs::read_dir(sysnet).map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
    names.sort();
    for dev in names {
        if dev == "lo" || ["veth", "ifb", "gre", "sit", "ip6tnl", "erspan"].iter().any(|p| dev.starts_with(p)) {
            continue;
        }
        if std::fs::symlink_metadata(format!("{}{}/master", sysnet, dev)).is_ok() || std::fs::symlink_metadata(format!("{}{}/dsa", sysnet, dev)).is_ok() {
            continue;
        }
        let dtype = if is_dir(format!("{}{}/bridge", sysnet, dev)) {
            translate("Bridge")
        } else if is_dir(format!("{}{}/wireless", sysnet, dev)) {
            translate("Wireless Adapter")
        } else if ["tun", "tap", "wg", "ppp"].iter().any(|p| dev.starts_with(p)) {
            translate("Tunnel Interface")
        } else {
            translate("Ethernet Adapter")
        };
        let mut label = format!("{}: \"{}\"", dtype, dev);
        if let Some(i) = dev_to_ifaces.get(&dev) {
            label = format!("{} ({})", label, i.join(", "));
        }
        devs.push(NetDevice { name: dev.clone(), label, sort: format!("{}:{}", dtype, dev) });
        seen.push(dev);
    }
    for (iface, dev) in iface_to_dev {
        if seen.contains(&dev) {
            continue;
        }
        let proto = iface_proto.get(&iface).cloned().flatten().unwrap_or_default();
        let dtype = if dev.starts_with("br-") {
            translate("Bridge")
        } else if ["wireguard", "pppoe", "pptp", "l2tp"].contains(&proto.as_str()) {
            translate("Tunnel Interface")
        } else {
            translate("Interface")
        };
        devs.push(NetDevice { label: format!("{}: \"{}\"", dtype, iface), sort: format!("zzz:{}", iface), name: iface });
        seen.push(dev);
    }
    devs.sort_by(|a, b| a.sort.cmp(&b.sort));
    devs
}

// ====================================================================== components (com.lua)

/// Component descriptor (`luci.passwall2.com`).
#[derive(Debug)]
pub struct Com {
    pub key: &'static str,
    pub name: &'static str,
    pub repo: Option<&'static str>,
    /// true → `-pre-release-api.json` (xray)
    pub pre_release: bool,
    pub cmd_version: Option<&'static str>,
    pub zipped: bool,
    pub zipped_suffix: Option<&'static str>,
    pub default_path: Option<&'static str>,
    /// Lua pattern format (after `%%`→`%`): `linux%-{}`
    pub match_fmt_str: Option<&'static str>,
    pub file_tree: &'static [(&'static str, &'static str)],
}
impl Com {
    /// `com[app]:get_url()`.
    pub fn get_url(&self) -> String {
        format!(
            "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/{}-{}release-api.json",
            self.name.to_lowercase(),
            if self.pre_release { "pre-" } else { "" }
        )
    }
}

/// `com.order`.
pub const COM_ORDER: [&str; 3] = ["geoview", "xray", "sing-box"];

static COMS: [Com; 4] = [
    Com { key: "passwall2", name: "PassWall2", repo: None, pre_release: false, cmd_version: None, zipped: false, zipped_suffix: None, default_path: None, match_fmt_str: None, file_tree: &[] },
    Com {
        key: "sing-box",
        name: "Sing-Box",
        repo: Some("SagerNet/sing-box"),
        pre_release: false,
        cmd_version: Some("version"),
        zipped: true,
        zipped_suffix: Some("tar.gz"),
        default_path: Some("/usr/bin/sing-box"),
        match_fmt_str: Some("linux%-{}"),
        file_tree: &[
            ("x86_64", "amd64%-musl"),
            ("x86", "386%-musl"),
            ("aarch64", "arm64%-musl"),
            ("rockchip", "arm64%-musl"),
            ("mips", "mips%-softfloat"),
            ("mips64", "mips64%-softfloat"),
            ("mipsel", "mipsle%-softfloat%-musl"),
            ("mips64el", "mips64le%-softfloat"),
            ("armv7", "armv7%-musl"),
            ("armv8", "arm64%-musl"),
            ("riscv64", "riscv64%-musl"),
        ],
    },
    Com {
        key: "xray",
        name: "Xray",
        repo: Some("XTLS/Xray-core"),
        pre_release: true,
        cmd_version: Some("version | awk '{print $2}' | sed -n 1P"),
        zipped: true,
        zipped_suffix: None,
        default_path: Some("/usr/bin/xray"),
        match_fmt_str: Some("linux%-{}"),
        file_tree: &[("x86_64", "64"), ("x86", "32"), ("mips", "mips32"), ("mipsel", "mips32le"), ("mips64el", "mips64le")],
    },
    Com {
        key: "geoview",
        name: "Geoview",
        repo: Some("snowie2000/geoview"),
        pre_release: false,
        cmd_version: Some("-version 2>/dev/null | awk 'NR==1 && $1==\"Geoview\" {print $2}'"),
        zipped: false,
        zipped_suffix: None,
        default_path: Some("/usr/bin/geoview"),
        match_fmt_str: Some("linux%-{}"),
        file_tree: &[("mipsel", "mipsle"), ("mips64el", "mips64le")],
    },
];

const DEFAULT_FILE_TREE: [(&str, &str); 13] = [
    ("x86_64", "amd64"),
    ("x86", "386"),
    ("aarch64", "arm64"),
    ("rockchip", "arm64"),
    ("mips", "mips"),
    ("mips64", "mips64"),
    ("mipsel", "mipsel"),
    ("mips64el", "mips64el"),
    ("armv5", "arm.*5"),
    ("armv6", "arm.*6[^4]*"),
    ("armv7", "arm.*7"),
    ("armv8", "arm64"),
    ("riscv64", "riscv64"),
];

/// `com[app]` descriptor (`passwall2`, `xray`, `sing-box`, `geoview`).
pub fn com(app: &str) -> Option<&'static Com> {
    COMS.iter().find(|c| c.key == app)
}

/// `api.get_app_path(app)`: `@global_app[0].<app with -→_>_file` or the default path.
pub fn get_app_path(app: &str) -> Option<String> {
    let c = com(app)?;
    let def = c.default_path.map(|s| s.to_string());
    match Config::load(C_CONFIG).get("@global_app[0]", &format!("{}_file", app.replace('-', "_"))) {
        Some(p) if !p.is_empty() => Some(p),
        _ => def,
    }
}

/// Binary version cache (`get_bin_version_cache`): `(version, tags)`; tags only in sing-box
/// mode. Cached in `/tmp/etc/passwall2_tmp/binver_<dev>_<ino>_<size>_<mtime>_<ctime>`.
fn get_bin_version_cache(file: &str, cmd: &str, sb_tags: bool) -> (String, String) {
    if file.is_empty() || !util::exists(file) {
        return (String::new(), String::new());
    }
    chmod_755(file);
    let cache_file = std::fs::metadata(file)
        .ok()
        .map(|m| format!("{}/binver_{}_{}_{}_{}_{}", CACHE_PATH, m.dev(), m.ino(), m.size(), m.mtime(), m.ctime()));
    if let Some(cf) = &cache_file {
        let cached = util::read(cf);
        let mut l = cached.split('\n');
        let v = trim(l.next().unwrap_or(""));
        if !v.is_empty() {
            return (v, if sb_tags { trim(l.next().unwrap_or("")) } else { String::new() });
        }
    }
    let (version, tags) = if sb_tags {
        let out = util::sh(&format!("{} {}", util::shq(file), cmd));
        let mut ver = String::new();
        let mut w = out.split_whitespace();
        if out.starts_with("sing-box") && w.next() == Some("sing-box") && w.next() == Some("version") {
            ver = w.next().unwrap_or("").to_string();
        }
        let tags = out.find("\nTags:").map(|i| out[i + 6..].trim_start_matches([' ', '\t']).split(['\r', '\n']).next().unwrap_or("").to_string()).unwrap_or_default();
        (ver, trim(&tags))
    } else {
        (echo_n(&util::sh(&format!("{} {}", util::shq(file), cmd))), String::new())
    };
    if !version.is_empty() {
        if let Some(cf) = cache_file {
            util::mkdir(CACHE_PATH);
            let _ = std::fs::write(cf, if sb_tags { format!("{}\n{}\n", version, tags) } else { version.clone() });
        }
    }
    (version, tags)
}

/// `api.get_app_version(app, file?)`: installed version of a component binary ("" if none).
pub fn get_app_version(app: &str, file: Option<&str>) -> String {
    let Some(c) = com(app) else { return String::new() };
    let f = match file {
        Some(f) => f.to_string(),
        None => get_app_path(app).unwrap_or_default(),
    };
    get_bin_version_cache(&f, c.cmd_version.unwrap_or(""), app == "sing-box").0
}

/// `api.get_singbox_tags()`: build tags of the sing-box binary (`with_gvisor,...`) or "".
pub fn get_singbox_tags() -> String {
    let f = get_app_path("sing-box").unwrap_or_default();
    get_bin_version_cache(&f, "version", true).1
}

fn release_value(file: &str, key: &str) -> Option<String> {
    let text = util::read(file);
    let mut vals = vec![];
    for l in text.lines().filter(|l| l.contains(key)) {
        // awk -F '["\']' '{print $2}'
        vals.push(l.split(['"', '\'']).nth(1).unwrap_or("").to_string());
    }
    let v = echo_n(&vals.join(" "));
    if v.is_empty() { None } else { Some(v) }
}

/// `auto_get_arch()` with explicit inputs (pure, for tests).
pub fn arch_from(machine: &str, openwrt_arch: Option<&str>, distrib_arch: Option<&str>) -> String {
    let mut arch = machine.to_string();
    let b = arch.as_bytes();
    if b.len() == 4 && b[0] == b'i' && b[1].is_ascii_digit() && &arch[2..] == "86" {
        arch = "x86".into();
    } else if arch.contains("armv5") {
        arch = "armv5".into();
    } else if arch.contains("armv6") {
        arch = "armv6".into();
    } else if arch.contains("armv7") {
        arch = "armv7".into();
    }
    if openwrt_arch.is_some() || distrib_arch.is_some() {
        if arch == "mips" {
            if openwrt_arch.is_some_and(|a| a.contains("mipsel")) || distrib_arch.is_some_and(|a| a.contains("mipsel")) {
                arch = "mipsel".into();
            }
        } else if arch == "armv7" {
            let no_fp = |a: &str| !a.contains("vfp") && !a.contains("neon");
            if openwrt_arch.is_some_and(no_fp) || distrib_arch.is_some_and(no_fp) {
                arch = "armv5".into();
            }
        }
    }
    trim(&arch)
}

/// `auto_get_arch()`: updater architecture key (x86_64, aarch64, armv7, mipsel, ...).
pub fn auto_get_arch() -> String {
    static A: OnceLock<(Option<String>, Option<String>)> = OnceLock::new();
    let (o, d) = A.get_or_init(|| (release_value("/usr/lib/os-release", "OPENWRT_ARCH"), release_value("/etc/openwrt_release", "DISTRIB_ARCH")));
    arch_from(trim(&util::cmd_out("uname", &["-m"])).as_str(), o.as_deref(), d.as_deref())
}

/// `api.get_api_json(url)`: fetch JSON (via `gh_proxy_url` + curl_direct, or curl_auto);
/// `{}` on any failure.
pub fn get_api_json(url: &str) -> Value {
    let gh = Config::load(C_CONFIG).get("@global_app[0]", "gh_proxy_url").unwrap_or_default();
    let (rc, content) = if !gh.is_empty() { curl_direct(&format!("{}{}", gh, url), None, &curl_args()) } else { curl_auto(url, None, &curl_args()) };
    if rc != 0 || content.is_empty() {
        return json!({});
    }
    serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
}

fn err(msg: String) -> Value {
    json!({"code": 1, "error": msg})
}

fn check_path(app: &str) -> Result<String, Value> {
    match get_app_path(app).filter(|p| !p.is_empty()) {
        Some(p) => Ok(p),
        None => Err(err(translatef("You did not fill in the %s path. Please save and apply then update manually.", &[app]))),
    }
}

fn cache_update_digests(app: &str, assets: &[&Value]) {
    let mut d = serde_json::Map::new();
    for a in assets {
        if let (Some(u), Some(dg)) = (a["browser_download_url"].as_str(), a["digest"].as_str()) {
            d.insert(u.to_string(), dg.into());
        }
    }
    util::mkdir(CACHE_PATH);
    let _ = std::fs::write(format!("{}/update_{}.json", CACHE_PATH, app), Value::Object(d).to_string());
}

/// Lua `s:match("[^v]+")`: first run of non-`v` chars ("" if none).
fn strip_v(s: &str) -> String {
    s.trim_start_matches('v').split('v').next().unwrap_or("").to_string()
}

/// `api.to_check(arch, app)`: compare the installed component with the latest GitHub release;
/// `{code, has_update, local_version, remote_version, html_url, data=<asset>}` or
/// `{code:1, error}`.
pub fn to_check(arch: Option<&str>, app: &str) -> Value {
    let Some(c) = com(app) else { return err(translatef("You did not fill in the %s path. Please save and apply then update manually.", &[app])) };
    if let Err(e) = check_path(app) {
        return e;
    }
    let arch = arch.filter(|a| !a.is_empty()).map(|a| a.to_string()).unwrap_or_else(auto_get_arch);
    let tree = c.file_tree.iter().chain(DEFAULT_FILE_TREE.iter()).find(|(k, _)| *k == arch).map(|(_, v)| *v).unwrap_or("");
    if tree.is_empty() {
        return err(translate("Can't determine ARCH, or ARCH not supported."));
    }
    let local_version = get_app_version(app, None);
    let pattern = c.match_fmt_str.unwrap_or("{}").replace("{}", tree);
    let mut j = get_api_json(&c.get_url());
    if let Value::Array(a) = &j {
        j = a.first().cloned().unwrap_or(Value::Null);
    }
    let Some(tag) = j["tag_name"].as_str().map(|s| s.to_string()) else {
        return err(translate("Get remote version info failed."));
    };
    let remote_version = tag;
    let has_update = compare_versions(&strip_v(&local_version), "<", &strip_v(&remote_version));
    let asset = j["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|v| v["name"].as_str().is_some_and(|n| lua_find(n, &pattern))))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let html_url = j["html_url"].clone();
    if asset["browser_download_url"].is_null() {
        return json!({
            "code": 1, "local_version": local_version, "remote_version": remote_version, "html_url": html_url,
            "data": asset, "error": translate("New version found, but failed to get new version download url.")
        });
    }
    cache_update_digests(app, &[&asset]);
    json!({"code": 0, "has_update": has_update, "local_version": local_version, "remote_version": remote_version, "html_url": html_url, "data": asset})
}

fn valid_task_id(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// `api.to_download(app, url, size, task_id, keep_files)`: download a release asset
/// (verified against the digest cached by `to_check`/`to_check_self`) into
/// `/tmp/<app>_download.<task_id>` → `{code:0, file, zip}` or `{code:1, error}`.
pub fn to_download(app: &str, url: &str, size: Option<&str>, task_id: Option<&str>, keep_files: bool) -> Value {
    let Some(c) = com(app) else { return err(translate("Invalid download task.")) };
    if app != APPNAME {
        if let Err(e) = check_path(app) {
            return e;
        }
    }
    if url.is_empty() {
        return err(translate("Download url is required."));
    }
    let digests: Value = serde_json::from_str(&util::read(&format!("{}/update_{}.json", CACHE_PATH, app))).unwrap_or(json!({}));
    let Some(digest) = digests[url].as_str().map(|s| s.to_string()) else {
        return err(translate("File verification failed."));
    };
    if !keep_files {
        util::sh_ok(&format!("/bin/rm -f /tmp/{}_download.*", app));
    }
    let tmp_file = match task_id.filter(|t| valid_task_id(t)) {
        Some(t) => {
            let f = format!("/tmp/{}_download.{}", app, t);
            let _ = std::fs::remove_file(&f);
            f
        }
        None => trim(&util::cmd_out("mktemp", &["-u", "-t", &format!("{}_download.XXXXXX", app)])),
    };
    if let Some(sz) = size.and_then(lua_tonumber) {
        if sz > get_free_space("/tmp") as f64 {
            return err(translatef("%s not enough space.", &["/tmp"]));
        }
    }
    let mut args = curl_args();
    args.push("--speed-limit 51200 --speed-time 15 --max-time 300".into());
    let gh = Config::load(C_CONFIG).get("@global_app[0]", "gh_proxy_url").unwrap_or_default();
    let full_url = format!("{}{}", gh, url);
    let (rc, _) = if !gh.is_empty() { curl_direct(&full_url, Some(&tmp_file), &args) } else { curl_auto(url, Some(&tmp_file), &args) };
    if rc != 0 {
        let _ = std::fs::remove_file(&tmp_file);
        return err(translatef("File download failed or timed out: %s", &[&full_url]));
    }
    if !verify_sha256(&tmp_file, &digest) {
        let _ = std::fs::remove_file(&tmp_file);
        return err(translate("File verification failed."));
    }
    json!({"code": 0, "file": tmp_file, "zip": c.zipped})
}

/// `api.to_download_progress(app, task_id, total_size)` → `{code:0, downloaded, total,
/// percent?}` (percent ≤ 99; passwall2 sums parts 1..5).
pub fn to_download_progress(app: &str, task_id: &str, total_size: Option<&str>) -> Value {
    if com(app).is_none() || !valid_task_id(task_id) {
        return err(translate("Invalid download task."));
    }
    let total = total_size.and_then(lua_tonumber).unwrap_or(0.0);
    let tmp = format!("/tmp/{}_download.{}", app, task_id);
    let size = |p: &str| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let downloaded: u64 = if app == APPNAME { (1..=5).map(|i| size(&format!("{}{}", tmp, i))).sum() } else { size(&tmp) };
    let mut r = json!({"code": 0, "downloaded": downloaded, "total": total_json(total)});
    if total > 0.0 {
        r["percent"] = json!(((downloaded as f64 * 100.0 / total).floor() as u64).min(99));
    }
    r
}
fn total_json(t: f64) -> Value {
    if t.fract() == 0.0 && t.abs() < 9.0e15 { json!(t as i64) } else { json!(t) }
}

/// `api.to_extract(app, file, subfix)`: extract the downloaded archive into
/// `/tmp/<app>_extract.XXXXXX` → `{code:0, file:<dir>}`.
pub fn to_extract(app: &str, file: &str) -> Value {
    let Some(c) = com(app) else { return err(translate("File path required.")) };
    if let Err(e) = check_path(app) {
        return e;
    }
    if file.is_empty() || !util::exists(file) {
        return err(translate("File path required."));
    }
    let mut tool: Option<&str> = None;
    if c.zipped {
        if c.zipped_suffix.is_none() || c.zipped_suffix == Some("zip") {
            tool = Some("unzip");
        }
        if c.zipped_suffix == Some("tar.gz") {
            tool = Some("tar");
        }
        if let Some(t) = tool {
            if which(t).is_none() {
                let _ = std::fs::remove_file(file);
                return err(translatef("Not installed %s, Can't unzip!", &[t]));
            }
        }
    }
    util::sh_ok(&format!("/bin/rm -rf /tmp/{}_extract.*", app));
    let new_size = get_file_space(file);
    let free = get_free_space("/tmp");
    if free == 0 || free <= new_size {
        return err(translatef("%s not enough space.", &["/tmp"]));
    }
    let tmp_dir = trim(&util::cmd_out("mktemp", &["-d", "-t", &format!("{}_extract.XXXXXX", app)]));
    match tool {
        Some("unzip") => {
            let bin = which("unzip").unwrap_or_else(|| "unzip".into());
            exec(&bin, &["-o", file, app, "-d", &tmp_dir], None);
        }
        Some("tar") => {
            let bin = which("tar").unwrap_or_else(|| "tar".into());
            exec(&bin, &["-zxf", file, "-C", &tmp_dir], None);
            util::sh_ok(&format!("/bin/mv -f {}/*/{} {}", util::shq(&tmp_dir), c.name.to_lowercase(), util::shq(&tmp_dir)));
        }
        _ => {}
    }
    let _ = std::fs::remove_file(file);
    json!({"code": 0, "file": tmp_dir})
}

/// `api.to_move(app, file)`: install the new binary (file, or `<dir>/<name>` when `file` is
/// the extract dir) to the app path; stops/restarts passwall2 if it runs the component.
pub fn to_move(app: &str, file: &str) -> Value {
    let Some(c) = com(app) else { return err(translate("Client file is required.")) };
    let app_path = match check_path(app) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut bin_path = file.to_string();
    let mut rm_tmp = format!("/bin/rm -rf /tmp/{}_download.*", app);
    if !file.is_empty() && std::fs::metadata(file).map(|m| m.is_dir()).unwrap_or(false) {
        bin_path = format!("{}/{}", file, c.name.to_lowercase());
        rm_tmp = format!("/bin/rm -rf /tmp/{}_extract.*", app);
    }
    if file.is_empty() {
        util::sh_ok(&rm_tmp);
        return err(translate("Client file is required."));
    }
    let new_version = get_app_version(app, Some(&bin_path));
    if new_version.is_empty() {
        util::sh_ok(&rm_tmp);
        return err(format!("{}{}__{}", translate("The client file is not suitable for current device."), app, bin_path));
    }
    let old_size = if util::exists(&app_path) { get_file_space(&app_path) } else { 0 };
    let new_size = get_file_space(&bin_path);
    let final_dir = get_final_dir(&app_path);
    let mut free = get_free_space(&final_dir);
    if free > 0 {
        free += old_size;
        if new_size > free {
            util::sh_ok(&rm_tmp);
            return err(translatef("%s not enough space.", &[&final_dir]));
        }
    }
    let running = util::sh_ok(&format!("busybox pgrep -af {} >/dev/null", util::shq(&format!("passwall2/.*{}", app))));
    if running {
        util::sh_ok("/etc/init.d/passwall2 stop");
    }
    let ok = exec("/bin/mv", &["-f", &bin_path, &app_path], Some(COMMAND_TIMEOUT)) == Some(0);
    util::sh_ok(&rm_tmp);
    if running {
        util::sh_ok("/etc/init.d/passwall2 restart >/dev/null 2>&1 &");
    }
    if !ok || !util::exists(&app_path) {
        return err(translatef("Can't move new file to path: %s", &[&app_path]));
    }
    json!({"code": 0})
}

/// Normalize a package version: trailing `-rN`/`-RN` → `-N`.
pub fn normalize_pkg_version(v: &str) -> String {
    if let Some(i) = v.rfind('-') {
        let r = &v[i + 1..];
        if let Some(n) = r.strip_prefix('r').or_else(|| r.strip_prefix('R')) {
            if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) {
                return format!("{}-{}", &v[..i], n);
            }
        }
    }
    v.to_string()
}

/// `api.get_version()`: installed luci-app-passwall2 version (cached in
/// `/tmp/etc/passwall2_tmp/passwall2_version`), `-rN` → `-N`. Also recognizes our
/// `luci-app-passwall2-rs` package name.
pub fn get_version() -> String {
    let vf = format!("{}/passwall2_version", CACHE_PATH);
    let mut v = trim(&util::read(&vf));
    if v.is_empty() {
        for pkg in ["luci-app-passwall2-rs", "luci-app-passwall2"] {
            v = trim(&util::sh(&format!("opkg list-installed {} 2>/dev/null | awk '{{print $3}}'", pkg)));
            if v.is_empty() {
                let line = trim(&util::sh(&format!("apk list {} 2>/dev/null | awk '/installed/ {{print $1}}'", pkg)));
                v = line.strip_prefix(&format!("{}-", pkg)).filter(|r| r.starts_with(|c: char| c.is_ascii_digit())).unwrap_or("").to_string();
            }
            if !v.is_empty() {
                break;
            }
        }
        if !v.is_empty() {
            util::mkdir(CACHE_PATH);
            let _ = std::fs::write(&vf, &v);
        }
    }
    normalize_pkg_version(&v)
}

/// Normalize a UI language code to one of our i18n package codes (fa, ru, zh-cn, zh-tw, ...).
pub fn normalize_ui_lang(l: &str) -> String {
    let c = l.to_lowercase().replace('_', "-");
    if c == "zh" || c == "zh-cn" || c == "zh-sg" || c.starts_with("zh-hans") {
        return "zh-cn".into();
    }
    if c == "zh-tw" || c == "zh-hk" || c == "zh-mo" || c.starts_with("zh-hant") {
        return "zh-tw".into();
    }
    if c.starts_with("fa-") {
        return "fa".into();
    }
    if c.starts_with("ru-") {
        return "ru".into();
    }
    c
}

/// `self_update_languages()`: i18n packages to update with the app, among fa, ru, zh-cn,
/// zh-tw: current UI language or installed `luci-i18n-passwall2-<code>`. `accept_language`
/// is the browser's `Accept-Language` (used when `luci.main.lang` is `auto`, like upstream's
/// HTTP context); None = non-HTTP context (backend language).
pub fn self_update_languages(accept_language: Option<&str>) -> Vec<String> {
    let luci = Config::load("luci");
    let mut cur = luci.get("main", "lang").unwrap_or_else(|| "auto".into());
    if cur == "auto" {
        match accept_language {
            Some(acc) => {
                cur = "en".into();
                'outer: for item in acc.split(',') {
                    let it = item.trim_start();
                    let code: String = it.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
                    if code.is_empty() {
                        continue;
                    }
                    let q = it.split_once(';').and_then(|(_, r)| {
                        let r = r.trim_start();
                        let r = r.strip_prefix('q')?.trim_start().strip_prefix('=')?.trim_start();
                        lua_tonumber(&r.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect::<String>())
                    });
                    if q.unwrap_or(1.0) <= 0.0 {
                        continue;
                    }
                    let code = code.replace('-', "_");
                    let lower = code.to_lowercase();
                    let mut alias = match lower.as_str() {
                        "zh" | "zh_cn" | "zh_sg" => "zh_Hans",
                        "zh_tw" | "zh_hk" | "zh_mo" => "zh_Hant",
                        _ => "",
                    }
                    .to_string();
                    if lower.starts_with("zh_hans") {
                        alias = "zh_Hans".into();
                    }
                    if lower.starts_with("zh_hant") {
                        alias = "zh_Hant".into();
                    }
                    let primary = code.split('_').next().unwrap_or("").to_string();
                    for cand in [code.clone(), lower, alias, primary] {
                        if !cand.is_empty() && luci.get("languages", &cand).is_some() {
                            cur = cand;
                            break 'outer;
                        }
                    }
                }
            }
            None => cur = current_lang(),
        }
    }
    let cur = normalize_ui_lang(&cur);
    ["fa", "ru", "zh-cn", "zh-tw"].iter().filter(|c| cur == **c || is_install(&format!("luci-i18n-passwall2-{}", c))).map(|c| c.to_string()).collect()
}

/// `api.to_check_self(accept_language)`: check the PassWall2 LuCI package release →
/// `{code:0, has_update, local_version, remote_version, html_url, data, i18n, languages}`.
pub fn to_check_self(accept_language: Option<&str>) -> Value {
    let Some(c) = com(APPNAME) else { return err(translate("Get remote version info failed.")) };
    let mut rel = get_api_json(&c.get_url());
    if let Value::Array(a) = &rel {
        rel = a.first().cloned().unwrap_or(Value::Null);
    }
    let Some(tag) = rel["tag_name"].as_str().map(|s| s.to_string()) else {
        return err(translate("Get remote version info failed."));
    };
    let local = get_version();
    let remote = normalize_pkg_version(tag.strip_prefix('v').unwrap_or(&tag));
    // remote "-N" → package "-rN"
    let package_version = match remote.rfind('-') {
        Some(i) if remote[i + 1..].bytes().all(|b| b.is_ascii_digit()) && i + 1 < remote.len() => format!("{}-r{}", &remote[..i], &remote[i + 1..]),
        _ => remote.clone(),
    };
    let language_version = {
        let parts: Vec<&str> = remote.splitn(4, ['.', '-']).collect();
        let num = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if parts.len() >= 3 && num(parts[0]) && num(parts[1]) {
            let third: String = parts[2].chars().take_while(|c| c.is_ascii_digit()).collect();
            if !third.is_empty() && remote.as_bytes()[parts[0].len()] == b'.' && remote.as_bytes()[parts[0].len() + 1 + parts[1].len()] == b'.' {
                format!("{}.{}.{}", parts[0], parts[1], third)
            } else {
                remote.clone()
            }
        } else {
            remote.clone()
        }
    };
    let apk = util::sh_ok("command -v apk >/dev/null 2>&1");
    let main_name = if apk { format!("luci-app-passwall2-{}.apk", package_version) } else { format!("luci-app-passwall2_{}_all.ipk", package_version) };
    let languages = self_update_languages(accept_language);
    let assets = rel["assets"].as_array().cloned().unwrap_or_default();
    let main = assets.iter().find(|a| a["name"].as_str() == Some(&main_name)).cloned();
    let mut selected = vec![];
    for code in &languages {
        let name = if apk { format!("luci-i18n-passwall2-{}-{}.apk", code, language_version) } else { format!("luci-i18n-passwall2-{}_{}_all.ipk", code, language_version) };
        match assets.iter().find(|a| a["name"].as_str() == Some(&name)) {
            Some(a) => selected.push(a.clone()),
            None => return err(translate("Get remote version info failed.")),
        }
    }
    let Some(main) = main else { return err(translate("Get remote version info failed.")) };
    let mut all: Vec<&Value> = vec![&main];
    all.extend(selected.iter());
    cache_update_digests(APPNAME, &all);
    json!({
        "code": 0, "has_update": compare_versions(&local, "<", &remote), "local_version": local,
        "remote_version": remote, "html_url": rel["html_url"].clone(), "data": main, "i18n": selected,
        "languages": languages.join(",")
    })
}

/// `api.to_install_self(id, force, languages)`: move the downloaded packages
/// (`/tmp/passwall2_download.<id>1..`) to `/tmp/passwall2_luci_update.<id>/` and start
/// `luci_update.sh` in the background → `{code:0}` / `{code:1}`.
pub fn to_install_self(id: &str, force: &str, languages: Option<&str>) -> Value {
    if !valid_task_id(id) {
        return json!({"code": 1});
    }
    let mut sel: Vec<&str> = vec![];
    for code in languages.unwrap_or("").split(',').filter(|s| !s.is_empty()) {
        if !["fa", "ru", "zh-cn", "zh-tw"].contains(&code) || sel.contains(&code) {
            return json!({"code": 1});
        }
        sel.push(code);
    }
    let dir = format!("/tmp/{}_luci_update.{}", APPNAME, id);
    let apk = util::sh_ok("command -v apk >/dev/null 2>&1");
    let (manager, ext) = if apk { ("apk", ".apk") } else { ("opkg", ".ipk") };
    let status_dir = format!("/www/luci-static/resources/{}-update", APPNAME);
    let status = format!("{}/{}.json", status_dir, id);
    let _ = std::fs::create_dir(&dir);
    let _ = std::fs::create_dir(&status_dir);
    let fail = |d: &str| {
        remove(&[d]);
        json!({"code": 1})
    };
    if exec("/bin/mv", &[&format!("/tmp/{}_download.{}1", APPNAME, id), &format!("{}/luci-app-{}{}", dir, APPNAME, ext)], None) != Some(0) {
        return fail(&dir);
    }
    for (i, code) in sel.iter().enumerate() {
        if exec("/bin/mv", &[&format!("/tmp/{}_download.{}{}", APPNAME, id, i + 2), &format!("{}/luci-i18n-{}-{}{}", dir, APPNAME, code, ext)], None) != Some(0) {
            return fail(&dir);
        }
    }
    let script = format!("{}/luci_update.sh", dir);
    if exec("/bin/cp", &[&format!("{}/luci_update.sh", util::APP_PATH), &script], None) != Some(0) {
        return fail(&dir);
    }
    chmod_755(&script);
    let _ = std::fs::write(&status, "{\"installing\":true}");
    util::sh_ok(&format!(
        "nohup {} {} {} {} {} >/dev/null 2>&1 </dev/null &",
        util::shq(&script),
        util::shq(&dir),
        util::shq(&status),
        manager,
        if force == "1" { "1" } else { "0" }
    ));
    json!({"code": 0})
}

// ====================================================================== self update (passwall2-rs)

/// GitHub API endpoint of our own releases (assets named by packaging/build.sh).
pub const SELF_RELEASE_API: &str = "https://api.github.com/repos/ParsaKSH/openwrt-passwall-rust/releases/latest";

/// Package architecture of this system (`opkg print-architecture` highest priority / `apk --print-arch`).
pub fn pkg_arch() -> String {
    if util::sh_ok("command -v apk >/dev/null 2>&1") {
        let a = trim(&util::sh("apk --print-arch 2>/dev/null"));
        if !a.is_empty() {
            return a;
        }
    }
    let a = trim(&util::sh(
        "opkg print-architecture 2>/dev/null | awk '$1 == \"arch\" && $2 != \"all\" && $2 != \"noarch\" { print $3, $2 }' | sort -n | tail -n 1 | cut -d' ' -f2",
    ));
    if !a.is_empty() {
        return a;
    }
    release_value("/etc/openwrt_release", "DISTRIB_ARCH").unwrap_or_default()
}

/// Release version `v26.11.0[-N]` → comparable package version `26.11.0-N` (release 1 by default,
/// like build.sh's PKG_RELEASE).
pub fn self_remote_version(tag: &str) -> String {
    let v = normalize_pkg_version(tag.trim().trim_start_matches(['v', 'V']));
    match v.rfind('-') {
        Some(i) if i + 1 < v.len() && v[i + 1..].bytes().all(|b| b.is_ascii_digit()) => v,
        _ => format!("{}-1", v),
    }
}

/// Parse a `SHA256SUMS` file → name → `sha256:<hex>`.
pub fn parse_sha256sums(text: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for l in text.lines() {
        let mut it = l.split_whitespace();
        if let (Some(h), Some(n)) = (it.next(), it.next()) {
            if h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()) {
                m.insert(n.trim_start_matches('*').to_string(), format!("sha256:{}", h.to_lowercase()));
            }
        }
    }
    m
}

/// Self-update check against our own GitHub releases → same shape as upstream's
/// `to_check_self`: `{code:0, has_update, local_version, remote_version, html_url,
/// data:<luci asset>, i18n:[<backend asset>], languages:""}` or `{code:1, error}`.
pub fn to_check_self_rs() -> Value {
    let gh = Config::load(C_CONFIG).get("@global_app[0]", "gh_proxy_url").unwrap_or_default();
    // PW2_RELEASE_API: test override (e.g. a local mirror of the release JSON)
    let url_s = std::env::var("PW2_RELEASE_API").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| SELF_RELEASE_API.to_string());
    let url = url_s.as_str();
    let mut args = curl_args();
    args.push("-w '\\n%{http_code}'".into());
    let (rc, out) = if !gh.is_empty() { curl_direct(&format!("{}{}", gh, url), None, &args) } else { curl_auto(url, None, &args) };
    let (body, code) = match out.trim_end().rsplit_once('\n') {
        Some((b, c)) => (b.to_string(), c.trim().to_string()),
        None => (String::new(), out.trim().to_string()),
    };
    if code == "404" {
        return err("No release of passwall2-rs has been published yet.".to_string());
    }
    if rc != 0 || body.is_empty() {
        return err(translate("Get remote version info failed."));
    }
    let rel: Value = serde_json::from_str(&body).unwrap_or(json!({}));
    let Some(tag) = rel["tag_name"].as_str().map(|s| s.to_string()) else {
        return err(translate("Get remote version info failed."));
    };
    let local = get_version();
    let remote = self_remote_version(&tag);
    let apk = util::sh_ok("command -v apk >/dev/null 2>&1");
    let arch = pkg_arch();
    let (luci_name, bin_name) = if apk {
        ("luci-app-passwall2-rs_noarch.apk".to_string(), format!("passwall2-rs_{}.apk", arch))
    } else {
        ("luci-app-passwall2-rs_all.ipk".to_string(), format!("passwall2-rs_{}.ipk", arch))
    };
    let assets = rel["assets"].as_array().cloned().unwrap_or_default();
    let find = |n: &str| assets.iter().find(|a| a["name"].as_str() == Some(n)).cloned();
    let html_url = rel["html_url"].clone();
    let (Some(mut luci), Some(mut bin)) = (find(&luci_name), find(&bin_name)) else {
        return json!({
            "code": 1, "local_version": local, "remote_version": remote, "html_url": html_url,
            "error": translate("New version found, but failed to get new version download url.")
        });
    };
    // assets without a GitHub digest: take it from the release's SHA256SUMS
    if luci["digest"].as_str().is_none() || bin["digest"].as_str().is_none() {
        if let Some(sums_url) = find("SHA256SUMS").and_then(|a| a["browser_download_url"].as_str().map(|s| s.to_string())) {
            let (rc, t) = if !gh.is_empty() { curl_direct(&format!("{}{}", gh, sums_url), None, &curl_args()) } else { curl_auto(&sums_url, None, &curl_args()) };
            if rc == 0 {
                let m = parse_sha256sums(&t);
                for a in [&mut luci, &mut bin] {
                    if a["digest"].as_str().is_none() {
                        if let Some(d) = a["name"].as_str().and_then(|n| m.get(n)) {
                            a["digest"] = json!(d);
                        }
                    }
                }
            }
        }
    }
    cache_update_digests(APPNAME, &[&luci, &bin]);
    let local_cmp = if local.is_empty() { "0".to_string() } else { local.clone() };
    json!({
        "code": 0, "has_update": compare_versions(&local_cmp, "<", &remote), "local_version": local,
        "remote_version": remote, "html_url": html_url, "data": luci, "i18n": [bin], "languages": ""
    })
}

/// Install the downloaded self-update packages (part 1 = luci-app-passwall2-rs, part 2 =
/// passwall2-rs) with `luci_update.sh` in the background → `{code:0}` / `{code:1}`.
pub fn to_install_self_rs(id: &str, force: &str) -> Value {
    if !valid_task_id(id) {
        return json!({"code": 1});
    }
    let dir = format!("/tmp/{}_luci_update.{}", APPNAME, id);
    let apk = util::sh_ok("command -v apk >/dev/null 2>&1");
    let (manager, ext) = if apk { ("apk", ".apk") } else { ("opkg", ".ipk") };
    let status_dir = format!("/www/luci-static/resources/{}-update", APPNAME);
    let status = format!("{}/{}.json", status_dir, id);
    let _ = std::fs::create_dir(&dir);
    let _ = std::fs::create_dir(&status_dir);
    let fail = |d: &str| {
        remove(&[d]);
        json!({"code": 1})
    };
    for (part, name) in [(1, "luci-app-passwall2-rs"), (2, "passwall2-rs")] {
        if exec("/bin/mv", &[&format!("/tmp/{}_download.{}{}", APPNAME, id, part), &format!("{}/{}{}", dir, name, ext)], None) != Some(0) {
            return fail(&dir);
        }
    }
    let script = format!("{}/luci_update.sh", util::APP_PATH);
    if !util::exists(&script) {
        return fail(&dir);
    }
    let _ = std::fs::write(&status, "{\"installing\":true}");
    util::sh_ok(&format!(
        "setsid /bin/sh {} {} {} {} {} >/dev/null 2>&1 </dev/null &",
        util::shq(&script),
        util::shq(&dir),
        util::shq(&status),
        manager,
        if force == "1" { "1" } else { "0" }
    ));
    json!({"code": 0})
}

// ====================================================================== CLI

/// `passwall2 api <function> [args...]` — shell bridge replacing upstream `lua_api`
/// (`echo $(lua -e "print(api.<f>(...))")`). Also accepts the Lua call syntax as a single
/// argument: `passwall2 api 'parseDNS("1.1.1.1:53")'`. Output mirrors Lua `print`
/// (`nil`, `true`/`false`, multiple returns tab-separated).
pub fn cli(args: &[String]) -> i32 {
    let mut args: Vec<String> = args.to_vec();
    if args.len() == 1 {
        if let Some((f, a)) = parse_lua_call(&args[0]) {
            args = std::iter::once(f).chain(a).collect();
        }
    }
    let Some(f) = args.first().cloned() else {
        println!();
        return 0;
    };
    let a = |i: usize| args.get(i).map(|s| s.as_str());
    let a0 = a(1).unwrap_or("");
    let b2s = |b: bool| if b { "true" } else { "false" }.to_string();
    let out: String = match f.as_str() {
        "get_domain_from_url" => get_domain_from_url(a0),
        "is_ip" => b2s(is_ip(a0)),
        "is_ipv6" => b2s(is_ipv6(a0)),
        "parseDNS" | "parse_dns" => match a(1) {
            Some(d) => {
                let (h, p) = parse_dns(d);
                format!("{}\t{}", h, p)
            }
            None => "nil".into(),
        },
        "get_ip_type" => get_ip_type(a0).into(),
        "get_ipv6_only" => get_ipv6_only(a0),
        "get_ipv6_full" => get_ipv6_full(a0),
        "iprange" => b2s(iprange(a0)),
        "ip_or_mac" => ip_or_mac(a0).into(),
        "is_mac" => b2s(is_mac(a0)),
        "get_domain_port_from_url" => match get_domain_port_from_url(a0) {
            Some((d, p)) => format!("{}\t{}", d, p),
            None => "nil\tnil".into(),
        },
        "get_socks_backup_nodes" => get_socks_backup_nodes(&Config::load(C_CONFIG), a0),
        "get_node_remarks" => Config::load(C_CONFIG).section(a0).map(get_node_remarks).unwrap_or_default(),
        "get_full_node_remarks" => Config::load(C_CONFIG).section(a0).map(get_full_node_remarks).unwrap_or_default(),
        "get_node_name" => get_node_name_by_id(&Config::load(C_CONFIG), a0),
        "get_node_list" => get_node_list(&Config::load(C_CONFIG)).to_string(),
        "get_batch_nodes" => get_batch_nodes(&Config::load(C_CONFIG), a(1), a(2)).join(" "),
        "match_node_rule" => b2s(match_node_rule(a0, a(2))),
        "compare_versions" => b2s(compare_versions(a0, a(2).unwrap_or(""), a(3).unwrap_or(""))),
        "format_go_time" => format_go_time(a(1), a(2)),
        "get_app_version" => get_app_version(a0, a(2)),
        "get_app_path" => get_app_path(a0).unwrap_or_else(|| "nil".into()),
        "finded_com" => finded_com(a0).unwrap_or_else(|| "nil".into()),
        "is_finded" => b2s(is_finded(a0)),
        "get_singbox_tags" => get_singbox_tags(),
        "get_version" => get_version(),
        "auto_get_arch" => auto_get_arch(),
        "get_new_port" => get_new_port(a(1).and_then(|p| p.parse().ok()), a(2).unwrap_or("")).to_string(),
        "get_cache_var" => get_cache_var(a0).unwrap_or_else(|| "nil".into()),
        "set_cache_var" => {
            set_cache_var(a0, a(2).unwrap_or(""));
            String::new()
        }
        "resolve_domain" => match resolve_domain(a0, a(2)) {
            Ok(ips) => ips.join(" "),
            Err(e) => format!("nil\t{}\t{}", e.output, e.rc),
        },
        "base64Decode" | "base64_decode" => base64_decode(a0),
        "base64Encode" | "base64_encode" => base64_encode(a0.as_bytes()),
        "UrlEncode" | "url_encode" => url_encode(a0),
        "UrlDecode" | "url_decode" => url_decode(a0),
        "md5_string" => md5_string(a0),
        "sha256_xray_sb" => sha256_xray_sb(a0),
        "sha256_sb_xray" => sha256_sb_xray(a0),
        "fetch_cert_sha256" => fetch_cert_sha256(a0, a(2).and_then(|p| p.parse().ok()), a(3), a(4).and_then(|t| t.parse().ok())),
        "gen_uuid" => gen_uuid(),
        "gen_random_char" => gen_random_char(a(1).and_then(|l| l.parse().ok()).unwrap_or(8)),
        "gen_wireguard_key" => match gen_wireguard_key() {
            Some((p, k)) => json!({"private_key": p, "public_key": k}).to_string(),
            None => "nil".into(),
        },
        "get_network_devices" => {
            Value::Array(get_network_devices().into_iter().map(|d| json!({"name": d.name, "label": d.label, "sort": d.sort})).collect()).to_string()
        }
        "parse_realm_uri" => match parse_realm_uri(a0) {
            Some(r) => json!({"scheme": r.scheme, "token": r.token, "server_url": r.server_url, "address": r.address, "port": r.port, "realm_id": r.realm_id, "stun_servers": r.stun_servers}).to_string(),
            None => "nil".into(),
        },
        "translate" | "i18n" => {
            let rest: Vec<&str> = args.iter().skip(2).map(|s| s.as_str()).collect();
            translatef(a0, &rest)
        }
        "to_check" => to_check(a(2), a0).to_string(),
        "to_check_self" => to_check_self(None).to_string(),
        "app_acl" | "acl" => {
            let st = crate::firewall::acl::run();
            match serde_json::to_string_pretty(&st.to_json()) {
                Ok(s) => s,
                Err(_) => "{}".into(),
            }
        }
        _ => {
            eprintln!("passwall2 api: unknown function '{}'", f);
            return 1;
        }
    };
    println!("{}", out);
    0
}

/// Parse `name("a", 'b', 3)` / `name()` into (name, args). Lua escapes `\"` `\\` `\n` handled.
pub fn parse_lua_call(s: &str) -> Option<(String, Vec<String>)> {
    let s = s.trim();
    let open = s.find('(')?;
    if !s.ends_with(')') {
        return None;
    }
    let name = s[..open].trim();
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return None;
    }
    let inner = &s[open + 1..s.len() - 1];
    let mut args = vec![];
    let mut chars = inner.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        let Some(&c) = chars.peek() else { break };
        if c == '"' || c == '\'' {
            chars.next();
            let mut v = String::new();
            while let Some(x) = chars.next() {
                if x == c {
                    break;
                }
                if x == '\\' {
                    match chars.next() {
                        Some('n') => v.push('\n'),
                        Some('t') => v.push('\t'),
                        Some(o) => v.push(o),
                        None => {}
                    }
                } else {
                    v.push(x);
                }
            }
            args.push(v);
        } else {
            let mut v = String::new();
            while let Some(&x) = chars.peek() {
                if x == ',' {
                    break;
                }
                v.push(x);
                chars.next();
            }
            let v = v.trim().to_string();
            if v != "nil" {
                args.push(v);
            }
        }
    }
    Some((name.to_string(), args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(name: &str, stype: &str, opts: &[(&str, &str)]) -> Section {
        let mut o = IndexMap::new();
        for (k, v) in opts {
            o.insert(k.to_string(), crate::uci::Value::Single(v.to_string()));
        }
        Section { name: name.into(), stype: stype.into(), anonymous: false, index: 0, options: o }
    }

    #[test]
    fn t_parse_dns() {
        assert_eq!(parse_dns("1.1.1.1:5053"), ("1.1.1.1".into(), "5053".into()));
        assert_eq!(parse_dns("1.1.1.1"), ("1.1.1.1".into(), "53".into()));
        assert_eq!(parse_dns("[::1]:5053"), ("::1".into(), "5053".into()));
        assert_eq!(parse_dns("[2001:db8::1]"), ("2001:db8::1".into(), "53".into()));
        assert_eq!(parse_dns("2001:db8::1"), ("2001:db8::1".into(), "53".into()));
        assert_eq!(parse_dns("dns.google:53"), ("dns.google:53".into(), "53".into()));
        assert_eq!(parse_dns("1.1.1.1:99999"), ("1.1.1.1:99999".into(), "53".into()));
    }

    #[test]
    fn t_domain_from_url() {
        assert_eq!(get_domain_from_url("https://dns.google:443/dns-query"), "dns.google:443");
        assert_eq!(get_domain_from_url("https://1.1.1.1/dns-query"), "1.1.1.1");
        assert_eq!(get_domain_from_url("plain"), "plain");
        assert_eq!(get_domain_port_from_url("https://example.com/x"), Some(("example.com".into(), 443)));
        assert_eq!(get_domain_port_from_url("http://example.com:8080/x"), Some(("example.com".into(), 8080)));
        assert_eq!(get_domain_port_from_url("https://1.2.3.4/x"), None);
        assert_eq!(get_domain_port_from_url("https://[::1]:443/x"), None);
        assert_eq!(get_domain_port_from_url("ftp://a.com"), None);
    }

    #[test]
    fn t_parse_url() {
        let u = parse_url("socks5://user:pass@[::1]:1080/path?x#y").unwrap();
        assert_eq!(u.protocol.as_deref(), Some("socks5"));
        assert_eq!(u.username.as_deref(), Some("user"));
        assert_eq!(u.password.as_deref(), Some("pass"));
        assert_eq!(u.hostname, "::1");
        assert_eq!(u.port, Some(1080));
        assert_eq!(u.pathname.as_deref(), Some("/path"));
        let u = parse_url("http://example.com").unwrap();
        assert_eq!((u.hostname.as_str(), u.port, u.pathname), ("example.com", None, None));
        let u = parse_url("h:80").unwrap();
        assert_eq!((u.hostname.as_str(), u.port), ("h", Some(80)));
    }

    #[test]
    fn t_ip_helpers() {
        assert!(is_ip("1.2.3.4"));
        assert!(is_ip(" [2001:db8::1] "));
        assert!(!is_ip("example.com"));
        assert!(dt_ip4addr("10.0.0.0/8"));
        assert!(dt_ip4addr("10.0.0.0/255.0.0.0"));
        assert!(!dt_ip4addr("10.0.0.0/33"));
        assert!(!dt_ip4addr("01.2.3.4"));
        assert_eq!(get_ip_type("1.2.3.4/24"), "4");
        assert_eq!(get_ip_type("::1"), "6");
        assert_eq!(ip_or_mac("aa:bb:cc:dd:ee:ff"), "mac");
        assert_eq!(ip_or_mac("a-b-c-d-e-f"), "mac");
        assert_eq!(ip_or_mac("192.168.1.0/24"), "ip");
        assert_eq!(ip_or_mac("fe80::1"), "");
        assert!(iprange("192.168.1.10-192.168.1.20"));
        assert!(!iprange("192.168.1.10/24-1.1.1.1"));
        assert_eq!(get_ipv6_full("::1"), "[::1]");
        assert_eq!(get_ipv6_only("[::1]"), "::1");
        assert!(is_ipv6addrport("[::1]:53"));
        assert!(dt_hostname("example.com"));
        assert!(dt_hostname("localhost"));
        assert!(!dt_hostname("1.2.3.4"));
        assert!(!dt_hostname("-bad.com"));
    }

    #[test]
    fn t_base64() {
        assert_eq!(base64_decode("aGVsbG8"), "hello");
        assert_eq!(base64_decode("aGVsbG8="), "hello");
        assert_eq!(base64_decode("aGVs\nbG8="), "hello");
        assert_eq!(base64_decode("not base64!"), "not base64!");
        assert_eq!(base64_decode("aGVsbG9"), "aGVsbG9"); // non-canonical trailing bits
        assert_eq!(base64_decode("a"), "a");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        let hex = "AB".repeat(32);
        let b = sha256_xray_sb(&hex);
        assert_eq!(sha256_sb_xray(&b), hex);
        assert_eq!(sha256_xray_sb(&b), b);
        assert_eq!(url_decode("a+b%20c%2"), "a b c%2");
        assert_eq!(url_decode("%e4%b8%ad"), "中");
    }

    #[test]
    fn t_versions() {
        assert!(compare_versions("1.8.4", "<", "1.8.10"));
        assert!(compare_versions("1.12.0", ">=", "1.12.0"));
        assert!(!compare_versions("1.12.0", "<", "1.12.0"));
        assert!(compare_versions("26.1.1-r1", "<", "26.1.1-r2"));
        assert!(compare_versions("1.0", "~=", "1.0")); // upstream quirk
        assert!(compare_versions("25.1.1", ">=", "25.1"));
        assert!(compare_versions("", "<", "1"));
        assert_eq!(normalize_pkg_version("26.1.1-r1"), "26.1.1-1");
        assert_eq!(strip_v("v1.2.3"), "1.2.3");
    }

    #[test]
    fn t_go_time() {
        assert_eq!(format_go_time(Some("3600"), None), "1h");
        assert_eq!(format_go_time(Some("90"), None), "1m30s");
        assert_eq!(format_go_time(Some("1h 30m"), None), "1h30m");
        assert_eq!(format_go_time(Some("0"), Some("5m")), "5m");
        assert_eq!(format_go_time(Some(""), None), "0s");
        assert_eq!(format_go_time(Some("90s"), None), "1m30s");
    }

    #[test]
    fn t_match_rule() {
        assert!(match_node_rule("HK 01 Premium", None));
        assert!(match_node_rule("HK 01 Premium", Some("HK&&Premium")));
        assert!(!match_node_rule("HK 01 Premium", Some("HK&&!Premium")));
        assert!(match_node_rule("HK 01", Some("US||^HK")));
        assert!(match_node_rule("HK 01", Some("01$")));
        assert!(!match_node_rule("HK 01", Some("^US || JP$")));
        assert!(match_node_rule("x", Some("^")));
    }

    #[test]
    fn t_lua_find() {
        assert!(lua_find("Xray-linux-64.zip", "linux%-64"));
        assert!(lua_find("sing-box-1.12.0-linux-amd64-musl.tar.gz", "linux%-amd64%-musl"));
        assert!(!lua_find("sing-box-1.12.0-linux-amd64.tar.gz", "linux%-amd64%-musl"));
        assert!(lua_find("Xray-linux-arm32-v7a.zip", "linux%-arm.*7"));
        assert!(lua_find("Xray-linux-arm32-v6.zip", "linux%-arm.*6[^4]*"));
        assert!(!lua_find("Xray-linux-arm64-v8a.zip", "linux%-arm.*5"));
        assert!(lua_find("abc", "^a.c$"));
        assert!(!lua_find("abcd", "^a.c$"));
        assert!(lua_find("a1", "%a%d"));
        assert!(lua_find("aaab", "a-b"));
        assert!(lua_find("color", "colou?r"));
        assert!(lua_find("colour", "^colou?r$"));
    }

    #[test]
    fn t_misc() {
        assert_eq!(split("a,b,,c,", ","), vec!["a", "b", "", "c"]);
        assert_eq!(split("", ","), Vec::<String>::new());
        assert!(is_timehhmm("3:05"));
        assert!(!is_timehhmm("24:00"));
        assert!(is_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid("123e4567-e89b-12d3-a456-42661417400"));
        assert_eq!(table_remove_duplicates(&["a".into(), "".into(), "a".into(), "b".into()]), Some(vec!["a".into(), "b".into()]));
        assert_eq!(trim("\t x \n"), "x");
        assert_eq!(clean_empty_tables(json!({"a": {}, "b": [{}], "c": 1})), Some(json!({"c": 1})));
        assert_eq!(clean_empty_tables(json!({"a": {}})), None);
        assert_eq!(parse_code_time("200:0.123456"), Some("123.46".into()));
        assert_eq!(parse_code_time("000:0.000000"), None);
        assert_eq!(parse_code_time("200:150"), Some("0.15".into()));
        assert_eq!(extract_time_ms("64 bytes from 1.1.1.1: seq=0 ttl=57 time=12.345 ms"), "12");
        let m = get_args(&["-a".into(), "1".into(), "-b".into(), "2".into()]);
        assert_eq!(m.get("-a").map(|s| s.as_str()), Some("1"));
        assert_eq!(m.get("-b").map(|s| s.as_str()), Some("2"));
        assert_eq!(parse_lua_call("parseDNS(\"1.1.1.1:53\")"), Some(("parseDNS".into(), vec!["1.1.1.1:53".into()])));
        assert_eq!(parse_lua_call("get_new_port()"), Some(("get_new_port".into(), vec![])));
        assert_eq!(arch_from("i686", None, None), "x86");
        assert_eq!(arch_from("mips", Some("mipsel_24kc"), None), "mipsel");
        assert_eq!(arch_from("armv7l", Some("arm_cortex-a7"), None), "armv5");
        assert_eq!(arch_from("armv7l", Some("arm_cortex-a7_neon-vfpv4"), None), "armv7");
        assert_eq!(lang_candidates("zh_cn"), vec!["zh-cn".to_string(), "zh".to_string()]);
        assert_eq!(lang_candidates("zh_Hans"), Vec::<String>::new());
        assert_eq!(normalize_ui_lang("zh_Hans"), "zh-cn");
        assert_eq!(com("xray").unwrap().get_url(), "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/releases/download/api-cache/xray-pre-release-api.json");
    }

    #[test]
    fn t_dnsmasq_servers() {
        let m = parse_dnsmasq_servers(&["/example.com/1.1.1.1#5353".into(), "8.8.8.8".into(), "/a.com/".into(), "/b.com/9.9.9.9".into()]);
        assert_eq!(m.len(), 2);
        assert_eq!(m["example.com"], DnsmasqServer { dnsmasq_dns: "1.1.1.1#5353".into(), server: "1.1.1.1".into(), port: Some(5353) });
        assert_eq!(m["b.com"].port, Some(53));
    }

    #[test]
    fn t_realm() {
        let r = parse_realm_uri("realm://tok@[::1]:8443/my-realm/?stun=a.com:3478&STUN=b.com").unwrap();
        assert_eq!(r.address, "::1");
        assert_eq!(r.port, 8443);
        assert_eq!(r.realm_id, "my-realm");
        assert_eq!(r.stun_servers, Some(vec!["a.com:3478".into(), "b.com".into()]));
        let r = parse_realm_uri("realm+http://tok@host/id").unwrap();
        assert_eq!((r.address.as_str(), r.port, r.stun_servers), ("host", 80, None));
        assert!(parse_realm_uri("realm://host/id").is_none());
    }

    #[test]
    fn t_nodes() {
        let n = sec("n1", "nodes", &[("type", "Xray"), ("protocol", "vless"), ("remarks", "HK"), ("address", "1.2.3.4"), ("port", "443")]);
        assert_eq!(get_node_remarks(&n), "Xray VLESS：[HK]");
        assert_eq!(get_full_node_remarks(&n), "Xray VLESS：[HK] 1.2.3.4:443");
        let s = sec("s1", "nodes", &[("type", "sing-box"), ("protocol", "_shunt"), ("remarks", "S")]);
        assert!(is_special_node(&s));
        assert_eq!(get_node_name(&s), "Sing-Box _shunt：[S] ");
        assert_eq!(protocol_display("trojan"), "Trojan");
        let cfg = Config::parse(
            "passwall2",
            "config nodes 'a'\n\toption type 'Xray'\n\toption protocol 'vmess'\n\toption remarks 'A'\n\toption address 'a.com'\n\toption port '1'\n\toption group 'G'\n\
             config nodes 'b'\n\toption type 'SS-Rust'\n\toption remarks 'B'\n\toption address '::1'\n\toption port '2'\n\
             config nodes 'c'\n\toption type 'Xray'\n\toption protocol '_shunt'\n\toption remarks 'C'\n\
             config nodes 'd'\n\toption type 'Xray'\n\toption remarks 'D'\n\
             config socks 'sk'\n\toption node 'b'\n\toption port '1070'\n\toption backup_node_add_mode 'batch'\n\toption backup_node_group 'default g'\n",
        );
        let v = get_valid_nodes(&cfg);
        let ids: Vec<&str> = v.iter().map(|x| x.id()).collect();
        assert_eq!(ids, vec!["b", "c", "a"]);
        assert_eq!(v[0].remark, "SS-Rust：[B]");
        assert_eq!(v[1].node_type, "special");
        let l = get_node_list(&cfg);
        assert_eq!(l["normal_list"].as_array().unwrap().len(), 2);
        assert_eq!(l["shunt_list"][0]["id"], "c");
        assert_eq!(l["socks_list"][0]["id"], "sk");
        assert_eq!(get_batch_nodes(&cfg, Some("G"), None), vec!["a".to_string()]);
        assert_eq!(get_socks_backup_nodes(&cfg, "sk"), "a");
        assert_eq!(get_core(&cfg, "ss_type", &[(false, "xray"), (true, "sing-box")]), Some("sing-box".into()));
    }

    #[test]
    fn t_lmo_hash() {
        // canonicalization: whitespace collapse/trim must not change the hash of the canonical form
        assert_eq!(lmo_canon_hash("  Hello   world \n"), lmo_canon_hash("Hello world"));
        assert_ne!(lmo_canon_hash("a"), lmo_canon_hash("b"));
        assert_eq!(sfh_hash(b"", 0), 0);
    }
}
