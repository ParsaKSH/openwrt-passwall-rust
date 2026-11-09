//! Geo rule update — port of upstream `root/usr/share/passwall2/rule_update.lua`
//! (plus the controller's `rollback_rules` / `update_rules` helpers for rpc.rs).
//!
//! CLI (upstream argument layout, `arg[1]` is ignored):
//!   passwall2 rule-update log <geoip,geosite|all> [cron]
//!   passwall2 rule-update log all cron              (cron / tasks)
//!   passwall2 rule-update <geoip,geosite> [cron]    (convenience: without the leading `log`)
//!   passwall2 rule-update rollback <geoip|geosite>  (controller `rollback_rules`)
//!   passwall2 rule-update status                    (JSON: asset/backup state for the UI)

use crate::{api, uci, util};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

pub const LOCK_FILE: &str = "/var/lock/passwall2_sub_rule.lock";
pub const BACKUP_PATH: &str = "/tmp/bak_v2ray/";
pub const DEFAULT_GEOIP_URL: &str = "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat";
pub const DEFAULT_GEOSITE_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
pub const DEFAULT_ASSET_LOCATION: &str = "/usr/share/v2ray/";
const TMP_DIR: &str = "/tmp/";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

// ====================================================================== shared update lock

#[cfg(all(target_env = "gnu", target_pointer_width = "32"))]
type OffT = i32;
#[cfg(not(all(target_env = "gnu", target_pointer_width = "32")))]
type OffT = i64;

extern "C" {
    fn lockf(fd: i32, cmd: i32, len: OffT) -> i32;
}
const F_LOCK: i32 = 1;
const F_TLOCK: i32 = 2;

/// POSIX `lockf` (what nixio's `file:lock("tlock"|"lock")` uses) from the current offset to EOF.
fn posix_lockf(f: &File, cmd: i32) -> bool {
    use std::os::unix::io::AsRawFd;
    loop {
        let r = unsafe { lockf(f.as_raw_fd(), cmd, 0) };
        if r == 0 {
            return true;
        }
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return false;
    }
}

/// Held `/var/lock/passwall2_sub_rule.lock` (shared by subscription and rule update).
/// The POSIX lock is released when this is dropped (fd closed), like `update_lock:close()`.
pub struct UpdateLock {
    _file: File,
}

fn task_name(marker: Option<u8>) -> String {
    match marker {
        Some(b's') => api::translate("Subscription"),
        Some(b'r') => api::translate("Rule Update"),
        _ => api::translate("Subscription/Rule Update"),
    }
}

/// Upstream lock/startup sequence shared by subscribe.lua and rule_update.lua (spec 06 §1.2/§3.2).
/// `marker` is `b's'` (subscription) or `b'r'` (rule update); `cron` = `arg[3] == "cron"`.
/// `Err(exit_code)` after logging: open failure → 1, busy non-cron → 0, blocking lock failure → 1.
pub fn acquire_update_lock(marker: u8, cron: bool) -> Result<UpdateLock, i32> {
    acquire_update_lock_at(LOCK_FILE, marker, cron)
}

pub fn acquire_update_lock_at(path: &str, marker: u8, cron: bool) -> Result<UpdateLock, i32> {
    if let Some(d) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path) else {
        util::log(0, &api::translate("Unable to open the subscription/rule update lock. Exiting."));
        return Err(1);
    };
    if !posix_lockf(&f, F_TLOCK) {
        if !cron {
            util::log(0, &api::translate("A subscription or rule update is already running. Skipping this request."));
            return Err(0);
        }
        let mut b = [0u8; 1];
        let running = match f.read(&mut b) {
            Ok(1) => Some(b[0]),
            _ => None,
        };
        let _ = f.seek(SeekFrom::Start(0));
        let me = task_name(Some(marker));
        util::log(0, &api::translatef("[%s] is running; [%s] is queued and waiting...", &[&task_name(running), &me]));
        if !posix_lockf(&f, F_LOCK) {
            util::log(0, &api::translate("Unable to acquire the update lock. Scheduled task failed."));
            return Err(1);
        }
    }
    let _ = f.seek(SeekFrom::Start(0));
    let _ = f.write_all(&[marker]);
    let _ = f.seek(SeekFrom::Start(0));
    Ok(UpdateLock { _file: f })
}

/// Probe used by `/etc/init.d/passwall2 restart` while waiting for subscription/rule updates:
/// 0 = free (lock could be taken), 1 = busy, 2 = lock file cannot be opened.
/// Must be called from a short-lived process or thread-free context: POSIX locks are per process,
/// so a process that itself holds the lock always sees 0.
pub fn update_lock_status() -> i32 {
    let Ok(f) = std::fs::OpenOptions::new().append(true).create(true).open(LOCK_FILE) else { return 2 };
    if posix_lockf(&f, F_TLOCK) {
        0
    } else {
        1
    }
}

// ====================================================================== settings

/// `@global_rules[0]` options used by the updater.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSettings {
    pub geoip_url: String,
    pub geosite_url: String,
    /// Always ends in `/`.
    pub asset_location: String,
}

impl RuleSettings {
    pub fn from_config(cfg: &uci::Config) -> RuleSettings {
        let g = |o: &str, d: &str| cfg.get("@global_rules[0]", o).unwrap_or_else(|| d.to_string());
        RuleSettings {
            geoip_url: g("geoip_url", DEFAULT_GEOIP_URL),
            geosite_url: g("geosite_url", DEFAULT_GEOSITE_URL),
            asset_location: with_slash(&g("v2ray_location_asset", DEFAULT_ASSET_LOCATION)),
        }
    }
}

fn with_slash(p: &str) -> String {
    if p.ends_with('/') {
        p.to_string()
    } else {
        format!("{}/", p)
    }
}

/// Manual target list (`arg[2]`, comma separated) → (geoip_update, geosite_update) flags.
/// Anything other than `geoip`/`geosite` (e.g. `all`) selects nothing, like upstream.
pub fn parse_targets(arg: &str) -> (bool, bool) {
    let mut ip = false;
    let mut site = false;
    for w in arg.split(',').filter(|w| !w.is_empty()) {
        if w == "geoip" {
            ip = true;
        }
        if w == "geosite" {
            site = true;
        }
    }
    (ip, site)
}

// ====================================================================== curl & download checks

/// Parse `curl --dump-header - -w '\n%{http_code}'` output → (http_code, headers without `\r`).
/// Lua: `result:match("^(.-)%s*([0-9]+)$")`, else trailing `(%d+)%s*$`, else 0.
pub fn parse_curl_output(result: &str) -> (u32, String) {
    if result.is_empty() {
        return (0, String::new());
    }
    let digits_start = |s: &str| -> Option<usize> {
        let t = s.trim_end_matches(|c: char| c.is_ascii_digit());
        if t.len() == s.len() {
            None
        } else {
            Some(t.len())
        }
    };
    let (code, header) = if let Some(i) = digits_start(result) {
        let body = result[..i].trim_end_matches(is_lua_space);
        (result[i..].parse::<u32>().unwrap_or(0), body.to_string())
    } else {
        let t = result.trim_end_matches(is_lua_space);
        match digits_start(t) {
            Some(i) => (t[i..].parse::<u32>().unwrap_or(0), String::new()),
            None => (0, String::new()),
        }
    };
    (code, header.replace('\r', ""))
}

fn is_lua_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

/// rule_update `curl(url, file)` → (http_code, headers).
fn curl(url: &str, file: &str) -> (u32, String) {
    let args: Vec<String> = vec![
        "-skL".into(),
        "--retry 3".into(),
        "--connect-timeout 3".into(),
        "--max-time 300".into(),
        "--speed-limit 51200 --speed-time 15".into(),
        "-H 'Accept: */*'".into(),
        format!("-A \"{}\"", USER_AGENT),
        "--dump-header -".into(),
        "-w '\\n%{http_code}'".into(),
        format!("-o {}", util::shq(file)),
    ];
    let (_rc, out) = api::curl_auto(url, None, &args);
    parse_curl_output(&out)
}

/// Last `Content-Length: N` with N > 0 among all (redirect) header blocks;
/// Lua `[Cc]ontent%-[Ll]ength:%s*(%d+)` matched anywhere.
pub fn remote_content_length(headers: &str) -> Option<u64> {
    let b = headers.as_bytes();
    let pat = b"ontent-";
    let mut found = None;
    let mut i = 0;
    while i + 15 <= b.len() {
        let ok = (b[i] == b'C' || b[i] == b'c')
            && &b[i + 1..i + 8] == pat
            && (b[i + 8] == b'L' || b[i + 8] == b'l')
            && &b[i + 9..i + 15] == b"ength:";
        if ok {
            let mut j = i + 15;
            while j < b.len() && is_lua_space(b[j] as char) {
                j += 1;
            }
            let k = j + b[j..].iter().take_while(|c| c.is_ascii_digit()).count();
            if k > j {
                if let Ok(n) = headers[j..k].parse::<u64>() {
                    if n > 0 {
                        found = Some(n);
                    }
                } else {
                    // tonumber of a huge digit run is a float > 0
                    found = Some(u64::MAX);
                }
            }
            i = k.max(i + 1);
        } else {
            i += 1;
        }
    }
    found
}

/// `non_file_check` decision: None = file ok; Some((fmt, args)) = log message, file bad.
pub fn size_check(local_size: u64, headers: &str) -> Option<(&'static str, Vec<String>)> {
    if local_size == 0 {
        return Some(("Downloaded file is empty or an error occurred while reading it.", vec![]));
    }
    if let Some(remote) = remote_content_length(headers) {
        if remote != local_size {
            return Some((
                "Download file size verification error. Original file size: %sB. Downloaded file size: %sB.",
                vec![remote.to_string(), local_size.to_string()],
            ));
        }
    }
    None
}

/// `non_file_check(file, headers)` → true when the download is bad (logged at level 2).
fn non_file_check(path: &str, headers: &str) -> bool {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    match size_check(size, headers) {
        Some((fmt, args)) => {
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            api::log_i18n(2, fmt, &a);
            true
        }
        None => false,
    }
}

/// Lua `url:match("^.*/([^/?#]+)")`: the run of non-`/?#` chars after the last `/` that is
/// followed by such a char.
pub fn url_filename(url: &str) -> Option<String> {
    let b = url.as_bytes();
    let stop = |c: u8| c == b'/' || c == b'?' || c == b'#';
    let mut i = b.len();
    while i > 0 {
        i -= 1;
        if b[i] == b'/' && i + 1 < b.len() && !stop(b[i + 1]) {
            let s = i + 1;
            let e = s + b[s..].iter().take_while(|c| !stop(**c)).count();
            return Some(url[s..e].to_string());
        }
    }
    None
}

/// sha256sum URL: every literal occurrence of the file name gets `.sha256sum` appended.
pub fn sha_url(url: &str, fname: &str) -> String {
    // upstream quirk: Lua gsub treats `%` in the replacement specially (a file name containing
    // `%2x` raises "invalid capture index"); we replace literally.
    url.replace(fname, &format!("{}.sha256sum", fname))
}

/// First line of a `.sha256sum` file → 64-hex hash (Lua `^(%x+)%s` + `#hash == 64`).
pub fn parse_sha256_line(content: &str) -> Option<String> {
    if content.is_empty() {
        return None;
    }
    let line = content.split('\n').next()?;
    let n = line.bytes().take_while(|c| c.is_ascii_hexdigit()).count();
    if n == 0 || n != 64 {
        return None;
    }
    match line[n..].chars().next() {
        Some(c) if is_lua_space(c) => Some(line[..n].to_string()),
        _ => None,
    }
}

fn files_equal(a: &str, b: &str) -> bool {
    let (Ok(fa), Ok(fb)) = (File::open(a), File::open(b)) else { return false };
    match (fa.metadata(), fb.metadata()) {
        (Ok(ma), Ok(mb)) if ma.len() != mb.len() => return false,
        (Ok(_), Ok(_)) => {}
        _ => return false,
    }
    let (mut ra, mut rb) = (BufReader::new(fa), BufReader::new(fb));
    let mut ba = vec![0u8; 65536];
    let mut bb = vec![0u8; 65536];
    loop {
        let Ok(na) = read_full(&mut ra, &mut ba) else { return false };
        let Ok(nb) = read_full(&mut rb, &mut bb) else { return false };
        if na != nb || ba[..na] != bb[..nb] {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

// ====================================================================== geo file validation

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    List,
    GeoIp,
    GeoSite,
    Cidr,
    Domain,
    Attribute,
}

/// (wire type, child message, numeric maximum) per field number (1-based).
type FieldSpec = (u64, Option<Kind>, Option<u64>);

const U32MAX: u64 = 4294967295;

fn schema(kind: Kind, entry: Kind, field: u64) -> Option<FieldSpec> {
    let t: &[FieldSpec] = match kind {
        Kind::List => return if field == 1 { Some((2, Some(entry), None)) } else { None },
        Kind::GeoIp => &[(2, None, None), (2, Some(Kind::Cidr), None), (0, None, None)],
        Kind::GeoSite => &[(2, None, None), (2, Some(Kind::Domain), None)],
        Kind::Cidr => &[(2, None, None), (0, None, Some(U32MAX))],
        Kind::Domain => &[(0, None, Some(3)), (2, None, None), (2, Some(Kind::Attribute), None)],
        Kind::Attribute => &[(2, None, None), (0, None, None), (0, None, None)],
    };
    if field == 0 {
        return None;
    }
    t.get((field - 1) as usize).copied()
}

struct GeoParser<R: Read + Seek> {
    r: R,
    pos: u64,
    rules: u64,
    entry: Kind,
}

type PResult<T> = Result<T, ()>;

fn ensure(c: bool) -> PResult<()> {
    if c {
        Ok(())
    } else {
        Err(())
    }
}

impl<R: Read + Seek> GeoParser<R> {
    fn skip(&mut self, len: u64, limit: u64) -> PResult<()> {
        ensure(len <= limit - self.pos)?;
        self.pos += len;
        self.r.seek(SeekFrom::Start(self.pos)).map_err(|_| ())?;
        Ok(())
    }

    /// Without a maximum, the varint is only validated/skipped and 0 is returned.
    fn varint(&mut self, limit: u64, maximum: Option<u64>) -> PResult<u64> {
        let mut value: u64 = 0;
        let mut factor: u64 = 1;
        for i in 1..=10 {
            ensure(self.pos < limit)?;
            let mut b = [0u8; 1];
            ensure(matches!(self.r.read(&mut b), Ok(1)))?;
            let byte = b[0] as u64;
            self.pos += 1;
            ensure(i < 10 || byte <= 1)?;
            if let Some(max) = maximum {
                let digit = byte % 128;
                ensure(digit <= (max - value) / factor)?;
                value += digit * factor;
            }
            if byte < 128 {
                return Ok(value);
            }
            factor = factor.saturating_mul(128);
        }
        Err(())
    }

    fn parse(&mut self, kind: Kind, limit: u64) -> PResult<()> {
        let mut values: [Option<u64>; 4] = [None; 4];
        let mut entries: u64 = 0;
        let is_entry = kind == Kind::GeoIp || kind == Kind::GeoSite;
        while self.pos < limit {
            if is_entry && values[1].is_some_and(|v| v > 0) && entries > 0 {
                return self.skip(limit - self.pos, limit);
            }
            let tag = self.varint(limit, Some(U32MAX))?;
            let (field, wire) = (tag / 8, tag % 8);
            let spec = schema(kind, self.entry, field);
            ensure(field > 0 && spec.is_none_or(|s| s.0 == wire))?;
            let value: Option<u64> = match wire {
                0 => Some(self.varint(limit, spec.and_then(|s| s.2))?),
                2 => {
                    let max = limit - self.pos;
                    let len = self.varint(limit, Some(max))?;
                    ensure(len <= limit - self.pos)?;
                    let child = spec.and_then(|s| s.1);
                    match child {
                        Some(c) if !(is_entry && entries > 0) => {
                            let end = self.pos + len;
                            self.parse(c, end)?;
                        }
                        _ => self.skip(len, limit)?,
                    }
                    if child.is_some() {
                        entries += 1;
                    }
                    Some(len)
                }
                1 | 5 => {
                    self.skip(if wire == 1 { 8 } else { 4 }, limit)?;
                    None
                }
                // Geo files do not use Protobuf group fields.
                _ => return Err(()),
            };
            if spec.is_some() {
                values[field as usize] = value;
            }
        }
        match kind {
            Kind::List => ensure(entries > 0 && self.rules > 0)?,
            Kind::GeoIp | Kind::GeoSite | Kind::Attribute => ensure(values[1].is_some_and(|v| v > 0))?,
            Kind::Cidr => {
                let ip = values[1];
                ensure(ip == Some(4) || ip == Some(16))?;
                ensure(values[2].unwrap_or(0) <= if ip == Some(4) { 32 } else { 128 })?;
                self.rules += 1;
            }
            Kind::Domain => {
                ensure(values[2].is_some_and(|v| v > 0))?;
                self.rules += 1;
            }
        }
        Ok(())
    }
}

/// Validate a geo file from any seekable reader of `size` bytes.
pub fn validate_geo_reader<R: Read + Seek>(r: R, size: u64, geo_type: &str) -> bool {
    let entry = match geo_type {
        "geoip" => Kind::GeoIp,
        "geosite" => Kind::GeoSite,
        _ => return false,
    };
    if size == 0 {
        return false;
    }
    let mut p = GeoParser { r, pos: 0, rules: 0, entry };
    p.parse(Kind::List, size).is_ok()
}

/// `validate_geo_file(path, "geoip"|"geosite")`: streaming protobuf sanity check that walks
/// every category boundary and samples the first rule of each.
pub fn validate_geo_file(path: &str, geo_type: &str) -> bool {
    if geo_type != "geoip" && geo_type != "geosite" {
        return false;
    }
    let Ok(f) = File::open(path) else { return false };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    validate_geo_reader(BufReader::new(f), size, geo_type)
}

// ====================================================================== updater

struct Updater {
    settings: RuleSettings,
    reboot: bool,
}

impl Updater {
    fn install(&mut self, tmp_path: &str, asset_path: &str) {
        util::sh(&format!("mkdir -p {b} && mv -f {} {b}", util::shq(asset_path), b = util::shq(BACKUP_PATH)));
        util::sh(&format!(
            "mkdir -p {} && mv -f {} {}",
            util::shq(&self.settings.asset_location),
            util::shq(tmp_path),
            util::shq(asset_path)
        ));
        // the download inherits the caller's umask (rpcd: 077); keep geo files world-readable
        // like the packaged ones
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(asset_path, std::fs::Permissions::from_mode(0o644));
        self.reboot = true;
    }

    /// `fetch_geofile(name, type, url)` → Ok(0|1) like upstream's return values;
    /// Err(msg) where upstream would raise a Lua error (caught by `safe_call`).
    fn fetch_geofile(&mut self, geo_name: &str, geo_type: &str, url: &str) -> Result<i32, String> {
        let tmp_path = format!("{}{}", TMP_DIR, geo_name);
        let asset_path = format!("{}{}", self.settings.asset_location, geo_name);
        let down_filename = url_filename(url).ok_or_else(|| format!("unable to get the file name from URL: {}", url))?;
        let sha_url = sha_url(url, &down_filename);
        let sha_path = format!("{}.sha256sum", tmp_path);

        let mut digest = None;
        let sha_verify = curl(&sha_url, &sha_path).0 == 200;
        if sha_verify {
            if let Some(h) = parse_sha256_line(&util::read(&sha_path)) {
                digest = Some(format!("sha256:{}", h));
            }
            let Some(d) = &digest else {
                api::log_i18n(1, "%s SHA256 verification information is invalid. Update failed.", &[geo_type]);
                return Ok(1);
            };
            if util::exists(&asset_path) && api::verify_sha256(&asset_path, d) {
                api::log_i18n(1, "%s version is the same and does not need to be updated.", &[geo_type]);
                return Ok(0);
            }
        }

        let (mut code, mut header) = curl(url, &tmp_path);
        if code == 200 && non_file_check(&tmp_path, &header) {
            api::log_i18n(1, "%s an error occurred during the file download process. Please try downloading again.", &[geo_type]);
            let _ = std::fs::remove_file(&tmp_path);
            (code, header) = curl(url, &tmp_path);
            if code == 200 && non_file_check(&tmp_path, &header) {
                code = 0;
                api::log_i18n(
                    1,
                    "%s an error occurred while downloading the file. Please check your network or the download link and try again!",
                    &[geo_type],
                );
            }
        }
        if code != 200 {
            api::log_i18n(1, "%s update failed, please try again later or change URL.", &[geo_type]);
            return Ok(1);
        }
        match &digest {
            Some(d) => {
                if !api::verify_sha256(&tmp_path, d) {
                    api::log_i18n(1, "%s update failed, please try again later or change URL.", &[geo_type]);
                    return Ok(1);
                }
            }
            _ => {
                if !validate_geo_file(&tmp_path, geo_type) {
                    api::log_i18n(1, "%s file format verification failed. Update failed.", &[geo_type]);
                    return Ok(1);
                }
                if util::exists(&asset_path) && files_equal(&tmp_path, &asset_path) {
                    api::log_i18n(1, "%s version is the same and does not need to be updated.", &[geo_type]);
                    return Ok(0);
                }
            }
        }
        self.install(&tmp_path, &asset_path);
        api::log_i18n(1, "%s update success.", &[geo_type]);
        Ok(0)
    }

    /// `safe_call(fetch_<type>, "%s update error!")` + `remove_tmp_geofile(<type>)`.
    fn update_one(&mut self, geo_type: &str) {
        api::log_i18n(1, "%s Start updating...", &[geo_type]);
        let url = if geo_type == "geoip" { self.settings.geoip_url.clone() } else { self.settings.geosite_url.clone() };
        if let Err(e) = self.fetch_geofile(&format!("{}.dat", geo_type), geo_type, &url) {
            // upstream also logs a Lua traceback here; there is no equivalent.
            util::log(1, &e);
            api::log_i18n(1, "%s update error!", &[geo_type]);
        }
        let _ = std::fs::remove_file(format!("{}{}.dat", TMP_DIR, geo_type));
        let _ = std::fs::remove_file(format!("{}{}.dat.sha256sum", TMP_DIR, geo_type));
    }
}

/// Full `rule_update.lua` run. `targets` = `arg[2]` (ignored when `cron`), `cron` = `arg[3]=="cron"`.
/// Returns the process exit code.
pub fn run(targets: Option<&str>, cron: bool) -> i32 {
    let lock = match acquire_update_lock(b'r', cron) {
        Ok(l) => l,
        Err(code) => return code,
    };
    uci::revert(util::CONFIG);
    let cfg = uci::Config::load(util::CONFIG);
    let settings = RuleSettings::from_config(&cfg);

    let targets = if cron { None } else { targets };
    // upstream compares the raw strings: only "1" runs an update and only "0" counts as off.
    let (geoip_flag, geosite_flag) = match targets {
        Some(t) => {
            let (ip, site) = parse_targets(t);
            let f = |b: bool| (if b { "1" } else { "0" }).to_string();
            (f(ip), f(site))
        }
        None => (
            cfg.get("@global_rules[0]", "geoip_update").unwrap_or_else(|| "1".into()),
            cfg.get("@global_rules[0]", "geosite_update").unwrap_or_else(|| "1".into()),
        ),
    };
    if geoip_flag == "0" && geosite_flag == "0" {
        drop(lock);
        return 0;
    }

    util::log(0, &api::translate("Start updating the rules..."));
    let mut up = Updater { settings, reboot: false };
    if geoip_flag == "1" {
        up.update_one("geoip");
    }
    if geosite_flag == "1" {
        up.update_one("geosite");
    }

    // upstream quirk (kept, the UI checkboxes mirror these flags): a manual run stores its
    // selection as the persistent cron flags.
    let mut b = uci::Batch::new();
    b.set("passwall2.@global_rules[0].geoip_update", &geoip_flag);
    b.set("passwall2.@global_rules[0].geosite_update", &geosite_flag);
    if up.reboot {
        util::log(1, &api::translate("Restart the service and apply the new rules."));
        b.set("passwall2.@global[0].flush_set", "1");
    }
    let _ = b.commit();
    util::log(0, &api::translate("The rules have been updated..."));

    drop(lock);
    if up.reboot {
        let mut a = vec!["restart".to_string()];
        if cron {
            a.push("cron".into());
        }
        util::spawn_bg("/etc/init.d/passwall2", &a, "/dev/null");
    }
    0
}

// ====================================================================== controller helpers (rpc.rs)

/// Controller `update_rules`: start `passwall2 rule-update log '<update>'` in the background.
/// Returns false when `update` is empty (→ `{"code":0,"data":{"message":"missing update target"}}`).
pub fn update_rules_bg(update: &str) -> bool {
    if update.is_empty() {
        return false;
    }
    let args = vec!["rule-update".to_string(), "log".to_string(), update.to_string()];
    util::spawn_bg(util::SELF_BIN, &args, "/dev/null");
    true
}

/// `fs.move` (nixio): rename, falling back to copy + unlink across filesystems.
fn fs_move(src: &str, dst: &str) -> bool {
    if std::fs::rename(src, dst).is_ok() {
        return true;
    }
    if !std::path::Path::new(src).is_file() {
        return false;
    }
    if std::fs::copy(src, dst).is_ok() {
        let _ = std::fs::remove_file(src);
        return true;
    }
    false
}

/// Controller `rollback_rules`: restore `/tmp/bak_v2ray/<type>.dat`, remove the (empty) backup
/// dir, set `@global[0].flush_set=1` and commit. false for an invalid type (→ `{"code":0}`).
pub fn rollback_rules(geo_type: &str) -> bool {
    if geo_type != "geoip" && geo_type != "geosite" {
        return false;
    }
    let cfg = uci::Config::load(util::CONFIG);
    // upstream quirk: upstream concatenates without adding a missing trailing '/'
    // (rule_update.lua adds it), so rollback could target the wrong file; we normalize.
    let geo_dir = with_slash(&cfg.get("@global_rules[0]", "v2ray_location_asset").unwrap_or_else(|| DEFAULT_ASSET_LOCATION.into()));
    fs_move(&format!("{}{}.dat", BACKUP_PATH, geo_type), &format!("{}{}.dat", geo_dir, geo_type));
    let _ = std::fs::remove_dir(BACKUP_PATH);
    let mut b = uci::Batch::new();
    b.set("passwall2.@global[0].flush_set", "1");
    let _ = b.commit();
    true
}

/// Whether a rollback backup exists for `geoip`/`geosite` (rule_version.htm's buttons).
pub fn has_backup(geo_type: &str) -> bool {
    util::exists(&format!("{}{}.dat", BACKUP_PATH, geo_type))
}

/// State of the geo assets for the UI: `{geoip:{path,exists,size,mtime,backup}, geosite:{...}}`.
pub fn status_json() -> serde_json::Value {
    let cfg = uci::Config::load(util::CONFIG);
    let s = RuleSettings::from_config(&cfg);
    let mut out = serde_json::Map::new();
    for t in ["geoip", "geosite"] {
        let path = format!("{}{}.dat", s.asset_location, t);
        let md = std::fs::metadata(&path).ok();
        let mtime = md
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        out.insert(
            t.to_string(),
            serde_json::json!({
                "path": path,
                "exists": md.is_some(),
                "size": md.as_ref().map(|m| m.len()).unwrap_or(0),
                "mtime": mtime,
                "backup": has_backup(t),
                "url": if t == "geoip" { &s.geoip_url } else { &s.geosite_url },
            }),
        );
    }
    serde_json::Value::Object(out)
}

// ====================================================================== CLI

/// `passwall2 rule-update ...` (see module docs). Upstream layout: `log <targets> [cron]`.
pub fn cli(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        Some("rollback") => {
            if rollback_rules(args.get(1).map(|s| s.as_str()).unwrap_or("")) {
                println!("{{\"code\":1}}");
                0
            } else {
                println!("{{\"code\":0}}");
                1
            }
        }
        Some("status") => {
            println!("{}", status_json());
            0
        }
        Some("log") | None => {
            let cron = args.get(2).map(|s| s.as_str()) == Some("cron");
            run(args.get(1).map(|s| s.as_str()), cron)
        }
        Some(_) => {
            // convenience form without the ignored leading `log`
            let cron = args.get(1).map(|s| s.as_str()) == Some("cron") || args[0] == "cron";
            let targets = if args[0] == "cron" { None } else { Some(args[0].as_str()) };
            run(targets, cron)
        }
    }
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = vec![];
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }
    fn tag(field: u64, wire: u64) -> Vec<u8> {
        varint(field << 3 | wire)
    }
    fn ld(field: u64, data: &[u8]) -> Vec<u8> {
        let mut v = tag(field, 2);
        v.extend(varint(data.len() as u64));
        v.extend_from_slice(data);
        v
    }
    fn vi(field: u64, val: u64) -> Vec<u8> {
        let mut v = tag(field, 0);
        v.extend(varint(val));
        v
    }
    fn cidr(ip: &[u8], prefix: u64) -> Vec<u8> {
        let mut c = ld(1, ip);
        c.extend(vi(2, prefix));
        c
    }
    fn geoip_entry(code: &str, cidrs: &[Vec<u8>]) -> Vec<u8> {
        let mut e = ld(1, code.as_bytes());
        for c in cidrs {
            e.extend(ld(2, c));
        }
        e
    }
    fn check(data: &[u8], t: &str) -> bool {
        validate_geo_reader(Cursor::new(data.to_vec()), data.len() as u64, t)
    }

    fn sample_geoip() -> Vec<u8> {
        let mut list = ld(1, &geoip_entry("CN", &[cidr(&[1, 0, 1, 0], 24), cidr(&[1, 0, 2, 0], 23)]));
        list.extend(ld(1, &geoip_entry("PRIVATE", &[cidr(&[0xfc; 16], 7)])));
        list
    }
    fn sample_geosite() -> Vec<u8> {
        let mut attr = ld(1, b"ads");
        attr.extend(vi(2, 1));
        let mut dom = vi(1, 2);
        dom.extend(ld(2, b"example.com"));
        dom.extend(ld(3, &attr));
        let mut entry = ld(1, b"CATEGORY-ADS");
        entry.extend(ld(2, &dom));
        entry.extend(ld(2, &dom));
        ld(1, &entry)
    }

    #[test]
    fn geo_valid() {
        assert!(check(&sample_geoip(), "geoip"));
        assert!(check(&sample_geosite(), "geosite"));
    }

    #[test]
    fn geo_invalid() {
        assert!(!check(&[], "geoip"));
        assert!(!check(&sample_geoip(), "other"));
        assert!(!check(&sample_geosite(), "geoip"));
        assert!(!check(&sample_geoip(), "geosite"));
        assert!(!check(b"<html>Not Found</html>", "geoip"));
        // truncated
        let g = sample_geoip();
        assert!(!check(&g[..g.len() - 3], "geoip"));
        // bad ip length / prefix
        assert!(!check(&ld(1, &geoip_entry("CN", &[cidr(&[1, 2, 3, 4, 5], 24)])), "geoip"));
        assert!(!check(&ld(1, &geoip_entry("CN", &[cidr(&[1, 2, 3, 4], 33)])), "geoip"));
        assert!(check(&ld(1, &geoip_entry("CN", &[cidr(&[0; 16], 128)])), "geoip"));
        // entry without code
        assert!(!check(&ld(1, &geoip_entry("", &[cidr(&[1, 2, 3, 4], 8)])), "geoip"));
        // entries but no rule
        assert!(!check(&ld(1, &geoip_entry("CN", &[])), "geoip"));
        // domain type > 3
        let mut dom = vi(1, 4);
        dom.extend(ld(2, b"x.com"));
        let mut entry = ld(1, b"X");
        entry.extend(ld(2, &dom));
        assert!(!check(&ld(1, &entry), "geosite"));
        // group wire type
        assert!(!check(&tag(1, 3), "geoip"));
    }

    #[test]
    fn geo_skips_rest_of_category() {
        // garbage after the first sampled rule inside a category is skipped, like upstream
        let mut e = geoip_entry("CN", &[cidr(&[1, 1, 1, 0], 24)]);
        e.extend(ld(2, &[0xff, 0xff]));
        assert!(check(&ld(1, &e), "geoip"));
        // unknown fields with fixed wire types are skipped
        let mut e = geoip_entry("CN", &[cidr(&[1, 1, 1, 0], 24)]);
        e.extend(tag(7, 5));
        e.extend([0, 0, 0, 0]);
        let mut l = ld(1, &e);
        l.extend(tag(9, 1));
        l.extend([0; 8]);
        assert!(check(&l, "geoip"));
    }

    #[test]
    fn curl_output() {
        let out = "HTTP/1.1 302 Found\r\nLocation: x\r\n\r\nHTTP/2 200\r\ncontent-length: 1234\r\n\r\n\n200";
        let (c, h) = parse_curl_output(out);
        assert_eq!(c, 200);
        assert_eq!(h, "HTTP/1.1 302 Found\nLocation: x\n\nHTTP/2 200\ncontent-length: 1234");
        assert_eq!(parse_curl_output("000"), (0, String::new()));
        assert_eq!(parse_curl_output("404"), (404, String::new()));
        assert_eq!(parse_curl_output("curl: (6) err"), (0, String::new()));
        assert_eq!(parse_curl_output(""), (0, String::new()));
        assert_eq!(parse_curl_output("x 200 \n").0, 200);
    }

    #[test]
    fn content_length() {
        let h = "HTTP/1.1 302\nContent-Length: 0\n\nHTTP/2 200\ncontent-length:  555\n";
        assert_eq!(remote_content_length(h), Some(555));
        assert_eq!(remote_content_length("Content-Length: 10\n\nX\ncontent-length: 0"), Some(10));
        assert_eq!(remote_content_length("no headers"), None);
        assert!(size_check(0, "").is_some());
        assert!(size_check(555, h).is_none());
        let (_, a) = size_check(554, h).unwrap();
        assert_eq!(a, vec!["555".to_string(), "554".to_string()]);
        assert!(size_check(7, "HTTP/2 200").is_none());
    }

    #[test]
    fn filenames() {
        let u = "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat";
        assert_eq!(url_filename(u).as_deref(), Some("geoip.dat"));
        assert_eq!(sha_url(u, "geoip.dat"), format!("{}.sha256sum", u));
        assert_eq!(url_filename("https://x.com/a/geo.dat?raw=1").as_deref(), Some("geo.dat"));
        assert_eq!(url_filename("https://x.com/").as_deref(), Some("x.com"));
        assert_eq!(url_filename("https://x.com/dl?f=/a").as_deref(), Some("a"));
        assert_eq!(url_filename("nourl"), None);
        assert_eq!(sha_url("https://h/geoip.dat/geoip.dat", "geoip.dat"), "https://h/geoip.dat.sha256sum/geoip.dat.sha256sum");
    }

    #[test]
    fn sha_line() {
        let h = "a".repeat(64);
        assert_eq!(parse_sha256_line(&format!("{}  geoip.dat\n", h)), Some(h.clone()));
        assert_eq!(parse_sha256_line(&format!("{}\r\n", h)), Some(h.clone()));
        assert_eq!(parse_sha256_line(&format!("{}\n", h)), None); // no whitespace on the line
        assert_eq!(parse_sha256_line(&format!("{}b  f", h)), None);
        assert_eq!(parse_sha256_line("<html>"), None);
        assert_eq!(parse_sha256_line(""), None);
    }

    #[test]
    fn targets() {
        assert_eq!(parse_targets("geoip,geosite"), (true, true));
        assert_eq!(parse_targets("geoip"), (true, false));
        assert_eq!(parse_targets(",geosite,"), (false, true));
        assert_eq!(parse_targets("all"), (false, false));
        assert_eq!(with_slash("/a"), "/a/");
        assert_eq!(with_slash("/a/"), "/a/");
    }

    #[test]
    fn settings_defaults() {
        let cfg = uci::Config::parse("passwall2", "config global_rules\n\toption v2ray_location_asset '/opt/geo'\n");
        let s = RuleSettings::from_config(&cfg);
        assert_eq!(s.asset_location, "/opt/geo/");
        assert_eq!(s.geoip_url, DEFAULT_GEOIP_URL);
        assert_eq!(s.geosite_url, DEFAULT_GEOSITE_URL);
    }

    #[test]
    fn lock_marker_and_compare() {
        let dir = std::env::temp_dir().join(format!("pw2-rules-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("l.lock");
        let l = acquire_update_lock_at(p.to_str().unwrap(), b'r', false).ok();
        assert!(l.is_some());
        assert_eq!(std::fs::read(&p).unwrap(), b"r");
        drop(l);
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"same").unwrap();
        std::fs::write(&b, b"same").unwrap();
        assert!(files_equal(a.to_str().unwrap(), b.to_str().unwrap()));
        std::fs::write(&b, b"diff").unwrap();
        assert!(!files_equal(a.to_str().unwrap(), b.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod real_file_tests {
    /// `PW2_GEO_DIR=/dir cargo test rules::real_file_tests -- --ignored` validates real
    /// geoip.dat / geosite.dat downloads.
    #[test]
    #[ignore]
    fn real_geo_files() {
        let d = std::env::var("PW2_GEO_DIR").unwrap_or_else(|_| "/tmp".into());
        assert!(super::validate_geo_file(&format!("{}/geoip.dat", d), "geoip"));
        assert!(super::validate_geo_file(&format!("{}/geosite.dat", d), "geosite"));
        assert!(!super::validate_geo_file(&format!("{}/geoip.dat", d), "geosite"));
        assert!(!super::validate_geo_file(&format!("{}/geosite.dat", d), "geoip"));
    }
}
