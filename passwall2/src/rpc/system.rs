//! Subscribe / rules / components / backup / misc endpoints (controller spec 07 §A.3).

use super::params::{is_safe_name, is_sid, split_keep_empty, Params};
use super::store::Store;
use super::{run_self, spawn_self};
use crate::api;
use crate::uci::Config;
use crate::util;
use serde_json::{json, Value};

const C: &str = util::CONFIG;

// ---------------------------------------------------------------- link_add_node

pub const LINKS_FILE: &str = "/tmp/links.conf";

/// Append (index 0: truncate) one chunk; true when it was the last one.
pub fn write_chunk(path: &str, chunk: &[u8], index: f64, total: f64) -> std::io::Result<bool> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).write(true).append(index != 0.0).truncate(index == 0.0).open(path)?;
    f.write_all(chunk)?;
    Ok(index + 1.0 == total)
}

/// `link_add_node {chunk, chunk_index, total_chunks, group}`: collect the share links in
/// `/tmp/links.conf`; after the last chunk run `passwall2 subscribe add <group>` (synchronous).
pub fn link_add_node(p: &Params) -> Value {
    let group = p.or("group", "default");
    if let (Some(chunk), Some(idx), Some(total)) = (p.get("chunk"), p.num("chunk_index"), p.num("total_chunks")) {
        if let Ok(true) = write_chunk(LINKS_FILE, chunk.as_bytes(), idx, total) {
            if group.is_empty() {
                run_self(&["subscribe", "add"]);
            } else {
                run_self(&["subscribe", "add", &group]);
            }
        }
    }
    json!({})
}

// ---------------------------------------------------------------- gen_client_config

/// `gen_client_config {id}`: the client config `app run_socks ... no_run=1` generates for the
/// node (returned as the JSON object itself, like upstream's response body).
pub fn gen_client_config(p: &Params) -> Value {
    let id = p.s("id");
    if !is_sid(&id) {
        return json!({"code": 0, "redirect": "node_list"});
    }
    let config_file = format!("{}/config_{}", util::TMP_PATH, id);
    let _ = std::fs::remove_file(&config_file);
    let a = [
        "app".to_string(),
        "run_socks".into(),
        format!("flag=config_{}", id),
        format!("node={}", id),
        "bind=127.0.0.1".into(),
        "socks_port=1080".into(),
        format!("config_file={}", config_file),
        "no_run=1".into(),
    ];
    let a: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
    run_self(&a);
    if !util::exists(&config_file) {
        return json!({"code": 0, "redirect": "node_list"});
    }
    let text = util::read(&config_file);
    let _ = std::fs::remove_file(&config_file);
    match serde_json::from_str::<Value>(&text) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({"result": text}),
    }
}

// ---------------------------------------------------------------- rules

pub fn update_rules(p: &Params) -> Value {
    let update = p.s("update");
    if update.is_empty() {
        return json!({"code": 0, "data": {"message": "missing update target"}});
    }
    // upstream single-quotes the value into a shell command; we pass it as one argv word
    if !update.bytes().all(|c| c.is_ascii_alphanumeric() || c == b',' || c == b'_') {
        return json!({"code": 0, "data": {"message": "missing update target"}});
    }
    crate::rules::update_rules_bg(&update);
    json!({"code": 1})
}

pub fn rollback_rules(p: &Params) -> Value {
    if crate::rules::rollback_rules(&p.s("type")) {
        json!({"code": 1})
    } else {
        json!({"code": 0})
    }
}

pub fn flush_set(p: &Params) -> Value {
    let redirect = p.or("redirect", "0");
    let reload = p.or("reload", "0");
    let mut st = Store::load(C);
    st.set("@global[0]", "flush_set", "1");
    st.save(reload == "1");
    if redirect == "1" {
        json!({"redirect": "log"})
    } else {
        json!({})
    }
}

// ---------------------------------------------------------------- geo_view

/// `get_rules(str, type)`: shunt rules whose `ip_list` (geoip) / `domain_list` contain `s`
/// → (id, group or translated "default").
pub fn geo_rules(cfg: &Config, s: &str, geo_type: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let str_is_ip = api::dt_ipaddr(s) || api::dt_ip6addr(s);
    for sec in cfg.sections_of("shunt_rules") {
        let list = sec.list_raw(if geo_type == "geoip" { "ip_list" } else { "domain_list" }).join("\n");
        for line in list.split(['\r', '\n']) {
            if line.is_empty() || line.contains('#') {
                continue;
            }
            let main = match line.split_once(':') {
                Some((_, m)) => m,
                None => line,
            };
            let hit = if geo_type == "geoip" && str_is_ip { main.contains(s) } else { main == s };
            if hit {
                out.push((sec.name.clone(), sec.get("group").unwrap_or_else(|| api::translate("default"))));
            }
        }
    }
    out
}

/// Format a geoview `lookup` result like the controller.
pub fn format_lookup(cfg: &Config, geo_type: &str, output: &str, value: &str) -> String {
    let out = output.to_lowercase();
    if out.is_empty() {
        return String::new();
    }
    let mut lines = vec![];
    let mut rules = vec![];
    let mut seen = std::collections::HashSet::new();
    for line in out.split('\n').filter(|l| !l.is_empty()) {
        lines.push(format!("{}:{}", geo_type, line));
        for (id, g) in geo_rules(cfg, line, geo_type) {
            if seen.insert(id.clone()) {
                rules.push(format!("[{}]{}", g, id));
            }
        }
    }
    for (id, g) in geo_rules(cfg, value, geo_type) {
        if seen.insert(id.clone()) {
            rules.push(format!("[{}]{}", g, id));
        }
    }
    let mut s = lines.join("\n");
    if !rules.is_empty() {
        s.push_str("\n--------------------\n");
        s.push_str(&api::translate("Rules containing this value:"));
        s.push('\n');
        s.push_str(&rules.join("\n"));
    }
    s
}

/// `value:match("^(geoip:)(.*)$")` / geosite → (type, list) with a non-empty list.
pub fn parse_extract(value: &str) -> Option<(&'static str, &str)> {
    for t in ["geoip", "geosite"] {
        if let Some(l) = value.strip_prefix(t).and_then(|r| r.strip_prefix(':')) {
            return if l.is_empty() { None } else { Some((t, l)) };
        }
    }
    None
}

fn geoview_out(bin: &str, args: &[&str]) -> String {
    use std::process::{Command, Stdio};
    Command::new(bin).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
}

/// `geo_view {action, value}` → `{"result": "<text>"}`.
pub fn geo_view(p: &Params) -> Value {
    let action = p.s("action");
    let value = p.s("value");
    if value.is_empty() {
        return json!({"result": api::translate("Please enter query content!")});
    }
    let cfg = Config::load(C);
    let asset = cfg.get("@global_rules[0]", "v2ray_location_asset").unwrap_or_else(|| "/usr/share/v2ray/".into());
    let mut geo_string = String::new();
    // upstream: `asset:match("^(.*)/")` (nil without '/' → error) and `%q` of a nil binary → error
    if let (Some(i), Some(bin)) = (asset.rfind('/'), api::finded_com("geoview")) {
        let geo_dir = &asset[..i];
        let geosite = format!("{}/geosite.dat", geo_dir);
        let geoip = format!("{}/geoip.dat", geo_dir);
        if action == "lookup" {
            let (t, f) = if api::dt_ipaddr(&value) || api::dt_ip6addr(&value) { ("geoip", &geoip) } else { ("geosite", &geosite) };
            let out = geoview_out(&bin, &["-type", t, "-action", "lookup", "-input", f, "-value", &value, "-lowmem=true"]);
            geo_string = format_lookup(&cfg, t, &out, &value);
        } else if action == "extract" {
            if let Some((t, list)) = parse_extract(&value) {
                let f = if t == "geoip" { &geoip } else { &geosite };
                geo_string = geoview_out(&bin, &["-type", t, "-action", "extract", "-input", f, "-list", list, "-lowmem=true"]);
            }
        }
    }
    if geo_string.is_empty() {
        geo_string = api::translate("No results were found!");
    }
    json!({"result": geo_string})
}

// ---------------------------------------------------------------- subscribe

pub fn subscribe_del_node(p: &Params) -> Value {
    let remark = p.s("remark");
    if !remark.is_empty() {
        run_self(&["subscribe", "truncate", &remark]);
    }
    json!({})
}

pub fn subscribe_del_all() -> Value {
    run_self(&["subscribe", "truncate"]);
    json!({})
}

fn sub_missing() -> Value {
    json!({"success": false, "msg": "Missing section or URL, skip."})
}
fn sub_unsaved() -> Value {
    json!({"success": false, "msg": api::translate("Please save and apply before manually subscribing.")})
}
fn sub_ok() -> Value {
    json!({"success": true, "msg": "Subscribe triggered."})
}

fn stored_url(section: &str) -> String {
    if is_sid(section) {
        api::sh_uci_get(C, section, "url")
    } else {
        String::new()
    }
}

/// A subscription URL as stored by `subscribe_manual*`: an `http(s)://` (or scheme-less) URL
/// or a local path, never something curl could parse as an option (`-K/tmp/x`) or with control
/// characters (see [`api::curl_url_ok`]).
pub fn valid_sub_url(url: &str) -> bool {
    api::curl_url_ok(url)
}

fn sub_bad_url() -> Value {
    json!({"success": false, "msg": "Invalid subscription URL."})
}

pub fn subscribe_manual(p: &Params) -> Value {
    let section = p.s("section");
    let url = p.s("url");
    if section.is_empty() || url.is_empty() {
        return sub_missing();
    }
    if !valid_sub_url(&url) {
        return sub_bad_url();
    }
    let uci_url = stored_url(&section);
    if uci_url.is_empty() {
        return sub_unsaved();
    }
    if uci_url != url {
        api::sh_uci_set(C, &section, "url", &url, true);
    }
    spawn_self(&["subscribe", "start", &section, "manual"]);
    sub_ok()
}

pub fn subscribe_manual_all(p: &Params) -> Value {
    let sections = p.s("sections");
    let urls = p.s("urls");
    if sections.is_empty() || urls.is_empty() {
        return sub_missing();
    }
    let section_list = split_keep_empty(&sections);
    let url_list = split_keep_empty(&urls);
    if url_list.iter().any(|u| !u.is_empty() && !valid_sub_url(u)) {
        return sub_bad_url();
    }
    if section_list.iter().any(|s| stored_url(s).is_empty()) {
        return sub_unsaved();
    }
    for (i, section) in section_list.iter().enumerate() {
        let cur = url_list.get(i).cloned().unwrap_or_default();
        if !cur.is_empty() && stored_url(section) != cur {
            api::sh_uci_set(C, section, "url", &cur, true);
        }
    }
    spawn_self(&["subscribe", "start", "all", "manual"]);
    sub_ok()
}

// ---------------------------------------------------------------- components

fn invalid_task() -> Value {
    json!({"code": 1, "error": api::translate("Invalid download task.")})
}

fn valid_com(com: &str) -> bool {
    com == api::APPNAME || api::COM_ORDER.contains(&com)
}

fn bad_com() -> Value {
    json!({"code": 1, "error": "Invalid component."})
}

/// `com_check {com}` (`check_<com>`, `check_passwall2`).
pub fn com_check(p: &Params) -> Value {
    let com = p.s("com");
    if !valid_com(&com) {
        return bad_com();
    }
    if com == api::APPNAME {
        // passwall2-rs updates itself from its own GitHub releases (not upstream's packages)
        let _ = p.get("accept_language");
        return api::to_check_self_rs();
    }
    api::to_check(p.get("arch").as_deref().filter(|a| !a.is_empty()), &com)
}

/// Download part number of `update_passwall2` (integer 1..=5, default 1).
pub fn parse_part(v: Option<f64>) -> Option<u32> {
    let part = v.unwrap_or(1.0);
    if !(1.0..=5.0).contains(&part) || part.fract() != 0.0 {
        return None;
    }
    Some(part as u32)
}

fn app_update(p: &Params) -> Value {
    let id = p.s("id");
    if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
        return invalid_task();
    }
    let task = p.s("task");
    if task == "progress" {
        return api::to_download_progress(api::APPNAME, &id, p.get("total_size").as_deref());
    }
    if task == "install" {
        return api::to_install_self_rs(&id, &p.s("force"));
    }
    let Some(part) = parse_part(p.num("part")) else { return invalid_task() };
    api::to_download(api::APPNAME, &p.s("url"), p.get("size").as_deref(), Some(&format!("{}{}", id, part)), part > 1)
}

/// `com_update {com, task, ...}` (`update_<com>`, `update_passwall2`).
pub fn com_update(p: &Params) -> Value {
    let com = p.s("com");
    if !valid_com(&com) {
        return bad_com();
    }
    if com == api::APPNAME {
        return app_update(p);
    }
    match p.s("task").as_str() {
        "progress" => api::to_download_progress(&com, &p.s("id"), p.get("total_size").as_deref()),
        // `subfix` is accepted for parity; the archive type comes from the component table
        "extract" => api::to_extract(&com, &p.s("file")),
        "move" => api::to_move(&com, &p.s("file")),
        _ => api::to_download(&com, &p.s("url"), p.get("size").as_deref(), p.get("id").as_deref(), false),
    }
}

/// `com_version {com}` → `{"code":1,"data":"<version>"}`.
pub fn com_version(p: &Params) -> Value {
    let com = p.s("com");
    if !valid_com(&com) {
        return bad_com();
    }
    let v = if com == api::APPNAME { api::get_version() } else { api::get_app_version(&com, None) };
    json!({"code": 1, "data": v})
}

// ---------------------------------------------------------------- backup / restore / reset

pub const BACKUP_FILES: [&str; 3] = ["/etc/config/passwall2", "/etc/config/passwall2_server", "/usr/share/passwall2/domains_excluded"];

/// `create_backup` → `{"result": "<base64 tar.gz>", "filename": "passwall2-<yymmddHHMM>-backup.tar.gz"}`.
pub fn create_backup() -> Value {
    use base64::Engine;
    let date = util::cmd_out("date", &["+%y%m%d%H%M"]).trim().to_string();
    let name = format!("passwall2-{}-backup.tar.gz", date);
    let tar_file = format!("/tmp/{}", name);
    let _ = std::fs::remove_file(&tar_file);
    let mut args: Vec<&str> = vec!["-czf", &tar_file];
    // busybox tar aborts on a missing member; upstream's archive just lacks it
    args.extend(BACKUP_FILES.iter().filter(|f| util::exists(f)).copied());
    util::cmd_ok("tar", &args);
    let data = std::fs::read(&tar_file).unwrap_or_default();
    let _ = std::fs::remove_file(&tar_file);
    if data.is_empty() {
        return json!({"code": 0, "error": "Backup failed!"});
    }
    json!({"result": base64::engine::general_purpose::STANDARD.encode(&data), "filename": name})
}

/// One `restore_backup` chunk into `<dir>/<filename>`: Ok(Some(path)) after the last chunk,
/// Ok(None) for intermediate chunks, Err(message) like upstream.
pub fn restore_chunk(dir: &str, filename: Option<&str>, chunk: Option<&str>, index: f64, total: f64) -> Result<Option<String>, String> {
    use base64::Engine;
    let Some(filename) = filename else { return Err("Missing filename".into()) };
    let Some(chunk) = chunk else { return Err("Missing chunk data".into()) };
    let file_path = format!("{}/{}", dir, filename);
    // upstream writes /tmp/<filename> unchecked (path traversal)
    if !is_safe_name(filename) {
        return Err(format!("Failed to open file: {}", file_path));
    }
    let clean: String = chunk.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let decoded = base64::engine::general_purpose::STANDARD.decode(clean.as_bytes()).map_err(|_| "Base64 decode failed".to_string())?;
    // upstream quirk: upstream opens "a+" for every chunk, so a leftover file from an aborted
    // upload corrupts the next one; chunk 0 truncates here.
    match write_chunk(&file_path, &decoded, index, total) {
        Ok(true) => Ok(Some(file_path)),
        Ok(false) => Ok(None),
        Err(_) => Err(format!("Failed to open file: {}", file_path)),
    }
}

fn pw_log(msg: &str) {
    api::log(0, &format!(" * PassWall2 {}", api::translate(msg)));
}

/// Archive member name without a leading `./` or `/` (busybox/GNU tar strip `/` on create).
fn member_name(n: &str) -> &str {
    let mut n = n.trim_end_matches(['\r', '\n']);
    loop {
        if let Some(r) = n.strip_prefix("./") {
            n = r;
        } else if let Some(r) = n.strip_prefix('/') {
            n = r;
        } else {
            return n;
        }
    }
}

/// Members a backup may contain: the three [`BACKUP_FILES`] and directory entries (`.../`)
/// of their parents. `names` = `tar -tzf`, `verbose` = `tar -tvzf` (symlinks and hard links
/// are refused: they could make the restore copy, or tar write, files outside the archive).
pub fn backup_members_ok(names: &str, verbose: &str) -> bool {
    let files: Vec<&str> = BACKUP_FILES.iter().map(|f| member_name(f)).collect();
    let mut any = false;
    for raw in names.lines() {
        let n = member_name(raw);
        if n.is_empty() || n == "." {
            continue;
        }
        if files.contains(&n) {
            any = true;
            continue;
        }
        let is_parent_dir = n.ends_with('/') && files.iter().any(|f| f.starts_with(n));
        if !is_parent_dir {
            return false;
        }
    }
    let links = verbose.lines().any(|l| l.starts_with('l') || l.starts_with('h') || l.contains(" -> ") || l.contains(" link to "));
    any && !links
}

/// Contents of the extracted `<root>/<rel>`: every component must be a real directory (no
/// symlink), the file a regular file with a single link, opened with O_NOFOLLOW.
pub fn read_extracted(root: &str, rel: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let rel = member_name(rel);
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return None;
    }
    let mut path = std::path::PathBuf::from(root);
    for (i, part) in parts.iter().enumerate() {
        path.push(part);
        let m = std::fs::symlink_metadata(&path).ok()?;
        let last = i + 1 == parts.len();
        if (!last && !m.file_type().is_dir()) || (last && (!m.file_type().is_file() || m.nlink() != 1)) {
            return None;
        }
    }
    // Linux O_NOFOLLOW (arm/arm64/powerpc use their own value, the rest asm-generic's)
    #[cfg(any(target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64"))]
    const O_NOFOLLOW: i32 = 0o100000;
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")))]
    const O_NOFOLLOW: i32 = 0o400000;
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(&path).ok()?;
    if !f.metadata().ok()?.file_type().is_file() {
        return None;
    }
    let mut data = vec![];
    f.read_to_end(&mut data).ok()?;
    Some(data)
}

/// `restore_backup {filename, chunk, chunk_index, total_chunks}` (also accepts `file_name`).
pub fn restore_backup(p: &Params) -> Value {
    let filename = p.get("filename").or_else(|| p.get("file_name"));
    let index = p.num("chunk_index").unwrap_or(-1.0);
    let total = p.num("total_chunks").unwrap_or(-1.0);
    let file_path = match restore_chunk("/tmp", filename.as_deref(), p.get("chunk").as_deref(), index, total) {
        Err(m) => return json!({"status": "error", "message": m}),
        Ok(None) => return json!({"status": "success", "message": "Chunk received"}),
        Ok(Some(f)) => f,
    };
    crate::uci::revert(C);
    let _ = std::fs::write(util::LOG_FILE, "\n");
    pw_log("Configuration file uploaded successfully…");
    let result = restore_archive(&file_path);
    let _ = std::fs::remove_file(&file_path);
    match result {
        Ok(()) => {
            // a backup made by an older passwall2 may use the legacy schema
            crate::migrate::run("restore backup");
            pw_log("Configuration restored successfully…");
            pw_log("Service restarting…");
            for init in ["/etc/init.d/passwall2", "/etc/init.d/passwall2_server"] {
                util::spawn_bg(init, &["restart".to_string()], "/dev/null");
            }
            json!({"status": "success", "message": "Upload completed", "path": file_path})
        }
        Err(()) => {
            pw_log("Configuration file decompression failed, please try again!");
            json!({"status": "error", "message": "Decompression failed"})
        }
    }
}

/// Validate and extract the uploaded archive into a fresh private directory, then install
/// the regular files among [`BACKUP_FILES`] it contains. Upstream extracts into the fixed
/// `/tmp/passwall2_bak` and `cp -f`s the members, which follows symlinks/hard links planted
/// in the archive (reading e.g. /etc/shadow into a LuCI-readable file).
fn restore_archive(file_path: &str) -> Result<(), ()> {
    let names = util::cmd_out("tar", &["-tzf", file_path]);
    let verbose = util::cmd_out("tar", &["-tvzf", file_path]);
    if !backup_members_ok(&names, &verbose) {
        return Err(());
    }
    // mktemp -d: new directory, mode 0700, owned by us
    let temp_dir = api::trim(&util::cmd_out("mktemp", &["-d", "-p", "/tmp", "passwall2_bak.XXXXXX"]));
    if !temp_dir.starts_with("/tmp/passwall2_bak.") || !std::fs::symlink_metadata(&temp_dir).map(|m| m.is_dir()).unwrap_or(false) {
        return Err(());
    }
    let ok = util::cmd_ok("tar", &["-xzf", file_path, "-C", &temp_dir]);
    let mut contents = vec![];
    if ok {
        for f in BACKUP_FILES {
            if let Some(data) = read_extracted(&temp_dir, f) {
                contents.push((f, data));
            }
        }
    }
    util::rm_rf(&temp_dir);
    if !ok || contents.is_empty() {
        return Err(());
    }
    for (f, data) in contents {
        let _ = std::fs::write(f, data);
    }
    Ok(())
}

/// Seconds `reset_config` waits for the service stop before answering (LuCI's rpc timeout
/// is 20 s; rpcd kills a plugin that runs past its exec timeout).
const RESET_WAIT_SECS: u64 = 15;

/// `reset_config`: revert, clear log, stop, restore `0_default_config`.
///
/// The stop (which may block on the service lock while a restart waits up to 600 s for a
/// subscription/rule update) and the copy of the default config run together in a detached
/// child, so the reset completes even when the stop outlives this rpcd call; we wait for it
/// up to [`RESET_WAIT_SECS`] so the usual case still answers after the config was reset.
pub fn reset_config() -> Value {
    crate::uci::revert(C);
    let _ = std::fs::write(util::LOG_FILE, "\n");
    let def = format!("{}/0_default_config", util::APP_PATH);
    let dst = format!("{}/passwall2", crate::uci::conf_dir());
    let script = "/etc/init.d/passwall2 stop >/dev/null 2>&1; [ -f \"$1\" ] && cp -f \"$1\" \"$2\"";
    let child = spawn_detached("/bin/sh", &["-c", script, "sh", &def, &dst]);
    let done = match child {
        Some(mut c) => {
            let mut done = false;
            for _ in 0..RESET_WAIT_SECS * 10 {
                if let Ok(Some(_)) = c.try_wait() {
                    done = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            done
        }
        None => false,
    };
    if done {
        json!({"redirect": ""})
    } else {
        json!({"redirect": "", "pending": true})
    }
}

/// Start `prog args` in its own session with stdio on /dev/null (it outlives us if needed and
/// never holds rpcd's stdout pipe open).
fn spawn_detached(prog: &str, args: &[&str]) -> Option<std::process::Child> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    extern "C" {
        fn setsid() -> i32;
    }
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // SAFETY: setsid(2) is async-signal-safe and only detaches the child from our session.
    unsafe {
        cmd.pre_exec(|| {
            setsid();
            Ok(())
        });
    }
    cmd.spawn().ok()
}

fn purge_luci_cache() {
    if let Ok(rd) = std::fs::read_dir("/tmp") {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("luci-") {
                util::rm_rf(&e.path().to_string_lossy());
            }
        }
    }
    // upstream restarts rpcd, which drops every LuCI session (logout) and does not refresh
    // the menu: the ucode dispatcher keeps the page tree in memory inside uhttpd. Restart
    // uhttpd instead (sessions live in rpcd), detached and after our reply was delivered.
    util::spawn_bg("/bin/sh", &["-c".to_string(), "sleep 1; [ -x /etc/init.d/uhttpd ] && /etc/init.d/uhttpd restart".to_string()], "/dev/null");
}

pub fn show_menu() -> Value {
    api::sh_uci_del(C, "@global[0]", "hide_from_luci", true);
    purge_luci_cache();
    json!({"redirect": ""})
}

pub fn hide_menu() -> Value {
    api::sh_uci_set(C, "@global[0]", "hide_from_luci", "1", true);
    purge_luci_cache();
    json!({"redirect": "/admin/status/overview"})
}

// ---------------------------------------------------------------- misc

pub fn fetch_certsha256(p: &Params) -> Value {
    let id = p.s("id");
    if id.is_empty() || !is_sid(&id) {
        return json!({"code": 0});
    }
    let cfg = Config::load(C);
    let address = cfg.s(&id, "address");
    // upstream: a missing port/address raises a Lua error; treat as failure
    let port = cfg.get(&id, "port").and_then(|v| v.trim().parse::<u16>().ok()).unwrap_or(0);
    let sni = cfg.get(&id, "tls_serverName").filter(|s| !s.is_empty()).unwrap_or_else(|| address.clone());
    if address.is_empty() || port == 0 {
        return json!({"code": 0});
    }
    let data = api::fetch_cert_sha256(&address, Some(port), Some(&sni), Some(5));
    if data.is_empty() {
        json!({"code": 0})
    } else {
        json!({"code": 1, "data": data})
    }
}

pub fn gen_wireguard_key() -> Value {
    match api::gen_wireguard_key() {
        Some((private_key, public_key)) => json!({"code": 1, "data": {"private_key": private_key, "public_key": public_key}}),
        None => json!({"code": 0}),
    }
}

/// `set_default_cbi` language detection: first `[%w-]+` token of Accept-Language (`-`→`_`,
/// as-is then lowercased) that is a `luci.languages` entry.
pub fn match_accept_language(accept: &str, known: impl Fn(&str) -> bool) -> Option<String> {
    let mut tok = String::new();
    let mut toks = vec![];
    for c in accept.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '-' {
            tok.push(c);
        } else if !tok.is_empty() {
            toks.push(std::mem::take(&mut tok));
        }
    }
    for t in toks {
        let l = t.replace('-', "_");
        if known(&l) {
            return Some(l);
        }
        let low = l.to_lowercase();
        if known(&low) {
            return Some(low);
        }
    }
    None
}

/// `set_auto_lang {accept_language}`: what upstream does on every CBI page load when
/// `luci.main.lang == auto` (writes `@global[0].auto_lang`, used for backend translations).
pub fn set_auto_lang(p: &Params) -> Value {
    let luci = Config::load("luci");
    let lang = luci.get("main", "lang").unwrap_or_else(|| "auto".into());
    if lang != "auto" {
        return json!({"code": 1, "lang": lang});
    }
    match match_accept_language(&p.s("accept_language"), |l| luci.get("languages", l).is_some()) {
        Some(l) => {
            if api::sh_uci_get(C, "@global[0]", "auto_lang") != l {
                api::sh_uci_set(C, "@global[0]", "auto_lang", &l, true);
            }
            json!({"code": 1, "lang": l})
        }
        None => json!({"code": 0, "lang": "auto"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("pw2rpc_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    #[test]
    fn chunks() {
        let d = tmpdir("chunks");
        let f = format!("{}/l.conf", d);
        assert!(!write_chunk(&f, b"ab", 0.0, 2.0).unwrap());
        assert!(write_chunk(&f, b"cd", 1.0, 2.0).unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "abcd");
        // index 0 truncates
        assert!(write_chunk(&f, b"x", 0.0, 1.0).unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "x");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restore_chunks() {
        let d = tmpdir("restore");
        assert_eq!(restore_chunk(&d, None, Some("YQ=="), 0.0, 1.0), Err("Missing filename".into()));
        assert_eq!(restore_chunk(&d, Some("a.tar.gz"), None, 0.0, 1.0), Err("Missing chunk data".into()));
        assert_eq!(restore_chunk(&d, Some("a.tar.gz"), Some("@@@"), 0.0, 1.0), Err("Base64 decode failed".into()));
        assert!(restore_chunk(&d, Some("../x"), Some("YQ=="), 0.0, 1.0).unwrap_err().starts_with("Failed to open file"));
        assert_eq!(restore_chunk(&d, Some("a.tar.gz"), Some("aGVs"), 0.0, 2.0), Ok(None));
        let r = restore_chunk(&d, Some("a.tar.gz"), Some("bG8="), 1.0, 2.0).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&r).unwrap(), "hello");
        // defaults (-1/-1) never finish
        assert_eq!(restore_chunk(&d, Some("b"), Some("YQ=="), -1.0, -1.0), Ok(None));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn geoview_rules() {
        let cfg = Config::parse(
            "passwall2",
            "config shunt_rules 'cn'\n\tlist domain_list 'geosite:cn'\n\tlist domain_list 'full:x.com'\n\tlist domain_list '# geosite:google'\n\tlist ip_list 'geoip:cn'\n\tlist ip_list '1.2.3.0/24'\n\nconfig shunt_rules 'g'\n\toption group 'grp'\n\tlist domain_list 'geosite:google'\n\tlist domain_list 'geosite:cn'\n",
        );
        assert_eq!(geo_rules(&cfg, "cn", "geosite").len(), 2);
        assert_eq!(geo_rules(&cfg, "x.com", "geosite"), vec![("cn".to_string(), api::translate("default"))]);
        assert!(geo_rules(&cfg, "google", "geosite").iter().any(|(id, g)| id == "g" && g == "grp"));
        // commented line ignored
        assert_eq!(geo_rules(&cfg, "google", "geosite").len(), 1);
        // IP → substring match on ip_list
        assert_eq!(geo_rules(&cfg, "1.2.3.0", "geoip").len(), 1);
        let s = format_lookup(&cfg, "geosite", "CN\n", "x.com");
        assert!(s.starts_with("geosite:cn\n--------------------\n"));
        assert!(s.ends_with("]cn\n[grp]g"));
        assert_eq!(format_lookup(&cfg, "geosite", "", "x"), "");
        assert_eq!(format_lookup(&cfg, "geosite", "abc", "zzz"), "geosite:abc");
        assert_eq!(parse_extract("geoip:cn"), Some(("geoip", "cn")));
        assert_eq!(parse_extract("geosite:gfw"), Some(("geosite", "gfw")));
        assert_eq!(parse_extract("geosite:"), None);
        assert_eq!(parse_extract("cn"), None);
        assert_eq!(geo_view(&Params::default())["result"], json!(api::translate("Please enter query content!")));
    }

    #[test]
    fn parts_and_coms() {
        assert_eq!(parse_part(None), Some(1));
        assert_eq!(parse_part(Some(5.0)), Some(5));
        assert_eq!(parse_part(Some(0.0)), None);
        assert_eq!(parse_part(Some(6.0)), None);
        assert_eq!(parse_part(Some(1.5)), None);
        assert!(valid_com("xray") && valid_com("sing-box") && valid_com("geoview") && valid_com("passwall2"));
        assert!(!valid_com("haproxy"));
        assert_eq!(com_update(&Params::from_json(r#"{"com":"passwall2","id":"bad id"}"#))["code"], json!(1));
        assert_eq!(com_check(&Params::from_json(r#"{"com":"x"}"#))["code"], json!(1));
        assert_eq!(update_rules(&Params::default())["code"], json!(0));
        assert_eq!(update_rules(&Params::from_json(r#"{"update":"a;b"}"#))["code"], json!(0));
        assert_eq!(rollback_rules(&Params::from_json(r#"{"type":"x"}"#)), json!({"code": 0}));
    }

    #[test]
    fn subscribe_validation() {
        assert_eq!(subscribe_manual(&Params::from_json(r#"{"section":"s"}"#)), sub_missing());
        assert_eq!(subscribe_manual_all(&Params::from_json(r#"{"sections":"a"}"#)), sub_missing());
        // option-like / multi-line URLs are refused before anything is stored
        assert_eq!(subscribe_manual(&Params::from_json(r#"{"section":"s","url":"-K/tmp/c"}"#)), sub_bad_url());
        assert_eq!(subscribe_manual(&Params::from_json(r#"{"section":"s","url":"https://a\nb"}"#)), sub_bad_url());
        assert_eq!(subscribe_manual_all(&Params::from_json(r#"{"sections":"a,b","urls":"https://ok,-K/tmp/c"}"#)), sub_bad_url());
        assert!(valid_sub_url("https://example.com/sub"));
        assert!(valid_sub_url("/tmp/local_sub.txt"));
        assert!(!valid_sub_url("file:///etc/shadow"));
    }

    #[test]
    fn backup_members() {
        let ok = "etc/config/passwall2\netc/config/passwall2_server\nusr/share/passwall2/domains_excluded\n";
        let v = "-rw-r--r-- root/root 10 2026-01-01 00:00:00 etc/config/passwall2\n";
        assert!(backup_members_ok(ok, v));
        assert!(backup_members_ok("./etc/\n./etc/config/\n./etc/config/passwall2\n", v));
        assert!(backup_members_ok("/etc/config/passwall2\n", v));
        // unknown members, traversal, a symlinked directory and empty archives are refused
        assert!(!backup_members_ok("etc/config/passwall2\netc/crontabs/root\n", v));
        assert!(!backup_members_ok("etc/config/passwall2\n../../etc/x\n", v));
        assert!(!backup_members_ok("etc/config\netc/config/passwall2\n", v));
        assert!(!backup_members_ok("", ""));
        assert!(!backup_members_ok("etc/\n", "drwxr-xr-x root/root 0 2026-01-01 00:00:00 etc/\n"));
        // symlink / hard link members (busybox and GNU tar -tv formats)
        assert!(!backup_members_ok(ok, "lrwxrwxrwx root/root 0 2026-01-01 00:00:00 usr/share/passwall2/domains_excluded -> /etc/shadow\n"));
        assert!(!backup_members_ok(ok, "hrw-r--r-- root/root 0 2026-01-01 00:00 etc/config/passwall2 link to etc/shadow\n"));
        assert!(!backup_members_ok(ok, "-rw-r--r-- root/root 0 2026-01-01 00:00:00 etc/config/passwall2 -> etc/shadow\n"));
    }

    #[test]
    fn extracted_files() {
        let d = tmpdir("extract");
        std::fs::create_dir_all(format!("{}/etc/config", d)).unwrap();
        std::fs::create_dir_all(format!("{}/usr/share", d)).unwrap();
        std::fs::write(format!("{}/etc/config/passwall2", d), "cfg").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", format!("{}/etc/config/passwall2_server", d)).unwrap();
        std::os::unix::fs::symlink("/etc", format!("{}/usr/share/passwall2", d)).unwrap();
        assert_eq!(read_extracted(&d, "/etc/config/passwall2").as_deref(), Some(&b"cfg"[..]));
        assert_eq!(read_extracted(&d, "/etc/config/passwall2_server"), None);
        assert_eq!(read_extracted(&d, "/usr/share/passwall2/hostname"), None);
        assert_eq!(read_extracted(&d, "/etc/../etc/config/passwall2"), None);
        // hard link (nlink 2) is refused
        std::fs::hard_link(format!("{}/etc/config/passwall2", d), format!("{}/etc/hl", d)).unwrap();
        assert_eq!(read_extracted(&d, "/etc/config/passwall2"), None);
        assert_eq!(read_extracted(&d, "/etc/missing"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn accept_language() {
        let known = |l: &str| ["zh_Hans", "fa", "en", "zh_cn"].contains(&l);
        assert_eq!(match_accept_language("fa-IR,fa;q=0.9,en;q=0.8", known), Some("fa".into()));
        assert_eq!(match_accept_language("zh-Hans", known), Some("zh_Hans".into()));
        assert_eq!(match_accept_language("zh-CN", known), Some("zh_cn".into()));
        assert_eq!(match_accept_language("de-DE, q=1", known), None);
        assert_eq!(match_accept_language("", known), None);
    }
}
