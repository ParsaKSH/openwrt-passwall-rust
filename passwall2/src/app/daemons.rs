//! Long-running helpers: `monitor.sh` (process watchdog), `tasks.sh` (interval updates) and
//! `lease2hosts.sh` (DHCP leases → hosts file for the dnsmasq copies). Spec 01 §8 / §17.

use super::{cmd_check, list_procs, self_bin, sleep_s, spawn_shell};
use crate::uci::Config;
use crate::util::{self, LOCK_PATH, TMP_PATH, TMP_PATH2, TMP_SCRIPT_FUNC_PATH};
use std::collections::BTreeMap;

// ====================================================================== monitor.sh

/// `monitor.sh`: respawn every recorded process (script_func entries) that is no longer
/// running, every 58 s. Exits immediately unless `enabled` and `start_daemon` are both 1.
pub fn monitor() -> i32 {
    let lock_file = format!("{}/passwall2_monitor.lock", LOCK_PATH);
    let cfg = Config::load(util::CONFIG);
    if cfg.get_or("@global[0]", "enabled", "0") != "1" {
        return 1;
    }
    if cfg.get_or("@global_delay[0]", "start_daemon", "0") != "1" {
        return 1;
    }
    sleep_s(58);
    loop {
        // Reap cores that died (and earlier respawns' shells): the Child handles from
        // spawn_shell are dropped, so without this every exited child stays a zombie of this
        // never-exiting daemon. Safe: this process is single-threaded and its own
        // `Command::output()` calls wait for their child synchronously.
        util::reap_children();
        if util::exists(&lock_file) {
            sleep_s(6);
            continue;
        }
        util::write(&lock_file, "");
        cap_logs(LOG_CAP_BYTES);
        monitor_pass();
        let _ = std::fs::remove_file(&lock_file);
        sleep_s(58);
    }
}

/// Largest size a runtime log may reach before the monitor empties it.
pub const LOG_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// Empty every `*.log` under the runtime dir (core logs such as `acl/default/global.log`) and
/// the main log once it is larger than `cap`. /tmp is RAM: with loglevel `info`, upstream's
/// core log grew to 253 MB in a week on a 512 MB router and filled /tmp.
/// upstream quirk: upstream never limits these logs. Cores write through O_APPEND descriptors
/// (see `spawn_out`/`append_redirect`), so truncation restarts them at offset 0.
pub fn cap_logs(cap: u64) {
    let mut files = Vec::new();
    super::find_files(TMP_PATH, &|n: &str| n.ends_with(".log"), &mut files);
    files.push(util::LOG_FILE.to_string());
    for f in files {
        let Ok(md) = std::fs::metadata(&f) else { continue };
        if md.len() <= cap {
            continue;
        }
        if let Ok(fh) = std::fs::OpenOptions::new().write(true).open(&f) {
            if fh.set_len(0).is_ok() {
                util::log(0, &format!("{} exceeded {} MB, truncated.", f, cap / (1024 * 1024)));
            }
        }
    }
}

/// One watchdog pass (exposed for tests / manual use).
pub fn monitor_pass() {
    let mut names: Vec<String> = match std::fs::read_dir(TMP_SCRIPT_FUNC_PATH) {
        Ok(rd) => rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| !n.starts_with('_')).collect(),
        Err(_) => return,
    };
    names.sort();
    let procs = list_procs();
    for n in names {
        let cmd = util::read(&format!("{}/{}", TMP_SCRIPT_FUNC_PATH, n)).trim().to_string();
        if cmd.is_empty() {
            continue;
        }
        let check = cmd_check(&cmd);
        if !procs.iter().any(|p| p.cmdline.contains(&check)) {
            util::log(0, &format!("{} crashed, restarting.", cmd));
            spawn_shell(&cmd);
        }
    }
}

// ====================================================================== tasks.sh

/// `expr T % (interval*60) == 0` with shell `expr` failure semantics (empty / non-numeric /
/// zero interval → false).
pub fn interval_due(t: i64, interval_hours: &str) -> bool {
    let Ok(h) = interval_hours.trim().parse::<i64>() else { return false };
    let m = h * 60;
    m != 0 && t % m == 0
}

/// `tasks.sh`: every 10 minutes run the "every N hours" (week mode 8) restart / rule update /
/// subscription jobs that are due.
pub fn tasks() -> i32 {
    let lock_file = format!("{}/passwall2_tasks.lock", LOCK_PATH);
    let Some(_lock) = util::try_lock(&lock_file) else { return 0 };
    let me = self_bin();
    let mut t: i64 = 0;
    loop {
        // reap the restart / rule-update / subscribe jobs started in earlier rounds
        util::reap_children();
        if t != 0 {
            let cfg = Config::load(util::CONFIG);
            if cfg.s("@global_delay[0]", "restart_week_mode") == "8" && interval_due(t, &cfg.s("@global_delay[0]", "restart_interval_mode")) {
                spawn_shell("/etc/init.d/passwall2 restart cron >/dev/null");
            }
            if cfg.s("@global_rules[0]", "update_week_mode") == "8" && interval_due(t, &cfg.s("@global_rules[0]", "update_interval_mode")) {
                let _ = util::spawn_bg(&me, &["rule-update".into(), "log".into(), "all".into(), "cron".into()], "/dev/null");
            }
            for (interval, ids) in sub_interval_groups(&cfg) {
                if interval_due(t, &interval) {
                    let _ = util::spawn_bg(&me, &["subscribe".into(), "start".into(), ids.join(","), "cron".into()], "/dev/null");
                }
            }
        }
        t += 10;
        sleep_s(600);
    }
}

/// subscribe_list sections with `update_week_mode == 8` and an interval, grouped by interval
/// (upstream `$TMP_PATH/sub_tasks/8_<interval>` files, `ls` order).
pub fn sub_interval_groups(cfg: &Config) -> BTreeMap<String, Vec<String>> {
    let mut g: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in cfg.sections_of("subscribe_list") {
        if s.s("update_week_mode") == "8" {
            let iv = s.s("update_interval_mode");
            if !iv.is_empty() {
                g.entry(iv).or_default().push(s.name.clone());
            }
        }
    }
    g
}

// ====================================================================== lease2hosts.sh

fn valid_name(n: &str) -> bool {
    let mut it = n.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => {}
        _ => return false,
    }
    it.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// awk numeric value of a field (leading numeric prefix, else 0).
fn awk_num(s: &str) -> f64 {
    let b = s.trim().as_bytes();
    let mut end = 0;
    let mut seen_digit = false;
    let mut seen_dot = false;
    while end < b.len() {
        let c = b[end];
        if c.is_ascii_digit() {
            seen_digit = true;
        } else if c == b'.' && !seen_dot {
            seen_dot = true;
        } else if (c == b'-' || c == b'+') && end == 0 {
        } else {
            break;
        }
        end += 1;
    }
    if !seen_digit {
        return 0.0;
    }
    s.trim()[..end].parse().unwrap_or(0.0)
}

/// `read_odhcpd_leases` (state records and legacy hosts-format lines).
pub fn parse_odhcpd_leases(text: &str, now: i64) -> Vec<String> {
    let mut out = vec![];
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() == Some(&"#") {
            if f.len() < 9 || !valid_name(f[4]) {
                continue;
            }
            let exp = awk_num(f[5]);
            if exp != -1.0 && exp <= now as f64 {
                continue;
            }
            let len = awk_num(f[7]);
            if !((f[3] == "ipv4" && len == 32.0) || (f[3] != "ipv4" && len == 128.0)) {
                continue;
            }
            for a in &f[8..] {
                let addr = a.split('/').next().unwrap_or("");
                out.push(format!("{} {}", addr, f[4]));
            }
            continue;
        }
        if f.len() >= 2 && f[0].chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
            for n in &f[1..] {
                if n.starts_with('#') {
                    break;
                }
                if valid_name(n) {
                    out.push(format!("{} {}", f[0], n));
                }
            }
        }
    }
    out
}

/// dnsmasq lease file: `NF >= 4 && $4 != "*"` → `$3 $4`.
pub fn parse_dnsmasq_leases(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 4 && f[3] != "*" {
                Some(format!("{} {}", f[2], f[3]))
            } else {
                None
            }
        })
        .collect()
}

/// Static `dhcp` `host` sections with a name (≠ `*`) and ip (≠ `ignore`) → `"<ip> <name>"`.
pub fn static_hosts(dhcp: &Config) -> Vec<String> {
    dhcp.sections_of("host")
        .filter_map(|s| {
            let name = s.s("name");
            let ip = s.s("ip");
            if !name.is_empty() && name != "*" && !ip.is_empty() && ip != "ignore" {
                Some(format!("{} {}", ip, name))
            } else {
                None
            }
        })
        .collect()
}

/// `kill -HUP` every live pid listed in `$TMP_PATH/acl/**/*_dnsmasq.pid`.
pub fn reload_dnsmasq_pids() {
    let mut files = vec![];
    super::find_files(&format!("{}/acl", TMP_PATH), &|n| n.ends_with("_dnsmasq.pid"), &mut files);
    for f in files {
        let pid = util::read(&f).lines().next().unwrap_or("").trim().parse::<u32>().ok();
        if let Some(pid) = pid {
            if util::exists(&format!("/proc/{}", pid)) {
                util::kill_pids(&[pid], 1);
            }
        }
    }
}

/// `lease2hosts.sh` daemon: every 60 s merge static hosts + dnsmasq + odhcpd leases into
/// `/tmp/etc/passwall2_tmp/dhcp-hosts` and HUP the dnsmasq copies when it changes.
pub fn lease2hosts() -> i32 {
    let lock_file = format!("{}/passwall2_lease2hosts.lock", LOCK_PATH);
    let Some(_lock) = util::try_lock(&lock_file) else { return 0 };
    let dhcp = Config::load("dhcp");
    let dnsmasq_lease = dhcp.get_or("@dnsmasq[0]", "leasefile", "/tmp/dhcp.leases");
    let odhcpd_lease = dhcp.get_or("odhcpd", "leasefile", "/tmp/odhcpd.leases");
    let hosts_file = format!("{}/dhcp-hosts", TMP_PATH2);
    let statics = static_hosts(&dhcp);
    loop {
        let mut lines: Vec<String> = statics.clone();
        if util::exists(&dnsmasq_lease) {
            lines.extend(parse_dnsmasq_leases(&util::read(&dnsmasq_lease)));
        }
        if util::exists(&odhcpd_lease) {
            lines.extend(parse_odhcpd_leases(&util::read(&odhcpd_lease), util::epoch() as i64));
        }
        lines.sort();
        lines.dedup();
        let new = if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) };
        let cur = std::fs::read_to_string(&hosts_file).ok();
        if !new.is_empty() {
            if cur.as_deref() != Some(new.as_str()) {
                // write to /tmp/dhcp-hosts.tmp then move into place (atomic for dnsmasq)
                let tmp = "/tmp/dhcp-hosts.tmp";
                if !(util::write(tmp, &new) && std::fs::rename(tmp, &hosts_file).is_ok()) {
                    util::write(&hosts_file, &new);
                    let _ = std::fs::remove_file(tmp);
                }
                reload_dnsmasq_pids();
            }
        } else if cur.is_some_and(|c| !c.is_empty()) {
            util::write(&hosts_file, "");
            reload_dnsmasq_pids();
        }
        sleep_s(60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_redirect_respawn() {
        use crate::app::append_redirect;
        assert_eq!(
            append_redirect("/tmp/etc/passwall2/bin/xray run -c /tmp/a.json >/tmp/a.log"),
            ": >/tmp/a.log; exec /tmp/etc/passwall2/bin/xray run -c /tmp/a.json >>/tmp/a.log 2>&1"
        );
        assert_eq!(append_redirect("x run >/dev/null"), "exec x run >/dev/null 2>&1");
        assert_eq!(append_redirect("x run"), "exec x run 2>&1");
    }

    #[test]
    fn appended_log_truncates_cleanly() {
        use std::io::Write;
        let p = std::env::temp_dir().join(format!("pw2cap{}.log", std::process::id()));
        std::fs::write(&p, vec![b'a'; 100]).unwrap();
        let mut w = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        std::fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(0).unwrap();
        w.write_all(b"new").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn odhcpd() {
        let t = "# br-lan 0001 1 pc1 -1 x 128 fd00::5/128 fd00::6/128\n# br-lan 0001 1 bad! -1 x 128 fd00::7/128\n# br-lan 0001 1 old 100 x 128 fd00::8/128\n# br-lan 0001 1 pd -1 x 64 fd00:1::/64\n# br-lan 01aa ipv4 v4 -1 x 32 192.168.1.9/32\nfd00::10 host1 alias.lan #comment more\n";
        assert_eq!(
            parse_odhcpd_leases(t, 1000),
            vec!["fd00::5 pc1", "fd00::6 pc1", "192.168.1.9 v4", "fd00::10 host1", "fd00::10 alias.lan"]
        );
    }

    #[test]
    fn dnsmasq_leases() {
        let t = "1700000000 aa:bb 192.168.1.2 phone 01:aa\n1700000000 aa:cc 192.168.1.3 * 01:cc\nshort line\n";
        assert_eq!(parse_dnsmasq_leases(t), vec!["192.168.1.2 phone"]);
    }

    #[test]
    fn statics() {
        let c = Config::parse("dhcp", "config host\n\toption name 'nas'\n\toption ip '192.168.1.5'\nconfig host\n\toption name '*'\n\toption ip '1.1.1.1'\nconfig host\n\toption name 'x'\n\toption ip 'ignore'\n");
        assert_eq!(static_hosts(&c), vec!["192.168.1.5 nas"]);
    }

    #[test]
    fn intervals() {
        assert!(interval_due(120, "2"));
        assert!(!interval_due(130, "2"));
        assert!(!interval_due(120, ""));
        assert!(!interval_due(120, "0"));
        assert!(!interval_due(120, "x"));
    }

    #[test]
    fn sub_groups() {
        let c = Config::parse(
            "passwall2",
            "config subscribe_list 'a'\n\toption update_week_mode '8'\n\toption update_interval_mode '6'\nconfig subscribe_list 'b'\n\toption update_week_mode '8'\n\toption update_interval_mode '6'\nconfig subscribe_list 'c'\n\toption update_week_mode '8'\nconfig subscribe_list 'd'\n\toption update_week_mode '1'\n\toption update_interval_mode '6'\n",
        );
        let g = sub_interval_groups(&c);
        assert_eq!(g.len(), 1);
        assert_eq!(g["6"], vec!["a".to_string(), "b".to_string()]);
    }
}
