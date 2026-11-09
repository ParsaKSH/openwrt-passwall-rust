//! SOCKS auto switch daemon (upstream `socks_auto_switch.sh`).
//! Spec: docs/spec/05-api-helpers.md §6, docs/spec/01-runtime-app.md §5 (start_socks / socks_node_switch).
//!
//! Public API:
//! * [`run`]`(socks_id) -> i32` — the daemon (`passwall2 socks-auto-switch <id>`). app.rs starts it in
//!   the background for every socks section with `enable_autoswitch=1`; it never returns while it
//!   has backup nodes (single instance per id via `/var/lock/passwall2_socks_auto_switch_<id>.lock`).
//! * [`busy_task_running`]`()` / [`check_process`]`()` — "start/stop/firewall/subscribe in progress"
//!   detection shared with the HAProxy external check.
//! * [`test_url`] — curl status probe (`200` for 200/204, `000` on failure).
//!
//! It drives the runtime through our own CLI exactly as upstream drives app.sh:
//! `NO_REC_PROCESS=1 passwall2 app run_socks flag=.. node=.. bind=127.0.0.1 socks_port=.. config_file=..`
//! and `NO_REC_PROCESS=1 passwall2 app socks_node_switch flag=<id> new_node=<node>` (exit 0 = ok).

use crate::api;
use crate::uci::Config;
use crate::util;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";

/// Command lines (argv) of all processes except ourselves.
fn proc_cmdlines() -> Vec<(u32, Vec<String>)> {
    let me = std::process::id();
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) else { continue };
        if raw.is_empty() {
            continue;
        }
        let argv: Vec<String> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).to_string()).collect();
        out.push((pid, argv));
    }
    out
}

/// Does this command line belong to a start/stop, firewall or subscription task?
/// Upstream: `busybox pgrep -af "passwall2/" | grep -E 'app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua'`;
/// our equivalents are `passwall2 start|stop|restart|boot`, `passwall2 app start|stop`,
/// `passwall2 nft|ipt|firewall ...` and `passwall2 subscribe ...`.
pub fn is_busy_cmdline(argv: &[String]) -> bool {
    let line = argv.join(" ");
    if line.contains("passwall2/") {
        if let Some(i) = line.find("app.sh") {
            let rest = &line[i..];
            if rest.contains("start") || rest.contains("stop") {
                return true;
            }
        }
        if line.contains("nftables.sh") || line.contains("iptables.sh") || line.contains("subscribe.lua") {
            return true;
        }
    }
    let Some(a0) = argv.first() else { return false };
    if a0.rsplit('/').next() != Some("passwall2") {
        return false;
    }
    match argv.get(1).map(|s| s.as_str()) {
        Some("start" | "stop" | "restart" | "boot" | "nft" | "ipt" | "firewall" | "subscribe") => true,
        Some("app") => argv[2..].iter().any(|a| a == "start" || a == "stop"),
        _ => false,
    }
}

/// True while a start/stop, firewall script or subscription is running.
pub fn busy_task_running() -> bool {
    proc_cmdlines().iter().any(|(_, a)| is_busy_cmdline(a))
}

/// `check_process`: wait (6 s steps) until no start/stop/firewall/subscribe task runs.
pub fn check_process() {
    while busy_task_running() {
        std::thread::sleep(Duration::from_secs(6));
    }
}

fn curl_retry_all_errors() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| util::cmd_out("/usr/bin/curl", &["--help", "all"]).contains("--retry-all-errors"))
}

/// curl arguments of `test_url` (without the binary).
pub fn test_url_args(url: &str, try_: u64, timeout: u64, extra: &[String], retry_all_errors: bool) -> Vec<String> {
    let max_time = timeout + 3;
    let retry_max_time = max_time * (try_ + 1) + try_;
    let mut a: Vec<String> = vec!["-skIL".into(), "-o".into(), "/dev/null".into()];
    if retry_all_errors {
        a.push("--retry-all-errors".into());
    }
    a.extend(extra.iter().cloned());
    for (k, v) in [
        ("--max-time", max_time.to_string()),
        ("--connect-timeout", timeout.to_string()),
        ("--retry", try_.to_string()),
        ("--retry-delay", "1".to_string()),
        ("--retry-max-time", retry_max_time.to_string()),
        ("-w", "%{http_code}".to_string()),
    ] {
        a.push(k.into());
        a.push(v);
    }
    a.push(url.into());
    a
}

fn curl_status(args: &[String]) -> String {
    let s = match Command::new("/usr/bin/curl").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => "000".to_string(),
    };
    if s == "204" {
        "200".into()
    } else {
        s
    }
}

/// `test_url url try timeout extra repeat`: HTTP status (`204` → `200`, failure → `000`); with
/// `repeat` a 200 is confirmed by a second probe 3 s later.
pub fn test_url(url: &str, try_: u64, timeout: u64, extra: &[String], repeat: bool) -> String {
    let args = test_url_args(url, try_, timeout, extra, curl_retry_all_errors());
    let mut status = curl_status(&args);
    if status == "200" && repeat {
        std::thread::sleep(Duration::from_secs(3));
        status = curl_status(&args);
    }
    status
}

/// Parse a busybox `sleep` argument (`30`, `1.5`, `30s`, `5m`, `1h`, `1d`).
pub fn parse_sleep(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, mul) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1.0),
        'm' => (&s[..s.len() - 1], 60.0),
        'h' => (&s[..s.len() - 1], 3600.0),
        'd' => (&s[..s.len() - 1], 86400.0),
        _ => (s, 1.0),
    };
    let v: f64 = num.parse().ok()?;
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(v * mul))
}

/// Next node after `now` in `list` (cyclic); first node when `now` is absent or last.
pub fn next_node(list: &[String], now: &str) -> String {
    let first = list.first().cloned().unwrap_or_default();
    match list.iter().position(|n| n == now) {
        Some(i) if i + 1 < list.len() => list[i + 1].clone(),
        _ => first,
    }
}

/// Backup list handling of `start()`: `None` = nothing to do (no backups, or the only backup is
/// the main node). With more than one backup and `restore_switch != 1` the main node is appended
/// when it is not already in the list. Returns `(list, original_backup_count)`.
pub fn plan_backup_list(main_node: &str, backup: &str, restore_switch: bool) -> Option<(Vec<String>, usize)> {
    let mut list: Vec<String> = backup.split_whitespace().map(String::from).collect();
    let num = list.len();
    if num == 0 {
        return None;
    }
    if num == 1 && list[0] == main_node {
        return None;
    }
    if num > 1 && !restore_switch && !main_node.is_empty() && !list.iter().any(|n| n == main_node) {
        list.push(main_node.to_string());
    }
    Some((list, num))
}

/// Daemon state (socks section options read once at start, like upstream).
pub struct Switcher {
    pub id: String,
    pub main_node: String,
    pub socks_port: String,
    pub delay: Duration,
    pub connect_timeout: u64,
    pub retry_num: u64,
    pub restore_switch: bool,
    pub probe_url: String,
    pub backup_node: Vec<String>,
    pub backup_node_num: usize,
}

fn num_or(v: String, def: u64) -> u64 {
    v.trim().parse().unwrap_or(def)
}

/// `config_n_get <node> <opt>` (fresh read; subscriptions may change nodes while we run).
fn node_opt(node: &str, opt: &str) -> String {
    Config::load(util::CONFIG).s(node, opt)
}

fn self_cmd(args: &[String]) -> bool {
    Command::new(util::SELF_BIN)
        .args(args)
        .env("NO_REC_PROCESS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

impl Switcher {
    fn proxy_extra(port: &str) -> Vec<String> {
        vec!["-x".into(), format!("socks5h://127.0.0.1:{}", port)]
    }

    /// `test_proxy`: 0 proxy ok, 1 proxy broken but network ok, 2 no network.
    pub fn test_proxy(&self) -> u8 {
        let status = test_url(&self.probe_url, self.retry_num, self.connect_timeout, &Self::proxy_extra(&self.socks_port), false);
        if status == "200" {
            return 0;
        }
        let status2 = test_url("https://www.baidu.com", self.retry_num, self.connect_timeout, &[], false);
        if status2 == "200" {
            return 1;
        }
        if util::cmd_ok("ping", &["-c", "3", "-W", "1", "223.5.5.5"]) {
            1
        } else {
            2
        }
    }

    /// `test_node node_id`: start a temporary socks instance for the node and probe through it
    /// (serialized across instances by `/var/lock/passwall2_socks_auto_switch_test.lock`).
    pub fn test_node(&self, node_id: &str) -> bool {
        let test_flag = format!("test_node_{}_{}", self.id, node_id);
        let Some(_lock) = util::lock(&format!("{}/{}_socks_auto_switch_test.lock", util::LOCK_PATH, util::CONFIG)) else {
            return false;
        };
        let typ = node_opt(node_id, "type").trim().to_lowercase();
        if typ.is_empty() {
            return false;
        }
        check_process();
        let tmp_port = api::get_new_port(Some(48800), "tcp,udp").to_string();
        self_cmd(&[
            "app".into(),
            "run_socks".into(),
            format!("flag={}", test_flag),
            format!("node={}", node_id),
            "bind=127.0.0.1".into(),
            format!("socks_port={}", tmp_port),
            format!("config_file={}.json", test_flag),
        ]);
        std::thread::sleep(Duration::from_secs(2));
        let status = test_url(&self.probe_url, self.retry_num, self.connect_timeout, &Self::proxy_extra(&tmp_port), true);
        cleanup_test(&test_flag);
        // upstream quirk: the reserved test port (cache `get_port_<n>`) is never released, so after
        // a few hundred tests get_new_port runs out of ports; release it.
        api::del_cache_var(&format!("get_port_{}", tmp_port));
        status == "200"
    }

    fn switch_to(&self, node: &str) -> bool {
        self_cmd(&["app".into(), "socks_node_switch".into(), format!("flag={}", self.id), format!("new_node={}", node)])
    }

    /// `try_switch_backup b_nodes now_node`.
    pub fn try_switch_backup(&self, b_nodes: &[String], now_node: &str) -> bool {
        let mut b: Vec<String> = b_nodes.to_vec();
        // Only one backup node, alternate with the primary node.
        if self.backup_node_num == 1 && !self.main_node.is_empty() {
            b.push(self.main_node.clone());
        }
        let total = b.len();
        let mut now = now_node.to_string();
        let port = self.socks_port.as_str();
        for _ in 0..total {
            let new_node = next_node(&b, &now);
            let role = if new_node == self.main_node { api::translate("main node") } else { api::translate("next backup node") };
            let ntype = node_opt(&new_node, "type");
            let nrem = node_opt(&new_node, "remarks");
            api::log_i18n(0, "Socks switch detection: Port [%s] try %s [%s:%s].", &[port, &role, &ntype, &nrem]);
            if self.test_node(&new_node) {
                check_process();
                api::log_i18n(0, "Socks switch detection: Port [%s] [%s:[%s]] normal, switch to this node!", &[port, &ntype, &nrem]);
                if self.switch_to(&new_node) {
                    api::log_i18n(0, "Socks switch detection: Port [%s] node switch complete!", &[port]);
                    return true;
                }
                api::log_i18n(0, "Socks switch detection: Port [%s] node switch failed, continue trying other nodes!", &[port]);
            } else {
                api::log_i18n(0, "Socks switch detection: Port [%s] [%s:[%s]] abnormal.", &[port, &ntype, &nrem]);
            }
            now = new_node;
        }
        api::log_i18n(0, "Socks switch detection: Port [%s] all nodes are unavailable or switching failed!", &[port]);
        false
    }

    /// `test_auto_switch b_nodes`: 0 ok/switched, 1 failed, 2 no network.
    pub fn test_auto_switch(&self, b_nodes: &[String]) -> u8 {
        let Some(now_node) = api::get_cache_var(&self.id) else { return 1 };
        let port = self.socks_port.as_str();
        let mut status = self.test_proxy();
        if status == 2 {
            api::log_i18n(0, "Socks switch detection: Port [%s] Unable to connect to the network. Please check if the network is working properly!", &[port]);
            return 2;
        }
        // Check if the main node is usable
        if self.restore_switch && !self.main_node.is_empty() && now_node != self.main_node && self.test_node(&self.main_node) {
            check_process();
            api::log_i18n(
                0,
                "Socks switch detection: Port [%s] Primary node [%s: [%s]] is normal. Switch to the primary node!",
                &[port, &node_opt(&self.main_node, "type"), &node_opt(&self.main_node, "remarks")],
            );
            if self.switch_to(&self.main_node) {
                api::log_i18n(0, "Socks switch detection: Port [%s] node switch complete!", &[port]);
                return 0;
            }
            api::log_i18n(0, "Socks switch detection: Port [%s] failed to restore the primary node!", &[port]);
            status = 1;
        }
        if status == 0 {
            return 0;
        }
        api::log_i18n(0, "Socks switch detection: Port [%s] [%s:[%s]] abnormal.", &[port, &node_opt(&now_node, "type"), &node_opt(&now_node, "remarks")]);
        if self.try_switch_backup(b_nodes, &now_node) {
            0
        } else {
            1
        }
    }
}

/// Kill and remove everything a `test_node` run left behind.
fn cleanup_test(test_flag: &str) {
    let pid_file = format!("{}/{}_plugin.pid", util::TMP_PATH, test_flag);
    if let Some(pid) = util::read(&pid_file).lines().next().and_then(|l| l.trim().parse::<u32>().ok()) {
        util::kill_pids(&[pid], 9);
    }
    let p1 = format!("{}/{}.", util::TMP_PATH, test_flag);
    let p2 = format!("{}/{}_", util::TMP_PATH, test_flag);
    let pids: Vec<u32> = proc_cmdlines()
        .into_iter()
        .filter(|(_, a)| {
            let l = a.join(" ");
            (l.contains(&p1) || l.contains(&p2)) && !l.contains("socks_auto_switch.sh") && !l.contains("socks-auto-switch")
        })
        .map(|(p, _)| p)
        .collect();
    util::kill_pids(&pids, 9);
    // rm -f "$TMP_PATH/${test_flag}"*.*
    if let Ok(rd) = std::fs::read_dir(util::TMP_PATH) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix(test_flag) {
                if rest.contains('.') && e.file_type().map(|t| !t.is_dir()).unwrap_or(false) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
}

/// The daemon (`start()` of socks_auto_switch.sh).
pub fn run(id: &str) -> i32 {
    let id = id.trim();
    if id.is_empty() {
        return 1;
    }
    let lock_file = format!("{}/{}_socks_auto_switch_{}.lock", util::LOCK_PATH, util::CONFIG, id);
    let Some(_lock) = util::try_lock(&lock_file) else { return 0 };
    let cfg = Config::load(util::CONFIG);
    let restore_switch = cfg.get_or(id, "autoswitch_restore_switch", "0") == "1";
    let delay_s = cfg.get_or(id, "autoswitch_testing_time", "30");
    let mut sw = Switcher {
        id: id.to_string(),
        main_node: cfg.s(id, "node"),
        socks_port: cfg.get_or(id, "port", "0"),
        // upstream quirk: an unparsable delay makes `sleep` fail and the loop spin; use 30 s.
        delay: parse_sleep(&delay_s).unwrap_or(Duration::from_secs(30)),
        connect_timeout: num_or(cfg.get_or(id, "autoswitch_connect_timeout", "3"), 3),
        retry_num: num_or(cfg.get_or(id, "autoswitch_retry_num", "1"), 1),
        restore_switch,
        probe_url: cfg.get_or(id, "autoswitch_probe_url", DEFAULT_PROBE_URL),
        backup_node: vec![],
        backup_node_num: 0,
    };
    let backup = api::get_socks_backup_nodes(&cfg, id);
    let num = backup.split_whitespace().count();
    api::log_i18n(0, "Socks switch detection: Port [%s] Number of backup nodes: %s", &[&sw.socks_port, &num.to_string()]);
    let Some((list, n)) = plan_backup_list(&sw.main_node, &backup, restore_switch) else { return 0 };
    sw.backup_node = list;
    sw.backup_node_num = n;
    loop {
        check_process();
        sw.test_auto_switch(&sw.backup_node);
        std::thread::sleep(sw.delay);
    }
}

/// `passwall2 socks-auto-switch <socks_id>`
pub fn cli(args: &[String]) -> i32 {
    match args.first() {
        Some(id) => run(id),
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn t_next_node() {
        let l = v("a b c");
        assert_eq!(next_node(&l, "a"), "b");
        assert_eq!(next_node(&l, "c"), "a");
        assert_eq!(next_node(&l, "x"), "a");
        assert_eq!(next_node(&[], "x"), "");
    }

    #[test]
    fn t_plan() {
        assert_eq!(plan_backup_list("m", "", false), None);
        assert_eq!(plan_backup_list("m", "m", false), None);
        assert_eq!(plan_backup_list("m", "b", false), Some((v("b"), 1)));
        assert_eq!(plan_backup_list("m", "b c", false), Some((v("b c m"), 2)));
        assert_eq!(plan_backup_list("m", "b m", false), Some((v("b m"), 2)));
        assert_eq!(plan_backup_list("m", "b c", true), Some((v("b c"), 2)));
    }

    #[test]
    fn t_sleep() {
        assert_eq!(parse_sleep("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_sleep("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_sleep("1.5"), Some(Duration::from_millis(1500)));
        assert_eq!(parse_sleep("x"), None);
    }

    #[test]
    fn t_curl_args() {
        let a = test_url_args("https://x/", 1, 3, &v("-x socks5h://127.0.0.1:1080"), true);
        assert_eq!(
            a.join(" "),
            "-skIL -o /dev/null --retry-all-errors -x socks5h://127.0.0.1:1080 --max-time 6 --connect-timeout 3 --retry 1 --retry-delay 1 --retry-max-time 13 -w %{http_code} https://x/"
        );
    }

    #[test]
    fn t_busy() {
        assert!(is_busy_cmdline(&v("/bin/sh /usr/share/passwall2/app.sh start")));
        assert!(is_busy_cmdline(&v("/bin/sh /usr/share/passwall2/nftables.sh stop")));
        assert!(is_busy_cmdline(&v("/usr/bin/passwall2 restart")));
        assert!(is_busy_cmdline(&v("passwall2 subscribe start abc cron")));
        assert!(is_busy_cmdline(&v("/usr/bin/passwall2 app stop")));
        assert!(!is_busy_cmdline(&v("/usr/bin/passwall2 app run_socks flag=x")));
        assert!(!is_busy_cmdline(&v("/usr/bin/passwall2 socks-auto-switch abc")));
        assert!(!is_busy_cmdline(&v("/tmp/etc/passwall2/bin/xray run -c /tmp/etc/passwall2/acl/default.json")));
    }
}
