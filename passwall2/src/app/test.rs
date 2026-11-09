//! `test.sh` (spec 01 §17): `passwall2 test test_url URL [TRY] [TIMEOUT] [EXTRA]` and
//! `passwall2 test url_test_node NODE_ID` (used by the node list "URL test" button).

use super::{kill_pids_excluding, list_procs, run_socks, sleep_s, Ctx};
use crate::uci::Config;
use crate::util::{self, Args, TMP_PATH};

fn curl_has_retry_all_errors() -> bool {
    util::cmd_out("curl", &["--help", "all"]).contains("--retry-all-errors")
}

/// `test_url URL [try=1] [timeout=2] [extra]` → HTTP code (`200` for 200/204).
pub fn test_url(url: &str, try_: Option<&str>, timeout: Option<&str>, extra: Option<&str>) -> String {
    let try_ = try_.filter(|s| !s.is_empty()).unwrap_or("1");
    let timeout = timeout.filter(|s| !s.is_empty()).unwrap_or("2");
    let mut extra_params: Vec<String> = extra.unwrap_or("").split_whitespace().map(|s| s.to_string()).collect();
    if curl_has_retry_all_errors() {
        extra_params.insert(0, "--retry-all-errors".into());
    }
    let mut args: Vec<String> = vec!["-I".into(), "-o".into(), "/dev/null".into(), "-skL".into()];
    args.extend(extra_params);
    args.extend(["--connect-timeout".into(), timeout.into(), "--retry".into(), try_.into(), "-w".into(), "%{http_code}".into(), url.into()]);
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let status = util::cmd_out("/usr/bin/curl", &a).trim().to_string();
    match status.as_str() {
        "204" | "200" => "200".into(),
        _ => status,
    }
}

/// `test_proxy` (globals `retry_num` / `connect_timeout` are unset upstream → defaults):
/// 0 = proxy ok, 1 = proxy broken but network ok, 2 = no network.
pub fn test_proxy(retry_num: Option<&str>, connect_timeout: Option<&str>) -> i32 {
    if test_url("https://www.google.com/generate_204", retry_num, connect_timeout, None) == "200" {
        return 0;
    }
    if test_url("https://www.baidu.com", retry_num, connect_timeout, None) == "200" {
        return 1;
    }
    if util::cmd_ok("ping", &["-c", "3", "-W", "1", "223.5.5.5"]) {
        1
    } else {
        2
    }
}

/// `url_test_node NODE_ID` → `"<http_code>:<time_pretransfer>"`, or `0` when the node has no type.
pub fn url_test_node(node_id: &str) -> String {
    let cfg = Config::load(util::CONFIG);
    let typ = cfg.s(node_id, "type").to_lowercase();
    if typ.is_empty() {
        return "0".into();
    }
    let port = util::get_new_port("48900", "tcp,udp");
    let flag = format!("url_test_{}", node_id);
    {
        // upstream: `NO_REC_PROCESS=1 app.sh run_socks ...` (a fresh app.sh: direct DNS only,
        // immediate launch, not recorded for the monitor)
        let mut ctx = Ctx::cli(&cfg);
        ctx.no_rec_process = true;
        let mut a = Args::new();
        a.insert("flag".into(), flag.clone());
        a.insert("node".into(), node_id.into());
        a.insert("bind".into(), "127.0.0.1".into());
        a.insert("socks_port".into(), port.to_string());
        a.insert("config_file".into(), format!("{}.json", flag));
        run_socks(&ctx, &cfg, &a);
    }
    sleep_s(2);
    let probe = cfg.get_or("@global_other[0]", "url_test_url", "https://www.google.com/generate_204");
    let proxy = format!("socks5h://127.0.0.1:{}", port);
    let result = util::cmd_out(
        "curl",
        &["--connect-timeout", "3", "--max-time", "5", "-o", "/dev/null", "-I", "-skL", "-w", "%{http_code}:%{time_pretransfer}", "-x", &proxy, &probe],
    )
    .trim()
    .to_string();
    let pid_file = format!("{}/{}_plugin.pid", TMP_PATH, flag);
    if let Some(pid) = util::read(&pid_file).lines().next().and_then(|l| l.trim().parse::<u32>().ok()) {
        util::kill_pids(&[pid], 9);
    }
    let pids: Vec<u32> = list_procs().into_iter().filter(|p| p.cmdline.contains(&flag) && !p.cmdline.contains("test.sh") && !p.is_self_cmd("test")).map(|p| p.pid).collect();
    kill_pids_excluding(&pids);
    // rm -rf $TMP_PATH/*url_test_<id>*.*
    if let Ok(rd) = std::fs::read_dir(TMP_PATH) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(i) = n.find(&flag) {
                if n[i + flag.len()..].contains('.') {
                    util::rm_rf(&e.path().to_string_lossy());
                }
            }
        }
    }
    // release the port reserved by get_new_port (like socks_switch's test_node); otherwise
    // every URL test leaks one `get_port_<n>` entry until the range 48900-49151 runs out
    util::del_cache_var(&format!("get_port_{}", port));
    if result.is_empty() {
        // curl printed nothing (could not run): upstream echoes an empty line
        return String::new();
    }
    result
}

/// `passwall2 test <test_url|url_test_node|test_proxy> ...`
pub fn cli(args: &[String]) -> i32 {
    let a = |i: usize| args.get(i).map(|s| s.as_str());
    match a(0) {
        Some("test_url") => {
            println!("{}", test_url(a(1).unwrap_or(""), a(2), a(3), a(4)));
            0
        }
        Some("url_test_node") => {
            println!("{}", url_test_node(a(1).unwrap_or("")));
            0
        }
        Some("test_proxy") => {
            println!("{}", test_proxy(a(1), a(2)));
            0
        }
        _ => 0,
    }
}
