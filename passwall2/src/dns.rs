//! dnsmasq helper (upstream `helper_dnsmasq.lua`) + the chinadns-ng / dnsmasq "direct ipset"
//! DNS config generators used by app.sh (`run_ipset_chinadns_ng`, `run_ipset_dnsmasq`).
//! Spec: docs/spec/05-api-helpers.md §4, docs/spec/01-runtime-app.md §6/§7.
//!
//! Public API for app.rs:
//! * [`stretch`] — `helper_dnsmasq.lua stretch`.
//! * [`restart`]`(log)` — `helper_dnsmasq.lua restart '{"LOG":..}'`.
//! * [`logic_restart`]`(log)` — `helper_dnsmasq.lua logic_restart`.
//! * [`copy_instance`]`(&Args)` — vars `LISTEN_PORT`, `DNSMASQ_CONF`, optional `TMP_DNSMASQ_PATH`,
//!   `return` ("1" → nothing written, lines only returned).
//! * [`add_rule`]`(&Args)` — vars `FLAG`, `TMP_DNSMASQ_PATH`, `DNSMASQ_CONF_FILE` (may be `"nil"`),
//!   `DEFAULT_DNS`, `LOCAL_DNS`, `TUN_DNS`, `NFTFLAG`, `NO_LOGIC_LOG`.
//! * [`default_dnsmasq_cfgid`], [`default_dnsmasq_conf_dir`] — the `get_config` lookups of the
//!   main dnsmasq instance (`DEFAULT_DNSMASQ_CONF = <dir>/dnsmasq-passwall2.conf`).
//! * [`write_vpslist`], [`chinadns_ng_ipset_config`], [`ipset_dnsmasq_config`] — config text of
//!   `run_ipset_chinadns_ng` / `run_ipset_dnsmasq` (the caller writes it and launches the binary).
//! * CLI: `passwall2 dns-helper <stretch|restart|logic_restart|copy_instance|add_rule> ['<json>']`.

use crate::api;
use crate::uci::{Batch, Config};
use crate::util::{self, Args, ArgsExt};
use indexmap::IndexMap;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

/// `api.CACHE_PATH`
const CACHE_PATH: &str = util::TMP_PATH2;
const DNSMASQ_SECTION: &str = "@dnsmasq[0]";

/// Lua `tinsert`: append only when not already present.
fn tinsert(list: &mut Vec<String>, val: &str) -> bool {
    if list.iter().any(|x| x == val) {
        return false;
    }
    list.push(val.to_string());
    true
}

fn uci_cmd() -> Command {
    let mut c = Command::new("uci");
    if let Ok(d) = std::env::var("PASSWALL2_UCI_DIR") {
        c.arg("-c").arg(d);
    }
    c
}
fn uci_show(target: &str) -> String {
    uci_cmd()
        .args(["-q", "show", target])
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// `uci_get("dhcp","@dnsmasq[0]","server")` as a list (empty when unset).
fn dnsmasq_servers(dhcp: &Config) -> Vec<String> {
    dhcp.list_raw(DNSMASQ_SECTION, "server")
}

fn dnsmasq_restart() {
    util::sh_ok("/etc/init.d/dnsmasq restart >/dev/null 2>&1");
}

/// `api.uci_set(config, section, option, list)`: set the list, or delete when empty.
fn set_list_or_delete(b: &mut Batch, path: &str, list: &[String]) {
    if list.is_empty() {
        b.delete(path);
    } else {
        b.set_list(path, list);
    }
}

/// `backup_servers()`: save the main dnsmasq `server` list to `passwall2.@global[0].dnsmasq_servers`.
fn backup_servers() {
    let dhcp = Config::load("dhcp");
    let servers = dnsmasq_servers(&dhcp);
    if !servers.is_empty() {
        let mut b = Batch::new();
        b.set_list("passwall2.@global[0].dnsmasq_servers", &servers);
        let _ = b.commit();
    }
}

/// `restore_servers()`: merge current + backed up server lists back into dhcp.
fn restore_servers() {
    let dhcp = Config::load("dhcp");
    let pw = Config::load(util::CONFIG);
    let mut dns_table: Vec<String> = vec![];
    for v in dnsmasq_servers(&dhcp) {
        tinsert(&mut dns_table, &v);
    }
    let old = pw.list_raw("@global[0]", "dnsmasq_servers");
    if !old.is_empty() {
        for v in &old {
            tinsert(&mut dns_table, v);
        }
        let mut b = Batch::new();
        b.delete("passwall2.@global[0].dnsmasq_servers");
        let _ = b.commit();
    }
    if !dns_table.is_empty() {
        let mut b = Batch::new();
        b.set_list("dhcp.@dnsmasq[0].server", &dns_table);
        let _ = b.commit();
    }
}

/// Resolv file chosen by `stretch`: `/tmp/resolv.conf.d/resolv.conf.auto` when it exists and is
/// non-empty, else `/tmp/resolv.conf.auto`.
pub fn auto_resolvfile() -> String {
    let p = "/tmp/resolv.conf.d/resolv.conf.auto";
    match std::fs::metadata(p) {
        Ok(m) if m.len() > 0 => p.to_string(),
        _ => "/tmp/resolv.conf.auto".to_string(),
    }
}

/// `stretch()`: if the main dnsmasq has no generic upstream (`server` entries without `/`) but
/// `noresolv=1`, drop `noresolv` and point `resolvfile` at the auto resolv file.
pub fn stretch() {
    let dhcp = Config::load("dhcp");
    let servers = dnsmasq_servers(&dhcp);
    let flag = servers.iter().any(|v| !v.contains('/'));
    if !flag && dhcp.get(DNSMASQ_SECTION, "noresolv").as_deref() == Some("1") {
        let mut b = Batch::new();
        b.delete("dhcp.@dnsmasq[0].noresolv");
        b.set("dhcp.@dnsmasq[0].resolvfile", &auto_resolvfile());
        let _ = b.commit();
    }
}

/// `restart(var)`: `/etc/init.d/dnsmasq restart`; `log` = `var.LOG == "1"`.
pub fn restart(log: bool) {
    dnsmasq_restart();
    if log {
        api::log(0, &api::translate("Restart dnsmasq service."));
    }
}

/// `logic_restart(var)`: when cache `DEFAULT_DNS` is set, restart dnsmasq with only the
/// domain-specific `server` entries (so passwall's own `server=` lines are used), then restore
/// the UCI server list; otherwise a plain restart.
pub fn logic_restart(log: bool) {
    if api::get_cache_var("DEFAULT_DNS").is_some() {
        backup_servers();
        let dhcp = Config::load("dhcp");
        let servers = dnsmasq_servers(&dhcp);
        if !servers.is_empty() {
            let mut dns_table: Vec<String> = vec![];
            for v in servers.iter().filter(|v| v.contains('/')) {
                tinsert(&mut dns_table, v);
            }
            let mut b = Batch::new();
            set_list_or_delete(&mut b, "dhcp.@dnsmasq[0].server", &dns_table);
            let _ = b.commit();
        }
        dnsmasq_restart();
        restore_servers();
    } else {
        dnsmasq_restart();
    }
    if log {
        api::log(0, &api::translate("Restart dnsmasq service."));
    }
}

/// Section id of `dhcp.@dnsmasq[0]` (e.g. `cfg01411c`), as
/// `uci -q show dhcp.@dnsmasq[0] | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}'`.
pub fn default_dnsmasq_cfgid() -> String {
    parse_cfgid(&uci_show("dhcp.@dnsmasq[0]"))
}
fn parse_cfgid(show: &str) -> String {
    show.lines().next().and_then(|l| l.split(['.', '=']).nth(1)).unwrap_or("").to_string()
}

/// Generated config of the main dnsmasq instance: `/var/etc/dnsmasq.conf.<cfgid>`.
pub fn default_dnsmasq_conf_file() -> String {
    format!("/var/etc/dnsmasq.conf.{}", default_dnsmasq_cfgid())
}

/// app.sh `get_config`: conf-dir of the main dnsmasq (first `conf-dir=` of its generated config,
/// trailing `/` stripped), default `/tmp/dnsmasq.d`.
pub fn default_dnsmasq_conf_dir() -> String {
    let f = default_dnsmasq_conf_file();
    conf_dir_from(&util::read(&f))
}
fn conf_dir_from(text: &str) -> String {
    let def = "/tmp/dnsmasq.d".to_string();
    // awk -F '=' '{print $2}': the text between the first and the second '='.
    match text.lines().find(|l| l.starts_with("conf-dir=")).map(|l| l.split('=').nth(1).unwrap_or("")) {
        Some(d) if !d.is_empty() => d.strip_suffix('/').unwrap_or(d).to_string(),
        _ => def,
    }
}

/// Filter the main dnsmasq config for a copy instance (pure part of `copy_instance`).
/// Returns `(kept_lines, conf_dirs)`; `conf_dirs` are the `conf-dir=` values encountered.
pub fn filter_dnsmasq_conf(text: &str) -> (Vec<String>, Vec<String>) {
    let mut lines: Vec<String> = vec![];
    let mut dirs = vec![];
    for line in text.lines() {
        let mut filter = line.contains("passwall2") || line.contains("ubus") || line.contains("dhcp") || line.starts_with("server=") || line.starts_with("port=");
        if let Some(d) = line.strip_prefix("conf-dir=") {
            filter = true;
            dirs.push(d.to_string());
        }
        if line.starts_with("address=") || (line.starts_with("server=") && line.contains('/')) {
            filter = false;
        }
        if !filter {
            tinsert(&mut lines, line);
        }
    }
    (lines, dirs)
}

/// `copy_instance(var)`: build a dnsmasq config for a dedicated copy instance listening on
/// `LISTEN_PORT`, based on the main instance's generated config. Appends to `DNSMASQ_CONF`
/// unless `return == "1"`. Returns the lines.
pub fn copy_instance(var: &Args) -> Vec<String> {
    let listen_port = var.s("LISTEN_PORT");
    let tmp_dnsmasq_path = var.g("TMP_DNSMASQ_PATH");
    let conf_file = default_dnsmasq_conf_file();

    let mut retry = 5;
    while !util::exists(&conf_file) && retry > 0 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        retry -= 1;
    }

    let mut conf_lines: Vec<String> = vec![];
    if util::exists(&conf_file) {
        let (lines, dirs) = filter_dnsmasq_conf(&util::read(&conf_file));
        if let Some(tmp) = tmp_dnsmasq_path {
            for d in dirs {
                util::sh_ok(&format!("cp -r {}/* {}/ 2>/dev/null", util::shq(&d), util::shq(tmp)));
            }
        }
        conf_lines = lines;
    } else {
        util::cmd_ok(
            "logger",
            &["-t", "passwall2", &format!("ERROR: dnsmasq config {} not found after 5s wait! DNS hijacking will fail.", conf_file)],
        );
    }

    tinsert(&mut conf_lines, &format!("port={}", listen_port));
    let hosts = format!("{}/dhcp-hosts", CACHE_PATH);
    touch(&hosts);
    tinsert(&mut conf_lines, &format!("addn-hosts={}", hosts));
    if let Some(tmp) = tmp_dnsmasq_path {
        remove_matching(tmp, |n| n.contains("passwall2"));
    }
    if var.g("return") == Some("1") {
        return conf_lines;
    }
    if !conf_lines.is_empty() {
        append_lines(&var.s("DNSMASQ_CONF"), &conf_lines);
    }
    conf_lines
}

fn touch(p: &str) {
    let _ = std::fs::OpenOptions::new().create(true).append(true).open(p);
}

/// `rm -rf <dir>/<glob>` for entries whose name satisfies `pred`.
fn remove_matching(dir: &str, pred: impl Fn(&str) -> bool) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if pred(&name) {
                util::rm_rf(&e.path().to_string_lossy());
            }
        }
    }
}

/// Append `lines` joined by "\n" plus a final "\n" (Lua `io.open(f, "a")`).
fn append_lines(path: &str, lines: &[String]) {
    if path.is_empty() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(format!("{}\n", lines.join("\n")).as_bytes());
    }
}

/// Per-domain DNS servers and sets (`list1` in upstream `add_rule`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DomainRule {
    pub dns: Vec<String>,
    pub ipsets: Vec<String>,
}

fn valid_rule_domain(d: &str) -> bool {
    !d.is_empty() && !d.contains('#')
}

/// Collect the node server domains of `passwall2` (`nodes` sections, `address` and
/// `download_address`, lowercased, hostnames only, `engage.cloudflareclient.com` skipped), each
/// resolved through `local_dns` (comma list) and added to the `psw2_vps`/`psw2_vps6` sets.
pub fn collect_node_domains(cfg: &Config, local_dns: &str, nft: bool) -> IndexMap<String, DomainRule> {
    let setflag_4 = if nft { "4#inet#passwall2#" } else { "" };
    let setflag_6 = if nft { "6#inet#passwall2#" } else { "" };
    let ipset = format!("{}psw2_vps,{}psw2_vps6", setflag_4, setflag_6);
    let mut list1: IndexMap<String, DomainRule> = IndexMap::new();
    for t in cfg.sections_of("nodes") {
        for opt in ["address", "download_address"] {
            let address = t.s(opt).to_lowercase();
            if address == "engage.cloudflareclient.com" || !api::dt_hostname(&address) || !valid_rule_domain(&address) {
                continue;
            }
            let e = list1.entry(address).or_default();
            for d in local_dns.split(',').filter(|s| !s.is_empty()) {
                tinsert(&mut e.dns, d);
            }
            for s in ipset.split(',').filter(|s| !s.is_empty()) {
                tinsert(&mut e.ipsets, s);
            }
        }
    }
    list1
}

/// Render `001-server.conf` and `ipset.conf` contents for the collected domains.
pub fn render_rule_files(list1: &IndexMap<String, DomainRule>, nft: bool) -> (String, String) {
    let set_name = if nft { "nftset" } else { "ipset" };
    let mut server = String::new();
    let mut ipset = String::new();
    for (key, value) in list1 {
        for dns in &value.dns {
            server.push_str(&format!("server=/.{}/{}\n", key, dns));
        }
        if !value.ipsets.is_empty() {
            ipset.push_str(&format!("{}=/.{}/{}\n", set_name, key, value.ipsets.join(",")));
        }
    }
    (server, ipset)
}

/// Lines `add_rule` appends to `DNSMASQ_CONF_FILE`: `conf-dir=<path>` then, when `tun_dns` is
/// given (even empty, like Lua's truthy ""), one `server=` per comma item + `all-servers`,
/// `no-poll`, `no-resolv`.
pub fn add_rule_conf_lines(tmp_dnsmasq_path: &str, tun_dns: Option<&str>) -> Vec<String> {
    let mut l: Vec<String> = vec![];
    tinsert(&mut l, &format!("conf-dir={}", tmp_dnsmasq_path));
    if let Some(t) = tun_dns {
        for s in t.split(',').filter(|s| !s.is_empty()) {
            tinsert(&mut l, &format!("server={}", s));
        }
        tinsert(&mut l, "all-servers");
        tinsert(&mut l, "no-poll");
        tinsert(&mut l, "no-resolv");
    }
    l
}

/// `echo -n $(uci show passwall2 | grep '\.address') | md5sum` with trailing whitespace stripped.
fn nodes_address_md5() -> String {
    let show = uci_show(util::CONFIG);
    let joined = show.lines().filter(|l| l.contains(".address")).flat_map(|l| l.split_whitespace()).collect::<Vec<_>>().join(" ");
    let (_, out) = util::cmd_stdin("md5sum", &[], &joined);
    out.trim_end().to_string()
}

/// `add_rule(var)`: per-flag dnsmasq rule directory (node domains → direct DNS + vps sets),
/// cached in `/tmp/etc/passwall2_tmp/dnsmasq_<FLAG>` and symlinked to `TMP_DNSMASQ_PATH`;
/// then the conf-dir/server lines appended to `DNSMASQ_CONF_FILE` (unless it is `"nil"`).
pub fn add_rule(var: &Args) {
    let flag = var.s("FLAG");
    let tmp_dnsmasq_path = var.s("TMP_DNSMASQ_PATH");
    let dnsmasq_conf_file = var.s("DNSMASQ_CONF_FILE");
    let default_dns = var.s("DEFAULT_DNS");
    let local_dns = var.s("LOCAL_DNS");
    let tun_dns = var.g("TUN_DNS");
    let nftflag = var.s("NFTFLAG");
    let cache_dns_path = format!("{}/dnsmasq_{}", CACHE_PATH, flag);
    let cache_text_file = format!("{}.txt", cache_dns_path);

    let new_text = format!(
        "{}{}{}{}{}{}{}",
        tmp_dnsmasq_path,
        dnsmasq_conf_file,
        default_dns,
        local_dns,
        tun_dns.unwrap_or(""),
        nodes_address_md5(),
        nftflag
    );
    let cache_text = util::read(&cache_text_file).lines().last().unwrap_or("").to_string();
    if cache_text != new_text {
        // api.remove(CACHE_DNS_PATH .. "*")
        let base = format!("dnsmasq_{}", flag);
        remove_matching(CACHE_PATH, |n| n.starts_with(&base));
    }

    let nft = nftflag == "1";
    if !util::exists(&cache_dns_path) {
        util::mkdir(&cache_dns_path);
        let cfg = Config::load(util::CONFIG);
        let list1 = collect_node_domains(&cfg, &local_dns, nft);
        if !list1.is_empty() {
            let (server, ipset) = render_rule_files(&list1, nft);
            append_raw(&format!("{}/001-server.conf", cache_dns_path), &server);
            append_raw(&format!("{}/ipset.conf", cache_dns_path), &ipset);
        }
        append_raw(&cache_text_file, &new_text);
    }

    if !tmp_dnsmasq_path.is_empty() && tmp_dnsmasq_path != "/" {
        util::rm_rf(&tmp_dnsmasq_path);
        let _ = std::os::unix::fs::symlink(&cache_dns_path, &tmp_dnsmasq_path);
    }

    if dnsmasq_conf_file != "nil" {
        let lines = add_rule_conf_lines(&tmp_dnsmasq_path, tun_dns);
        if tun_dns.is_some() && flag == "acl_default" {
            api::set_cache_var("DEFAULT_DNS", &default_dns);
        }
        if !lines.is_empty() {
            append_lines(&dnsmasq_conf_file, &lines);
        }
    }
}

fn append_raw(path: &str, data: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(data.as_bytes());
    }
}

// ---------------------------------------------------------------- app.sh direct-ipset DNS helpers

/// The vpslist used by chinadns-ng (`$TMP_ACL_PATH/vpslist`): every value of an option whose name
/// ends in `address` (first value for lists), split on spaces/commas, passed through
/// `host_from_url`, kept when ending in a letter, sorted unique, `engage.cloudflareclient.com`
/// dropped.
pub fn vpslist_domains(cfg: &Config) -> Vec<String> {
    let mut set = BTreeSet::new();
    for s in &cfg.sections {
        for (k, v) in &s.options {
            // grep -E "(.address=|.download_address=)" on `uci show` lines `cfg.sec.opt=...`
            if k.len() < 7 || !k.ends_with("address") {
                continue;
            }
            let val = match v {
                crate::uci::Value::Single(x) => x.clone(),
                crate::uci::Value::List(l) => l.first().cloned().unwrap_or_default(),
            };
            for h in val.split([' ', ',', '\t', '\n']).filter(|x| !x.is_empty()) {
                let host = util::host_from_url(h);
                if host.chars().last().is_some_and(|c| c.is_ascii_alphabetic()) {
                    set.insert(host);
                }
            }
        }
    }
    set.into_iter().filter(|h| !h.contains("engage.cloudflareclient.com")).collect()
}

/// Write `$TMP_ACL_PATH/vpslist` when it is missing or empty (as `run_ipset_chinadns_ng`).
pub fn write_vpslist(cfg: &Config) {
    let p = format!("{}/vpslist", util::TMP_ACL_PATH);
    if std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false) {
        return;
    }
    let l = vpslist_domains(cfg);
    let mut s = l.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    util::write(&p, &s);
}

/// chinadns-ng config of `run_ipset_chinadns_ng` (`server_dns` is `ip#port`; `ipset` like
/// `psw2_x,psw2_x6`, `nftset` like `4#inet#passwall2#psw2_x,6#inet#passwall2#psw2_x6`).
pub fn chinadns_ng_ipset_config(listen_port: &str, proto: &str, server_dns: &str, ipset: &str, nftset: &str) -> String {
    let mut set_names = String::new();
    let mut vps_set_names = "";
    if !ipset.is_empty() {
        set_names = ipset.to_string();
        vps_set_names = "psw2_vps,psw2_vps6";
    }
    if !nftset.is_empty() {
        let f: Vec<&str> = nftset.split(',').collect();
        let sub3 = |s: Option<&&str>| s.map(|x| x.chars().skip(2).collect::<String>()).unwrap_or_default();
        set_names = format!("{},{}", sub3(f.first()), sub3(f.get(1))).replace('#', "@");
        vps_set_names = "inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6";
    }
    let up = format!("{}://{}", proto, server_dns);
    format!(
        "bind-addr 127.0.0.1\nbind-port {lp}\nchina-dns {up}\ntrust-dns {up}\nfilter-qtype 65\nadd-tagchn-ip {sn}\ndefault-tag chn\ngroup vpslist\ngroup-dnl {acl}/vpslist\ngroup-upstream {up}\ngroup-ipset {vps}\n",
        lp = listen_port,
        up = up,
        sn = set_names,
        acl = util::TMP_ACL_PATH,
        vps = vps_set_names
    )
}

/// dnsmasq config of `run_ipset_dnsmasq` (`server_dns` comma/space separated).
pub fn ipset_dnsmasq_config(listen_port: &str, server_dns: &str, ipset: &str, nftset: &str, cache_size: &str, dns_forward_max: &str) -> String {
    let mut s = format!(
        "port={}\nno-poll\nno-resolv\nstrict-order\ncache-size={}\ndns-forward-max={}\n",
        listen_port,
        if cache_size.is_empty() { "0" } else { cache_size },
        if dns_forward_max.is_empty() { "1000" } else { dns_forward_max }
    );
    for i in server_dns.split([',', ' ', '\t', '\n']).filter(|x| !x.is_empty()) {
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

/// `passwall2 dns-helper <func> ['<json>']` (= `lua helper_dnsmasq.lua <func> '<json>'`).
pub fn cli(args: &[String]) -> i32 {
    let Some(func) = args.first() else { return 0 };
    let var = args.get(1).map(|s| util::args_from_json(s)).unwrap_or_default();
    match func.as_str() {
        "stretch" => stretch(),
        "restart" => restart(var.is1("LOG")),
        "logic_restart" => logic_restart(var.is1("LOG")),
        "copy_instance" => {
            let l = copy_instance(&var);
            if var.is1("return") {
                for x in l {
                    println!("{}", x);
                }
            }
        }
        "add_rule" => add_rule(&var),
        _ => return 1,
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_cfgid_confdir() {
        assert_eq!(parse_cfgid("dhcp.cfg01411c=dnsmasq\ndhcp.cfg01411c.domainneeded='1'\n"), "cfg01411c");
        assert_eq!(parse_cfgid(""), "");
        assert_eq!(conf_dir_from("port=53\nconf-dir=/tmp/dnsmasq.cfg01411c.d/\n"), "/tmp/dnsmasq.cfg01411c.d");
        assert_eq!(conf_dir_from("port=53\n"), "/tmp/dnsmasq.d");
    }

    #[test]
    fn t_filter_conf() {
        let text = "# auto-generated config file from /etc/config/dhcp\nconf-file=/etc/dnsmasq.conf\ndhcp-authoritative\ndomain-needed\nlocalise-queries\nport=53\nserver=8.8.8.8\nserver=/lan/\nserver=/example.com/1.1.1.1\naddress=/dhcp.lan/1.2.3.4\nubus\nconf-dir=/tmp/dnsmasq.cfg01411c.d\nresolv-file=/tmp/resolv.conf.d/resolv.conf.auto\nstop-dns-rebind\nlocal-service\ndomain-needed\n";
        let (l, d) = filter_dnsmasq_conf(text);
        assert_eq!(d, vec!["/tmp/dnsmasq.cfg01411c.d".to_string()]);
        let exp = [
            "conf-file=/etc/dnsmasq.conf",
            "domain-needed",
            "localise-queries",
            "server=/lan/",
            "server=/example.com/1.1.1.1",
            "address=/dhcp.lan/1.2.3.4",
            "resolv-file=/tmp/resolv.conf.d/resolv.conf.auto",
            "stop-dns-rebind",
            "local-service",
        ];
        assert_eq!(l, exp.iter().map(|x| x.to_string()).collect::<Vec<_>>());
    }

    fn cfg() -> Config {
        Config::parse(
            "passwall2",
            "config nodes 'n1'\n\toption address 'Example.COM'\n\toption download_address 'dl.example.org'\n\nconfig nodes 'n2'\n\toption address '1.2.3.4'\n\nconfig nodes 'n3'\n\toption address 'engage.cloudflareclient.com'\n\nconfig nodes 'n4'\n\toption address 'example.com'\n\nconfig haproxy_config 'h'\n\toption lbss 'lb.example.net:443'\n\nconfig socks 's'\n\toption server_address 'https://user:pw@sub.example.io:8443/x'\n",
        )
    }

    #[test]
    fn t_rule_files_nft() {
        let l = collect_node_domains(&cfg(), "223.5.5.5#53,119.29.29.29", true);
        assert_eq!(l.keys().cloned().collect::<Vec<_>>(), vec!["example.com", "dl.example.org"]);
        let (s, i) = render_rule_files(&l, true);
        assert_eq!(
            s,
            "server=/.example.com/223.5.5.5#53\nserver=/.example.com/119.29.29.29\nserver=/.dl.example.org/223.5.5.5#53\nserver=/.dl.example.org/119.29.29.29\n"
        );
        assert_eq!(
            i,
            "nftset=/.example.com/4#inet#passwall2#psw2_vps,6#inet#passwall2#psw2_vps6\nnftset=/.dl.example.org/4#inet#passwall2#psw2_vps,6#inet#passwall2#psw2_vps6\n"
        );
    }

    #[test]
    fn t_rule_files_ipt() {
        let l = collect_node_domains(&cfg(), "", false);
        let (s, i) = render_rule_files(&l, false);
        assert_eq!(s, "");
        assert_eq!(i, "ipset=/.example.com/psw2_vps,psw2_vps6\nipset=/.dl.example.org/psw2_vps,psw2_vps6\n");
    }

    #[test]
    fn t_conf_lines() {
        assert_eq!(
            add_rule_conf_lines("/tmp/etc/passwall2/acl/x_dnsmasq.d", Some("127.0.0.1#15353")),
            vec!["conf-dir=/tmp/etc/passwall2/acl/x_dnsmasq.d", "server=127.0.0.1#15353", "all-servers", "no-poll", "no-resolv"]
        );
        assert_eq!(add_rule_conf_lines("/d", None), vec!["conf-dir=/d"]);
        assert_eq!(add_rule_conf_lines("/d", Some("")), vec!["conf-dir=/d", "all-servers", "no-poll", "no-resolv"]);
    }

    #[test]
    fn t_vpslist() {
        // upstream does not lowercase here; sort order is byte order (busybox sort)
        let exp = ["Example.COM", "dl.example.org", "example.com", "sub.example.io"];
        assert_eq!(vpslist_domains(&cfg()), exp.iter().map(|x| x.to_string()).collect::<Vec<_>>());
    }

    #[test]
    fn t_chinadns_cfg() {
        let c = chinadns_ng_ipset_config("15355", "udp", "223.5.5.5#53", "", "4#inet#passwall2#psw2_abc_white,6#inet#passwall2#psw2_abc_white6");
        assert_eq!(
            c,
            "bind-addr 127.0.0.1\nbind-port 15355\nchina-dns udp://223.5.5.5#53\ntrust-dns udp://223.5.5.5#53\nfilter-qtype 65\nadd-tagchn-ip inet@passwall2@psw2_abc_white,inet@passwall2@psw2_abc_white6\ndefault-tag chn\ngroup vpslist\ngroup-dnl /tmp/etc/passwall2/acl/vpslist\ngroup-upstream udp://223.5.5.5#53\ngroup-ipset inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6\n"
        );
        let c = chinadns_ng_ipset_config("1", "tcp", "1.1.1.1#53", "a,a6", "");
        assert!(c.contains("add-tagchn-ip a,a6\n") && c.ends_with("group-ipset psw2_vps,psw2_vps6\n"));
    }

    #[test]
    fn t_ipset_dnsmasq_cfg() {
        assert_eq!(
            ipset_dnsmasq_config("15355", "223.5.5.5#53,1.1.1.1", "", "4#inet#passwall2#x,6#inet#passwall2#x6", "", ""),
            "port=15355\nno-poll\nno-resolv\nstrict-order\ncache-size=0\ndns-forward-max=1000\nserver=223.5.5.5#53\nserver=1.1.1.1\nnftset=4#inet#passwall2#x,6#inet#passwall2#x6\n"
        );
    }
}
