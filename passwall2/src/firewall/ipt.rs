//! iptables backend: port of upstream `root/usr/share/passwall2/iptables.sh` (spec 02 §3).
//!
//! Builds the fw3 / iptables + ipset transparent-proxy rule set: ipsets `psw2_*`,
//! nat `PSW2`/`PSW2_OUTPUT`/`PSW2_DNS` (REDIRECT, DNS hijack, ICMP), mangle
//! `PSW2_RULE`/`PSW2`/`PSW2_OUTPUT` (TPROXY + fwmark `0x50535732`), ip6tables equivalents,
//! multiport chunking (15 ports per rule), mwan3-aware jump insertion, policy routing
//! (table 999) and the fw3 include `/var/etc/passwall2.include` (iptables-save/restore).
//!
//! Every command goes through the [`Sys`] trait, so the exact rule sequence is unit-tested
//! with a recording mock. Rules are executed one by one exactly like the shell script
//! (failures are ignored, as upstream), because `insert_rule_before/after` depend on the
//! live chain contents.
//!
//! Entry points (same names as the shell dispatcher): `start`, `stop`,
//! `filter_direct_node_list`, `update_wan_sets`, `insert_rule_before`, `insert_rule_after`,
//! `RULE_LAST_INDEX`, `get_ipt_bin`, `get_ip6t_bin` — see [`cli`].

use crate::api;
use crate::firewall::acl::{self, AclSource};
use crate::uci::Config;
use crate::util::{self, Args, ArgsExt};
use std::collections::HashMap;
use std::process::{Command, Stdio};

pub const IPSET_LOCAL: &str = "psw2_local";
pub const IPSET_DIRECT: &str = "psw2_direct";
pub const IPSET_VPS: &str = "psw2_vps";
pub const IPSET_WAN: &str = "psw2_wan";
pub const IPSET_LOCAL6: &str = "psw2_local6";
pub const IPSET_DIRECT6: &str = "psw2_direct6";
pub const IPSET_VPS6: &str = "psw2_vps6";
pub const IPSET_WAN6: &str = "psw2_wan6";
pub const FWMARK: &str = "0x50535732";
pub const FAKE_IP: &str = "198.18.0.0/16";
pub const FAKE_IP_6: &str = "2001:2::/48";
/// Default include path (`uci -q get firewall.passwall2.path`).
pub const DEFAULT_FWI: &str = "/var/etc/passwall2.include";
const DIRECT_IP_FILE: &str = "/usr/share/passwall2/direct_ip";

// ====================================================================== system interface

/// Everything the backend needs from the system. The default methods talk to the real
/// system; tests override them with a recorder.
pub trait Sys {
    /// Run a command, true on exit status 0 (stdout/stderr discarded).
    fn run(&mut self, argv: &[String]) -> bool;
    /// Run a command and return its stdout ("" on failure).
    fn output(&mut self, argv: &[String]) -> String;
    /// Run a command feeding `input` on stdin.
    fn run_stdin(&mut self, argv: &[String], input: &str) -> bool;

    fn log(&mut self, level: usize, msg: &str) {
        util::log(level, msg)
    }
    fn read(&mut self, path: &str) -> String {
        util::read(path)
    }
    fn write(&mut self, path: &str, data: &str) {
        util::write(path, data);
    }
    fn append(&mut self, path: &str, data: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(data.as_bytes());
        }
    }
    /// Sorted entries of a directory, None when it is not a directory (`[ -d ] && ls`).
    fn list_dir(&mut self, path: &str) -> Option<Vec<String>> {
        let rd = std::fs::read_dir(path).ok()?;
        let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        v.sort();
        Some(v)
    }
    fn get_cache_var(&mut self, key: &str) -> Option<String> {
        util::get_cache_var(key).filter(|s| !s.is_empty())
    }
    fn set_cache_var(&mut self, key: &str, val: &str) {
        util::set_cache_var(key, val)
    }
    fn local_ips(&mut self, fam: &str) -> Vec<String> {
        util::get_local_ips(fam)
    }
    fn wan_ips(&mut self, fam: &str) -> Vec<String> {
        util::get_wan_ips(fam)
    }
    fn host_ip(&mut self, fam: &str, host: &str, count: u32) -> Option<String> {
        util::get_host_ip(fam, host, count)
    }
    /// `network_get_device`, then ubus `@.device`, then `/sys/class/net/<if>`, else the name.
    fn iface_device(&mut self, iface: &str) -> String {
        let st = util::cmd_out("ubus", &["call", &format!("network.interface.{}", iface), "status"]);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&st) {
            for k in ["l3_device", "device"] {
                if let Some(d) = v[k].as_str().filter(|d| !d.is_empty()) {
                    return d.to_string();
                }
            }
        }
        iface.to_string()
    }
    /// `uci -q -p /tmp/state get network.lan.ifname`
    fn lan_ifname(&mut self) -> String {
        util::cmd_out("uci", &["-q", "-p", "/tmp/state", "get", "network.lan.ifname"]).trim().to_string()
    }
    /// `get_geoip <codes> ipv4|ipv6` (utils.sh), cached in `$TMP_PATH2/geo_output`.
    fn geoip(&mut self, cfg: &Config, codes: &str, typ: &str) -> String {
        get_geoip(cfg, codes, typ)
    }
    /// Is `geoview` available (`first_type geoview`)?
    fn has_geoview(&mut self) -> bool {
        util::first_type("geoview", "").is_some()
    }
    /// Run `passwall2 ipt <sub>` detached in the background (shell `... > /dev/null 2>&1 &`).
    fn spawn_bg(&mut self, sub: &str) {
        let me = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| util::SELF_BIN.to_string());
        let _ = util::spawn_bg(&me, &["ipt".to_string(), sub.to_string()], "/dev/null");
    }
    /// `flock -x` on a lock file; the lock is held while the returned handle lives.
    fn lock(&mut self, path: &str) -> Option<std::fs::File> {
        util::lock(path)
    }
}

/// The real system.
pub struct RealSys;

impl Sys for RealSys {
    fn run(&mut self, argv: &[String]) -> bool {
        let Some((p, a)) = argv.split_first() else { return false };
        Command::new(p).args(a).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    }
    fn output(&mut self, argv: &[String]) -> String {
        let Some((p, a)) = argv.split_first() else { return String::new() };
        Command::new(p)
            .args(a)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }
    fn run_stdin(&mut self, argv: &[String], input: &str) -> bool {
        let Some((p, a)) = argv.split_first() else { return false };
        let a: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
        util::cmd_stdin(p, &a, input).0
    }
}

fn sv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}
fn words(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

// ====================================================================== pure helpers

/// `factor value prefix`: "" if either is empty or value == `1:65535`, else `"prefix value"`.
pub fn factor(value: &str, prefix: &str) -> String {
    if value.is_empty() || prefix.is_empty() || value == "1:65535" {
        String::new()
    } else {
        format!("{} {}", prefix, value)
    }
}

/// `dst set [!]` → `-m set [!] --match-set <set> dst`.
pub fn dst(set: &str, neg: bool) -> String {
    if neg {
        format!("-m set ! --match-set {} dst", set)
    } else {
        format!("-m set --match-set {} dst", set)
    }
}

/// `comment s` → `-m comment --comment <s>` with whitespace runs replaced by `_`
/// (`echo $1 | sed 's/ /_/g'`).
// upstream quirk: an empty comment makes iptables swallow the next argument as the comment
// text, so every rule of an ACL without remarks fails. We omit the match instead.
pub fn comment(s: &str) -> String {
    let name = s.split_whitespace().collect::<Vec<_>>().join("_");
    if name.is_empty() {
        String::new()
    } else {
        format!("-m comment --comment {}", name)
    }
}

/// `REDIRECT [port] [mode]`
pub fn redirect(port: &str, mode: &str) -> String {
    if port.is_empty() {
        "-j REDIRECT".into()
    } else if mode == "TPROXY" {
        format!("-m mark --mark {} -j TPROXY --on-port {}", FWMARK, port)
    } else {
        format!("-j REDIRECT --to-ports {}", port)
    }
}

/// `has_1_65535 list` (utils.sh): `:`→`-`, true when `,list,` contains `,1-65535,`.
pub fn has_1_65535(v: &str) -> bool {
    format!(",{},", v.replace(':', "-")).contains(",1-65535,")
}

/// `add_port_rules` expansion: the list of `-m multiport --dport ...` / `--dport a:b`
/// fragments (empty string = "no port match"). None when the list yields no rule at all.
pub fn port_fragments(ports: &str) -> Option<Vec<String>> {
    if !ports.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    // upstream quirk: the shell passes the list unquoted, so a list containing spaces is
    // split into several arguments; we treat it as one list (spaces removed), which is what
    // `tr -d ' '` inside add_port_rules intends.
    let cleaned: String = ports.chars().filter(|c| *c != ' ').collect::<String>().replace('-', ":");
    let mut list: Vec<String> = vec![];
    for p in cleaned.split([',', '\n']) {
        if p.is_empty() || list.iter().any(|x| x == p) {
            continue;
        }
        list.push(p.to_string());
    }
    if list.is_empty() {
        return None;
    }
    if list.iter().any(|p| p == "1:65535") {
        return Some(vec![String::new()]);
    }
    let mut out = vec![];
    let mut singles: Vec<&str> = vec![];
    let mut ranges: Vec<&str> = vec![];
    for p in &list {
        if p.contains(':') {
            ranges.push(p);
        } else {
            singles.push(p);
            if singles.len() == 15 {
                out.push(format!("-m multiport --dport {}", singles.join(",")));
                singles.clear();
            }
        }
    }
    if !singles.is_empty() {
        out.push(format!("-m multiport --dport {}", singles.join(",")));
    }
    for r in ranges {
        out.push(format!("--dport {}", r));
    }
    Some(out)
}

/// Does `s` contain what the upstream IPv6 grep `([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}`
/// matches (hex digit, `:` or `::`, hex digit)?
pub fn v6_regex_match(s: &str) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if !b[i].is_ascii_hexdigit() {
            continue;
        }
        let mut j = i + 1;
        if j < b.len() && b[j] == b':' {
            j += 1;
            if j < b.len() && b[j] == b':' {
                j += 1;
            }
            if j < b.len() && b[j].is_ascii_hexdigit() {
                return true;
            }
        }
    }
    false
}

/// An entry `ipset restore` accepts for a `hash:net` / `hash:ip` set of the family:
/// address, CIDR or `a-b` range. Upstream only filters with a loose grep, so one bad line
/// aborts the whole `ipset -R` batch; we drop invalid lines instead.
pub fn valid_set_entry(e: &str, v6: bool) -> bool {
    let fam_ok = |ip: &str| if v6 { util::is_ipv6(ip) && !ip.starts_with('[') } else { util::is_ipv4(ip) };
    if let Some((a, b)) = e.split_once('-') {
        return fam_ok(a) && fam_ok(b);
    }
    match e.split_once('/') {
        Some((ip, m)) => fam_ok(ip) && m.parse::<u8>().is_ok_and(|m| m <= if v6 { 128 } else { 32 }),
        None => fam_ok(e) && (!v6 || v6_regex_match(e)),
    }
}

/// Lines for `ipset -! -R`: `add <set> <entry>` for each valid entry (+ optional COMMIT).
pub fn restore_input(set: &str, entries: &[String], commit: bool) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!("add {} {}\n", set, e));
    }
    if commit {
        s.push_str("COMMIT\n");
    }
    s
}

/// Filter text lines (comments after `#` removed, trimmed) to valid entries of the family.
pub fn filter_entries(text: &str, v6: bool, strip_comments: bool) -> Vec<String> {
    let mut out = vec![];
    for l in text.split(['\n', '\r']) {
        let l = if strip_comments { l.split('#').next().unwrap_or("") } else { l };
        let l = l.trim();
        if !l.is_empty() && valid_set_entry(l, v6) {
            out.push(l.to_string());
        }
    }
    out
}

/// `get_geoip codes ipv4|ipv6` (utils.sh).
pub fn get_geoip(cfg: &Config, codes: &str, typ: &str) -> String {
    let dir = format!("{}/geo_output", util::TMP_PATH2);
    util::mkdir(&dir);
    let out = format!("{}/geoip-{}-{}", dir, codes, typ);
    let nonempty = |p: &str| std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false);
    if !nonempty(&out) {
        let asset = cfg.s("@global_rules[0]", "v2ray_location_asset");
        let asset = asset.strip_suffix('/').unwrap_or(&asset);
        let geoip_path = format!("{}/geoip.dat", asset);
        let gv = cfg.s("@global_app[0]", "geoview_file");
        let bin = if gv.is_empty() { util::first_type("geoview", "") } else { util::first_type(&gv, "geoview") };
        let Some(bin) = bin else { return String::new() };
        if !nonempty(&geoip_path) {
            return String::new();
        }
        let mut args = vec!["-input", geoip_path.as_str(), "-list", codes];
        match typ {
            "ipv4" => args.push("-ipv6=false"),
            "ipv6" => args.push("-ipv4=false"),
            _ => {}
        }
        args.extend(["-lowmem=true", "-output", out.as_str()]);
        let _ = Command::new(&bin).args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    if nonempty(&out) {
        util::read(&out)
    } else {
        String::new()
    }
}

/// `command -v name` over `$PATH` (default OpenWrt PATH when unset).
pub fn command_v(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    path.split(':').filter(|d| !d.is_empty()).map(|d| format!("{}/{}", d, name)).find(|p| util::is_executable(p))
}

/// `command -v iptables-legacy || command -v iptables`
pub fn get_ipt_bin() -> Option<String> {
    command_v("iptables-legacy").or_else(|| command_v("iptables"))
}
/// `command -v ip6tables-legacy || command -v ip6tables`
pub fn get_ip6t_bin() -> Option<String> {
    command_v("ip6tables-legacy").or_else(|| command_v("ip6tables"))
}
fn module_loaded(m: &str) -> bool {
    util::read("/proc/modules").contains(m)
}

/// First / last (`after`) line number of `<ipt> -n -L chain --line-numbers` whose text
/// contains `keyword`.
pub fn rule_index(listing: &str, keyword: &str, last: bool) -> Option<usize> {
    let mut it = listing
        .lines()
        .filter(|l| l.contains(keyword))
        .filter_map(|l| l.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()));
    if last {
        it.next_back()
    } else {
        it.next()
    }
}

/// `insert_rule_before` / `insert_rule_after` with `base` = the `$ipt_tmp` words.
pub fn insert_rule(sys: &mut dyn Sys, base: &[String], chain: &str, keyword: &str, rule: &str, default_index: usize, after: bool) -> bool {
    if base.is_empty() || base[0] == "eval" {
        // `eval #...` (ip6tables table not available): upstream no-op
        return false;
    }
    let mut l = base.to_vec();
    l.extend(sv(&["-n", "-L", chain, "--line-numbers"]));
    let idx = rule_index(&sys.output(&l), keyword, after);
    let mut cmd = base.to_vec();
    match (idx, default_index) {
        (None, 0) => {
            cmd.extend(sv(&["-A", chain]));
        }
        (Some(i), _) => {
            let pos = if after { i + 1 } else { i };
            cmd.extend(sv(&["-I", chain, &pos.to_string()]));
        }
        (None, d) => {
            cmd.extend(sv(&["-I", chain, &d.to_string()]));
        }
    }
    cmd.extend(words(rule));
    sys.run(&cmd)
}

/// Runtime ISP DNS lists from the resolv file (`get_direct_dns`): (ISP_DNS, ISP_DNS6).
pub fn parse_isp_dns(resolv: &str) -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = vec![];
    for tok in resolv.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        // grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
        let parts: Vec<&str> = tok.split('.').collect();
        let mut i = 0;
        while i + 4 <= parts.len() {
            if parts[i..i + 4].iter().all(|p| !p.is_empty()) {
                let ip = parts[i..i + 4].join(".");
                if ip != "0.0.0.0" && ip != "127.0.0.1" && !v4.contains(&ip) {
                    v4.push(ip);
                }
                i += 4;
            } else {
                i += 1;
            }
        }
    }
    let mut v6: Vec<String> = vec![];
    for l in resolv.lines() {
        if !v6_regex_match(l) {
            continue;
        }
        let l = l.split('%').next().unwrap_or("");
        // awk -F " " '{print $2}'
        let Some(ip) = l.split_whitespace().nth(1) else { continue };
        if ip == "::1" || ip == "::" || v6.iter().any(|x| x == ip) {
            continue;
        }
        v6.push(ip.to_string());
    }
    (v4, v6)
}

/// `RETURN_DNS` of `get_direct_dns`: AUTO_DNS (dnsmasq upstream servers, else the first two
/// ISP DNS, else 119.29.29.29) plus `,server#port#proto` for a tcp/udp direct DNS.
pub fn compute_return_dns(dnsmasq_servers: &[String], isp_dns: &[String], direct_dns_protocol: &str, direct_dns: &str) -> String {
    let mut ups: Vec<String> = vec![];
    for s in dnsmasq_servers.iter().flat_map(|s| s.split_whitespace()) {
        if s.contains('/') {
            continue;
        }
        ups.push(if s.contains('#') { s.to_string() } else { format!("{}#53", s) });
        if ups.len() == 2 {
            break;
        }
    }
    let mut auto = ups.join(",");
    if auto.is_empty() {
        auto = isp_dns.iter().take(2).cloned().collect::<Vec<_>>().join(",");
    }
    if auto.is_empty() {
        auto = "119.29.29.29".into();
    }
    let mut ret = auto;
    if (direct_dns_protocol == "tcp" || direct_dns_protocol == "udp") && !direct_dns.is_empty() {
        let (srv, port) = api::parse_dns(direct_dns);
        if !srv.is_empty() {
            ret = format!("{},{}#{}#{}", ret, srv, port, direct_dns_protocol);
        }
    }
    ret
}

// ====================================================================== runtime context

/// Values app.sh hands to the sourced iptables.sh (shell globals of `start`).
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    /// `ISP_DNS` (IPv4)
    pub isp_dns: Vec<String>,
    /// `ISP_DNS6`
    pub isp_dns6: Vec<String>,
    /// `RETURN_DNS`: comma list `addr[#port[#proto]]`
    pub return_dns: String,
    /// `TCP_PROXY_WAY` (`redirect` | `tproxy`)
    pub tcp_proxy_way: String,
    /// `PROXY_IPV6`
    pub proxy_ipv6: bool,
    pub enabled_default_acl: bool,
    pub enabled_acls: bool,
    /// `$.acl[*].flag` of the ACL JSON (rules in UCI order, `acl_default` last)
    pub acl_flags: Vec<String>,
}

impl Ctx {
    /// Build the context like app.sh `get_config` + `get_direct_dns` does (used by the
    /// standalone `passwall2 ipt start`; the runtime normally fills it itself).
    pub fn from_system(cfg: &Config) -> Ctx {
        let resolv = {
            let p = "/tmp/resolv.conf.d/resolv.conf.auto";
            if std::fs::metadata(p).map(|m| m.is_file() && m.len() > 0).unwrap_or(false) {
                util::read(p)
            } else {
                util::read("/tmp/resolv.conf.auto")
            }
        };
        let (isp_dns, isp_dns6) = parse_isp_dns(&resolv);
        let dhcp = Config::load("dhcp");
        let servers = dhcp.list_raw("@dnsmasq[0]", "server");
        let return_dns = compute_return_dns(&servers, &isp_dns, &cfg.s("@global[0]", "direct_dns_protocol"), &cfg.s("@global[0]", "direct_dns"));
        let node = cfg.s("@global[0]", "node");
        let def_acl_cfg = cfg.get_or("@global[0]", "enabled", "0") == "1" && !node.is_empty() && cfg.stype(&node).as_deref() == Some("nodes");
        let node_order = acl::saved_node_order();
        let cache = |k: &str| util::get_cache_var(k).filter(|s| !s.is_empty());
        let enabled_default_acl = match cache("ENABLED_DEFAULT_ACL") {
            Some(v) => v == "1",
            None => def_acl_cfg && node_order.iter().any(|f| f == "acl_default"),
        };
        let enabled_acls = match cache("ENABLED_ACLS") {
            Some(v) => v == "1",
            None => cfg.get_or("@global[0]", "acl_enable", "0") == "1" && !node_order.is_empty(),
        };
        Ctx {
            isp_dns,
            isp_dns6,
            return_dns,
            tcp_proxy_way: cfg.get_or("@global_forwarding[0]", "tcp_proxy_way", "redirect"),
            proxy_ipv6: cfg.get_or("@global_forwarding[0]", "ipv6_tproxy", "0") == "1",
            enabled_default_acl,
            enabled_acls,
            acl_flags: acl::saved_flags(),
        }
    }
}

// ====================================================================== the backend

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tb {
    N4,
    M4,
    N6,
    M6,
}

/// One shunt set reference `set:outbound` (`outbound` = `direct` | `redirect`).
pub type ShuntList = Vec<(String, String)>;

pub struct Fw<'a> {
    pub sys: &'a mut dyn Sys,
    pub cfg: &'a Config,
    pub ipt: Option<String>,
    pub ip6t: Option<String>,
    /// base words per table (None = upstream's `eval #...` no-op)
    tables: [Option<Vec<String>>; 4],
    pub is_tproxy: bool,
    pub accept_icmp: bool,
    pub accept_icmpv6: bool,
    pub proxy_ipv6: bool,
    /// include file path (`firewall.passwall2.path`)
    pub fwi: String,
    pub acl_path: String,
    pub iface_path: String,
    pub tmp_path: String,
    /// per-node shunt lists (upstream keeps one global, see `gen_shunt_list` quirk)
    shunt: HashMap<String, (ShuntList, ShuntList)>,
}

impl<'a> Fw<'a> {
    /// `ip6_nat` / `ip6_mangle`: whether `ip6table_nat` / `ip6table_mangle` are loaded.
    pub fn new(sys: &'a mut dyn Sys, cfg: &'a Config, ipt: Option<String>, ip6t: Option<String>, ip6_nat: bool, ip6_mangle: bool) -> Fw<'a> {
        let base = |b: &Option<String>, t: &str| b.as_ref().map(|b| sv(&[b, "-t", t, "-w"]));
        let tables = [
            base(&ipt, "nat"),
            base(&ipt, "mangle"),
            if ip6_nat { base(&ip6t, "nat") } else { None },
            if ip6_mangle { base(&ip6t, "mangle") } else { None },
        ];
        let way = cfg.get_or("@global_forwarding[0]", "tcp_proxy_way", "redirect");
        Fw {
            sys,
            cfg,
            ipt,
            ip6t,
            tables,
            is_tproxy: way == "tproxy",
            accept_icmp: cfg.get_or("@global_forwarding[0]", "accept_icmp", "0") == "1",
            accept_icmpv6: cfg.get_or("@global_forwarding[0]", "accept_icmpv6", "0") == "1",
            proxy_ipv6: cfg.get_or("@global_forwarding[0]", "ipv6_tproxy", "0") == "1",
            fwi: DEFAULT_FWI.into(),
            acl_path: util::TMP_ACL_PATH.into(),
            iface_path: util::TMP_IFACE_PATH.into(),
            tmp_path: util::TMP_PATH.into(),
            shunt: HashMap::new(),
        }
    }

    /// Detect binaries / ip6 modules / include path from the running system.
    pub fn system(sys: &'a mut dyn Sys, cfg: &'a Config) -> Fw<'a> {
        let ipt = get_ipt_bin();
        let ip6t = get_ip6t_bin();
        let has6 = ip6t.is_some();
        let mut fw = Fw::new(sys, cfg, ipt, ip6t, has6 && module_loaded("ip6table_nat"), has6 && module_loaded("ip6table_mangle"));
        let fwc = Config::load("firewall");
        fw.fwi = fwc.s("passwall2", "path");
        fw
    }

    fn base(&self, t: Tb) -> Option<&Vec<String>> {
        self.tables[t as usize].as_ref()
    }
    /// Display string of a table command (`$ipt_n`, or upstream's `eval #...`).
    fn base_str(&self, t: Tb) -> String {
        match self.base(t) {
            Some(b) => b.join(" "),
            None => {
                let (bin, tbl) = match t {
                    Tb::N4 => (&self.ipt, "nat"),
                    Tb::M4 => (&self.ipt, "mangle"),
                    Tb::N6 => (&self.ip6t, "nat"),
                    Tb::M6 => (&self.ip6t, "mangle"),
                };
                format!("eval #{} -t {} -w", bin.clone().unwrap_or_default(), tbl)
            }
        }
    }
    /// `$ipt_tmp`: nat in redirect mode, mangle in tproxy mode.
    fn tmp4(&self) -> Tb {
        if self.is_tproxy {
            Tb::M4
        } else {
            Tb::N4
        }
    }

    /// `$<table> <rule words>`
    pub fn x(&mut self, t: Tb, rule: &str) -> bool {
        let Some(b) = self.base(t) else { return false };
        let mut argv = b.clone();
        argv.extend(words(rule));
        self.sys.run(&argv)
    }

    fn run(&mut self, parts: &[&str]) -> bool {
        self.sys.run(&sv(parts))
    }

    fn ipset_restore(&mut self, input: &str) {
        if input.trim().is_empty() || input.trim() == "COMMIT" {
            return;
        }
        self.sys.run_stdin(&sv(&["ipset", "-!", "-R"]), input);
    }

    /// `add_port_rules "<table> <cmd>" ports target`
    pub fn add_port_rules(&mut self, t: Tb, cmd: &str, ports: &str, target: &str) {
        let Some(frags) = port_fragments(ports) else { return };
        for f in frags {
            self.x(t, &format!("{} {} {}", cmd, f, target));
        }
    }

    /// `add_shunt_t_rule list "<table> <cmd>" jump [ports]`
    pub fn add_shunt_t_rule(&mut self, t: Tb, list: &ShuntList, cmd: &str, jump: &str, ports: &str) {
        for (set, outbound) in list {
            if set.is_empty() || outbound.is_empty() {
                continue;
            }
            let arg = if outbound == "direct" { "-j RETURN" } else { jump };
            let c = format!("{} {}", cmd, dst(set, false));
            if ports.is_empty() || ports == "1:65535" {
                self.x(t, &format!("{} {}", c, arg));
            } else {
                self.add_port_rules(t, &c, ports, arg);
            }
        }
    }

    pub fn insert_rule_before(&mut self, t: Tb, chain: &str, keyword: &str, rule: &str) {
        if let Some(b) = self.base(t).cloned() {
            insert_rule(self.sys, &b, chain, keyword, rule, 0, false);
        }
    }
    pub fn insert_rule_after(&mut self, t: Tb, chain: &str, keyword: &str, rule: &str) {
        if let Some(b) = self.base(t).cloned() {
            insert_rule(self.sys, &b, chain, keyword, rule, 0, true);
        }
    }

    fn log(&mut self, level: usize, msg: &str) {
        self.sys.log(level, msg);
    }
    fn logf(&mut self, level: usize, fmt: &str, args: &[&str]) {
        let m = api::translatef(fmt, args);
        self.sys.log(level, &m);
    }

    // ------------------------------------------------------------------ gen_shunt_list

    /// `gen_shunt_list node` → (shunt_list4, shunt_list6); creates and fills the sets.
    pub fn gen_shunt_list(&mut self, node: &str) -> (ShuntList, ShuntList) {
        let cfg = self.cfg;
        let mut l4: ShuntList = vec![];
        let mut l6: ShuntList = vec![];
        if cfg.s(node, "protocol") == "_shunt" {
            let mut enable_geoview_ip = cfg.get_or(node, "enable_geoview_ip", "0");
            if !self.sys.has_geoview() {
                enable_geoview_ip = "0".into();
            }
            if enable_geoview_ip == "1" {
                let default_outbound = if cfg.get_or(node, "default_node", "_direct") == "_direct" { "direct" } else { "redirect" };
                let shunt_group = cfg.s(node, "shunt_group");
                let ids: Vec<String> = cfg.sections_of("shunt_rules").map(|s| s.name.clone()).collect();
                for sid in ids {
                    if shunt_group != cfg.s(&sid, "group") {
                        continue;
                    }
                    let shunt_node = cfg.s(node, &sid);
                    if shunt_node.is_empty() {
                        continue;
                    }
                    let v4 = format!("psw2_{}_{}", node, sid);
                    let v6 = format!("psw2_{}_{}6", node, sid);
                    self.run(&["ipset", "-!", "create", &v4, "nethash", "maxelem", "1048576"]);
                    self.run(&["ipset", "-!", "create", &v6, "nethash", "family", "inet6", "maxelem", "1048576"]);
                    let outbound = match shunt_node.as_str() {
                        "_direct" => "direct",
                        "_default" => default_outbound,
                        _ => "redirect",
                    };
                    l4.push((v4.clone(), outbound.into()));
                    l6.push((v6.clone(), outbound.into()));
                    let ip_list = cfg.s(&sid, "ip_list");
                    self.ipset_restore(&restore_input(&v4, &filter_entries(&ip_list, false, true), true));
                    self.ipset_restore(&restore_input(&v6, &filter_entries(&ip_list, true, true), true));
                    let codes: Vec<String> = ip_list
                        .split(['\r', '\n'])
                        .filter(|l| l.starts_with("geoip:") && !l.starts_with("geoip:private"))
                        .filter_map(|l| l["geoip:".len()..].split_whitespace().next().map(|c| c.to_string()))
                        .collect();
                    if !codes.is_empty() {
                        let codes = codes.join(",");
                        let g4 = self.sys.geoip(cfg, &codes, "ipv4");
                        self.ipset_restore(&restore_input(&v4, &filter_entries(&g4, false, false), true));
                        let g6 = self.sys.geoip(cfg, &codes, "ipv6");
                        self.ipset_restore(&restore_input(&v6, &filter_entries(&g6, true, false), true));
                    }
                }
            }
            if let Some(d4) = self.sys.get_cache_var(&format!("node_{}_direct_ipset4", node)) {
                self.run(&["ipset", "-!", "create", &d4, "iphash", "maxelem", "1048576", "timeout", "259200"]);
                l4.push((d4, "direct".into()));
            }
            if let Some(d6) = self.sys.get_cache_var(&format!("node_{}_direct_ipset6", node)) {
                self.run(&["ipset", "-!", "create", &d6, "iphash", "family", "inet6", "maxelem", "1048576", "timeout", "259200"]);
                l6.push((d6, "direct".into()));
            }
        }
        self.sys.set_cache_var(&format!("node_{}_gen_shunt_list", node), "1");
        (l4, l6)
    }

    // ------------------------------------------------------------------ load_acl

    /// `load_acl`: `acl_node` (start the ACL cores/dnsmasq) then the per-ACL rules.
    pub fn load_acl(&mut self, flags: &[String], acl_node: &mut dyn FnMut()) {
        self.logf(1, "Access Control:", &[]);
        acl_node();
        for sid in flags {
            let var = acl::parse_assignments(&self.sys.read(&format!("{}/{}/var", self.acl_path, sid)));
            let sources = acl::parse_source_list(&self.sys.read(&format!("{}/{}/source_list", self.acl_path, sid)));
            self.load_one_acl(&var, &sources);
        }
    }

    /// Rules of one ACL (`var` file contents + parsed `source_list`).
    pub fn load_one_acl(&mut self, v: &Args, sources: &[AclSource]) {
        let node = v.s("node");
        // upstream quirk: shunt_list4/6 are shell globals, so a later ACL with an already
        // processed node reuses the last generated list. We keep one list per node.
        let (sl4, sl6) = if node.is_empty() {
            (vec![], vec![])
        } else if let Some(l) = self.shunt.get(&node) {
            l.clone()
        } else {
            let l = self.gen_shunt_list(&node);
            self.shunt.insert(node.clone(), l.clone());
            l
        };
        let dns_port = match ArgsExt::ne(v, "use") {
            Some(u) => self.sys.get_cache_var(&format!("ACL_{}_dns_port", u)).unwrap_or_default(),
            None => String::new(),
        };
        let tmp = self.tmp4();
        // backstop for state files written before the ACL values were cleaned (see clean_ports)
        let port = |k: &str| super::acl::clean_ports(Some(v.s(k))).unwrap_or_default();
        let tcp_no = port("tcp_no_redir_ports");
        let udp_no = port("udp_no_redir_ports");
        let tcp_redir = port("tcp_redir_ports");
        let udp_redir = port("udp_redir_ports");
        let redir_port = v.s("redir_port");
        let node_remarks = v.s("node_remarks");
        let remarks = v.s("remarks");

        if v.is1("local_proxy") {
            let msg = api::translate("[Local],");
            let mut no_tcp_local = false;
            let mut no_udp_local = false;
            if !tcp_no.is_empty() {
                self.add_port_rules(tmp, "-A PSW2_OUTPUT -p tcp", &tcp_no, "-j RETURN");
                self.add_port_rules(Tb::M6, "-A PSW2_OUTPUT -p tcp", &tcp_no, "-j RETURN");
                if !has_1_65535(&tcp_no) {
                    self.log(2, &format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["TCP", &tcp_no])));
                } else {
                    no_tcp_local = true;
                    self.log(2, &format!("{}{}", msg, api::translatef("not proxy all %s", &["TCP"])));
                }
            }
            if !udp_no.is_empty() {
                self.add_port_rules(Tb::M4, "-A PSW2_OUTPUT -p udp", &udp_no, "-j RETURN");
                self.add_port_rules(Tb::M6, "-A PSW2_OUTPUT -p udp", &udp_no, "-j RETURN");
                if !has_1_65535(&udp_no) {
                    self.log(2, &format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["UDP", &udp_no])));
                } else {
                    no_udp_local = true;
                    self.log(2, &format!("{}{}", msg, api::translatef("not proxy all %s", &["UDP"])));
                }
            }
            let comment_l = comment(&api::translate("Local"));

            if !node.is_empty() && (!no_tcp_local || !no_udp_local) && !dns_port.is_empty() {
                let c = comment("PSW2_DNS");
                for p in ["udp", "tcp"] {
                    let r = format!("-A OUTPUT {} -p {} -o lo --dport 53 -j REDIRECT --to-ports {}", c, p, dns_port);
                    self.x(Tb::N4, &r);
                    self.x(Tb::N6, &r);
                }
                self.log(2, &format!("{}{}", msg, api::translatef("DNS will redirected to the dedicated DNS server [%s].", &[&dns_port])));
            }

            // Loading local router proxy TCP
            if !node.is_empty() && !no_tcp_local {
                if self.accept_icmp {
                    self.x(Tb::N4, &format!("-A OUTPUT {} -p icmp -j PSW2_OUTPUT", dst(IPSET_DIRECT, true)));
                    self.x(Tb::N4, &format!("-A PSW2_OUTPUT -p icmp -d {} {}", FAKE_IP, redirect("", "")));
                    self.add_shunt_t_rule(Tb::N4, &sl4, "-A PSW2_OUTPUT -p icmp", &redirect("", ""), "");
                    self.x(Tb::N4, &format!("-A PSW2_OUTPUT -p icmp {}", redirect("", "")));
                }
                if self.accept_icmpv6 {
                    self.x(Tb::N6, &format!("-A OUTPUT {} -p ipv6-icmp -j PSW2_OUTPUT", dst(IPSET_DIRECT6, true)));
                    self.x(Tb::N6, &format!("-A PSW2_OUTPUT -p ipv6-icmp -d {} {}", FAKE_IP_6, redirect("", "")));
                    self.add_shunt_t_rule(Tb::N6, &sl6, "-A PSW2_OUTPUT -p ipv6-icmp", &redirect("", ""), "");
                    self.x(Tb::N6, &format!("-A PSW2_OUTPUT -p ipv6-icmp {}", redirect("", "")));
                }
                let mut msg2 = format!("{}{}", msg, api::translatef("Use the %s node [%s]", &["TCP", &node_remarks]));
                let ipt_j = if self.is_tproxy {
                    msg2.push_str(&format!("(TPROXY:{})", redir_port));
                    "-j PSW2_RULE".to_string()
                } else {
                    msg2.push_str(&format!("(REDIRECT:{})", redir_port));
                    redirect(&redir_port, "")
                };
                self.x(tmp, &format!("-A PSW2_OUTPUT -p tcp -d {} {}", FAKE_IP, ipt_j));
                self.add_shunt_t_rule(tmp, &sl4, "-A PSW2_OUTPUT -p tcp", &ipt_j, &tcp_redir);
                self.add_port_rules(tmp, "-A PSW2_OUTPUT -p tcp", &tcp_redir, &ipt_j);
                if !self.is_tproxy {
                    self.x(Tb::N4, &format!("-A OUTPUT {} -p tcp -j PSW2_OUTPUT", dst(IPSET_DIRECT, true)));
                } else {
                    self.x(Tb::M4, &format!("-A PSW2 {} -p tcp -i lo {}", comment_l, redirect(&redir_port, "TPROXY")));
                    self.x(Tb::M4, &format!("-A PSW2 {} -p tcp -i lo -j RETURN", comment_l));
                    let r = format!("{} {} -p tcp -j PSW2_OUTPUT", comment("mangle-OUTPUT-PSW2"), dst(IPSET_DIRECT, true));
                    self.insert_rule_before(Tb::M4, "OUTPUT", "mwan3", &r);
                }
                if self.proxy_ipv6 {
                    self.x(Tb::M6, &format!("-A PSW2_OUTPUT -p tcp -d {} -j PSW2_RULE", FAKE_IP_6));
                    self.add_shunt_t_rule(Tb::M6, &sl6, "-A PSW2_OUTPUT -p tcp", "-j PSW2_RULE", &tcp_redir);
                    self.add_port_rules(Tb::M6, "-A PSW2_OUTPUT -p tcp", &tcp_redir, "-j PSW2_RULE");
                    self.x(Tb::M6, &format!("-A PSW2 {} -p tcp -i lo {}", comment_l, redirect(&redir_port, "TPROXY")));
                    self.x(Tb::M6, &format!("-A PSW2 {} -p tcp -i lo -j RETURN", comment_l));
                    let r = format!("{} {} -p tcp -j PSW2_OUTPUT", comment("mangle-OUTPUT-PSW2"), dst(IPSET_DIRECT6, true));
                    self.insert_rule_before(Tb::M6, "OUTPUT", "mwan3", &r);
                }
                let ip = self.iface_path.clone();
                if let Some(ifaces) = self.sys.list_dir(&ip) {
                    for iface in ifaces {
                        self.x(Tb::N4, &format!("-A PSW2_OUTPUT -o {} -p tcp -j RETURN", iface));
                        self.x(Tb::M4, &format!("-A PSW2_OUTPUT -o {} -p tcp -j RETURN", iface));
                    }
                }
                self.log(2, &msg2);
            }

            // Loading local router proxy UDP
            if !node.is_empty() && !no_udp_local {
                let msg2 = format!("{}{}(TPROXY:{})", msg, api::translatef("Use the %s node [%s]", &["UDP", &node_remarks]), redir_port);
                self.x(Tb::M4, &format!("-A PSW2_OUTPUT -p udp -d {} -j PSW2_RULE", FAKE_IP));
                self.add_shunt_t_rule(Tb::M4, &sl4, "-A PSW2_OUTPUT -p udp", "-j PSW2_RULE", &udp_redir);
                self.add_port_rules(Tb::M4, "-A PSW2_OUTPUT -p udp", &udp_redir, "-j PSW2_RULE");
                self.x(Tb::M4, &format!("-A PSW2 {} -p udp -i lo {}", comment_l, redirect(&redir_port, "TPROXY")));
                self.x(Tb::M4, &format!("-A PSW2 {} -p udp -i lo -j RETURN", comment_l));
                let r = format!("{} {} -p udp -j PSW2_OUTPUT", comment("mangle-OUTPUT-PSW2"), dst(IPSET_DIRECT, true));
                self.insert_rule_before(Tb::M4, "OUTPUT", "mwan3", &r);
                if self.proxy_ipv6 {
                    self.x(Tb::M6, &format!("-A PSW2_OUTPUT -p udp -d {} -j PSW2_RULE", FAKE_IP_6));
                    self.add_shunt_t_rule(Tb::M6, &sl6, "-A PSW2_OUTPUT -p udp", "-j PSW2_RULE", &udp_redir);
                    self.add_port_rules(Tb::M6, "-A PSW2_OUTPUT -p udp", &udp_redir, "-j PSW2_RULE");
                    self.x(Tb::M6, &format!("-A PSW2 {} -p udp -i lo {}", comment_l, redirect(&redir_port, "TPROXY")));
                    self.x(Tb::M6, &format!("-A PSW2 {} -p udp -i lo -j RETURN", comment_l));
                    let r = format!("{} {} -p udp -j PSW2_OUTPUT", comment("mangle-OUTPUT-PSW2"), dst(IPSET_DIRECT6, true));
                    self.insert_rule_before(Tb::M6, "OUTPUT", "mwan3", &r);
                }
                let ip = self.iface_path.clone();
                if let Some(ifaces) = self.sys.list_dir(&ip) {
                    for iface in ifaces {
                        self.x(Tb::N4, &format!("-A PSW2_OUTPUT -o {} -p udp -j RETURN", iface));
                        self.x(Tb::M4, &format!("-A PSW2_OUTPUT -o {} -p udp -j RETURN", iface));
                    }
                }
                self.log(2, &msg2);
            }

            let c = comment("mangle-OUTPUT-PSW2");
            let mark_ret = format!("{} -m mark --mark {} -j RETURN", c, FWMARK);
            self.x(Tb::M4, &format!("-I OUTPUT {} -o lo -j RETURN", c));
            self.insert_rule_before(Tb::M4, "OUTPUT", "mwan3", &mark_ret);
            self.x(Tb::M6, &format!("-I OUTPUT {} -o lo -j RETURN", c));
            self.insert_rule_before(Tb::M6, "OUTPUT", "mwan3", &mark_ret);
        }

        if v.is1("client_proxy") {
            let msg1 = api::translatef("[%s],", &[&remarks]);
            let cr = comment(&remarks);
            let interface = v.s("interface");
            for src in sources {
                let mut s = String::new();
                let mut ipv4 = false;
                let mut msg = if !interface.is_empty() {
                    let device = self.sys.iface_device(&interface);
                    s = format!("-i {} ", device);
                    api::translatef("Source iface [%s],", &[&device])
                } else {
                    api::translatef("Source iface [%s],", &[&api::translate("All")])
                };
                match src {
                    AclSource::IpRange(r) => {
                        s = factor(r, &format!("{}-m iprange --src-range", s));
                        msg.push_str(&api::translatef("IP range [%s],", &[r]));
                        ipv4 = true;
                    }
                    AclSource::Ipset(n) => {
                        msg.push_str(&format!("IPset{}", api::translatef("[%s],", &[n])));
                        if self.run(&["ipset", "-q", "list", n]) {
                            s.push_str(&format!("-m set --match-set {} src", n));
                        } else {
                            self.log(2, &format!("{}{}{}", msg1, msg, api::translate("Does not exist, ignore.")));
                            continue;
                        }
                    }
                    AclSource::Ip(a) => {
                        s = factor(a, &format!("{}-s", s));
                        msg.push_str(&format!("IP{}", api::translatef("[%s],", &[a])));
                        ipv4 = true;
                    }
                    AclSource::Mac(m) => {
                        s = factor(m, &format!("{}-m mac --mac-source", s));
                        msg.push_str(&format!("MAC{}", api::translatef("[%s],", &[m])));
                    }
                    AclSource::Any => {
                        msg.push_str(&api::translate("All device,"));
                    }
                }
                let msg = format!("{}{}", msg1, msg);
                let mut no_tcp = false;
                let mut no_udp = false;

                if !tcp_no.is_empty() {
                    if !has_1_65535(&tcp_no) {
                        let cmd = format!("-A PSW2 {} {} -p tcp", cr, s);
                        if !ipv4 {
                            self.add_port_rules(Tb::M6, &cmd, &tcp_no, "-j RETURN");
                        }
                        self.add_port_rules(tmp, &cmd, &tcp_no, "-j RETURN");
                        self.log(2, &format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["TCP", &tcp_no])));
                    } else {
                        // It will return when it ends, so no extra rules are needed.
                        no_tcp = true;
                        self.log(2, &format!("{}{}", msg, api::translatef("not proxy all %s", &["TCP"])));
                    }
                }
                if !udp_no.is_empty() {
                    if !has_1_65535(&udp_no) {
                        let cmd = format!("-A PSW2 {} {} -p udp", cr, s);
                        if !ipv4 {
                            self.add_port_rules(Tb::M6, &cmd, &udp_no, "-j RETURN");
                        }
                        self.add_port_rules(Tb::M4, &cmd, &udp_no, "-j RETURN");
                        self.log(2, &format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["UDP", &udp_no])));
                    } else {
                        no_udp = true;
                        self.log(2, &format!("{}{}", msg, api::translatef("not proxy all %s", &["UDP"])));
                    }
                }

                if (!no_tcp || !no_udp) && !dns_port.is_empty() {
                    for t in [Tb::M4, Tb::M6] {
                        self.x(t, &format!("-A PSW2 {} -p udp {} --dport 53 -j ACCEPT", cr, s));
                        self.x(t, &format!("-A PSW2 {} -p tcp {} --dport 53 -j ACCEPT", cr, s));
                    }
                    for p in ["udp", "tcp"] {
                        let r = format!("-A PSW2_DNS {} -p {} {} --dport 53 -j REDIRECT --to-ports {}", cr, p, s, dns_port);
                        self.x(Tb::N4, &r);
                        self.x(Tb::N6, &r);
                    }
                    self.log(2, &format!("{}{}", msg, api::translatef("DNS will redirected to the dedicated DNS server [%s].", &[&dns_port])));
                } else {
                    for p in ["udp", "tcp"] {
                        let r = format!("-A PSW2_DNS {} -p {} {} --dport 53 -j RETURN", cr, p, s);
                        self.x(Tb::N4, &r);
                        self.x(Tb::N6, &r);
                    }
                }

                if !no_tcp && !redir_port.is_empty() {
                    let mut msg2 = format!("{}{}", msg, api::translatef("Use the %s node [%s]", &["TCP", &node_remarks]));
                    let ipt_j = if self.is_tproxy {
                        msg2.push_str(&format!("(TPROXY:{})", redir_port));
                        "-j PSW2_RULE".to_string()
                    } else {
                        msg2.push_str(&format!("(REDIRECT:{})", redir_port));
                        redirect(&redir_port, "")
                    };
                    if self.accept_icmp {
                        self.x(Tb::N4, &format!("-A PSW2 {} -p icmp {} -d {} {}", cr, s, FAKE_IP, redirect("", "")));
                        self.add_shunt_t_rule(Tb::N4, &sl4, &format!("-A PSW2 {} -p icmp {}", cr, s), &redirect("", ""), "");
                        self.x(Tb::N4, &format!("-A PSW2 {} -p icmp {} {}", cr, s, redirect("", "")));
                    }
                    if self.accept_icmpv6 && self.proxy_ipv6 {
                        self.x(Tb::N6, &format!("-A PSW2 {} -p ipv6-icmp {} -d {} {}", cr, s, FAKE_IP_6, redirect("", "")));
                        self.add_shunt_t_rule(Tb::N6, &sl6, &format!("-A PSW2 {} -p ipv6-icmp {}", cr, s), &redirect("", ""), "");
                        self.x(Tb::N6, &format!("-A PSW2 {} -p ipv6-icmp {} {}", cr, s, redirect("", "")));
                    }
                    let cmd = format!("-A PSW2 {} -p tcp {}", cr, s);
                    self.x(tmp, &format!("{} -d {} {}", cmd, FAKE_IP, ipt_j));
                    self.add_shunt_t_rule(tmp, &sl4, &cmd, &ipt_j, &tcp_redir);
                    self.add_port_rules(tmp, &cmd, &tcp_redir, &ipt_j);
                    if self.is_tproxy {
                        self.x(Tb::M4, &format!("{} {}", cmd, redirect(&redir_port, "TPROXY")));
                    }
                    if self.proxy_ipv6 && !ipv4 {
                        self.x(Tb::M6, &format!("{} -d {} -j PSW2_RULE", cmd, FAKE_IP_6));
                        // upstream quirk: upstream passes `$ipt_j` here, i.e. `-j REDIRECT` in
                        // redirect mode, which is invalid in mangle and fails. Use PSW2_RULE.
                        self.add_shunt_t_rule(Tb::M6, &sl6, &cmd, "-j PSW2_RULE", &tcp_redir);
                        self.add_port_rules(Tb::M6, &cmd, &tcp_redir, "-j PSW2_RULE");
                        self.x(Tb::M6, &format!("{} {}", cmd, redirect(&redir_port, "TPROXY")));
                    }
                    self.log(2, &msg2);
                }
                self.x(tmp, &format!("-A PSW2 {} {} -p tcp -j RETURN", cr, s));
                if !ipv4 {
                    self.x(Tb::M6, &format!("-A PSW2 {} {} -p tcp -j RETURN", cr, s));
                }

                if !no_udp && !redir_port.is_empty() {
                    let msg2 = format!("{}{}(TPROXY:{})", msg, api::translatef("Use the %s node [%s]", &["UDP", &node_remarks]), redir_port);
                    let cmd = format!("-A PSW2 {} -p udp {}", cr, s);
                    self.x(Tb::M4, &format!("{} -d {} -j PSW2_RULE", cmd, FAKE_IP));
                    self.add_shunt_t_rule(Tb::M4, &sl4, &cmd, "-j PSW2_RULE", &udp_redir);
                    self.add_port_rules(Tb::M4, &cmd, &udp_redir, "-j PSW2_RULE");
                    self.x(Tb::M4, &format!("{} {}", cmd, redirect(&redir_port, "TPROXY")));
                    if self.proxy_ipv6 && !ipv4 {
                        self.x(Tb::M6, &format!("{} -d {} -j PSW2_RULE", cmd, FAKE_IP_6));
                        self.add_shunt_t_rule(Tb::M6, &sl6, &cmd, "-j PSW2_RULE", &udp_redir);
                        self.add_port_rules(Tb::M6, &cmd, &udp_redir, "-j PSW2_RULE");
                        self.x(Tb::M6, &format!("{} {}", cmd, redirect(&redir_port, "TPROXY")));
                    }
                    self.log(2, &msg2);
                }
                self.x(Tb::M4, &format!("-A PSW2 {} {} -p udp -j RETURN", cr, s));
                if !ipv4 {
                    self.x(Tb::M6, &format!("-A PSW2 {} {} -p udp -j RETURN", cr, s));
                }
            }
        }
    }

    // ------------------------------------------------------------------ bypass helpers

    /// `filter_haproxy`: load-balancer backend server IPs → psw2_vps.
    pub fn filter_haproxy(&mut self) {
        if self.cfg.get_or("@global_haproxy[0]", "balancing_enable", "0") != "1" {
            return;
        }
        let cfg = self.cfg;
        let mut items = vec![];
        for s in &cfg.sections {
            for (k, v) in &s.options {
                // regex `.lbss=`: any option whose name ends with "lbss"
                if k.ends_with("lbss") {
                    if let Some(first) = v.as_list().into_iter().next() {
                        items.push(first);
                    }
                }
            }
        }
        for item in items {
            let host = item.split(':').next().unwrap_or("").to_string();
            if host.is_empty() {
                continue;
            }
            if let Some(ip) = self.sys.host_ip("ipv4", &host, 1) {
                self.run(&["ipset", "-q", "add", IPSET_VPS, &ip]);
            }
        }
        self.logf(1, "Add node to the load balancer is directly connected to %s[%s].", &["ipset", IPSET_VPS]);
    }

    /// Server addresses of all nodes (`uci show | grep -E "(.address=|.download_address=)"`).
    pub fn vps_addresses(cfg: &Config) -> (Vec<String>, Vec<String>) {
        let mut v4 = vec![];
        let mut v6 = vec![];
        for s in &cfg.sections {
            for (k, v) in &s.options {
                // regex `.address=`: any option whose name ends with "address"
                if !k.ends_with("address") {
                    continue;
                }
                let Some(val) = v.as_list().into_iter().next() else { continue };
                if util::is_ipv4(&val) && val != "127.0.0.1" {
                    if !v4.contains(&val) {
                        v4.push(val);
                    }
                } else {
                    let bare = val.trim_start_matches('[').trim_end_matches(']').to_string();
                    if v6_regex_match(&bare) && util::is_ipv6(&bare) && !v6.contains(&bare) {
                        v6.push(bare);
                    }
                }
            }
        }
        (v4, v6)
    }

    /// `filter_vpsip`: all node server IPs → psw2_vps / psw2_vps6.
    pub fn filter_vpsip(&mut self) {
        let (v4, v6) = Self::vps_addresses(self.cfg);
        if !v4.is_empty() {
            self.ipset_restore(&restore_input(IPSET_VPS, &v4, true));
            self.logf(1, "Add all %s nodes to %s[%s] direct connection complete.", &["IPv4", "ipset", IPSET_VPS]);
        }
        if !v6.is_empty() {
            self.ipset_restore(&restore_input(IPSET_VPS6, &v6, true));
            self.logf(1, "Add all %s nodes to %s[%s] direct connection complete.", &["IPv6", "ipset", IPSET_VPS6]);
        }
    }

    /// `filter_server_port address port stream`
    pub fn filter_server_port(&mut self, address: &str, port: &str, stream: &str) {
        let stream = stream.to_lowercase();
        let t4 = if stream == "udp" || self.is_tproxy { Tb::M4 } else { Tb::N4 };
        let key = format!("{}:{}", address, port);
        for t in [t4, Tb::M6] {
            let Some(b) = self.base(t).cloned() else { continue };
            let mut l = b.clone();
            l.extend(sv(&["-n", "-L", "PSW2_OUTPUT"]));
            if !self.sys.output(&l).contains(&key) {
                self.x(t, &format!("-I PSW2_OUTPUT {} -p {} -d {} --dport {} -j RETURN", comment(&key), stream, address, port));
            }
        }
    }

    /// `filter_node node stream`
    pub fn filter_node(&mut self, node: &str, stream: &str) -> bool {
        if node.is_empty() {
            return true;
        }
        let address = self.cfg.s(node, "address");
        let port = self.cfg.s(node, "port");
        if address.is_empty() && port.is_empty() {
            return false;
        }
        self.filter_server_port(&address, &port, stream);
        self.filter_server_port(&address, &port, stream);
        true
    }

    /// `filter_direct_node_list`: nodes of non-xray/sing-box cores → server RETURN rules.
    pub fn filter_direct_node_list(&mut self) {
        let f = format!("{}/direct_node_list", self.tmp_path);
        let text = self.sys.read(&f);
        let mut seen: Vec<String> = vec![];
        for id in text.split_whitespace() {
            if seen.iter().any(|x| x == id) {
                continue;
            }
            seen.push(id.to_string());
            self.filter_node(id, "TCP");
            self.filter_node(id, "UDP");
        }
    }

    /// `update_wan_sets`: WAN IPs → psw2_wan / psw2_wan6 (under the update lock).
    pub fn update_wan_sets(&mut self) {
        let lock = format!("{}/{}_update_wan_sets.lock", util::LOCK_PATH, util::CONFIG);
        let Some(_guard) = self.sys.lock(&lock) else { return };
        for ip in self.sys.wan_ips("ip4") {
            self.run(&["ipset", "-!", "add", IPSET_WAN, &ip]);
        }
        for ip in self.sys.wan_ips("ip6") {
            self.run(&["ipset", "-!", "add", IPSET_WAN6, &ip]);
        }
    }

    // ------------------------------------------------------------------ add / del

    /// `add_firewall_rule`
    pub fn add_firewall_rule(&mut self, ctx: &Ctx, acl_node: &mut dyn FnMut()) {
        self.logf(0, "Starting to load %s firewall rules...", &["iptables"]);
        self.is_tproxy = ctx.tcp_proxy_way == "tproxy";
        self.proxy_ipv6 = ctx.proxy_ipv6;

        for (n, t) in [(IPSET_LOCAL, "nethash"), (IPSET_DIRECT, "nethash"), (IPSET_VPS, "iphash"), (IPSET_WAN, "nethash")] {
            self.run(&["ipset", "-!", "create", n, t, "maxelem", "1048576"]);
        }
        for (n, t) in [(IPSET_LOCAL6, "nethash"), (IPSET_DIRECT6, "nethash"), (IPSET_VPS6, "iphash"), (IPSET_WAN6, "nethash")] {
            self.run(&["ipset", "-!", "create", n, t, "family", "inet6", "maxelem", "1048576"]);
        }

        let l4 = self.sys.local_ips("ip4");
        self.ipset_restore(&restore_input(IPSET_LOCAL, &l4, false));
        let l6 = self.sys.local_ips("ip6");
        self.ipset_restore(&restore_input(IPSET_LOCAL6, &l6, false));

        let direct_ip = self.sys.read(DIRECT_IP_FILE);
        let entries: Vec<String> = direct_ip
            .split(['\r', '\n'])
            .filter(|l| !l.starts_with('#'))
            .flat_map(|l| l.split_whitespace().map(|x| x.to_string()).collect::<Vec<_>>())
            .collect();
        for ip in entries.iter().map(|s| s.as_str()) {
            if ip.contains("::") {
                self.run(&["ipset", "-!", "add", IPSET_DIRECT6, ip]);
            } else if let Some(rest) = ip.strip_prefix("geoip:") {
                let code = rest.split(':').next().unwrap_or("").to_string();
                let cfg = self.cfg;
                let g4 = self.sys.geoip(cfg, &code, "ipv4");
                self.ipset_restore(&restore_input(IPSET_DIRECT, &filter_entries(&g4, false, false), true));
                let g6 = self.sys.geoip(cfg, &code, "ipv6");
                self.ipset_restore(&restore_input(IPSET_DIRECT6, &filter_entries(&g6, true, false), true));
            } else {
                self.run(&["ipset", "-!", "add", IPSET_DIRECT, ip]);
            }
        }

        // Ignore special IP ranges
        let lan_ifname = self.sys.lan_ifname();
        if !lan_ifname.is_empty() {
            let out = self.sys.output(&sv(&["ip", "address", "show", &lan_ifname]));
            let pick = |fam: &str| -> Vec<String> {
                let mut v = vec![];
                for l in out.lines() {
                    let w: Vec<&str> = l.split_whitespace().collect();
                    if w.len() >= 2 && w[0] == fam {
                        v.push(w[1].to_string());
                    }
                }
                v
            };
            let (a4, a6) = (pick("inet"), pick("inet6"));
            if !a4.is_empty() {
                self.ipset_restore(&restore_input(IPSET_DIRECT, &a4, false));
            }
            if !a6.is_empty() {
                self.ipset_restore(&restore_input(IPSET_DIRECT6, &a6, false));
            }
        }

        self.update_wan_sets();

        for ip in &ctx.isp_dns {
            self.run(&["ipset", "-!", "add", IPSET_DIRECT, ip]);
            self.logf(1, "Add ISP %s DNS to the whitelist: %s", &["IPv4", ip]);
        }
        for ip in &ctx.isp_dns6 {
            self.run(&["ipset", "-!", "add", IPSET_DIRECT6, ip]);
            self.logf(1, "Add ISP %s DNS to the whitelist: %s", &["IPv6", ip]);
        }

        // Filter all node IPs (background, like upstream `&`)
        self.sys.spawn_bg("filter_vpsip");
        self.sys.spawn_bg("filter_haproxy");

        let ipt_n_needed = !self.is_tproxy || self.accept_icmp;
        let ip6t_n_needed = !self.is_tproxy || self.accept_icmpv6;

        self.x(Tb::N4, "-N PSW2");
        self.x(Tb::N4, &format!("-A PSW2 {} -j RETURN", dst(IPSET_VPS, false)));
        self.x(Tb::N4, &format!("-A PSW2 {} {} -j RETURN", comment("WAN_IP_RETURN"), dst(IPSET_WAN, false)));
        if self.accept_icmp {
            self.insert_rule_after(Tb::N4, "PREROUTING", "prerouting_rule", &format!("{} -p icmp -j PSW2", dst(IPSET_DIRECT, true)));
        }
        if !self.is_tproxy {
            self.insert_rule_after(Tb::N4, "PREROUTING", "prerouting_rule", &format!("{} -p tcp -j PSW2", dst(IPSET_DIRECT, true)));
        }
        self.x(Tb::N4, "-N PSW2_OUTPUT");
        self.x(Tb::N4, &format!("-A PSW2_OUTPUT {} -j RETURN", dst(IPSET_VPS, false)));
        self.x(Tb::N4, "-A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN");

        let dns_only_local = self.cfg.get_or("@global[0]", "dns_redirect", "1") == "0";
        self.x(Tb::N4, "-N PSW2_DNS");
        if dns_only_local {
            // Only hijack when dest address is local IP
            self.x(Tb::N4, &format!("-I PREROUTING -m set --match-set {} src {} -j PSW2_DNS", IPSET_DIRECT, dst(IPSET_LOCAL, false)));
        } else {
            self.x(Tb::N4, &format!("-I PREROUTING -m set --match-set {} src -j PSW2_DNS", IPSET_DIRECT));
        }

        self.psw2_rule_chain(Tb::M4);
        self.x(Tb::M4, "-N PSW2");
        // Socket Only TCP, UDP Invalid.
        self.x(Tb::M4, &format!("-A PSW2 -p tcp -m socket --transparent -j MARK --set-mark {}", FWMARK));
        self.x(Tb::M4, "-A PSW2 -p tcp -m socket --transparent -j ACCEPT");
        self.x(Tb::M4, &format!("-A PSW2 {} -j RETURN", dst(IPSET_VPS, false)));
        self.x(Tb::M4, &format!("-A PSW2 {} {} -j RETURN", comment("WAN_IP_RETURN"), dst(IPSET_WAN, false)));
        self.x(Tb::M4, "-A PSW2 -m conntrack --ctdir REPLY -j RETURN");
        self.insert_rule_before(Tb::M4, "PREROUTING", "mwan3", &format!("{} -j PSW2", dst(IPSET_DIRECT, true)));
        self.x(Tb::M4, "-N PSW2_OUTPUT");
        self.x(Tb::M4, &format!("-A PSW2_OUTPUT {} -j RETURN", dst(IPSET_VPS, false)));
        self.x(Tb::M4, "-A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN");
        self.x(Tb::M4, "-A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN");

        self.run(&["ip", "rule", "add", "fwmark", FWMARK, "table", "999", "priority", "999"]);
        self.run(&["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "999"]);

        if self.accept_icmpv6 {
            self.x(Tb::N6, "-N PSW2");
            self.x(Tb::N6, &format!("-A PSW2 {} -j RETURN", dst(IPSET_VPS6, false)));
            self.x(Tb::N6, &format!("-A PREROUTING {} -p ipv6-icmp -j PSW2", dst(IPSET_DIRECT6, true)));
            self.x(Tb::N6, "-N PSW2_OUTPUT");
            self.x(Tb::N6, &format!("-A PSW2_OUTPUT {} -j RETURN", dst(IPSET_VPS6, false)));
            self.x(Tb::N6, "-A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN");
        }

        self.x(Tb::N6, "-N PSW2_DNS");
        if dns_only_local {
            self.x(Tb::N6, &format!("-I PREROUTING -m set --match-set {} src {} -j PSW2_DNS", IPSET_DIRECT6, dst(IPSET_LOCAL6, false)));
        } else {
            self.x(Tb::N6, &format!("-I PREROUTING -m set --match-set {} src -j PSW2_DNS", IPSET_DIRECT6));
        }

        self.psw2_rule_chain(Tb::M6);
        self.x(Tb::M6, "-N PSW2");
        self.x(Tb::M6, &format!("-A PSW2 -p tcp -m socket --transparent -j MARK --set-mark {}", FWMARK));
        self.x(Tb::M6, "-A PSW2 -p tcp -m socket --transparent -j ACCEPT");
        self.x(Tb::M6, &format!("-A PSW2 {} -j RETURN", dst(IPSET_VPS6, false)));
        self.x(Tb::M6, &format!("-A PSW2 {} {} -j RETURN", comment("WAN6_IP_RETURN"), dst(IPSET_WAN6, false)));
        self.x(Tb::M6, "-A PSW2 -m conntrack --ctdir REPLY -j RETURN");
        self.insert_rule_before(Tb::M6, "PREROUTING", "mwan3", &format!("{} -j PSW2", dst(IPSET_DIRECT6, true)));
        self.x(Tb::M6, "-N PSW2_OUTPUT");
        self.x(Tb::M6, "-A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN");
        self.x(Tb::M6, &format!("-A PSW2_OUTPUT {} -j RETURN", dst(IPSET_VPS6, false)));
        self.x(Tb::M6, "-A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN");

        for d in ctx.return_dns.split([',', ' ']).filter(|s| !s.is_empty()) {
            let mut f = d.split('#');
            let addr = f.next().unwrap_or("");
            let port = f.next().filter(|s| !s.is_empty()).unwrap_or("53");
            let proto = f.next().filter(|s| !s.is_empty()).unwrap_or("udp");
            if addr.is_empty() {
                continue;
            }
            let r = format!("-I PSW2_OUTPUT -p {} -d {} --dport {} -j RETURN", proto, addr, port);
            if addr.contains("::") {
                self.x(Tb::M6, &r);
                let a = format!("[{}]:{}", addr, port);
                self.logf(1, "Add direct DNS to %s: %s", &["ip6tables", &a]);
            } else {
                self.x(Tb::M4, &r);
                let a = format!("{}:{}", addr, port);
                self.logf(1, "Add direct DNS to %s: %s", &["iptables", &a]);
            }
        }

        self.run(&["ip", "-6", "rule", "add", "fwmark", FWMARK, "table", "999", "priority", "999"]);
        self.run(&["ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "999"]);

        self.load_acl(&ctx.acl_flags, acl_node);

        // upstream quirk: upstream runs this in the background, racing gen_include (the include
        // then sometimes misses the node RETURN rules). It is a handful of local rules, so it runs
        // in the foreground here and the include always captures them.
        self.filter_direct_node_list();

        if !ipt_n_needed {
            for c in ["PSW2", "PSW2_OUTPUT"] {
                self.x(Tb::N4, &format!("-F {}", c));
                self.x(Tb::N4, &format!("-X {}", c));
            }
        }
        if !ip6t_n_needed {
            for c in ["PSW2", "PSW2_OUTPUT"] {
                self.x(Tb::N6, &format!("-F {}", c));
                self.x(Tb::N6, &format!("-X {}", c));
            }
        }

        let direct = format!("-I OUTPUT {} -m owner --gid-owner {} -j RETURN", comment("PSW2_DIRECT"), util::DIRECT_GID);
        for t in [Tb::N4, Tb::M4, Tb::N6, Tb::M6] {
            self.x(t, &direct);
        }

        self.logf(0, "%s firewall rules load complete!", &["iptables"]);
    }

    fn psw2_rule_chain(&mut self, t: Tb) {
        self.x(t, "-N PSW2_RULE");
        self.x(t, "-A PSW2_RULE -j CONNMARK --restore-mark");
        self.x(t, &format!("-A PSW2_RULE -m mark --mark {} -j RETURN", FWMARK));
        self.x(t, &format!("-A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark {}", FWMARK));
        self.x(t, &format!("-A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark {}", FWMARK));
        self.x(t, "-A PSW2_RULE -j CONNMARK --save-mark");
    }

    /// `del_firewall_rule`
    pub fn del_firewall_rule(&mut self) {
        for t in [Tb::N4, Tb::M4, Tb::N6, Tb::M6] {
            let Some(b) = self.base(t).cloned() else { continue };
            for chain in ["PREROUTING", "OUTPUT"] {
                let mut l = b.clone();
                l.extend(sv(&["-nL", chain]));
                let count = self.sys.output(&l).lines().filter(|x| x.contains("PSW2")).count();
                let mut ln = b.clone();
                ln.extend(sv(&["--line-number", "-nL", chain]));
                for _ in 0..count {
                    let Some(idx) = rule_index(&self.sys.output(&ln), "PSW2", false) else { break };
                    self.x(t, &format!("-D {} {}", chain, idx));
                }
            }
            for chain in ["PSW2", "PSW2_OUTPUT", "PSW2_DNS", "PSW2_RULE"] {
                self.x(t, &format!("-F {}", chain));
                self.x(t, &format!("-X {}", chain));
            }
        }
        self.run(&["ip", "rule", "del", "fwmark", FWMARK]);
        self.run(&["ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "999"]);
        self.run(&["ip", "-6", "rule", "del", "fwmark", FWMARK]);
        self.run(&["ip", "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "999"]);
        self.logf(0, "Delete %s rules is complete.", &["iptables"]);
    }

    /// `flush_ipset`: destroy every `psw2_*` ipset.
    pub fn flush_ipset(&mut self) {
        self.logf(0, "Clear %s.", &["IPSet"]);
        let names = self.sys.output(&sv(&["ipset", "-n", "list"]));
        for n in names.split_whitespace().filter(|n| n.contains("psw2_")) {
            self.run(&["ipset", "-q", "-F", n]);
            self.run(&["ipset", "-q", "-X", n]);
        }
    }

    /// `flush_include`
    pub fn flush_include(&mut self) {
        if self.fwi.is_empty() {
            return;
        }
        let f = self.fwi.clone();
        self.sys.write(&f, "#!/bin/sh\n");
    }

    /// `extract_rules 4|6 table` (evaluated at generation time).
    fn extract_rules(&mut self, v6: bool, table: &str) -> String {
        let bin = if v6 { self.ip6t.clone() } else { self.ipt.clone() };
        let Some(bin) = bin else { return String::new() };
        let save = self.sys.output(&sv(&[&format!("{}-save", bin), "-t", table]));
        let mut out = format!("*{}\n", table);
        for l in save.lines() {
            if !l.contains("PSW2") || l.contains("PSW2_DIRECT") || l.ends_with("-j PSW2") {
                continue;
            }
            let l = if let Some(r) = l.strip_prefix("-A OUTPUT") {
                format!("-I OUTPUT 1{}", r)
            } else if let Some(r) = l.strip_prefix("-A PREROUTING") {
                format!("-I PREROUTING 1{}", r)
            } else {
                l.to_string()
            };
            out.push_str(&l);
            out.push('\n');
        }
        out.push_str("COMMIT");
        out
    }

    /// Text appended to the include after `#!/bin/sh` (see [`Fw::gen_include`]).
    pub fn include_body(&mut self) -> String {
        let me = format!("{} ipt", util::SELF_BIN);
        // a disabled table (ip6 module missing) renders as upstream's `eval #...` no-op
        let line = |base: String, rest: &str| -> String { format!("{} {}", base, rest) };
        let direct = format!("-I OUTPUT {} -m owner --gid-owner {} -j RETURN", comment("PSW2_DIRECT"), util::DIRECT_GID);
        let mut ipt_block = String::new();
        if let Some(ipt) = self.ipt.clone() {
            let nat = self.extract_rules(false, "nat");
            let mangle = self.extract_rules(false, "mangle");
            let n4 = self.base_str(Tb::N4);
            let m4 = self.base_str(Tb::M4);
            ipt_block = [
                format!("{} update_wan_sets", me),
                format!("{}-save -c | grep -v \"PSW2\" | {}-restore -c", ipt, ipt),
                format!("{}-restore -n <<-'EOT'", ipt),
                nat,
                mangle,
                "EOT".into(),
                line(n4.clone(), &direct),
                line(m4.clone(), &direct),
                String::new(),
                format!(
                    "[ \"{}\" = \"1\" ] && {} insert_rule_after \"{}\" \"PREROUTING\" \"prerouting_rule\" \"{} -p icmp -j PSW2\"",
                    if self.accept_icmp { "1" } else { "0" },
                    me,
                    n4,
                    dst(IPSET_DIRECT, true)
                ),
                format!(
                    "[ -z \"{}\" ] && {} insert_rule_after \"{}\" \"PREROUTING\" \"prerouting_rule\" \"{} -p tcp -j PSW2\"",
                    if self.is_tproxy { "TPROXY" } else { "" },
                    me,
                    n4,
                    dst(IPSET_DIRECT, true)
                ),
                String::new(),
                format!("{} insert_rule_before \"{}\" \"PREROUTING\" \"mwan3\" \"{} -j PSW2\"", me, m4, dst(IPSET_DIRECT, true)),
            ]
            .join("\n");
        }
        let mut ip6t_block = String::new();
        if let Some(ip6t) = self.ip6t.clone() {
            let nat = self.extract_rules(true, "nat");
            let mangle = self.extract_rules(true, "mangle");
            let n6 = self.base_str(Tb::N6);
            let m6 = self.base_str(Tb::M6);
            ip6t_block = [
                format!("{} update_wan_sets", me),
                format!("{}-save -c | grep -v \"PSW2\" | {}-restore -c", ip6t, ip6t),
                format!("{}-restore -n <<-'EOT'", ip6t),
                nat,
                mangle,
                "EOT".into(),
                line(n6.clone(), &direct),
                line(m6.clone(), &direct),
                String::new(),
                format!(
                    "[ \"{}\" = \"1\" ] && {}",
                    if self.accept_icmpv6 { "1" } else { "0" },
                    line(n6, &format!("-A PREROUTING {} -p ipv6-icmp -j PSW2", dst(IPSET_DIRECT6, true)))
                ),
                String::new(),
                format!("{} insert_rule_before \"{}\" \"PREROUTING\" \"mwan3\" \"{} -j PSW2\"", me, m6, dst(IPSET_DIRECT6, true)),
            ]
            .join("\n");
        }
        format!("{}\n\n{}\n\nreturn 0\n", ipt_block, ip6t_block)
    }

    /// `gen_include`: write the fw3 include restoring the rules on firewall reload.
    pub fn gen_include(&mut self) {
        self.flush_include();
        if self.fwi.is_empty() {
            return;
        }
        let body = self.include_body();
        let f = self.fwi.clone();
        self.sys.append(&f, &body);
    }

    /// `start`
    pub fn start(&mut self, ctx: &Ctx, acl_node: &mut dyn FnMut()) {
        if !ctx.enabled_default_acl && !ctx.enabled_acls {
            return;
        }
        self.add_firewall_rule(ctx, acl_node);
        self.gen_include();
    }

    /// `stop`
    pub fn stop(&mut self) {
        self.del_firewall_rule();
        if self.cfg.get_or("@global[0]", "flush_set", "0") == "1" {
            let mut b = crate::uci::Batch::new();
            b.delete(&format!("{}.@global[0].flush_set", util::CONFIG));
            let _ = b.commit();
            self.flush_ipset();
            if let Some(entries) = self.sys.list_dir(util::TMP_PATH2) {
                for e in entries.iter().filter(|e| e.starts_with("singbox")) {
                    util::rm_rf(&format!("{}/{}", util::TMP_PATH2, e));
                }
            }
            util::rm_rf(&format!("{}/geo_output", util::TMP_PATH2));
        }
        self.flush_include();
    }
}

// ====================================================================== public API

/// `iptables.sh start` (app.sh sources it inside `start`). `acl_node` is app.sh's
/// `acl_node` (starts every ACL core + dnsmasq copy); it is called from `load_acl`
/// before the per-ACL rules, exactly like upstream.
pub fn start(ctx: &Ctx, acl_node: &mut dyn FnMut()) {
    let cfg = Config::load(util::CONFIG);
    let mut sys = RealSys;
    let mut fw = Fw::system(&mut sys, &cfg);
    fw.start(ctx, acl_node);
}

/// `iptables.sh stop`
pub fn stop() {
    let cfg = Config::load(util::CONFIG);
    let mut sys = RealSys;
    Fw::system(&mut sys, &cfg).stop();
}

/// `iptables.sh filter_direct_node_list` (called by the runtime after starting a node
/// whose core is not xray/sing-box).
pub fn filter_direct_node_list() {
    let cfg = Config::load(util::CONFIG);
    let mut sys = RealSys;
    Fw::system(&mut sys, &cfg).filter_direct_node_list();
}

/// `iptables.sh update_wan_sets` (hotplug / firewall include).
pub fn update_wan_sets() {
    let cfg = Config::load(util::CONFIG);
    let mut sys = RealSys;
    Fw::system(&mut sys, &cfg).update_wan_sets();
}

/// `flush_ipset` (also used by the `flush_set` controller endpoint path at stop).
pub fn flush_ipset() {
    let cfg = Config::load(util::CONFIG);
    let mut sys = RealSys;
    Fw::system(&mut sys, &cfg).flush_ipset();
}

/// `passwall2 ipt <sub> [args]` — same dispatcher as the shell script, plus the internal
/// background helpers `filter_vpsip`, `filter_haproxy` and `flush_ipset`.
pub fn cli(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let a = |i: usize| rest.get(i).cloned().unwrap_or_default();
    let mut sys = RealSys;
    match sub {
        "RULE_LAST_INDEX" => {
            if rest.len() < 3 {
                api::log_i18n(1, "Incorrect index listing method (%s), execution terminated!", &["iptables"]);
                return 1;
            }
            let mut l = words(&a(0));
            if l.first().map(|s| s.as_str()) == Some("eval") {
                println!("{}", rest.get(3).filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "0".into()));
                return 0;
            }
            l.extend(sv(&["-n", "-L", &a(1), "--line-numbers"]));
            let idx = rule_index(&sys.output(&l), &a(2), false);
            let def = rest.get(3).filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "0".into());
            println!("{}", idx.map(|i| i.to_string()).unwrap_or(def));
            0
        }
        "insert_rule_before" | "insert_rule_after" => {
            if rest.len() < 3 {
                return 1;
            }
            let def = rest.get(4).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            insert_rule(&mut sys, &words(&a(0)), &a(1), &a(2), &a(3), def, sub == "insert_rule_after");
            0
        }
        "get_ipt_bin" => {
            println!("{}", get_ipt_bin().unwrap_or_default());
            0
        }
        "get_ip6t_bin" => {
            println!("{}", get_ip6t_bin().unwrap_or_default());
            0
        }
        "filter_direct_node_list" | "filter_vpsip" | "filter_haproxy" | "update_wan_sets" | "flush_ipset" | "stop" | "start" => {
            let cfg = Config::load(util::CONFIG);
            let mut fw = Fw::system(&mut sys, &cfg);
            match sub {
                "filter_direct_node_list" => fw.filter_direct_node_list(),
                "filter_vpsip" => fw.filter_vpsip(),
                "filter_haproxy" => fw.filter_haproxy(),
                "update_wan_sets" => fw.update_wan_sets(),
                "flush_ipset" => fw.flush_ipset(),
                "stop" => fw.stop(),
                _ => {
                    // inside the service start (QUEUE_RUN=1) launch the ACL cores from load_acl
                    // (app.sh's acl_node); standalone: they are expected to be running already
                    let ctx = Ctx::from_system(&cfg);
                    fw.start(&ctx, &mut crate::firewall::acl_node_hook);
                }
            }
            0
        }
        _ => 0,
    }
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Mock {
        cmds: Vec<String>,
        stdin: Vec<(String, String)>,
        outputs: HashMap<String, String>,
        files: HashMap<String, String>,
        cache: HashMap<String, String>,
        bg: Vec<String>,
        ipsets: Vec<String>,
        ifaces: Option<Vec<String>>,
        geo: bool,
    }
    impl Sys for Mock {
        fn run(&mut self, argv: &[String]) -> bool {
            let j = argv.join(" ");
            let ok = !(j.starts_with("ipset -q list ") && !self.ipsets.iter().any(|s| j.ends_with(&format!(" {}", s))));
            self.cmds.push(j);
            ok
        }
        fn output(&mut self, argv: &[String]) -> String {
            let j = argv.join(" ");
            self.outputs.get(&j).cloned().unwrap_or_default()
        }
        fn run_stdin(&mut self, argv: &[String], input: &str) -> bool {
            self.stdin.push((argv.join(" "), input.to_string()));
            true
        }
        fn log(&mut self, _l: usize, _m: &str) {}
        fn read(&mut self, p: &str) -> String {
            self.files.get(p).cloned().unwrap_or_default()
        }
        fn write(&mut self, p: &str, d: &str) {
            self.files.insert(p.into(), d.into());
        }
        fn append(&mut self, p: &str, d: &str) {
            self.files.entry(p.into()).or_default().push_str(d);
        }
        fn list_dir(&mut self, _p: &str) -> Option<Vec<String>> {
            self.ifaces.clone()
        }
        fn get_cache_var(&mut self, k: &str) -> Option<String> {
            self.cache.get(k).cloned()
        }
        fn set_cache_var(&mut self, k: &str, v: &str) {
            self.cache.insert(k.into(), v.into());
        }
        fn local_ips(&mut self, fam: &str) -> Vec<String> {
            if fam == "ip6" {
                vec!["::1".into()]
            } else {
                vec!["192.168.1.1".into(), "127.0.0.1".into()]
            }
        }
        fn wan_ips(&mut self, fam: &str) -> Vec<String> {
            if fam == "ip6" {
                vec![]
            } else {
                vec!["100.1.2.3".into()]
            }
        }
        fn host_ip(&mut self, _f: &str, h: &str, _c: u32) -> Option<String> {
            Some(if util::is_ipv4(h) { h.to_string() } else { "9.9.9.9".into() })
        }
        fn iface_device(&mut self, i: &str) -> String {
            format!("br-{}", i)
        }
        fn lan_ifname(&mut self) -> String {
            String::new()
        }
        fn geoip(&mut self, _c: &Config, codes: &str, typ: &str) -> String {
            if typ == "ipv4" {
                format!("1.0.1.0/24\nbad\n# {}\n", codes)
            } else {
                "2400:da00::/32\n".into()
            }
        }
        fn has_geoview(&mut self) -> bool {
            self.geo
        }
        fn spawn_bg(&mut self, sub: &str) {
            self.bg.push(sub.into());
        }
        fn lock(&mut self, _p: &str) -> Option<std::fs::File> {
            std::fs::File::open("/dev/null").ok()
        }
    }

    const ACL_PATH: &str = "/acl";

    fn cfg(extra_fwd: &str) -> Config {
        let t = format!(
            "config global\n\toption enabled '1'\n\toption node 'n1'\n\
config global_forwarding\n\toption tcp_redir_ports '1:65535'\n\toption udp_redir_ports '1:65535'\n{}\
config global_haproxy\n\toption balancing_enable '1'\n\
config haproxy_config\n\toption lbss 'lb.example.com:443'\n\
config nodes 'n1'\n\toption protocol '_shunt'\n\toption enable_geoview_ip '1'\n\toption sr1 '_direct'\n\toption sr2 'n2'\n\toption default_node 'n2'\n\
config nodes 'n2'\n\toption address '5.6.7.8'\n\toption port '443'\n\toption download_address '2001:db8::5'\n\
config nodes 'n3'\n\toption address '127.0.0.1'\n\
config shunt_rules 'sr1'\n\toption ip_list 'geoip:cn'\n\
config shunt_rules 'sr2'\n\toption ip_list '8.8.8.8'\n\
config shunt_rules 'sr3'\n\toption group 'other'\n",
            extra_fwd
        );
        Config::parse("passwall2", &t)
    }

    fn mock_with_acls() -> Mock {
        let mut m = Mock { geo: true, ipsets: vec!["myset".into()], ..Default::default() };
        m.files.insert(
            format!("{}/r1/var", ACL_PATH),
            "flag=\"r1\"\nremarks=\"LAN A\"\ninterface=\"lan\"\ntcp_no_redir_ports=\"25\"\nudp_no_redir_ports=\"\"\ntcp_redir_ports=\"80,443\"\nudp_redir_ports=\"1:65535\"\nclient_proxy=\"1\"\nlocal_proxy=\"0\"\nnode=\"n2\"\nuse=\"r1\"\nnode=\"n2\"\nnode_remarks=\"Node 2\"\nredir_port=\"1041\"\n".into(),
        );
        m.files.insert(format!("{}/r1/source_list", ACL_PATH), "ip:192.168.1.10\nipset:ipset:myset\nipset:ipset:nope\nmac:aa:bb:cc:dd:ee:ff".into());
        m.files.insert(
            format!("{}/acl_default/var", ACL_PATH),
            "flag=\"acl_default\"\nremarks=\"Default\"\ntcp_redir_ports=\"1:65535\"\nudp_redir_ports=\"1:65535\"\nclient_proxy=\"1\"\nlocal_proxy=\"1\"\nnode=\"n1\"\nuse=\"acl_default\"\nnode=\"n1\"\nnode_remarks=\"Shunt\"\nredir_port=\"1031\"\n".into(),
        );
        m.files.insert(format!("{}/acl_default/source_list", ACL_PATH), "any".into());
        m.cache.insert("ACL_acl_default_dns_port".into(), "1035".into());
        m.cache.insert("ACL_r1_dns_port".into(), "1045".into());
        m.cache.insert("node_n1_direct_ipset4".into(), "psw2_n1_white".into());
        m.files.insert("/usr/share/passwall2/direct_ip".into(), "# c\n10.0.0.0/8\nfc00::/7\n\ngeoip:private\n".into());
        m.outputs.insert("iptables -t mangle -w -n -L PREROUTING --line-numbers".into(), "Chain PREROUTING (policy ACCEPT)\nnum  target     prot opt source               destination\n1    mwan3_hook  all  --  0.0.0.0/0            0.0.0.0/0\n".into());
        m
    }

    fn ctx(way: &str, v6: bool) -> Ctx {
        Ctx {
            isp_dns: vec!["223.5.5.5".into()],
            isp_dns6: vec![],
            return_dns: "223.5.5.5#53,2001:4860::8888#53#tcp".into(),
            tcp_proxy_way: way.into(),
            proxy_ipv6: v6,
            enabled_default_acl: true,
            enabled_acls: true,
            acl_flags: vec!["r1".into(), "acl_default".into()],
        }
    }

    fn run_start(c: &Config, m: &mut Mock, cx: &Ctx, nat6: bool) -> Vec<String> {
        let mut called = 0;
        {
            let mut fw = Fw::new(m, c, Some("iptables".into()), Some("ip6tables".into()), nat6, true);
            fw.acl_path = ACL_PATH.into();
            fw.fwi = "/fwi".into();
            fw.start(cx, &mut || called += 1);
        }
        assert_eq!(called, 1);
        m.cmds.clone()
    }

    fn pos(cmds: &[String], s: &str) -> usize {
        cmds.iter().position(|c| c == s).unwrap_or_else(|| panic!("missing: {}\n---\n{}", s, cmds.join("\n")))
    }

    #[test]
    fn t_helpers() {
        assert_eq!(factor("1:65535", "-s"), "");
        assert_eq!(factor("1.2.3.4", "-i br-lan -s"), "-i br-lan -s 1.2.3.4");
        assert_eq!(dst("x", true), "-m set ! --match-set x dst");
        assert_eq!(comment("LAN  A b"), "-m comment --comment LAN_A_b");
        assert_eq!(comment(""), "");
        assert_eq!(redirect("", ""), "-j REDIRECT");
        assert_eq!(redirect("12", ""), "-j REDIRECT --to-ports 12");
        assert_eq!(redirect("12", "TPROXY"), "-m mark --mark 0x50535732 -j TPROXY --on-port 12");
        assert!(has_1_65535("80,1:65535"));
        assert!(has_1_65535("1-65535"));
        assert!(!has_1_65535("11:65535"));
    }

    #[test]
    fn t_port_fragments() {
        assert_eq!(port_fragments(""), None);
        assert_eq!(port_fragments("abc"), None);
        assert_eq!(port_fragments("1:65535"), Some(vec![String::new()]));
        assert_eq!(port_fragments("80,1-65535"), Some(vec![String::new()]));
        let ports: Vec<String> = (1..=17).map(|p| p.to_string()).collect();
        let s = format!("{},1000-2000,5,3000:4000", ports.join(","));
        let f = port_fragments(&s).unwrap();
        assert_eq!(f.len(), 4);
        assert_eq!(f[0], "-m multiport --dport 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15");
        assert_eq!(f[1], "-m multiport --dport 16,17");
        assert_eq!(f[2], "--dport 1000:2000");
        assert_eq!(f[3], "--dport 3000:4000");
        assert_eq!(port_fragments(" 80 , 443,80").unwrap(), vec!["-m multiport --dport 80,443".to_string()]);
    }

    #[test]
    fn t_entries() {
        assert!(valid_set_entry("1.2.3.0/24", false));
        assert!(valid_set_entry("1.2.3.1-1.2.3.9", false));
        assert!(!valid_set_entry("1.2.3.4:80", false));
        assert!(!valid_set_entry("geoip:cn", false));
        assert!(valid_set_entry("2001:db8::/32", true));
        assert!(!valid_set_entry("::1", true));
        assert!(!valid_set_entry("1.2.3.4", true));
        assert_eq!(filter_entries("1.1.1.1 # x\n2001::1\nfoo\r\n8.8.8.0/24", false, true), vec!["1.1.1.1", "8.8.8.0/24"]);
        assert!(v6_regex_match("nameserver fe80::1%eth0"));
        assert!(!v6_regex_match("::1"));
    }

    #[test]
    fn t_dns() {
        let (v4, v6) = parse_isp_dns("# Interface wan\nnameserver 223.5.5.5\nnameserver 127.0.0.1\nnameserver 223.5.5.5\nnameserver 1.2.3.4\nnameserver fe80::1%eth0\nnameserver ::1\n");
        assert_eq!(v4, vec!["223.5.5.5", "1.2.3.4"]);
        assert_eq!(v6, vec!["fe80::1"]);
        assert_eq!(compute_return_dns(&[], &v4, "", ""), "223.5.5.5,1.2.3.4");
        assert_eq!(compute_return_dns(&[], &[], "auto", ""), "119.29.29.29");
        let srv = vec!["/lan/127.0.0.1".to_string(), "8.8.8.8".to_string(), "1.1.1.1#5353".to_string(), "9.9.9.9".to_string()];
        assert_eq!(compute_return_dns(&srv, &v4, "udp", "114.114.114.114:5353"), "8.8.8.8#53,1.1.1.1#5353,114.114.114.114#5353#udp");
    }

    #[test]
    fn t_insert_rule() {
        let mut m = Mock::default();
        let base = sv(&["iptables", "-t", "nat", "-w"]);
        let listing = "Chain PREROUTING (policy ACCEPT)\nnum  target     prot opt source destination\n1    prerouting_rule  all  --  0.0.0.0/0 0.0.0.0/0\n2    zone_lan_prerouting  all\n3    prerouting_rule  all\n4    x\n";
        m.outputs.insert("iptables -t nat -w -n -L PREROUTING --line-numbers".into(), listing.into());
        insert_rule(&mut m, &base, "PREROUTING", "prerouting_rule", "-p tcp -j PSW2", 0, true);
        insert_rule(&mut m, &base, "PREROUTING", "prerouting_rule", "-p tcp -j PSW2", 0, false);
        insert_rule(&mut m, &base, "PREROUTING", "mwan3", "-j PSW2", 0, false);
        insert_rule(&mut m, &base, "PREROUTING", "mwan3", "-j PSW2", 2, true);
        assert!(!insert_rule(&mut m, &sv(&["eval", "#ip6tables"]), "PREROUTING", "mwan3", "-j PSW2", 0, true));
        assert_eq!(
            m.cmds,
            vec![
                "iptables -t nat -w -I PREROUTING 4 -p tcp -j PSW2",
                "iptables -t nat -w -I PREROUTING 1 -p tcp -j PSW2",
                "iptables -t nat -w -A PREROUTING -j PSW2",
                "iptables -t nat -w -I PREROUTING 2 -j PSW2",
            ]
        );
    }

    #[test]
    fn t_start_redirect() {
        let c = cfg("\toption accept_icmp '1'\n");
        let mut m = mock_with_acls();
        let cmds = run_start(&c, &mut m, &ctx("redirect", false), false);
        // ipsets first
        assert_eq!(cmds[0], "ipset -! create psw2_local nethash maxelem 1048576");
        assert_eq!(cmds[6], "ipset -! create psw2_vps6 iphash family inet6 maxelem 1048576");
        assert_eq!(m.stdin[0].1, "add psw2_local 192.168.1.1\nadd psw2_local 127.0.0.1\n");
        pos(&cmds, "ipset -! add psw2_direct 10.0.0.0/8");
        pos(&cmds, "ipset -! add psw2_direct6 fc00::/7");
        pos(&cmds, "ipset -! add psw2_wan 100.1.2.3");
        pos(&cmds, "ipset -! add psw2_direct 223.5.5.5");
        assert_eq!(m.bg, vec!["filter_vpsip", "filter_haproxy"]);
        // nat base (redirect + icmp): no prerouting_rule → appended
        let a = pos(&cmds, "iptables -t nat -w -A PREROUTING -m set ! --match-set psw2_direct dst -p icmp -j PSW2");
        let b = pos(&cmds, "iptables -t nat -w -A PREROUTING -m set ! --match-set psw2_direct dst -p tcp -j PSW2");
        assert!(a < b);
        pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment WAN_IP_RETURN -m set --match-set psw2_wan dst -j RETURN");
        pos(&cmds, "iptables -t nat -w -I PREROUTING -m set --match-set psw2_direct src -j PSW2_DNS");
        // mangle PREROUTING jump inserted before mwan3 (line 1)
        pos(&cmds, "iptables -t mangle -w -I PREROUTING 1 -m set ! --match-set psw2_direct dst -j PSW2");
        // ip6 nat disabled (module missing): no N6 commands at all
        assert!(!cmds.iter().any(|c| c.starts_with("ip6tables -t nat")));
        pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment WAN6_IP_RETURN -m set --match-set psw2_wan6 dst -j RETURN");
        // RETURN_DNS
        pos(&cmds, "iptables -t mangle -w -I PSW2_OUTPUT -p udp -d 223.5.5.5 --dport 53 -j RETURN");
        pos(&cmds, "ip6tables -t mangle -w -I PSW2_OUTPUT -p tcp -d 2001:4860::8888 --dport 53 -j RETURN");
        pos(&cmds, "ip -6 route add local ::/0 dev lo table 999");

        // shunt sets for n1 (geoview enabled): sr1 direct, sr2 redirect; sr3 other group
        pos(&cmds, "ipset -! create psw2_n1_sr1 nethash maxelem 1048576");
        pos(&cmds, "ipset -! create psw2_n1_white iphash maxelem 1048576 timeout 259200");
        assert!(!cmds.iter().any(|c| c.contains("psw2_n1_sr3")));
        assert!(m.stdin.iter().any(|(_, i)| i == "add psw2_n1_sr1 1.0.1.0/24\nCOMMIT\n"));
        assert!(m.stdin.iter().any(|(_, i)| i == "add psw2_n1_sr2 8.8.8.8\nCOMMIT\n"));
        assert_eq!(m.cache.get("node_n1_gen_shunt_list").map(|s| s.as_str()), Some("1"));

        // ACL r1, source ip (ipv4 only → no v6 rules)
        let s = "-m comment --comment LAN_A -i br-lan -s 192.168.1.10";
        let no = pos(&cmds, &format!("iptables -t nat -w -A PSW2 {} -p tcp -m multiport --dport 25 -j RETURN", s));
        let d1 = pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment LAN_A -p udp -i br-lan -s 192.168.1.10 --dport 53 -j ACCEPT");
        let d2 = pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -s 192.168.1.10 --dport 53 -j ACCEPT");
        let d3 = pos(&cmds, "iptables -t nat -w -A PSW2_DNS -m comment --comment LAN_A -p udp -i br-lan -s 192.168.1.10 --dport 53 -j REDIRECT --to-ports 1045");
        assert!(no < d1 && d1 < d2 && d2 < d3);
        let icmp = pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment LAN_A -p icmp -i br-lan -s 192.168.1.10 -d 198.18.0.0/16 -j REDIRECT");
        let fake = pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -s 192.168.1.10 -d 198.18.0.0/16 -j REDIRECT --to-ports 1041");
        let ports = pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -s 192.168.1.10 -m multiport --dport 80,443 -j REDIRECT --to-ports 1041");
        let ret = pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment LAN_A -i br-lan -s 192.168.1.10 -p tcp -j RETURN");
        assert!(icmp < fake && fake < ports && ports < ret);
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment LAN_A -p udp -i br-lan -s 192.168.1.10 -m mark --mark 0x50535732 -j TPROXY --on-port 1041");
        assert!(!cmds.iter().any(|c| c.starts_with("ip6tables -t mangle -w -A PSW2 -m comment --comment LAN_A -i br-lan -s 192.168.1.10")));
        // ipset source (exists) gets v6 rules; missing set skipped
        pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment LAN_A -i br-lan -m set --match-set myset src -p udp -j RETURN");
        assert!(!cmds.iter().any(|c| c.contains("--match-set nope src")));
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment LAN_A -p udp -i br-lan -m mac --mac-source aa:bb:cc:dd:ee:ff -d 198.18.0.0/16 -j PSW2_RULE");

        // default ACL: local proxy (redirect) with shunt sets + dns
        pos(&cmds, "iptables -t nat -w -A OUTPUT -m comment --comment PSW2_DNS -p udp -o lo --dport 53 -j REDIRECT --to-ports 1035");
        pos(&cmds, "iptables -t nat -w -A OUTPUT -m set ! --match-set psw2_direct dst -p icmp -j PSW2_OUTPUT");
        pos(&cmds, "iptables -t nat -w -A PSW2_OUTPUT -p icmp -m set --match-set psw2_n1_sr1 dst -j RETURN");
        pos(&cmds, "iptables -t nat -w -A PSW2_OUTPUT -p icmp -m set --match-set psw2_n1_sr2 dst -j REDIRECT");
        pos(&cmds, "iptables -t nat -w -A PSW2_OUTPUT -p tcp -m set --match-set psw2_n1_sr2 dst -j REDIRECT --to-ports 1031");
        pos(&cmds, "iptables -t nat -w -A PSW2_OUTPUT -p tcp -m set --match-set psw2_n1_white dst -j RETURN");
        pos(&cmds, "iptables -t nat -w -A PSW2_OUTPUT -p tcp -j REDIRECT --to-ports 1031");
        pos(&cmds, "iptables -t nat -w -A OUTPUT -m set ! --match-set psw2_direct dst -p tcp -j PSW2_OUTPUT");
        pos(&cmds, "iptables -t mangle -w -A PSW2_OUTPUT -p udp -j PSW2_RULE");
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment Local -p udp -i lo -m mark --mark 0x50535732 -j TPROXY --on-port 1031");
        pos(&cmds, "iptables -t mangle -w -A OUTPUT -m comment --comment mangle-OUTPUT-PSW2 -m set ! --match-set psw2_direct dst -p udp -j PSW2_OUTPUT");
        pos(&cmds, "iptables -t mangle -w -I OUTPUT -m comment --comment mangle-OUTPUT-PSW2 -o lo -j RETURN");
        pos(&cmds, "ip6tables -t mangle -w -A OUTPUT -m comment --comment mangle-OUTPUT-PSW2 -m mark --mark 0x50535732 -j RETURN");
        // default ACL client "any": no source match
        pos(&cmds, "iptables -t nat -w -A PSW2 -m comment --comment Default -p tcp -j REDIRECT --to-ports 1031");
        pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment Default -p udp -j RETURN");

        // tail: PSW2_DIRECT on all enabled tables, nat kept (redirect)
        let n = cmds.len();
        assert_eq!(cmds[n - 3], "iptables -t nat -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN");
        assert_eq!(cmds[n - 1], "ip6tables -t mangle -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN");
        assert!(!cmds.iter().any(|c| c == "iptables -t nat -w -X PSW2"));
        // include written
        let inc = m.files.get("/fwi").unwrap();
        assert!(inc.starts_with("#!/bin/sh\n/usr/bin/passwall2 ipt update_wan_sets\niptables-save -c | grep -v \"PSW2\" | iptables-restore -c\n"));
        assert!(inc.ends_with("\n\nreturn 0\n"));
    }

    #[test]
    fn t_start_tproxy_v6() {
        let c = cfg("");
        let mut m = mock_with_acls();
        let cmds = run_start(&c, &mut m, &ctx("tproxy", true), true);
        // no nat tcp jump; nat PSW2 removed at the end
        assert!(!cmds.iter().any(|c| c.contains("-p tcp -j PSW2") && c.starts_with("iptables -t nat")));
        let f = pos(&cmds, "iptables -t nat -w -F PSW2");
        pos(&cmds, "ip6tables -t nat -w -X PSW2_OUTPUT");
        assert!(f > pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment Default -p udp -j RETURN"));
        // tcp goes through mangle with PSW2_RULE + TPROXY
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -s 192.168.1.10 -m multiport --dport 80,443 -j PSW2_RULE");
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -s 192.168.1.10 -m mark --mark 0x50535732 -j TPROXY --on-port 1041");
        // v6 for non-ipv4 sources
        pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment LAN_A -p tcp -i br-lan -m mac --mac-source aa:bb:cc:dd:ee:ff -d 2001:2::/48 -j PSW2_RULE");
        pos(&cmds, "ip6tables -t mangle -w -A PSW2 -m comment --comment Default -p tcp -m set --match-set psw2_n1_sr26 dst -j PSW2_RULE");
        // local tcp in tproxy: mangle OUTPUT jump appended (no mwan3 in OUTPUT listing)
        pos(&cmds, "iptables -t mangle -w -A PSW2_OUTPUT -p tcp -d 198.18.0.0/16 -j PSW2_RULE");
        pos(&cmds, "iptables -t mangle -w -A PSW2 -m comment --comment Local -p tcp -i lo -m mark --mark 0x50535732 -j TPROXY --on-port 1031");
        pos(&cmds, "iptables -t mangle -w -A OUTPUT -m comment --comment mangle-OUTPUT-PSW2 -m set ! --match-set psw2_direct dst -p tcp -j PSW2_OUTPUT");
        pos(&cmds, "ip6tables -t mangle -w -A PSW2_OUTPUT -p tcp -d 2001:2::/48 -j PSW2_RULE");
        // ip6 nat DNS chain exists
        pos(&cmds, "ip6tables -t nat -w -I PREROUTING -m set --match-set psw2_direct6 src -j PSW2_DNS");
        pos(&cmds, "ip6tables -t nat -w -A PSW2_DNS -m comment --comment Default -p tcp --dport 53 -j REDIRECT --to-ports 1035");
    }

    #[test]
    fn t_start_disabled() {
        let c = cfg("");
        let mut m = Mock::default();
        let mut cx = ctx("redirect", false);
        cx.enabled_acls = false;
        cx.enabled_default_acl = false;
        let mut fw = Fw::new(&mut m, &c, Some("iptables".into()), None, false, false);
        fw.start(&cx, &mut || panic!("acl_node must not run"));
        assert!(m.cmds.is_empty());
    }

    #[test]
    fn t_local_no_proxy_all() {
        let c = cfg("");
        let mut m = Mock::default();
        let mut v = Args::new();
        for (k, val) in [("local_proxy", "1"), ("node", "n2"), ("use", "acl_default"), ("tcp_no_redir_ports", "1:65535"), ("udp_no_redir_ports", "53,123"), ("udp_redir_ports", "")] {
            v.insert(k.into(), val.into());
        }
        let mut fw = Fw::new(&mut m, &c, Some("iptables".into()), Some("ip6tables".into()), true, true);
        fw.load_one_acl(&v, &[]);
        let cmds = m.cmds.clone();
        assert_eq!(cmds[0], "iptables -t nat -w -A PSW2_OUTPUT -p tcp -j RETURN");
        assert_eq!(cmds[1], "ip6tables -t mangle -w -A PSW2_OUTPUT -p tcp -j RETURN");
        assert_eq!(cmds[2], "iptables -t mangle -w -A PSW2_OUTPUT -p udp -m multiport --dport 53,123 -j RETURN");
        // no tcp local proxy; udp proxied, but empty udp_redir_ports → no catch-all rule
        assert!(!cmds.iter().any(|c| c.contains("-p tcp -d 198.18.0.0/16")));
        pos(&cmds, "iptables -t mangle -w -A PSW2_OUTPUT -p udp -d 198.18.0.0/16 -j PSW2_RULE");
        assert!(!cmds.iter().any(|c| c == "iptables -t mangle -w -A PSW2_OUTPUT -p udp -j PSW2_RULE"));
        // no dns port in cache → no DNS redirect
        assert!(!cmds.iter().any(|c| c.contains("PSW2_DNS")));
    }

    #[test]
    fn t_del_and_flush() {
        let c = Config::parse("passwall2", "config global\n");
        let mut m = Mock::default();
        m.outputs.insert("iptables -t nat -w -nL PREROUTING".into(), "Chain PREROUTING\nnum target\nPSW2_DNS all\nPSW2 tcp\nzone\n".into());
        m.outputs.insert("iptables -t nat -w --line-number -nL PREROUTING".into(), "Chain PREROUTING\nnum target\n1 PSW2_DNS all\n2 zone\n".into());
        m.outputs.insert("ipset -n list".into(), "psw2_local\nother\npsw2_n1_sr1\n".into());
        let mut fw = Fw::new(&mut m, &c, Some("iptables".into()), None, false, false);
        fw.del_firewall_rule();
        fw.flush_ipset();
        let cmds = m.cmds.clone();
        assert_eq!(cmds.iter().filter(|c| *c == "iptables -t nat -w -D PREROUTING 1").count(), 2);
        pos(&cmds, "iptables -t mangle -w -X PSW2_RULE");
        pos(&cmds, "ip rule del fwmark 0x50535732");
        pos(&cmds, "ip -6 route del local ::/0 dev lo table 999");
        pos(&cmds, "ipset -q -X psw2_n1_sr1");
        assert!(!cmds.iter().any(|c| c.contains("other")));
        assert!(!cmds.iter().any(|c| c.starts_with("ip6tables")));
    }

    #[test]
    fn t_include() {
        let c = cfg("\toption accept_icmpv6 '1'\n");
        let mut m = Mock::default();
        m.outputs.insert(
            "iptables-save -t nat".into(),
            "# Generated\n*nat\n:PREROUTING ACCEPT [0:0]\n:PSW2 - [0:0]\n:PSW2_DNS - [0:0]\n-A PREROUTING -m set --match-set psw2_direct src -j PSW2_DNS\n-A PREROUTING -m set ! --match-set psw2_direct dst -p tcp -j PSW2\n-A OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN\n-A OUTPUT -m comment --comment PSW2_DNS -p udp -o lo -m udp --dport 53 -j REDIRECT --to-ports 1035\n-A PSW2 -m set --match-set psw2_vps dst -j RETURN\nCOMMIT\n".into(),
        );
        let mut fw = Fw::new(&mut m, &c, Some("iptables".into()), Some("ip6tables".into()), false, true);
        fw.fwi = "/fwi".into();
        fw.gen_include();
        let inc = m.files.get("/fwi").unwrap().clone();
        let expect_v4 = "#!/bin/sh\n/usr/bin/passwall2 ipt update_wan_sets\n\
iptables-save -c | grep -v \"PSW2\" | iptables-restore -c\n\
iptables-restore -n <<-'EOT'\n*nat\n:PSW2 - [0:0]\n:PSW2_DNS - [0:0]\n\
-I PREROUTING 1 -m set --match-set psw2_direct src -j PSW2_DNS\n\
-I OUTPUT 1 -m comment --comment PSW2_DNS -p udp -o lo -m udp --dport 53 -j REDIRECT --to-ports 1035\n\
-A PSW2 -m set --match-set psw2_vps dst -j RETURN\nCOMMIT\n*mangle\nCOMMIT\nEOT\n\
iptables -t nat -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN\n\
iptables -t mangle -w -I OUTPUT -m comment --comment PSW2_DIRECT -m owner --gid-owner 9912 -j RETURN\n\n\
[ \"0\" = \"1\" ] && /usr/bin/passwall2 ipt insert_rule_after \"iptables -t nat -w\" \"PREROUTING\" \"prerouting_rule\" \"-m set ! --match-set psw2_direct dst -p icmp -j PSW2\"\n\
[ -z \"\" ] && /usr/bin/passwall2 ipt insert_rule_after \"iptables -t nat -w\" \"PREROUTING\" \"prerouting_rule\" \"-m set ! --match-set psw2_direct dst -p tcp -j PSW2\"\n\n\
/usr/bin/passwall2 ipt insert_rule_before \"iptables -t mangle -w\" \"PREROUTING\" \"mwan3\" \"-m set ! --match-set psw2_direct dst -j PSW2\"\n\n";
        assert!(inc.starts_with(expect_v4), "{}", inc);
        assert!(inc.contains("\neval #ip6tables -t nat -w -I OUTPUT -m comment --comment PSW2_DIRECT"));
        assert!(inc.contains("\nip6tables -t mangle -w -I OUTPUT -m comment --comment PSW2_DIRECT"));
        assert!(inc.contains("[ \"1\" = \"1\" ] && eval #ip6tables -t nat -w -A PREROUTING -m set ! --match-set psw2_direct6 dst -p ipv6-icmp -j PSW2"));
        assert!(inc.ends_with("\"-m set ! --match-set psw2_direct6 dst -j PSW2\"\n\nreturn 0\n"));
    }

    #[test]
    fn t_vps_and_direct_nodes() {
        let c = cfg("");
        let (v4, v6) = Fw::vps_addresses(&c);
        assert_eq!(v4, vec!["5.6.7.8"]);
        assert_eq!(v6, vec!["2001:db8::5"]);
        let mut m = Mock::default();
        m.files.insert("/tmp/etc/passwall2/direct_node_list".into(), "n2\nn2\nmissing\n".into());
        m.outputs.insert("iptables -t mangle -w -n -L PSW2_OUTPUT".into(), "RETURN udp /* 5.6.7.8:443 */".into());
        let mut fw = Fw::new(&mut m, &c, Some("iptables".into()), Some("ip6tables".into()), true, true);
        fw.filter_vpsip();
        fw.filter_haproxy();
        fw.filter_direct_node_list();
        assert_eq!(m.stdin[0].1, "add psw2_vps 5.6.7.8\nCOMMIT\n");
        assert_eq!(m.stdin[1].1, "add psw2_vps6 2001:db8::5\nCOMMIT\n");
        let cmds = m.cmds.clone();
        pos(&cmds, "ipset -q add psw2_vps 9.9.9.9");
        // TCP (redirect → nat) inserted; v6 mangle too; UDP already present in mangle
        pos(&cmds, "iptables -t nat -w -I PSW2_OUTPUT -m comment --comment 5.6.7.8:443 -p tcp -d 5.6.7.8 --dport 443 -j RETURN");
        pos(&cmds, "ip6tables -t mangle -w -I PSW2_OUTPUT -m comment --comment 5.6.7.8:443 -p udp -d 5.6.7.8 --dport 443 -j RETURN");
        assert!(!cmds.iter().any(|c| c.starts_with("iptables -t mangle -w -I PSW2_OUTPUT")));
        assert!(!cmds.iter().any(|c| c.contains("missing")));
    }
}
