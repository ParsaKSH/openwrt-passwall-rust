//! nftables backend: port of upstream `root/usr/share/passwall2/nftables.sh` (spec 02 §1–§2).
//!
//! Kernel state is identical to upstream: table `inet passwall2` with the base chains
//! `dstnat`, `mangle_prerouting`, `mangle_output` and `nat_output`; regular chains `PSW2_*`;
//! sets `psw2_*`; fwmark `0x50535732`; policy routing table/priority 999; gid 9912 bypass.
//!
//! Execution model:
//! * Sets are created and filled first, with one `nft -f` batch per `insert_nftset` call
//!   (exactly like upstream, so one bad list only loses that batch).
//! * All chains and rules (§2.3 steps 13–26, including the whole `load_acl`) are generated
//!   as one script, in upstream order, and loaded atomically with `nft -f -`. If the kernel
//!   rejects the transaction, the same commands are applied one at a time, ignoring errors,
//!   which is what upstream's individual `nft` calls do.
//! * `stop` deletes everything in one transaction as well (same per-command fallback).
//! * Handle-based helpers (`insert_rule_before/after`, `RULE_LAST_INDEX`, mwan3 cleanup)
//!   use `nft -a` handles like upstream.
//!
//! The rule generators are pure functions ([`gen_base_rules`], [`gen_acl_rules`]) so the
//! produced ruleset text is unit tested.

use crate::api;
use crate::firewall::acl::{self, AclSource};
use crate::uci::{self, Config};
use crate::util::{self, Args, ArgsExt};
use std::collections::HashMap;

pub const NFTABLE_NAME: &str = "inet passwall2";
pub const NFTSET_LOCAL: &str = "psw2_local";
pub const NFTSET_DIRECT: &str = "psw2_direct";
pub const NFTSET_VPS: &str = "psw2_vps";
pub const NFTSET_WAN: &str = "psw2_wan";
pub const NFTSET_LOCAL6: &str = "psw2_local6";
pub const NFTSET_DIRECT6: &str = "psw2_direct6";
pub const NFTSET_VPS6: &str = "psw2_vps6";
pub const NFTSET_WAN6: &str = "psw2_wan6";
pub const FWMARK: &str = "0x50535732";
pub const FAKE_IP: &str = "198.18.0.0/16";
pub const FAKE_IP_6: &str = "2001:2::/48";
/// Rule dump replayed by the firewall include after an fw4 reload.
pub const RULE_DUMP_FILE: &str = "/tmp/etc/passwall2/PSW2_RULE.nft";
const MWAN3_INIT: &str = "/etc/init.d/mwan3";
const MWAN3_RULE_ARGS: [&str; 6] = ["-m", "connmark", "--mark", "0x50535732/0xffffffff", "-j", "RETURN"];
const DIRECT_IP_FILE: &str = "/usr/share/passwall2/direct_ip";
const BASE_CHAINS: [&str; 5] = ["dstnat", "srcnat", "nat_output", "mangle_prerouting", "mangle_output"];
/// nft limits comments to 128 bytes.
const NFT_COMMENT_MAX: usize = 128;

// ====================================================================== pure helpers

/// `factor <value> <prefix>`: nft match fragment for a port list / MAC / address list.
pub fn factor(value: &str, prefix: &str) -> String {
    if value.is_empty() || prefix.is_empty() || value == "1:65535" {
        return String::new();
    }
    if has_mac(value) {
        return format!("{} {{{}}}", prefix, value);
    }
    let s: String = value.chars().filter(|c| *c != ' ').collect::<String>().replace(':', "-");
    let mut items: Vec<&str> = vec![];
    for it in s.split(',') {
        if !it.is_empty() && !items.contains(&it) {
            items.push(it);
        }
    }
    if items.is_empty() || items.contains(&"1-65535") {
        return String::new();
    }
    format!("{} {{{}}}", prefix, items.join(","))
}

/// `REDIRECT [port] [mode]` action string.
pub fn redirect(port: &str, mode: &str) -> String {
    if port.is_empty() {
        return "counter redirect".into();
    }
    match mode {
        "TPROXY" => format!("counter meta mark {} tproxy to :{}", FWMARK, port),
        "TPROXY4" => format!("counter meta mark {} tproxy ip to :{}", FWMARK, port),
        "TPROXY6" => format!("counter meta mark {} tproxy ip6 to :{}", FWMARK, port),
        _ => format!("counter redirect to :{}", port),
    }
}

/// `has_1_65535 list`
pub fn has_1_65535(v: &str) -> bool {
    format!(",{},", v.replace(':', "-")).contains(",1-65535,")
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// grep -E `([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}` (unanchored)
pub fn has_mac(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 17 {
        return false;
    }
    (0..=b.len() - 17).any(|i| (0..17).all(|k| if k % 3 == 2 { b[i + k] == b':' } else { is_hex(b[i + k]) }))
}

/// grep -E `([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}` (unanchored; upstream's "IPv6" test)
pub fn re_ipv6(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| {
        is_hex(b[i])
            && b.get(i + 1) == Some(&b':')
            && (b.get(i + 2).is_some_and(|c| is_hex(*c)) || (b.get(i + 2) == Some(&b':') && b.get(i + 3).is_some_and(|c| is_hex(*c))))
    })
}

/// grep -E `(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}` (unanchored; shunt/geoip "IPv4" test)
pub fn re_ipv4_octets(s: &str) -> bool {
    fn group_ok(d: &[u8]) -> bool {
        match d.len() {
            1 | 2 => true,
            3 => matches!(d[0], b'0' | b'1') || (d[0] == b'2' && ((d[1] == b'5' && d[2] <= b'5') || (b'0'..=b'4').contains(&d[1]))),
            _ => false,
        }
    }
    fn m(b: &[u8], i: usize, k: usize) -> bool {
        if b.get(i) != Some(&b'.') {
            return false;
        }
        for len in 1..=3 {
            let end = i + 1 + len;
            if end > b.len() || !b[i + 1..end].iter().all(|c| c.is_ascii_digit()) {
                break;
            }
            if group_ok(&b[i + 1..end]) && (k == 1 || m(b, end, k - 1)) {
                return true;
            }
        }
        false
    }
    let b = s.as_bytes();
    (0..b.len()).any(|i| m(b, i, 3))
}

/// grep -E `([0-9]{1,3}[\.]){3}[0-9]{1,3}` (unanchored; `filter_vpsip` / `get_host_ip`)
pub fn re_ipv4_dotted(s: &str) -> bool {
    fn m(b: &[u8], i: usize, k: usize) -> bool {
        for len in 1..=3 {
            let end = i + len;
            if end > b.len() || !b[i..end].iter().all(|c| c.is_ascii_digit()) {
                break;
            }
            if k == 0 {
                return true;
            }
            if b.get(end) == Some(&b'.') && m(b, end + 1, k - 1) {
                return true;
            }
        }
        false
    }
    let b = s.as_bytes();
    (0..b.len()).any(|i| m(b, i, 3))
}

/// True when `tok` is a valid element for an `ipv4_addr` (`v6=false`) / `ipv6_addr`
/// (`v6=true`) interval set: address, CIDR or `a-b` range. `None` accepts both families.
pub fn valid_elem(tok: &str, v6: Option<bool>) -> bool {
    let fam = |s: &str| -> Option<bool> {
        let ip = s.split('/').next().unwrap_or("");
        if !util::is_cidr(s) {
            return None;
        }
        if util::is_ipv4(ip) {
            Some(false)
        } else if ip.parse::<std::net::Ipv6Addr>().is_ok() {
            Some(true)
        } else {
            None
        }
    };
    let f = match tok.split_once('-') {
        Some((a, b)) if !a.contains('/') && !b.contains('/') => match (fam(a), fam(b)) {
            (Some(x), Some(y)) if x == y => Some(x),
            _ => None,
        },
        Some(_) => None,
        None => fam(tok),
    };
    match (f, v6) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(x), Some(y)) => x == y,
    }
}

/// Text that upstream's `insert_nftset` pipes to `nft -f -` (empty when no tokens).
pub fn insert_nftset_text(name: &str, items: &[String]) -> String {
    let toks: Vec<&str> = items.iter().flat_map(|s| s.split_whitespace()).collect();
    if toks.is_empty() || name.is_empty() {
        return String::new();
    }
    let mut s = format!("add element {} {} {{ \n", NFTABLE_NAME, name);
    for (i, t) in toks.iter().enumerate() {
        if i > 0 {
            s.push_str(",\n");
        }
        s.push(' ');
        s.push_str(t);
    }
    s.push_str("\n }\n");
    s
}

/// `comment "<s>"` with the text made safe for nft (no `"`, no control chars, <=128 bytes).
fn cmt(s: &str) -> String {
    // upstream quirk: upstream interpolates remarks verbatim, so a `"` or an over-long
    // remark breaks the rule; we sanitize instead.
    let mut out = String::new();
    for c in s.chars() {
        let c = match c {
            '"' => '\'',
            c if c.is_control() => ' ',
            c => c,
        };
        if out.len() + c.len_utf8() > NFT_COMMENT_MAX {
            break;
        }
        out.push(c);
    }
    format!("comment \"{}\"", out)
}

/// Join rule fragments with single spaces, skipping empty ones.
fn j(parts: &[&str]) -> String {
    parts.iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ")
}

/// Rule handles (`# handle N`) of `nft -a list chain` lines containing `keyword`.
pub fn parse_handles(listing: &str, keyword: &str) -> Vec<u64> {
    listing
        .lines()
        .filter(|l| l.contains(keyword))
        .filter_map(|l| l.split("# handle ").nth(1))
        .filter_map(|h| h.split_whitespace().next())
        .filter_map(|h| h.parse().ok())
        .collect()
}

/// Names of `chain X {` / `set X {` blocks in an `nft list table` dump.
pub fn parse_block_names(listing: &str, kind: &str) -> Vec<String> {
    let pfx = format!("{} ", kind);
    listing
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix(&pfx))
        .filter_map(|r| r.split_whitespace().next())
        .filter(|n| *n != "{")
        .map(|n| n.to_string())
        .collect()
}

/// Type (`ipv4_addr`, ...) of a set from `nft list set` output.
fn parse_set_type(listing: &str) -> Option<String> {
    listing.lines().find_map(|l| l.trim().strip_prefix("type ").map(|t| t.trim_end_matches(';').split_whitespace().next().unwrap_or("").to_string()))
}

// ====================================================================== nft execution

fn nft_cmd(cmd: &str) -> bool {
    nft_script(&format!("{}\n", cmd)).0
}

/// `nft -f -` with the given text; (ok, combined output).
fn nft_script(text: &str) -> (bool, String) {
    if text.trim().is_empty() {
        return (true, String::new());
    }
    util::cmd_stdin("nft", &["-f", "-"], text)
}

fn nft_out(args: &[&str]) -> Option<String> {
    let o = std::process::Command::new("nft").args(args).stderr(std::process::Stdio::null()).output().ok()?;
    if o.status.success() {
        Some(String::from_utf8_lossy(&o.stdout).to_string())
    } else {
        None
    }
}

fn split_table(t: &str) -> Vec<&str> {
    t.split_whitespace().collect()
}

/// `nft -a list chain <table> <chain>` (None when it does not exist).
fn list_chain(table: &str, chain: &str) -> Option<String> {
    let mut a = vec!["-a", "list", "chain"];
    a.extend(split_table(table));
    a.push(chain);
    nft_out(&a)
}

/// Apply commands as one atomic transaction; on failure apply them one by one (errors
/// ignored, like upstream's individual `nft` calls). Returns true when the transaction
/// succeeded atomically.
pub fn apply_cmds(cmds: &[String]) -> bool {
    if cmds.is_empty() {
        return true;
    }
    let mut text = cmds.join("\n");
    text.push('\n');
    let (ok, out) = nft_script(&text);
    if ok {
        return true;
    }
    let first = out.lines().next().unwrap_or("").to_string();
    util::log(1, &format!("nftables: atomic load failed ({}), loading rules one by one.", first));
    for c in cmds {
        nft_cmd(c);
    }
    false
}

/// `destroy_nftset names...`
pub fn destroy_nftset(names: &[&str]) {
    for n in names {
        nft_cmd(&format!("flush set {} {}", NFTABLE_NAME, n));
        nft_cmd(&format!("delete set {} {}", NFTABLE_NAME, n));
    }
}

fn set_exists(name: &str) -> bool {
    nft_out(&["list", "set", "inet", "passwall2", name]).is_some()
}

/// `gen_nftset name ipv4_addr|ipv6_addr 0 ...` (creates only when missing).
pub fn gen_nftset(name: &str, ip_type: &str, timeout: &str) {
    if name.is_empty() || set_exists(name) {
        return;
    }
    nft_cmd(&gen_nftset_cmd(name, ip_type, timeout));
}

pub fn gen_nftset_cmd(name: &str, ip_type: &str, timeout: &str) -> String {
    if timeout == "0" || timeout.is_empty() {
        format!("add set {} {} {{ type {}; flags interval, timeout; auto-merge; }}", NFTABLE_NAME, name, ip_type)
    } else {
        format!("add set {} {} {{ type {}; flags interval, timeout; timeout {}; gc-interval 1h; auto-merge; }}", NFTABLE_NAME, name, ip_type, timeout)
    }
}

/// `insert_nftset name` with the given whitespace-separated tokens. Tokens that are not a
/// valid address/CIDR/range of the set's family (`v6`) are dropped.
pub fn insert_nftset(name: &str, v6: Option<bool>, items: &[String]) {
    // upstream quirk: upstream pipes every matched token to nft, so one malformed token
    // (e.g. a hostname that happens to contain digits and dots) aborts the whole batch.
    let toks: Vec<String> = items.iter().flat_map(|s| s.split_whitespace()).filter(|t| valid_elem(t, v6)).map(|t| t.to_string()).collect();
    let text = insert_nftset_text(name, &toks);
    if !text.is_empty() {
        nft_script(&text);
    }
}

fn gen_nft_tables() {
    if nft_out(&["list", "table", "inet", "passwall2"]).is_some() {
        return;
    }
    nft_script(&gen_nft_tables_text());
}

pub fn gen_nft_tables_text() -> String {
    format!(
        "table {} {{\n\tchain dstnat {{\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n\t}}\n\tchain mangle_prerouting {{\n\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n\t}}\n\tchain mangle_output {{\n\t\ttype route hook output priority mangle - 1; policy accept;\n\t}}\n\tchain nat_output {{\n\t\ttype nat hook output priority -1; policy accept;\n\t}}\n}}\n",
        NFTABLE_NAME
    )
}

// ====================================================================== handle helpers

fn first_handle(table: &str, chain: &str, keyword: &str) -> Option<u64> {
    parse_handles(&list_chain(table, chain).unwrap_or_default(), keyword).first().copied()
}

/// `insert_rule_before table chain keyword rule [default_index]`
pub fn insert_rule_before(table: &str, chain: &str, keyword: &str, rule: &str, default_index: &str) -> bool {
    let def = if default_index.is_empty() { "0" } else { default_index };
    match first_handle(table, chain, keyword) {
        None if def == "0" => nft_cmd(&format!("add rule {} {} {}", table, chain, rule)),
        Some(h) => nft_cmd(&format!("insert rule {} {} position {} {}", table, chain, h, rule)),
        None => nft_cmd(&format!("insert rule {} {} position {} {}", table, chain, def, rule)),
    }
}

/// `insert_rule_after table chain keyword rule [default_index]`
pub fn insert_rule_after(table: &str, chain: &str, keyword: &str, rule: &str, default_index: &str) -> bool {
    let def = if default_index.is_empty() { "0" } else { default_index };
    match first_handle(table, chain, keyword) {
        None if def == "0" => nft_cmd(&format!("add rule {} {} {}", table, chain, rule)),
        // upstream quirk: upstream inserts at `position <handle+1>`, which names an unrelated
        // (or missing) handle; `add rule ... position <handle>` places the rule after it.
        Some(h) => nft_cmd(&format!("add rule {} {} position {} {}", table, chain, h, rule)),
        None => nft_cmd(&format!("insert rule {} {} position {} {}", table, chain, def, rule)),
    }
}

/// `RULE_LAST_INDEX table chain keyword [default]` → handle of the first matching rule.
pub fn rule_last_index(table: &str, chain: &str, keyword: &str, default: &str) -> String {
    match first_handle(table, chain, keyword) {
        Some(h) => h.to_string(),
        None => if default.is_empty() { "0".into() } else { default.to_string() },
    }
}

// ====================================================================== environment

/// Variables upstream's nftables.sh inherits from app.sh (spec 02 §0.3).
#[derive(Debug, Clone, Default)]
pub struct NftEnv {
    pub enabled_default_acl: bool,
    pub enabled_acls: bool,
    /// `redirect` | `tproxy` (anything else is treated as `redirect`)
    pub tcp_proxy_way: String,
    pub proxy_ipv6: bool,
    /// `@global[0].node`
    pub node: String,
    pub isp_dns: Vec<String>,
    pub isp_dns6: Vec<String>,
    /// comma list `addr[#port[#proto]]`
    pub return_dns: String,
    /// `$.acl[*].flag` of the ACL JSON (rules in UCI order, `acl_default` last)
    pub acl_flags: Vec<String>,
}

impl NftEnv {
    /// Compute everything like app.sh `get_config` + `get_direct_dns`, with the ACL flags
    /// from the saved ACL state and the ENABLED_* flags from the cache when present.
    pub fn from_system(cfg: &Config) -> NftEnv {
        let (isp_dns, isp_dns6, return_dns) = get_direct_dns(cfg);
        let node = cfg.s("@global[0]", "node");
        let enabled_default_acl = match util::get_cache_var("ENABLED_DEFAULT_ACL") {
            Some(v) if !v.is_empty() => v == "1",
            _ => {
                cfg.get_or("@global[0]", "enabled", "0") == "1"
                    && !node.is_empty()
                    && cfg.stype(&node).as_deref() == Some("nodes")
                    && util::exists(&format!("{}/acl_node_acl_default", util::TMP_ACL_PATH))
            }
        };
        let enabled_acls = match util::get_cache_var("ENABLED_ACLS") {
            Some(v) if !v.is_empty() => v == "1",
            _ => cfg.get_or("@global[0]", "acl_enable", "0") == "1",
        };
        NftEnv {
            enabled_default_acl,
            enabled_acls,
            tcp_proxy_way: cfg.get_or("@global_forwarding[0]", "tcp_proxy_way", "redirect"),
            proxy_ipv6: cfg.get_or("@global_forwarding[0]", "ipv6_tproxy", "0") == "1",
            node,
            isp_dns,
            isp_dns6,
            return_dns,
            acl_flags: acl::saved_flags(),
        }
    }
    pub fn is_tproxy(&self) -> bool {
        self.tcp_proxy_way == "tproxy"
    }
}

/// ISP DNS from resolv.conf.auto (app.sh `get_direct_dns`).
pub fn parse_isp_dns(text: &str) -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = vec![];
    for l in text.lines() {
        // grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
        let b = l.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if !b[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            let start = i;
            let mut groups = 0;
            let mut end = i;
            let mut k = i;
            loop {
                let gs = k;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                if k == gs {
                    break;
                }
                groups += 1;
                end = k;
                if groups == 4 || k >= b.len() || b[k] != b'.' {
                    break;
                }
                k += 1;
            }
            if groups == 4 {
                let ip = &l[start..end];
                if ip != "0.0.0.0" && ip != "127.0.0.1" && !v4.iter().any(|x| x == ip) {
                    v4.push(ip.to_string());
                }
                i = end;
            } else {
                // leftmost-longest: skip this digit run
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
        }
    }
    let mut v6: Vec<String> = vec![];
    for l in text.lines().filter(|l| re_ipv6(l)) {
        let l = l.split('%').next().unwrap_or("");
        let Some(f2) = l.split(' ').filter(|s| !s.is_empty()).nth(1) else { continue };
        if f2 == "::1" || f2 == "::" || v6.iter().any(|x| x == f2) {
            continue;
        }
        v6.push(f2.to_string());
    }
    (v4, v6)
}

/// AUTO_DNS from dnsmasq's `server` list (first two non-domain entries) or ISP DNS.
pub fn auto_dns(dnsmasq_servers: &[String], isp_dns: &[String]) -> String {
    let ups: Vec<String> = dnsmasq_servers
        .iter()
        .flat_map(|s| s.split(' ').map(|x| x.to_string()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .map(|s| if s.contains('#') { s } else { format!("{}#53", s) })
        .take(2)
        .collect();
    let mut d = ups.join(",");
    if d.is_empty() {
        d = isp_dns.iter().take(2).cloned().collect::<Vec<_>>().join(",");
    }
    if d.is_empty() {
        "119.29.29.29".into()
    } else {
        d
    }
}

/// `(ISP_DNS, ISP_DNS6, RETURN_DNS)` as computed by app.sh `get_direct_dns`.
pub fn get_direct_dns(cfg: &Config) -> (Vec<String>, Vec<String>, String) {
    let mut rf = "/tmp/resolv.conf.d/resolv.conf.auto";
    if util::read(rf).is_empty() {
        rf = "/tmp/resolv.conf.auto";
    }
    let (isp, isp6) = parse_isp_dns(&util::read(rf));
    let dhcp = Config::load("dhcp");
    let mut ret = auto_dns(&dhcp.list_raw("@dnsmasq[0]", "server"), &isp);
    let proto = cfg.s("@global[0]", "direct_dns_protocol");
    if proto == "tcp" || proto == "udp" {
        let (srv, port) = api::parse_dns(&cfg.s("@global[0]", "direct_dns"));
        ret = format!("{},{}#{}#{}", ret, srv, port, proto);
    }
    (isp, isp6, ret)
}

// ====================================================================== rule generation

/// Generated nft commands (without the leading `nft`) plus log lines.
#[derive(Debug, Default, Clone)]
pub struct Gen {
    pub cmds: Vec<String>,
    pub logs: Vec<(usize, String)>,
}

impl Gen {
    fn add(&mut self, chain: &str, parts: &[&str]) {
        self.cmds.push(format!("add rule {} {} {}", NFTABLE_NAME, chain, j(parts)));
    }
    fn ins(&mut self, chain: &str, parts: &[&str]) {
        self.cmds.push(format!("insert rule {} {} {}", NFTABLE_NAME, chain, j(parts)));
    }
    fn chain(&mut self, name: &str) {
        self.cmds.push(format!("add chain {} {}", NFTABLE_NAME, name));
        self.cmds.push(format!("flush chain {} {}", NFTABLE_NAME, name));
    }
    fn log(&mut self, level: usize, msg: String) {
        self.logs.push((level, msg));
    }
    /// `add_shunt_t_rule list "<add rule chain pre...> <daddr_kw>" jump [comment]`
    fn shunt(&mut self, chain: &str, pre: &[&str], daddr_kw: &str, list: &[(String, String)], jump: &str, comment: Option<&str>) {
        let c = comment.map(cmt).unwrap_or_default();
        for (set, out) in list {
            if set.is_empty() || out.is_empty() {
                continue;
            }
            let act = if out == "direct" { "counter return" } else { jump };
            let target = format!("@{}", set);
            let mut parts: Vec<&str> = pre.to_vec();
            parts.extend([daddr_kw, target.as_str(), act, c.as_str()]);
            self.add(chain, &parts);
        }
    }
    pub fn script(&self) -> String {
        let mut s = self.cmds.join("\n");
        s.push('\n');
        s
    }
}

/// Global switches for rule generation.
#[derive(Debug, Clone, Default)]
pub struct RuleCtx {
    pub tproxy: bool,
    pub proxy_ipv6: bool,
    pub accept_icmp: bool,
    pub accept_icmpv6: bool,
    /// `@global[0].dns_redirect` != "0"
    pub dns_redirect: bool,
    pub return_dns: String,
    /// entries of `$TMP_IFACE_PATH` (excluded output interfaces)
    pub ifaces: Vec<String>,
}

impl RuleCtx {
    pub fn prerouting_chain(&self) -> &'static str {
        if self.tproxy { "PSW2_MANGLE" } else { "PSW2_NAT" }
    }
    pub fn output_chain(&self) -> &'static str {
        if self.tproxy { "PSW2_OUTPUT_MANGLE" } else { "PSW2_OUTPUT_NAT" }
    }
}

/// Shunt sets of a node: `(set name, "direct"|"redirect")`.
pub type ShuntList = Vec<(String, String)>;

/// One ACL as consumed by `load_acl`: the evaluated `var` file and resolved inputs.
#[derive(Debug, Clone, Default)]
pub struct AclInput {
    pub var: Args,
    /// sources (ipset sources whose set does not exist already removed)
    pub sources: Vec<AclSource>,
    /// resolved device of `interface` (None when no interface)
    pub device: Option<String>,
    pub dns_redirect_port: Option<String>,
    /// shunt sets `(set, "direct"|"redirect")` of the ACL's node
    pub shunt4: ShuntList,
    pub shunt6: ShuntList,
}

/// §2.3 steps 13–23: chains and base rules (before `load_acl`).
pub fn gen_base_rules(ctx: &RuleCtx, g: &mut Gen) {
    let tp = ctx.tproxy;
    g.chain("PSW2_DNS");
    if !ctx.dns_redirect {
        g.ins("dstnat", &["ip saddr @psw2_direct ip daddr @psw2_local jump PSW2_DNS"]);
        g.ins("dstnat", &["ip6 saddr @psw2_direct6 ip6 daddr @psw2_local6 jump PSW2_DNS"]);
    } else {
        g.ins("dstnat", &["ip saddr @psw2_direct jump PSW2_DNS"]);
        g.ins("dstnat", &["ip6 saddr @psw2_direct6 jump PSW2_DNS"]);
    }

    g.chain("PSW2_RULE");
    g.add("PSW2_RULE", &["counter meta mark set ct mark"]);
    g.add("PSW2_RULE", &[&format!("meta mark {} counter return", FWMARK)]);
    g.add("PSW2_RULE", &[&format!("tcp flags & (fin|syn|rst|ack) == syn counter meta mark set {}", FWMARK)]);
    g.add("PSW2_RULE", &[&format!("meta l4proto udp ct state {{ new, related }} counter meta mark set {}", FWMARK)]);
    g.add("PSW2_RULE", &["counter ct mark set mark"]);

    g.chain("PSW2_MANGLE");
    g.add("PSW2_MANGLE", &["ip daddr @psw2_vps counter return"]);
    g.add("PSW2_MANGLE", &["ct direction reply counter return"]);
    g.chain("PSW2_OUTPUT_MANGLE");
    g.add("PSW2_OUTPUT_MANGLE", &["ip daddr @psw2_vps counter return"]);
    g.add("PSW2_OUTPUT_MANGLE", &["ct direction reply counter return"]);
    g.add("PSW2_OUTPUT_MANGLE", &["meta mark and 0xff == 0xff counter return"]);

    g.add("mangle_prerouting", &[&format!("meta nfproto ipv4 meta l4proto tcp socket transparent 1 mark set {} counter accept comment PSW2_SOCKET", FWMARK)]);
    g.add("mangle_prerouting", &["ip daddr != @psw2_direct ip protocol udp counter jump PSW2_MANGLE"]);
    if tp {
        g.add("mangle_prerouting", &["ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_MANGLE"]);
    }

    if !tp {
        g.chain("PSW2_NAT");
        g.add("PSW2_NAT", &["ip daddr @psw2_vps counter return"]);
        g.add("dstnat", &["ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_NAT"]);
        g.chain("PSW2_OUTPUT_NAT");
        g.add("PSW2_OUTPUT_NAT", &["ip daddr @psw2_vps counter return"]);
        g.add("PSW2_OUTPUT_NAT", &["meta mark and 0xff == 0xff counter return"]);
    }

    if ctx.accept_icmp {
        g.chain("PSW2_ICMP_REDIRECT");
        g.add("PSW2_ICMP_REDIRECT", &["ip daddr @psw2_vps counter return"]);
        if ctx.accept_icmpv6 {
            g.add("PSW2_ICMP_REDIRECT", &["ip6 daddr @psw2_vps6 counter return"]);
        }
        g.add("dstnat", &["ip daddr != @psw2_direct meta l4proto icmp counter jump PSW2_ICMP_REDIRECT"]);
        g.add("dstnat", &["ip6 daddr != @psw2_direct6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT"]);
        g.add("nat_output", &["ip daddr != @psw2_direct meta l4proto icmp counter jump PSW2_ICMP_REDIRECT"]);
        g.add("nat_output", &["ip6 daddr != @psw2_direct6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT"]);
    }

    if !tp {
        g.add("PSW2_NAT", &["ip daddr @psw2_wan counter return", &cmt("WAN_IP_RETURN")]);
    }
    g.add("PSW2_MANGLE", &["ip daddr @psw2_wan counter return", &cmt("WAN_IP_RETURN")]);

    g.chain("PSW2_MANGLE_V6");
    g.add("PSW2_MANGLE_V6", &["ip6 daddr @psw2_vps6 counter return"]);
    g.add("PSW2_MANGLE_V6", &["ct direction reply counter return"]);
    g.chain("PSW2_OUTPUT_MANGLE_V6");
    g.add("PSW2_OUTPUT_MANGLE_V6", &["ip6 daddr @psw2_vps6 counter return"]);
    g.add("PSW2_OUTPUT_MANGLE_V6", &["ct direction reply counter return"]);
    g.add("PSW2_OUTPUT_MANGLE_V6", &["meta mark and 0xff == 0xff counter return"]);

    for item in ctx.return_dns.split([',', ' ', '\t', '\n']).filter(|s| !s.is_empty()) {
        let f: Vec<&str> = item.split('#').collect();
        let addr = f.first().copied().unwrap_or("");
        let port = f.get(1).copied().filter(|s| !s.is_empty()).unwrap_or("53");
        let proto = f.get(2).copied().filter(|s| !s.is_empty()).unwrap_or("udp");
        if addr.is_empty() {
            // upstream quirk: an empty direct_dns produced an invalid rule; skipped.
            continue;
        }
        let dport = factor(port, &format!("{} dport", proto));
        // upstream tests only `*::*`; a full-form IPv6 address is also routed to the v6 chain.
        if addr.contains("::") || util::is_ipv6(addr) {
            g.ins("PSW2_OUTPUT_MANGLE_V6", &["meta l4proto", proto, "ip6 daddr", addr, &dport, "counter return"]);
            g.log(1, api::translatef("Add direct DNS to %s: %s", &["nftables", &format!("[{}]:{}", addr, port)]));
        } else {
            g.ins("PSW2_OUTPUT_MANGLE", &["ip protocol", proto, "ip daddr", addr, &dport, "counter return"]);
            g.log(1, api::translatef("Add direct DNS to %s: %s", &["nftables", &format!("{}:{}", addr, port)]));
        }
    }

    if ctx.proxy_ipv6 {
        g.add("mangle_prerouting", &[&format!("meta nfproto ipv6 meta l4proto tcp socket transparent 1 mark set {} counter accept comment PSW2_SOCKET", FWMARK)]);
        g.add("mangle_prerouting", &["ip6 daddr != @psw2_direct6 meta nfproto {ipv6} counter jump PSW2_MANGLE_V6"]);
        g.add("mangle_output", &["ip6 daddr != @psw2_direct6 meta nfproto {ipv6} counter jump PSW2_OUTPUT_MANGLE_V6", &cmt("PSW2_OUTPUT_MANGLE")]);
        g.add("PSW2_MANGLE_V6", &["ip6 daddr @psw2_wan6 counter return", &cmt("WAN6_IP_RETURN")]);
    }
}

/// §2.3 step 26: gid 9912 bypass at the top of the output chains.
pub fn gen_direct_gid_rules(g: &mut Gen) {
    g.ins("mangle_output", &[&format!("meta skgid {} counter return", util::DIRECT_GID), &cmt("PSW2_DIRECT")]);
    g.ins("nat_output", &[&format!("meta skgid {} counter return", util::DIRECT_GID), &cmt("PSW2_DIRECT")]);
}

/// `load_acl` rule generation for one ACL (§2.4).
pub fn gen_acl_rules(ctx: &RuleCtx, a: &AclInput, g: &mut Gen) {
    let v = &a.var;
    let tcp_no = v.s("tcp_no_redir_ports");
    let udp_no = v.s("udp_no_redir_ports");
    let tcp_redir = v.s("tcp_redir_ports");
    let udp_redir = v.s("udp_redir_ports");
    let node = v.s("node");
    let node_remarks = v.s("node_remarks");
    let redir_port = v.s("redir_port");
    let remarks = v.s("remarks");
    let dns_port = a.dns_redirect_port.clone().unwrap_or_default();
    let oc = ctx.output_chain();
    let pc = ctx.prerouting_chain();
    let tdport = factor(&tcp_redir, "tcp dport");
    let udport = factor(&udp_redir, "udp dport");

    if v.g("local_proxy") == Some("1") {
        let msg = api::translate("[Local],");
        let mut no_tcp_local = false;
        let mut no_udp_local = false;
        if !tcp_no.is_empty() {
            let f = factor(&tcp_no, "tcp dport");
            g.add(oc, &["ip protocol tcp", &f, "counter return"]);
            g.add("PSW2_OUTPUT_MANGLE_V6", &["meta l4proto tcp", &f, "counter return"]);
            if !has_1_65535(&tcp_no) {
                g.log(2, format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["TCP", &tcp_no])));
            } else {
                no_tcp_local = true;
                g.log(2, format!("{}{}", msg, api::translatef("not proxy all %s", &["TCP"])));
            }
        }
        if !udp_no.is_empty() {
            let f = factor(&udp_no, "udp dport");
            g.add("PSW2_OUTPUT_MANGLE", &["ip protocol udp", &f, "counter return"]);
            g.add("PSW2_OUTPUT_MANGLE_V6", &["meta l4proto udp", &f, "counter return"]);
            if !has_1_65535(&udp_no) {
                g.log(2, format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["UDP", &udp_no])));
            } else {
                no_udp_local = true;
                g.log(2, format!("{}{}", msg, api::translatef("not proxy all %s", &["UDP"])));
            }
        }
        let local = cmt(&api::translate("Local"));

        if !node.is_empty() && (!no_tcp_local || !no_udp_local) && !dns_port.is_empty() {
            let r = format!("counter redirect to :{}", dns_port);
            g.add("nat_output", &["oif lo meta l4proto udp udp dport 53", &r, &cmt("PSW2_DNS")]);
            g.add("nat_output", &["oif lo meta l4proto tcp tcp dport 53", &r, &cmt("PSW2_DNS")]);
            g.log(2, format!("{}{}", msg, api::translatef("DNS will redirected to the dedicated DNS server [%s].", &[&dns_port])));
        }

        if !node.is_empty() && !no_tcp_local {
            if ctx.accept_icmp {
                let c = "PSW2_ICMP_REDIRECT";
                g.add(c, &["oif lo ip protocol icmp ip daddr", FAKE_IP, "counter redirect"]);
                g.shunt(c, &["oif lo ip protocol icmp"], "ip daddr", &a.shunt4, "counter redirect", None);
                g.add(c, &["oif lo ip protocol icmp counter redirect"]);
                g.add(c, &["oif lo ip protocol icmp counter return"]);
            }
            // upstream quirk: upstream also emits these when accept_icmp=0, where the chain does
            // not exist and the commands fail; they are only generated when the chain exists.
            if ctx.accept_icmpv6 && ctx.accept_icmp {
                let c = "PSW2_ICMP_REDIRECT";
                g.add(c, &["oif lo meta l4proto icmpv6 ip6 daddr", FAKE_IP_6, "counter redirect"]);
                g.shunt(c, &["oif lo meta l4proto icmpv6"], "ip6 daddr", &a.shunt6, "counter redirect", None);
                g.add(c, &["oif lo meta l4proto icmpv6 counter redirect"]);
                g.add(c, &["oif lo meta l4proto icmpv6 counter return"]);
            }
            let mut msg2 = format!("{}{}", msg, api::translatef("Use the %s node [%s]", &["TCP", &node_remarks]));
            let (chain, jmp) = if ctx.tproxy {
                msg2.push_str(&format!("(TPROXY:{})", redir_port));
                ("PSW2_OUTPUT_MANGLE", "counter jump PSW2_RULE".to_string())
            } else {
                msg2.push_str(&format!("(REDIRECT:{})", redir_port));
                ("PSW2_OUTPUT_NAT", redirect(&redir_port, ""))
            };
            g.add(chain, &["ip protocol tcp ip daddr", FAKE_IP, &jmp]);
            g.shunt(chain, &["ip protocol tcp", &tdport], "ip daddr", &a.shunt4, &jmp, None);
            g.add(chain, &["ip protocol tcp", &tdport, &jmp]);
            if !ctx.tproxy {
                g.add("nat_output", &["ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_NAT"]);
            } else {
                g.add("PSW2_MANGLE", &["ip protocol tcp iif lo", &redirect(&redir_port, "TPROXY4"), &local]);
                g.add("PSW2_MANGLE", &["ip protocol tcp iif lo counter return", &local]);
                g.add("mangle_output", &["ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_MANGLE", &cmt("PSW2_OUTPUT_MANGLE")]);
            }
            if ctx.proxy_ipv6 {
                let c = "PSW2_OUTPUT_MANGLE_V6";
                g.add(c, &["meta l4proto tcp ip6 daddr", FAKE_IP_6, "jump PSW2_RULE"]);
                g.shunt(c, &["meta l4proto tcp", &tdport], "ip6 daddr", &a.shunt6, "counter jump PSW2_RULE", None);
                g.add(c, &["meta l4proto tcp", &tdport, "counter jump PSW2_RULE"]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto tcp iif lo", &redirect(&redir_port, "TPROXY6"), &local]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto tcp iif lo counter return", &local]);
            }
            for i in &ctx.ifaces {
                g.add(oc, &["ip protocol tcp oifname", &format!("\"{}\"", i), "counter return"]);
                g.add("PSW2_OUTPUT_MANGLE_V6", &["ip protocol tcp oifname", &format!("\"{}\"", i), "counter return"]);
            }
            g.log(2, msg2);
        }

        if !node.is_empty() && !no_udp_local {
            let msg2 = format!("{}{}(TPROXY:{})", msg, api::translatef("Use the %s node [%s]", &["UDP", &node_remarks]), redir_port);
            let c = "PSW2_OUTPUT_MANGLE";
            g.add(c, &["ip protocol udp ip daddr", FAKE_IP, "counter jump PSW2_RULE"]);
            g.shunt(c, &["ip protocol udp", &udport], "ip daddr", &a.shunt4, "counter jump PSW2_RULE", None);
            g.add(c, &["ip protocol udp", &udport, "counter jump PSW2_RULE"]);
            g.add("PSW2_MANGLE", &["ip protocol udp iif lo", &redirect(&redir_port, "TPROXY4"), &local]);
            g.add("PSW2_MANGLE", &["ip protocol udp iif lo counter return", &local]);
            g.add("mangle_output", &["ip daddr != @psw2_direct ip protocol udp counter jump PSW2_OUTPUT_MANGLE", &cmt("PSW2_OUTPUT_MANGLE")]);
            if ctx.proxy_ipv6 {
                let c = "PSW2_OUTPUT_MANGLE_V6";
                g.add(c, &["meta l4proto udp ip6 daddr", FAKE_IP_6, "jump PSW2_RULE"]);
                g.shunt(c, &["meta l4proto udp", &udport], "ip6 daddr", &a.shunt6, "counter jump PSW2_RULE", None);
                g.add(c, &["meta l4proto udp", &udport, "counter jump PSW2_RULE"]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto udp iif lo", &redirect(&redir_port, "TPROXY6"), &local]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto udp iif lo counter return", &local]);
            }
            for i in &ctx.ifaces {
                g.add(oc, &["ip protocol udp oifname", &format!("\"{}\"", i), "counter return"]);
                g.add("PSW2_OUTPUT_MANGLE_V6", &["ip protocol udp oifname", &format!("\"{}\"", i), "counter return"]);
            }
            g.log(2, msg2);
        }

        g.add("mangle_output", &["oif lo counter return", &cmt("PSW2_OUTPUT_MANGLE")]);
        g.add("mangle_output", &[&format!("meta mark {} counter return", FWMARK), &cmt("PSW2_OUTPUT_MANGLE")]);
    }

    if v.g("client_proxy") == Some("1") {
        let msg1 = api::translatef("[%s],", &[&remarks]);
        let rem = cmt(&remarks);
        for src in &a.sources {
            let mut ipv4 = false;
            let (mut s, mut msg) = match &a.device {
                Some(dev) => (format!("iifname \"{}\"", dev.replace('"', "")), api::translatef("Source iface [%s],", &[dev])),
                None => (String::new(), api::translatef("Source iface [%s],", &[&api::translate("All")])),
            };
            match src {
                AclSource::IpRange(r) => {
                    s = factor(r, &j(&[&s, "ip saddr"]));
                    msg.push_str(&api::translatef("IP range [%s],", &[r]));
                    ipv4 = true;
                }
                AclSource::Ipset(n) => {
                    // upstream quirk kept: an ipset source matches the destination address.
                    s = j(&[&s, &format!("ip daddr @{}", n)]);
                    msg.push_str(&format!("Nftset{}", api::translatef("[%s],", &[n])));
                }
                AclSource::Ip(ip) => {
                    s = factor(ip, &j(&[&s, "ip saddr"]));
                    msg.push_str(&format!("IP{}", api::translatef("[%s],", &[ip])));
                    ipv4 = true;
                }
                AclSource::Mac(m) => {
                    s = factor(m, &j(&[&s, "ether saddr"]));
                    msg.push_str(&format!("MAC{}", api::translatef("[%s],", &[m])));
                }
                AclSource::Any => msg.push_str(&api::translate("All device,")),
            }
            let msg = format!("{}{}", msg1, msg);
            // An IPv4 source match (ip/iprange, and the `ip daddr @set` of an ipset source)
            // cannot be combined with `ip6 daddr` or a family-less `tproxy`: nft rejects those
            // rules, so upstream (one nft call per rule) silently ends up without them. They
            // are not generated, so the atomic load keeps working; the kernel state is the same.
            let v4s = ipv4 || matches!(src, AclSource::Ipset(_));
            let s = s.as_str();
            let mut no_tcp = false;
            let mut no_udp = false;

            if !tcp_no.is_empty() {
                if !has_1_65535(&tcp_no) {
                    let f = factor(&tcp_no, "tcp dport");
                    g.add(pc, &[s, "ip protocol tcp", &f, "counter return", &rem]);
                    if !ipv4 {
                        g.add("PSW2_MANGLE_V6", &[s, "meta l4proto tcp", &f, "counter return", &rem]);
                    }
                    g.log(2, format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["TCP", &tcp_no])));
                } else {
                    no_tcp = true;
                    g.log(2, format!("{}{}", msg, api::translatef("not proxy all %s", &["TCP"])));
                }
            }
            if !udp_no.is_empty() {
                if !has_1_65535(&udp_no) {
                    let f = factor(&udp_no, "udp dport");
                    g.add("PSW2_MANGLE", &["ip protocol udp", s, &f, "counter return", &rem]);
                    if !ipv4 {
                        g.add("PSW2_MANGLE_V6", &["meta l4proto udp", s, &f, "counter return", &rem]);
                    }
                    g.log(2, format!("{}{}", msg, api::translatef("not proxy %s port [%s]", &["UDP", &udp_no])));
                } else {
                    no_udp = true;
                    g.log(2, format!("{}{}", msg, api::translatef("not proxy all %s", &["UDP"])));
                }
            }

            if (!no_tcp || !no_udp) && !dns_port.is_empty() {
                let r = format!("counter redirect to :{}", dns_port);
                g.add("PSW2_MANGLE", &["ip protocol udp", s, "udp dport 53 counter accept"]);
                g.add("PSW2_MANGLE", &["ip protocol tcp", s, "tcp dport 53 counter accept"]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto udp", s, "udp dport 53 counter accept"]);
                g.add("PSW2_MANGLE_V6", &["meta l4proto tcp", s, "tcp dport 53 counter accept"]);
                g.add("PSW2_DNS", &["meta l4proto udp", s, "udp dport 53", &r, &rem]);
                g.add("PSW2_DNS", &["meta l4proto tcp", s, "tcp dport 53", &r, &rem]);
                g.log(2, format!("{}{}", msg, api::translatef("DNS will redirected to the dedicated DNS server [%s].", &[&dns_port])));
            } else {
                g.add("PSW2_DNS", &["meta l4proto udp", s, "udp dport 53 counter return", &rem]);
                g.add("PSW2_DNS", &["meta l4proto tcp", s, "tcp dport 53 counter return", &rem]);
            }

            if !no_tcp && !redir_port.is_empty() {
                let mut msg2 = format!("{}{}", msg, api::translatef("Use the %s node [%s]", &["TCP", &node_remarks]));
                let (chain, jmp) = if ctx.tproxy {
                    msg2.push_str(&format!("(TPROXY:{})", redir_port));
                    ("PSW2_MANGLE", "counter jump PSW2_RULE".to_string())
                } else {
                    msg2.push_str(&format!("(REDIRECT:{})", redir_port));
                    ("PSW2_NAT", redirect(&redir_port, ""))
                };
                let red = redirect("", "");
                if ctx.accept_icmp {
                    let c = "PSW2_ICMP_REDIRECT";
                    g.add(c, &["ip protocol icmp", s, "ip daddr", FAKE_IP, &red, &rem]);
                    g.shunt(c, &["ip protocol icmp", s], "ip daddr", &a.shunt4, &red, Some(&remarks));
                    g.add(c, &["ip protocol icmp", s, &red, &rem]);
                    g.add(c, &["ip protocol icmp", s, "return", &rem]);
                }
                // upstream quirk: see the local-proxy icmpv6 note (chain exists only with accept_icmp).
                if ctx.accept_icmpv6 && ctx.proxy_ipv6 && ctx.accept_icmp {
                    let c = "PSW2_ICMP_REDIRECT";
                    if !v4s {
                        g.add(c, &["meta l4proto icmpv6", s, "ip6 daddr", FAKE_IP_6, &red, &rem]);
                        g.shunt(c, &["meta l4proto icmpv6", s], "ip6 daddr", &a.shunt6, &red, Some(&remarks));
                    }
                    g.add(c, &["meta l4proto icmpv6", s, &red, &rem]);
                    g.add(c, &["meta l4proto icmpv6", s, "return", &rem]);
                }
                g.add(chain, &["ip protocol tcp", s, "ip daddr", FAKE_IP, &jmp, &rem]);
                g.shunt(chain, &["ip protocol tcp", s, &tdport], "ip daddr", &a.shunt4, &jmp, Some(&remarks));
                g.add(chain, &["ip protocol tcp", s, &tdport, &jmp, &rem]);
                if ctx.tproxy {
                    g.add("PSW2_MANGLE", &["ip protocol tcp", s, &redirect(&redir_port, "TPROXY4"), &rem]);
                }
                if ctx.proxy_ipv6 && !ipv4 {
                    let c = "PSW2_MANGLE_V6";
                    if !v4s {
                        g.add(c, &["meta l4proto tcp", s, "ip6 daddr", FAKE_IP_6, "counter jump PSW2_RULE", &rem]);
                        g.shunt(c, &["meta l4proto tcp", s, &tdport], "ip6 daddr", &a.shunt6, "counter jump PSW2_RULE", Some(&remarks));
                    }
                    g.add(c, &["meta l4proto tcp", s, &tdport, "counter jump PSW2_RULE", &rem]);
                    if !v4s {
                        g.add(c, &["meta l4proto tcp", s, &redirect(&redir_port, "TPROXY"), &rem]);
                    }
                }
                g.log(2, msg2);
            }
            g.add(pc, &["ip protocol tcp", s, "counter return", &rem]);
            if !ipv4 {
                g.add("PSW2_MANGLE_V6", &["meta l4proto tcp", s, "counter return", &rem]);
            }

            if !no_udp && !redir_port.is_empty() {
                let msg2 = format!("{}{}(TPROXY:{})", msg, api::translatef("Use the %s node [%s]", &["UDP", &node_remarks]), redir_port);
                let c = "PSW2_MANGLE";
                g.add(c, &["ip protocol udp", s, "ip daddr", FAKE_IP, "counter jump PSW2_RULE", &rem]);
                g.shunt(c, &["ip protocol udp", s, &udport], "ip daddr", &a.shunt4, "counter jump PSW2_RULE", Some(&remarks));
                g.add(c, &["ip protocol udp", s, &udport, "counter jump PSW2_RULE", &rem]);
                g.add(c, &["ip protocol udp", s, &redirect(&redir_port, "TPROXY4"), &rem]);
                if ctx.proxy_ipv6 && !ipv4 {
                    let c = "PSW2_MANGLE_V6";
                    if !v4s {
                        g.add(c, &["meta l4proto udp", s, "ip6 daddr", FAKE_IP_6, "counter jump PSW2_RULE", &rem]);
                        g.shunt(c, &["meta l4proto udp", s, &udport], "ip6 daddr", &a.shunt6, "counter jump PSW2_RULE", Some(&remarks));
                    }
                    g.add(c, &["meta l4proto udp", s, &udport, "counter jump PSW2_RULE", &rem]);
                    if !v4s {
                        g.add(c, &["meta l4proto udp", s, &redirect(&redir_port, "TPROXY"), &rem]);
                    }
                }
                g.log(2, msg2);
            }
            g.add("PSW2_MANGLE", &["ip protocol udp", s, "counter return", &rem]);
            if !ipv4 {
                g.add("PSW2_MANGLE_V6", &["meta l4proto udp", s, "counter return", &rem]);
            }
        }
    }
}

// ====================================================================== geoip / shunt sets

/// `get_geoip <codes> ipv4|ipv6` → lines (cached under `$TMP_PATH2/geo_output`).
pub fn get_geoip(cfg: &Config, codes: &str, ip_type: &str) -> Vec<String> {
    let dir = format!("{}/geo_output", util::TMP_PATH2);
    util::mkdir(&dir);
    let out = format!("{}/geoip-{}-{}", dir, codes, ip_type);
    if util::read(&out).is_empty() {
        let asset = cfg.t_get("global_rules", "v2ray_location_asset", "");
        let asset = asset.strip_suffix('/').unwrap_or(&asset);
        let path = format!("{}/geoip.dat", asset);
        let bin = util::first_type(&cfg.t_get("global_app", "geoview_file", ""), "geoview");
        let Some(bin) = bin else { return vec![] };
        if std::fs::metadata(&path).map(|m| m.len() == 0).unwrap_or(true) {
            return vec![];
        }
        let flag = match ip_type {
            "ipv4" => "-ipv6=false",
            "ipv6" => "-ipv4=false",
            _ => "",
        };
        let mut args = vec!["-input", path.as_str(), "-list", codes];
        if !flag.is_empty() {
            args.push(flag);
        }
        args.extend(["-lowmem=true", "-output", out.as_str()]);
        util::cmd_ok(&bin, &args);
    }
    util::read(&out).lines().map(|l| l.to_string()).collect()
}

/// Lines of a (possibly multi-line, possibly list) option, `\r` normalised.
fn option_lines(cfg: &Config, sid: &str, opt: &str) -> Vec<String> {
    cfg.list_raw(sid, opt).iter().flat_map(|v| v.split(['\r', '\n']).map(|l| l.to_string()).collect::<Vec<_>>()).collect()
}

/// `geoip:` codes of a shunt rule's ip_list (without `geoip:private*`), comma-joined.
pub fn shunt_geoip_codes(lines: &[String]) -> String {
    lines
        .iter()
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.strip_prefix("geoip:"))
        .filter(|c| !c.starts_with("private"))
        // upstream joins the raw rest of the line; strip trailing comments/space so the
        // code list stays one argument
        .map(|c| c.split('#').next().unwrap_or("").trim().to_string())
        .filter(|c| !c.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// `gen_shunt_list node` → (shunt4, shunt6); creates and fills the shunt sets.
pub fn gen_shunt_list(cfg: &Config, node: &str) -> (ShuntList, ShuntList) {
    let mut l4 = vec![];
    let mut l6 = vec![];
    if node.is_empty() {
        return (l4, l6);
    }
    if cfg.s(node, "protocol") == "_shunt" {
        let mut geo = cfg.get_or(node, "enable_geoview_ip", "0");
        if util::first_type("geoview", "").is_none() {
            geo = "0".into();
        }
        if geo == "1" {
            let default_out = if cfg.get_or(node, "default_node", "_direct") == "_direct" { "direct" } else { "redirect" };
            let group = cfg.s(node, "shunt_group");
            for r in cfg.sections_of("shunt_rules") {
                if group != r.s("group") {
                    continue;
                }
                let sn = cfg.s(node, &r.name);
                if sn.is_empty() {
                    continue;
                }
                let s4 = format!("psw2_{}_{}", node, r.name);
                let s6 = format!("psw2_{}_{}6", node, r.name);
                gen_nftset(&s4, "ipv4_addr", "0");
                gen_nftset(&s6, "ipv6_addr", "0");
                let out = match sn.as_str() {
                    "_direct" => "direct",
                    "_default" => default_out,
                    _ => "redirect",
                };
                l4.push((s4.clone(), out.to_string()));
                l6.push((s6.clone(), out.to_string()));
                let lines = option_lines(cfg, &r.name, "ip_list");
                let stripped: Vec<String> = lines.iter().map(|l| l.split('#').next().unwrap_or("").to_string()).collect();
                let v4: Vec<String> = stripped.iter().filter(|l| re_ipv4_octets(l)).cloned().collect();
                let v6: Vec<String> = stripped.iter().filter(|l| re_ipv6(l)).cloned().collect();
                insert_nftset(&s4, Some(false), &v4);
                insert_nftset(&s6, Some(true), &v6);
                let codes = shunt_geoip_codes(&lines);
                if !codes.is_empty() {
                    let g4: Vec<String> = get_geoip(cfg, &codes, "ipv4").into_iter().filter(|l| re_ipv4_octets(l)).collect();
                    insert_nftset(&s4, Some(false), &g4);
                    let g6: Vec<String> = get_geoip(cfg, &codes, "ipv6").into_iter().filter(|l| re_ipv6(l)).collect();
                    insert_nftset(&s6, Some(true), &g6);
                }
            }
        }
        if let Some(d4) = util::get_cache_var(&format!("node_{}_direct_nftset4", node)).filter(|s| !s.is_empty()) {
            gen_nftset(&d4, "ipv4_addr", "0");
            l4.push((d4, "direct".into()));
        }
        if let Some(d6) = util::get_cache_var(&format!("node_{}_direct_nftset6", node)).filter(|s| !s.is_empty()) {
            gen_nftset(&d6, "ipv6_addr", "0");
            l6.push((d6, "direct".into()));
        }
    }
    util::set_cache_var(&format!("node_{}_gen_shunt_list", node), "1");
    (l4, l6)
}

// ====================================================================== set filling / filters

/// Lines in `uci show passwall2` form (`passwall2.<sec>.<opt>='<v>'`).
fn uci_show_lines(cfg: &Config) -> Vec<String> {
    let mut out = vec![];
    for s in &cfg.sections {
        out.push(format!("{}.{}={}", cfg.name, s.name, s.stype));
        for (k, v) in &s.options {
            let val = match v {
                uci::Value::Single(x) => format!("'{}'", x),
                uci::Value::List(l) => l.iter().map(|x| format!("'{}'", x)).collect::<Vec<_>>().join(" "),
            };
            out.push(format!("{}.{}.{}={}", cfg.name, s.name, k, val));
        }
    }
    out
}

/// `cut -d "'" -f 2`
fn cut_quote2(l: &str) -> String {
    l.split('\'').nth(1).unwrap_or(if l.contains('\'') { "" } else { l }).to_string()
}

/// Address values selected by `filter_vpsip` (v4, v6).
pub fn vps_addrs(cfg: &Config) -> (Vec<String>, Vec<String>) {
    let vals: Vec<String> = uci_show_lines(cfg)
        .iter()
        .filter(|l| l.find("address=").is_some_and(|i| i >= 1))
        .map(|l| cut_quote2(l))
        .collect();
    let v4 = vals.iter().filter(|v| re_ipv4_dotted(v) && v.as_str() != "127.0.0.1").cloned().collect();
    let v6 = vals.iter().filter(|v| re_ipv6(v)).cloned().collect();
    (v4, v6)
}

/// `filter_vpsip`
pub fn filter_vpsip(cfg: &Config) {
    let (v4, v6) = vps_addrs(cfg);
    if !v4.is_empty() {
        insert_nftset(NFTSET_VPS, Some(false), &v4);
        api::log_i18n(1, "Add all %s nodes to %s[%s] direct connection complete.", &["IPv4", "nftset", NFTSET_VPS]);
    }
    if !v6.is_empty() {
        insert_nftset(NFTSET_VPS6, Some(true), &v6);
        api::log_i18n(1, "Add all %s nodes to %s[%s] direct connection complete.", &["IPv6", "nftset", NFTSET_VPS6]);
    }
}

/// `filter_haproxy`
pub fn filter_haproxy(cfg: &Config) {
    if cfg.get_or("@global_haproxy[0]", "balancing_enable", "0") != "1" {
        return;
    }
    let ips: Vec<String> = uci_show_lines(cfg)
        .iter()
        .filter(|l| l.contains(".lbss="))
        .filter_map(|l| {
            let item = cut_quote2(l);
            let host = item.split(':').next().unwrap_or("").to_string();
            util::get_host_ip("ipv4", &host, 1)
        })
        .collect();
    insert_nftset(NFTSET_VPS, Some(false), &ips);
    api::log_i18n(1, "Add node to the load balancer is directly connected to %s[%s].", &["nftset", NFTSET_VPS]);
}

/// `filter_vps_addr hosts...`
pub fn filter_vps_addr(hosts: &[String]) {
    let hosts: Vec<&String> = hosts.iter().filter(|h| !h.is_empty()).collect();
    let v4: Vec<String> = hosts.iter().filter_map(|h| get_host_ip_sh("ipv4", h, 3)).collect();
    insert_nftset(NFTSET_VPS, Some(false), &v4);
    let v6: Vec<String> = hosts.iter().filter_map(|h| get_host_ip_sh("ipv6", h, 3)).collect();
    insert_nftset(NFTSET_VPS6, Some(true), &v6);
}

/// utils.sh `get_host_ip` (regex test for literal addresses, else resolveip).
fn get_host_ip_sh(fam: &str, host: &str, count: u32) -> Option<String> {
    if fam == "ipv6" {
        if re_ipv6(host) {
            return Some(host.replace(['[', ']'], ""));
        }
    } else if re_ipv4_dotted(host) {
        return Some(host.to_string());
    }
    util::get_host_ip(fam, host, count)
}

/// `filter_server_port addr port stream` into the output chain `oc`.
pub fn filter_server_port(oc: &str, address: &str, port: &str, stream: &str) {
    let stream = stream.to_lowercase();
    let key = format!("{}:{}", address, port);
    for ip_type in ["ip", "ip6"] {
        let listing = list_chain(NFTABLE_NAME, oc).unwrap_or_default();
        if listing.contains(&key) {
            continue;
        }
        nft_cmd(&format!(
            "insert rule {} {} meta l4proto {} {} daddr {} {} dport {} return {}",
            NFTABLE_NAME,
            oc,
            stream,
            ip_type,
            address,
            stream,
            port,
            cmt(&key)
        ));
    }
}

/// `filter_node node stream`
pub fn filter_node(cfg: &Config, oc: &str, node: &str, stream: &str) -> bool {
    if node.is_empty() {
        return true;
    }
    let address = cfg.s(node, "address");
    let port = cfg.s(node, "port");
    if address.is_empty() && port.is_empty() {
        return false;
    }
    filter_server_port(oc, &address, &port, stream);
    filter_server_port(oc, &address, &port, stream);
    true
}

/// Output chain from the config (upstream relies on a variable that is unset when this is
/// called standalone; we derive it from `tcp_proxy_way`).
fn output_chain_from(cfg: &Config) -> &'static str {
    if cfg.get_or("@global_forwarding[0]", "tcp_proxy_way", "redirect") == "tproxy" { "PSW2_OUTPUT_MANGLE" } else { "PSW2_OUTPUT_NAT" }
}

/// `filter_direct_node_list`
pub fn filter_direct_node_list() {
    let text = util::read(&format!("{}/direct_node_list", util::TMP_PATH));
    if text.trim().is_empty() {
        return;
    }
    let cfg = Config::load(util::CONFIG);
    let oc = output_chain_from(&cfg);
    let mut seen: Vec<&str> = vec![];
    for id in text.lines() {
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        filter_node(&cfg, oc, id, "TCP");
        filter_node(&cfg, oc, id, "UDP");
    }
}

/// `update_wan_sets` (locked; sets only grow).
pub fn update_wan_sets() {
    let _lock = util::lock(&format!("{}/{}_update_wan_sets.lock", util::LOCK_PATH, util::CONFIG));
    let w4 = util::get_wan_ips("ip4");
    if !w4.is_empty() {
        insert_nftset(NFTSET_WAN, Some(false), &w4);
    }
    let w6 = util::get_wan_ips("ip6");
    if !w6.is_empty() {
        insert_nftset(NFTSET_WAN6, Some(true), &w6);
    }
}

/// Split the direct_ip file into (v4 entries, v6 entries, geoip codes) in file order.
pub enum DirectEntry {
    V4(String),
    V6(String),
    Geoip(String),
}
pub fn parse_direct_ip(text: &str) -> Vec<DirectEntry> {
    text.split(['\r', '\n'])
        .filter(|l| !l.starts_with('#'))
        .flat_map(|l| l.split_whitespace())
        .map(|ip| {
            if ip.contains("::") {
                DirectEntry::V6(ip.to_string())
            } else if let Some(rest) = ip.strip_prefix("geoip:") {
                DirectEntry::Geoip(rest.split(':').next().unwrap_or("").to_string())
            } else {
                DirectEntry::V4(ip.to_string())
            }
        })
        .collect()
}

/// CIDRs of `ip address show <if>` (inet, inet6).
fn iface_cidrs(ifname: &str) -> (Vec<String>, Vec<String>) {
    let out = util::cmd_out("ip", &["address", "show", ifname]);
    let mut v4 = vec![];
    let mut v6 = vec![];
    for l in out.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        match f.first().copied() {
            Some("inet") => v4.extend(f.get(1).map(|s| s.to_string())),
            Some("inet6") => v6.extend(f.get(1).map(|s| s.to_string())),
            _ => {}
        }
    }
    (v4, v6)
}

/// Device for an ACL `interface` (network_get_device → ubus `.device` → sysfs → name).
pub fn interface_device(iface: &str) -> String {
    let st = util::cmd_out("ubus", &["call", &format!("network.interface.{}", iface), "status"]);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&st) {
        for k in ["l3_device", "device"] {
            if let Some(d) = v[k].as_str().filter(|s| !s.is_empty()) {
                return d.to_string();
            }
        }
    }
    iface.to_string()
}

// ====================================================================== start / stop

fn spawn_self(args: &[&str]) {
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| util::SELF_BIN.to_string());
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    util::spawn_bg(&exe, &a, "/dev/null");
}

/// Background part of §2.3 step 10 (`filter_vpsip`, `filter_haproxy`, `filter_vps_addr`).
pub fn filter_vps_all() {
    let cfg = Config::load(util::CONFIG);
    filter_vpsip(&cfg);
    filter_haproxy(&cfg);
    let node = cfg.s("@global[0]", "node");
    let addr = cfg.s(&node, "address");
    filter_vps_addr(&[addr]);
    let daddr = cfg.s(&node, "download_address");
    filter_vps_addr(&[daddr]);
}

/// Gather the `load_acl` inputs (reads ACL files, creates shunt sets).
fn load_acl_inputs(cfg: &Config, flags: &[String]) -> Vec<AclInput> {
    let mut shunts: HashMap<String, (ShuntList, ShuntList)> = HashMap::new();
    let mut out = vec![];
    for sid in flags {
        let var = acl::read_acl_var(sid);
        let node = var.s("node");
        // upstream quirk: upstream keeps one global shunt_list shared by all ACLs; we keep
        // the list per node.
        let (shunt4, shunt6) = if node.is_empty() {
            (vec![], vec![])
        } else {
            shunts.entry(node.clone()).or_insert_with(|| gen_shunt_list(cfg, &node)).clone()
        };
        let dns_redirect_port = ArgsExt::ne(&var, "use").and_then(|u| util::get_cache_var(&format!("ACL_{}_dns_port", u))).filter(|s| !s.is_empty());
        let device = ArgsExt::ne(&var, "interface").map(interface_device);
        let mut sources = vec![];
        if var.g("client_proxy") == Some("1") {
            for s in acl::read_source_list(sid) {
                if let AclSource::Ipset(n) = &s {
                    let ok = nft_out(&["list", "set", "inet", "passwall2", n]).and_then(|l| parse_set_type(&l)).as_deref() == Some("ipv4_addr");
                    if !ok {
                        // upstream emits rules against the missing set, which nft rejects; the
                        // source is skipped (same effect), like the iptables backend does.
                        util::log(2, &format!("{}Nftset{}{}", api::translatef("[%s],", &[&var.s("remarks")]), api::translatef("[%s],", &[n]), api::translate("Does not exist, ignore.")));
                        continue;
                    }
                }
                sources.push(s);
            }
        }
        out.push(AclInput { var, sources, device, dns_redirect_port, shunt4, shunt6 });
    }
    out
}

fn ip_cmd(args: &[&str]) {
    util::cmd_ok("ip", args);
}

/// `add_firewall_rule` (§2.3). `acl_node` is app.sh's `acl_node` (starts the ACL cores and
/// dnsmasq copies); it runs at the start of `load_acl`, as upstream.
pub fn add_firewall_rule(env: &NftEnv, acl_node: &mut dyn FnMut()) {
    let cfg = Config::load(util::CONFIG);
    api::log_i18n(0, "Starting to load %s firewall rules...", &["nftables"]);
    gen_nft_tables();
    add_script_mwan3();
    mwan3_start();

    for s in [NFTSET_LOCAL, NFTSET_DIRECT, NFTSET_VPS, NFTSET_WAN] {
        gen_nftset(s, "ipv4_addr", "0");
    }
    for s in [NFTSET_LOCAL6, NFTSET_DIRECT6, NFTSET_VPS6, NFTSET_WAN6] {
        gen_nftset(s, "ipv6_addr", "0");
    }
    insert_nftset(NFTSET_LOCAL, Some(false), &util::get_local_ips("ip4"));
    insert_nftset(NFTSET_LOCAL6, Some(true), &util::get_local_ips("ip6"));

    for e in parse_direct_ip(&util::read(DIRECT_IP_FILE)) {
        match e {
            DirectEntry::V6(ip) => insert_nftset(NFTSET_DIRECT6, Some(true), &[ip]),
            DirectEntry::V4(ip) => insert_nftset(NFTSET_DIRECT, Some(false), &[ip]),
            DirectEntry::Geoip(code) => {
                let g4: Vec<String> = get_geoip(&cfg, &code, "ipv4").into_iter().filter(|l| re_ipv4_octets(l)).collect();
                insert_nftset(NFTSET_DIRECT, Some(false), &g4);
                let g6: Vec<String> = get_geoip(&cfg, &code, "ipv6").into_iter().filter(|l| re_ipv6(l)).collect();
                insert_nftset(NFTSET_DIRECT6, Some(true), &g6);
            }
        }
    }

    let lan_ifname = util::cmd_out("uci", &["-q", "-p", "/tmp/state", "get", "network.lan.ifname"]).trim().to_string();
    if !lan_ifname.is_empty() {
        let (v4, v6) = iface_cidrs(&lan_ifname);
        insert_nftset(NFTSET_DIRECT, Some(false), &v4);
        insert_nftset(NFTSET_DIRECT6, Some(true), &v6);
    }

    update_wan_sets();

    if !env.isp_dns.is_empty() {
        insert_nftset(NFTSET_DIRECT, Some(false), &env.isp_dns);
        for ip in &env.isp_dns {
            util::log(1, &api::translatef("Add ISP %s DNS to the whitelist: %s", &["IPv4", ip]));
        }
    }
    if !env.isp_dns6.is_empty() {
        insert_nftset(NFTSET_DIRECT6, Some(true), &env.isp_dns6);
        for ip in &env.isp_dns6 {
            util::log(1, &api::translatef("Add ISP %s DNS to the whitelist: %s", &["IPv6", ip]));
        }
    }

    // filter_vpsip / filter_haproxy / filter_vps_addr run in the background like upstream.
    spawn_self(&["nft", "filter_vps"]);

    let ifaces: Vec<String> = std::fs::read_dir(util::TMP_IFACE_PATH)
        .map(|rd| {
            let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            v.sort();
            v
        })
        .unwrap_or_default();
    let ctx = RuleCtx {
        tproxy: env.is_tproxy(),
        proxy_ipv6: env.proxy_ipv6,
        accept_icmp: cfg.get_or("@global_forwarding[0]", "accept_icmp", "0") == "1",
        accept_icmpv6: cfg.get_or("@global_forwarding[0]", "accept_icmpv6", "0") == "1",
        dns_redirect: cfg.get_or("@global[0]", "dns_redirect", "1") != "0",
        return_dns: env.return_dns.clone(),
        ifaces,
    };

    let mut g = Gen::default();
    gen_base_rules(&ctx, &mut g);

    api::log_i18n(1, "Access Control:", &[]);
    acl_node();
    let inputs = load_acl_inputs(&cfg, &env.acl_flags);
    for a in &inputs {
        gen_acl_rules(&ctx, a, &mut g);
    }
    gen_direct_gid_rules(&mut g);

    apply_cmds(&g.cmds);
    for (lvl, m) in &g.logs {
        util::log(*lvl, m);
    }

    ip_cmd(&["rule", "add", "fwmark", FWMARK, "table", "999", "priority", "999"]);
    ip_cmd(&["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "999"]);
    if ctx.proxy_ipv6 {
        ip_cmd(&["-6", "rule", "add", "fwmark", FWMARK, "table", "999", "priority", "999"]);
        ip_cmd(&["-6", "route", "add", "local", "::/0", "dev", "lo", "table", "999"]);
    }

    spawn_self(&["nft", "filter_direct_node_list"]);

    api::log_i18n(0, "%s firewall rules load complete!", &["nftables"]);
}

/// Commands that `del_firewall_rule` runs, from the current listings.
pub fn gen_del_cmds(base_listings: &[(&str, String)], table_terse: &str) -> Vec<String> {
    let mut cmds = vec![];
    for (chain, listing) in base_listings {
        for h in parse_handles(listing, "PSW2_") {
            cmds.push(format!("delete rule {} {} handle {}", NFTABLE_NAME, chain, h));
        }
    }
    let chains: Vec<String> = parse_block_names(table_terse, "chain").into_iter().filter(|c| c.starts_with("PSW2_")).collect();
    for c in &chains {
        cmds.push(format!("flush chain {} {}", NFTABLE_NAME, c));
    }
    for c in chains.iter().filter(|c| c.as_str() != "PSW2_RULE") {
        cmds.push(format!("delete chain {} {}", NFTABLE_NAME, c));
    }
    // PSW2_RULE last, otherwise it is still referenced ("Resource busy")
    if chains.iter().any(|c| c == "PSW2_RULE") {
        cmds.push(format!("delete chain {} PSW2_RULE", NFTABLE_NAME));
    }
    let sets = parse_block_names(table_terse, "set");
    for s in [NFTSET_LOCAL, NFTSET_WAN, NFTSET_DIRECT, NFTSET_VPS, NFTSET_LOCAL6, NFTSET_WAN6, NFTSET_DIRECT6, NFTSET_VPS6] {
        if sets.iter().any(|x| x == s) {
            cmds.push(format!("flush set {} {}", NFTABLE_NAME, s));
            cmds.push(format!("delete set {} {}", NFTABLE_NAME, s));
        }
    }
    cmds
}

/// `del_firewall_rule` (§2.8).
pub fn del_firewall_rule() {
    let listings: Vec<(&str, String)> = BASE_CHAINS.iter().filter_map(|c| list_chain(NFTABLE_NAME, c).map(|l| (*c, l))).collect();
    // upstream quirk: upstream lists chains of every table (`nft -a list chains`); only
    // `inet passwall2` is considered here.
    let terse = nft_out(&["-t", "list", "table", "inet", "passwall2"]).unwrap_or_default();
    apply_cmds(&gen_del_cmds(&listings, &terse));

    ip_cmd(&["rule", "del", "fwmark", FWMARK]);
    ip_cmd(&["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "999"]);
    ip_cmd(&["-6", "rule", "del", "fwmark", FWMARK]);
    ip_cmd(&["-6", "route", "del", "local", "::/0", "dev", "lo", "table", "999"]);

    del_script_mwan3();
    api::log_i18n(0, "Delete %s rules is complete.", &["nftables"]);
}

/// `flush_nftset`: destroy every `psw2_*` set of `inet passwall2`.
pub fn flush_nftset() {
    api::log_i18n(0, "Clear %s.", &["NFTSet"]);
    let terse = nft_out(&["-t", "list", "table", "inet", "passwall2"]).unwrap_or_default();
    let names: Vec<String> = parse_block_names(&terse, "set").into_iter().filter(|n| n.contains("psw2_")).collect();
    let mut cmds = vec![];
    for n in &names {
        cmds.push(format!("flush set {} {}", NFTABLE_NAME, n));
        cmds.push(format!("delete set {} {}", NFTABLE_NAME, n));
    }
    apply_cmds(&cmds);
}

/// `flush_table` (unused upstream; kept for completeness).
pub fn flush_table() {
    nft_cmd(&format!("flush table {}", NFTABLE_NAME));
    nft_cmd(&format!("delete table {}", NFTABLE_NAME));
}

/// FWI = `uci get firewall.passwall2.path`
pub fn fwi_path() -> Option<String> {
    Config::load("firewall").get("passwall2", "path").filter(|s| !s.is_empty())
}

/// `flush_include`
pub fn flush_include() {
    if let Some(f) = fwi_path() {
        util::write(&f, "#!/bin/sh\n");
    }
}

/// Firewall include content (§2.10); `update_wan_sets` is run through our binary.
pub fn include_text(dump_file: &str) -> String {
    format!(
        "#!/bin/sh\n[ -z \"$(nft list chain {} mangle_prerouting | grep PSW2)\" ] && nft -f {}\n\n{} nft update_wan_sets\n\nreturn 0\n",
        NFTABLE_NAME,
        dump_file,
        util::SELF_BIN
    )
}

/// `gen_include`
pub fn gen_include() {
    let dump = nft_out(&["list", "table", "inet", "passwall2"]).unwrap_or_default();
    util::write(RULE_DUMP_FILE, &format!("#!/bin/sh\n{}", dump));
    if let Some(f) = fwi_path() {
        util::write(&f, &include_text(RULE_DUMP_FILE));
    }
}

/// `start`: returns false when nothing was loaded.
pub fn start(env: &NftEnv, acl_node: &mut dyn FnMut()) -> bool {
    if !env.enabled_default_acl && !env.enabled_acls {
        return false;
    }
    add_firewall_rule(env, acl_node);
    gen_include();
    true
}

/// `stop`
pub fn stop() {
    del_firewall_rule();
    let cfg = Config::load(util::CONFIG);
    if cfg.get_or("@global[0]", "flush_set", "0") == "1" {
        let mut b = uci::Batch::new();
        b.delete(&format!("{}.@global[0].flush_set", util::CONFIG));
        let _ = b.commit();
        flush_nftset();
        if let Ok(rd) = std::fs::read_dir(util::TMP_PATH2) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("singbox") {
                    util::rm_rf(&e.path().to_string_lossy());
                }
            }
        }
        util::rm_rf(&format!("{}/geo_output", util::TMP_PATH2));
    }
    flush_include();
}

// ====================================================================== mwan3

fn mwan3_line(sub: &str) -> String {
    format!("    {} nft {}", util::SELF_BIN, sub)
}

/// `sed -i "/passwall2/d"`
pub fn mwan3_unpatch(text: &str) -> String {
    let mut out: String = text.lines().filter(|l| !l.contains(util::CONFIG)).collect::<Vec<_>>().join("\n");
    if text.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    out
}

/// The two `sed -i` edits of `add_script_mwan3` (start line before `}` of start_service,
/// stop line after `stop_service() {`).
pub fn mwan3_patch(text: &str) -> String {
    let start_line = mwan3_line("mwan3_start");
    let stop_line = mwan3_line("mwan3_stop");
    // pass 1: /start_service()/,/}/ s/^}/X\n}/
    let mut p1: Vec<String> = vec![];
    let mut in_range = false;
    for l in text.lines() {
        if !in_range {
            if l.contains("start_service()") {
                in_range = true;
                if l.starts_with('}') {
                    p1.push(start_line.clone());
                }
            }
            p1.push(l.to_string());
            continue;
        }
        if l.starts_with('}') {
            p1.push(start_line.clone());
        }
        p1.push(l.to_string());
        if l.contains('}') {
            in_range = false;
        }
    }
    // pass 2: /stop_service().*{/a X
    let mut p2: Vec<String> = vec![];
    for l in p1 {
        let m = l.find("stop_service()").is_some_and(|i| l[i + "stop_service()".len()..].contains('{'));
        p2.push(l);
        if m {
            p2.push(stop_line.clone());
        }
    }
    let mut s = p2.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn mwan3_nonempty() -> bool {
    std::fs::metadata(MWAN3_INIT).map(|m| m.len() > 0).unwrap_or(false)
}

/// `del_script_mwan3`
pub fn del_script_mwan3() {
    if mwan3_nonempty() {
        let t = util::read(MWAN3_INIT);
        let n = mwan3_unpatch(&t);
        if n != t {
            util::write(MWAN3_INIT, &n);
        }
    }
}

/// `add_script_mwan3`
pub fn add_script_mwan3() {
    del_script_mwan3();
    if mwan3_nonempty() {
        let t = util::read(MWAN3_INIT);
        util::write(MWAN3_INIT, &mwan3_patch(&t));
    }
}

fn mwan3_hook_exists() -> bool {
    nft_out(&["list", "chain", "ip", "mangle", "mwan3_hook"]).is_some()
}

/// `mwan3_stop`
pub fn mwan3_stop() {
    if !mwan3_hook_exists() {
        return;
    }
    let listing = list_chain("ip mangle", "mwan3_hook").unwrap_or_default();
    for h in parse_handles(&listing, FWMARK) {
        nft_cmd(&format!("delete rule ip mangle mwan3_hook handle {}", h));
    }
    let mut args = vec!["-w", "5", "-t", "mangle", "-D", "mwan3_hook"];
    args.extend(MWAN3_RULE_ARGS);
    for _ in 0..1000 {
        if !util::cmd_ok("iptables", &args) {
            break;
        }
    }
}

/// `mwan3_start`
pub fn mwan3_start() {
    if !mwan3_hook_exists() {
        return;
    }
    mwan3_stop();
    let mut args = vec!["-w", "5", "-t", "mangle", "-I", "mwan3_hook", "1"];
    args.extend(MWAN3_RULE_ARGS);
    if !util::cmd_ok("iptables", &args) {
        util::cmd_ok("logger", &["-t", "passwall2", &format!("mwan3: failed to add {} exemption rule to mangle/mwan3_hook", FWMARK)]);
    }
}

// ====================================================================== CLI

/// `passwall2 nft <sub> ...` — same subcommands as `nftables.sh`, plus the helpers.
pub fn cli(args: &[String]) -> i32 {
    let a = |i: usize| args.get(i).map(|s| s.as_str()).unwrap_or("");
    match a(0) {
        "start" => {
            let env = NftEnv::from_system(&Config::load(util::CONFIG));
            start(&env, &mut || {});
            0
        }
        "stop" => {
            stop();
            0
        }
        "filter_direct_node_list" => {
            filter_direct_node_list();
            0
        }
        "filter_vps" => {
            filter_vps_all();
            0
        }
        "mwan3_start" => {
            mwan3_start();
            0
        }
        "mwan3_stop" => {
            mwan3_stop();
            0
        }
        "update_wan_sets" => {
            update_wan_sets();
            0
        }
        "flush_nftset" => {
            flush_nftset();
            0
        }
        "gen_include" => {
            gen_include();
            0
        }
        "flush_include" => {
            flush_include();
            0
        }
        "insert_nftset" => {
            use std::io::Read;
            let mut s = String::new();
            let _ = std::io::stdin().read_to_string(&mut s);
            insert_nftset(a(1), None, &[s]);
            0
        }
        "destroy_nftset" => {
            let names: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
            destroy_nftset(&names);
            0
        }
        "gen_nftset" => {
            gen_nftset(a(1), if a(2).is_empty() { "ipv4_addr" } else { a(2) }, a(3));
            0
        }
        "insert_rule_before" | "insert_rule_after" => {
            if args.len() < 5 {
                return 1;
            }
            let ok = if a(0) == "insert_rule_before" {
                insert_rule_before(a(1), a(2), a(3), a(4), a(5))
            } else {
                insert_rule_after(a(1), a(2), a(3), a(4), a(5))
            };
            if ok { 0 } else { 1 }
        }
        "RULE_LAST_INDEX" => {
            if args.len() < 4 {
                api::log_i18n(1, "Incorrect index listing method (%s), execution terminated!", &["nftables"]);
                return 1;
            }
            println!("{}", rule_last_index(a(1), a(2), a(3), a(4)));
            0
        }
        "gen_rules" => {
            // debugging aid: print the rule script `start` would load (no changes made)
            let cfg = Config::load(util::CONFIG);
            let env = NftEnv::from_system(&cfg);
            let ctx = RuleCtx {
                tproxy: env.is_tproxy(),
                proxy_ipv6: env.proxy_ipv6,
                accept_icmp: cfg.get_or("@global_forwarding[0]", "accept_icmp", "0") == "1",
                accept_icmpv6: cfg.get_or("@global_forwarding[0]", "accept_icmpv6", "0") == "1",
                dns_redirect: cfg.get_or("@global[0]", "dns_redirect", "1") != "0",
                return_dns: env.return_dns.clone(),
                ifaces: vec![],
            };
            let mut g = Gen::default();
            gen_base_rules(&ctx, &mut g);
            for sid in &env.acl_flags {
                let var = acl::read_acl_var(sid);
                let input = AclInput {
                    dns_redirect_port: ArgsExt::ne(&var, "use").and_then(|u| util::get_cache_var(&format!("ACL_{}_dns_port", u))),
                    device: ArgsExt::ne(&var, "interface").map(interface_device),
                    sources: acl::read_source_list(sid),
                    var,
                    ..Default::default()
                };
                gen_acl_rules(&ctx, &input, &mut g);
            }
            gen_direct_gid_rules(&mut g);
            print!("{}", g.script());
            0
        }
        _ => 0,
    }
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn args(kv: &[(&str, &str)]) -> Args {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn t_factor() {
        assert_eq!(factor("80,443,1000:2000", "tcp dport"), "tcp dport {80,443,1000-2000}");
        assert_eq!(factor("53", "udp dport"), "udp dport {53}");
        assert_eq!(factor("1:65535", "tcp dport"), "");
        assert_eq!(factor("80,1:65535", "tcp dport"), "");
        assert_eq!(factor("", "tcp dport"), "");
        assert_eq!(factor("80", ""), "");
        assert_eq!(factor("80, 80 ,,443", "tcp dport"), "tcp dport {80,443}");
        assert_eq!(factor("aa:bb:cc:dd:ee:ff", "ether saddr"), "ether saddr {aa:bb:cc:dd:ee:ff}");
        assert_eq!(factor("192.168.1.2-192.168.1.9", "ip saddr"), "ip saddr {192.168.1.2-192.168.1.9}");
    }

    #[test]
    fn t_redirect_and_ports() {
        assert_eq!(redirect("", ""), "counter redirect");
        assert_eq!(redirect("1041", ""), "counter redirect to :1041");
        assert_eq!(redirect("1041", "TPROXY"), "counter meta mark 0x50535732 tproxy to :1041");
        assert_eq!(redirect("1041", "TPROXY4"), "counter meta mark 0x50535732 tproxy ip to :1041");
        assert_eq!(redirect("1041", "TPROXY6"), "counter meta mark 0x50535732 tproxy ip6 to :1041");
        assert_eq!(redirect("", "TPROXY4"), "counter redirect");
        assert!(has_1_65535("1:65535"));
        assert!(has_1_65535("22,1:65535"));
        assert!(!has_1_65535("1:6553"));
        assert!(!has_1_65535(""));
    }

    #[test]
    fn t_regexes() {
        assert!(re_ipv4_octets("1.2.3.4/24"));
        assert!(re_ipv4_octets("x.255.0.1"));
        assert!(!re_ipv4_octets("geoip:cn"));
        assert!(!re_ipv4_octets("1.300.300.300"));
        assert!(re_ipv6("2001:db8::/32"));
        assert!(re_ipv6("::ffff:1.2.3.4"));
        assert!(!re_ipv6("geoip:cn"));
        assert!(!re_ipv6("1.2.3.4"));
        assert!(re_ipv4_dotted("1.2.3.4"));
        assert!(re_ipv4_dotted("a1234.5.6.7"));
        assert!(!re_ipv4_dotted("1.2.3"));
        assert!(!re_ipv4_dotted("example.com"));
        assert!(has_mac("mac AA:bb:cc:00:11:22"));
        assert!(!has_mac("aa:bb:cc:00:11"));
    }

    #[test]
    fn t_valid_elem() {
        assert!(valid_elem("10.0.0.0/8", Some(false)));
        assert!(valid_elem("192.168.1.1/24", Some(false)));
        assert!(valid_elem("1.1.1.1-1.1.1.9", Some(false)));
        assert!(!valid_elem("1.1.1.1-::1", None));
        assert!(!valid_elem("10.0.0.0/8", Some(true)));
        assert!(valid_elem("::/127", Some(true)));
        assert!(valid_elem("fe80::/10", Some(true)));
        assert!(!valid_elem("1.2.3.4.nip.io", None));
        assert!(!valid_elem("geoip:cn", None));
    }

    #[test]
    fn t_insert_text() {
        let t = insert_nftset_text("psw2_vps", &["1.1.1.1\n2.2.2.2".into(), " 3.3.3.3 ".into()]);
        assert_eq!(t, "add element inet passwall2 psw2_vps { \n 1.1.1.1,\n 2.2.2.2,\n 3.3.3.3\n }\n");
        assert_eq!(insert_nftset_text("psw2_vps", &["  ".into()]), "");
        assert_eq!(gen_nftset_cmd("psw2_x", "ipv6_addr", "0"), "add set inet passwall2 psw2_x { type ipv6_addr; flags interval, timeout; auto-merge; }");
        assert_eq!(
            gen_nftset_cmd("psw2_x", "ipv4_addr", "3600"),
            "add set inet passwall2 psw2_x { type ipv4_addr; flags interval, timeout; timeout 3600; gc-interval 1h; auto-merge; }"
        );
    }

    #[test]
    fn t_base_redirect() {
        let ctx = RuleCtx { dns_redirect: true, return_dns: "223.5.5.5#53,2400:3200::1,8.8.8.8#5353#tcp".into(), ..Default::default() };
        let mut g = Gen::default();
        gen_base_rules(&ctx, &mut g);
        let s = g.script();
        let expect_head = "add chain inet passwall2 PSW2_DNS\n\
flush chain inet passwall2 PSW2_DNS\n\
insert rule inet passwall2 dstnat ip saddr @psw2_direct jump PSW2_DNS\n\
insert rule inet passwall2 dstnat ip6 saddr @psw2_direct6 jump PSW2_DNS\n\
add chain inet passwall2 PSW2_RULE\n\
flush chain inet passwall2 PSW2_RULE\n\
add rule inet passwall2 PSW2_RULE counter meta mark set ct mark\n\
add rule inet passwall2 PSW2_RULE meta mark 0x50535732 counter return\n\
add rule inet passwall2 PSW2_RULE tcp flags & (fin|syn|rst|ack) == syn counter meta mark set 0x50535732\n\
add rule inet passwall2 PSW2_RULE meta l4proto udp ct state { new, related } counter meta mark set 0x50535732\n\
add rule inet passwall2 PSW2_RULE counter ct mark set mark\n";
        assert!(s.starts_with(expect_head), "{}", s);
        assert!(s.contains("add rule inet passwall2 mangle_prerouting ip daddr != @psw2_direct ip protocol udp counter jump PSW2_MANGLE\n"));
        assert!(!s.contains("ip protocol tcp counter jump PSW2_MANGLE"));
        assert!(s.contains("add rule inet passwall2 dstnat ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_NAT\n"));
        assert!(s.contains("add rule inet passwall2 PSW2_NAT ip daddr @psw2_wan counter return comment \"WAN_IP_RETURN\"\n"));
        assert!(s.contains("insert rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol udp ip daddr 223.5.5.5 udp dport {53} counter return\n"));
        assert!(s.contains("insert rule inet passwall2 PSW2_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr 2400:3200::1 udp dport {53} counter return\n"));
        assert!(s.contains("insert rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol tcp ip daddr 8.8.8.8 tcp dport {5353} counter return\n"));
        assert!(!s.contains("PSW2_ICMP_REDIRECT"));
        assert!(!s.contains("PSW2_MANGLE_V6 ip6 daddr @psw2_wan6"));
        assert_eq!(g.logs.len(), 3);
    }

    #[test]
    fn t_base_tproxy_ipv6_icmp() {
        let ctx = RuleCtx { tproxy: true, proxy_ipv6: true, accept_icmp: true, accept_icmpv6: true, dns_redirect: false, ..Default::default() };
        let mut g = Gen::default();
        gen_base_rules(&ctx, &mut g);
        let s = g.script();
        assert!(s.contains("insert rule inet passwall2 dstnat ip saddr @psw2_direct ip daddr @psw2_local jump PSW2_DNS\n"));
        assert!(s.contains("mangle_prerouting ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_MANGLE\n"));
        assert!(!s.contains("PSW2_NAT"));
        assert!(!s.contains("PSW2_OUTPUT_NAT"));
        assert!(s.contains("add rule inet passwall2 PSW2_ICMP_REDIRECT ip6 daddr @psw2_vps6 counter return\n"));
        assert!(s.contains("add rule inet passwall2 nat_output ip6 daddr != @psw2_direct6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT\n"));
        assert!(s.contains(
            "add rule inet passwall2 mangle_output ip6 daddr != @psw2_direct6 meta nfproto {ipv6} counter jump PSW2_OUTPUT_MANGLE_V6 comment \"PSW2_OUTPUT_MANGLE\"\n"
        ));
        assert!(s.ends_with("add rule inet passwall2 PSW2_MANGLE_V6 ip6 daddr @psw2_wan6 counter return comment \"WAN6_IP_RETURN\"\n"));
        let mut g2 = Gen::default();
        gen_direct_gid_rules(&mut g2);
        assert_eq!(
            g2.cmds,
            vec![
                "insert rule inet passwall2 mangle_output meta skgid 9912 counter return comment \"PSW2_DIRECT\"",
                "insert rule inet passwall2 nat_output meta skgid 9912 counter return comment \"PSW2_DIRECT\"",
            ]
        );
    }

    fn default_acl() -> AclInput {
        AclInput {
            var: args(&[
                ("flag", "acl_default"),
                ("remarks", "Default"),
                ("tcp_redir_ports", "1:65535"),
                ("udp_redir_ports", "1:65535"),
                ("local_proxy", "1"),
                ("client_proxy", "1"),
                ("use", "acl_default"),
                ("node", "n1"),
                ("node_remarks", "N1"),
                ("redir_port", "1041"),
            ]),
            sources: vec![AclSource::Any],
            dns_redirect_port: Some("15353".into()),
            ..Default::default()
        }
    }

    #[test]
    fn t_acl_default_redirect() {
        let ctx = RuleCtx { dns_redirect: true, ..Default::default() };
        let mut a = default_acl();
        a.shunt4 = vec![("psw2_n1_white".into(), "direct".into()), ("psw2_n1_r1".into(), "redirect".into())];
        let mut g = Gen::default();
        gen_acl_rules(&ctx, &a, &mut g);
        let expect = "\
add rule inet passwall2 nat_output oif lo meta l4proto udp udp dport 53 counter redirect to :15353 comment \"PSW2_DNS\"
add rule inet passwall2 nat_output oif lo meta l4proto tcp tcp dport 53 counter redirect to :15353 comment \"PSW2_DNS\"
add rule inet passwall2 PSW2_OUTPUT_NAT ip protocol tcp ip daddr 198.18.0.0/16 counter redirect to :1041
add rule inet passwall2 PSW2_OUTPUT_NAT ip protocol tcp ip daddr @psw2_n1_white counter return
add rule inet passwall2 PSW2_OUTPUT_NAT ip protocol tcp ip daddr @psw2_n1_r1 counter redirect to :1041
add rule inet passwall2 PSW2_OUTPUT_NAT ip protocol tcp counter redirect to :1041
add rule inet passwall2 nat_output ip daddr != @psw2_direct ip protocol tcp counter jump PSW2_OUTPUT_NAT
add rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol udp ip daddr 198.18.0.0/16 counter jump PSW2_RULE
add rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol udp ip daddr @psw2_n1_white counter return
add rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol udp ip daddr @psw2_n1_r1 counter jump PSW2_RULE
add rule inet passwall2 PSW2_OUTPUT_MANGLE ip protocol udp counter jump PSW2_RULE
add rule inet passwall2 PSW2_MANGLE ip protocol udp iif lo counter meta mark 0x50535732 tproxy ip to :1041 comment \"Local\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp iif lo counter return comment \"Local\"
add rule inet passwall2 mangle_output ip daddr != @psw2_direct ip protocol udp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\"
add rule inet passwall2 mangle_output oif lo counter return comment \"PSW2_OUTPUT_MANGLE\"
add rule inet passwall2 mangle_output meta mark 0x50535732 counter return comment \"PSW2_OUTPUT_MANGLE\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp udp dport 53 counter accept
add rule inet passwall2 PSW2_MANGLE ip protocol tcp tcp dport 53 counter accept
add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto udp udp dport 53 counter accept
add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto tcp tcp dport 53 counter accept
add rule inet passwall2 PSW2_DNS meta l4proto udp udp dport 53 counter redirect to :15353 comment \"Default\"
add rule inet passwall2 PSW2_DNS meta l4proto tcp tcp dport 53 counter redirect to :15353 comment \"Default\"
add rule inet passwall2 PSW2_NAT ip protocol tcp ip daddr 198.18.0.0/16 counter redirect to :1041 comment \"Default\"
add rule inet passwall2 PSW2_NAT ip protocol tcp ip daddr @psw2_n1_white counter return comment \"Default\"
add rule inet passwall2 PSW2_NAT ip protocol tcp ip daddr @psw2_n1_r1 counter redirect to :1041 comment \"Default\"
add rule inet passwall2 PSW2_NAT ip protocol tcp counter redirect to :1041 comment \"Default\"
add rule inet passwall2 PSW2_NAT ip protocol tcp counter return comment \"Default\"
add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto tcp counter return comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp ip daddr 198.18.0.0/16 counter jump PSW2_RULE comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp ip daddr @psw2_n1_white counter return comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp ip daddr @psw2_n1_r1 counter jump PSW2_RULE comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp counter jump PSW2_RULE comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp counter meta mark 0x50535732 tproxy ip to :1041 comment \"Default\"
add rule inet passwall2 PSW2_MANGLE ip protocol udp counter return comment \"Default\"
add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto udp counter return comment \"Default\"
";
        assert_eq!(g.script(), expect);
    }

    #[test]
    fn t_acl_rule_tproxy_sources() {
        let ctx = RuleCtx { tproxy: true, proxy_ipv6: true, accept_icmp: true, accept_icmpv6: true, dns_redirect: true, ..Default::default() };
        let a = AclInput {
            var: args(&[
                ("flag", "acl_x"),
                ("remarks", "Kid \"pc\""),
                ("interface", "lan"),
                ("tcp_no_redir_ports", "25,1:100"),
                ("udp_no_redir_ports", "1:65535"),
                ("tcp_redir_ports", "80,443"),
                ("client_proxy", "1"),
                ("local_proxy", "0"),
                ("node", "n2"),
                ("use", "acl_x"),
                ("redir_port", "1051"),
            ]),
            sources: vec![AclSource::Ip("192.168.1.5".into()), AclSource::Mac("aa:bb:cc:dd:ee:ff".into()), AclSource::Ipset("myset".into())],
            device: Some("br-lan".into()),
            dns_redirect_port: None,
            shunt4: vec![],
            shunt6: vec![("psw2_n2_r6".into(), "redirect".into())],
        };
        let mut g = Gen::default();
        gen_acl_rules(&ctx, &a, &mut g);
        let s = g.script();
        let rem = "comment \"Kid 'pc'\"";
        // ip source: IPv4 only, no V6 rules for it
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_MANGLE iifname \"br-lan\" ip saddr {{192.168.1.5}} ip protocol tcp tcp dport {{25,1-100}} counter return {}\n", rem)));
        assert!(!s.contains("PSW2_MANGLE_V6 iifname \"br-lan\" ip saddr"));
        assert!(!s.contains("PSW2_MANGLE_V6 meta l4proto tcp iifname \"br-lan\" ip saddr"));
        // udp all not proxied → no udp proxy rules, but trailing return
        assert!(!s.contains("ip protocol udp iifname \"br-lan\" ip saddr {192.168.1.5} udp dport"));
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_MANGLE ip protocol udp iifname \"br-lan\" ip saddr {{192.168.1.5}} counter return {}\n", rem)));
        // no dns port → DNS return
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_DNS meta l4proto udp iifname \"br-lan\" ip saddr {{192.168.1.5}} udp dport 53 counter return {}\n", rem)));
        // tproxy tcp
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_MANGLE ip protocol tcp iifname \"br-lan\" ip saddr {{192.168.1.5}} tcp dport {{80,443}} counter jump PSW2_RULE {}\n", rem)));
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_MANGLE ip protocol tcp iifname \"br-lan\" ip saddr {{192.168.1.5}} counter meta mark 0x50535732 tproxy ip to :1051 {}\n", rem)));
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_ICMP_REDIRECT ip protocol icmp iifname \"br-lan\" ip saddr {{192.168.1.5}} return {}\n", rem)));
        // mac source gets the IPv6 rules
        assert!(s.contains(&format!(
            "add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto tcp iifname \"br-lan\" ether saddr {{aa:bb:cc:dd:ee:ff}} tcp dport {{80,443}} ip6 daddr @psw2_n2_r6 counter jump PSW2_RULE {}\n",
            rem
        )));
        assert!(s.contains(&format!(
            "add rule inet passwall2 PSW2_MANGLE_V6 meta l4proto tcp iifname \"br-lan\" ether saddr {{aa:bb:cc:dd:ee:ff}} counter meta mark 0x50535732 tproxy to :1051 {}\n",
            rem
        )));
        assert!(s.contains(&format!(
            "add rule inet passwall2 PSW2_ICMP_REDIRECT meta l4proto icmpv6 iifname \"br-lan\" ether saddr {{aa:bb:cc:dd:ee:ff}} ip6 daddr @psw2_n2_r6 counter redirect {}\n",
            rem
        )));
        // ipset source (destination match, upstream quirk)
        assert!(s.contains(&format!("add rule inet passwall2 PSW2_MANGLE ip protocol tcp iifname \"br-lan\" ip daddr @myset counter return {}\n", rem)));
        // no local-proxy rules for an ACL rule
        assert!(!s.contains("oif lo"));
    }

    #[test]
    fn t_acl_no_icmpv6_without_chain() {
        let ctx = RuleCtx { accept_icmp: false, accept_icmpv6: true, proxy_ipv6: true, ..Default::default() };
        let mut g = Gen::default();
        gen_acl_rules(&ctx, &default_acl(), &mut g);
        assert!(!g.script().contains("PSW2_ICMP_REDIRECT"));
    }

    #[test]
    fn t_local_tcp_all_excluded() {
        let ctx = RuleCtx::default();
        let mut a = default_acl();
        a.var.insert("tcp_no_redir_ports".into(), "1:65535".into());
        a.var.insert("client_proxy".into(), "0".into());
        let mut g = Gen::default();
        gen_acl_rules(&ctx, &a, &mut g);
        let s = g.script();
        assert!(s.starts_with(
            "add rule inet passwall2 PSW2_OUTPUT_NAT ip protocol tcp counter return\nadd rule inet passwall2 PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp counter return\n"
        ));
        assert!(!s.contains("PSW2_OUTPUT_NAT ip protocol tcp ip daddr"));
        assert!(s.contains("PSW2_OUTPUT_MANGLE ip protocol udp counter jump PSW2_RULE"));
    }

    #[test]
    fn t_comment_sanitize() {
        assert_eq!(cmt("a\"b\nc"), "comment \"a'b c\"");
        let long = "é".repeat(100);
        let c = cmt(&long);
        assert!(c.len() <= NFT_COMMENT_MAX + 10);
    }

    #[test]
    fn t_parse_listings() {
        let l = "table inet passwall2 {\n\tchain mangle_output { # handle 3\n\t\ttype route hook output priority mangle - 1; policy accept;\n\t\tmeta skgid 9912 counter packets 0 bytes 0 return comment \"PSW2_DIRECT\" # handle 40\n\t\toif \"lo\" counter packets 0 bytes 0 return # handle 41\n\t\tip daddr != @psw2_direct ip protocol udp counter packets 0 bytes 0 jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\" # handle 42\n\t}\n}\n";
        assert_eq!(parse_handles(l, "PSW2_"), vec![40, 42]);
        let t = "table inet passwall2 {\n\tset psw2_local {\n\t\ttype ipv4_addr\n\t}\n\tset psw2_n1_r1 {\n\t}\n\tchain dstnat {\n\t}\n\tchain PSW2_RULE {\n\t}\n\tchain PSW2_DNS {\n\t}\n}\n";
        assert_eq!(parse_block_names(t, "set"), vec!["psw2_local", "psw2_n1_r1"]);
        assert_eq!(parse_set_type(t).as_deref(), Some("ipv4_addr"));
        let cmds = gen_del_cmds(&[("mangle_output", l.to_string())], t);
        assert_eq!(
            cmds,
            vec![
                "delete rule inet passwall2 mangle_output handle 40",
                "delete rule inet passwall2 mangle_output handle 42",
                "flush chain inet passwall2 PSW2_RULE",
                "flush chain inet passwall2 PSW2_DNS",
                "delete chain inet passwall2 PSW2_DNS",
                "delete chain inet passwall2 PSW2_RULE",
                "flush set inet passwall2 psw2_local",
                "delete set inet passwall2 psw2_local",
            ]
        );
    }

    #[test]
    fn t_mwan3_patch() {
        let orig = "#!/bin/sh /etc/rc.common\n\nstart_service() {\n\tmwan3_init\n\tprocd_open_instance\n}\n\nstop_service() {\n\tkillall mwan3track\n}\n";
        let p = mwan3_patch(orig);
        assert_eq!(
            p,
            "#!/bin/sh /etc/rc.common\n\nstart_service() {\n\tmwan3_init\n\tprocd_open_instance\n    /usr/bin/passwall2 nft mwan3_start\n}\n\nstop_service() {\n    /usr/bin/passwall2 nft mwan3_stop\n\tkillall mwan3track\n}\n"
        );
        assert_eq!(mwan3_unpatch(&p), orig);
        // inner indented `}` ends the sed range without insertion (upstream behaviour)
        let o2 = "start_service() {\n\t[ x ] && {\n\t}\n}\n";
        assert_eq!(mwan3_patch(o2), o2);
    }

    #[test]
    fn t_include() {
        assert_eq!(
            include_text(RULE_DUMP_FILE),
            "#!/bin/sh\n[ -z \"$(nft list chain inet passwall2 mangle_prerouting | grep PSW2)\" ] && nft -f /tmp/etc/passwall2/PSW2_RULE.nft\n\n/usr/bin/passwall2 nft update_wan_sets\n\nreturn 0\n"
        );
    }

    #[test]
    fn t_dns_env() {
        let r = "# Interface wan\nnameserver 192.168.0.1\nnameserver 0.0.0.0\nnameserver 192.168.0.1\nnameserver 8.8.8.8\nnameserver fe80::1%eth0\nnameserver ::1\nnameserver 2001:4860::8888\n";
        let (v4, v6) = parse_isp_dns(r);
        assert_eq!(v4, vec!["192.168.0.1", "8.8.8.8"]);
        assert_eq!(v6, vec!["fe80::1", "2001:4860::8888"]);
        assert_eq!(auto_dns(&["/lan/1.1.1.1".into(), "9.9.9.9".into(), "1.0.0.1#5353".into(), "4.4.4.4".into()], &v4), "9.9.9.9#53,1.0.0.1#5353");
        assert_eq!(auto_dns(&[], &v4), "192.168.0.1,8.8.8.8");
        assert_eq!(auto_dns(&[], &[]), "119.29.29.29");
    }

    #[test]
    fn t_direct_ip_and_vps() {
        let e = parse_direct_ip("# c\n0.0.0.0/8\n\n::/127\ngeoip:cn\r\nfc00::/7\n");
        let kinds: Vec<String> = e
            .iter()
            .map(|x| match x {
                DirectEntry::V4(s) => format!("4{}", s),
                DirectEntry::V6(s) => format!("6{}", s),
                DirectEntry::Geoip(s) => format!("g{}", s),
            })
            .collect();
        assert_eq!(kinds, vec!["40.0.0.0/8", "6::/127", "gcn", "6fc00::/7"]);
        let cfg = Config::parse(
            "passwall2",
            "config nodes 'a'\n\toption address '1.2.3.4'\n\toption download_address '2001:db8::1'\nconfig nodes 'b'\n\toption address '127.0.0.1'\nconfig nodes 'c'\n\toption address 'example.com'\n",
        );
        let (v4, v6) = vps_addrs(&cfg);
        assert_eq!(v4, vec!["1.2.3.4"]);
        assert_eq!(v6, vec!["2001:db8::1"]);
        assert_eq!(shunt_geoip_codes(&["geoip:cn".into(), "geoip:private".into(), "1.1.1.1".into(), "geoip:us # x".into()]), "cn,us");
    }
}
