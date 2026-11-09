//! Port of `root/usr/share/passwall2/app_acl.lua` (spec 05 §7, 02 §0.4/§0.5): computes the
//! access-control list (enabled `acl_rule` sections, then the default ACL) and the per-ACL
//! node run arguments, writes the ACL state files under `/tmp/etc/passwall2/acl/` and
//! provides readers for the firewall backends and the runtime (`app`).
//!
//! Files written (append mode, like upstream):
//! * `acl/<flag>/var`          `key="value"` lines (eval'ed by the firewall code)
//! * `acl/<flag>/source_list`  `any` | `iprange:a-b` | `ipset:ipset:<name>` | `ip:<ip>` | `mac:<mac>`
//! * `acl/acl_node_<flag>`     one line of `key="value"` pairs → `run_xray` / `run_singbox` args
//! * cache var `ENABLED_ACLS` = 1/0
//!
//! Additionally (not upstream) the computed JSON is saved as `acl/acl.json` so a later
//! process (firewall reload, rpc) can get the ACL order without recomputing ports.

use crate::api;
use crate::uci::{Config, Section};
use crate::util::{self, Args};
use indexmap::IndexMap;
use serde_json::{json, Value};

/// One ACL (an enabled `acl_rule`, or the default ACL `acl_default`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AclEntry {
    pub flag: String,
    pub remarks: Option<String>,
    pub interface: Option<String>,
    /// `sources` UCI list (None when unset)
    pub sources: Option<Vec<String>>,
    pub tcp_no_redir_ports: Option<String>,
    pub udp_no_redir_ports: Option<String>,
    pub tcp_redir_ports: Option<String>,
    pub udp_redir_ports: Option<String>,
    pub client_proxy: Option<String>,
    pub local_proxy: Option<String>,
    /// configured node id (removed when both no_redir lists are `1:65535`)
    pub node: Option<String>,
    /// key into [`AclState::node`] of the node instance this ACL redirects to
    pub use_: Option<String>,
}

impl AclEntry {
    /// String fields in the order they are written to `var` (Lua writes every string field).
    pub fn string_fields(&self) -> Vec<(&'static str, &str)> {
        let mut v: Vec<(&'static str, &str)> = vec![("flag", self.flag.as_str())];
        let opt = [
            ("remarks", &self.remarks),
            ("interface", &self.interface),
            ("tcp_no_redir_ports", &self.tcp_no_redir_ports),
            ("udp_no_redir_ports", &self.udp_no_redir_ports),
            ("tcp_redir_ports", &self.tcp_redir_ports),
            ("udp_redir_ports", &self.udp_redir_ports),
            ("client_proxy", &self.client_proxy),
            ("local_proxy", &self.local_proxy),
            ("node", &self.node),
            ("use", &self.use_),
        ];
        for (k, val) in opt {
            if let Some(s) = val {
                v.push((k, s.as_str()));
            }
        }
        v
    }
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (k, v) in self.string_fields() {
            m.insert(k.into(), v.into());
        }
        if let Some(s) = &self.sources {
            m.insert("sources".into(), json!(s));
        }
        Value::Object(m)
    }
}

/// A core instance to start for an ACL (`L.node[flag]`).
#[derive(Debug, Clone)]
pub struct AclNode {
    /// full node section
    pub config: Section,
    pub enabled: String,
    pub log: String,
    pub loglevel: String,
    pub socks_listen: Option<String>,
    pub socks_port: Option<String>,
    pub redir_port: u16,
    pub dns_port: u16,
    pub direct_dns_query_strategy: Option<String>,
    pub remote_dns_protocol: Option<String>,
    pub remote_dns_detour: Option<String>,
    pub remote_dns: Option<String>,
    pub remote_dns_doh: Option<String>,
    pub remote_dns_client_ip: Option<String>,
    pub remote_dns_query_strategy: Option<String>,
    pub remote_rewrite_ttl: Option<String>,
    pub remote_fakedns: Option<String>,
}

impl AclNode {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("config".into(), self.config.to_json());
        m.insert("enabled".into(), self.enabled.clone().into());
        m.insert("log".into(), self.log.clone().into());
        m.insert("loglevel".into(), self.loglevel.clone().into());
        let opt = [
            ("socks_listen", &self.socks_listen),
            ("socks_port", &self.socks_port),
            ("direct_dns_query_strategy", &self.direct_dns_query_strategy),
            ("remote_dns_protocol", &self.remote_dns_protocol),
            ("remote_dns_detour", &self.remote_dns_detour),
            ("remote_dns", &self.remote_dns),
            ("remote_dns_doh", &self.remote_dns_doh),
            ("remote_dns_client_ip", &self.remote_dns_client_ip),
            ("remote_dns_query_strategy", &self.remote_dns_query_strategy),
            ("remote_rewrite_ttl", &self.remote_rewrite_ttl),
            ("remote_fakedns", &self.remote_fakedns),
        ];
        for (k, v) in opt {
            if let Some(s) = v {
                m.insert(k.into(), s.clone().into());
            }
        }
        m.insert("redir_port".into(), self.redir_port.into());
        m.insert("dns_port".into(), self.dns_port.into());
        Value::Object(m)
    }

    /// Run arguments for `run_xray` / `run_singbox` (the `acl_node_<flag>` line), in upstream
    /// order; only present values.
    pub fn run_args(&self, flag: &str, acl_path: &str) -> Vec<(String, String)> {
        let config_path = format!("{}/{}", acl_path, flag);
        let config_file = format!("{}.json", config_path);
        let log_file = if self.log == "0" { "/dev/null".to_string() } else { format!("{}.log", config_path) };
        let dns = self.remote_dns.as_deref().map(api::parse_dns);
        let (dns_server, dns_port) = match &dns {
            Some((s, p)) => (Some(s.clone()), Some(p.clone())),
            None => (None, None),
        };
        let mut out: Vec<(String, String)> = vec![];
        let mut add = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                out.push((k.to_string(), v));
            }
        };
        add("flag", Some(flag.to_string()));
        add("node", Some(self.config.name.clone()));
        add("redir_port", Some(self.redir_port.to_string()));
        add("socks_address", self.socks_listen.clone());
        add("socks_port", self.socks_port.clone());
        add("dns_listen_port", Some(self.dns_port.to_string()));
        add("direct_dns_query_strategy", self.direct_dns_query_strategy.clone());
        add("remote_dns_protocol", self.remote_dns_protocol.clone());
        add("remote_dns_tcp_server", dns_server.clone());
        add("remote_dns_tcp_port", dns_port.clone());
        add("remote_dns_udp_server", dns_server);
        add("remote_dns_udp_port", dns_port);
        add("remote_dns_doh", self.remote_dns_doh.clone());
        add("remote_dns_client_ip", self.remote_dns_client_ip.clone());
        add("remote_dns_detour", self.remote_dns_detour.clone());
        add("remote_dns_query_strategy", self.remote_dns_query_strategy.clone());
        add("remote_fakedns", self.remote_fakedns.clone());
        add("remote_rewrite_ttl", self.remote_rewrite_ttl.clone());
        add("config_file", Some(config_file));
        add("loglevel", Some(self.loglevel.clone()));
        add("log_file", Some(log_file));
        out
    }
}

/// Result of [`init_acl`] (upstream table `L` + `VAR`).
#[derive(Debug, Clone, Default)]
pub struct AclState {
    /// enabled rules in UCI order, then the default ACL last
    pub acl: Vec<AclEntry>,
    pub node: IndexMap<String, AclNode>,
    /// flags of node instances to start (enabled ones), in order
    pub node_order: Vec<String>,
    /// `VAR.ENABLED_ACLS` (at least one enabled acl_rule while `acl_enable=1`)
    pub enabled_acls: bool,
}

impl AclState {
    /// JSON printed by `app_acl.lua` (`{acl:[...], node:{...}, node_order:[...]}`).
    pub fn to_json(&self) -> Value {
        let mut nodes = serde_json::Map::new();
        for (k, v) in &self.node {
            nodes.insert(k.clone(), v.to_json());
        }
        json!({
            "acl": self.acl.iter().map(|a| a.to_json()).collect::<Vec<_>>(),
            "node": Value::Object(nodes),
            "node_order": self.node_order,
        })
    }
    /// `$.acl[*].flag`
    pub fn flags(&self) -> Vec<String> {
        self.acl.iter().map(|a| a.flag.clone()).collect()
    }
}

/// `init_acl()`: build the ACL state from the passwall2 config. `new_port` allocates a free
/// port (upstream `api.get_new_port()`; injectable for tests).
pub fn init_acl(cfg: &Config, new_port: &mut dyn FnMut() -> u16) -> AclState {
    let mut st = AclState::default();
    let g = |o: &str| cfg.get("@global[0]", o);
    let gf = |o: &str| cfg.get("@global_forwarding[0]", o);
    let mut d = AclEntry {
        flag: "acl_default".into(),
        remarks: Some(api::translatef("Default", &[])),
        tcp_no_redir_ports: gf("tcp_no_redir_ports"),
        udp_no_redir_ports: gf("udp_no_redir_ports"),
        tcp_redir_ports: gf("tcp_redir_ports"),
        udp_redir_ports: gf("udp_redir_ports"),
        node: g("node"),
        local_proxy: g("localhost_proxy"),
        client_proxy: g("client_proxy"),
        ..Default::default()
    };
    if let Some(node) = d.node.as_deref().and_then(|id| cfg.section(id)).filter(|s| s.stype == "nodes") {
        let redir_port = new_port();
        let dns_port = new_port();
        let n = AclNode {
            config: node.clone(),
            enabled: g("enabled").unwrap_or_else(|| "0".into()),
            log: g("log_node").unwrap_or_else(|| "0".into()),
            loglevel: g("loglevel").unwrap_or_else(|| "warn".into()),
            socks_listen: Some(if g("node_socks_bind_local").as_deref() == Some("0") { "0.0.0.0" } else { "127.0.0.1" }.into()),
            socks_port: g("node_socks_port"),
            redir_port,
            dns_port,
            direct_dns_query_strategy: Some(g("direct_dns_query_strategy").unwrap_or_else(|| "UseIP".into())),
            remote_dns_protocol: Some(g("remote_dns_protocol").unwrap_or_else(|| "tcp".into())),
            remote_dns_detour: Some(g("remote_dns_detour").unwrap_or_else(|| "remote".into())),
            remote_dns: Some(g("remote_dns").unwrap_or_else(|| "1.1.1.1:53".into())),
            remote_dns_doh: Some(g("remote_dns_doh").unwrap_or_else(|| "https://1.1.1.1/dns-query".into())),
            remote_dns_client_ip: g("remote_dns_client_ip"),
            remote_dns_query_strategy: Some(g("remote_dns_query_strategy").unwrap_or_else(|| "UseIPv4".into())),
            remote_rewrite_ttl: g("remote_rewrite_ttl"),
            remote_fakedns: Some(g("remote_fakedns").unwrap_or_else(|| "0".into())),
        };
        let enabled = n.enabled == "1";
        st.node.insert(d.flag.clone(), n);
        d.use_ = Some(d.flag.clone());
        if enabled {
            st.node_order.push(d.flag.clone());
        }
    }
    let mut acl_num = 0;
    if g("acl_enable").as_deref() == Some("1") {
        for o in cfg.sections_of("acl_rule") {
            if o.get("enabled").as_deref() != Some("1") {
                continue;
            }
            acl_num += 1;
            let mut a = AclEntry {
                flag: o.name.clone(),
                remarks: o.get("remarks"),
                interface: o.get("interface"),
                sources: if o.has("sources") { Some(o.list_raw("sources")) } else { None },
                tcp_no_redir_ports: o.get("tcp_no_redir_ports"),
                udp_no_redir_ports: o.get("udp_no_redir_ports"),
                tcp_redir_ports: o.get("tcp_redir_ports"),
                udp_redir_ports: o.get("udp_redir_ports"),
                client_proxy: Some("1".into()),
                local_proxy: Some("0".into()),
                node: o.get("node"),
                use_: None,
            };
            match o.get("mode").as_deref() {
                Some("0") => {
                    a.tcp_no_redir_ports = Some("1:65535".into());
                    a.udp_no_redir_ports = Some("1:65535".into());
                }
                Some("2") => {
                    // upstream quirk: upstream crashes here when the default node is invalid
                    // (L.node[nil]); we just leave this ACL without the default node.
                    match d.use_.clone().and_then(|u| st.node.get_mut(&u).map(|n| (u, n))) {
                        Some((u, n)) => {
                            if n.enabled == "0" {
                                n.enabled = "1".into();
                                d.local_proxy = Some("0".into());
                                d.client_proxy = Some("0".into());
                            }
                            a.use_ = Some(u);
                        }
                        None => util::log(1, &format!("ACL {}: default node is not available, mode 2 ignored", o.name)),
                    }
                }
                _ => {}
            }
            if a.tcp_no_redir_ports.as_deref() == Some("1:65535") && a.udp_no_redir_ports.as_deref() == Some("1:65535") {
                a.node = None;
            }
            if let Some(node) = a.node.as_deref().and_then(|id| cfg.section(id)).filter(|s| s.stype == "nodes") {
                let redir_port = new_port();
                let dns_port = new_port();
                let n = AclNode {
                    config: node.clone(),
                    enabled: "1".into(),
                    log: o.get("log").unwrap_or_else(|| "0".into()),
                    loglevel: o.get("loglevel").unwrap_or_else(|| "warn".into()),
                    socks_listen: None,
                    socks_port: None,
                    redir_port,
                    dns_port,
                    direct_dns_query_strategy: o.get("direct_dns_query_strategy"),
                    remote_dns_protocol: o.get("remote_dns_protocol"),
                    remote_dns_detour: o.get("remote_dns_detour"),
                    remote_dns: o.get("remote_dns"),
                    remote_dns_doh: o.get("remote_dns_doh"),
                    remote_dns_client_ip: o.get("remote_dns_client_ip"),
                    remote_dns_query_strategy: o.get("remote_dns_query_strategy"),
                    remote_rewrite_ttl: o.get("remote_rewrite_ttl"),
                    remote_fakedns: o.get("remote_fakedns"),
                };
                st.node.insert(a.flag.clone(), n);
                a.use_ = Some(a.flag.clone());
                st.node_order.push(a.flag.clone());
            }
            st.acl.push(a);
        }
    }
    st.acl.push(d);
    st.enabled_acls = acl_num > 0;
    st
}

/// Convert the `sources` list to `source_list` tokens (upstream quirk kept: `ipset:x` →
/// `ipset:ipset:x`; IPv6 / invalid entries dropped; nothing → `any`).
pub fn source_list_tokens(sources: Option<&[String]>) -> Vec<String> {
    let mut s1 = vec![];
    for w in sources.unwrap_or(&[]) {
        if api::iprange(w) {
            s1.push(format!("iprange:{}", w));
        } else if w.starts_with("ipset:") {
            s1.push(format!("ipset:{}", w));
        } else {
            match api::ip_or_mac(w) {
                "ip" => s1.push(format!("ip:{}", w)),
                "mac" => s1.push(format!("mac:{}", w)),
                _ => {}
            }
        }
    }
    if s1.is_empty() {
        s1.push("any".into());
    }
    s1
}

fn append(path: &str, data: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(data.as_bytes());
    }
}

/// `acl_app(L)`: write the per-ACL `var`/`source_list` files and `acl_node_<flag>` run-arg
/// lines under `acl_path` (normally `/tmp/etc/passwall2/acl`).
pub fn acl_app(st: &AclState, acl_path: &str) {
    for v in &st.acl {
        let dir = format!("{}/{}", acl_path, v.flag);
        util::mkdir(&dir);
        let mut var = String::new();
        for (k, val) in v.string_fields() {
            var.push_str(&format!("{}=\"{}\"\n", k, val));
        }
        if let Some(n) = v.use_.as_ref().and_then(|u| st.node.get(u)) {
            var.push_str(&format!("node=\"{}\"\n", n.config.name));
            var.push_str(&format!("node_remarks=\"{}\"\n", n.config.s("remarks")));
            var.push_str(&format!("redir_port=\"{}\"\n", n.redir_port));
        }
        append(&format!("{}/var", dir), &var);
        append(&format!("{}/source_list", dir), &source_list_tokens(v.sources.as_deref()).join("\n"));
    }
    for flag in &st.node_order {
        let Some(n) = st.node.get(flag) else { continue };
        if n.enabled != "1" {
            continue;
        }
        let line = format_run_args(&n.run_args(flag, acl_path));
        append(&format!("{}/acl_node_{}", acl_path, flag), &line);
    }
}

/// Join run args as upstream: `k="v" k2="v2"`.
pub fn format_run_args(args: &[(String, String)]) -> String {
    args.iter().map(|(k, v)| format!("{}=\"{}\"", k, v)).collect::<Vec<_>>().join(" ")
}

/// Full `lua app_acl.lua` equivalent: load config, compute (allocating ports), write the
/// files under `TMP_ACL_PATH`, set cache var `ENABLED_ACLS`, save `acl/acl.json`.
pub fn run() -> AclState {
    let cfg = Config::load(util::CONFIG);
    let mut alloc = || api::get_new_port(None, "");
    let st = init_acl(&cfg, &mut alloc);
    util::mkdir(util::TMP_ACL_PATH);
    acl_app(&st, util::TMP_ACL_PATH);
    api::set_cache_var("ENABLED_ACLS", if st.enabled_acls { "1" } else { "0" });
    let _ = std::fs::write(format!("{}/acl.json", util::TMP_ACL_PATH), st.to_json().to_string());
    st
}

/// Saved ACL JSON (`acl/acl.json` written by [`run`]), if any.
pub fn load_saved() -> Option<Value> {
    serde_json::from_str(&util::read(&format!("{}/acl.json", util::TMP_ACL_PATH))).ok()
}
/// `$.acl[*].flag` from the saved ACL JSON (empty when passwall2 is not running).
pub fn saved_flags() -> Vec<String> {
    load_saved()
        .and_then(|v| v["acl"].as_array().map(|a| a.iter().filter_map(|x| x["flag"].as_str().map(|s| s.to_string())).collect()))
        .unwrap_or_default()
}
/// `$.node_order[*]` from the saved ACL JSON.
pub fn saved_node_order() -> Vec<String> {
    load_saved()
        .and_then(|v| v["node_order"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()))
        .unwrap_or_default()
}

/// Parse shell assignments `k="v"` / `k=v` separated by newlines or spaces (what `eval`
/// of the `var` / `acl_node_*` files yields). Later keys override earlier ones.
pub fn parse_assignments(text: &str) -> Args {
    let mut a = Args::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            continue;
        }
        let key = text[ks..i].to_string();
        i += 1;
        let mut val = Vec::new();
        while i < b.len() && !b[i].is_ascii_whitespace() {
            match b[i] {
                b'"' => {
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        if b[i] == b'\\' && i + 1 < b.len() && matches!(b[i + 1], b'"' | b'\\' | b'$' | b'`') {
                            i += 1;
                        }
                        val.push(b[i]);
                        i += 1;
                    }
                    i += 1;
                }
                b'\'' => {
                    i += 1;
                    while i < b.len() && b[i] != b'\'' {
                        val.push(b[i]);
                        i += 1;
                    }
                    i += 1;
                }
                c => {
                    val.push(c);
                    i += 1;
                }
            }
        }
        if !key.is_empty() {
            a.insert(key, String::from_utf8_lossy(&val).to_string());
        }
    }
    a
}

/// Read `acl/<sid>/var` as key → value (eval semantics: last assignment wins).
pub fn read_acl_var(sid: &str) -> Args {
    parse_assignments(&util::read(&format!("{}/{}/var", util::TMP_ACL_PATH, sid)))
}
/// Read `acl/acl_node_<flag>` run args (None when the file is missing).
pub fn read_acl_node_args(flag: &str) -> Option<Args> {
    let p = format!("{}/acl_node_{}", util::TMP_ACL_PATH, flag);
    if !util::exists(&p) {
        return None;
    }
    Some(parse_assignments(&util::read(&p)))
}

/// One entry of `source_list`.
#[derive(Debug, Clone, PartialEq)]
pub enum AclSource {
    Any,
    IpRange(String),
    /// ipset / nft set name (the doubled `ipset:ipset:` prefix stripped, like the shell's
    /// `sed 's#ipset:##g'`)
    Ipset(String),
    Ip(String),
    Mac(String),
}

/// Parse `source_list` text.
pub fn parse_source_list(text: &str) -> Vec<AclSource> {
    let mut v = vec![];
    for t in text.split_whitespace() {
        if t == "any" {
            v.push(AclSource::Any);
        } else if let Some(r) = t.strip_prefix("iprange:") {
            v.push(AclSource::IpRange(r.to_string()));
        } else if t.starts_with("ipset:") {
            v.push(AclSource::Ipset(t.replace("ipset:", "")));
        } else if let Some(r) = t.strip_prefix("ip:") {
            v.push(AclSource::Ip(r.to_string()));
        } else if let Some(r) = t.strip_prefix("mac:") {
            v.push(AclSource::Mac(r.to_string()));
        }
    }
    v
}
/// Read and parse `acl/<sid>/source_list`.
pub fn read_source_list(sid: &str) -> Vec<AclSource> {
    parse_source_list(&util::read(&format!("{}/{}/source_list", util::TMP_ACL_PATH, sid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "config global\n\toption enabled '1'\n\toption node 'n1'\n\toption localhost_proxy '1'\n\toption client_proxy '1'\n\toption acl_enable '1'\n\toption remote_dns '8.8.8.8:5353'\n\
config global_forwarding\n\toption tcp_redir_ports '1:65535'\n\toption udp_redir_ports '1:65535'\n\
config nodes 'n1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption remarks 'Node 1'\n\
config nodes 'n2'\n\toption type 'Xray'\n\toption remarks 'Node 2'\n\
config acl_rule 'r1'\n\toption enabled '1'\n\toption remarks 'LAN A'\n\tlist sources '192.168.1.10'\n\tlist sources 'ipset:myset'\n\tlist sources '192.168.1.2-192.168.1.5'\n\tlist sources 'aa:bb:cc:dd:ee:ff'\n\tlist sources 'fe80::1'\n\toption node 'n2'\n\toption remote_dns '[::1]:53'\n\
config acl_rule 'r2'\n\toption enabled '1'\n\toption mode '0'\n\toption node 'n2'\n\
config acl_rule 'r3'\n\toption enabled '0'\n\
config acl_rule 'r4'\n\toption enabled '1'\n\toption mode '2'\n";

    fn state(cfg: &str) -> AclState {
        let c = Config::parse("passwall2", cfg);
        let mut p = 1000u16;
        let mut alloc = || {
            p += 1;
            p
        };
        init_acl(&c, &mut alloc)
    }

    #[test]
    fn t_init() {
        let st = state(CFG);
        assert_eq!(st.flags(), vec!["r1", "r2", "r4", "acl_default"]);
        assert_eq!(st.node_order, vec!["acl_default", "r1"]);
        assert!(st.enabled_acls);
        let r1 = &st.acl[0];
        assert_eq!(r1.use_.as_deref(), Some("r1"));
        assert_eq!(r1.client_proxy.as_deref(), Some("1"));
        let r2 = &st.acl[1];
        assert_eq!(r2.node, None);
        assert_eq!(r2.use_, None);
        assert_eq!(r2.tcp_no_redir_ports.as_deref(), Some("1:65535"));
        let r4 = &st.acl[2];
        assert_eq!(r4.use_.as_deref(), Some("acl_default"));
        let d = &st.acl[3];
        assert_eq!(d.use_.as_deref(), Some("acl_default"));
        // default node was enabled, so mode 2 did not touch the default scope
        assert_eq!(d.local_proxy.as_deref(), Some("1"));
        assert_eq!(st.node["acl_default"].redir_port, 1001);
        assert_eq!(st.node["r1"].redir_port, 1003);
        let j = st.to_json();
        assert_eq!(j["node"]["acl_default"]["redir_port"], 1001);
        assert_eq!(j["node"]["acl_default"]["config"][".name"], "n1");
        assert_eq!(j["acl"][0]["sources"][1], "ipset:myset");
    }

    #[test]
    fn t_mode2_disabled_default() {
        let st = state(&CFG.replace("option enabled '1'\n\toption node 'n1'", "option enabled '0'\n\toption node 'n1'"));
        assert_eq!(st.node["acl_default"].enabled, "1");
        let d = st.acl.last().unwrap();
        assert_eq!(d.local_proxy.as_deref(), Some("0"));
        assert_eq!(d.client_proxy.as_deref(), Some("0"));
        // upstream quirk preserved: enabled late, not in node_order
        assert_eq!(st.node_order, vec!["r1"]);
    }

    #[test]
    fn t_mode2_invalid_default() {
        let st = state(&CFG.replace("option node 'n1'", "option node 'missing'"));
        assert_eq!(st.acl.last().unwrap().use_, None);
        assert_eq!(st.acl[2].use_, None);
    }

    #[test]
    fn t_sources() {
        let st = state(CFG);
        let toks = source_list_tokens(st.acl[0].sources.as_deref());
        assert_eq!(toks, vec!["ip:192.168.1.10", "ipset:ipset:myset", "iprange:192.168.1.2-192.168.1.5", "mac:aa:bb:cc:dd:ee:ff"]);
        assert_eq!(source_list_tokens(None), vec!["any"]);
        let parsed = parse_source_list(&toks.join("\n"));
        assert_eq!(parsed[1], AclSource::Ipset("myset".into()));
        assert_eq!(parsed[2], AclSource::IpRange("192.168.1.2-192.168.1.5".into()));
    }

    #[test]
    fn t_run_args() {
        let st = state(CFG);
        let a = st.node["acl_default"].run_args("acl_default", "/tmp/etc/passwall2/acl");
        let line = format_run_args(&a);
        assert!(line.starts_with("flag=\"acl_default\" node=\"n1\" redir_port=\"1001\" socks_address=\"127.0.0.1\" dns_listen_port=\"1002\""));
        assert!(line.contains("remote_dns_tcp_server=\"8.8.8.8\" remote_dns_tcp_port=\"5353\" remote_dns_udp_server=\"8.8.8.8\" remote_dns_udp_port=\"5353\""));
        assert!(line.ends_with("config_file=\"/tmp/etc/passwall2/acl/acl_default.json\" loglevel=\"warn\" log_file=\"/dev/null\""));
        let r = parse_assignments(&line);
        assert_eq!(r.get("remote_dns_doh").map(|s| s.as_str()), Some("https://1.1.1.1/dns-query"));
        let a1 = st.node["r1"].run_args("r1", "/x");
        let m: Args = a1.into_iter().collect();
        assert_eq!(m.get("remote_dns_tcp_server").map(|s| s.as_str()), Some("::1"));
        assert!(!m.contains_key("socks_port"));
        assert!(!m.contains_key("remote_dns_doh"));
    }

    #[test]
    fn t_files() {
        let st = state(CFG);
        let dir = std::env::temp_dir().join(format!("pw2acl{}", std::process::id()));
        let d = dir.to_string_lossy().to_string();
        acl_app(&st, &d);
        let var = parse_assignments(&std::fs::read_to_string(format!("{}/r1/var", d)).unwrap());
        assert_eq!(var.get("remarks").map(|s| s.as_str()), Some("LAN A"));
        assert_eq!(var.get("node_remarks").map(|s| s.as_str()), Some("Node 2"));
        assert_eq!(var.get("redir_port").map(|s| s.as_str()), Some("1003"));
        let r2 = parse_assignments(&std::fs::read_to_string(format!("{}/r2/var", d)).unwrap());
        assert!(!r2.contains_key("node"));
        assert_eq!(std::fs::read_to_string(format!("{}/r2/source_list", d)).unwrap(), "any");
        assert!(std::path::Path::new(&format!("{}/acl_node_acl_default", d)).exists());
        assert!(!std::path::Path::new(&format!("{}/acl_node_r4", d)).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t_parse_assignments() {
        let a = parse_assignments("a=\"x y\"\nb=2 c='q'\na=\"z\"\n");
        assert_eq!(a.get("a").map(|s| s.as_str()), Some("z"));
        assert_eq!(a.get("b").map(|s| s.as_str()), Some("2"));
        assert_eq!(a.get("c").map(|s| s.as_str()), Some("q"));
    }
}
