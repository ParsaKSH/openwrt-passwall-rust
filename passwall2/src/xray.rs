//! Xray config generator — complete port of upstream `luasrc/passwall2/util_xray.lua`.
//! Spec: docs/spec/03-xray-config.md
//!
//! * [`gen_config`]       client config (transparent proxy / socks / http / DNS / shunt / balancers)
//! * [`gen_proto_config`] tiny socks/http relay (old `servers` outbound schema)
//! * [`gen_config_server`] server config for a `passwall2_server` `server` section
//! * [`cli`]              `passwall2 xray <gen_config|gen_proto_config|gen_config_server> '<json>'`
//!
//! The Lua module keeps its state in module/upvalue globals (`NO_RUN`, `TMP_PORT`, `fragment_table`,
//! `noise_table`, `GLOBAL.DNS_SERVER`, `outbounds`, `balancers`, `rules`, ...). Here they live in the
//! private [`Gen`] context. Outbounds are `Rc<RefCell<Value>>` because upstream mutates outbound tables
//! by reference after they were inserted (loopbacks, the `dns-out` outbound, detour tags).
//!
//! Nodes are UCI sections as JSON objects (`Section::to_json`: `.name`, `.type`, options as strings,
//! lists as arrays), exactly like the tables `api.uci_get_c` returns in Lua.

use crate::api;
use crate::uci::{self, Config, Section};
use crate::util::{self, Args};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::process::{Command, Stdio};
use std::rc::Rc;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod server_raw_tests {
    use super::*;
    fn raw_of(extra: &str) -> Value {
        let cfg_s = Config::parse(
            "passwall2_server",
            &format!("config server 's1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption port '443'\n\toption uuid 'x'\n\toption transport 'raw'\n{}", extra),
        );
        let cfg_c = Config::parse("passwall2", "");
        let node = node_of(cfg_s.section("s1").unwrap());
        let c = server_config(&cfg_c, &cfg_s, node, false);
        c["inbounds"][0]["streamSettings"].get("rawSettings").cloned().unwrap_or(Value::Null)
    }
    #[test]
    fn server_raw_header_omitted_without_guise() {
        // no tcp_guise: no header object at all (an empty `header` is rejected by Xray)
        assert_eq!(raw_of(""), Value::Null);
        assert_eq!(raw_of("\toption tcp_guise ''\n"), Value::Null);
        assert_eq!(raw_of("\toption tcp_guise 'none'\n"), json!({"header": {"type": "none"}}));
        let h = raw_of("\toption tcp_guise 'http'\n\tlist tcp_guise_http_host 'h.com'\n");
        assert_eq!(h["header"]["type"], "http");
        assert_eq!(h["header"]["request"]["path"], json!(["/"]));
    }
}

/// `xray_min_version`
pub const XRAY_MIN_VERSION: &str = "26.7.11";
const DOMAINS_EXCLUDED: &str = "/usr/share/passwall2/domains_excluded";

const DIRECT_DNS_TAG: &str = "dns-in-direct";
const REMOTE_DNS_TAG: &str = "dns-in-remote";
const REMOTE_FAKEDNS_TAG: &str = "dns-in-remote-fakedns";
const DEFAULT_DNS_TAG: &str = "dns-in-default";

/// A node table (UCI section as JSON object, or a synthesized table).
pub type Node = Map<String, Value>;
type Obj = Rc<RefCell<Value>>;

// ====================================================================== small Lua-ish helpers

/// Lua field read as a string (`node.x`). Lists are space-joined (like `uci get`), `false`/null → None.
fn ns(n: &Node, k: &str) -> Option<String> {
    match n.get(k)? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => Some(a.iter().map(val_to_string).collect::<Vec<_>>().join(" ")),
        Value::Number(x) => Some(x.to_string()),
        Value::Bool(true) => Some("true".into()),
        _ => None,
    }
}
fn val_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
/// Non-empty string field.
fn nne(n: &Node, k: &str) -> Option<String> {
    ns(n, k).filter(|s| !s.is_empty())
}
/// `node.x == v`
fn neq(n: &Node, k: &str, v: &str) -> bool {
    ns(n, k).as_deref() == Some(v)
}
/// Lua truthiness of a field (present and not false/nil).
fn has(n: &Node, k: &str) -> bool {
    !matches!(n.get(k), None | Some(Value::Null) | Some(Value::Bool(false)))
}
/// List field (`ipairs(node.x)`); a single option becomes a one-element list.
fn nl(n: &Node, k: &str) -> Option<Vec<String>> {
    match n.get(k)? {
        Value::Array(a) => Some(a.iter().map(val_to_string).collect()),
        Value::String(s) => Some(vec![s.clone()]),
        Value::Number(x) => Some(vec![x.to_string()]),
        _ => None,
    }
}
/// The stored value as-is (string or list), for options Lua passes straight into the JSON.
fn raw(n: &Node, k: &str) -> Option<Value> {
    n.get(k).filter(|v| !v.is_null() && !matches!(v, Value::Bool(false))).cloned()
}
fn set(n: &mut Node, k: &str, v: impl Into<Value>) {
    n.insert(k.to_string(), v.into());
}

/// String field of a JSON value.
fn vstr<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}
/// Present (non-null) field of a JSON value.
fn vget<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| !x.is_null())
}

/// Lua `tonumber(s)`.
fn tonum<S: AsRef<str>>(s: Option<S>) -> Option<f64> {
    s.and_then(|x| api::lua_tonumber(x.as_ref())).filter(|f| f.is_finite())
}
/// A Lua number as JSON (integral numbers are emitted as integers, like luci.jsonc).
fn numv(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}
/// `tonumber(s)` as JSON (None → key omitted).
fn tonumv<S: AsRef<str>>(s: Option<S>) -> Option<Value> {
    tonum(s).map(numv)
}
/// Lua number → string (`n .. ""`).
fn lnum(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 9.0e15 {
        format!("{}", f as i64)
    } else {
        format!("{}", f)
    }
}
/// `tonumber(s:match("^%d+"))`
fn leading_int(s: &str) -> Option<f64> {
    let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if d.is_empty() {
        None
    } else {
        d.parse::<f64>().ok()
    }
}
fn lua_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}
/// `string.gsub(s, "[^<seps>]+", f)`: non-empty tokens separated by any of `seps`.
fn tokens(s: &str, seps: &[char]) -> Vec<String> {
    s.split(|c| seps.contains(&c)).filter(|w| !w.is_empty()).map(|w| w.to_string()).collect()
}
/// Recursively drop JSON nulls (Lua tables cannot hold nil).
fn prune(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            for x in m.values_mut() {
                prune(x);
            }
        }
        Value::Array(a) => {
            a.retain(|x| !x.is_null());
            for x in a.iter_mut() {
                prune(x);
            }
        }
        _ => {}
    }
}
/// `api.cleanEmptyTables(t)`
fn clean(mut v: Value) -> Option<Value> {
    prune(&mut v);
    api::clean_empty_tables(v)
}
/// `pcall(jsonc.parse, api.base64Decode(s))` that yielded a table.
fn b64_json_table(s: &str) -> Option<Value> {
    let mut v: Value = serde_json::from_str(&api::base64_decode(s)).ok()?;
    if !(v.is_object() || v.is_array()) {
        return None;
    }
    prune(&mut v);
    Some(v)
}
/// Lua `split(s:gsub("\\n", "\n"), "\n")` (PEM text stored with literal `\n`).
fn pem_lines(s: &str) -> Vec<String> {
    api::split(&s.replace("\\n", "\n"), "\n")
}
/// `get_log_level`
fn get_log_level(s: &str) -> String {
    if s == "warn" {
        "warning".into()
    } else {
        s.to_string()
    }
}
/// `get_domain_excluded()`
fn get_domain_excluded() -> Option<Vec<String>> {
    let content = std::fs::read_to_string(DOMAINS_EXCLUDED).ok()?;
    let hosts: Vec<String> = tokens(&content, &['\n']).iter().map(|w| api::trim(w)).filter(|s| !s.is_empty() && !s.starts_with('#')).collect();
    if hosts.is_empty() {
        None
    } else {
        Some(hosts)
    }
}
/// UCI section → Lua table.
fn node_of(s: &Section) -> Node {
    match s.to_json() {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}
fn rc(v: Value) -> Obj {
    Rc::new(RefCell::new(v))
}
fn otag(o: &Obj) -> Option<String> {
    vstr(&o.borrow(), "tag").map(|s| s.to_string())
}
/// `o.streamSettings = o.streamSettings or {}; o.streamSettings.sockopt = ... or {}; sockopt.dialerProxy = tag`
fn set_dialer(o: &mut Value, tag: &str) {
    let Some(m) = o.as_object_mut() else { return };
    let ss = m.entry("streamSettings").or_insert_with(|| json!({}));
    if !ss.is_object() {
        *ss = json!({});
    }
    let so = ss.as_object_mut().unwrap().entry("sockopt").or_insert_with(|| json!({}));
    if !so.is_object() {
        *so = json!({});
    }
    so["dialerProxy"] = Value::from(tag);
}
/// Remove every key starting with `_` (internal fields `_id`, `_flag`, `_flag_proxy_tag`).
fn strip_internal(o: &mut Value) {
    if let Some(m) = o.as_object_mut() {
        m.retain(|k, _| !k.starts_with('_'));
    }
}
/// Split an `alpn` option (`"h2,http/1.1"`); `"default"` → none.
fn alpn_list(n: &Node) -> Vec<String> {
    match ns(n, "alpn") {
        Some(a) if a != "default" => tokens(&a, &[',']),
        _ => vec![],
    }
}

// ====================================================================== finalmask pieces (client+server)

/// mkcp `finalmask.udp` list.
fn mkcp_udp(n: &Node) -> Value {
    let mut s = json!({"type": "mkcp-legacy"});
    if let Some(seed) = nne(n, "mkcp_seed") {
        s["settings"] = json!({ "value": seed });
    }
    let mut udp = vec![s];
    if let Some(guise) = ns(n, "mkcp_guise").filter(|g| g != "none") {
        let header = match guise.as_str() {
            "none" => Some("none"),
            "srtp" => Some("srtp"),
            "utp" => Some("utp"),
            "wechat-video" => Some("wechat"),
            "dtls" => Some("dtls"),
            "wireguard" => Some("wireguard"),
            "dns" => Some("dns"),
            _ => None,
        };
        let mut g = json!({"type": "mkcp-legacy", "settings": {"header": header}});
        if guise == "dns" {
            if let Some(d) = nne(n, "mkcp_domain") {
                g["settings"]["value"] = Value::from(d);
            }
        }
        udp.push(g);
    }
    Value::Array(udp)
}

/// hysteria `finalmask.udp` list (salamander/gecko obfs + realm).
fn hysteria_udp(n: &Node) -> Vec<Value> {
    let mut udp = vec![];
    if let Some(t) = nne(n, "hysteria2_obfs_type") {
        let mut o = json!({"type": "salamander"});
        if let Some(pw) = ns(n, "hysteria2_obfs_password") {
            o["settings"] = json!({ "password": pw });
        }
        if t == "gecko" {
            let mut min = tonum(ns(n, "hysteria2_obfs_MinPacketSize").as_deref()).unwrap_or(512.0);
            let mut max = tonum(ns(n, "hysteria2_obfs_MaxPacketSize").as_deref()).unwrap_or(1200.0);
            if min <= 0.0 || min > max || max > 2048.0 {
                min = 512.0;
                max = 1200.0;
            }
            // upstream quirk: Lua crashes here when no obfs password is set (settings is nil);
            // we create the settings table instead.
            if !o.get("settings").is_some_and(|s| s.is_object()) {
                o["settings"] = json!({});
            }
            o["settings"]["packetSize"] = Value::from(format!("{}-{}", lnum(min), lnum(max)));
        }
        udp.push(o);
    }
    if has(n, "hysteria2_realms") {
        let realm = ns(n, "hysteria2_realm_url").and_then(|u| api::parse_realm_uri(&u));
        let (url, stun) = match realm {
            Some(r) => (
                Some(format!("{}://{}@{}/{}", r.scheme, r.token, r.server_url, r.realm_id)),
                r.stun_servers.map(Value::from).or_else(|| raw(n, "hysteria2_realm_stun")),
            ),
            None => (None, None),
        };
        udp.push(json!({
            "type": "realm",
            "settings": {
                "url": url,
                "stunServers": stun,
                "portMapping": if neq(n, "hysteria2_realm_upnp", "1") { json!({"enabled": true}) } else { Value::Null }
            }
        }));
    }
    udp
}

/// `udpHop.interval` (hysteria2_hop_interval).
fn hop_interval(v: Option<String>) -> Value {
    let Some(v) = v else { return Value::from(30) };
    if v.contains('-') {
        if let Some((a, b)) = v.split_once('-') {
            let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
            if digits(a) && digits(b) {
                if let (Ok(min), Ok(max)) = (a.parse::<f64>(), b.parse::<f64>()) {
                    let min = if min >= 5.0 { min } else { 5.0 };
                    let max = if max >= min { max } else { min };
                    return Value::from(format!("{}-{}", lnum(min), lnum(max)));
                }
            }
        }
        return Value::from(30);
    }
    match leading_int(&v) {
        Some(n) if n >= 5.0 => numv(n),
        _ => Value::from(30),
    }
}

/// `wireguard_reserved` → byte array.
fn wireguard_reserved(s: &str) -> Option<Vec<u32>> {
    let bytes: Vec<u32> = if s.chars().all(|c| c.is_ascii_digit() || c == ',') {
        tokens(s, &[','])
            .iter()
            .flat_map(|t| {
                // `%d+` runs inside the token (only digits here)
                t.parse::<f64>().ok().map(|f| f as u32)
            })
            .collect()
    } else {
        // upstream quirk: api.base64Decode strips NUL bytes, which corrupts reserved values that
        // contain a 0x00 byte; we keep the raw decoded bytes. Non-base64 input is used as-is
        // (base64Decode returns its input unchanged).
        match api::base64_decode_bytes(s) {
            Some(b) => b.into_iter().map(u32::from).collect(),
            None => s.bytes().map(u32::from).collect(),
        }
    };
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

// ====================================================================== generator context

/// `proxy_table` argument of gen_outbound / gen_outbound_get_tag.
#[derive(Clone, Debug, Default)]
pub struct ProxyTable {
    pub tag: Option<String>,
    pub fragment: bool,
    pub noise: bool,
    pub chain_proxy: Option<String>,
    pub preproxy_node: Option<String>,
    pub to_node: Option<String>,
}

/// `get_node_by_id` accepts an id or a table.
enum NodeRef {
    Id(String),
    Table(Node),
}

struct Gen<'a> {
    cfg: &'a Config,
    /// gen_config `flag` (upvalue used by the inner functions)
    flag: Option<String>,
    /// `NO_RUN`
    no_run: bool,
    /// `TMP_PORT`
    tmp_port: Option<u32>,
    fragment_table: Option<Value>,
    noise_table: Option<Value>,
    default_node_address: Option<String>,
    default_node_port: Option<String>,
    /// `GLOBAL.DNS_SERVER` (node id → DNS server)
    dns_server: IndexMap<String, Value>,
    /// `GLOBAL.DNS_HOSTNAME`
    dns_hostname: Vec<String>,
    /// `@global_xray[0]`
    xray: Node,
    inbounds: Vec<Value>,
    outbounds: Vec<Obj>,
    balancers: Vec<Value>,
    rules: Vec<Value>,
    observatory: Option<Value>,
    burst_observatory: Option<Value>,
    /// perform side effects (exec run_socks, port allocation, files, set flush)
    effects: bool,
    /// fake port counter when `effects` is off
    fake_port: u32,
    /// recursion guard for balancer/fallback cycles (Lua would overflow its stack)
    depth: u32,
}

impl<'a> Gen<'a> {
    fn new(cfg: &'a Config, effects: bool) -> Self {
        Gen {
            cfg,
            flag: None,
            no_run: false,
            tmp_port: None,
            fragment_table: None,
            noise_table: None,
            default_node_address: None,
            default_node_port: None,
            dns_server: IndexMap::new(),
            dns_hostname: vec![],
            xray: Node::new(),
            inbounds: vec![],
            outbounds: vec![],
            balancers: vec![],
            rules: vec![],
            observatory: None,
            burst_observatory: None,
            effects,
            fake_port: 2000,
            depth: 0,
        }
    }

    /// `api.get_new_port()`
    fn new_port(&mut self) -> String {
        if self.effects {
            api::get_new_port(None, "").to_string()
        } else {
            self.fake_port += 1;
            self.fake_port.to_string()
        }
    }

    /// `{ fragment = xray_settings.fragment == "1", noise = xray_settings.noise == "1" }`
    fn fragment_noise(&self) -> ProxyTable {
        ProxyTable { fragment: neq(&self.xray, "fragment", "1"), noise: neq(&self.xray, "noise", "1"), ..Default::default() }
    }

    /// `/usr/share/passwall2/app.sh run_socks "flag=... node=... ..." > /dev/null`
    fn run_socks(&self, port: &str, node_id: &str, config_file: &str, relay_port: &str) {
        if !self.effects {
            return;
        }
        let _ = Command::new(util::SELF_BIN)
            .args([
                "app".to_string(),
                "run_socks".to_string(),
                format!("flag={}", port),
                format!("node={}", node_id),
                "bind=127.0.0.1".to_string(),
                format!("socks_port={}", port),
                format!("config_file={}", config_file),
                format!("relay_port={}", relay_port),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status();
    }

    /// `mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>`
    fn touch_iface(&self, iface: &str) {
        if !self.effects {
            return;
        }
        util::mkdir(api::TMP_IFACE_PATH);
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(format!("{}/{}", api::TMP_IFACE_PATH, iface));
    }

    // ------------------------------------------------------------------ gen_outbound

    /// `gen_outbound(flag, node, tag, proxy_table)`. `node_in` is mutated like the Lua table
    /// (stream_security, protocol/transport normalization, lowercased address).
    fn gen_outbound(&mut self, flag: Option<&str>, node_in: &mut Node, tag: Option<String>, proxy: Option<&ProxyTable>) -> Value {
        let node_id = ns(node_in, ".name");
        let mut tag = tag.or_else(|| node_id.clone());
        let remarks = ns(node_in, "remarks");

        let mut proxy_tag: Option<String> = None;
        let mut fragment = false;
        let mut noise = false;
        if let Some(p) = proxy {
            proxy_tag = p.tag.clone();
            let realms = has(node_in, "hysteria2_realms");
            fragment = p.fragment && !realms;
            noise = p.noise && !realms;
        }
        let mut dialer_proxy_tag: Option<String> = None;

        let mut synth: Node;
        let node: &mut Node = if !neq(node_in, "type", "Xray") {
            // non-Xray node: run it as a local SOCKS instance and chain to it
            let nid = node_id.clone().unwrap_or_default();
            let new_port: String;
            if self.no_run {
                let p = self.tmp_port.map(|p| p + 1).unwrap_or(3001);
                self.tmp_port = Some(p);
                new_port = p.to_string();
            } else {
                let relay_port = match (&proxy_tag, ns(node_in, "port")) {
                    (Some(_), Some(p)) => p,
                    _ => String::new(),
                };
                let cached = if relay_port.is_empty() && self.effects { api::get_socks_port_by_cache(&nid) } else { None };
                match cached {
                    Some(c) => new_port = c,
                    None => {
                        let p = self.new_port();
                        let mut config_file = format!("nodesocks_{}_{}.json", nid, p);
                        if let (Some(t), Some(id)) = (&tag, &node_id) {
                            if !api::lua_find(t, id) {
                                config_file = format!("nodesocks_{}_{}_{}.json", t, id, p);
                            }
                        }
                        self.run_socks(&p, &nid, &config_file, &relay_port);
                        if relay_port.is_empty() && self.effects {
                            api::set_socks_port_to_cache(&nid, &p);
                        }
                        new_port = p;
                    }
                }
            }
            synth = Node::new();
            set(&mut synth, "protocol", "socks");
            set(&mut synth, "transport", "raw");
            set(&mut synth, "address", "127.0.0.1");
            set(&mut synth, "port", new_port);
            set(&mut synth, "stream_security", "none");
            proxy_tag = Some(format!("socks <- {}", nid));
            &mut synth
        } else {
            dialer_proxy_tag = proxy_tag.clone();
            node_in
        };

        let is_xray = neq(node, "type", "Xray");
        if is_xray && neq(node, "tls", "1") {
            set(node, "stream_security", "tls");
            if neq(node, "reality", "1") {
                set(node, "stream_security", "reality");
            }
        }
        if neq(node, "protocol", "wireguard") {
            if let Some(r) = ns(node, "wireguard_reserved") {
                match wireguard_reserved(&r) {
                    Some(b) => set(node, "wireguard_reserved", b),
                    None => {
                        node.remove("wireguard_reserved");
                    }
                }
            }
        }
        if neq(node, "protocol", "hysteria2") {
            set(node, "protocol", "hysteria");
            set(node, "transport", "hysteria");
            set(node, "stream_security", "tls");
        }
        if neq(node, "protocol", "masque") {
            set(node, "transport", "masque");
            set(node, "stream_security", "tls");
            node.remove("utls");
        }
        if neq(node, "protocol", "http") && neq(node, "stream_security", "tls") {
            set(node, "transport", "raw");
        }
        if let Some(r) = &remarks {
            tag = Some(format!("{}:{}", tag.unwrap_or_default(), r));
        }
        let address = ns(node, "address").unwrap_or_default().to_lowercase();
        set(node, "address", address.clone());

        let node = &*node;
        let g = |k: &str| ns(node, k);
        let proto = g("protocol").unwrap_or_default();
        let p = proto.as_str();
        let transport = g("transport");
        let tp = transport.as_deref().unwrap_or("");
        let sec = g("stream_security");
        let ua = g("user_agent");
        let has_ua = ua.is_some();

        let stream_cond = has(node, "streamSettings")
            || dialer_proxy_tag.is_some()
            || matches!(p, "vmess" | "vless" | "socks" | "shadowsocks" | "trojan" | "hysteria" | "http" | "masque");

        let stream = if stream_cond {
            let tls_settings = if sec.as_deref() == Some("tls") {
                json!({
                    "serverName": g("tls_serverName"),
                    "fingerprint": if is_xray && neq(node, "utls", "1") { nne(node, "fingerprint") } else { None },
                    "pinnedPeerCertSha256": nne(node, "tls_pinSHA256").map(|x| api::sha256_sb_xray(&x)).unwrap_or_default(),
                    "verifyPeerCertByName": g("tls_CertByName").unwrap_or_default(),
                    "echConfigList": if neq(node, "ech", "1") { g("ech_config") } else { None },
                    "certificates": match g("tls_certificate_pem") {
                        // upstream crashes on a nil pem; treated as "no certificate".
                        // upstream quirk: Lua emits a single object here, which Xray rejects
                        // (`certificates` is []TLSCertConfig); we emit a one-element list.
                        Some(pem) if neq(node, "tls_certificate", "1") && !pem.is_empty() => json!([{
                            "certificate": pem_lines(&pem),
                            "usage": "verify"
                        }]),
                        _ => Value::Null,
                    },
                    "cipherSuites": nl(node, "cipherSuites").filter(|l| !l.is_empty()).map(|l| l.join(":")),
                })
            } else {
                Value::Null
            };
            let reality_settings = if sec.as_deref() == Some("reality") {
                json!({
                    "serverName": g("tls_serverName"),
                    "publicKey": g("reality_publicKey"),
                    "shortId": g("reality_shortId").unwrap_or_default(),
                    "spiderX": g("reality_spiderX").unwrap_or_else(|| "/".into()),
                    "fingerprint": (if is_xray { nne(node, "fingerprint") } else { None }).unwrap_or_else(|| "chrome".into()),
                    "mldsa65Verify": if neq(node, "use_mldsa65Verify", "1") { g("reality_mldsa65Verify") } else { None },
                })
            } else {
                Value::Null
            };
            let tcp_guise = g("tcp_guise");
            let raw_settings = if (tp == "raw" || tp == "tcp") && p != "socks" && tcp_guise.as_deref().is_some_and(|t| t != "none") {
                let tg = tcp_guise.clone().unwrap_or_default();
                let request = if tg == "http" {
                    let path: Vec<String> = match nl(node, "tcp_guise_http_path") {
                        Some(l) => l.into_iter().map(|v| if v.is_empty() { "/".into() } else { v }).collect(),
                        None => vec!["/".into()],
                    };
                    let host = raw(node, "tcp_guise_http_host");
                    let headers = if host.is_some() || has_ua {
                        json!({ "Host": host, "User-Agent": ua.clone().map(|u| vec![u]) })
                    } else {
                        Value::Null
                    };
                    json!({ "path": path, "headers": headers })
                } else {
                    Value::Null
                };
                json!({ "header": { "type": tg, "request": request } })
            } else {
                Value::Null
            };
            let kcp_settings = if tp == "mkcp" {
                json!({
                    "mtu": tonumv(nne(node, "mkcp_mtu").as_deref()).unwrap_or(Value::from(1350)),
                    "tti": 50,
                    "uplinkCapacity": 12,
                    "downlinkCapacity": 100,
                    "cwndMultiplier": 1,
                    "maxSendingWindow": 2 * 1024 * 1024
                })
            } else {
                Value::Null
            };
            let ws_settings = if tp == "ws" {
                json!({
                    "path": g("ws_path").unwrap_or_else(|| "/".into()),
                    "host": g("ws_host"),
                    "headers": ua.clone().map(|u| json!({ "User-Agent": u })),
                    "maxEarlyData": tonumv(g("ws_maxEarlyData").as_deref()),
                    "earlyDataHeaderName": g("ws_earlyDataHeaderName"),
                    "heartbeatPeriod": tonumv(g("ws_heartbeatPeriod").as_deref()),
                })
            } else {
                Value::Null
            };
            let grpc_settings = if tp == "grpc" {
                // upstream crashes when grpc_idle_timeout is not a number; we drop it then
                let idle = tonum(g("grpc_idle_timeout").as_deref()).map(|t| numv(if t < 10.0 { 10.0 } else { t }));
                json!({
                    "serviceName": g("grpc_serviceName"),
                    "multiMode": neq(node, "grpc_mode", "multi"),
                    "idle_timeout": idle,
                    "health_check_timeout": tonumv(g("grpc_health_check_timeout").as_deref()),
                    "permit_without_stream": neq(node, "grpc_permit_without_stream", "1"),
                    "initial_windows_size": tonumv(g("grpc_initial_windows_size").as_deref()).unwrap_or(Value::from(0)),
                    "user_agent": ua.clone(),
                })
            } else {
                Value::Null
            };
            let httpupgrade_settings = if tp == "httpupgrade" {
                json!({
                    "path": g("httpupgrade_path").unwrap_or_else(|| "/".into()),
                    "host": g("httpupgrade_host"),
                    "headers": ua.clone().map(|u| json!({ "User-Agent": u })),
                })
            } else {
                Value::Null
            };
            let xhttp_settings = if tp == "xhttp" {
                let mut extra = json!({});
                if let Some(x) = g("xhttp_extra") {
                    if let Some(parsed) = b64_json_table(&x) {
                        extra = match parsed.get("extra") {
                            Some(e) if !e.is_null() => e.clone(),
                            _ => parsed,
                        };
                    }
                }
                if let Some(u) = ua.clone().filter(|u| !u.is_empty()) {
                    if let Some(m) = extra.as_object_mut() {
                        let h = m.entry("headers").or_insert_with(|| json!({}));
                        if let Some(hm) = h.as_object_mut() {
                            if !hm.contains_key("User-Agent") && !hm.contains_key("user-agent") {
                                hm.insert("User-Agent".into(), Value::from(u));
                            }
                        }
                    }
                }
                json!({
                    "mode": g("xhttp_mode").unwrap_or_else(|| "auto".into()),
                    "path": g("xhttp_path").unwrap_or_else(|| "/".into()),
                    "host": g("xhttp_host"),
                    "extra": clean(extra),
                })
            } else {
                Value::Null
            };
            let masque_settings = if p == "masque" {
                let warp = if neq(node, "masque_warp", "1") {
                    json!({
                        "privateKey": g("masque_warp_private_key").unwrap_or_default().replace("\\n", "\n"),
                        "publicKey": g("masque_warp_public_key").unwrap_or_default().replace("\\n", "\n"),
                        "address": raw(node, "masque_warp_address"),
                    })
                } else {
                    Value::Null
                };
                let mut headers = Map::new();
                let user = g("username").unwrap_or_default();
                let pass = g("password").unwrap_or_default();
                if !neq(node, "masque_warp", "1") && (!user.is_empty() || !pass.is_empty()) {
                    headers.insert("authorization".into(), Value::from(format!("Basic {}", api::base64_encode(format!("{}:{}", user, pass).as_bytes()))));
                }
                if let Some(u) = ua.clone().filter(|u| !u.is_empty()) {
                    headers.insert("user-agent".into(), Value::from(u));
                }
                let mh = g("masque_headers").unwrap_or_default().replace("\\n", "\n");
                for line in tokens(&mh, &['\r', '\n']) {
                    // ^%s*([^:]+):%s*(.-)%s*$
                    let l = line.trim_start_matches(lua_space);
                    if let Some(i) = l.find(':') {
                        if i > 0 {
                            let key = api::trim(&l[..i]).to_lowercase();
                            let value = l[i + 1..].trim_matches(lua_space).to_string();
                            headers.insert(key, Value::from(value));
                        }
                    }
                }
                json!({
                    "path": nne(node, "masque_path"),
                    "warp": warp,
                    "headers": if headers.is_empty() { Value::Null } else { Value::Object(headers) },
                })
            } else {
                Value::Null
            };
            let hysteria_settings = if tp == "hysteria" {
                json!({ "version": 2, "auth": g("hysteria2_auth_password") })
            } else {
                Value::Null
            };
            let finalmask = self.client_finalmask(node, tp, fragment, noise);

            json!({
                "sockopt": {
                    "mark": 255,
                    "domainStrategy": g("domain_strategy").unwrap_or_else(|| "UseIP".into()),
                    "tcpFastOpen": if neq(node, "tcp_fast_open", "1") { Some(true) } else { None },
                    "tcpMptcp": if neq(node, "tcpMptcp", "1") { Some(true) } else { None },
                    "happyEyeballs": if neq(node, "happy_eyeballs", "1") {
                        json!({"TryDelayMs": 250, "PrioritizeIPv6": false, "Interleave": 1, "MaxConcurrentTry": 4})
                    } else { Value::Null },
                    "dialerProxy": dialer_proxy_tag.clone(),
                },
                "method": transport.clone(),
                "security": sec.clone(),
                "tlsSettings": tls_settings,
                "realitySettings": reality_settings,
                "rawSettings": raw_settings,
                "kcpSettings": kcp_settings,
                "wsSettings": ws_settings,
                "grpcSettings": grpc_settings,
                "httpupgradeSettings": httpupgrade_settings,
                "xhttpSettings": xhttp_settings,
                "masqueSettings": masque_settings,
                "hysteriaSettings": hysteria_settings,
                "finalmask": finalmask,
            })
        } else {
            Value::Null
        };

        let ss_method = g("ss_method");
        let method = if p == "shadowsocks" {
            match ss_method.as_deref() {
                Some("chacha20-ietf-poly1305") => Some("chacha20-poly1305".to_string()),
                Some("xchacha20-ietf-poly1305") => Some("xchacha20-poly1305".to_string()),
                Some(m) if !m.is_empty() => Some(m.to_string()),
                _ => None,
            }
        } else {
            None
        };
        let encryption = g("encryption");
        let enc_set = encryption.as_deref().is_some_and(|e| !e.is_empty() && e != "none");
        let wg = p == "wireguard";
        let settings = json!({
            "address": if wg { raw(node, "wireguard_local_address") } else { Some(Value::from(address.clone())) },
            "port": tonumv(g("port").as_deref()),
            "id": if p == "vmess" || p == "vless" { g("uuid") } else { None },
            "encryption": if p == "vless" { Some(encryption.clone().filter(|e| !e.is_empty()).unwrap_or_else(|| "none".into())) } else { None },
            "flow": if p == "vless" && (neq(node, "tls", "1") || enc_set) { nne(node, "flow") } else { None },
            "security": if p == "vmess" { g("security") } else { None },
            "user": if p == "socks" || p == "http" { g("username") } else { None },
            "pass": if p == "socks" || p == "http" { g("password") } else { None },
            "password": if p == "shadowsocks" || p == "trojan" { g("password") } else { None },
            "method": method,
            "secretKey": if wg { g("wireguard_secret_key") } else { None },
            "peers": if wg {
                json!([{
                    "publicKey": g("wireguard_public_key"),
                    "endpoint": format!("{}:{}", address, g("port").unwrap_or_default()),
                    "preSharedKey": g("wireguard_preSharedKey"),
                    "keepAlive": tonumv(g("wireguard_keepAlive").as_deref()),
                }])
            } else { Value::Null },
            "mtu": if wg { tonumv(g("wireguard_mtu").as_deref()) } else { None },
            "reserved": if wg { raw(node, "wireguard_reserved") } else { None },
            "version": if p == "hysteria" { Some(2) } else { None },
            "level": 0,
        });

        let mut result = json!({
            "_id": node_id.clone(),
            "_flag": flag,
            "_flag_proxy_tag": proxy_tag.clone(),
            "tag": tag,
            "protocol": g("protocol"),
            "mux": if p != "masque" {
                let on = neq(node, "mux", "1");
                json!({
                    "enabled": on,
                    "concurrency": if on { Some(tonumv(g("mux_concurrency").as_deref()).unwrap_or(Value::from(-1))) } else { None },
                    "xudpConcurrency": if on { Some(tonumv(g("xudp_concurrency").as_deref()).unwrap_or(Value::from(8))) } else { None },
                })
            } else { Value::Null },
            "streamSettings": stream,
            "settings": settings,
        });

        if p == "hysteria" && has(node, "hysteria2_realms") {
            if let Some(r) = g("hysteria2_realm_url").and_then(|u| api::parse_realm_uri(&u)) {
                result["settings"]["address"] = Value::from(r.address);
                result["settings"]["port"] = Value::from(r.port);
            }
        }
        if wg {
            result["settings"]["noKernelTun"] = Value::from(true);
            if let Some(fm) = nne(node, "finalmask").and_then(|f| b64_json_table(&f)) {
                if !result["streamSettings"].is_object() {
                    result["streamSettings"] = json!({});
                }
                result["streamSettings"]["finalmask"] = fm;
            }
        }

        let alpn = alpn_list(node);
        // upstream crashes when streamSettings is nil here (e.g. wireguard + alpn); guarded
        if !alpn.is_empty() && vget(&result["streamSettings"], "tlsSettings").is_some() {
            result["streamSettings"]["tlsSettings"]["alpn"] = Value::from(alpn);
        }

        // per-node bootstrap resolver for the server hostname
        if api::dt_hostname(&address) && has(node, "domain_resolver") && (has(node, "domain_resolver_dns") || has(node, "domain_resolver_dns_https")) {
            let nid = node_id.clone().unwrap_or_default();
            let dns_tag = format!("{}_dns", nid);
            let dns_proto = g("domain_resolver").unwrap_or_default();
            let mut config_address: Option<String> = None;
            let mut config_port: Option<Value> = None;
            if dns_proto == "https" {
                let url = g("domain_resolver_dns_https").unwrap_or_default();
                if let Some(a) = api::parse_url(&url) {
                    config_address = Some(url.clone());
                    config_port = Some(Value::from(a.port.unwrap_or(443)));
                    if !a.hostname.is_empty() && api::dt_hostname(&a.hostname) && !self.dns_hostname.contains(&a.hostname) {
                        self.dns_hostname.push(a.hostname.clone());
                    }
                }
            } else {
                let mut server_address = g("domain_resolver_dns").unwrap_or_default();
                // upstream quirk: a shadowed local makes the emitted port nil for udp/tcp; kept.
                let mut local_port: f64 = 53.0;
                let split = api::split(&server_address, ":");
                if split.len() > 1 {
                    local_port = tonum(split.last().map(|s| s.as_str())).unwrap_or(53.0);
                    server_address = split[0].clone();
                }
                config_address = Some(if dns_proto == "tcp" { format!("tcp://{}:{}", server_address, lnum(local_port)) } else { server_address });
            }
            let mut srv = json!({
                "tag": dns_tag,
                "queryStrategy": g("domain_strategy").unwrap_or_else(|| "UseIP".into()),
                "address": config_address,
                "port": config_port,
                "domains": [format!("full:{}", address)],
                "finalQuery": true,
                "disableCache": false,
                "serveStale": true,
            });
            prune(&mut srv);
            self.dns_server.insert(nid, srv);
        }
        result
    }

    /// client `finalmask` (mkcp/hysteria + fragment/noise + base64 override), cleaned.
    fn client_finalmask(&self, node: &Node, tp: &str, fragment: bool, noise: bool) -> Value {
        let mut fm = json!({});
        if tp == "mkcp" {
            fm["udp"] = mkcp_udp(node);
        } else if tp == "hysteria" {
            fm["udp"] = Value::from(hysteria_udp(node));
            let up = tonum(ns(node, "hysteria2_up_mbps").as_deref()).unwrap_or(0.0);
            let down = tonum(ns(node, "hysteria2_down_mbps").as_deref()).unwrap_or(0.0);
            let idle = leading_int(&ns(node, "hysteria2_idle_timeout").unwrap_or_else(|| "30".into())).filter(|t| (4.0..=120.0).contains(t)).unwrap_or(30.0);
            let keep = leading_int(&ns(node, "hysteria2_keep_alive_period").unwrap_or_else(|| "0".into())).filter(|t| (2.0..=60.0).contains(t));
            let srw = tonum(ns(node, "hysteria2_stream_recv_win").as_deref()).map(|x| numv(x * 1048576.0));
            let crw = tonum(ns(node, "hysteria2_conn_recv_win").as_deref()).map(|x| numv(x * 1048576.0));
            fm["quicParams"] = json!({
                "congestion": if up <= 0.0 && down <= 0.0 { "bbr" } else { "brutal" },
                "brutalUp": if up > 0.0 { Some(format!("{}mbps", lnum(up))) } else { None },
                "brutalDown": if down > 0.0 { Some(format!("{}mbps", lnum(down))) } else { None },
                "udpHop": match ns(node, "hysteria2_hop") {
                    Some(hop) if has(node, "hysteria2_hop") => json!({
                        "ports": hop.replace(':', "-"),
                        "interval": hop_interval(ns(node, "hysteria2_hop_interval")),
                    }),
                    _ => Value::Null,
                },
                "maxIdleTimeout": numv(idle),
                "keepAlivePeriod": keep.map(numv),
                "disablePathMTUDiscovery": neq(node, "hysteria2_disable_mtu_discovery", "1"),
                "initStreamReceiveWindow": srw.clone(),
                "maxStreamReceiveWindow": srw,
                "initConnectionReceiveWindow": crw.clone(),
                "maxConnectionReceiveWindow": crw,
            });
        }
        if fragment && matches!(tp, "raw" | "ws" | "httpupgrade" | "grpc" | "xhttp") {
            if let Some(ft) = &self.fragment_table {
                if !fm["tcp"].is_array() {
                    fm["tcp"] = json!([]);
                }
                fm["tcp"].as_array_mut().unwrap().push(ft.clone());
            }
        }
        if noise && (tp == "mkcp" || (tp == "xhttp" && neq(node, "alpn", "h3"))) {
            if let Some(nt) = &self.noise_table {
                if !fm["udp"].is_array() {
                    fm["udp"] = json!([]);
                }
                fm["udp"].as_array_mut().unwrap().push(nt.clone());
            }
        }
        if let Some(over) = nne(node, "finalmask").and_then(|f| b64_json_table(&f)) {
            fm = over;
        }
        clean(fm).unwrap_or(Value::Null)
    }

    // ------------------------------------------------------------------ gen_config inner functions

    /// `get_node_by_id(node_id)`
    fn get_node_by_id(&self, r: NodeRef) -> Option<Node> {
        let section = match r {
            NodeRef::Table(t) => t,
            NodeRef::Id(id) => {
                if id.is_empty() || id == "nil" {
                    return None;
                }
                self.cfg.section(&id).map(node_of).unwrap_or_default()
            }
        };
        match ns(&section, ".type").as_deref() {
            Some("socks") => {
                let mut n = Node::new();
                if let Some(name) = section.get(".name") {
                    n.insert(".name".into(), name.clone());
                }
                set(&mut n, "remarks", format!("socks[{}]", ns(&section, "port").unwrap_or_default()));
                set(&mut n, "type", "Xray");
                set(&mut n, "protocol", "socks");
                set(&mut n, "address", "127.0.0.1");
                if let Some(p) = section.get("port") {
                    n.insert("port".into(), p.clone());
                }
                set(&mut n, "transport", "raw");
                set(&mut n, "stream_security", "none");
                Some(n)
            }
            Some("nodes") => Some(section),
            _ => None,
        }
    }

    /// `gen_loopback(outbound_tag, loopback_dst)`
    fn gen_loopback(&mut self, outbound_tag: Option<&str>, loopback_dst: Option<&str>) -> Option<Obj> {
        let ot = outbound_tag.filter(|t| !t.is_empty())?;
        let inbound_tag = match loopback_dst {
            Some(d) => format!("lo-to-{}", d),
            None => format!("{}-lo", ot),
        };
        for o in &self.outbounds {
            let b = o.borrow();
            if vstr(&b, "tag") == Some(ot) && vstr(&b, "protocol") == Some("loopback") && b["settings"]["inboundTag"].as_str() == Some(inbound_tag.as_str()) {
                return Some(o.clone());
            }
        }
        let lo = rc(json!({ "protocol": "loopback", "tag": ot, "settings": { "inboundTag": inbound_tag } }));
        if ot == "default" {
            self.outbounds.insert(0, lo.clone());
        } else {
            self.outbounds.push(lo.clone());
        }
        Some(lo)
    }

    /// First outbound whose tag starts with `prefix` (`string.sub(tag, 1, #prefix) == prefix`).
    fn outbound_with_prefix(&self, prefix: &str) -> Option<String> {
        self.outbounds.iter().find_map(|o| otag(o).filter(|t| t.as_bytes().starts_with(prefix.as_bytes())))
    }

    /// `gen_balancer(_node, loopback_tag)` → `(balancer_tag, loopback_outbound)`
    fn gen_balancer(&mut self, bnode: &mut Node, loopback_tag: Option<&str>) -> Option<(String, Option<Obj>)> {
        if self.depth > 16 {
            return None;
        }
        self.depth += 1;
        let r = self.gen_balancer_inner(bnode, loopback_tag);
        self.depth -= 1;
        r
    }

    fn gen_balancer_inner(&mut self, bnode: &mut Node, loopback_tag: Option<&str>) -> Option<(String, Option<Obj>)> {
        let balancer_id = ns(bnode, ".name").unwrap_or_default();
        let balancer_tag = format!("balancer-{}", balancer_id);
        let loopback_tag = loopback_tag.filter(|t| !t.is_empty()).map(|t| t.to_string()).unwrap_or_else(|| balancer_id.clone());
        if self.balancers.iter().any(|b| vstr(b, "tag") == Some(balancer_tag.as_str())) {
            let lo = self.gen_loopback(Some(&loopback_tag), Some(&balancer_id));
            return Some((balancer_tag, lo));
        }
        let blc_nodes: Vec<String> = if neq(bnode, "node_add_mode", "batch") {
            api::get_batch_nodes(self.cfg, ns(bnode, "node_group").as_deref(), ns(bnode, "node_match_rule").as_deref())
        } else {
            nl(bnode, "balancing_node").unwrap_or_default()
        };
        let mut valid_nodes: Vec<String> = vec![];
        for blc_id in blc_nodes {
            let blc_tag = format!("blc-{}", blc_id);
            if let Some(t) = self.outbound_with_prefix(&blc_tag) {
                valid_nodes.push(t);
                continue;
            }
            let mut pt = ProxyTable { fragment: neq(&self.xray, "fragment", "1"), noise: neq(&self.xray, "noise", "1"), ..Default::default() };
            if let Some(t) = self.gen_outbound_get_tag(NodeRef::Id(blc_id.clone()), Some(blc_tag), &mut pt) {
                valid_nodes.push(t);
            }
            if ns(bnode, "fallback_node").as_deref() == Some(blc_id.as_str()) {
                bnode.remove("fallback_node");
            }
        }
        if valid_nodes.is_empty() {
            return None;
        }

        let fallback_id = nne(bnode, "fallback_node");
        let mut fallback_tag = if fallback_id.as_deref() == Some("_direct") { "direct".to_string() } else { "blackhole".to_string() };
        if let Some(fb) = fallback_id.filter(|f| f != "_direct") {
            if let Some(t) = self.outbound_with_prefix(&fb) {
                fallback_tag = t;
            } else if let Some(mut fnode) = self.get_node_by_id(NodeRef::Id(fb.clone())) {
                if !neq(&fnode, "protocol", "_balancing") {
                    let mut pt = ProxyTable { fragment: neq(&self.xray, "fragment", "1"), noise: neq(&self.xray, "noise", "1"), ..Default::default() };
                    if let Some(t) = self.gen_outbound_get_tag(NodeRef::Table(fnode), Some(fb.clone()), &mut pt) {
                        fallback_tag = t;
                    }
                } else if self.gen_balancer(&mut fnode, None).is_some() {
                    fallback_tag = fb.clone();
                }
            }
        }

        let bs = ns(bnode, "balancingStrategy");
        let strategy = if bs.as_deref() == Some("leastLoad") {
            let tolerance = {
                let t = tonum(ns(bnode, "tolerance").as_deref()).unwrap_or(0.0);
                if t < 1.0 {
                    Value::Null
                } else {
                    numv(t.min(100.0) / 100.0)
                }
            };
            json!({
                "type": "leastLoad",
                "settings": {
                    "expected": tonumv(ns(bnode, "expected").as_deref()).unwrap_or(Value::from(2)),
                    "maxRTT": "1s",
                    "tolerance": tolerance,
                }
            })
        } else {
            json!({ "type": bs.clone().unwrap_or_else(|| "random".into()) })
        };
        self.balancers.push(json!({
            "tag": balancer_tag,
            "selector": valid_nodes,
            "fallbackTag": fallback_tag,
            "strategy": strategy,
        }));
        // upstream: the condition includes fallback_node_tag, which is never nil → always runs
        let mut t = api::format_go_time(ns(bnode, "probeInterval").as_deref(), None);
        if t == "0s" {
            t = "60s".into();
        } else if !t.contains(['h', 'm']) {
            let first: String = t.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
            if first.parse::<f64>().map(|n| n < 10.0).unwrap_or(false) {
                t = "10s".into();
            }
        }
        let probe_url = if has(bnode, "useCustomProbeUrl") { ns(bnode, "probeUrl") } else { None };
        if bs.as_deref() == Some("leastLoad") {
            if self.burst_observatory.is_none() {
                self.burst_observatory = Some(json!({
                    "subjectSelector": ["blc-"],
                    "pingConfig": { "destination": probe_url, "interval": t, "sampling": 3, "timeout": "5s" }
                }));
            }
        } else if self.observatory.is_none() {
            self.observatory = Some(json!({
                "subjectSelector": ["blc-"],
                "probeUrl": probe_url,
                "probeInterval": t,
                "enableConcurrency": true
            }));
        }
        let lo = self.gen_loopback(Some(&loopback_tag), Some(&balancer_id));
        let inbound_tag = lo.as_ref().map(|o| o.borrow()["settings"]["inboundTag"].clone()).unwrap_or(Value::Null);
        self.rules.push(json!({ "inboundTag": [inbound_tag], "balancerTag": balancer_tag }));
        Some((balancer_tag, lo))
    }

    /// `set_outbound_detour(node, outbound, outbounds)` → `(default_outTag, last_insert_outbound)`
    fn set_outbound_detour(&mut self, node: &Node, outbound: &Obj) -> (Option<String>, Option<Obj>) {
        let mut default_tag = otag(outbound);
        let mut last_insert: Option<Obj> = None;
        let node_name = ns(node, ".name");

        if neq(node, "chain_proxy", "1") && has(node, "preproxy_node") {
            let ignore = vget(&outbound.borrow(), "_flag_proxy_tag").is_some();
            if !ignore {
                if let Some(mut pre_node) = self.get_node_by_id(NodeRef::Id(ns(node, "preproxy_node").unwrap_or_default())) {
                    let (pre, exist) = if neq(&pre_node, "protocol", "_balancing") {
                        match self.gen_balancer(&mut pre_node, None) {
                            Some((_, Some(lo))) => (Some(lo), true),
                            _ => (None, false),
                        }
                    } else {
                        (Some(rc(self.gen_outbound(node_name.as_deref(), &mut pre_node, None, None))), false)
                    };
                    if let Some(pre) = pre {
                        let pre_tag = otag(&pre).unwrap_or_default();
                        {
                            let mut b = outbound.borrow_mut();
                            let cur = vstr(&b, "tag").unwrap_or("").to_string();
                            b["tag"] = Value::from(format!("{} -> {}", pre_tag, cur));
                            set_dialer(&mut b, &pre_tag);
                        }
                        if !exist {
                            last_insert = Some(pre);
                        }
                        default_tag = otag(outbound);
                    }
                }
            }
        }

        if neq(node, "chain_proxy", "2") && has(node, "to_node") {
            let mut to_node = self.get_node_by_id(NodeRef::Id(ns(node, "to_node").unwrap_or_default()));
            // landing node can not be a special node
            if to_node.as_ref().is_some_and(|t| ns(t, "protocol").is_some_and(|p| p.starts_with('_'))) {
                to_node = None;
            }
            if let Some(mut t) = to_node {
                let ob_tag = otag(outbound).unwrap_or_else(|| "nil".into());
                let t_is_xray = neq(&t, "type", "Xray");
                let mut to = if !t_is_xray {
                    let tname = ns(&t, ".name").unwrap_or_default();
                    let in_tag = format!("inbound_{}_{}", tname, ob_tag);
                    let new_port = self.new_port();
                    self.inbounds.push(json!({
                        "tag": in_tag,
                        "listen": "127.0.0.1",
                        "port": tonumv(Some(&new_port)),
                        "protocol": "tunnel",
                        "settings": {
                            "allowedNetwork": "tcp,udp",
                            "rewriteAddress": ns(&t, "address"),
                            "rewritePort": tonumv(ns(&t, "port").as_deref()),
                        }
                    }));
                    if !has(&t, "tls_serverName") {
                        if let Some(a) = t.get("address").cloned() {
                            t.insert("tls_serverName".into(), a);
                        }
                    }
                    set(&mut t, "address", "127.0.0.1");
                    set(&mut t, "port", new_port);
                    self.rules.insert(0, json!({ "inboundTag": [in_tag], "outboundTag": otag(outbound) }));
                    let pt = ProxyTable { tag: Some(tname.clone()), ..Default::default() };
                    self.gen_outbound(node_name.as_deref(), &mut t, Some(tname), Some(&pt))
                } else {
                    self.gen_outbound(node_name.as_deref(), &mut t, None, None)
                };
                let to_tag = format!("{} -> {}", ob_tag, vstr(&to, "tag").unwrap_or(""));
                to["tag"] = Value::from(to_tag.clone());
                if t_is_xray {
                    set_dialer(&mut to, &ob_tag);
                }
                self.outbounds.push(rc(to));
                default_tag = Some(to_tag);
            }
        }

        if neq(node, "chain_proxy", "3") {
            if let Some(iface) = ns(node, "outbound_iface") {
                let mut b = outbound.borrow_mut();
                if b.get("streamSettings").and_then(|s| s.get("sockopt")).is_some_and(|s| s.is_object()) {
                    b["streamSettings"]["sockopt"]["interface"] = Value::from(iface);
                }
            }
        }
        (default_tag, last_insert)
    }

    /// `gen_outbound_get_tag(flag, node_id, tag, proxy_table)` → outbound tag
    fn gen_outbound_get_tag(&mut self, r: NodeRef, tag: Option<String>, pt: &mut ProxyTable) -> Option<String> {
        if self.depth > 16 {
            return None;
        }
        self.depth += 1;
        let res = self.gen_outbound_get_tag_inner(r, tag, pt);
        self.depth -= 1;
        res
    }

    fn gen_outbound_get_tag_inner(&mut self, r: NodeRef, tag: Option<String>, pt: &mut ProxyTable) -> Option<String> {
        if let NodeRef::Id(id) = &r {
            if id.is_empty() || id == "nil" {
                return None;
            }
        }
        // upstream reads node[".name"] before the nil check (crash for missing ids)
        let mut node = self.get_node_by_id(r)?;
        let tag = tag.or_else(|| ns(&node, ".name"));
        let cp = pt.chain_proxy.clone();
        if matches!(cp.as_deref(), Some("1") | Some("2")) {
            let cp = cp.unwrap_or_default();
            set(&mut node, "chain_proxy", cp.clone());
            match (cp == "1").then(|| pt.preproxy_node.clone()).flatten() {
                Some(p) => set(&mut node, "preproxy_node", p),
                None => {
                    node.remove("preproxy_node");
                }
            }
            match (cp == "2").then(|| pt.to_node.clone()).flatten() {
                Some(p) => set(&mut node, "to_node", p),
                None => {
                    node.remove("to_node");
                }
            }
            pt.chain_proxy = None;
            pt.preproxy_node = None;
            pt.to_node = None;
        }
        if tag.as_deref() == Some("default") {
            if let (Some(a), Some(p)) = (self.default_node_address.clone(), self.default_node_port.clone()) {
                set(&mut node, "address", a);
                set(&mut node, "port", p);
            }
        }
        let mut outbound: Option<Obj> = None;
        let mut has_add = false;
        let needle = format!("socks <- {}", ns(&node, ".name").unwrap_or_default());
        for o in &self.outbounds {
            let b = o.borrow();
            if vstr(&b, "_flag_proxy_tag").is_some_and(|f| f.contains(&needle)) {
                // avoid generating duplicate nested processes
                let mut c = b.clone();
                match &tag {
                    Some(t) => c["tag"] = Value::from(t.clone()),
                    None => {
                        if let Some(m) = c.as_object_mut() {
                            m.remove("tag");
                        }
                    }
                }
                outbound = Some(rc(c));
                break;
            }
        }
        if neq(&node, "protocol", "_balancing") {
            if let Some((_, Some(lo))) = self.gen_balancer(&mut node, tag.as_deref()) {
                if let Some(t) = otag(&lo) {
                    set(&mut node, ".name", t);
                }
                outbound = Some(lo);
                has_add = true;
            }
        } else if neq(&node, "protocol", "_iface") {
            if let Some(iface) = ns(&node, "iface") {
                outbound = Some(rc(json!({
                    "tag": tag.clone(),
                    "protocol": "freedom",
                    "streamSettings": { "sockopt": { "mark": 255, "interface": iface } },
                    "settings": { "finalRules": [{ "action": "allow" }] }
                })));
                self.touch_iface(&iface);
            }
        }
        let outbound = match outbound {
            Some(o) => o,
            None => {
                let flag = self.flag.clone();
                rc(self.gen_outbound(flag.as_deref(), &mut node, tag.clone(), Some(pt)))
            }
        };
        let (default_tag, last_insert) = self.set_outbound_detour(&node, &outbound);
        if !has_add {
            if tag.as_deref() == Some("default") {
                self.outbounds.insert(0, outbound);
            } else {
                self.outbounds.push(outbound);
            }
        }
        if let Some(l) = last_insert {
            self.outbounds.push(l);
        }
        default_tag
    }

    /// `gen_shunt_node(rule_name, _node_id)`
    fn gen_shunt_node(&mut self, shunt: &Node, rule_name: &str, node_id: Option<String>) -> Option<String> {
        let nid = node_id.or_else(|| ns(shunt, rule_name))?;
        match nid.as_str() {
            "_direct" => Some("direct".into()),
            "_blackhole" => Some("blackhole".into()),
            "_default" if rule_name != "default" => Some("default".into()),
            _ => {
                let mut pt = self.fragment_noise();
                let mut pre = ns(shunt, &format!("{}_proxy_tag", rule_name));
                if pre.as_deref() == Some(nid.as_str()) {
                    pre = None;
                }
                match pre {
                    Some(pre) => {
                        pt.chain_proxy = Some("2".into());
                        pt.to_node = Some(nid);
                        self.gen_outbound_get_tag(NodeRef::Id(pre), Some(rule_name.to_string()), &mut pt)
                    }
                    None => self.gen_outbound_get_tag(NodeRef::Id(nid), Some(rule_name.to_string()), &mut pt),
                }
            }
        }
    }
}

// ====================================================================== gen_config

/// Every `*address` option value (first list item) of passwall2 that ends with a letter:
/// `uci show passwall2 | grep ".address=" | cut -d "'" -f 2 | grep "[a-zA-Z]$" | sort -u`.
fn vps_domains(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for s in &cfg.sections {
        for (k, val) in &s.options {
            if !k.ends_with("address") {
                continue;
            }
            let first = match val {
                uci::Value::Single(x) => x.clone(),
                uci::Value::List(l) => l.first().cloned().unwrap_or_default(),
            };
            let cut = first.split('\'').next().unwrap_or("").to_string();
            if cut.chars().last().is_some_and(|c| c.is_ascii_alphabetic()) {
                v.push(cut);
            }
        }
    }
    v.sort();
    v.dedup();
    v.into_iter().map(|w| format!("full:{}", w.to_lowercase())).collect()
}

/// `gen_config(var)`: client config. `var` = the jshn JSON args of upstream `run_xray` / `run_socks`.
/// Always returns a config (like upstream). Loads `/etc/config/passwall2`.
pub fn gen_config(var: &Args) -> Option<Value> {
    let cfg = Config::load(util::CONFIG);
    Some(gen_config_with(&cfg, var))
}

/// [`gen_config`] on an already loaded passwall2 config.
pub fn gen_config_with(cfg: &Config, var: &Args) -> Value {
    build_config(cfg, var, true)
}

fn build_config(cfg: &Config, var: &Args, effects: bool) -> Value {
    let v = |k: &str| var.get(k).cloned();
    let mut flag = v("flag");
    let loglevel = v("loglevel").unwrap_or_else(|| "warning".into());
    let node_id = v("node");
    let server_host = v("server_host");
    let server_port = v("server_port");
    let tcp_proxy_way = v("tcp_proxy_way");
    let redir_port = v("redir_port");
    let local_socks_address = v("local_socks_address").unwrap_or_else(|| "0.0.0.0".into());
    let local_socks_port = v("local_socks_port");
    let local_socks_username = v("local_socks_username");
    let local_socks_password = v("local_socks_password");
    let local_http_address = v("local_http_address").unwrap_or_else(|| "0.0.0.0".into());
    let local_http_port = v("local_http_port");
    let local_http_username = v("local_http_username");
    let local_http_password = v("local_http_password");
    let dns_listen_port = v("dns_listen_port");
    let direct_dns_udp_server = v("direct_dns_udp_server");
    let direct_dns_udp_port = v("direct_dns_udp_port");
    let direct_dns_tcp_server = v("direct_dns_tcp_server");
    let direct_dns_tcp_port = v("direct_dns_tcp_port");
    let direct_dns_query_strategy = v("direct_dns_query_strategy");
    let direct_ipset = v("direct_ipset");
    let direct_nftset = v("direct_nftset");
    let remote_dns_udp_server = v("remote_dns_udp_server");
    let remote_dns_udp_port = v("remote_dns_udp_port");
    let remote_dns_tcp_server = v("remote_dns_tcp_server");
    let remote_dns_tcp_port = v("remote_dns_tcp_port");
    let remote_dns_doh_url = v("remote_dns_doh_url");
    let remote_dns_doh_host = v("remote_dns_doh_host");
    let remote_dns_doh_ip = v("remote_dns_doh_ip");
    let remote_dns_doh_port = v("remote_dns_doh_port");
    let remote_dns_fake_str = v("remote_dns_fake");
    let mut remote_dns_fake = remote_dns_fake_str.is_some();
    let remote_dns_query_strategy = v("remote_dns_query_strategy");
    let remote_dns_detour = v("remote_dns_detour");
    let dns_cache = v("dns_cache");

    let mut g = Gen::new(cfg, effects);
    g.flag = flag.clone();
    g.no_run = var.contains_key("no_run");

    let mut dns_domain_rules: Vec<Value> = vec![];
    let mut fakedns: Option<Vec<Value>> = None;
    let mut routing: Option<Map<String, Value>> = None;
    let mut default_outbound_tag: Option<String> = None; // COMMON.default_outbound_tag
    let mut inner_fakedns: Option<String> = None;

    let cache_text_file = format!("{}/cache_{}.txt", api::CACHE_PATH, flag.clone().unwrap_or_default());

    g.xray = cfg.section("@global_xray[0]").map(node_of).unwrap_or_default();
    let xs = g.xray.clone();

    if neq(&xs, "fragment", "1") {
        let toks = |k: &str| -> Vec<String> {
            // upstream crashes on api.trim(nil); unset is treated as ""
            tokens(&api::trim(&ns(&xs, k).unwrap_or_default()), &[','])
                .into_iter()
                .map(|w| w.chars().filter(|c| !lua_space(*c)).collect::<String>())
                .filter(|w| !w.is_empty())
                .collect()
        };
        let lengths = toks("fragment_lengths");
        let delays = toks("fragment_delays");
        g.fragment_table = Some(json!({
            "type": "fragment",
            "settings": {
                "packets": ns(&xs, "fragment_packets").unwrap_or_else(|| "tlshello".into()),
                "lengths": if lengths.is_empty() { vec!["3-5".to_string(), "6-8".into(), "10-20".into()] } else { lengths },
                "delays": if delays.is_empty() { vec!["10-20".to_string()] } else { delays },
                "maxSplit": ns(&xs, "fragment_maxSplit").unwrap_or_else(|| "3-6".into()),
            }
        }));
    }

    if neq(&xs, "noise", "1") {
        let mut noises = vec![];
        for n in cfg.sections_of("xray_noise_packets") {
            if !n.flag("enabled") {
                continue;
            }
            let ty = n.get("type");
            let packet = n.get("packet");
            let is_rand = ty.as_deref() == Some("rand");
            let num_or_range = |s: &str| -> Option<Value> {
                if s.contains('-') {
                    Some(Value::from(s))
                } else {
                    tonumv(Some(s))
                }
            };
            let mut noise = json!({
                "rand": if is_rand { packet.as_deref().and_then(num_or_range) } else { None },
                "type": if !is_rand { ty.clone() } else { None },
                "packet": if !is_rand { packet.clone() } else { None },
                "delay": n.get("delay").as_deref().and_then(num_or_range),
            });
            prune(&mut noise);
            noises.push(noise);
        }
        g.noise_table = if noises.is_empty() { None } else { Some(json!({ "type": "noise", "settings": { "reset": 0, "noise": noises } })) };
    }

    let mut node: Option<Node> = node_id.as_ref().and_then(|id| cfg.section(id)).map(node_of);

    if let Some(lsp) = &local_socks_port {
        // upstream reads the *unwrapped* node here (and crashes when there is none)
        let override_dest = neq(&xs, "sniffing_override_dest", "1");
        let enabled = override_dest || node.as_ref().is_some_and(|n| neq(n, "protocol", "_shunt"));
        let mut sniffing = json!({ "enabled": enabled });
        if enabled {
            sniffing["destOverride"] = json!(["http", "tls", "quic"]);
            sniffing["routeOnly"] = if !override_dest { Value::from(true) } else { Value::Null };
            sniffing["domainsExcluded"] = if override_dest { get_domain_excluded().map(Value::from).unwrap_or(Value::Null) } else { Value::Null };
        }
        let mut inbound = json!({
            "tag": "socks-in",
            "listen": local_socks_address,
            "port": tonumv(Some(lsp)),
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": sniffing,
        });
        if let (Some(u), Some(p)) = (&local_socks_username, &local_socks_password) {
            if !u.is_empty() && !p.is_empty() {
                inbound["settings"]["auth"] = Value::from("password");
                inbound["settings"]["users"] = json!([{ "user": u, "pass": p }]);
            }
        }
        g.inbounds.push(inbound);
    }

    if let Some(lhp) = &local_http_port {
        let mut inbound = json!({
            "listen": local_http_address,
            "port": tonumv(Some(lhp)),
            "protocol": "http",
            "settings": { "allowTransparent": false },
        });
        if let (Some(u), Some(p)) = (&local_http_username, &local_http_password) {
            if !u.is_empty() && !p.is_empty() {
                inbound["settings"]["users"] = json!([{ "user": u, "pass": p }]);
            }
        }
        g.inbounds.push(inbound);
    }

    if let Some(orig) = node.take() {
        let mut shunt = orig.clone();
        if !neq(&orig, "protocol", "_shunt") {
            // create shunt logic
            shunt = Node::new();
            if let Some(r) = orig.get("remarks") {
                shunt.insert("remarks".into(), r.clone());
            }
            set(&mut shunt, "type", "Xray");
            set(&mut shunt, "protocol", "_shunt");
            if let Some(n) = orig.get(".name") {
                shunt.insert("default_node".into(), n.clone());
            }
            if let Some(f) = &remote_dns_fake_str {
                set(&mut shunt, "fakedns", f.clone());
                set(&mut shunt, "default_fakedns", f.clone());
            }
        }
        if let (Some(h), Some(p)) = (&server_host, &server_port) {
            g.default_node_address = Some(h.clone());
            g.default_node_port = Some(p.clone());
        }

        inner_fakedns = Some(ns(&shunt, "fakedns").unwrap_or_else(|| "0".into()));
        let inner_on = inner_fakedns.as_deref() == Some("1");

        let default_node_id = ns(&shunt, "default_node").unwrap_or_else(|| "_direct".into());
        let default_tag = g.gen_shunt_node(&shunt, "default", Some(default_node_id));
        default_outbound_tag = default_tag.clone();

        if inner_on && neq(&shunt, "default_fakedns", "1") {
            remote_dns_fake = true;
        }

        // gaps §7.1: unset shunt_group ≡ "" (upstream compares nil/strings exactly)
        let shunt_group = ns(&shunt, "shunt_group").unwrap_or_default();
        let rule_sections: Vec<Section> = cfg.sections_of("shunt_rules").cloned().collect();
        for e in rule_sections {
            if e.get("group").unwrap_or_default() != shunt_group {
                continue;
            }
            let ename = e.name.clone();
            let Some(ot) = g.gen_shunt_node(&shunt, &ename, None) else { continue };
            let Some(remarks) = e.get("remarks") else { continue };
            let ot_opt = if ot == "default" { default_tag.clone() } else { Some(ot) };
            let protocols = e.get("protocol").filter(|p| !p.is_empty()).map(|p| tokens(&p, &[' ']));
            let inbound_tag = e.get("inbound").filter(|i| !i.is_empty()).map(|i| {
                let mut t: Vec<String> = vec![];
                if i.contains("tproxy") && redir_port.is_some() {
                    t.push("tcp_redir".into());
                    t.push("udp_redir".into());
                }
                if i.contains("socks") && local_socks_port.is_some() {
                    t.push("socks-in".into());
                }
                t
            });
            let rule_line_ok = |w: &str| !(w.starts_with('#') || w.starts_with("rule-set:") || w.starts_with("rs:") || w.starts_with("ext:"));
            let mut domains: Option<Vec<String>> = None;
            if let Some(dl) = e.get("domain_list") {
                let d: Vec<String> = tokens(&dl, &['\r', '\n']).into_iter().filter(|w| rule_line_ok(w)).collect();
                if !d.is_empty() {
                    let fake = inner_on && neq(&shunt, &format!("{}_fakedns", ename), "1");
                    if ot_opt.is_some() {
                        dns_domain_rules.push(json!({
                            "shunt_rule_name": ename,
                            "outboundTag": ot_opt.clone(),
                            "domain": d.clone(),
                            "fakedns": if fake { Some(true) } else { None },
                        }));
                    }
                    domains = Some(d);
                }
            }
            let ip: Option<Vec<String>> = e.get("ip_list").map(|il| tokens(&il, &['\r', '\n']).into_iter().filter(|w| rule_line_ok(w)).collect::<Vec<_>>()).filter(|l| !l.is_empty());
            let source: Option<Vec<String>> = e.get("source").map(|s| tokens(&s, &[' ']));
            let rule = json!({
                "ruleTag": remarks,
                "inboundTag": inbound_tag,
                "outboundTag": ot_opt.clone(),
                "network": e.get("network").unwrap_or_else(|| "tcp,udp".into()),
                "source": source,
                "port": e.get("port").filter(|p| !p.is_empty()),
                "protocol": protocols,
            });
            if let Some(d) = &domains {
                let mut r = rule.clone();
                r["ruleTag"] = Value::from(format!("{} Domains", remarks));
                r["domains"] = Value::from(d.clone());
                g.rules.push(r);
            }
            if let Some(ip) = &ip {
                let mut r = rule.clone();
                r["ruleTag"] = Value::from(format!("{} IP", remarks));
                r["ip"] = Value::from(ip.clone());
                g.rules.push(r);
            }
            if domains.is_none() && ip.is_none() {
                g.rules.push(rule);
            }
        }

        if let Some(dt) = &default_tag {
            let mut rule = json!({ "ruleTag": "default", "outboundTag": dt });
            if neq(&shunt, "domainStrategy", "IPIfNonMatch") {
                rule["port"] = Value::from("1-65535");
            } else {
                rule["network"] = Value::from("tcp,udp");
            }
            g.rules.push(rule);
        }

        let mut r = Map::new();
        r.insert("domainStrategy".into(), Value::from(ns(&shunt, "domainStrategy").unwrap_or_else(|| "AsIs".into())));
        r.insert("domainMatcher".into(), Value::from(ns(&shunt, "domainMatcher").unwrap_or_else(|| "hybrid".into())));
        r.insert("balancers".into(), if g.balancers.is_empty() { Value::Null } else { Value::from(g.balancers.clone()) });
        routing = Some(r);
        node = Some(shunt);
    }

    // ------------------------------------------------------------------ DNS
    let mut dns_servers: Vec<(Option<String>, Value)> = vec![];
    let mut dns_hosts: Map<String, Value> = Map::new();
    let mut dns_list: Vec<Value> = vec![]; // dns.servers

    for s in g.dns_server.values() {
        dns_servers.push((Some("direct".into()), s.clone()));
    }

    let ddqs = direct_dns_query_strategy.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "UseIP".into());
    let mut direct_dns: Option<Value> = None;
    if let Some(srv) = &direct_dns_udp_server {
        direct_dns = Some(json!({
            "tag": DIRECT_DNS_TAG,
            "address": srv,
            "port": tonumv(direct_dns_udp_port.as_deref()).unwrap_or(Value::from(53)),
            "queryStrategy": ddqs,
        }));
    } else if let Some(srv) = &direct_dns_tcp_server {
        let s = if api::is_ipv6(srv) { api::get_ipv6_full(srv) } else { srv.clone() };
        // upstream errors on a non-numeric port inside the URL; we default to 53
        let p = tonum(direct_dns_tcp_port.as_deref()).unwrap_or(53.0);
        direct_dns = Some(json!({
            "tag": DIRECT_DNS_TAG,
            "address": format!("tcp://{}:{}", s, lnum(p)),
            "port": numv(p),
            "queryStrategy": ddqs,
        }));
    }
    if let Some(d) = &direct_dns {
        dns_servers.push((Some("direct".into()), d.clone()));
    }

    if !g.dns_hostname.is_empty() {
        let mut s = direct_dns.clone().unwrap_or_else(|| json!({ "address": "localhost" }));
        s["tag"] = Value::from("dns-in-bootstrap");
        s["domains"] = Value::from(g.dns_hostname.clone());
        // Lua table.insert(t, #t - 1, v): 0-based index n-2
        let idx = dns_servers.len().saturating_sub(2);
        dns_servers.insert(idx, (Some("direct".into()), s));
    }

    let mut remote_fakedns: Option<Value> = None;
    if let Some(dlp) = &dns_listen_port {
        if routing.is_none() {
            let mut r = Map::new();
            r.insert("domainStrategy".into(), Value::from("IPOnDemand"));
            routing = Some(r);
        }

        let dns_host = if flag.as_deref() == Some("global") {
            cfg.get("@global[0]", "dns_hosts").unwrap_or_default()
        } else {
            let f = flag.clone().unwrap_or_default().replace("acl_", "");
            flag = Some(f.clone());
            match cfg.get(&f, "dns_hosts_mode").unwrap_or_else(|| "default".into()).as_str() {
                "default" => cfg.get("@global[0]", "dns_hosts").unwrap_or_default(),
                "custom" => cfg.get(&f, "dns_hosts").unwrap_or_default(),
                _ => String::new(),
            }
        };
        for w in tokens(&dns_host, &['\r', '\n']) {
            let mut it = w.split_whitespace();
            let host = it.next().unwrap_or("");
            let key = it.next().unwrap_or("");
            if !host.is_empty() && !key.is_empty() {
                dns_hosts.insert(host.to_string(), Value::from(key));
            }
        }

        let mut remote_dns = json!({
            "tag": REMOTE_DNS_TAG,
            "queryStrategy": remote_dns_query_strategy.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "UseIPv4".into()),
        });
        if let Some(srv) = &remote_dns_udp_server {
            remote_dns["address"] = Value::from(srv.clone());
            remote_dns["port"] = tonumv(remote_dns_udp_port.as_deref()).unwrap_or(Value::from(53));
        }
        if let Some(srv) = &remote_dns_tcp_server {
            let s = if api::is_ipv6(srv) { api::get_ipv6_full(srv) } else { srv.clone() };
            let p = tonum(remote_dns_tcp_port.as_deref()).unwrap_or(53.0);
            remote_dns["address"] = Value::from(format!("tcp://{}:{}", s, lnum(p)));
            remote_dns["port"] = numv(p);
        }
        if let (Some(url), Some(host)) = (&remote_dns_doh_url, &remote_dns_doh_host) {
            if let Some(ip) = &remote_dns_doh_ip {
                if host != ip && !api::is_ip(host) {
                    dns_hosts.insert(host.clone(), Value::from(ip.clone()));
                }
            }
            remote_dns["address"] = Value::from(url.clone());
            remote_dns["port"] = tonumv(remote_dns_doh_port.as_deref()).unwrap_or(Value::from(443));
        }
        if vget(&remote_dns, "address").is_some() {
            dns_servers.push((if remote_dns_detour.as_deref() == Some("direct") { Some("direct".into()) } else { None }, remote_dns.clone()));
        }

        if remote_dns_fake || inner_fakedns.as_deref() == Some("1") {
            let v4 = json!({ "ipPool": "198.18.0.0/16", "poolSize": 65535 });
            let v6 = json!({ "ipPool": "2001:2::/48", "poolSize": 65535 });
            fakedns = Some(match remote_dns_query_strategy.as_deref() {
                Some("UseIP") => vec![v4, v6],
                Some("UseIPv4") => vec![v4],
                Some("UseIPv6") => vec![v6],
                _ => vec![],
            });
            let rf = json!({ "tag": REMOTE_FAKEDNS_TAG, "address": "fakedns" });
            dns_servers.push((None, rf.clone()));
            remote_fakedns = Some(rf);
        }

        if direct_dns_udp_server.is_some() || direct_dns_tcp_server.is_some() {
            let domain = vps_domains(cfg);
            if !domain.is_empty() {
                dns_list.insert(
                    0,
                    json!({
                        "tag": "dns-in-vpslist",
                        "address": "localhost",
                        "domains": domain,
                        "finalQuery": true,
                        "disableCache": false,
                        "serveStale": true,
                    }),
                );
            }
        }

        g.inbounds.push(json!({
            "listen": "127.0.0.1",
            "port": tonumv(Some(dlp)),
            "protocol": "tunnel",
            "tag": "dns-in",
            "settings": { "allowedNetwork": "tcp,udp" }
        }));
        let dout = rc(json!({
            "tag": "dns-out",
            "protocol": "dns",
            "streamSettings": { "sockopt": { "dialerProxy": "direct" } },
            "settings": {
                "rewriteAddress": direct_dns_udp_server.clone(),
                "rewritePort": tonumv(direct_dns_udp_port.as_deref()).unwrap_or(Value::from(53)),
                "rewriteNetwork": "udp",
                "rules": [
                    { "qType": "1,28", "action": "hijack" },
                    { "qType": 65, "action": "return", "rCode": 0 },
                    { "action": "direct" }
                ]
            }
        }));
        g.outbounds.push(dout.clone());
        let dns_outbound: Option<Obj> = Some(dout);
        g.rules.insert(0, json!({ "inboundTag": ["dns-in"], "outboundTag": "dns-out" }));

        let default_dns_tag_name = match default_outbound_tag.as_deref() {
            None | Some("direct") => DIRECT_DNS_TAG,
            _ => REMOTE_DNS_TAG,
        };

        if !dns_servers.is_empty() {
            // default DNS
            if let Some(pos) = dns_servers.iter().position(|(_, s)| vstr(s, "tag") == Some(default_dns_tag_name)) {
                let (ot, srv) = dns_servers[pos].clone();
                let mut d_ot = ot.clone();
                let mut d_srv = srv.clone();
                d_srv["tag"] = Value::from(DEFAULT_DNS_TAG);
                if vstr(&srv, "tag") == Some(REMOTE_DNS_TAG) {
                    if remote_dns_fake {
                        let mut f = remote_fakedns.clone().unwrap_or_else(|| json!({}));
                        f["tag"] = Value::from(DEFAULT_DNS_TAG);
                        d_srv = f;
                    } else {
                        d_ot = ot.or_else(|| default_outbound_tag.clone());
                    }
                }
                dns_servers.insert(0, (d_ot, d_srv));
            }

            // shunt rule DNS
            let mut dns_out_rules: Vec<Value> = vec![];
            for rule in &dns_domain_rules {
                let (Some(domain), Some(ot)) = (vget(rule, "domain"), vstr(rule, "outboundTag")) else { continue };
                let mut dns_ot = ot.to_string();
                let mut dns_server: Option<Value> = if ot == "direct" {
                    // upstream crashes (clone(nil)) when there is no direct DNS; skipped
                    direct_dns.clone()
                } else if vget(rule, "fakedns").is_some_and(|f| f == &Value::Bool(true)) {
                    remote_fakedns.clone()
                } else {
                    if remote_dns_detour.as_deref() == Some("direct") {
                        dns_ot = "direct".into();
                    }
                    Some(remote_dns.clone())
                };
                if ot == "blackhole" {
                    dns_out_rules.push(json!({ "action": "return", "rCode": 0, "domain": domain.clone() }));
                    dns_server = None;
                } else {
                    dns_out_rules.push(json!({ "action": "hijack", "qType": "1,28", "domain": domain.clone() }));
                }
                if let Some(mut s) = dns_server {
                    s["finalQuery"] = Value::from(true);
                    s["domains"] = domain.clone();
                    if let Some(n) = vstr(rule, "shunt_rule_name") {
                        s["tag"] = Value::from(format!("dns-in-{}", n));
                    }
                    dns_servers.push((Some(dns_ot), s));
                }
            }
            if !dns_out_rules.is_empty() {
                if let Some(d) = &dns_outbound {
                    let mut b = d.borrow_mut();
                    if let Some(rules) = b["settings"]["rules"].as_array_mut() {
                        for (i, r) in dns_out_rules.into_iter().enumerate() {
                            rules.insert(i, r);
                        }
                    }
                }
            }
        }

        // move the "default" routing rule to the end
        if let Some(i) = g.rules.iter().position(|r| vstr(r, "ruleTag") == Some("default")) {
            let r = g.rules.remove(i);
            g.rules.push(r);
        }

        let mut rules_v = Value::from(g.rules.clone());
        prune(&mut rules_v);
        let content = format!("{}{}{}", flag.clone().unwrap_or_default(), node_id.clone().unwrap_or_default(), rules_v);
        if effects && !api::cache_file_compare_to_logic(&cache_text_file, &content) {
            flush_direct_sets(direct_ipset.as_deref(), direct_nftset.as_deref(), &node_id.clone().unwrap_or_default());
        }
    }

    for i in (0..dns_servers.len()).rev() {
        let (ot, srv) = &dns_servers[i];
        let tag = vstr(srv, "tag");
        if tag == Some(DIRECT_DNS_TAG) || tag == Some(REMOTE_DNS_TAG) {
            continue;
        }
        // DNS rule must be at the front, prevents being matched by rules.
        if let Some(ot) = ot {
            if vstr(srv, "address") != Some("fakedns") && routing.is_some() {
                g.rules.insert(0, json!({ "inboundTag": [tag], "outboundTag": ot }));
            }
        }
        let has_domains = srv.get("domains").and_then(|d| d.as_array()).is_some_and(|d| !d.is_empty());
        if has_domains || tag == Some(DEFAULT_DNS_TAG) {
            dns_list.insert(0, srv.clone());
        }
    }
    if dns_list.is_empty() {
        dns_list.insert(0, json!({ "tag": "local", "address": "localhost" }));
    }

    if let Some(rp) = &redir_port {
        let override_dest = neq(&xs, "sniffing_override_dest", "1");
        let enabled = override_dest || node.as_ref().is_some_and(|n| neq(n, "protocol", "_shunt"));
        let mut sniffing = json!({ "enabled": enabled });
        if enabled {
            sniffing["destOverride"] = json!(["http", "tls", "quic"]);
            sniffing["metadataOnly"] = Value::from(false);
            sniffing["routeOnly"] = if !override_dest { Value::from(true) } else { Value::Null };
            sniffing["domainsExcluded"] = if override_dest { get_domain_excluded().map(Value::from).unwrap_or(Value::Null) } else { Value::Null };
        }
        if remote_dns_fake || inner_fakedns.as_deref() == Some("1") {
            sniffing["enabled"] = Value::from(true);
            match sniffing.get_mut("destOverride").and_then(|d| d.as_array_mut()) {
                Some(d) => {
                    d.push(Value::from("fakedns"));
                    sniffing["metadataOnly"] = Value::from(false);
                }
                None => {
                    sniffing["destOverride"] = json!(["fakedns"]);
                    sniffing["metadataOnly"] = Value::from(true);
                }
            }
        }
        let inbound = json!({
            "port": tonumv(Some(rp)),
            "protocol": "tunnel",
            "settings": { "allowedNetwork": "tcp,udp", "followRedirect": true },
            "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
            "sniffing": sniffing,
        });
        let mut tcp = inbound.clone();
        tcp["tag"] = Value::from("tcp_redir");
        tcp["settings"]["allowedNetwork"] = Value::from("tcp");
        tcp["streamSettings"]["sockopt"]["tproxy"] = tcp_proxy_way.clone().map(Value::from).unwrap_or(Value::Null);
        g.inbounds.push(tcp);
        let mut udp = inbound;
        udp["tag"] = Value::from("udp_redir");
        udp["settings"]["allowedNetwork"] = Value::from("udp");
        g.inbounds.push(udp);
    }

    let direct_outbound = rc(json!({
        "protocol": "freedom",
        "tag": "direct",
        "settings": { "finalRules": [{ "action": "allow" }] },
        "streamSettings": { "sockopt": { "mark": 255, "domainStrategy": ddqs } }
    }));
    if default_outbound_tag.as_deref() == Some("direct") {
        g.outbounds.insert(0, direct_outbound);
    } else {
        g.outbounds.push(direct_outbound);
    }
    let blackhole_outbound = rc(json!({ "protocol": "blackhole", "tag": "blackhole" }));
    if default_outbound_tag.as_deref() == Some("blackhole") {
        g.outbounds.insert(0, blackhole_outbound);
    } else {
        g.outbounds.push(blackhole_outbound);
    }

    let mut outbounds_out: Vec<Value> = vec![];
    for o in &g.outbounds {
        let mut v = o.borrow().clone();
        prune(&mut v);
        if effects && !g.no_run && vget(&v, "_flag_proxy_tag").is_none() {
            if let (Some(id), Some(s)) = (vget(&v, "_id"), vget(&v, "settings")) {
                let first = |k: &str| s.get(k).and_then(|a| a.get(0)).cloned().unwrap_or(Value::Null);
                let (vn, sv, pe) = (first("vnext"), first("servers"), first("peers"));
                let ok = (vget(&vn, "address").is_some() && vget(&vn, "port").is_some())
                    || (vget(&sv, "address").is_some() && vget(&sv, "port").is_some())
                    || vget(&pe, "endpoint").is_some()
                    || (vget(s, "address").is_some() && vget(s, "port").is_some());
                if ok {
                    util::append_file(&format!("{}/direct_node_list", util::TMP_PATH), &val_to_string(id));
                }
            }
        }
        strip_internal(&mut v);
        outbounds_out.push(v);
    }

    let routing_v = routing.map(|mut r| {
        r.insert("rules".into(), Value::from(g.rules.clone()));
        Value::Object(r)
    });
    let dns = json!({
        "tag": "dns-global",
        "hosts": if dns_hosts.is_empty() { Value::Null } else { Value::Object(dns_hosts) },
        "disableCache": dns_cache.as_deref() == Some("0"),
        "disableFallback": true,
        "disableFallbackIfMatch": true,
        "servers": dns_list,
        "queryStrategy": "UseIP",
    });
    let asset = cfg.get("@global_rules[0]", "v2ray_location_asset").unwrap_or_else(|| "/usr/share/v2ray/".into());
    let buffer_size = ns(&xs, "buffer_size").and_then(|b| tonumv(Some(&b)));
    let mut config = json!({
        "env": { "XRAY_LOCATION_ASSET": asset },
        "log": { "loglevel": get_log_level(&loglevel) },
        "dns": dns,
        // spec: an empty fakedns table (upstream `[]`) is left out
        "fakedns": fakedns.filter(|f| !f.is_empty()),
        "inbounds": g.inbounds,
        "outbounds": outbounds_out,
        "observatory": if g.burst_observatory.is_none() { g.observatory.clone() } else { None },
        "burstObservatory": g.burst_observatory.clone(),
        "routing": routing_v,
        "policy": { "levels": { "0": { "bufferSize": buffer_size, "statsUserUplink": false, "statsUserDownlink": false } } },
        "version": { "min": XRAY_MIN_VERSION },
    });
    prune(&mut config);
    config
}

/// ipset/nftset flush when the routing rules changed (cacheFileCompareToLogic == false).
fn flush_direct_sets(direct_ipset: Option<&str>, direct_nftset: Option<&str>, node_id: &str) {
    if let Some(sets) = direct_ipset {
        for w in tokens(sets, &[',']) {
            util::sh(&format!("ipset -q -F {}", util::shq(&w)));
        }
        let prefix = format!("psw2_{}_", node_id);
        let list = util::sh(&format!("ipset list | grep 'Name: ' | grep {} | awk '{{print $2}}'", util::shq(&prefix)));
        for w in tokens(&list, &['\r', '\n']) {
            util::sh(&format!("ipset -q -F {}", util::shq(&w)));
        }
    }
    if let Some(sets) = direct_nftset {
        for w in tokens(sets, &[',']) {
            let split = api::split(&w, "#");
            if split.len() > 3 {
                util::sh(&format!("nft flush set {} {} {} 2>/dev/null", util::shq(&split[1]), util::shq(&split[2]), util::shq(&split[3])));
            }
        }
        let prefix = format!("psw2_{}_", node_id);
        let list = util::sh(&format!("nft -a list sets | grep -E {} | awk -F 'set ' '{{print $2}}' | awk '{{print $1}}'", util::shq(&prefix)));
        for w in tokens(&list, &['\r', '\n']) {
            util::sh(&format!("nft flush set inet passwall2 {} 2>/dev/null", util::shq(&w)));
        }
    }
}

// ====================================================================== gen_proto_config

/// `gen_proto_config(var)`: socks/http inbounds → one upstream (`servers` schema) + direct.
pub fn gen_proto_config(var: &Args) -> Option<Value> {
    let v = |k: &str| var.get(k).cloned();
    let local_socks_address = v("local_socks_address").unwrap_or_else(|| "0.0.0.0".into());
    let local_http_address = v("local_http_address").unwrap_or_else(|| "0.0.0.0".into());
    let mut inbounds = vec![];
    let mut outbounds = vec![];

    let creds = |u: &Option<String>, p: &Option<String>| -> Option<Value> {
        match (u, p) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some(json!([{ "user": u, "pass": p }])),
            _ => None,
        }
    };
    if let Some(port) = v("local_socks_port") {
        let mut inbound = json!({
            "listen": local_socks_address,
            "port": tonumv(Some(&port)),
            "protocol": "socks",
            "settings": { "udp": true, "auth": "noauth" }
        });
        if let Some(users) = creds(&v("local_socks_username"), &v("local_socks_password")) {
            inbound["settings"]["auth"] = Value::from("password");
            inbound["settings"]["users"] = users;
        }
        inbounds.push(inbound);
    }
    if let Some(port) = v("local_http_port") {
        let mut inbound = json!({
            "listen": local_http_address,
            "port": tonumv(Some(&port)),
            "protocol": "http",
            "settings": { "allowTransparent": false }
        });
        if let Some(users) = creds(&v("local_http_username"), &v("local_http_password")) {
            inbound["settings"]["users"] = users;
        }
        inbounds.push(inbound);
    }
    let not_nil = |k: &str| var.get(k).map(|s| s.as_str()) != Some("nil");
    if not_nil("server_proto") && not_nil("server_address") && not_nil("server_port") {
        let users = match (v("server_username"), v("server_password")) {
            (Some(u), Some(p)) => json!([{ "user": u, "pass": p }]),
            _ => Value::Null,
        };
        outbounds.push(json!({
            "protocol": v("server_proto"),
            "streamSettings": { "method": "raw", "security": "none" },
            "settings": {
                "servers": [{
                    "address": v("server_address"),
                    "port": tonumv(v("server_port").as_deref()),
                    "users": users
                }]
            }
        }));
    }
    outbounds.push(json!({
        "protocol": "freedom",
        "tag": "direct",
        "settings": { "finalRules": [{ "action": "allow" }] },
        "streamSettings": { "sockopt": { "mark": 255 } }
    }));
    let mut config = json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "version": { "min": XRAY_MIN_VERSION },
    });
    prune(&mut config);
    Some(config)
}

// ====================================================================== gen_config_server

/// Server config for the `passwall2_server` section `server_id` (type `server`; the stub's
/// "user section" wording refers to upstream's `server` sections whose `users` list points to
/// `user` sections). None if the section does not exist.
pub fn gen_config_server(server_id: &str) -> Option<Value> {
    let cfg_s = Config::load(util::CONFIG_SERVER);
    let node = node_of(cfg_s.section(server_id)?);
    let cfg_c = Config::load(util::CONFIG);
    Some(server_config(&cfg_c, &cfg_s, node, true))
}

/// `gen_config_server(node)` with the server section given as a Lua-like table
/// (`Section::to_json()` of a `passwall2_server` `server` section).
pub fn gen_config_server_node(node: &Node) -> Value {
    let cfg_s = Config::load(util::CONFIG_SERVER);
    let cfg_c = Config::load(util::CONFIG);
    server_config(&cfg_c, &cfg_s, node.clone(), true)
}

/// [`gen_config_server_node`] on already loaded configs (client `passwall2`, server `passwall2_server`).
pub fn gen_config_server_with(cfg_c: &Config, cfg_s: &Config, node: &Node) -> Value {
    server_config(cfg_c, cfg_s, node.clone(), true)
}

fn server_config(cfg_c: &Config, cfg_s: &Config, mut node: Node, effects: bool) -> Value {
    let mut outbounds: Vec<Value> = vec![
        json!({ "protocol": "freedom", "tag": "direct", "settings": { "finalRules": [{ "action": "allow" }] } }),
        json!({ "protocol": "blackhole", "tag": "blocked" }),
    ];
    let proto = ns(&node, "protocol").unwrap_or_default();

    let mut users: Option<Vec<Value>> = None;
    if let Some(ids) = nl(&node, "users").filter(|l| !l.is_empty()) {
        let mut list = vec![];
        for id in ids {
            let Some(us) = cfg_s.section(&id) else { continue };
            if us.stype != "user" {
                continue;
            }
            let user = node_of(us);
            let u = |k: &str| ns(&user, k);
            let mut o = match proto.as_str() {
                "socks" | "http" => json!({ "user": u("username"), "pass": u("password") }),
                "masque" => json!({ "email": u("username"), "pass": u("password") }),
                "shadowsocks" | "trojan" => json!({ "email": u("username"), "password": u("password") }),
                "vmess" => json!({ "email": u("username"), "id": u("uuid"), "alterId": 0 }),
                "vless" => json!({ "email": u("username"), "id": u("uuid"), "flow": ns(&node, "flow") }),
                "hysteria2" => json!({ "email": u("username"), "auth": u("password") }),
                "wireguard" => json!({
                    "publicKey": u("wireguard_public_key"),
                    "preSharedKey": u("wireguard_pre_shared_key"),
                    "keepAlive": 0,
                    "allowedIPs": raw(&user, "allowed_ips"),
                }),
                _ => json!({}),
            };
            prune(&mut o);
            list.push(o);
        }
        if !list.is_empty() {
            users = Some(list);
        }
    }
    let uv = users.clone().map(Value::from);

    let mut settings: Option<Value> = match proto.as_str() {
        "vless" => Some(json!({ "users": uv, "decryption": nne(&node, "decryption").unwrap_or_else(|| "none".into()) })),
        "vmess" | "trojan" => uv.clone().map(|u| json!({ "users": u })),
        "socks" => Some(json!({
            "udp": neq(&node, "udp_forward", "1"),
            "auth": if users.is_some() { "password" } else { "noauth" },
            "users": uv,
        })),
        "http" => {
            set(&mut node, "transport", "raw");
            set(&mut node, "tcp_guise", "none");
            Some(json!({ "allowTransparent": false, "users": uv }))
        }
        "shadowsocks" => Some(json!({
            "method": ns(&node, "ss_method"),
            "password": ns(&node, "ss_password"),
            "users": uv,
            "network": ns(&node, "ss_network").unwrap_or_else(|| "tcp,udp".into()),
        })),
        "hysteria2" => Some(json!({ "version": 2, "users": uv })),
        "masque" => {
            set(&mut node, "transport", "masque");
            set(&mut node, "tls", "1");
            for k in ["reality", "alpn", "fallback", "finalmask"] {
                node.remove(k);
            }
            Some(json!({
                "users": uv,
                "address": raw(&node, "masque_address"),
                "mtu": tonumv(Some(&ns(&node, "masque_mtu").unwrap_or_else(|| "1280".into()))),
            }))
        }
        "tunnel" => Some(json!({
            "allowedNetwork": ns(&node, "d_protocol"),
            "rewriteAddress": ns(&node, "d_address"),
            "rewritePort": tonumv(ns(&node, "d_port").as_deref()),
        })),
        "wireguard" => Some(json!({
            "secretKey": ns(&node, "wireguard_private_key"),
            "mtu": tonumv(Some(&ns(&node, "wireguard_mtu").unwrap_or_else(|| "1420".into()))),
            "peers": uv,
        })),
        _ => None,
    };

    if neq(&node, "fallback", "1") {
        let mut fallbacks = vec![];
        for f in nl(&node, "fallback_list").unwrap_or_default() {
            let tmp = tokens(&f, &[',']);
            let dest_s = tmp.first().cloned().unwrap_or_default();
            let dest = if !dest_s.contains('.') { tonumv(Some(&dest_s)).unwrap_or(Value::Null) } else { Value::from(dest_s) };
            fallbacks.push(json!({
                "path": tmp.get(1).cloned(),
                "dest": dest,
                "xver": tonumv(tmp.get(2).map(|s| s.as_str())),
            }));
        }
        // upstream crashes when settings is nil (vmess/trojan without users); we create it
        let s = settings.get_or_insert_with(|| json!({}));
        s["fallbacks"] = Value::from(fallbacks);
    }

    let accept_lan = ns(&node, "accept_lan");
    let routing = json!({
        "domainStrategy": "IPOnDemand",
        "rules": [{
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "outboundTag": if accept_lan.is_none() || accept_lan.as_deref() == Some("0") { "blocked" } else { "direct" }
        }]
    });

    if let Some(on) = ns(&node, "outbound_node") {
        let mut g = Gen::new(cfg_c, effects);
        let mut outbound: Option<Value> = None;
        let iface = ns(&node, "outbound_node_iface");
        if on == "_iface" && iface.is_some() {
            let iface = iface.unwrap_or_default();
            outbound = Some(json!({
                "protocol": "freedom",
                "tag": "outbound",
                "streamSettings": { "sockopt": { "mark": 255, "interface": iface } },
                "settings": { "finalRules": [{ "action": "allow" }] }
            }));
            g.touch_iface(&iface);
        } else {
            let mut t: Option<Node> = cfg_c.section(&on).map(node_of);
            if on == "_socks" || on == "_http" {
                let mut n = Node::new();
                if let Some(ty) = node.get("type") {
                    n.insert("type".into(), ty.clone());
                }
                set(&mut n, "protocol", on.replace('_', ""));
                set(&mut n, "transport", "raw");
                if let Some(a) = node.get("outbound_node_address") {
                    n.insert("address".into(), a.clone());
                }
                if let Some(p) = node.get("outbound_node_port") {
                    n.insert("port".into(), p.clone());
                }
                if let Some(u) = nne(&node, "outbound_node_username") {
                    set(&mut n, "username", u);
                }
                if let Some(p) = nne(&node, "outbound_node_password") {
                    set(&mut n, "password", p);
                }
                t = Some(n);
            }
            if let Some(mut t) = t {
                outbound = Some(g.gen_outbound(None, &mut t, Some("outbound".into()), None));
            }
        }
        if let Some(o) = outbound {
            outbounds.insert(0, o);
        }
    }

    if proto == "hysteria2" {
        set(&mut node, "protocol", "hysteria");
        set(&mut node, "transport", "hysteria");
        set(&mut node, "tls", "1");
    }

    let gs = |k: &str| ns(&node, k);
    let transport = gs("transport");
    let tp = transport.clone().unwrap_or_default();
    let use_pem = neq(&node, "tls_use_pem", "1");
    let tls_settings = if neq(&node, "tls", "1") {
        json!({
            "disableSystemRoot": false,
            "certificates": [{
                "certificateFile": if !use_pem { gs("tls_certificateFile") } else { None },
                "keyFile": if !use_pem { gs("tls_keyFile") } else { None },
                "certificate": if use_pem { gs("tls_certificate").map(|c| pem_lines(&c)) } else { None },
                "key": if use_pem { gs("tls_key").map(|c| pem_lines(&c)) } else { None },
            }],
            "echServerKeys": if neq(&node, "ech", "1") { gs("ech_key") } else { None },
        })
    } else {
        Value::Null
    };
    // upstream quirk: Lua always emits `header = { type = node.tcp_guise }`, which for an unset
    // tcp_guise becomes an empty header object that Xray rejects (no header type). Without a
    // guise there is nothing to configure, so rawSettings is omitted (Xray's default: no header).
    let raw_settings = match gs("tcp_guise").filter(|g| !g.is_empty() && (tp == "raw" || tp == "tcp")) {
        Some(tg) => {
            let request = if tg == "http" {
                let path: Vec<String> = match nl(&node, "tcp_guise_http_path") {
                    Some(l) => l.into_iter().map(|v| if v.is_empty() { "/".into() } else { v }).collect(),
                    None => vec!["/".into()],
                };
                json!({ "path": path, "headers": { "Host": raw(&node, "tcp_guise_http_host").unwrap_or(json!([])) } })
            } else {
                Value::Null
            };
            json!({ "header": { "type": tg, "request": request } })
        }
        None => Value::Null,
    };
    let kcp_settings = if tp == "mkcp" {
        json!({
            "mtu": tonumv(nne(&node, "mkcp_mtu").as_deref()).unwrap_or(Value::from(1350)),
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "cwndMultiplier": 1,
            "maxSendingWindow": 2 * 1024 * 1024
        })
    } else {
        Value::Null
    };
    let finalmask = {
        let mut fm = json!({});
        if tp == "mkcp" {
            fm["udp"] = mkcp_udp(&node);
        } else if tp == "hysteria" {
            fm["udp"] = Value::from(hysteria_udp(&node));
            let ignore = tonum(gs("hysteria2_ignore_client_bandwidth").as_deref()) == Some(1.0);
            // Lua: (not ignore) and tonumber(x) or 0
            let up = if ignore { 0.0 } else { tonum(gs("hysteria2_up_mbps").as_deref()).unwrap_or(0.0) };
            let down = if ignore { 0.0 } else { tonum(gs("hysteria2_down_mbps").as_deref()).unwrap_or(0.0) };
            fm["quicParams"] = json!({
                "congestion": if up <= 0.0 && down <= 0.0 { "bbr" } else { "brutal" },
                "brutalUp": if up > 0.0 { Some(format!("{}mbps", lnum(up))) } else { None },
                "brutalDown": if down > 0.0 { Some(format!("{}mbps", lnum(down))) } else { None },
            });
        }
        if let Some(over) = nne(&node, "finalmask").and_then(|f| b64_json_table(&f)) {
            fm = over;
        }
        clean(fm).unwrap_or(Value::Null)
    };
    let stream = json!({
        "method": transport,
        "security": "none",
        "masqueSettings": if neq(&node, "protocol", "masque") { json!({ "path": nne(&node, "masque_path") }) } else { Value::Null },
        "tlsSettings": tls_settings,
        "rawSettings": raw_settings,
        "kcpSettings": kcp_settings,
        "wsSettings": if tp == "ws" { json!({ "host": gs("ws_host"), "path": gs("ws_path") }) } else { Value::Null },
        "grpcSettings": match gs("grpc_serviceName") {
            Some(sn) if tp == "grpc" => json!({ "serviceName": sn }),
            _ => Value::Null,
        },
        "httpupgradeSettings": if tp == "httpupgrade" {
            json!({ "path": gs("httpupgrade_path").unwrap_or_else(|| "/".into()), "host": gs("httpupgrade_host") })
        } else { Value::Null },
        "xhttpSettings": if tp == "xhttp" {
            json!({
                "path": gs("xhttp_path").unwrap_or_else(|| "/".into()),
                "host": gs("xhttp_host"),
                "maxUploadSize": gs("xhttp_maxuploadsize"),
                "maxConcurrentUploads": gs("xhttp_maxconcurrentuploads"),
            })
        } else { Value::Null },
        "hysteriaSettings": if tp == "hysteria" { json!({ "version": 2 }) } else { Value::Null },
        "finalmask": finalmask,
        "sockopt": {
            "tcpFastOpen": if neq(&node, "tcp_fast_open", "1") { Some(true) } else { None },
            "acceptProxyProtocol": neq(&node, "acceptProxyProtocol", "1"),
        }
    });
    let log_on = neq(&node, "log", "1");
    let loglevel = (if log_on { gs("loglevel").map(|l| get_log_level(&l)) } else { None }).unwrap_or_else(|| "none".into());
    let mut inbound = json!({
        "listen": "::",
        "port": tonumv(gs("port").as_deref()),
        "protocol": gs("protocol"),
        "settings": settings,
        "streamSettings": stream,
    });

    let alpn = alpn_list(&node);
    if !alpn.is_empty() && vget(&inbound["streamSettings"], "tlsSettings").is_some() {
        inbound["streamSettings"]["tlsSettings"]["alpn"] = Value::from(alpn);
    }
    if neq(&node, "tls", "1") {
        inbound["streamSettings"]["security"] = Value::from("tls");
        if neq(&node, "reality", "1") {
            if let Some(m) = inbound["streamSettings"].as_object_mut() {
                m.remove("tlsSettings");
            }
            inbound["streamSettings"]["security"] = Value::from("reality");
            inbound["streamSettings"]["realitySettings"] = json!({
                "show": false,
                "dest": gs("reality_dest"),
                // upstream quirk: Lua passes the stored value through (`or {}` / `or ""`), so an
                // option-style string or an unset short id list gives a string, which Xray rejects
                // ([]string). We always emit a list; unset short ids become [""] (empty short id).
                "serverNames": nl(&node, "reality_serverNames").unwrap_or_default(),
                "privateKey": gs("reality_private_key"),
                "shortIds": nl(&node, "reality_shortId").unwrap_or_else(|| vec![String::new()]),
                "mldsa65Seed": if neq(&node, "use_mldsa65Seed", "1") { gs("reality_mldsa65Seed") } else { None },
                "minClientVer": "1.0.0",
            });
        }
    }

    for o in outbounds.iter_mut() {
        strip_internal(o);
    }
    let mut config = json!({
        "log": { "loglevel": loglevel },
        "inbounds": [inbound],
        "outbounds": outbounds,
        "routing": routing,
        "version": { "min": XRAY_MIN_VERSION },
    });
    prune(&mut config);
    config
}

// ====================================================================== CLI

/// `passwall2 xray <gen_config|gen_proto_config|gen_config_server> '<json>'`
/// (`gen_config_server` takes a server section id or the section as a JSON object).
/// Prints the config as pretty JSON (Lua `print(func(var))`; `nil` when there is no result).
pub fn cli(args: &[String]) -> i32 {
    let Some(func) = args.first().map(|s| s.as_str()) else {
        eprintln!("usage: passwall2 xray <gen_config|gen_proto_config|gen_config_server> '<json>'");
        return 1;
    };
    let arg = args.get(1).cloned().unwrap_or_default();
    let result = match func {
        "gen_config" => gen_config(&util::args_from_json(&arg)),
        "gen_proto_config" => gen_proto_config(&util::args_from_json(&arg)),
        "gen_config_server" => {
            let t = arg.trim();
            if t.starts_with('{') {
                match serde_json::from_str::<Value>(t) {
                    Ok(Value::Object(m)) => Some(gen_config_server_node(&m)),
                    _ => None,
                }
            } else {
                gen_config_server(t)
            }
        }
        _ => return 1,
    };
    match result {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| "nil".into())),
        None => println!("nil"),
    }
    0
}
