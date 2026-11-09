//! Clash YAML subscription converter (clash_subconverter.lua). Spec: docs/spec/06 §2.
//!
//! [`parse_clash_node`] turns a Clash/mihomo document into share links (one per line) that the
//! regular link parser understands; [`parse_clash_sub_info`] reads the
//! `Subscription-Userinfo` response header. YAML is loaded with the built-in [`super::yaml`]
//! loader (upstream: lyaml).

use super::links::lua_num;
use super::yaml::{self, Yaml};
use crate::api;
use crate::util;
use serde_json::{Map as JMap, Value as J};
use std::collections::HashMap;

/// Node-domain resolver extracted from the Clash `dns:` block.
#[derive(Clone, Debug, PartialEq)]
pub struct Resolver {
    /// `udp` | `tcp` | `https`
    pub domain_resolver: String,
    /// `ip:port` for udp/tcp
    pub domain_resolver_dns: Option<String>,
    /// DoH URL for https
    pub domain_resolver_dns_https: Option<String>,
}

/// Account information from the `Subscription-Userinfo` header.
#[derive(Clone, Debug, PartialEq)]
pub struct SubInfo {
    pub rem_traffic: String,
    pub expired_date: String,
}

/// Outcome of encoding one proxy.
enum Enc {
    Link(String),
    /// `return 1, msg` (logged at level 2)
    Msg(String),
    /// nothing returned (unsupported type, already logged)
    Nothing,
}

/// A Lua runtime error inside `encode_node` (pcall → "conversion failed").
struct Fail;

type ER = Result<Enc, Fail>;

// ------------------------------------------------------------------------------ value helpers

fn get<'a>(n: &'a Yaml, k: &str) -> Option<&'a Yaml> {
    n.get(k)
}
fn truthy(v: Option<&Yaml>) -> bool {
    v.is_some_and(|x| x.truthy())
}
/// Lua `a or b`
fn or<'a>(a: Option<&'a Yaml>, b: Option<&'a Yaml>) -> Option<&'a Yaml> {
    if truthy(a) {
        a
    } else {
        b.filter(|x| x.truthy())
    }
}
/// `tostring(v)` (tables: first array element, as the only sensible text)
fn tostr(v: &Yaml) -> String {
    match v {
        Yaml::Null => String::new(),
        Yaml::Bool(b) => b.to_string(),
        Yaml::Str(s) => s.clone(),
        Yaml::Num(s) => super::yaml::num_text(s),
        Yaml::Seq(s) => s.first().map(tostr).unwrap_or_default(),
        Yaml::Map(_) => String::new(),
    }
}
/// `..` concatenation: strings and numbers only, anything else raises.
fn cat(v: Option<&Yaml>) -> Result<String, Fail> {
    match v {
        Some(Yaml::Str(s)) => Ok(s.clone()),
        Some(Yaml::Num(s)) => Ok(super::yaml::num_text(s)),
        _ => Err(Fail),
    }
}
/// add_param value: nil/"" skipped, booleans → 1/0.
fn pval(v: Option<&Yaml>) -> Option<String> {
    match v? {
        Yaml::Null => None,
        Yaml::Bool(b) => Some(if *b { "1".into() } else { "0".into() }),
        Yaml::Str(s) if s.is_empty() => None,
        other => Some(tostr(other)),
    }
}
fn urlencode(v: &str) -> String {
    api::url_encode(v)
}
fn add(p: &mut Vec<String>, key: &str, v: Option<String>) {
    if let Some(v) = v.filter(|s| !s.is_empty()) {
        p.push(format!("{}={}", key, urlencode(&v)));
    }
}
fn add_b(p: &mut Vec<String>, key: &str, v: bool) {
    p.push(format!("{}={}", key, if v { "1" } else { "0" }));
}
fn finish_link(mut link: String, p: &[String], name: Option<&Yaml>) -> Enc {
    if !p.is_empty() {
        link.push('?');
        link.push_str(&p.join("&"));
    }
    Enc::Link(format!("{}#{}", link, urlencode(&name.map(tostr).unwrap_or_default())))
}

/// `host_format(h)`: IPv6 (bare or in brackets) → `[addr]`, anything else unchanged.
fn host_format(h: Option<&Yaml>) -> String {
    let Some(h) = h else { return String::new() };
    let h = tostr(h);
    let inner = match (h.find('['), h.find(']')) {
        (Some(i), Some(_)) => h[i + 1..].split(']').next().unwrap_or("").to_string(),
        _ => h.clone(),
    };
    if api::dt_ip6addr(&inner) {
        format!("[{}]", inner)
    } else {
        h
    }
}

/// `build_alpn(alpn)`: only h3, h2, http/1.1 in that order, deduplicated.
fn build_alpn(alpn: Option<&Yaml>) -> Option<String> {
    let alpn = alpn?;
    let seen: Vec<String> = match alpn {
        Yaml::Seq(items) => items.iter().filter_map(|x| x.scalar_text()).collect(),
        Yaml::Map(_) => vec![],
        other => vec![tostr(other)],
    };
    let t: Vec<&str> = ["h3", "h2", "http/1.1"].into_iter().filter(|o| seen.iter().any(|s| s == o)).collect();
    if t.is_empty() {
        None
    } else {
        Some(t.join(","))
    }
}

/// `build_ech(node)`
fn build_ech(node: &Yaml) -> Result<Option<String>, Fail> {
    let Some(opts) = get(node, "ech-opts").filter(|o| matches!(o, Yaml::Map(_))) else { return Ok(None) };
    if get(opts, "enable") != Some(&Yaml::Bool(true)) {
        return Ok(None);
    }
    if let Some(c) = get(opts, "config").filter(|c| c.truthy() && **c != Yaml::Str(String::new())) {
        return Ok(Some(tostr(c)));
    }
    let mut name = get(opts, "query-server-name").filter(|n| **n != Yaml::Str(String::new()) && n.truthy());
    if name.is_none() {
        name = or(or(get(node, "servername"), get(node, "sni")), get(node, "server"));
    }
    if name == Some(&Yaml::Str(String::new())) {
        name = get(node, "server");
    }
    Ok(Some(format!("{}+https://223.5.5.5/dns-query", cat(name)?)))
}

/// `bandwidth_mbps(v)`: number, or `"<n> [KMGT]bps|Bps"` → Mbps; None when invalid.
fn bandwidth_mbps(v: &Yaml) -> Option<f64> {
    if let Some(n) = v.num() {
        return Some(n);
    }
    let s = tostr(v);
    let t = s.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let rest = t[digits.len()..].trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let (scale, rest) = match rest.chars().next() {
        Some('K') => (1e3, &rest[1..]),
        Some('M') => (1e6, &rest[1..]),
        Some('G') => (1e9, &rest[1..]),
        Some('T') => (1e12, &rest[1..]),
        _ => (1.0, rest),
    };
    let mult = match rest {
        "Bps" => 8.0,
        "bps" => 1.0,
        _ => return None,
    };
    let amount: f64 = digits.parse().ok()?;
    Some(amount * scale * mult / 1e6)
}

/// `inherit(base, overrides)`: shallow merge of two mappings.
fn inherit(base: &Yaml, over: &Yaml) -> Result<Yaml, Fail> {
    let mut m: Vec<(String, Yaml)> = vec![];
    for t in [base, over] {
        match t {
            Yaml::Map(src) => {
                for (k, v) in src {
                    if let Some(e) = m.iter_mut().find(|(x, _)| x == k) {
                        e.1 = v.clone();
                    } else {
                        m.push((k.clone(), v.clone()));
                    }
                }
            }
            Yaml::Null | Yaml::Seq(_) | Yaml::Bool(false) => {}
            // pairs() over a string/number raises
            _ => return Err(Fail),
        }
    }
    Ok(Yaml::Map(m))
}

const XHTTP_FIELDS: [(&str, &str); 20] = [
    ("headers", "headers"),
    ("x-padding-bytes", "xPaddingBytes"),
    ("no-grpc-header", "noGRPCHeader"),
    ("x-padding-obfs-mode", "xPaddingObfsMode"),
    ("x-padding-key", "xPaddingKey"),
    ("x-padding-header", "xPaddingHeader"),
    ("x-padding-placement", "xPaddingPlacement"),
    ("x-padding-method", "xPaddingMethod"),
    ("uplink-http-method", "uplinkHTTPMethod"),
    ("session-placement", "sessionIDPlacement"),
    ("session-key", "sessionIDKey"),
    ("session-table", "sessionIDTable"),
    ("session-length", "sessionIDLength"),
    ("seq-placement", "seqPlacement"),
    ("seq-key", "seqKey"),
    ("uplink-data-placement", "uplinkDataPlacement"),
    ("uplink-data-key", "uplinkDataKey"),
    ("uplink-chunk-size", "uplinkChunkSize"),
    ("sc-max-each-post-bytes", "scMaxEachPostBytes"),
    ("sc-min-posts-interval-ms", "scMinPostsIntervalMs"),
];

const XMUX_FIELDS: [(&str, &str); 5] = [
    ("max-concurrency", "maxConcurrency"),
    ("max-connections", "maxConnections"),
    ("c-max-reuse-times", "cMaxReuseTimes"),
    ("h-max-request-times", "hMaxRequestTimes"),
    ("h-max-reusable-secs", "hMaxReusableSecs"),
];

/// `build_xhttp_extra(opts)`: Clash xhttp-opts → Xray `extra` keys.
fn build_xhttp_extra(opts: &Yaml) -> JMap<String, J> {
    let mut extra = JMap::new();
    for (src, dst) in XHTTP_FIELDS {
        if let Some(v) = get(opts, src) {
            if src == "headers" {
                match v {
                    Yaml::Map(m) if m.is_empty() => continue,
                    Yaml::Seq(s) if s.is_empty() => continue,
                    _ => {}
                }
            }
            extra.insert(dst.to_string(), v.to_json());
        }
    }
    if let Some(reuse) = get(opts, "reuse-settings").filter(|r| r.truthy()) {
        let mut xmux = JMap::new();
        for (src, dst) in XMUX_FIELDS {
            if let Some(v) = get(reuse, src) {
                let jv = match v.num() {
                    Some(n) => yaml::num_json(n),
                    None => v.to_json(),
                };
                xmux.insert(dst.to_string(), jv);
            }
        }
        if let Some(n) = get(reuse, "h-keep-alive-period").and_then(|v| v.num()) {
            xmux.insert("hKeepAlivePeriod".into(), yaml::num_json(n));
        }
        if !xmux.is_empty() {
            extra.insert("xmux".into(), J::Object(xmux));
        }
    }
    extra
}

// ------------------------------------------------------------------------------ build_common

#[derive(Default)]
struct Tls {
    security: Option<String>,
    pbk: Option<String>,
    sid: Option<String>,
    sni: Option<String>,
    fp: Option<String>,
    pcs: Option<String>,
    vcn: Option<String>,
    insecure: bool,
    alpn: Option<String>,
    ech: Option<String>,
}

#[derive(Default)]
struct Transport {
    ty: String,
    host: Option<String>,
    path: Option<String>,
    service_name: Option<String>,
    header_type: Option<String>,
    mode: Option<String>,
    extra: Option<String>,
}

struct Common {
    server: String,
    port: Option<Yaml>,
    name: Option<Yaml>,
    tls: Tls,
    tr: Transport,
}

/// `get_first(v)`: first element of a list, or v itself.
fn get_first(v: Option<&Yaml>) -> Option<&Yaml> {
    match v? {
        Yaml::Seq(s) => s.first().filter(|x| !matches!(x, Yaml::Null)),
        Yaml::Map(_) => None,
        other => Some(other),
    }
}

fn build_common(node: &Yaml, redir: &HashMap<String, String>) -> Result<Common, Fail> {
    let mut tls = Tls::default();
    if let Some(r) = get(node, "reality-opts").filter(|r| r.truthy()) {
        tls.security = Some("reality".into());
        tls.pbk = pval(get(r, "public-key"));
        tls.sid = pval(get(r, "short-id"));
    } else if truthy(get(node, "tls")) {
        tls.security = Some("tls".into());
    }
    tls.sni = pval(or(get(node, "servername"), get(node, "sni")));
    tls.fp = pval(get(node, "client-fingerprint"));
    tls.pcs = pval(get(node, "fingerprint"));
    tls.vcn = pval(get(node, "name-cert-verify"));
    tls.insecure = get(node, "skip-cert-verify") == Some(&Yaml::Bool(true));
    tls.alpn = build_alpn(get(node, "alpn"));
    tls.ech = build_ech(node)?;

    let net = get(node, "network").filter(|v| v.truthy()).map(tostr).unwrap_or_else(|| "tcp".into());
    let mut tr = Transport { ty: net.clone(), ..Default::default() };
    match net.as_str() {
        "ws" => {
            if let Some(opts) = get(node, "ws-opts").filter(|o| o.truthy()) {
                let upgrade = get(opts, "v2ray-http-upgrade") == Some(&Yaml::Bool(true));
                let mut path = match get(opts, "path").filter(|v| v.truthy()) {
                    Some(p) => cat(Some(p))?,
                    None => "/".to_string(),
                };
                if !upgrade {
                    if let Some(ed) = get(opts, "max-early-data").filter(|v| v.truthy()) {
                        path = format!("{}{}{}", path, if path.contains('?') { "&ed=" } else { "?ed=" }, cat(Some(ed))?);
                    }
                    if let Some(eh) = get(opts, "early-data-header-name").filter(|v| v.truthy()) {
                        path = format!("{}{}{}", path, if path.contains('?') { "&eh=" } else { "?eh=" }, cat(Some(eh))?);
                    }
                }
                tr.path = Some(path);
                tr.host = get(opts, "headers").and_then(|h| pval(get_first(get(h, "Host"))));
                if upgrade {
                    tr.ty = "httpupgrade".into();
                }
            }
        }
        "grpc" => {
            if let Some(opts) = get(node, "grpc-opts").filter(|o| o.truthy()) {
                tr.service_name = pval(get(opts, "grpc-service-name"));
            }
        }
        "http" => {
            // TCP + HTTP camouflage so each core selects its matching transport
            tr.ty = "tcp".into();
            tr.header_type = Some("http".into());
            tr.host = pval(get(node, "server"));
            tr.path = Some("/".into());
            if let Some(opts) = get(node, "http-opts").filter(|o| o.truthy()) {
                let h = or(get_first(get(opts, "host")), get(opts, "headers").and_then(|h| get_first(get(h, "Host"))));
                if let Some(h) = pval(h) {
                    tr.host = Some(h);
                }
                if let Some(p) = pval(get_first(get(opts, "path"))) {
                    tr.path = Some(p);
                }
            }
        }
        "h2" => {
            if let Some(opts) = get(node, "h2-opts").filter(|o| o.truthy()) {
                tr.host = pval(get_first(get(opts, "host")));
                tr.path = pval(get(opts, "path"));
            }
        }
        "xhttp" => {
            if let Some(opts) = get(node, "xhttp-opts").filter(|o| o.truthy()) {
                tr.host = pval(get(opts, "host"));
                tr.path = pval(get(opts, "path"));
                tr.mode = pval(get(opts, "mode"));
                let mut extra = build_xhttp_extra(opts);
                if let Some(d) = get(opts, "download-settings").filter(|d| d.truthy()) {
                    let eff = inherit(node, d)?;
                    let eserver = get(&eff, "server");
                    let addr = eserver.map(tostr).and_then(|s| redir.get(&s).cloned()).map(J::String).or_else(|| eserver.map(|v| v.to_json()));
                    let mut ds = JMap::new();
                    if let Some(a) = addr {
                        ds.insert("address".into(), a);
                    }
                    if let Some(p) = get(&eff, "port") {
                        ds.insert("port".into(), p.to_json());
                    }
                    ds.insert("network".into(), "xhttp".into());
                    let etls = truthy(get(&eff, "tls"));
                    ds.insert("security".into(), if etls { "tls" } else { "none" }.into());
                    let sni = or(or(get(&eff, "servername"), get(&eff, "sni")), get(&eff, "server")).cloned();
                    let alpn = build_alpn(get(&eff, "alpn"));
                    let reality = get(&eff, "reality-opts").filter(|r| r.truthy()).cloned();
                    if etls || reality.is_some() {
                        let mut t = JMap::new();
                        if let Some(s) = &sni {
                            t.insert("serverName".into(), s.to_json());
                        }
                        t.insert("allowInsecure".into(), J::Bool(get(&eff, "skip-cert-verify") == Some(&Yaml::Bool(true))));
                        if let Some(f) = get(&eff, "client-fingerprint") {
                            t.insert("fingerprint".into(), f.to_json());
                        }
                        if let Some(f) = get(&eff, "fingerprint").filter(|f| f.truthy()) {
                            t.insert("pinnedPeerCertSha256".into(), J::String(api::sha256_sb_xray(&tostr(f))));
                        }
                        if let Some(v) = get(&eff, "name-cert-verify") {
                            t.insert("verifyPeerCertByName".into(), v.to_json());
                        }
                        if let Some(a) = &alpn {
                            t.insert("alpn".into(), J::Array(api::split(a, ",").into_iter().map(J::String).collect()));
                        }
                        if let Some(e) = build_ech(&eff)? {
                            t.insert("echConfigList".into(), J::String(e));
                        }
                        ds.insert("tlsSettings".into(), J::Object(t));
                        if let Some(r) = reality {
                            ds.insert("security".into(), "reality".into());
                            let mut rs = JMap::new();
                            if let Some(s) = &sni {
                                rs.insert("serverName".into(), s.to_json());
                            }
                            rs.insert("fingerprint".into(), get(&eff, "client-fingerprint").filter(|v| v.truthy()).map(|v| v.to_json()).unwrap_or_else(|| "chrome".into()));
                            if let Some(pk) = get(&r, "public-key") {
                                rs.insert("publicKey".into(), pk.to_json());
                            }
                            rs.insert("shortId".into(), get(&r, "short-id").filter(|v| v.truthy()).map(|v| v.to_json()).unwrap_or_else(|| "".into()));
                            ds.insert("realitySettings".into(), J::Object(rs));
                            ds.remove("tlsSettings");
                        }
                    }
                    let mut xs = build_xhttp_extra(&inherit(opts, d)?);
                    let path = or(or(get(d, "path"), get(opts, "path")), None).map(|v| v.to_json()).unwrap_or_else(|| "/".into());
                    xs.insert("path".into(), path);
                    if let Some(h) = or(or(get(d, "host"), get(opts, "host")), sni.as_ref()) {
                        xs.insert("host".into(), h.to_json());
                    }
                    xs.insert("mode".into(), get(opts, "mode").filter(|v| v.truthy()).map(|v| v.to_json()).unwrap_or_else(|| "auto".into()));
                    ds.insert("xhttpSettings".into(), J::Object(xs));
                    extra.insert("downloadSettings".into(), J::Object(ds));
                }
                if !extra.is_empty() {
                    tr.extra = Some(J::Object(extra).to_string());
                }
            }
        }
        _ => {}
    }
    Ok(Common { server: host_format(get(node, "server")), port: get(node, "port").cloned(), name: get(node, "name").cloned(), tls, tr })
}

// ------------------------------------------------------------------------------ encoders

fn tls_params(p: &mut Vec<String>, o: &Common) {
    add(p, "security", o.tls.security.clone());
    add(p, "pbk", o.tls.pbk.clone());
    add(p, "sid", o.tls.sid.clone());
    add(p, "sni", o.tls.sni.clone());
    add(p, "fp", o.tls.fp.clone());
    add(p, "alpn", o.tls.alpn.clone());
    add(p, "ech", o.tls.ech.clone());
    add(p, "pcs", o.tls.pcs.clone());
    add(p, "vcn", o.tls.vcn.clone());
    add_b(p, "allowInsecure", o.tls.insecure);
}

fn encode_vless(node: &Yaml, redir: &HashMap<String, String>) -> ER {
    let o = build_common(node, redir)?;
    let link = format!("vless://{}@{}:{}", cat(get(node, "uuid"))?, o.server, cat(o.port.as_ref())?);
    let mut p = vec![];
    if let Some(Yaml::Str(flow)) = get(node, "flow") {
        if flow.starts_with("xtls-") {
            add(&mut p, "flow", Some(flow.clone()));
        }
    }
    add(&mut p, "encryption", pval(get(node, "encryption")));
    tls_params(&mut p, &o);
    add(&mut p, "type", Some(o.tr.ty.clone()));
    add(&mut p, "headerType", o.tr.header_type.clone());
    add(&mut p, "host", o.tr.host.clone());
    add(&mut p, "path", o.tr.path.clone());
    add(&mut p, "serviceName", o.tr.service_name.clone());
    add(&mut p, "mode", o.tr.mode.clone());
    add(&mut p, "extra", o.tr.extra.clone());
    Ok(finish_link(link, &p, o.name.as_ref()))
}

fn encode_trojan(node: &Yaml, redir: &HashMap<String, String>) -> ER {
    let o = build_common(node, redir)?;
    let pw = get(node, "password").map(tostr).unwrap_or_default();
    let link = format!("trojan://{}@{}:{}", urlencode(&pw), o.server, cat(o.port.as_ref())?);
    let mut p = vec![];
    tls_params(&mut p, &o);
    add(&mut p, "type", Some(o.tr.ty.clone()));
    add(&mut p, "headerType", o.tr.header_type.clone());
    add(&mut p, "host", o.tr.host.clone());
    add(&mut p, "path", o.tr.path.clone());
    add(&mut p, "serviceName", o.tr.service_name.clone());
    Ok(finish_link(link, &p, o.name.as_ref()))
}

fn encode_vmess(node: &Yaml, redir: &HashMap<String, String>) -> ER {
    let o = build_common(node, redir)?;
    let mut obj = JMap::new();
    let mut put = |k: &str, v: Option<J>| {
        if let Some(v) = v {
            obj.insert(k.to_string(), v);
        }
    };
    let js = |v: Option<&Yaml>| v.map(|x| x.to_json());
    let jo = |v: &Option<String>| v.clone().map(J::String);
    put("v", Some("2".into()));
    put("ps", o.name.as_ref().map(|n| n.to_json()));
    put("add", js(get(node, "server")));
    put("port", Some(J::String(o.port.as_ref().map(tostr).unwrap_or_else(|| "nil".into()))));
    put("id", js(get(node, "uuid")));
    put("aid", Some(J::String(get(node, "alterId").filter(|v| v.truthy()).map(tostr).unwrap_or_else(|| "0".into()))));
    put("net", Some(J::String(o.tr.ty.clone())));
    put("security", js(get(node, "cipher")));
    put("scy", js(get(node, "cipher")));
    put("type", Some(J::String(o.tr.header_type.clone().unwrap_or_else(|| "none".into()))));
    put("host", Some(J::String(o.tr.host.clone().unwrap_or_default())));
    let path = if o.tr.ty == "grpc" { o.tr.service_name.clone() } else { o.tr.path.clone() };
    put("path", Some(J::String(urlencode(&path.unwrap_or_default()))));
    put("tls", Some(J::String(if o.tls.security.as_deref() == Some("tls") { "tls".into() } else { String::new() })));
    put("sni", jo(&o.tls.sni));
    put("alpn", jo(&o.tls.alpn));
    put("fp", jo(&o.tls.fp));
    put("ech", jo(&o.tls.ech));
    put("pcs", jo(&o.tls.pcs));
    put("vcn", jo(&o.tls.vcn));
    put("insecure", Some(J::String(if o.tls.insecure { "1".into() } else { "0".into() })));
    put("tfo", Some(J::String(if truthy(get(node, "tfo")) { "1".into() } else { "0".into() })));
    Ok(Enc::Link(format!("vmess://{}", api::base64_encode(J::Object(obj).to_string().as_bytes()))))
}

const SS_METHODS: [&str; 18] = [
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

fn encode_ss(node: &Yaml) -> ER {
    let name = get(node, "name").map(tostr).unwrap_or_default();
    let cipher = get(node, "cipher").map(tostr).unwrap_or_default();
    if !SS_METHODS.contains(&cipher.as_str()) {
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard SS node %s, unsupported cipher: %s", &[&name, &cipher])));
    }
    let base = format!("{}:{}@{}:{}", cat(get(node, "cipher"))?, cat(get(node, "password"))?, host_format(get(node, "server")), cat(get(node, "port"))?);
    // upstream used standard base64, whose '+' the ss parser's UrlDecode turns into a space
    // (such nodes were silently lost); the url-safe alphabet decodes identically
    let b64 = api::base64_encode(base.as_bytes()).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
    let link = format!("ss://{}", b64);
    let mut p = vec![];
    if truthy(get(node, "udp")) {
        add_b(&mut p, "udp", true);
    }
    if truthy(get(node, "udp-over-tcp")) {
        add_b(&mut p, "uot", true);
    }
    if let Some(pl) = get(node, "plugin").filter(|v| v.truthy()) {
        let pl = tostr(pl);
        let plugin = if pl == "obfs" { "obfs-local".to_string() } else { pl };
        let popts = get(node, "plugin-opts").filter(|v| v.truthy());
        if plugin == "shadow-tls" {
            let json = match popts {
                Some(v) => v.to_json(),
                None => J::Object(JMap::new()),
            };
            add(&mut p, "shadow-tls", Some(api::base64_encode(json.to_string().as_bytes())));
        } else if plugin == "obfs-local" || plugin == "v2ray-plugin" {
            let mut opts: Vec<String> = vec![];
            let pairs: Vec<(String, Yaml)> = match popts {
                None => vec![],
                Some(Yaml::Map(m)) => m.clone(),
                Some(Yaml::Seq(s)) => s.iter().enumerate().map(|(i, v)| ((i + 1).to_string(), v.clone())).collect(),
                Some(_) => return Err(Fail),
            };
            for (k0, v0) in pairs {
                if matches!(v0, Yaml::Null) {
                    continue;
                }
                let mut k = k0;
                let mut v = Some(v0);
                if plugin == "obfs-local" {
                    if k == "mode" {
                        k = "obfs".into();
                    }
                    if k == "host" {
                        k = "obfs-host".into();
                    }
                } else if k == "mode" && v.as_ref().map(tostr).as_deref() == Some("websocket") && matches!(v, Some(Yaml::Str(_))) {
                    v = None;
                } else if let Some(Yaml::Bool(b)) = v {
                    if b {
                        opts.push(k.clone());
                    }
                    v = None;
                }
                if let Some(v) = v {
                    let vs = match v {
                        Yaml::Bool(b) => if b { "1".to_string() } else { "0".to_string() },
                        Yaml::Str(s) => s,
                        Yaml::Num(s) => super::yaml::num_text(&s),
                        _ => return Err(Fail),
                    };
                    opts.push(format!("{}={}", k, vs));
                }
            }
            let plugin = if opts.is_empty() { plugin } else { format!("{};{}", plugin, opts.join(";")) };
            add(&mut p, "plugin", Some(plugin));
        } else {
            return Ok(Enc::Msg(api::translatef("Subscription conversion: discard SS node %s, unsupported plugin: %s", &[&name, &plugin])));
        }
    }
    Ok(finish_link(link, &p, get(node, "name")))
}

fn num_param(v: Option<f64>) -> Option<String> {
    v.map(lua_num)
}

fn encode_hysteria(node: &Yaml, up: Option<f64>, down: Option<f64>) -> ER {
    if let Some(proto) = get(node, "protocol").filter(|v| v.truthy()) {
        if tostr(proto) != "udp" {
            let name = get(node, "name").map(tostr).unwrap_or_default();
            return Ok(Enc::Msg(api::translatef("Subscription conversion: discard Hysteria node %s, unsupported transport: %s", &[&name, &tostr(proto)])));
        }
    }
    let port = match get(node, "port").filter(|v| v.truthy()) {
        Some(p) => cat(Some(p))?,
        None => String::new(),
    };
    let link = format!("hysteria://{}:{}", host_format(get(node, "server")), port);
    let mut p = vec![];
    add(&mut p, "auth", pval(get(node, "auth-str")));
    add(&mut p, "mport", pval(get(node, "ports")));
    add(&mut p, "obfsParam", pval(get(node, "obfs")));
    add(&mut p, "sni", pval(get(node, "sni")));
    add(&mut p, "upmbps", num_param(up));
    add(&mut p, "downmbps", num_param(down));
    add_b(&mut p, "insecure", get(node, "skip-cert-verify") == Some(&Yaml::Bool(true)));
    add(&mut p, "vcn", pval(get(node, "name-cert-verify")));
    add(&mut p, "pinSHA256", pval(get(node, "fingerprint")));
    add(&mut p, "alpn", build_alpn(get(node, "alpn")));
    Ok(finish_link(link, &p, get(node, "name")))
}

fn encode_hysteria2(node: &Yaml, up: Option<f64>, down: Option<f64>) -> ER {
    // hopping subscriptions may omit port; use the first number of `ports`
    let port = match get(node, "port").filter(|v| v.truthy()) {
        Some(p) => cat(Some(p))?,
        None => {
            let ports = get(node, "ports").map(tostr).unwrap_or_default();
            let t = ports.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
            let d: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
            if d.is_empty() {
                return Err(Fail);
            }
            d
        }
    };
    let pw = get(node, "password").map(tostr).unwrap_or_default();
    let link = format!("hysteria2://{}@{}:{}", urlencode(&pw), host_format(get(node, "server")), port);
    let mut p = vec![];
    add(&mut p, "mport", pval(get(node, "ports")));
    add(&mut p, "hopInterval", pval(get(node, "hop-interval")));
    add(&mut p, "obfs", pval(get(node, "obfs")));
    add(&mut p, "obfs-password", pval(get(node, "obfs-password")));
    add(&mut p, "minPacketSize", pval(get(node, "obfs-min-packet-size")));
    add(&mut p, "maxPacketSize", pval(get(node, "obfs-max-packet-size")));
    add(&mut p, "upmbps", num_param(up));
    add(&mut p, "downmbps", num_param(down));
    add(&mut p, "ech", build_ech(node)?);
    add(&mut p, "vcn", pval(get(node, "name-cert-verify")));
    add(&mut p, "sni", pval(get(node, "sni")));
    add_b(&mut p, "insecure", get(node, "skip-cert-verify") == Some(&Yaml::Bool(true)));
    add(&mut p, "pinSHA256", pval(get(node, "fingerprint")));
    Ok(finish_link(link, &p, get(node, "name")))
}

fn encode_tuic(node: &Yaml) -> ER {
    let name = get(node, "name").map(tostr).unwrap_or_default();
    if truthy(get(node, "token")) {
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard TUIC node %s, TUIC v4 is not supported.", &[&name])));
    }
    if !truthy(get(node, "uuid")) || get(node, "password").is_none() {
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard TUIC node %s, authentication information is incomplete.", &[&name])));
    }
    let uuid = get(node, "uuid").map(tostr).unwrap_or_default();
    let pw = get(node, "password").map(tostr).unwrap_or_default();
    let link = format!("tuic://{}:{}@{}:{}", urlencode(&uuid), urlencode(&pw), host_format(get(node, "server")), cat(get(node, "port"))?);
    let mut p = vec![];
    add(&mut p, "congestion_control", pval(get(node, "congestion-controller")));
    add(&mut p, "alpn", build_alpn(get(node, "alpn")));
    add(&mut p, "sni", pval(get(node, "sni")));
    if truthy(get(node, "disable-sni")) {
        add_b(&mut p, "disable_sni", true);
    }
    add_b(&mut p, "allowInsecure", get(node, "skip-cert-verify") == Some(&Yaml::Bool(true)));
    add(&mut p, "udp_relay_mode", pval(get(node, "udp-relay-mode")));
    add(&mut p, "pcs", pval(get(node, "fingerprint")));
    add(&mut p, "vcn", pval(get(node, "name-cert-verify")));
    Ok(finish_link(link, &p, get(node, "name")))
}

fn encode_anytls(node: &Yaml, redir: &HashMap<String, String>) -> ER {
    let err = if truthy(get(node, "shadow-tls-opts")) {
        Some("ShadowTLS")
    } else if truthy(get(node, "restls-opts")) {
        Some("ResTLS")
    } else if truthy(get(node, "jls-opts")) {
        Some("JLS")
    } else {
        None
    };
    if let Some(e) = err {
        let name = get(node, "name").map(tostr).unwrap_or_default();
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard AnyTLS node %s, Sing-Box does not support AnyTLS + %s", &[&name, e])));
    }
    let o = build_common(node, redir)?;
    let pw = get(node, "password").map(tostr).unwrap_or_default();
    let link = format!("anytls://{}@{}:{}", urlencode(&pw), host_format(get(node, "server")), cat(get(node, "port"))?);
    let mut p = vec![];
    add(&mut p, "security", o.tls.security.clone());
    add(&mut p, "pbk", o.tls.pbk.clone());
    add(&mut p, "sid", o.tls.sid.clone());
    add(&mut p, "sni", o.tls.sni.clone());
    add(&mut p, "alpn", o.tls.alpn.clone());
    add(&mut p, "fp", o.tls.fp.clone());
    add(&mut p, "ech", o.tls.ech.clone());
    add(&mut p, "pcs", o.tls.pcs.clone());
    add_b(&mut p, "insecure", o.tls.insecure);
    Ok(finish_link(link, &p, o.name.as_ref()))
}

fn encode_ssr(node: &Yaml) -> ER {
    let b64 = |v: Option<&Yaml>| -> Result<String, Fail> { Ok(api::base64_encode(cat(v)?.as_bytes())) };
    let opt = |k: &str| get(node, k).filter(|v| v.truthy()).map(tostr).unwrap_or_default();
    let mut link = format!(
        "{}:{}:{}:{}:{}:{}",
        host_format(get(node, "server")),
        cat(get(node, "port"))?,
        opt("protocol"),
        opt("cipher"),
        opt("obfs"),
        b64(get(node, "password"))?
    );
    let mut p = vec![];
    if let Some(v) = get(node, "obfs-param").filter(|v| v.truthy()) {
        p.push(format!("obfsparam={}", b64(Some(v))?));
    }
    if let Some(v) = get(node, "protocol-param").filter(|v| v.truthy()) {
        p.push(format!("protoparam={}", b64(Some(v))?));
    }
    p.push(format!("remarks={}", b64(get(node, "name"))?));
    link.push('?');
    link.push_str(&p.join("&"));
    Ok(Enc::Link(format!("ssr://{}", api::base64_encode(link.as_bytes()))))
}

fn encode_snell(node: &Yaml) -> ER {
    let name = get(node, "name").map(tostr).unwrap_or_default();
    let obfs = get(node, "obfs-opts").filter(|v| v.truthy());
    let mode = obfs.and_then(|o| get(o, "mode")).filter(|v| v.truthy()).map(tostr);
    if let Some(m) = &mode {
        if m != "http" && m != "none" {
            return Ok(Enc::Msg(api::translatef("Subscription conversion: discard Snell node %s, Sing-Box does not support Snell + %s", &[&name, m])));
        }
    }
    let mut version = match get(node, "version").filter(|v| v.truthy()) {
        Some(v) => v.num().unwrap_or(4.0),
        None => 4.0,
    };
    if version == 5.0 {
        version = 4.0;
    }
    if version < 4.0 {
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard Snell node %s, Sing-Box does not support Snell versions below 4.", &[&name])));
    }
    let link = format!("snell://{}:{}", host_format(get(node, "server")), cat(get(node, "port"))?);
    let mut p = vec![];
    add(&mut p, "psk", pval(get(node, "psk")));
    add(&mut p, "version", Some(lua_num(version)));
    if mode.as_deref() == Some("http") {
        add(&mut p, "obfs", Some("http".into()));
        add(&mut p, "obfs-host", obfs.and_then(|o| pval(get(o, "host"))));
    }
    add(&mut p, "reuse", Some(if truthy(get(node, "reuse")) { "1".into() } else { "0".into() }));
    Ok(finish_link(link, &p, get(node, "name")))
}

/// `encode_node(node)`
fn encode_node(node: &Yaml, redir: &HashMap<String, String>) -> ER {
    if !matches!(node, Yaml::Map(_)) || !truthy(get(node, "type")) || !truthy(get(node, "name")) {
        return Ok(Enc::Msg(api::translate("Subscription conversion: skip a malformed node.")));
    }
    let t = get(node, "type").map(tostr).unwrap_or_default();
    let server_ok = truthy(get(node, "server")) && get(node, "server") != Some(&Yaml::Str(String::new()));
    let port_ok = truthy(get(node, "port")) || (t == "hysteria2" && truthy(get(node, "ports")));
    if !server_ok || !port_ok {
        let name = get(node, "name").map(tostr).unwrap_or_default();
        return Ok(Enc::Msg(api::translatef("Subscription conversion: discard node %s, node information is incomplete.", &[&name])));
    }
    let mut node = node.clone();
    let (mut up, mut down) = (None, None);
    if t == "hysteria" || t == "hysteria2" {
        let u = get(&node, "up").map(bandwidth_mbps);
        let d = get(&node, "down").map(bandwidth_mbps);
        if u == Some(None) || d == Some(None) {
            let name = get(&node, "name").map(tostr).unwrap_or_default();
            return Ok(Enc::Msg(api::translatef("Subscription conversion: discard node %s, invalid bandwidth format.", &[&name])));
        }
        up = u.flatten();
        down = d.flatten();
    }
    if let Some(r) = get(&node, "server").map(tostr).and_then(|s| redir.get(&s).cloned()) {
        if let Yaml::Map(m) = &mut node {
            if let Some(e) = m.iter_mut().find(|(k, _)| k == "server") {
                e.1 = Yaml::Str(r);
            }
        }
    }
    match t.as_str() {
        "vless" => encode_vless(&node, redir),
        "trojan" => encode_trojan(&node, redir),
        "vmess" => encode_vmess(&node, redir),
        "ss" => encode_ss(&node),
        "hysteria" => encode_hysteria(&node, up, down),
        "hysteria2" => encode_hysteria2(&node, up, down),
        "tuic" => encode_tuic(&node),
        "anytls" => encode_anytls(&node, redir),
        "ssr" => encode_ssr(&node),
        "snell" => encode_snell(&node),
        _ => {
            let name = get(&node, "name").map(tostr).unwrap_or_default();
            util::log(2, &api::translatef("Subscription conversion: discard unsupported node %s, node type: %s", &[&name, &t]));
            Ok(Enc::Nothing)
        }
    }
}

// ------------------------------------------------------------------------------ DNS extraction

#[derive(Clone, Debug, PartialEq)]
struct Endpoint {
    protocol: String,
    host: String,
    port: u32,
    url: String,
}

/// `parse_dns_endpoint(v)`
fn parse_dns_endpoint(v: Option<&Yaml>) -> Option<Endpoint> {
    let Some(Yaml::Str(s)) = v else { return None };
    let value = api::trim(s);
    if value.is_empty() || value.chars().any(|c| c.is_ascii_whitespace() || c == '\x0b' || matches!(c, '#' | '?' | '@' | ',')) {
        return None;
    }
    let url = if value.contains("://") { value.clone() } else { format!("udp://{}", value) };
    let ep = api::parse_url(&url)?;
    let protocol = ep.protocol.clone()?;
    if !matches!(protocol.as_str(), "udp" | "tcp" | "https") {
        return None;
    }
    let host = ep.hostname.clone();
    if host.is_empty() || !(api::is_ip(&host) || api::dt_hostname(&host)) {
        return None;
    }
    let bracketed = ep.host.starts_with('[');
    let ipv6 = api::dt_ip6addr(&host);
    if bracketed && !ipv6 {
        return None;
    }
    if protocol == "https" && ipv6 && !bracketed {
        return None;
    }
    let port = ep.port.unwrap_or(if protocol == "https" { 443 } else { 53 });
    if !(1..=65535).contains(&port) {
        return None;
    }
    if protocol != "https" && ep.pathname.is_some() {
        return None;
    }
    let mut h = host.to_lowercase();
    if h.ends_with('.') {
        h.pop();
    }
    Some(Endpoint { protocol, host: h, port, url })
}

fn is_loopback_dns(h: &str) -> bool {
    if h == "localhost" || (api::dt_ip4addr(h) && h.starts_with("127.")) {
        return true;
    }
    // ^[0:]+:0*1$
    let Some(t) = h.strip_suffix('1') else { return false };
    t.chars().all(|c| c == '0' || c == ':') && t.rfind(':').is_some_and(|k| k >= 1)
}

fn is_unspecified_dns(h: &str) -> bool {
    h == "0.0.0.0" || (!h.is_empty() && h.chars().all(|c| c == '0' || c == ':'))
}

fn pick(dns: &Yaml, cands: Option<&Yaml>, depth: u32, listener: &Option<Endpoint>, has_policy: bool, resolving: &mut Vec<String>) -> Option<Resolver> {
    if depth > 4 {
        return None;
    }
    let list: Vec<Yaml> = match cands? {
        Yaml::Str(s) => vec![Yaml::Str(s.clone())],
        Yaml::Seq(v) => v.clone(),
        Yaml::Map(_) => vec![],
        _ => return None,
    };
    for value in list.iter() {
        let Some(ep) = parse_dns_endpoint(Some(value)) else { continue };
        if is_unspecified_dns(&ep.host) {
            continue;
        }
        if is_loopback_dns(&ep.host) {
            let key = format!("{}://{}:{}", ep.protocol, ep.host, ep.port);
            let listen_matches = listener.as_ref().is_some_and(|l| {
                l.protocol != "https"
                    && l.port == ep.port
                    && (l.host == ep.host
                        || (l.host == "0.0.0.0" && !ep.host.contains(':'))
                        || (is_unspecified_dns(&l.host) && l.host != "0.0.0.0" && ep.host.contains(':'))
                        || (ep.host == "localhost" && is_loopback_dns(&l.host)))
            });
            if ep.protocol != "https" && get(dns, "enable") == Some(&Yaml::Bool(true)) && listen_matches && !resolving.contains(&key) && !has_policy {
                resolving.push(key.clone());
                let r = pick(dns, get(dns, "nameserver"), depth + 1, listener, has_policy, resolving);
                resolving.retain(|k| *k != key);
                if r.is_some() {
                    return r;
                }
            }
        } else if ep.protocol == "https" {
            return Some(Resolver { domain_resolver: "https".into(), domain_resolver_dns: None, domain_resolver_dns_https: Some(ep.url.clone()) });
        } else if api::dt_ip4addr(&ep.host) {
            return Some(Resolver { domain_resolver: ep.protocol.clone(), domain_resolver_dns: Some(format!("{}:{}", ep.host, ep.port)), domain_resolver_dns_https: None });
        }
    }
    None
}

fn non_empty_table(v: Option<&Yaml>) -> bool {
    match v {
        Some(Yaml::Map(m)) => !m.is_empty(),
        Some(Yaml::Seq(s)) => !s.is_empty(),
        _ => false,
    }
}

/// `extract_clash_dns(data)`: subscription-wide node-domain resolver.
fn extract_clash_dns(data: &Yaml) -> Option<Resolver> {
    let dns = get(data, "dns").filter(|d| d.is_table())?;
    get(dns, "proxy-server-nameserver").filter(|v| v.truthy())?;
    if non_empty_table(get(dns, "proxy-server-nameserver-policy")) {
        return None;
    }
    let listener = parse_dns_endpoint(get(dns, "listen"));
    let has_policy = non_empty_table(get(dns, "nameserver-policy"));
    let mut resolving = vec![];
    let r = pick(dns, get(dns, "proxy-server-nameserver"), 0, &listener, has_policy, &mut resolving);
    if let Some(r) = &r {
        let address = r.domain_resolver_dns_https.clone().unwrap_or_else(|| format!("{}://{}", r.domain_resolver, r.domain_resolver_dns.clone().unwrap_or_default()));
        util::log(1, &api::translatef("Subscription conversion: extracted node domain DNS: %s", &[&address]));
    }
    r
}

// ------------------------------------------------------------------------------ public API

/// True when the text looks like it was meant to be a Clash document.
fn looks_like_clash(raw: &str) -> bool {
    raw.lines().any(|l| l.trim_start().starts_with("proxies:")) || raw.contains("\"proxies\"")
}

/// `parseClashNode(raw, remark, auto_dns)` → (text for the link parser, resolver).
///
/// * not YAML / a scalar document (base64 blob, plain link list) → `raw` unchanged;
/// * a mapping without a `proxies` table → `""` (empty subscription);
/// * a Clash document → one share link per line (`""` if none converted), and with
///   `auto_dns` the node-domain resolver from its `dns:` block.
///
/// Deviation: upstream returns `""` on any YAML syntax error; here text that does not look
/// like a Clash document (no `proxies:` key) is returned unchanged so plain link lists that
/// happen to be invalid YAML (e.g. a `: ` in a remark) are still parsed.
pub fn parse_clash_node(raw: &str, remark: &str, auto_dns: bool) -> (String, Option<Resolver>) {
    let data = match yaml::load(raw) {
        Ok(d) => d,
        Err(_) if !looks_like_clash(raw) => return (raw.to_string(), None),
        Err(_) => {
            util::log(1, &api::translatef("Subscription conversion: YAML parsing failed: %s", &[remark]));
            return (String::new(), None);
        }
    };
    if !data.is_table() {
        return (raw.to_string(), None);
    }
    let Some(proxies) = get(&data, "proxies").filter(|p| p.is_table()) else { return (String::new(), None) };
    util::log(1, &api::translate("Subscription conversion: Clash subscription detected, converting..."));
    let mut redir: HashMap<String, String> = HashMap::new();
    if let Some(Yaml::Map(hosts)) = get(&data, "hosts") {
        for (k, v) in hosts {
            if let Yaml::Str(v) = v {
                if api::dt_hostname(k) && api::dt_hostname(v) {
                    redir.insert(k.clone(), v.clone());
                }
            }
        }
    }
    let mut links = vec![];
    for node in proxies.as_seq().map(|s| s.as_slice()).unwrap_or(&[]) {
        match encode_node(node, &redir) {
            Err(Fail) => {
                let name = get(node, "name").map(tostr).unwrap_or_default();
                util::log(2, &api::translatef("Subscription conversion: discard node %s, conversion failed.", &[&name]));
            }
            Ok(Enc::Msg(m)) => util::log(2, &m),
            Ok(Enc::Link(l)) => links.push(l),
            Ok(Enc::Nothing) => {}
        }
    }
    let resolver = if !links.is_empty() && auto_dns { extract_clash_dns(&data) } else { None };
    (links.join("\n"), resolver)
}

/// `format_size(bytes)`
fn format_size(mut bytes: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut i = 0;
    while bytes >= 1024.0 && i < units.len() - 1 {
        bytes /= 1024.0;
        i += 1;
    }
    if bytes >= 100.0 {
        format!("{:.0}{}", bytes, units[i])
    } else if bytes >= 10.0 {
        format!("{:.1}{}", bytes, units[i])
    } else {
        format!("{:.2}{}", bytes, units[i])
    }
}

/// Days since 1970-01-01 → (y, m, d) (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `os.date("*t", expire)` → `Y-M-D` without padding (local time via `date`, UTC fallback).
fn local_date(expire: u64) -> String {
    let out = util::cmd_out("date", &["-d", &format!("@{}", expire), "+%Y %m %d"]);
    let parts: Vec<u64> = out.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    if parts.len() == 3 {
        return format!("{}-{}-{}", parts[0], parts[1], parts[2]);
    }
    let (y, m, d) = civil_from_days((expire / 86400) as i64);
    format!("{}-{}-{}", y, m, d)
}

/// `parse_clash_sub_info(headers)`: `Subscription-Userinfo: upload=..; download=..; total=..;
/// expire=..` → remaining traffic and expiry date.
pub fn parse_clash_sub_info(headers: &str) -> Option<SubInfo> {
    // upstream quirk: the Lua pattern `[Ss]ubscription%-userinfo:` misses `Subscription-Userinfo`
    // (HTTP/1.1 servers that capitalise it); header names are case-insensitive, so match any case.
    let lower = headers.to_ascii_lowercase();
    let i = lower.find("subscription-userinfo:")?;
    let rest = &headers[i + "subscription-userinfo:".len()..];
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let userinfo: String = rest.chars().take_while(|c| *c != '\r' && *c != '\n').collect();
    if userinfo.is_empty() {
        return None;
    }
    let num = |key: &str| -> Option<f64> {
        let mut from = 0;
        while let Some(j) = userinfo[from..].find(key) {
            let s = from + j + key.len();
            let d: String = userinfo[s..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if !d.is_empty() {
                return d.parse().ok();
            }
            from = s;
        }
        None
    };
    let upload = num("upload=").unwrap_or(0.0);
    let download = num("download=").unwrap_or(0.0);
    let total = num("total=").unwrap_or(0.0);
    let expire = num("expire=");
    let remain = (total - (upload + download)).max(0.0);
    let expired_date = match expire {
        Some(e) if e > 0.0 => local_date(e as u64),
        _ => api::translate("Never expires"),
    };
    Some(SubInfo { rem_traffic: format_size(remain), expired_date })
}

#[cfg(test)]
mod tests {
    use super::super::links::{parse_link, Cores, KeywordFilter, NVal, Node, ParseCtx};
    use super::*;

    fn ctx() -> ParseCtx {
        ParseCtx {
            cores: Cores::all(),
            ss_type: Some("sing-box".into()),
            trojan_type: Some("xray".into()),
            vmess_type: Some("xray".into()),
            vless_type: Some("xray".into()),
            hysteria2_type: Some("sing-box".into()),
            filter: KeywordFilter::default(),
        }
    }

    fn nodes(yaml: &str) -> Vec<Node> {
        let (text, _) = parse_clash_node(yaml, "t", false);
        parse_link(&ctx(), &text, "2", Some("g"), None, &mut |_, _| {}).nodes
    }

    const DOC: &str = r#"
hosts:
  fake.example.com: real.example.com
dns:
  enable: true
  listen: 0.0.0.0:1053
  proxy-server-nameserver:
    - 127.0.0.1:1053
  nameserver:
    - https://1.1.1.1/dns-query
proxies:
  - name: "VL"
    type: vless
    server: fake.example.com
    port: 443
    uuid: 1111-2222
    flow: xtls-rprx-vision
    tls: true
    servername: sni.example.com
    client-fingerprint: chrome
    reality-opts: {public-key: PUBKEY, short-id: "01ab"}
    network: tcp
  - {name: SS, type: ss, server: "2001:db8::1", port: 8388, cipher: aes-256-gcm, password: "p+ss/w>?", udp: true, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}
  - name: VM
    type: vmess
    server: vm.example.com
    port: 80
    uuid: abcd
    alterId: 0
    cipher: auto
    network: ws
    ws-opts: {path: /ws, headers: {Host: cdn.example.com}, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol}
  - name: H2
    type: hysteria2
    server: hy.example.com
    ports: 20000-30000
    password: pw
    up: "100 Mbps"
    down: 50
    obfs: salamander
    obfs-password: op
    sni: s.example.com
    skip-cert-verify: true
  - {name: BAD, type: hysteria2, server: x.com, port: 1, up: "fast"}
  - {name: TU, type: tuic, server: t.com, port: 443, token: abc}
  - {name: WG, type: wireguard, server: w.com, port: 51820}
  - {name: TR, type: trojan, server: tr.com, port: 443, password: "a@b", network: grpc, grpc-opts: {grpc-service-name: svc}, alpn: [h2, http/1.1]}
  - {name: SN, type: snell, server: sn.com, port: 6000, psk: k, version: 3}
  - {name: SR, type: ssr, server: r.com, port: 1, cipher: aes-256-cfb, password: pw, protocol: origin, obfs: plain}
  - {name: AT, type: anytls, server: a.com, port: 443, password: pw, sni: a.com, skip-cert-verify: false}
"#;

    #[test]
    fn converts_clash_document() {
        let (text, res) = parse_clash_node(DOC, "t", true);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7, "{}", text);
        assert_eq!(
            lines[0],
            "vless://1111-2222@real.example.com:443?flow=xtls-rprx-vision&security=reality&pbk=PUBKEY&sid=01ab&sni=sni.example.com&fp=chrome&allowInsecure=0&type=tcp#VL"
        );
        assert!(lines[3].starts_with("hysteria2://pw@hy.example.com:20000?mport=20000-30000&obfs=salamander&obfs-password=op&upmbps=100&downmbps=50&sni=s.example.com&insecure=1"));
        assert_eq!(lines[4], "trojan://a%40b@tr.com:443?alpn=h2%2Chttp%2F1.1&allowInsecure=0&type=grpc&serviceName=svc#TR");
        // loopback proxy-server-nameserver resolved through the listener to nameserver
        assert_eq!(res, Some(Resolver { domain_resolver: "https".into(), domain_resolver_dns: None, domain_resolver_dns_https: Some("https://1.1.1.1/dns-query".into()) }));
    }

    #[test]
    fn clash_round_trip_through_link_parser() {
        let n = nodes(DOC);
        let by = |name: &str| n.iter().find(|x| x.get("remarks") == Some(name)).cloned().unwrap();
        let vl = by("VL");
        assert_eq!(vl.get("address"), Some("real.example.com"));
        assert_eq!(vl.get("reality"), Some("1"));
        assert_eq!(vl.get("tls_allowInsecure"), Some("0"));
        let ss = by("SS");
        assert_eq!(ss.get("type"), Some("sing-box"));
        assert_eq!(ss.get("address"), Some("2001:db8::1"));
        assert_eq!(ss.get("password"), Some("p+ss/w>?"));
        assert_eq!(ss.get("plugin"), Some("obfs-local"));
        assert_eq!(ss.get("plugin_opts"), Some("obfs=http;obfs-host=bing.com"));
        let vm = by("VM");
        assert_eq!(vm.get("ws_path"), Some("/ws?ed=2048&eh=Sec-WebSocket-Protocol"));
        assert_eq!(vm.get("ws_host"), Some("cdn.example.com"));
        assert_eq!(vm.get("port"), Some("80"));
        assert_eq!(vm.get("tls"), Some("0"));
        assert_eq!(vm.get("tls_allowInsecure"), None);
        let h2 = by("H2");
        assert_eq!(h2.get("hysteria2_hop"), Some("20000-30000"));
        assert_eq!(h2.get("hysteria2_up_mbps"), Some("100"));
        assert_eq!(h2.get("tls_allowInsecure"), Some("1"));
        let tr = by("TR");
        assert_eq!(tr.get("password"), Some("a@b"));
        assert_eq!(tr.get("alpn"), Some("h2,http/1.1"));
        let sr = by("SR");
        assert_eq!(sr.get("password"), Some("pw"));
        assert_eq!(sr.get("protocol"), Some("origin"));
        let at = by("AT");
        assert_eq!(at.get("tls"), Some("1"));
        assert!(matches!(by("TR").0.get("timeout"), Some(NVal::S(_))));
        assert!(n.iter().all(|x| x.get("remarks") != Some("SN")));
    }

    #[test]
    fn non_clash_inputs() {
        let b = api::base64_encode(b"trojan://p@a.com:1#x");
        assert_eq!(parse_clash_node(&b, "r", true).0, b);
        let list = "trojan://p@a.com:1#x\nvless://u@b.com:2#y";
        assert_eq!(parse_clash_node(list, "r", true).0, list);
        // invalid YAML that is not a Clash document is kept
        let odd = "trojan://p@a.com:1#x\ntrojan://p@b.com:1#Traffic: 1GB";
        assert_eq!(parse_clash_node(odd, "r", true).0, odd);
        // mapping without proxies → empty
        assert_eq!(parse_clash_node("port: 7890\nmode: rule\n", "r", true).0, "");
        assert_eq!(parse_clash_node(r#"{"outbounds": []}"#, "r", true).0, "");
    }

    #[test]
    fn helpers() {
        assert_eq!(bandwidth_mbps(&Yaml::Str("1 Gbps".into())), Some(1000.0));
        assert_eq!(bandwidth_mbps(&Yaml::Str("10 MBps".into())), Some(80.0));
        assert_eq!(bandwidth_mbps(&Yaml::Str("500Kbps".into())), Some(0.5));
        assert_eq!(bandwidth_mbps(&Yaml::Str("fast".into())), None);
        assert_eq!(bandwidth_mbps(&Yaml::Num("30".into())), Some(30.0));
        assert_eq!(build_alpn(Some(&Yaml::Seq(vec![Yaml::Str("http/1.1".into()), Yaml::Str("h3".into()), Yaml::Str("x".into())]))), Some("h3,http/1.1".into()));
        assert_eq!(build_alpn(Some(&Yaml::Str("h2,h3".into()))), None);
        assert_eq!(host_format(Some(&Yaml::Str("::1".into()))), "[::1]");
        assert_eq!(host_format(Some(&Yaml::Str("[::1]".into()))), "[::1]");
        assert_eq!(host_format(Some(&Yaml::Str("a.com".into()))), "a.com");
        assert_eq!(format_size(0.0), "0.00B");
        assert_eq!(format_size(1536.0 * 1024.0 * 1024.0), "1.50GB");
        assert_eq!(format_size(150.0 * 1024.0), "150KB");
        assert!(is_loopback_dns("::1"));
        assert!(is_loopback_dns("0:0:0:0:0:0:0:1"));
        assert!(!is_loopback_dns("::2"));
        assert!(is_unspecified_dns("::"));
        assert_eq!(civil_from_days(20519), (2026, 3, 7));
    }

    #[test]
    fn sub_info() {
        let h = "HTTP/1.1 200 OK\ncontent-type: text/plain\nsubscription-userinfo: upload=1024; download=1024; total=10737418240; expire=0\n";
        let i = parse_clash_sub_info(h).unwrap();
        assert_eq!(i.rem_traffic, "10.00GB");
        assert_eq!(i.expired_date, "Never expires");
        assert!(parse_clash_sub_info("x: y").is_none());
    }

    #[test]
    fn dns_endpoints() {
        let e = parse_dns_endpoint(Some(&Yaml::Str("tcp://8.8.8.8".into()))).unwrap();
        assert_eq!((e.protocol.as_str(), e.port), ("tcp", 53));
        assert!(parse_dns_endpoint(Some(&Yaml::Str("https://[2001:db8::1]/dns-query".into()))).is_some());
        assert!(parse_dns_endpoint(Some(&Yaml::Str("https://2001:db8::1/dns-query".into()))).is_none());
        assert!(parse_dns_endpoint(Some(&Yaml::Str("quic://8.8.8.8".into()))).is_none());
        assert!(parse_dns_endpoint(Some(&Yaml::Str("8.8.8.8#proxy".into()))).is_none());
        assert!(parse_dns_endpoint(Some(&Yaml::Str("udp://8.8.8.8/x".into()))).is_none());
        let y = yaml::load("dns:\n  proxy-server-nameserver: [udp://223.5.5.5:53]\nproxies: []").unwrap();
        assert_eq!(extract_clash_dns(&y).unwrap().domain_resolver_dns.as_deref(), Some("223.5.5.5:53"));
        let y = yaml::load("dns:\n  proxy-server-nameserver: [udp://223.5.5.5]\n  proxy-server-nameserver-policy: {a: b}\n").unwrap();
        assert!(extract_clash_dns(&y).is_none());
    }
}
