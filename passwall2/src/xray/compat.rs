//! Xray-core version gates: the generator emits the config form of upstream master (Xray ≥
//! 26.7.11); [`downgrade`] rewrites the finished JSON into the older form that the installed
//! core understands. All compatibility logic lives here, so the generator stays a 1:1 port.
//!
//! Gates (first Xray release that accepts the new form; checked against Xray-core source at
//! the release tags and by running `xray run -test` / `xray convert pb -debug` on 26.1.31 and
//! 26.10.31):
//!
//! | flag               | since    | new form                                    | legacy form (upstream 26.4.20)               |
//! |--------------------|----------|---------------------------------------------|----------------------------------------------|
//! | `stream_method`    | 26.7.11  | `streamSettings.method`, `version.min`      | `streamSettings.network`, no `version`        |
//! | `flat_outbound`    | 26.7.11* | flat `settings.{address,port,id,...}`       | `settings.vnext[]` / `settings.servers[]`     |
//! | `fragment_arrays`  | 26.6.27  | fragment mask `lengths[]` / `delays[]`      | `length` / `delay`                            |
//! | `mkcp_legacy_mask` | 26.6.1   | `mkcp-legacy {header, value}`               | `header-<x>` + `mkcp-original/aes128gcm`      |
//! | `tunnel_fields`    | 26.5.9   | `tunnel {allowedNetwork,rewrite*}`          | `dokodemo-door {network,address,port}`        |
//! | `dns_rewrite`      | 26.5.9   | dns `rewrite*` + `rules[]`                  | dns `address/port/network/nonIPQuery`         |
//! | `inbound_users`    | 26.5.9   | inbound `users`                             | `accounts` (socks/http) / `clients`           |
//! | `finalmask_tcp`    | 26.3.23  | `finalmask.tcp` fragment, `udp` noise       | freedom `fragment` outbound via `dialerProxy` |
//! | `pin_byname`       | 26.1.31  | `pinnedPeerCertSha256` / `verifyPeerCertByName` | omitted (upstream 26.4.20 gate)           |
//!
//! \* The flat outbound settings parse correctly on 26.1.31 but the first release that accepts
//! them is unknown; the array form is accepted by every version (old and new), it is what
//! upstream 26.4.20 emitted, and it is proven on the target routers, so the array form is used
//! whenever the core predates the new stream form.
//!
//! Forms that every supported core accepts are always emitted in the new form and need no gate:
//! `sockopt.dialerProxy` (the old `proxySettings` is a hard error on new cores), freedom
//! `sockopt.domainStrategy`, `finalRules` (ignored by old cores), `env`, `happyEyeballs`.

use crate::api;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

/// Capabilities of the installed Xray core (see the module table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrayCaps {
    /// The version string was recognised (false → modern form assumed, like upstream).
    pub known: bool,
    pub stream_method: bool,
    pub flat_outbound: bool,
    pub fragment_arrays: bool,
    pub mkcp_legacy_mask: bool,
    pub tunnel_fields: bool,
    pub dns_rewrite: bool,
    pub inbound_users: bool,
    pub finalmask_tcp: bool,
    pub pin_byname: bool,
}

/// Tag of the freedom outbound that carries the fragment settings for cores without
/// `finalmask.tcp` (chained with `dialerProxy`).
pub const FRAGMENT_TAG: &str = "fragment";

impl XrayCaps {
    /// The form upstream master emits (Xray ≥ 26.7.11).
    pub const fn modern() -> XrayCaps {
        XrayCaps {
            known: true,
            stream_method: true,
            flat_outbound: true,
            fragment_arrays: true,
            mkcp_legacy_mask: true,
            tunnel_fields: true,
            dns_rewrite: true,
            inbound_users: true,
            finalmask_tcp: true,
            pin_byname: true,
        }
    }
    /// The most conservative form (every gate off): used when the version is unknown and the
    /// modern config failed `xray run -test`.
    pub const fn legacy() -> XrayCaps {
        XrayCaps {
            known: true,
            stream_method: false,
            flat_outbound: false,
            fragment_arrays: false,
            mkcp_legacy_mask: false,
            tunnel_fields: false,
            dns_rewrite: false,
            inbound_users: false,
            finalmask_tcp: false,
            pin_byname: false,
        }
    }
    pub fn is_modern(&self) -> bool {
        let mut m = XrayCaps::modern();
        m.known = self.known;
        *self == m
    }
    /// From the output of `xray version | awk '{print $2}'` (`26.1.31`, `v1.8.24`, ...).
    /// Empty or unrecognised → modern form with `known = false`.
    pub fn from_version(v: &str) -> XrayCaps {
        let v = v.trim().trim_start_matches(['v', 'V']);
        let v: String = v.chars().take_while(|c| !c.is_whitespace()).collect();
        if !v.starts_with(|c: char| c.is_ascii_digit()) {
            let mut m = XrayCaps::modern();
            m.known = false;
            return m;
        }
        let ge = |min: &str| api::compare_versions(&v, ">=", min);
        let stream_method = ge("26.7.11");
        XrayCaps {
            known: true,
            stream_method,
            flat_outbound: stream_method,
            fragment_arrays: ge("26.6.27"),
            mkcp_legacy_mask: ge("26.6.1"),
            tunnel_fields: ge("26.5.9"),
            dns_rewrite: ge("26.5.9"),
            inbound_users: ge("26.5.9"),
            finalmask_tcp: ge("26.3.23"),
            pin_byname: ge("26.1.31"),
        }
    }
    /// Installed core (configured `@global_app[0].xray_file`), detected once per process (the
    /// version itself is cached on disk by `api::get_app_version`). `PASSWALL2_XRAY_VERSION`
    /// overrides the detection.
    pub fn detect() -> XrayCaps {
        static C: OnceLock<XrayCaps> = OnceLock::new();
        *C.get_or_init(|| {
            let v = std::env::var("PASSWALL2_XRAY_VERSION").unwrap_or_else(|_| {
                // unit tests never probe a binary of the build host
                if cfg!(test) {
                    String::new()
                } else {
                    api::get_app_version("xray", None)
                }
            });
            XrayCaps::from_version(&v)
        })
    }
}

fn obj(v: &mut Value) -> Option<&mut Map<String, Value>> {
    v.as_object_mut()
}

/// Move `from` to `to` inside an object (keeps an existing `to`).
fn rename(m: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = m.remove(from) {
        m.entry(to.to_string()).or_insert(v);
    }
}

/// Rewrite a generated config (client, proto relay or server) for the given core.
pub fn downgrade(cfg: &mut Value, caps: &XrayCaps) {
    if caps.is_modern() {
        return;
    }
    let Some(root) = obj(cfg) else { return };
    if !caps.stream_method {
        root.remove("version");
    }
    let mut fragment: Option<Value> = None;
    let mut blackhole_domains: Vec<String> = vec![];

    if let Some(Value::Array(inbounds)) = root.get_mut("inbounds") {
        for ib in inbounds.iter_mut() {
            let proto = ib.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string();
            if let Some(ss) = ib.get_mut("streamSettings") {
                stream(ss, caps, &mut None);
            }
            let Some(m) = obj(ib) else { continue };
            if !caps.tunnel_fields && proto == "tunnel" {
                m.insert("protocol".into(), Value::from("dokodemo-door"));
                if let Some(s) = m.get_mut("settings").and_then(obj) {
                    rename(s, "allowedNetwork", "network");
                    rename(s, "rewriteAddress", "address");
                    rename(s, "rewritePort", "port");
                    // upstream 26.4.20: the DNS inbound has an explicit wildcard address
                    if !s.contains_key("address") && !s.contains_key("followRedirect") {
                        s.insert("address".into(), Value::from("0.0.0.0"));
                    }
                }
            }
            if !caps.inbound_users {
                if let Some(s) = m.get_mut("settings").and_then(obj) {
                    match proto.as_str() {
                        "socks" | "http" | "mixed" => rename(s, "users", "accounts"),
                        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "hysteria2" => rename(s, "users", "clients"),
                        _ => {}
                    }
                }
            }
        }
    }

    if let Some(Value::Array(outbounds)) = root.get_mut("outbounds") {
        for ob in outbounds.iter_mut() {
            let proto = ob.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string();
            let mut frag_here: Option<Value> = None;
            if let Some(ss) = ob.get_mut("streamSettings") {
                stream(ss, caps, &mut frag_here);
            }
            if let Some(f) = frag_here {
                // chain through the freedom fragment outbound unless already chained
                let has_dialer = ob.pointer("/streamSettings/sockopt/dialerProxy").is_some_and(|d| !d.is_null());
                if has_dialer {
                    crate::util::log(1, &format!("Xray: fragment is not supported by this Xray version for chained outbound [{}], skipped.", ob.get("tag").and_then(|t| t.as_str()).unwrap_or("")));
                } else {
                    super::set_dialer(ob, FRAGMENT_TAG);
                    fragment.get_or_insert(f);
                }
            }
            if !caps.flat_outbound {
                flat_to_arrays(ob, &proto);
            }
            if !caps.dns_rewrite && proto == "dns" {
                legacy_dns_outbound(ob, &mut blackhole_domains);
            }
        }
        if let Some(f) = fragment {
            outbounds.push(json!({
                "protocol": "freedom",
                "tag": FRAGMENT_TAG,
                "settings": { "fragment": f },
                "streamSettings": { "sockopt": { "mark": 255 } }
            }));
        }
    }

    if !blackhole_domains.is_empty() {
        // upstream 26.4.20 blocks the DNS of blackholed shunt domains through dns.hosts
        if let Some(dns) = root.get_mut("dns").and_then(obj) {
            let hosts = dns.entry("hosts").or_insert_with(|| json!({}));
            if !hosts.is_object() {
                *hosts = json!({});
            }
            if let Some(h) = hosts.as_object_mut() {
                for d in blackhole_domains {
                    h.entry(d).or_insert_with(|| Value::from("0.0.0.0"));
                }
            }
        }
    }
}

/// One `streamSettings` object. `fragment` receives the legacy freedom fragment settings when
/// a `finalmask.tcp` fragment had to be removed (core without `finalmask.tcp`).
fn stream(ss: &mut Value, caps: &XrayCaps, fragment: &mut Option<Value>) {
    let Some(m) = obj(ss) else { return };
    if !caps.stream_method {
        rename(m, "method", "network");
    }
    if !caps.pin_byname {
        if let Some(t) = m.get_mut("tlsSettings").and_then(obj) {
            t.remove("pinnedPeerCertSha256");
            t.remove("verifyPeerCertByName");
        }
    }
    let mut drop_fm = false;
    if let Some(fm) = m.get_mut("finalmask").and_then(obj) {
        if let Some(Value::Array(udp)) = fm.get_mut("udp") {
            if !caps.mkcp_legacy_mask {
                legacy_mkcp_masks(udp);
            }
            if !caps.finalmask_tcp {
                let before = udp.len();
                udp.retain(|u| u.get("type").and_then(|t| t.as_str()) != Some("noise"));
                if udp.len() != before {
                    crate::util::log(1, "Xray: noise is not supported by this Xray version, skipped.");
                }
            }
        }
        if let Some(Value::Array(tcp)) = fm.get_mut("tcp") {
            for t in tcp.iter_mut() {
                if t.get("type").and_then(|x| x.as_str()) == Some("fragment") && !caps.fragment_arrays {
                    if let Some(s) = t.get_mut("settings").and_then(obj) {
                        legacy_fragment_settings(s);
                    }
                }
            }
            if !caps.finalmask_tcp {
                for t in tcp.drain(..) {
                    if t.get("type").and_then(|x| x.as_str()) == Some("fragment") && fragment.is_none() {
                        let s = t.get("settings").cloned().unwrap_or_else(|| json!({}));
                        *fragment = Some(json!({
                            "packets": s.get("packets").cloned().unwrap_or(Value::from("tlshello")),
                            "length": s.get("length").cloned().unwrap_or(Value::from("100-200")),
                            "interval": s.get("delay").cloned().unwrap_or(Value::from("10-20")),
                        }));
                    }
                }
            }
        }
        fm.retain(|_, v| !matches!(v, Value::Array(a) if a.is_empty()));
        drop_fm = fm.is_empty();
    }
    if drop_fm {
        m.remove("finalmask");
    }
}

/// fragment mask `lengths[]` / `delays[]` → `length` / `delay` (first element; upstream
/// 26.4.20 had a single range, a number when it is not a range).
fn legacy_fragment_settings(s: &mut Map<String, Value>) {
    let first = |v: Option<Value>| -> Option<Value> {
        match v? {
            Value::Array(a) => a.into_iter().next(),
            other => Some(other),
        }
    };
    if let Some(l) = first(s.remove("lengths")) {
        s.entry("length").or_insert(l);
    }
    if let Some(d) = first(s.remove("delays")) {
        let d = match &d {
            Value::String(x) if !x.contains('-') => x.trim().parse::<i64>().map(Value::from).unwrap_or(d),
            _ => d,
        };
        s.entry("delay").or_insert(d);
    }
}

/// `mkcp-legacy` masks → `header-<x>` (first) + `mkcp-original` / `mkcp-aes128gcm` (upstream
/// 26.4.20 order); other masks keep their place after them.
fn legacy_mkcp_masks(udp: &mut Vec<Value>) {
    if !udp.iter().any(|u| u.get("type").and_then(|t| t.as_str()) == Some("mkcp-legacy")) {
        return;
    }
    let mut headers = vec![];
    let mut ciphers = vec![];
    let mut rest = vec![];
    for u in udp.drain(..) {
        if u.get("type").and_then(|t| t.as_str()) != Some("mkcp-legacy") {
            rest.push(u);
            continue;
        }
        let s = u.get("settings").cloned().unwrap_or(Value::Null);
        match s.get("header").and_then(|h| h.as_str()) {
            Some(h) => {
                let mut g = json!({ "type": if h == "none" { "none".to_string() } else { format!("header-{}", h) } });
                if let Some(d) = s.get("value").filter(|v| !v.is_null()) {
                    g["settings"] = json!({ "domain": d });
                }
                headers.push(g);
            }
            None => match s.get("value").filter(|v| !v.is_null()) {
                Some(seed) => ciphers.push(json!({ "type": "mkcp-aes128gcm", "settings": { "password": seed } })),
                None => ciphers.push(json!({ "type": "mkcp-original" })),
            },
        }
    }
    udp.extend(headers);
    udp.extend(ciphers);
    udp.extend(rest);
}

/// Flat outbound settings → upstream 26.4.20 `vnext` / `servers`.
fn flat_to_arrays(ob: &mut Value, proto: &str) {
    let Some(s) = ob.get_mut("settings").and_then(obj) else { return };
    if s.contains_key("vnext") || s.contains_key("servers") {
        return;
    }
    let mut take = |k: &str| s.remove(k).filter(|v| !v.is_null());
    match proto {
        "vmess" | "vless" => {
            let (address, port) = (take("address"), take("port"));
            let mut user = Map::new();
            for k in ["id", "level", "security", "encryption", "flow"] {
                if let Some(v) = take(k) {
                    user.insert(k.into(), v);
                }
            }
            let mut srv = Map::new();
            srv.insert("address".into(), address.unwrap_or(Value::Null));
            srv.insert("port".into(), port.unwrap_or(Value::Null));
            srv.insert("users".into(), json!([Value::Object(user)]));
            s.insert("vnext".into(), json!([Value::Object(srv)]));
        }
        "shadowsocks" | "trojan" => {
            let mut srv = Map::new();
            for k in ["address", "port", "method", "password"] {
                if let Some(v) = take(k) {
                    srv.insert(k.into(), v);
                }
            }
            take("level");
            s.insert("servers".into(), json!([Value::Object(srv)]));
        }
        "socks" | "http" => {
            let mut srv = Map::new();
            for k in ["address", "port"] {
                if let Some(v) = take(k) {
                    srv.insert(k.into(), v);
                }
            }
            let (user, pass) = (take("user"), take("pass"));
            take("level");
            if let (Some(u), Some(p)) = (user, pass) {
                srv.insert("users".into(), json!([{ "user": u, "pass": p }]));
            }
            s.insert("servers".into(), json!([Value::Object(srv)]));
        }
        _ => {}
    }
}

/// dns outbound `rewrite*` + `rules` → upstream 26.4.20 settings. Domain rules with action
/// `return` (blackholed shunt domains) are collected for `dns.hosts`.
fn legacy_dns_outbound(ob: &mut Value, blackhole: &mut Vec<String>) {
    let Some(m) = obj(ob) else { return };
    let Some(s) = m.get_mut("settings").and_then(obj) else { return };
    if !s.contains_key("rewriteAddress") && !s.contains_key("rewritePort") && !s.contains_key("rules") {
        return;
    }
    if let Some(Value::Array(rules)) = s.get("rules") {
        for r in rules {
            if r.get("action").and_then(|a| a.as_str()) == Some("return") {
                if let Some(Value::Array(d)) = r.get("domain") {
                    blackhole.extend(d.iter().filter_map(|x| x.as_str().map(|x| x.to_string())));
                }
            }
        }
    }
    let mut n = Map::new();
    if let Some(a) = s.get("rewriteAddress").filter(|v| !v.is_null()) {
        n.insert("address".into(), a.clone());
    }
    n.insert("port".into(), s.get("rewritePort").filter(|v| !v.is_null()).cloned().unwrap_or(Value::from(53)));
    n.insert("network".into(), s.get("rewriteNetwork").filter(|v| !v.is_null()).cloned().unwrap_or(Value::from("udp")));
    n.insert("nonIPQuery".into(), Value::from("skip"));
    n.insert("blockTypes".into(), json!([65]));
    *s = n;
    // the dns outbound dials the direct server: keep the bypass mark even if this core ignored
    // dialerProxy on dns outbounds
    let ss = m.entry("streamSettings").or_insert_with(|| json!({}));
    if let Some(so) = ss.as_object_mut().map(|x| x.entry("sockopt").or_insert_with(|| json!({}))) {
        if let Some(so) = so.as_object_mut() {
            so.entry("mark").or_insert(Value::from(255));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_from_version() {
        let c = XrayCaps::from_version("26.1.31");
        assert!(c.known && c.pin_byname);
        assert!(!c.stream_method && !c.flat_outbound && !c.tunnel_fields && !c.dns_rewrite && !c.inbound_users && !c.finalmask_tcp);
        assert!(!c.mkcp_legacy_mask && !c.fragment_arrays);
        assert!(XrayCaps::from_version("26.7.11").is_modern());
        assert!(XrayCaps::from_version("v26.10.31").is_modern());
        let c = XrayCaps::from_version("26.6.27");
        assert!(!c.stream_method && c.fragment_arrays && c.mkcp_legacy_mask && c.tunnel_fields);
        let c = XrayCaps::from_version("26.5.3");
        assert!(!c.tunnel_fields && c.finalmask_tcp);
        let c = XrayCaps::from_version("1.8.24");
        assert_eq!(c, XrayCaps::legacy());
        let u = XrayCaps::from_version("");
        assert!(!u.known && u.is_modern());
        assert!(!XrayCaps::from_version("garbage").known);
    }

    #[test]
    fn mkcp_masks_back_to_headers() {
        let mut udp = vec![
            json!({"type": "mkcp-legacy", "settings": {"value": "seed"}}),
            json!({"type": "mkcp-legacy", "settings": {"header": "dns", "value": "x.com"}}),
            json!({"type": "noise"}),
        ];
        legacy_mkcp_masks(&mut udp);
        assert_eq!(
            udp,
            vec![
                json!({"type": "header-dns", "settings": {"domain": "x.com"}}),
                json!({"type": "mkcp-aes128gcm", "settings": {"password": "seed"}}),
                json!({"type": "noise"}),
            ]
        );
        let mut udp = vec![json!({"type": "mkcp-legacy"})];
        legacy_mkcp_masks(&mut udp);
        assert_eq!(udp, vec![json!({"type": "mkcp-original"})]);
    }

    #[test]
    fn fragment_settings_back_to_single() {
        let mut s = json!({"packets": "tlshello", "lengths": ["3-5", "6-8"], "delays": ["7"], "maxSplit": "3-6"});
        legacy_fragment_settings(s.as_object_mut().unwrap());
        assert_eq!(s, json!({"packets": "tlshello", "length": "3-5", "delay": 7, "maxSplit": "3-6"}));
    }
}
