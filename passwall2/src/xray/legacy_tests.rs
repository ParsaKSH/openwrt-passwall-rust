//! Version-gated output: every node of a 26.4-era config (synthetic, with the shapes of a real
//! router config) generated for Xray 26.1.31 (legacy form) and for a current Xray.
//!
//! `real_config_dump` (ignored) does the same for a real config given by
//! `PASSWALL2_REAL_UCI=<dir with passwall2>` and writes the configs to `PASSWALL2_DUMP_DIR`,
//! for an end-to-end `xray run -test` with the target binary. Real configs contain secrets:
//! never commit them.

use super::*;

/// 26.4-era client config (fake addresses/credentials).
const LEGACY_CONF: &str = "\
config global
\toption enabled '1'
\toption node 'ssc'
\toption node_socks_port '1070'
\toption direct_dns_query_strategy 'UseIP'
\toption remote_dns_protocol 'tcp'
\toption remote_dns '1.1.1.1'
\toption remote_dns_query_strategy 'UseIPv4'
\toption dns_hosts 'cloudflare-dns.com 1.1.1.1'
\toption remote_dns_detour 'remote'

config global_forwarding
\toption tcp_no_redir_ports 'disable'
\toption udp_no_redir_ports 'disable'
\toption tcp_redir_ports '22,25,53,80,443'
\toption udp_redir_ports '1:65535'
\toption tcp_proxy_way 'redirect'

config global_xray
\toption sniffing_override_dest '0'

config global_rules
\toption v2ray_location_asset '/usr/share/v2ray/'

config shunt_rules 'Direct'
\toption remarks 'Direct'
\toption network 'tcp,udp'
\toption domain_list 'geosite:private'
\toption ip_list 'geoip:private'

config shunt_rules 'Block'
\toption remarks 'Block'
\toption network 'tcp,udp'
\toption domain_list 'domain:ads.example'

config nodes 'empty'

config nodes 'grouponly'
\toption group 'G'

config nodes 'typeonly'
\toption type 'Xray'

config nodes 'ssc'
\toption type 'Xray'
\toption protocol 'shadowsocks'
\toption remarks 'SS chacha'
\toption address '203.0.113.10'
\toption port '1044'
\toption password 'pw1'
\toption method 'chacha20-ietf-poly1305'
\toption tls '0'
\toption transport 'raw'
\toption tcp_guise 'none'
\toption tcp_fast_open '0'
\toption tcpMptcp '0'
\toption shadowtls '0'
\toption plugin_enabled '0'

config nodes 'ss22'
\toption type 'Xray'
\toption protocol 'shadowsocks'
\toption remarks 'SS 2022'
\toption address 'ss.example.com'
\toption port '8443'
\toption password 'cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ='
\toption method '2022-blake3-aes-256-gcm'
\toption tls '0'
\toption transport 'raw'
\toption tcp_guise 'none'

config nodes 'vhttp'
\toption type 'Xray'
\toption protocol 'vless'
\toption remarks 'vless raw http tls'
\toption address 'v.example.com'
\toption port '443'
\toption uuid '00000000-0000-4000-8000-000000000001'
\toption encryption 'none'
\toption tls '1'
\toption reality '0'
\toption tls_serverName 'v.example.com'
\toption alpn 'h2,http/1.1'
\toption tls_allowInsecure '1'
\toption utls '1'
\toption fingerprint 'firefox'
\toption transport 'raw'
\toption tcp_guise 'http'
\tlist tcp_guise_http_path '/'
\tlist tcp_guise_http_host 'h.example.com'

config nodes 'vws'
\toption type 'Xray'
\toption protocol 'vless'
\toption remarks 'vless ws tls'
\toption address 'w.example.com'
\toption port '443'
\toption uuid '00000000-0000-4000-8000-000000000002'
\toption encryption 'none'
\toption tls '1'
\toption reality '0'
\toption tls_serverName 'w.example.com'
\toption alpn 'h3,h2,http/1.1'
\toption utls '1'
\toption fingerprint 'chrome'
\toption transport 'ws'
\toption ws_host 'w.example.com'
\toption ws_path '/graphql?ed=2560'
\toption user_agent 'Mozilla/5.0'

config nodes 'vraw'
\toption type 'Xray'
\toption protocol 'vless'
\toption remarks 'vless raw'
\toption address '198.51.100.7'
\toption port '2052'
\toption uuid '00000000-0000-4000-8000-000000000003'
\toption encryption 'none'
\toption tls '0'
\toption transport 'raw'
\toption tcp_guise 'none'

config nodes 'vreal'
\toption type 'Xray'
\toption protocol 'vless'
\toption remarks 'vless reality'
\toption address 'r.example.com'
\toption port '443'
\toption uuid '00000000-0000-4000-8000-000000000004'
\toption encryption 'none'
\toption flow 'xtls-rprx-vision'
\toption tls '1'
\toption reality '1'
\toption tls_serverName 'www.example.org'
\toption reality_publicKey 'SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc'
\toption reality_shortId '6ba85179e30d4fc2'
\toption fingerprint 'chrome'
\toption transport 'raw'
\toption tcp_guise 'none'

config nodes 'vxhttp'
\toption type 'Xray'
\toption protocol 'vless'
\toption remarks 'vless reality xhttp'
\toption address 'x.example.com'
\toption port '443'
\toption uuid '00000000-0000-4000-8000-000000000005'
\toption encryption 'none'
\toption tls '1'
\toption reality '1'
\toption tls_serverName 'www.example.org'
\toption reality_publicKey 'SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc'
\toption reality_shortId '6ba85179e30d4fc2'
\toption reality_spiderX '/'
\toption fingerprint 'chrome'
\toption transport 'xhttp'
\toption xhttp_mode 'auto'
\toption xhttp_path '/x'
\toption xhttp_host 'x.example.com'

config nodes 'trj'
\toption type 'Xray'
\toption protocol 'trojan'
\toption remarks 'trojan tls'
\toption address 't.example.com'
\toption port '443'
\toption password 'tpw'
\toption tls '1'
\toption tls_serverName 't.example.com'
\toption tls_CertSha 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
\toption transport 'grpc'
\toption grpc_serviceName 'svc'

config nodes 'kcp'
\toption type 'Xray'
\toption protocol 'vmess'
\toption remarks 'vmess mkcp'
\toption address 'k.example.com'
\toption port '4000'
\toption uuid '00000000-0000-4000-8000-000000000006'
\toption security 'auto'
\toption transport 'mkcp'
\toption mkcp_guise 'wechat-video'
\toption mkcp_seed 'seed'

config nodes 'sk'
\toption type 'Xray'
\toption protocol 'socks'
\toption remarks 'socks auth'
\toption address '192.0.2.5'
\toption port '1080'
\toption username 'u'
\toption password 'p'
\toption transport 'raw'

config nodes 'shunt'
\toption type 'Xray'
\toption protocol '_shunt'
\toption remarks 'Shunt'
\toption domainStrategy 'AsIs'
\toption domainMatcher 'hybrid'
\toption write_ipset_direct '1'
\toption Direct '_direct'
\toption Block '_blackhole'
\toption default_node 'ss22'

config socks 'sock1'
\toption port '1082'
\toption enabled '1'
\toption node 'ssc'
\toption http_port '0'
";

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// `run_socks` args of a SOCKS instance for `node` (no side effects).
fn socks_args(node: &str) -> Args {
    args(&[("flag", node), ("node", node), ("local_socks_address", "127.0.0.1"), ("local_socks_port", "1082"), ("no_run", "1"), ("loglevel", "warning")])
}

/// `run_xray` args of the transparent-proxy instance (default ACL), as the service builds them
/// for a 26.4-era router config.
fn global_args(node: &str) -> Args {
    args(&[
        ("flag", "acl_default"),
        ("node", node),
        ("loglevel", "info"),
        ("local_socks_address", "0.0.0.0"),
        ("local_socks_port", "1070"),
        ("redir_port", "2001"),
        ("tcp_proxy_way", "redirect"),
        ("dns_listen_port", "2002"),
        ("direct_dns_udp_server", "192.168.70.1"),
        ("direct_dns_udp_port", "53"),
        ("direct_dns_query_strategy", "UseIP"),
        ("remote_dns_tcp_server", "1.1.1.1"),
        ("remote_dns_tcp_port", "53"),
        ("remote_dns_query_strategy", "UseIPv4"),
        ("remote_dns_detour", "remote"),
        ("no_run", "1"),
    ])
}

const LEGACY_XRAY: &str = "26.1.31";
const NEW_XRAY: &str = "26.10.31";

/// Every object of a JSON tree.
fn objects(v: &Value, out: &mut Vec<(String, Map<String, Value>)>, key: &str) {
    match v {
        Value::Object(m) => {
            out.push((key.to_string(), m.clone()));
            for (k, x) in m {
                objects(x, out, k);
            }
        }
        Value::Array(a) => {
            for x in a {
                objects(x, out, key);
            }
        }
        _ => {}
    }
}

/// Invariants of the legacy (Xray < 26.5.9) form; returns the problems found.
fn legacy_problems(c: &Value) -> Vec<String> {
    let mut p = vec![];
    if c.get("version").is_some() {
        p.push("version.min present".into());
    }
    let mut all = vec![];
    objects(c, &mut all, "");
    for (k, m) in &all {
        if k == "streamSettings" && m.contains_key("method") {
            p.push(format!("streamSettings.method: {:?}", m.get("method")));
        }
        for bad in ["allowedNetwork", "rewriteAddress", "rewritePort", "rewriteNetwork", "pinnedPeerCertSha256_x"] {
            if m.contains_key(bad) {
                p.push(format!("{} in {}", bad, k));
            }
        }
        if m.get("protocol").and_then(|x| x.as_str()) == Some("tunnel") {
            p.push("tunnel protocol".into());
        }
        if m.get("type").and_then(|x| x.as_str()) == Some("mkcp-legacy") {
            p.push("mkcp-legacy mask".into());
        }
    }
    for ob in c["outbounds"].as_array().into_iter().flatten() {
        let proto = ob["protocol"].as_str().unwrap_or("");
        let s = &ob["settings"];
        match proto {
            "vless" | "vmess" => {
                if s.get("vnext").is_none() || s.get("address").is_some() || s.get("id").is_some() {
                    p.push(format!("{} outbound not in vnext form", proto));
                }
            }
            "shadowsocks" => {
                let m = s.pointer("/servers/0/method").and_then(|x| x.as_str()).unwrap_or("");
                if m.is_empty() {
                    p.push("shadowsocks outbound without method".into());
                }
            }
            "trojan" | "socks" | "http" if s.get("servers").is_none() => p.push(format!("{} outbound not in servers form", proto)),
            _ => {}
        }
        let proxied = !matches!(proto, "freedom" | "blackhole" | "dns" | "loopback");
        if proxied && ob.get("streamSettings").is_some() && ob.pointer("/streamSettings/network").is_none() {
            p.push(format!("{} outbound without streamSettings.network", proto));
        }
    }
    p
}

/// Invariants of the modern (upstream master) form.
fn modern_problems(c: &Value) -> Vec<String> {
    let mut p = vec![];
    if c.pointer("/version/min").and_then(|x| x.as_str()) != Some(XRAY_MIN_VERSION) {
        p.push("version.min missing".into());
    }
    for ob in c["outbounds"].as_array().into_iter().flatten() {
        let proto = ob["protocol"].as_str().unwrap_or("");
        if proto == "shadowsocks" && ob.pointer("/settings/method").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
            p.push("shadowsocks outbound without method".into());
        }
        if ob.pointer("/streamSettings/network").is_some() {
            p.push("streamSettings.network in modern form".into());
        }
    }
    p
}

fn node_ids(cfg: &Config) -> Vec<String> {
    cfg.sections_of("nodes").map(|s| s.name.clone()).collect()
}

#[test]
fn every_node_legacy_and_modern() {
    let cfg = Config::parse("passwall2", LEGACY_CONF);
    let old = XrayCaps::from_version(LEGACY_XRAY);
    let new = XrayCaps::from_version(NEW_XRAY);
    for id in node_ids(&cfg) {
        let a = socks_args(&id);
        let lc = gen_config_caps(&cfg, &a, &old, false);
        let lp = legacy_problems(&lc);
        assert!(lp.is_empty(), "node {} legacy: {:?}\n{:#}", id, lp, lc);
        let mc = gen_config_caps(&cfg, &a, &new, false);
        let mp = modern_problems(&mc);
        assert!(mp.is_empty(), "node {} modern: {:?}\n{:#}", id, mp, mc);
        // modern output is exactly the upstream-parity generator output
        assert_eq!(mc, build_config(&cfg, &a, false));
    }
}

#[test]
fn legacy_shadowsocks_cipher_from_method() {
    let cfg = Config::parse("passwall2", LEGACY_CONF);
    let c = gen_config_caps(&cfg, &socks_args("ssc"), &XrayCaps::from_version(LEGACY_XRAY), false);
    let ob = c["outbounds"].as_array().unwrap().iter().find(|o| o["protocol"] == "shadowsocks").unwrap();
    // upstream 26.4.20 form
    assert_eq!(
        ob["settings"],
        json!({"servers": [{"address": "203.0.113.10", "port": 1044, "method": "chacha20-poly1305", "password": "pw1"}]})
    );
    assert_eq!(ob["streamSettings"]["network"], "raw");
    let m = gen_config_caps(&cfg, &socks_args("ssc"), &XrayCaps::modern(), false);
    let ob = m["outbounds"].as_array().unwrap().iter().find(|o| o["protocol"] == "shadowsocks").unwrap();
    assert_eq!(ob["settings"]["method"], "chacha20-poly1305");
    assert_eq!(ob["streamSettings"]["method"], "raw");
}

#[test]
fn legacy_transports_and_tls() {
    let cfg = Config::parse("passwall2", LEGACY_CONF);
    let old = XrayCaps::from_version(LEGACY_XRAY);
    // the node's outbound (tagged `default:<remarks>` in a single-node instance)
    let ob = |id: &str| -> Value {
        let c = gen_config_caps(&cfg, &socks_args(id), &old, false);
        c["outbounds"].as_array().unwrap().iter().find(|o| !matches!(o["protocol"].as_str(), Some("freedom" | "blackhole" | "dns" | "loopback"))).cloned().unwrap()
    };
    let ws = ob("vws");
    assert_eq!(ws["streamSettings"]["network"], "ws");
    assert_eq!(ws["streamSettings"]["wsSettings"]["path"], "/graphql?ed=2560");
    assert_eq!(ws["settings"]["vnext"][0]["users"][0]["encryption"], "none");
    assert_eq!(ws["settings"]["vnext"][0]["users"][0]["level"], 0);
    // 26.1.31 has pinned certs: the legacy tls_CertSha is honoured
    let t = ob("trj");
    assert_eq!(t["streamSettings"]["network"], "grpc");
    assert_eq!(t["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // older than 26.1.31: dropped like upstream 26.4.20
    let c = gen_config_caps(&cfg, &socks_args("trj"), &XrayCaps::from_version("25.12.8"), false);
    assert!(c.pointer("/outbounds/0/streamSettings/tlsSettings/pinnedPeerCertSha256").is_none());
    let x = ob("vxhttp");
    assert_eq!(x["streamSettings"]["network"], "xhttp");
    let r = ob("vreal");
    assert_eq!(r["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
    let k = ob("kcp");
    assert_eq!(k["streamSettings"]["network"], "mkcp");
    assert_eq!(
        k["streamSettings"]["finalmask"]["udp"],
        json!([{"type": "header-wechat"}, {"type": "mkcp-aes128gcm", "settings": {"password": "seed"}}])
    );
    let s = ob("sk");
    assert_eq!(s["settings"], json!({"servers": [{"address": "192.0.2.5", "port": 1080, "users": [{"user": "u", "pass": "p"}]}]}));
}

#[test]
fn legacy_global_instance() {
    let cfg = Config::parse("passwall2", LEGACY_CONF);
    let old = XrayCaps::from_version(LEGACY_XRAY);
    let c = gen_config_caps(&cfg, &global_args("ssc"), &old, false);
    let lp = legacy_problems(&c);
    assert!(lp.is_empty(), "{:?}\n{:#}", lp, c);
    let ib = |tag: &str| c["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == tag).cloned().unwrap();
    assert_eq!(ib("dns-in")["protocol"], "dokodemo-door");
    assert_eq!(ib("dns-in")["settings"], json!({"network": "tcp,udp", "address": "0.0.0.0"}));
    assert_eq!(ib("tcp_redir")["settings"], json!({"network": "tcp", "followRedirect": true}));
    assert_eq!(ib("udp_redir")["settings"], json!({"network": "udp", "followRedirect": true}));
    let dns = c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "dns-out").cloned().unwrap();
    assert_eq!(dns["settings"], json!({"address": "192.168.70.1", "port": 53, "network": "udp", "nonIPQuery": "skip", "blockTypes": [65]}));
    assert_eq!(dns["streamSettings"]["sockopt"]["dialerProxy"], "direct");
}

#[test]
fn legacy_shunt_blackhole_dns_and_socks_auth() {
    let cfg = Config::parse("passwall2", LEGACY_CONF);
    let old = XrayCaps::from_version(LEGACY_XRAY);
    let mut a = global_args("shunt");
    a.insert("local_socks_username".into(), "u".into());
    a.insert("local_socks_password".into(), "p".into());
    let c = gen_config_caps(&cfg, &a, &old, false);
    let lp = legacy_problems(&c);
    assert!(lp.is_empty(), "{:?}\n{:#}", lp, c);
    assert_eq!(c["dns"]["hosts"]["domain:ads.example"], "0.0.0.0");
    let socks = c["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "socks-in").cloned().unwrap();
    assert_eq!(socks["settings"]["accounts"], json!([{"user": "u", "pass": "p"}]));
    assert!(socks["settings"].get("users").is_none());
    // modern: rules-based blocking, no hosts entry
    let m = gen_config_caps(&cfg, &a, &XrayCaps::modern(), false);
    assert!(m.pointer("/dns/hosts/domain:ads.example").is_none());
}

#[test]
fn legacy_fragment_without_finalmask_tcp() {
    let conf = format!("{}\nconfig global_xray 'x2'\n\toption fragment '1'\n\toption fragment_length '100-200'\n\toption fragment_delay '10'\n", LEGACY_CONF.replace("config global_xray\n\toption sniffing_override_dest '0'\n", ""));
    let cfg = Config::parse("passwall2", &conf);
    // 26.3.23 .. 26.6.26: finalmask fragment with single length/delay
    let c = gen_config_caps(&cfg, &global_args("vws"), &XrayCaps::from_version("26.5.9"), false);
    let ob = c["outbounds"].as_array().unwrap().iter().find(|o| o["protocol"] == "vless").cloned().unwrap();
    assert_eq!(ob["streamSettings"]["finalmask"]["tcp"][0]["settings"]["length"], "100-200");
    assert_eq!(ob["streamSettings"]["finalmask"]["tcp"][0]["settings"]["delay"], 10);
    // 26.1.31: freedom fragment outbound chained with dialerProxy
    let c = gen_config_caps(&cfg, &global_args("vws"), &XrayCaps::from_version(LEGACY_XRAY), false);
    let ob = c["outbounds"].as_array().unwrap().iter().find(|o| o["protocol"] == "vless").cloned().unwrap();
    assert!(ob["streamSettings"].get("finalmask").is_none());
    assert_eq!(ob["streamSettings"]["sockopt"]["dialerProxy"], "fragment");
    let fr = c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "fragment").cloned().unwrap();
    assert_eq!(fr["settings"]["fragment"], json!({"packets": "tlshello", "length": "100-200", "interval": 10}));
}

#[test]
fn legacy_proto_and_server() {
    let a = args(&[("local_socks_port", "1081"), ("local_socks_username", "u"), ("local_socks_password", "p"), ("server_proto", "socks"), ("server_address", "127.0.0.1"), ("server_port", "1082")]);
    let c = gen_proto_config_caps(&a, &XrayCaps::from_version(LEGACY_XRAY)).unwrap();
    assert!(c.get("version").is_none());
    assert_eq!(c["inbounds"][0]["settings"]["accounts"], json!([{"user": "u", "pass": "p"}]));
    assert_eq!(c["outbounds"][0]["streamSettings"]["network"], "raw");

    let cfg_s = Config::parse(
        "passwall2_server",
        "config server 's1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption port '443'\n\toption transport 'ws'\n\toption ws_path '/p'\n\tlist users 'u1'\n\
         config user 'u1'\n\toption uuid '00000000-0000-4000-8000-000000000009'\n\
         config server 's2'\n\toption type 'Xray'\n\toption protocol 'dokodemo-door'\n\toption port '5353'\n\toption d_protocol 'udp'\n\toption d_address '1.1.1.1'\n\toption d_port '53'\n\
         config server 's3'\n\toption type 'Xray'\n\toption protocol 'shadowsocks'\n\toption port '8388'\n\toption method 'aes-128-gcm'\n\toption password 'pw'\n",
    );
    let cfg_c = Config::parse("passwall2", "");
    let old = XrayCaps::from_version(LEGACY_XRAY);
    let srv = |id: &str, caps: &XrayCaps| server_config_caps(&cfg_c, &cfg_s, node_of(cfg_s.section(id).unwrap()), caps, false);
    let v = srv("s1", &old);
    assert_eq!(v["inbounds"][0]["streamSettings"]["network"], "ws");
    assert_eq!(v["inbounds"][0]["settings"]["clients"][0]["id"], "00000000-0000-4000-8000-000000000009");
    let d = srv("s2", &old);
    assert_eq!(d["inbounds"][0]["protocol"], "dokodemo-door");
    assert_eq!(d["inbounds"][0]["settings"], json!({"network": "udp", "address": "1.1.1.1", "port": 53}));
    let d = srv("s2", &XrayCaps::modern());
    assert_eq!(d["inbounds"][0]["protocol"], "tunnel");
    let s = srv("s3", &XrayCaps::modern());
    assert_eq!(s["inbounds"][0]["settings"]["method"], "aes-128-gcm");
    assert_eq!(s["inbounds"][0]["settings"]["password"], "pw");
}

/// End-to-end helper (VM only): `PASSWALL2_REAL_UCI=<dir> PASSWALL2_DUMP_DIR=<dir> cargo test
/// real_config_dump -- --ignored`. Writes `<dump>/<legacy|modern>/<node>.json` (SOCKS instance)
/// and `global_<node>.json` (transparent proxy) for the global node and every shunt node.
#[test]
#[ignore]
fn real_config_dump() {
    let (Ok(dir), Ok(out)) = (std::env::var("PASSWALL2_REAL_UCI"), std::env::var("PASSWALL2_DUMP_DIR")) else {
        panic!("set PASSWALL2_REAL_UCI and PASSWALL2_DUMP_DIR");
    };
    let text = std::fs::read_to_string(format!("{}/passwall2", dir)).expect("passwall2 config");
    let cfg = Config::parse("passwall2", &text);
    let gnode = cfg.get("@global[0]", "node").unwrap_or_default();
    for (name, caps) in [("legacy", XrayCaps::from_version(LEGACY_XRAY)), ("modern", XrayCaps::from_version(NEW_XRAY))] {
        let d = format!("{}/{}", out, name);
        std::fs::create_dir_all(&d).unwrap();
        let mut n = 0;
        for id in node_ids(&cfg) {
            // skip sections that are not runnable Xray nodes (upstream skips them too)
            let s = cfg.section(&id).unwrap();
            if s.get("type").as_deref() != Some("Xray") || s.get("protocol").is_none() {
                continue;
            }
            let c = gen_config_caps(&cfg, &socks_args(&id), &caps, false);
            std::fs::write(format!("{}/{}.json", d, id), serde_json::to_string_pretty(&c).unwrap()).unwrap();
            n += 1;
            if id == gnode || s.get("protocol").as_deref() == Some("_shunt") {
                let c = gen_config_caps(&cfg, &global_args(&id), &caps, false);
                std::fs::write(format!("{}/global_{}.json", d, id), serde_json::to_string_pretty(&c).unwrap()).unwrap();
            }
        }
        eprintln!("{}: {} node configs", name, n);
    }
}
