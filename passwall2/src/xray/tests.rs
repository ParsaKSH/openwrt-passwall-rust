//! Unit tests for the Xray generator (no side effects: `effects = false`, `no_run`).

use super::*;
use base64::Engine;

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn outbound<'a>(cfg: &'a Value, tag: &str) -> &'a Value {
    cfg["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap_or_else(|| panic!("no outbound {tag}: {:#}", cfg["outbounds"]))
}

fn gen(conf: &str, var: &[(&str, &str)]) -> Value {
    let cfg = Config::parse("passwall2", conf);
    build_config(&cfg, &args(var), false)
}

fn set_opt(cfg: &mut Config, sec: &str, k: &str, v: &str) {
    let s = cfg.sections.iter_mut().find(|s| s.name == sec).unwrap();
    s.options.insert(k.to_string(), crate::uci::Value::Single(v.to_string()));
}

/// SHUNT_CONF with the multi-line `domain_list` injected (the line-based test parser cannot hold it).
fn shunt_cfg(extra: &str) -> Config {
    let mut cfg = Config::parse("passwall2", &format!("{}{}", SHUNT_CONF, extra));
    set_opt(&mut cfg, "Proxy", "domain_list", "geosite:google\r\n#comment\next:x.dat:y\nrs:foo\ndomain:abc.com");
    cfg
}

fn node_table(conf: &str, name: &str) -> Node {
    let cfg = Config::parse("passwall2", conf);
    node_of(cfg.section(name).unwrap())
}

fn out_of(conf: &str, name: &str) -> Value {
    let cfg = Config::parse("passwall2", conf);
    let mut g = Gen::new(&cfg, false);
    let mut n = node_table(conf, name);
    let mut v = g.gen_outbound(None, &mut n, None, None);
    prune(&mut v);
    v
}

#[test]
fn vless_reality_xhttp() {
    let extra = b64(r#"{"extra":{"xPaddingBytes":"100-1000","noGRPCHeader":false,"empty":{}}}"#);
    let conf = format!(
        "config nodes 'n1'\n\toption remarks 'HK'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption address 'EXAMPLE.com'\n\
         \toption port '443'\n\toption uuid 'u-u-i-d'\n\toption encryption 'none'\n\toption flow 'xtls-rprx-vision'\n\
         \toption tls '1'\n\toption reality '1'\n\toption tls_serverName 'www.apple.com'\n\toption reality_publicKey 'PUB'\n\
         \toption reality_shortId 'ab12'\n\toption fingerprint 'firefox'\n\toption transport 'xhttp'\n\toption xhttp_mode 'stream-one'\n\
         \toption xhttp_path '/x'\n\toption xhttp_extra '{extra}'\n\toption user_agent 'UA/1'\n"
    );
    let o = out_of(&conf, "n1");
    assert_eq!(o["tag"], "n1:HK");
    assert_eq!(o["protocol"], "vless");
    assert_eq!(o["mux"], json!({"enabled": false}));
    let s = &o["settings"];
    assert_eq!(s["address"], "example.com");
    assert_eq!(s["port"], 443);
    assert_eq!(s["id"], "u-u-i-d");
    assert_eq!(s["encryption"], "none");
    assert_eq!(s["flow"], "xtls-rprx-vision");
    assert_eq!(s["level"], 0);
    let ss = &o["streamSettings"];
    assert_eq!(ss["method"], "xhttp");
    assert_eq!(ss["security"], "reality");
    assert!(ss.get("tlsSettings").is_none());
    assert_eq!(
        ss["realitySettings"],
        json!({"serverName": "www.apple.com", "publicKey": "PUB", "shortId": "ab12", "spiderX": "/", "fingerprint": "firefox"})
    );
    assert_eq!(ss["sockopt"], json!({"mark": 255, "domainStrategy": "UseIP"}));
    assert_eq!(
        ss["xhttpSettings"],
        json!({"mode": "stream-one", "path": "/x", "extra": {"xPaddingBytes": "100-1000", "noGRPCHeader": false, "headers": {"User-Agent": "UA/1"}}})
    );
    assert!(ss.get("finalmask").is_none());
}

#[test]
fn vmess_ws_tls_alpn() {
    let conf = "config nodes 'vm'\n\toption type 'Xray'\n\toption protocol 'vmess'\n\toption address '1.2.3.4'\n\toption port '8443'\n\
                \toption uuid 'id1'\n\toption security 'auto'\n\toption tls '1'\n\toption tls_serverName 'a.com'\n\toption utls '1'\n\
                \toption fingerprint 'chrome'\n\toption alpn 'h2,http/1.1'\n\toption transport 'ws'\n\toption ws_host 'a.com'\n\
                \toption ws_path '/ws'\n\toption ws_maxEarlyData '2048'\n\toption mux '1'\n\toption tcp_fast_open '1'\n";
    let o = out_of(conf, "vm");
    assert_eq!(o["tag"], "vm");
    assert_eq!(o["mux"], json!({"enabled": true, "concurrency": -1, "xudpConcurrency": 8}));
    assert_eq!(o["settings"]["security"], "auto");
    assert!(o["settings"].get("encryption").is_none());
    let ss = &o["streamSettings"];
    assert_eq!(ss["security"], "tls");
    assert_eq!(
        ss["tlsSettings"],
        json!({"serverName": "a.com", "fingerprint": "chrome", "pinnedPeerCertSha256": "", "verifyPeerCertByName": "", "alpn": ["h2", "http/1.1"]})
    );
    assert_eq!(ss["wsSettings"], json!({"path": "/ws", "host": "a.com", "maxEarlyData": 2048}));
    assert_eq!(ss["sockopt"]["tcpFastOpen"], true);
    assert!(!api::dt_hostname("1.2.3.4"));
}

#[test]
fn trojan_and_ss() {
    let conf = "config nodes 'tr'\n\toption type 'Xray'\n\toption protocol 'trojan'\n\toption address 't.example'\n\toption port '443'\n\
                \toption password 'pw'\n\toption tls '1'\n\toption tls_pinSHA256 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='\n\
                \toption transport 'raw'\n\toption tcp_guise 'http'\n\tlist tcp_guise_http_path ''\n\tlist tcp_guise_http_path '/p'\n\
                \tlist tcp_guise_http_host 'h.com'\n\
                config nodes 'ss'\n\toption type 'Xray'\n\toption protocol 'shadowsocks'\n\toption address '5.6.7.8'\n\toption port '8388'\n\
                \toption password 'sspw'\n\toption ss_method 'chacha20-ietf-poly1305'\n\toption transport 'raw'\n";
    let t = out_of(conf, "tr");
    assert_eq!(t["settings"]["password"], "pw");
    assert!(t["settings"].get("method").is_none());
    let tls = &t["streamSettings"]["tlsSettings"];
    assert_eq!(tls["pinnedPeerCertSha256"], "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    assert_eq!(
        t["streamSettings"]["rawSettings"],
        json!({"header": {"type": "http", "request": {"path": ["/", "/p"], "headers": {"Host": ["h.com"]}}}})
    );
    let s = out_of(conf, "ss");
    assert_eq!(s["settings"], json!({"address": "5.6.7.8", "port": 8388, "password": "sspw", "method": "chacha20-poly1305", "level": 0}));
    assert_eq!(s["streamSettings"]["method"], "raw");
    assert!(s["streamSettings"].get("security").is_none());
}

#[test]
fn hysteria2_finalmask_and_realm() {
    let conf = "config nodes 'hy'\n\toption type 'Xray'\n\toption protocol 'hysteria2'\n\toption address 'h.example'\n\toption port '443'\n\
                \toption hysteria2_auth_password 'pass'\n\toption hysteria2_obfs_type 'gecko'\n\toption hysteria2_obfs_password 'ob'\n\
                \toption hysteria2_obfs_MinPacketSize '600'\n\toption hysteria2_obfs_MaxPacketSize '5000'\n\toption hysteria2_up_mbps '50'\n\
                \toption hysteria2_hop '20000:30000'\n\toption hysteria2_hop_interval '3-20'\n\toption hysteria2_idle_timeout '200'\n\
                \toption hysteria2_keep_alive_period '10'\n\toption hysteria2_stream_recv_win '8'\n\toption tls_serverName 'h.example'\n";
    let o = out_of(conf, "hy");
    assert_eq!(o["protocol"], "hysteria");
    assert_eq!(o["settings"]["version"], 2);
    let ss = &o["streamSettings"];
    assert_eq!(ss["method"], "hysteria");
    assert_eq!(ss["security"], "tls");
    assert_eq!(ss["hysteriaSettings"], json!({"version": 2, "auth": "pass"}));
    assert_eq!(ss["finalmask"]["udp"], json!([{"type": "salamander", "settings": {"password": "ob", "packetSize": "512-1200"}}]));
    assert_eq!(
        ss["finalmask"]["quicParams"],
        json!({
            "congestion": "brutal", "brutalUp": "50mbps",
            "udpHop": {"ports": "20000-30000", "interval": "5-20"},
            "maxIdleTimeout": 30, "keepAlivePeriod": 10, "disablePathMTUDiscovery": false,
            "initStreamReceiveWindow": 8388608, "maxStreamReceiveWindow": 8388608
        })
    );
    // realm overrides address/port and adds the realm mask
    let conf2 = "config nodes 'hr'\n\toption type 'Xray'\n\toption protocol 'hysteria2'\n\toption address 'x'\n\toption port '1'\n\
                 \toption hysteria2_realms '1'\n\toption hysteria2_realm_url 'realm://tok@r.example:8443/id1/?stun=s1:3478&stun=s2:3478'\n";
    let r = out_of(conf2, "hr");
    assert_eq!(r["settings"]["address"], "r.example");
    assert_eq!(r["settings"]["port"], 8443);
    assert_eq!(
        r["streamSettings"]["finalmask"]["udp"],
        json!([{"type": "realm", "settings": {"url": "realm://tok@r.example:8443/id1", "stunServers": ["s1:3478", "s2:3478"]}}])
    );
    assert_eq!(hop_interval(None), json!(30));
    assert_eq!(hop_interval(Some("3".into())), json!(30));
    assert_eq!(hop_interval(Some("45s".into())), json!(45));
    assert_eq!(hop_interval(Some("a-b".into())), json!(30));
}

#[test]
fn wireguard_outbound() {
    let conf = "config nodes 'wg'\n\toption type 'Xray'\n\toption protocol 'wireguard'\n\toption address 'Engage.Cloudflareclient.com'\n\
                \toption port '2408'\n\tlist wireguard_local_address '172.16.0.2/32'\n\toption wireguard_secret_key 'SK'\n\
                \toption wireguard_public_key 'PK'\n\toption wireguard_reserved '1,2,3'\n\toption wireguard_mtu '1280'\n\toption alpn 'h2'\n";
    let o = out_of(conf, "wg");
    assert!(o.get("streamSettings").is_none());
    assert_eq!(
        o["settings"],
        json!({"address": ["172.16.0.2/32"], "port": 2408, "secretKey": "SK",
               "peers": [{"publicKey": "PK", "endpoint": "engage.cloudflareclient.com:2408"}],
               "mtu": 1280, "reserved": [1, 2, 3], "level": 0, "noKernelTun": true})
    );
    assert_eq!(wireguard_reserved("AAEC"), Some(vec![0, 1, 2]));
    assert_eq!(wireguard_reserved(""), None);
}

#[test]
fn domain_resolver_bootstrap() {
    let conf = "config nodes 'd'\n\toption type 'Xray'\n\toption protocol 'trojan'\n\toption address 'srv.example'\n\toption port '443'\n\
                \toption domain_resolver 'https'\n\toption domain_resolver_dns_https 'https://dns.example/dns-query'\n\toption domain_strategy 'UseIPv4'\n";
    let cfg = Config::parse("passwall2", conf);
    let mut g = Gen::new(&cfg, false);
    let mut n = node_of(cfg.section("d").unwrap());
    g.gen_outbound(None, &mut n, None, None);
    assert_eq!(
        g.dns_server["d"],
        json!({"tag": "d_dns", "queryStrategy": "UseIPv4", "address": "https://dns.example/dns-query", "port": 443,
               "domains": ["full:srv.example"], "finalQuery": true, "disableCache": false, "serveStale": true})
    );
    assert_eq!(g.dns_hostname, vec!["dns.example".to_string()]);
}

#[test]
fn non_xray_node_no_run_uses_local_socks() {
    let conf = "config nodes 'sb'\n\toption remarks 'SB'\n\toption type 'sing-box'\n\toption protocol 'tuic'\n\toption address 'x.example'\n\toption port '1'\n";
    let c = gen(conf, &[("flag", "global"), ("node", "sb"), ("no_run", "1"), ("local_socks_port", "1070")]);
    let o = outbound(&c, "default:SB");
    assert_eq!(o["protocol"], "socks");
    assert_eq!(o["settings"], json!({"address": "127.0.0.1", "port": 3001, "level": 0}));
    assert_eq!(o["streamSettings"]["security"], "none");
    assert!(o.get("_flag_proxy_tag").is_none());
    // default is the node → first outbound; direct/blackhole appended
    assert_eq!(c["outbounds"][0]["tag"], "default:SB");
    assert_eq!(c["outbounds"][1]["tag"], "direct");
    assert_eq!(c["outbounds"][2]["tag"], "blackhole");
    // socks-in sniffing uses the unwrapped node (not _shunt) → disabled
    assert_eq!(c["inbounds"][0]["sniffing"], json!({"enabled": false}));
    assert_eq!(c["routing"]["rules"], json!([{"ruleTag": "default", "outboundTag": "default:SB", "network": "tcp,udp"}]));
    assert_eq!(c["routing"]["domainStrategy"], "AsIs");
    assert_eq!(c["dns"]["servers"], json!([{"tag": "local", "address": "localhost"}]));
    assert_eq!(c["version"]["min"], "26.7.11");
    assert_eq!(c["policy"]["levels"]["0"], json!({"statsUserUplink": false, "statsUserDownlink": false}));
    assert_eq!(c["env"]["XRAY_LOCATION_ASSET"], "/usr/share/v2ray/");
}

const SHUNT_CONF: &str = "config global_rules\n\toption v2ray_location_asset '/usr/share/v2ray/'\n\
config global_xray\n\toption sniffing_override_dest '0'\n\
config shunt_rules 'Proxy'\n\toption remarks 'Proxy'\n\toption network 'tcp,udp'\n\
config shunt_rules 'CN'\n\toption remarks 'China'\n\toption ip_list 'geoip:cn'\n\toption domain_list 'geosite:cn'\n\
config shunt_rules 'Ads'\n\toption remarks 'Ads'\n\toption domain_list 'geosite:category-ads'\n\toption inbound 'tproxy socks'\n\
config nodes 'a'\n\toption remarks 'A'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption address '1.1.1.1'\n\toption port '1'\n\toption uuid 'x'\n\
config nodes 'b'\n\toption remarks 'B'\n\toption type 'Xray'\n\toption protocol 'trojan'\n\toption address '2.2.2.2'\n\toption port '2'\n\toption password 'p'\n\
config nodes 'bal'\n\toption remarks 'Bal'\n\toption type 'Xray'\n\toption protocol '_balancing'\n\tlist balancing_node 'a'\n\tlist balancing_node 'b'\n\
\toption balancingStrategy 'leastPing'\n\toption fallback_node '_direct'\n\toption probeInterval '5'\n\
config nodes 'sh'\n\toption remarks 'Shunt'\n\toption type 'Xray'\n\toption protocol '_shunt'\n\toption default_node 'bal'\n\
\toption Proxy 'a'\n\toption CN '_direct'\n\toption Ads '_blackhole'\n\toption domainStrategy 'IPIfNonMatch'\n";

#[test]
fn shunt_with_balancer() {
    let cfg = shunt_cfg("");
    let c = build_config(&cfg, &args(&[("flag", "global"), ("node", "sh"), ("no_run", "1"), ("redir_port", "1041"), ("tcp_proxy_way", "redirect")]), false);
    // balancer loopback "default" goes first, members appended, then rule outbounds
    let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, vec!["default", "blc-a:A", "blc-b:B", "Proxy:A", "direct", "blackhole"]);
    assert_eq!(outbound(&c, "default"), &json!({"protocol": "loopback", "tag": "default", "settings": {"inboundTag": "lo-to-bal"}}));
    let r = &c["routing"];
    assert_eq!(r["domainStrategy"], "IPIfNonMatch");
    assert_eq!(r["domainMatcher"], "hybrid");
    assert_eq!(
        r["balancers"],
        json!([{"tag": "balancer-bal", "selector": ["blc-a:A", "blc-b:B"], "fallbackTag": "direct", "strategy": {"type": "leastPing"}}])
    );
    assert_eq!(c["observatory"], json!({"subjectSelector": ["blc-"], "probeInterval": "10s", "enableConcurrency": true}));
    assert!(c.get("burstObservatory").is_none());
    assert_eq!(
        r["rules"],
        json!([
            {"inboundTag": ["lo-to-bal"], "balancerTag": "balancer-bal"},
            {"ruleTag": "Proxy Domains", "outboundTag": "Proxy:A", "network": "tcp,udp", "domains": ["geosite:google", "domain:abc.com"]},
            {"ruleTag": "China Domains", "outboundTag": "direct", "network": "tcp,udp", "domains": ["geosite:cn"]},
            {"ruleTag": "China IP", "outboundTag": "direct", "network": "tcp,udp", "ip": ["geoip:cn"]},
            {"ruleTag": "Ads Domains", "inboundTag": ["tcp_redir", "udp_redir"], "outboundTag": "blackhole", "network": "tcp,udp", "domains": ["geosite:category-ads"]},
            {"ruleTag": "default", "outboundTag": "default", "port": "1-65535"}
        ])
    );
    // redir inbounds: sniffing on (shunt), routeOnly since override is off
    let tcp = &c["inbounds"][0];
    assert_eq!(tcp["tag"], "tcp_redir");
    assert_eq!(tcp["settings"], json!({"allowedNetwork": "tcp", "followRedirect": true}));
    assert_eq!(tcp["streamSettings"]["sockopt"]["tproxy"], "redirect");
    assert_eq!(tcp["sniffing"], json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "metadataOnly": false, "routeOnly": true}));
    assert_eq!(c["inbounds"][1]["tag"], "udp_redir");
    assert_eq!(c["inbounds"][1]["streamSettings"]["sockopt"]["tproxy"], "tproxy");
}

#[test]
fn shunt_fakedns_and_dns() {
    let mut cfg = shunt_cfg("\toption fakedns '1'\n\toption Proxy_fakedns '1'\nconfig global 'g'\nconfig nodes 'v'\n\toption address 'VPS.example'\n");
    set_opt(&mut cfg, "g", "dns_hosts", "h.lan 10.0.0.1\n  bad\r\nx.lan   10.0.0.2  extra");
    let c = build_config(
        &cfg,
        &args(&[
            ("flag", "global"),
            ("node", "sh"),
            ("no_run", "1"),
            ("redir_port", "1041"),
            ("tcp_proxy_way", "tproxy"),
            ("dns_listen_port", "15353"),
            ("direct_dns_udp_server", "223.5.5.5"),
            ("direct_dns_udp_port", "53"),
            ("remote_dns_tcp_server", "1.1.1.1"),
            ("remote_dns_tcp_port", "53"),
            ("remote_dns_query_strategy", "UseIPv4"),
            ("dns_cache", "0"),
        ]),
        false,
    );
    assert_eq!(c["fakedns"], json!([{"ipPool": "198.18.0.0/16", "poolSize": 65535}]));
    let dns = &c["dns"];
    assert_eq!(dns["hosts"], json!({"h.lan": "10.0.0.1", "x.lan": "10.0.0.2"}));
    assert_eq!(dns["disableCache"], true);
    let servers = dns["servers"].as_array().unwrap();
    let stags: Vec<&str> = servers.iter().map(|s| s["tag"].as_str().unwrap()).collect();
    // default (remote, because default outbound is the balancer) first, then per-rule servers, vpslist last
    assert_eq!(stags, vec!["dns-in-default", "dns-in-Proxy", "dns-in-CN", "dns-in-vpslist"]);
    assert_eq!(servers[0], json!({"tag": "dns-in-default", "queryStrategy": "UseIPv4", "address": "tcp://1.1.1.1:53", "port": 53}));
    assert_eq!(servers[1], json!({"tag": "dns-in-Proxy", "address": "fakedns", "finalQuery": true, "domains": ["geosite:google", "domain:abc.com"]}));
    assert_eq!(servers[2]["address"], "223.5.5.5");
    assert_eq!(servers[2]["domains"], json!(["geosite:cn"]));
    assert_eq!(servers[3], json!({"tag": "dns-in-vpslist", "address": "localhost", "domains": ["full:vps.example"], "finalQuery": true, "disableCache": false, "serveStale": true}));
    // DNS outbound: shunt rules prepended (hijack/return), then the static rules
    let dout = outbound(&c, "dns-out");
    let drules = dout["settings"]["rules"].as_array().unwrap();
    assert_eq!(drules[0], json!({"action": "hijack", "qType": "1,28", "domain": ["geosite:google", "domain:abc.com"]}));
    assert_eq!(drules[1], json!({"action": "hijack", "qType": "1,28", "domain": ["geosite:cn"]}));
    assert_eq!(drules[2], json!({"action": "return", "rCode": 0, "domain": ["geosite:category-ads"]}));
    assert_eq!(drules.len(), 6);
    assert_eq!(dout["settings"]["rewriteAddress"], "223.5.5.5");
    // routing: dns server rules first (default→default, CN→direct; fakedns has none), then dns-in, ..., default last
    let rules = c["routing"]["rules"].as_array().unwrap();
    assert_eq!(rules[0], json!({"inboundTag": ["dns-in-default"], "outboundTag": "default"}));
    assert_eq!(rules[1], json!({"inboundTag": ["dns-in-CN"], "outboundTag": "direct"}));
    assert_eq!(rules[2], json!({"inboundTag": ["dns-in"], "outboundTag": "dns-out"}));
    assert_eq!(rules.last().unwrap()["ruleTag"], "default");
    // fakedns sniffing on redir inbounds
    assert_eq!(c["inbounds"][1]["sniffing"]["destOverride"], json!(["http", "tls", "quic", "fakedns"]));
    let dns_in = c["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "dns-in").unwrap();
    assert_eq!(dns_in, &json!({"listen": "127.0.0.1", "port": 15353, "protocol": "tunnel", "tag": "dns-in", "settings": {"allowedNetwork": "tcp,udp"}}));
}

#[test]
fn vps_domain_list() {
    let cfg = Config::parse(
        "passwall2",
        "config nodes 'a'\n\toption address 'Foo.Example.COM'\nconfig nodes 'b'\n\toption address '1.2.3.4'\n\
         config nodes 'c'\n\toption outbound_node_address 'bar.net'\nconfig nodes 'd'\n\toption address 'Foo.Example.COM'\n",
    );
    // `sort -u` (byte order) runs before lowercasing, like upstream
    assert_eq!(vps_domains(&cfg), vec!["full:foo.example.com".to_string(), "full:bar.net".to_string()]);
}

#[test]
fn chain_preproxy_and_landing() {
    let conf = "config nodes 'pre'\n\toption remarks 'Pre'\n\toption type 'Xray'\n\toption protocol 'socks'\n\toption address '9.9.9.9'\n\toption port '1080'\n\
                config nodes 'land'\n\toption remarks 'Land'\n\toption type 'Xray'\n\toption protocol 'trojan'\n\toption address '8.8.8.8'\n\toption port '443'\n\toption password 'p'\n\
                config nodes 'main'\n\toption remarks 'Main'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption address '7.7.7.7'\n\toption port '443'\n\toption uuid 'u'\n\
                \toption chain_proxy '1'\n\toption preproxy_node 'pre'\n";
    let c = gen(conf, &[("flag", "global"), ("node", "main"), ("no_run", "1")]);
    let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, vec!["pre:Pre -> default:Main", "pre:Pre", "direct", "blackhole"]);
    assert_eq!(c["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "pre:Pre");
    assert_eq!(c["routing"]["rules"][0]["outboundTag"], "pre:Pre -> default:Main");

    // landing node via shunt "_proxy_tag"
    let conf2 = format!(
        "{}config shunt_rules 'R'\n\toption remarks 'R'\n\toption domain_list 'domain:x.com'\n\
         config nodes 'sh'\n\toption type 'Xray'\n\toption protocol '_shunt'\n\toption default_node '_direct'\n\toption R 'land'\n\toption R_proxy_tag 'pre'\n",
        conf
    );
    let c2 = gen(&conf2, &[("flag", "global"), ("node", "sh"), ("no_run", "1")]);
    let tags: Vec<&str> = c2["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, vec!["direct", "R:Pre -> land:Land", "R:Pre", "blackhole"]);
    assert_eq!(outbound(&c2, "R:Pre -> land:Land")["streamSettings"]["sockopt"]["dialerProxy"], "R:Pre");
    assert_eq!(c2["routing"]["rules"][0]["outboundTag"], "R:Pre -> land:Land");
    assert_eq!(c2["routing"]["rules"][1], json!({"ruleTag": "default", "outboundTag": "direct", "network": "tcp,udp"}));
}

#[test]
fn fragment_and_noise() {
    let conf = "config global_xray\n\toption fragment '1'\n\toption fragment_lengths ' 1-2 , ,3-4'\n\toption noise '1'\n\
                config xray_noise_packets 'n1'\n\toption enabled '1'\n\toption type 'rand'\n\toption packet '10-20'\n\toption delay '5'\n\
                config xray_noise_packets 'n2'\n\toption enabled '1'\n\toption type 'str'\n\toption packet 'abc'\n\
                config nodes 'k'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption address '1.1.1.1'\n\toption port '1'\n\toption uuid 'u'\n\
                \toption transport 'mkcp'\n\toption mkcp_guise 'wechat-video'\n\toption mkcp_seed 'seed'\n";
    let c = gen(conf, &[("flag", "global"), ("node", "k"), ("no_run", "1")]);
    let o = outbound(&c, "default");
    assert_eq!(o["streamSettings"]["kcpSettings"]["mtu"], 1350);
    assert_eq!(
        o["streamSettings"]["finalmask"],
        json!({"udp": [
            {"type": "mkcp-legacy", "settings": {"value": "seed"}},
            {"type": "mkcp-legacy", "settings": {"header": "wechat"}},
            {"type": "noise", "settings": {"reset": 0, "noise": [{"rand": "10-20", "delay": 5}, {"type": "str", "packet": "abc"}]}}
        ]})
    );
    // fragment applies to raw/ws/... transports
    let conf2 = conf.replace("\toption transport 'mkcp'\n", "\toption transport 'ws'\n");
    let c2 = gen(&conf2, &[("flag", "global"), ("node", "k"), ("no_run", "1")]);
    assert_eq!(
        outbound(&c2, "default")["streamSettings"]["finalmask"],
        json!({"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["1-2", "3-4"], "delays": ["10-20"], "maxSplit": "3-6"}}]})
    );
}

#[test]
fn proto_config() {
    let c = gen_proto_config(&args(&[
        ("local_http_port", "1081"),
        ("server_proto", "socks"),
        ("server_address", "127.0.0.1"),
        ("server_port", "1080"),
    ]))
    .unwrap();
    assert_eq!(
        c,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "0.0.0.0", "port": 1081, "protocol": "http", "settings": {"allowTransparent": false}}],
            "outbounds": [
                {"protocol": "socks", "streamSettings": {"method": "raw", "security": "none"}, "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]}},
                {"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow"}]}, "streamSettings": {"sockopt": {"mark": 255}}}
            ],
            "version": {"min": "26.7.11"}
        })
    );
    let c2 = gen_proto_config(&args(&[("local_socks_port", "1", ), ("local_socks_username", "u"), ("local_socks_password", "p"), ("server_proto", "nil")])).unwrap();
    assert_eq!(c2["inbounds"][0]["settings"], json!({"udp": true, "auth": "password", "users": [{"user": "u", "pass": "p"}]}));
    assert_eq!(c2["outbounds"].as_array().unwrap().len(), 1);
}

#[test]
fn server_vless_reality_fallback() {
    let cfg_s = Config::parse(
        "passwall2_server",
        "config user 'u1'\n\toption username 'alice'\n\toption uuid 'uuid-1'\n\
         config user 'u2'\n\toption username 'bob'\n\toption uuid 'uuid-2'\n\
         config server 's1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption port '443'\n\tlist users 'u1'\n\tlist users 'u2'\n\tlist users 'zz'\n\
         \toption flow 'xtls-rprx-vision'\n\toption transport 'raw'\n\toption tcp_guise 'none'\n\toption tls '1'\n\toption reality '1'\n\
         \toption reality_dest 'www.apple.com:443'\n\tlist reality_serverNames 'www.apple.com'\n\toption reality_private_key 'PRIV'\n\
         \tlist reality_shortId 'ab'\n\toption fallback '1'\n\tlist fallback_list '80'\n\tlist fallback_list '/dev/shm/x.sock,/ws,1'\n\toption log '1'\n\toption loglevel 'warn'\n",
    );
    let cfg_c = Config::parse("passwall2", "");
    let node = node_of(cfg_s.section("s1").unwrap());
    let c = server_config(&cfg_c, &cfg_s, node, false);
    assert_eq!(c["log"]["loglevel"], "warning");
    let ib = &c["inbounds"][0];
    assert_eq!(ib["listen"], "::");
    assert_eq!(ib["port"], 443);
    assert_eq!(
        ib["settings"],
        json!({"users": [{"email": "alice", "id": "uuid-1", "flow": "xtls-rprx-vision"}, {"email": "bob", "id": "uuid-2", "flow": "xtls-rprx-vision"}],
               "decryption": "none",
               "fallbacks": [{"dest": 80}, {"path": "/ws", "dest": "/dev/shm/x.sock", "xver": 1}]})
    );
    let ss = &ib["streamSettings"];
    assert_eq!(ss["security"], "reality");
    assert!(ss.get("tlsSettings").is_none());
    assert_eq!(
        ss["realitySettings"],
        json!({"show": false, "dest": "www.apple.com:443", "serverNames": ["www.apple.com"], "privateKey": "PRIV", "shortIds": ["ab"], "minClientVer": "1.0.0"})
    );
    assert_eq!(ss["rawSettings"], json!({"header": {"type": "none"}}));
    assert_eq!(ss["sockopt"], json!({"acceptProxyProtocol": false}));
    assert_eq!(c["outbounds"], json!([{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow"}]}}, {"protocol": "blackhole", "tag": "blocked"}]));
    assert_eq!(c["routing"]["rules"][0]["outboundTag"], "blocked");
}

#[test]
fn server_socks_outbound_and_hysteria() {
    let cfg_s = Config::parse(
        "passwall2_server",
        "config user 'u1'\n\toption username 'a'\n\toption password 'b'\n\
         config server 'h'\n\toption type 'Xray'\n\toption protocol 'hysteria2'\n\toption port '8443'\n\tlist users 'u1'\n\
         \toption tls_certificateFile '/c.pem'\n\toption tls_keyFile '/k.pem'\n\toption hysteria2_up_mbps '100'\n\
         \toption hysteria2_ignore_client_bandwidth '1'\n\toption alpn 'h3'\n\toption accept_lan '1'\n\
         \toption outbound_node '_socks'\n\toption outbound_node_address '10.0.0.2'\n\toption outbound_node_port '1080'\n",
    );
    let cfg_c = Config::parse("passwall2", "");
    let c = server_config(&cfg_c, &cfg_s, node_of(cfg_s.section("h").unwrap()), false);
    let ib = &c["inbounds"][0];
    assert_eq!(ib["protocol"], "hysteria");
    assert_eq!(ib["settings"], json!({"version": 2, "users": [{"email": "a", "auth": "b"}]}));
    let ss = &ib["streamSettings"];
    assert_eq!(ss["method"], "hysteria");
    assert_eq!(ss["security"], "tls");
    assert_eq!(
        ss["tlsSettings"],
        json!({"disableSystemRoot": false, "certificates": [{"certificateFile": "/c.pem", "keyFile": "/k.pem"}], "alpn": ["h3"]})
    );
    assert_eq!(ss["finalmask"], json!({"quicParams": {"congestion": "bbr"}}));
    assert_eq!(c["log"]["loglevel"], "none");
    let o = &c["outbounds"][0];
    assert_eq!(o["tag"], "outbound");
    assert_eq!(o["protocol"], "socks");
    assert_eq!(o["settings"], json!({"address": "10.0.0.2", "port": 1080, "level": 0}));
    assert!(o.get("_id").is_none() && o.get("_flag").is_none());
    assert_eq!(c["routing"]["rules"][0]["outboundTag"], "direct");
}

#[test]
fn client_tls_certificate_is_a_list() {
    let conf = "config nodes 'n1'\n\toption type 'Xray'\n\toption protocol 'trojan'\n\toption address '1.2.3.4'\n\toption port '443'\n\
                \toption password 'p'\n\toption tls '1'\n\toption transport 'raw'\n\toption tls_certificate '1'\n\
                \toption tls_certificate_pem '-----BEGIN-----\\nAB\\n-----END-----'\n";
    let o = out_of(conf, "n1");
    assert_eq!(
        o["streamSettings"]["tlsSettings"]["certificates"],
        json!([{"certificate": ["-----BEGIN-----", "AB", "-----END-----"], "usage": "verify"}])
    );
}

#[test]
fn server_reality_lists_always_arrays() {
    let cfg_s = Config::parse(
        "passwall2_server",
        "config server 's1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption port '443'\n\toption transport 'raw'\n\
         \toption tcp_guise 'none'\n\toption tls '1'\n\toption reality '1'\n\toption reality_serverNames 'one.com'\n",
    );
    let cfg_c = Config::parse("passwall2", "");
    let c = server_config(&cfg_c, &cfg_s, node_of(cfg_s.section("s1").unwrap()), false);
    let r = &c["inbounds"][0]["streamSettings"]["realitySettings"];
    assert_eq!(r["serverNames"], json!(["one.com"]));
    assert_eq!(r["shortIds"], json!([""]));
}
