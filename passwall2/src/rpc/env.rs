//! Extra read-only methods replacing the server-side computations of the Lua CBI pages
//! (capability gates, node pickers, ...), so the JS views can render the same choices.

use crate::api;
use crate::uci::Config;
use crate::util;
use serde_json::{json, Map, Value};

/// `lsmod` based gates of global.lua / other.lua → (tproxy_ok, ipv6_tproxy_ok).
pub fn tproxy_gates(lsmod: &str) -> (bool, bool) {
    let tproxy = (lsmod.contains("REDIRECT") && lsmod.contains("TPROXY")) || (lsmod.contains("nft_redir") && lsmod.contains("nft_tproxy"));
    let v6 = tproxy && (lsmod.contains("ip6table_mangle") || lsmod.contains("nft_tproxy"));
    (tproxy, v6)
}

/// `get_env`: installed cores/binaries, versions, capability gates and runtime state.
pub fn get_env() -> Value {
    let cfg = Config::load(util::CONFIG);
    let singbox = api::finded_com("sing-box");
    let xray = api::finded_com("xray");
    let geoview = api::finded_com("geoview");
    let has_sb = singbox.is_some();
    let has_xray = xray.is_some();
    let has_ssrust = api::is_finded("sslocal");

    let mut bins = Map::new();
    for b in [
        "sslocal", "ssserver", "ssr-local", "ssr-server", "xray-plugin", "v2ray-plugin", "obfs-local", "shadow-tls", "hysteria", "tcping", "wg", "haproxy",
        "chinadns-ng", "dnsmasq", "openssl", "unzip", "tar",
    ] {
        bins.insert(b.into(), api::is_finded(b).into());
    }
    let xray_version = if has_xray { api::get_app_version("xray", None) } else { String::new() };
    let singbox_version = if has_sb { api::get_app_version("sing-box", None) } else { String::new() };
    let geoview_version = if geoview.is_some() { api::get_app_version("geoview", None) } else { String::new() };

    // node_config/link_share_man.htm core picks (07 §B.0)
    let core_types = json!({
        "ss_type": api::get_core(&cfg, "ss_type", &[(has_ssrust, "shadowsocks-rust"), (has_sb, "sing-box"), (has_xray, "xray")]),
        "trojan_type": api::get_core(&cfg, "trojan_type", &[(has_sb, "sing-box"), (has_xray, "xray")]),
        "vmess_type": api::get_core(&cfg, "vmess_type", &[(has_xray, "xray"), (has_sb, "sing-box")]),
        "vless_type": api::get_core(&cfg, "vless_type", &[(has_xray, "xray"), (has_sb, "sing-box")]),
        "hysteria2_type": api::get_core(&cfg, "hysteria2_type", &[(has_sb, "sing-box"), (has_xray, "xray")]),
    });
    let (tproxy_ok, ipv6_tproxy_ok) = tproxy_gates(&util::cmd_out("lsmod", &[]));

    let mut socks_nodes = Map::new();
    for s in cfg.sections_of("socks") {
        if let Some(n) = api::get_cache_var(&s.name) {
            socks_nodes.insert(s.name.clone(), n.into());
        }
    }
    let devices: Vec<Value> = api::get_network_devices().into_iter().map(|d| json!({"name": d.name, "label": d.label})).collect();
    let asset = cfg.get("@global_rules[0]", "v2ray_location_asset").unwrap_or_else(|| "/usr/share/v2ray/".into());
    let geo_dir = asset.rfind('/').map(|i| asset[..i].to_string()).unwrap_or_default();

    json!({
        "version": api::get_version(),
        "has_singbox": has_sb,
        "has_xray": has_xray,
        "has_geoview": geoview.is_some(),
        "has_haproxy": util::exists("/usr/sbin/haproxy"),
        "singbox_path": singbox,
        "xray_path": xray,
        "geoview_path": geoview,
        "xray_version": xray_version,
        "singbox_version": singbox_version,
        "geoview_version": geoview_version,
        "singbox_tags": if has_sb { api::get_singbox_tags() } else { String::new() },
        // node_subscribe: xray offers hysteria2 only from 26.1.13
        "xray_hysteria2": has_xray && api::compare_versions(&xray_version, ">=", "26.1.13"),
        "bins": bins,
        "core_types": core_types,
        "tproxy_ok": tproxy_ok,
        "ipv6_tproxy_ok": ipv6_tproxy_ok,
        "nft": crate::app::use_nft(),
        "geo_files": util::exists(&format!("{}/geoip.dat", geo_dir)) && util::exists(&format!("{}/geosite.dat", geo_dir)),
        "now_use_node": api::get_cache_var("ACL_acl_default_node"),
        "socks_nodes": socks_nodes,
        "network_devices": devices,
        "lang": api::current_lang(),
        "self_update": !api::is_install("luci-app-passwall2-rs"),
    })
}

/// `api.get_valid_nodes()` → `{"result": [node + id/remark/node_type]}`.
pub fn get_valid_nodes() -> Value {
    let cfg = Config::load(util::CONFIG);
    json!({"result": api::get_valid_nodes(&cfg).iter().map(|n| n.to_json()).collect::<Vec<_>>()})
}

/// `api.get_node_list()`.
pub fn get_node_list() -> Value {
    api::get_node_list(&Config::load(util::CONFIG))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates() {
        assert_eq!(tproxy_gates("xt_REDIRECT 1\nxt_TPROXY 1\nip6table_mangle 1"), (true, true));
        assert_eq!(tproxy_gates("xt_REDIRECT 1\nxt_TPROXY 1"), (true, false));
        assert_eq!(tproxy_gates("nft_redir\nnft_tproxy"), (true, true));
        assert_eq!(tproxy_gates("nft_redir"), (false, false));
    }
}
