//! Firewall: nftables (fw4) and iptables backends. Spec: docs/spec/02-firewall.md
pub mod nft;
pub mod ipt;
pub mod acl;

/// `passwall2 nft <sub> ...` / `passwall2 ipt <sub> ...` / `passwall2 firewall <sub>` (auto-select).
pub fn cli(cmd: &str, args: &[String]) -> i32 {
    match cmd {
        "nft" => nft::cli(args),
        "ipt" => ipt::cli(args),
        _ => {
            if crate::app::use_nft() { nft::cli(args) } else { ipt::cli(args) }
        }
    }
}
