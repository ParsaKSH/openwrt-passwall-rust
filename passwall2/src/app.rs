//! Runtime orchestration: app.sh + utils.sh + monitor/tasks/lease2hosts/test helpers. Spec: docs/spec/01-runtime-app.md
//! STUB — to be implemented (see docs/ARCHITECTURE.md for the owner and contract).

/// true when nftables (fw4) backend should be used (check_run_environment).
pub fn use_nft() -> bool { crate::util::exists("/usr/sbin/fw4") }
pub fn cli(_cmd: &str, _args: &[String]) -> i32 { 1 }
