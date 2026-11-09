//! Xray config generator (util_xray.lua). Spec: docs/spec/03-xray-config.md
//! STUB — to be implemented (see docs/ARCHITECTURE.md for the owner and contract).

use crate::util::Args;
use serde_json::Value;
/// gen_config: transparent/local client config. `var` = the jshn JSON args of upstream run_xray.
pub fn gen_config(_var: &Args) -> Option<Value> { None }
/// gen_proto_config: simple single-outbound config (socks/http inbound → node).
pub fn gen_proto_config(_var: &Args) -> Option<Value> { None }
/// Server config for a passwall2_server `user` section id.
pub fn gen_config_server(_user_id: &str) -> Option<Value> { None }
pub fn cli(_args: &[String]) -> i32 { 1 }
