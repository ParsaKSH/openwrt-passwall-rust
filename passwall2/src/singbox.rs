//! sing-box config generator (util_sing-box.lua). Spec: docs/spec/04-singbox-config.md
//! STUB — to be implemented (see docs/ARCHITECTURE.md for the owner and contract).

use crate::util::Args;
use serde_json::Value;
pub fn gen_config(_var: &Args) -> Option<Value> { None }
pub fn gen_proto_config(_var: &Args) -> Option<Value> { None }
pub fn gen_config_server(_user_id: &str) -> Option<Value> { None }
pub fn cli(_args: &[String]) -> i32 { 1 }
