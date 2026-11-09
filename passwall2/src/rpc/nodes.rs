//! Node / shunt-rule / socks endpoints that edit UCI (controller spec 07 §A.3).
//! Each endpoint = a pure function on a [`Store`] (unit-tested) + a thin wrapper that loads,
//! saves and builds the response.

use super::params::{is_sid, is_sref, split_nonempty, Params};
use super::store::{section_json, Store};
use crate::api;
use crate::uci::Config;
use crate::util;
use serde_json::{json, Map, Value};

const C: &str = util::CONFIG;
const S: &str = util::CONFIG_SERVER;

fn ok() -> Value {
    json!({"code": 1})
}
fn err() -> Value {
    json!({"code": 0})
}

// ---------------------------------------------------------------- update_config / server_update_config

/// Parse the `data` param (JSON text as upstream, or an already decoded object).
fn data_object(p: &Params) -> Option<Map<String, Value>> {
    match p.raw("data")? {
        Value::Object(m) => Some(m.clone()),
        Value::String(s) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        },
        _ => None,
    }
}

/// `update_config`: for each k,v of data → `uci_set(id,k,v)`; empty data → `{"code":0}`.
pub fn apply_data(st: &mut Store, id: &str, data: &Map<String, Value>) -> bool {
    if data.is_empty() || !is_sref(id) {
        return false;
    }
    for (k, v) in data {
        if is_sid(k) {
            st.set_value(id, k, v);
        }
    }
    true
}

fn update_config_in(conf: &str, p: &Params) -> Value {
    let (Some(id), Some(data)) = (p.get("id"), data_object(p)) else { return err() };
    let mut st = Store::load(conf);
    if !apply_data(&mut st, &id, &data) {
        return err();
    }
    st.save(false);
    ok()
}

pub fn update_config(p: &Params) -> Value {
    update_config_in(C, p)
}
pub fn server_update_config(p: &Params) -> Value {
    update_config_in(S, p)
}

// ---------------------------------------------------------------- add_node / set_node / copy_node

/// Default node type for a new node: first installed of sing-box, Xray, SS-Rust, SSR.
pub fn default_node_type(has_singbox: bool, has_xray: bool, has_ssrust: bool, has_ssr: bool) -> Option<&'static str> {
    if has_singbox {
        Some("sing-box")
    } else if has_xray {
        Some("Xray")
    } else if has_ssrust {
        Some("SS-Rust")
    } else if has_ssr {
        Some("SSR")
    } else {
        None
    }
}

pub fn add_node_in(st: &mut Store, uid: &str, group: Option<&str>, typ: Option<&str>) {
    st.add_section(uid, "nodes");
    if let Some(g) = group {
        if g != "default" {
            st.set(uid, "group", g);
        }
    }
    if let Some(t) = typ {
        st.set(uid, "type", t);
    }
}

pub fn add_node(p: &Params) -> Value {
    let uid = api::gen_random_char(8);
    let mut st = Store::load(C);
    let typ = default_node_type(api::finded_com("sing-box").is_some(), api::finded_com("xray").is_some(), api::is_finded("sslocal"), api::is_finded("ssr-local"));
    add_node_in(&mut st, &uid, p.get("group").as_deref(), typ);
    if p.get("redirect").as_deref() == Some("1") {
        st.save(false);
        json!({"result": uid, "redirect": format!("node_config/{}", uid)})
    } else {
        st.save(true);
        json!({"result": uid})
    }
}

/// `set_node`: `uci_set(P(type), P(config), P(section))` (section, option, value), commit+apply.
pub fn set_node(p: &Params) -> Value {
    let sec = p.s("type");
    let opt = p.s("config");
    if !is_sref(&sec) || !is_sid(&opt) {
        return json!({"code": 0, "redirect": "log"});
    }
    let mut st = Store::load(C);
    st.set(&sec, &opt, &p.s("section"));
    st.save(true);
    json!({"redirect": "log"})
}

/// `copy_node`: new `nodes` section with every option of `section` except `.x`/`group`,
/// `remarks .. "(1)"`, `add_mode=1`. false when the source does not exist.
pub fn copy_node_in(st: &mut Store, section: &str, uid: &str) -> bool {
    let Some(src) = st.section(section).cloned() else { return false };
    st.add_section(uid, "nodes");
    for (k, v) in &src.options {
        if k.starts_with('.') || k == "group" {
            continue;
        }
        match v {
            crate::uci::Value::List(l) => st.set_list(uid, k, l),
            crate::uci::Value::Single(s) => {
                if k == "remarks" {
                    st.set(uid, k, &format!("{}(1)", s));
                } else {
                    st.set(uid, k, s)
                }
            }
        }
    }
    st.set(uid, "add_mode", "1");
    true
}

pub fn copy_node(p: &Params) -> Value {
    let section = p.s("section");
    let uid = api::gen_random_char(8);
    let mut st = Store::load(C);
    if !is_sref(&section) || !copy_node_in(&mut st, &section, &uid) {
        return json!({"code": 0, "redirect": "node_list"});
    }
    st.save(false);
    json!({"result": uid, "redirect": format!("node_config/{}", uid)})
}

// ---------------------------------------------------------------- clear_all_nodes / delete_select_nodes

pub fn clear_all_nodes_in(st: &mut Store) {
    st.set("@global[0]", "enabled", "0");
    st.set("@global[0]", "socks_enabled", "0");
    st.set("@global_haproxy[0]", "balancing_enable", "0");
    st.del("@global[0]", "node");
    for n in st.names_of("socks") {
        st.del_section(&n);
    }
    for n in st.names_of("haproxy_config") {
        st.del_section(&n);
    }
    for n in st.names_of("acl_rule") {
        st.del(&n, "node");
    }
    for n in st.names_of("nodes") {
        st.del_section(&n);
    }
    for n in st.names_of("subscribe_list") {
        for o in ["md5", "chain_proxy", "preproxy_node", "to_node"] {
            st.del(&n, o);
        }
    }
}

pub fn clear_all_nodes() -> Value {
    let mut st = Store::load(C);
    clear_all_nodes_in(&mut st);
    st.save(true);
    json!({})
}

fn drop_chain_refs(st: &mut Store, name: &str, w: &str) {
    if st.get(name, "preproxy_node").as_deref() == Some(w) {
        st.del(name, "preproxy_node");
        st.del(name, "chain_proxy");
    }
    if st.get(name, "to_node").as_deref() == Some(w) {
        st.del(name, "to_node");
        st.del(name, "chain_proxy");
    }
}

/// `delete_select_nodes` (exact upstream order of cleanups for each id).
pub fn delete_select_nodes_in(st: &mut Store, ids: &str) {
    let mut ids_t: Vec<String> = vec![];
    for w in split_nonempty(ids) {
        ids_t.push(w.clone());
        if !is_sid(&w) {
            continue;
        }
        if st.get("@global[0]", "node").unwrap_or_default() == w {
            st.del("@global[0]", "node");
        }
        for t in st.names_of("socks") {
            let list = st.list(&t, "autoswitch_backup_node");
            let kept: Vec<String> = list.iter().filter(|x| **x != w).cloned().collect();
            if kept.len() != list.len() {
                st.set_list(&t, "autoswitch_backup_node", &kept);
            }
            if st.get(&t, "node").as_deref() == Some(w.as_str()) {
                match api::get_random_normal_node(&st.cfg, &ids_t) {
                    Some(n) => {
                        let id = n.id().to_string();
                        st.set(&t, "node", &id)
                    }
                    None => st.set(&t, "enabled", "0"),
                }
            }
        }
        for t in st.names_of("haproxy_config") {
            if st.get(&t, "lbss").as_deref() == Some(w.as_str()) {
                st.del_section(&t);
            }
        }
        for t in st.names_of("acl_rule") {
            if st.get(&t, "node").as_deref() == Some(w.as_str()) {
                st.del(&t, "node");
            }
        }
        for t in st.names_of("nodes") {
            drop_chain_refs(st, &t, &w);
            let list_name = if st.get(&t, "urltest_node").is_some() {
                Some("urltest_node")
            } else if st.get(&t, "balancing_node").is_some() {
                Some("balancing_node")
            } else {
                None
            };
            if let Some(ln) = list_name {
                let list = st.list(&t, ln);
                let kept: Vec<String> = list.iter().filter(|x| **x != w).cloned().collect();
                if kept.len() != list.len() {
                    st.set_list(&t, ln, &kept);
                }
            }
            if st.get(&t, "fallback_node").as_deref() == Some(w.as_str()) {
                st.del(&t, "fallback_node");
            }
        }
        for t in st.names_of("subscribe_list") {
            drop_chain_refs(st, &t, &w);
        }
        if st.get(&w, "add_mode").unwrap_or_else(|| "0".into()) == "2" {
            let group = st.get(&w, "group").unwrap_or_default();
            if !group.is_empty() {
                for t in st.names_of("subscribe_list") {
                    if st.get(&t, "remark").as_deref() == Some(group.as_str()) {
                        st.del(&t, "md5");
                    }
                }
            }
        }
        st.del_section(&w);
    }
}

pub fn delete_select_nodes(p: &Params) -> Value {
    let mut st = Store::load(C);
    delete_select_nodes_in(&mut st, &p.s("ids"));
    if p.get("redirect").as_deref() == Some("1") {
        st.save(false);
        json!({"redirect": "node_list"})
    } else {
        st.save(true);
        json!({})
    }
}

// ---------------------------------------------------------------- reassign_group / save_node_list_opt

pub fn reassign_group_in(st: &mut Store, ids: &str, group: &str) {
    for id in split_nonempty(ids) {
        if !is_sid(&id) {
            continue;
        }
        if !group.is_empty() && group != "default" {
            st.set(&id, "group", group);
        } else {
            st.del(&id, "group");
        }
    }
}

/// `reassign_group`: `uci set/delete passwall2.<id>.group` + commit (no reload).
pub fn reassign_group(p: &Params) -> Value {
    let mut st = Store::load(C);
    reassign_group_in(&mut st, &p.s("ids"), &p.or("group", "default"));
    st.save(false);
    json!({"status": "ok"})
}

/// `save_node_list_opt`: `@global_other[0].<option>=<value>` + commit.
pub fn save_node_list_opt(p: &Params) -> Value {
    let option = p.s("option");
    if !option.is_empty() && is_sid(&option) {
        let mut st = Store::load(C);
        st.set("@global_other[0]", &option, &p.s("value"));
        st.save(false);
    }
    json!({"status": "ok"})
}

// ---------------------------------------------------------------- get_node / get_shunt_rules

/// `get_node` / `get_shunt_rules` listing: one section (no `.index`), or all sections of
/// `stype` with ungrouped ones first (`.index` = position in the config). `show_ipv6` adds
/// `ipv6`/`full_address` for IPv6 addresses (show_node_info=1).
pub fn sections_listing(cfg: &Config, stype: &str, id: Option<&str>, show_ipv6: bool) -> Value {
    let add_ipv6 = |m: &mut Map<String, Value>| {
        if !show_ipv6 {
            return;
        }
        if let Some(Value::String(a)) = m.get("address") {
            let f = api::get_ipv6_full(a);
            if !f.is_empty() {
                m.insert("ipv6".into(), true.into());
                m.insert("full_address".into(), f.into());
            }
        }
    };
    if let Some(id) = id {
        // upstream: uci_get(id) → nil → http_write_json(nil) → {"code":1}
        return match cfg.section(id) {
            Some(s) => {
                let mut m = section_json(s, None);
                add_ipv6(&mut m);
                Value::Object(m)
            }
            None => json!({"code": 1}),
        };
    }
    let mut default_items = vec![];
    let mut other_items = vec![];
    for (i, s) in cfg.sections.iter().enumerate() {
        if s.stype != stype {
            continue;
        }
        let mut m = section_json(s, Some(i));
        add_ipv6(&mut m);
        if s.get("group").unwrap_or_default().is_empty() {
            default_items.push(Value::Object(m));
        } else {
            other_items.push(Value::Object(m));
        }
    }
    default_items.extend(other_items);
    json!({"result": default_items})
}

pub fn get_node(p: &Params) -> Value {
    let cfg = Config::load(C);
    let show = cfg.get("@global_other[0]", "show_node_info").unwrap_or_else(|| "0".into()) == "1";
    sections_listing(&cfg, "nodes", p.get("id").as_deref(), show)
}

pub fn get_shunt_rules(p: &Params) -> Value {
    let cfg = Config::load(C);
    sections_listing(&cfg, "shunt_rules", p.get("id").as_deref(), false)
}

// ---------------------------------------------------------------- shunt rules

/// `add_shunt_rule`: Err(message) when the requested id exists (or is not a valid uci name).
pub fn add_shunt_rule_in(st: &mut Store, add_name: Option<&str>, group: Option<&str>, random: &str) -> Result<String, String> {
    let uid = match add_name.filter(|n| !n.is_empty()) {
        Some(n) => {
            if st.exists(n) {
                return Err(api::translate("This ID already exists."));
            }
            if !is_sid(n) {
                // upstream would create nothing (invalid uci name) yet report success
                return Err("Invalid ID.".into());
            }
            n.to_string()
        }
        None => random.to_string(),
    };
    st.add_section(&uid, "shunt_rules");
    if let Some(g) = group {
        if g != "default" {
            st.set(&uid, "group", g);
        }
    }
    Ok(uid)
}

pub fn add_shunt_rule(p: &Params) -> Value {
    let mut st = Store::load(C);
    let random = api::gen_random_char(8);
    match add_shunt_rule_in(&mut st, p.get("add_name").as_deref(), p.get("group").as_deref(), &random) {
        Err(m) => json!({"code": 0, "data": {"message": m}}),
        Ok(uid) => {
            st.save(false);
            let page = format!("shunt_rules/{}", uid);
            if p.get("redirect").as_deref() == Some("1") {
                json!({"code": 1, "data": {"uid": uid, "redirect_url": api::url(&["shunt_rules", &uid])}, "redirect": page})
            } else {
                json!({"code": 1, "data": {"uid": uid, "redirect_url": api::url(&["shunt_rules", &uid])}})
            }
        }
    }
}

pub fn delete_select_shunt_rules_in(st: &mut Store, ids: &str) {
    for w in split_nonempty(ids) {
        if !is_sid(&w) {
            continue;
        }
        for n in st.names_of("nodes") {
            if st.get(&n, "protocol").as_deref() == Some("_shunt") {
                st.del(&n, &w);
            }
        }
        st.del_section(&w);
    }
}

pub fn delete_select_shunt_rules(p: &Params) -> Value {
    let mut st = Store::load(C);
    delete_select_shunt_rules_in(&mut st, &p.s("ids"));
    if p.get("redirect").as_deref() == Some("1") {
        st.save(false);
        json!({"redirect": "rule"})
    } else {
        st.save(true);
        json!({})
    }
}

// ---------------------------------------------------------------- socks auto switch

/// `socks_autoswitch_add_node` (add=true) / `_remove_node`: drop backup nodes whose remarks
/// contain `key`, then (add) append every normal valid node whose display remark contains it.
/// Returns the new list.
pub fn socks_autoswitch_in(st: &mut Store, id: &str, key: &str, add: bool) -> Vec<String> {
    st.set(id, "enable_autoswitch", "1");
    let mut list = st.list(id, "autoswitch_backup_node");
    list.retain(|n| !st.get(n, "remarks").unwrap_or_default().contains(key));
    if add {
        for e in api::get_valid_nodes(&st.cfg) {
            if e.node_type == "normal" && e.remark.contains(key) {
                list.push(e.id().to_string());
            }
        }
    }
    st.set_list(id, "autoswitch_backup_node", &list);
    list
}

pub fn socks_autoswitch(p: &Params, add: bool) -> Value {
    let id = p.s("id");
    let key = p.s("key");
    let redirect = format!("socks_config/{}", id);
    if id.is_empty() || key.is_empty() || !is_sid(&id) {
        return json!({"redirect": redirect});
    }
    let mut st = Store::load(C);
    if !st.exists(&id) {
        return json!({"redirect": redirect});
    }
    let list = socks_autoswitch_in(&mut st, &id, &key, add);
    st.save(false);
    json!({"result": list, "redirect": redirect})
}

// ---------------------------------------------------------------- reorder (CBI `group.order.*`)

/// CBI submit `group.order.<g>` equivalent: `uci reorder <config>.<name>=<idx>` for the
/// space/comma separated `ids` (absolute positions 0..n-1, in order), then commit.
pub fn reorder_in(st: &mut Store, ids: &str) -> usize {
    let names: Vec<String> = ids.split([' ', ',']).filter(|x| !x.is_empty() && is_sid(x)).map(|x| x.to_string()).collect();
    for (i, n) in names.iter().enumerate() {
        st.reorder(n, i);
    }
    names.len()
}

pub fn reorder_sections(p: &Params) -> Value {
    let conf = p.or("config", C);
    if conf != C && conf != S {
        return err();
    }
    let mut st = Store::load(&conf);
    if reorder_in(&mut st, &p.s("ids")) == 0 {
        return err();
    }
    st.save(false);
    ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "
config global
\toption enabled '1'
\toption node 'n1'
\toption socks_enabled '1'

config global_haproxy
\toption balancing_enable '1'

config global_other
\toption show_node_info '1'

config socks 'socks_a'
\toption node 'n1'
\toption enabled '1'
\tlist autoswitch_backup_node 'n1'
\tlist autoswitch_backup_node 'n2'

config haproxy_config 'hp1'
\toption lbss 'n1'

config haproxy_config 'hp2'
\toption lbss 'n2'

config acl_rule 'acl_x'
\toption node 'n1'

config nodes 'n1'
\toption remarks 'one'
\toption type 'Xray'
\toption protocol 'vless'
\toption address '1.1.1.1'
\toption port '443'
\toption add_mode '2'
\toption group 'subA'

config nodes 'n2'
\toption remarks 'two'
\toption type 'Xray'
\toption protocol 'vmess'
\toption address '2001:db8::1'
\toption port '80'
\toption preproxy_node 'n1'
\toption chain_proxy '1'

config nodes 'n3'
\toption remarks 'bal'
\toption type 'Xray'
\toption protocol '_balancing'
\tlist balancing_node 'n1'
\tlist balancing_node 'n2'
\toption fallback_node 'n1'

config nodes 'sh'
\toption remarks 'shunt'
\toption type 'Xray'
\toption protocol '_shunt'
\toption r1 'n2'

config subscribe_list 'sub_1'
\toption remark 'subA'
\toption md5 'abc'
\toption to_node 'n1'
\toption chain_proxy '2'

config shunt_rules 'r1'
\toption remarks 'Rule 1'

config shunt_rules 'r2'
\toption group 'g'

config shunt_rules 'r3'
";

    fn st() -> Store {
        Store::from_config(Config::parse("passwall2", CFG))
    }

    #[test]
    fn delete_nodes() {
        let mut s = st();
        delete_select_nodes_in(&mut s, "n1");
        assert_eq!(s.get("@global[0]", "node"), None);
        assert_eq!(s.list("socks_a", "autoswitch_backup_node"), vec!["n2"]);
        // replacement picked among remaining normal nodes (n2 only)
        assert_eq!(s.get("socks_a", "node").as_deref(), Some("n2"));
        assert!(!s.exists("hp1"));
        assert!(s.exists("hp2"));
        assert_eq!(s.get("acl_x", "node"), None);
        assert_eq!(s.get("n2", "preproxy_node"), None);
        assert_eq!(s.get("n2", "chain_proxy"), None);
        assert_eq!(s.list("n3", "balancing_node"), vec!["n2"]);
        assert_eq!(s.get("n3", "fallback_node"), None);
        assert_eq!(s.get("sub_1", "to_node"), None);
        assert_eq!(s.get("sub_1", "chain_proxy"), None);
        assert_eq!(s.get("sub_1", "md5"), None, "subscribed node → md5 dropped");
        assert!(!s.exists("n1"));
    }

    #[test]
    fn delete_all_candidates_disables_socks() {
        let mut s = st();
        delete_select_nodes_in(&mut s, "n1,n2");
        assert_eq!(s.get("socks_a", "enabled").as_deref(), Some("0"));
        assert!(!s.exists("n2"));
        assert!(!s.section("n3").unwrap().has("balancing_node"));
    }

    #[test]
    fn clear_all() {
        let mut s = st();
        clear_all_nodes_in(&mut s);
        assert_eq!(s.get("@global[0]", "enabled").as_deref(), Some("0"));
        assert_eq!(s.get("@global[0]", "socks_enabled").as_deref(), Some("0"));
        assert_eq!(s.get("@global_haproxy[0]", "balancing_enable").as_deref(), Some("0"));
        assert_eq!(s.get("@global[0]", "node"), None);
        assert!(s.names_of("nodes").is_empty());
        assert!(s.names_of("socks").is_empty());
        assert!(s.names_of("haproxy_config").is_empty());
        assert!(s.exists("acl_x"));
        assert_eq!(s.get("acl_x", "node"), None);
        assert_eq!(s.get("sub_1", "md5"), None);
        assert_eq!(s.get("sub_1", "remark").as_deref(), Some("subA"));
        assert_eq!(s.names_of("shunt_rules").len(), 3);
    }

    #[test]
    fn copy_and_add() {
        let mut s = st();
        assert!(copy_node_in(&mut s, "n1", "cp1"));
        assert_eq!(s.get("cp1", "remarks").as_deref(), Some("one(1)"));
        assert_eq!(s.get("cp1", "group"), None);
        assert_eq!(s.get("cp1", "add_mode").as_deref(), Some("1"));
        assert_eq!(s.get("cp1", "address").as_deref(), Some("1.1.1.1"));
        assert!(copy_node_in(&mut s, "n3", "cp2"));
        assert_eq!(s.list("cp2", "balancing_node"), vec!["n1", "n2"]);
        assert!(!copy_node_in(&mut s, "nope", "cp3"));
        add_node_in(&mut s, "new1", Some("default"), Some("Xray"));
        assert_eq!(s.get("new1", "group"), None);
        assert_eq!(s.get("new1", "type").as_deref(), Some("Xray"));
        add_node_in(&mut s, "new2", Some("G"), None);
        assert_eq!(s.get("new2", "group").as_deref(), Some("G"));
        assert_eq!(s.get("new2", "type"), None);
        assert_eq!(default_node_type(false, true, true, true), Some("Xray"));
        assert_eq!(default_node_type(false, false, false, true), Some("SSR"));
        assert_eq!(default_node_type(false, false, false, false), None);
    }

    #[test]
    fn update_data() {
        let mut s = st();
        let d: Map<String, Value> = serde_json::from_str(r#"{"remarks":"x","list":["a","b"],"port":8080,"address":"","bad key":"v"}"#).unwrap();
        assert!(apply_data(&mut s, "n2", &d));
        assert_eq!(s.get("n2", "remarks").as_deref(), Some("x"));
        assert_eq!(s.list("n2", "list"), vec!["a", "b"]);
        assert_eq!(s.get("n2", "port").as_deref(), Some("8080"));
        assert_eq!(s.get("n2", "address"), None);
        assert!(!apply_data(&mut s, "n2", &Map::new()));
        assert!(!apply_data(&mut s, "bad id", &d));
        let p = Params::from_json(r#"{"data":"{\"a\":1}"}"#);
        assert_eq!(data_object(&p).unwrap()["a"], json!(1));
        let p = Params::from_json(r#"{"data":{"a":1}}"#);
        assert_eq!(data_object(&p).unwrap()["a"], json!(1));
        assert!(data_object(&Params::from_json(r#"{"data":"[1]"}"#)).is_none());
    }

    #[test]
    fn groups() {
        let mut s = st();
        reassign_group_in(&mut s, "n1,n2,,bad.id", "G2");
        assert_eq!(s.get("n1", "group").as_deref(), Some("G2"));
        assert_eq!(s.get("n2", "group").as_deref(), Some("G2"));
        reassign_group_in(&mut s, "n1", "default");
        assert_eq!(s.get("n1", "group"), None);
        reassign_group_in(&mut s, "n2", "");
        assert_eq!(s.get("n2", "group"), None);
    }

    #[test]
    fn listing() {
        let cfg = Config::parse("passwall2", CFG);
        let v = sections_listing(&cfg, "nodes", None, true);
        let a = v["result"].as_array().unwrap();
        let names: Vec<&str> = a.iter().map(|x| x[".name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["n2", "n3", "sh", "n1"], "ungrouped first");
        assert_eq!(a[0]["ipv6"], json!(true));
        assert_eq!(a[0]["full_address"], json!("[2001:db8::1]"));
        assert!(a[0][".index"].is_number());
        assert!(a[3].get("ipv6").is_none());
        let one = sections_listing(&cfg, "nodes", Some("n1"), false);
        assert_eq!(one["remarks"], json!("one"));
        assert!(one.get(".index").is_none());
        assert_eq!(sections_listing(&cfg, "nodes", Some("zz"), false), json!({"code": 1}));
        let r = sections_listing(&cfg, "shunt_rules", None, false);
        let names: Vec<&str> = r["result"].as_array().unwrap().iter().map(|x| x[".name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["r1", "r3", "r2"]);
    }

    #[test]
    fn shunt_rules() {
        let mut s = st();
        assert!(add_shunt_rule_in(&mut s, Some("r1"), None, "rnd").is_err());
        assert!(add_shunt_rule_in(&mut s, Some("bad name"), None, "rnd").is_err());
        assert_eq!(add_shunt_rule_in(&mut s, Some("r9"), Some("G"), "rnd").unwrap(), "r9");
        assert_eq!(s.get("r9", "group").as_deref(), Some("G"));
        assert_eq!(add_shunt_rule_in(&mut s, None, Some("default"), "rnd").unwrap(), "rnd");
        assert_eq!(s.get("rnd", "group"), None);
        assert_eq!(add_shunt_rule_in(&mut s, Some(""), None, "rnd2").unwrap(), "rnd2");
        delete_select_shunt_rules_in(&mut s, "r1,r2");
        assert!(!s.exists("r1"));
        assert!(!s.exists("r2"));
        assert_eq!(s.get("sh", "r1"), None);
        assert_eq!(s.get("sh", "remarks").as_deref(), Some("shunt"));
    }

    #[test]
    fn autoswitch() {
        let mut s = st();
        let l = socks_autoswitch_in(&mut s, "socks_a", "two", false);
        assert_eq!(l, vec!["n1"]);
        assert_eq!(s.get("socks_a", "enable_autoswitch").as_deref(), Some("1"));
        let l = socks_autoswitch_in(&mut s, "socks_a", "two", true);
        assert_eq!(l, vec!["n1", "n2"]);
        let l = socks_autoswitch_in(&mut s, "socks_a", "o", false);
        // "one" and "two" both contain "o"
        assert!(l.is_empty());
        assert!(!s.section("socks_a").unwrap().has("autoswitch_backup_node"));
    }

    #[test]
    fn reorder() {
        let mut s = st();
        assert_eq!(reorder_in(&mut s, "r3 r1"), 2);
        assert_eq!(s.cfg.sections[0].name, "r3");
        assert_eq!(s.cfg.sections[1].name, "r1");
        assert_eq!(reorder_in(&mut s, " , "), 0);
    }
}
