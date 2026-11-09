//! Legacy configuration migration (`passwall2 migrate`).
//!
//! Upstream renamed or re-encoded a number of UCI options between luci-app-passwall2 26.4.x and
//! 26.11.x (master) without shipping a migration, so a 26.4-era `/etc/config/passwall2` breaks
//! after an upgrade (empty Shadowsocks cipher, `disable` passed to nft as a port, ...). This
//! module brings such a config to the current schema.
//!
//! Design rules:
//! * **Non-destructive.** A renamed option is *copied* to its new name when the new one is unset;
//!   the legacy option stays, so the user can still roll back to upstream 26.4.x. Values are only
//!   rewritten in place where the old value has the same meaning for 26.4 (`disable` ports in
//!   `global_forwarding` = 26.4's default when unset) or where the schema itself moved (removed
//!   node types, the server section type `user` → `server`).
//! * **Idempotent.** Every step checks the new option first, so running it again is a no-op.
//!   It runs from uci-defaults on install, at service start (before any config is generated),
//!   after subscription updates and after a restored backup.
//! * The generators also accept the legacy names at read time (`ss_method || method`, port
//!   cleaning, `H` → `H:00`, ...), so a config that was not migrated yet still works.
//!
//! The planner is pure ([`plan_client`] / [`plan_server`] → [`Plan`]); [`run`] applies it with
//! `uci batch` and commits, unless the config has uncommitted changes staged for the `uci` CLI
//! (`/tmp/.uci/<config>`, which a commit would publish on the user's behalf) — then only the
//! read-time fallbacks apply until the next run. Changes a user staged in LuCI are *not* in
//! there: rpcd keeps them per session and applies them on top of the committed config when the
//! user presses "Save & Apply", so the migration commit neither publishes nor discards them.

use crate::firewall::acl::{clean_ports, legacy_acl_mode};
use crate::uci::{self, Batch, Config, Section, Value as UVal};
use crate::util;

/// One UCI write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `set <path>=<value>` (also `set config.section=type`)
    Set(String, String),
    /// `delete <path>`
    Del(String),
    /// `add_list <path>=<value>`
    AddList(String, String),
}

/// Writes for one config plus a human readable line per change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub config: String,
    pub ops: Vec<Op>,
    pub notes: Vec<String>,
}

impl Plan {
    fn new(config: &str) -> Plan {
        Plan { config: config.to_string(), ..Default::default() }
    }
    fn path(&self, sec: &str, opt: &str) -> String {
        format!("{}.{}.{}", self.config, sec, opt)
    }
    fn set(&mut self, sec: &str, opt: &str, v: &str) {
        let p = self.path(sec, opt);
        self.ops.push(Op::Set(p, v.to_string()));
    }
    fn del(&mut self, sec: &str, opt: &str) {
        let p = self.path(sec, opt);
        self.ops.push(Op::Del(p));
    }
    fn note(&mut self, s: String) {
        self.notes.push(s);
    }
    /// Copy option `from` (single or list) to `to` when `to` is unset/empty.
    fn copy(&mut self, s: &Section, from: &str, to: &str) -> bool {
        if ne(s, to) {
            return false;
        }
        match s.options.get(from) {
            Some(UVal::Single(v)) if !v.is_empty() => {
                self.set(&s.name, to, v);
            }
            Some(UVal::List(l)) if !l.is_empty() => {
                let p = self.path(&s.name, to);
                for v in l {
                    self.ops.push(Op::AddList(p.clone(), v.clone()));
                }
            }
            _ => return false,
        }
        self.note(format!("{}.{}: copied legacy option '{}' to '{}'", self.config, s.name, from, to));
        true
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    fn batch(&self, b: &mut Batch) {
        for op in &self.ops {
            match op {
                Op::Set(p, v) => b.set(p, v),
                Op::Del(p) => b.delete(p),
                Op::AddList(p, v) => b.add_list(p, v),
            };
        }
    }
}

/// Option set and non-empty.
fn ne(s: &Section, k: &str) -> bool {
    match s.options.get(k) {
        Some(UVal::Single(v)) => !v.is_empty(),
        Some(UVal::List(l)) => !l.is_empty(),
        None => false,
    }
}
fn get(s: &Section, k: &str) -> Option<String> {
    s.get(k).filter(|v| !v.is_empty())
}
/// `3` → `3:00` (26.4 stored whole hours); other values unchanged.
fn hour_to_hhmm(v: &str) -> String {
    if (1..=2).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_digit()) {
        format!("{}:00", v)
    } else {
        v.to_string()
    }
}
/// Bytes → MB (rounded, 1..=1000) for the hysteria2 receive windows.
fn bytes_to_mb(v: &str) -> Option<String> {
    let b: f64 = v.trim().parse().ok()?;
    if b <= 0.0 {
        return None;
    }
    Some(((b / 1048576.0).round().clamp(1.0, 1000.0) as u64).to_string())
}

/// `auto_update/week_update/time_update/interval_update` → `update_*_mode` (global_rules and
/// subscribe_list; 26.11 reads only the new names, "" = off).
fn update_schedule(p: &mut Plan, s: &Section) {
    if ne(s, "update_week_mode") || s.get("auto_update").as_deref() != Some("1") {
        return;
    }
    let week = get(s, "week_update").unwrap_or_else(|| "7".into());
    p.set(&s.name, "update_week_mode", &week);
    p.set(&s.name, "update_time_mode", &hour_to_hhmm(&get(s, "time_update").unwrap_or_else(|| "0".into())));
    if let Some(i) = get(s, "interval_update") {
        p.set(&s.name, "update_interval_mode", &i);
    }
    p.note(format!("{}.{}: auto update schedule converted to update_week_mode/update_time_mode", p.config, s.name));
}

/// Migration plan for `/etc/config/passwall2`.
pub fn plan_client(c: &Config) -> Plan {
    let mut p = Plan::new(&c.name);
    for s in &c.sections {
        match s.stype.as_str() {
            "nodes" => plan_node(&mut p, s),
            "global_forwarding" => {
                // `disable` = no ports (26.4 default when unset, so deleting is rollback-safe)
                for k in ["tcp_no_redir_ports", "udp_no_redir_ports"] {
                    if s.get(k).is_some_and(|v| v.trim() == "disable") {
                        p.del(&s.name, k);
                        p.note(format!("{}.{}.{}: legacy value 'disable' removed (empty = no ports)", p.config, s.name, k));
                    }
                }
                // 26.4 put these destinations into a "proxy LAN" set exempted from the built-in
                // LAN-direct ranges; the current firewall has no such set. Kept for a rollback.
                if ne(s, "force_proxy_lan_ip") {
                    p.note(format!(
                        "{}.{}.force_proxy_lan_ip: no longer supported, ignored; traffic to these LAN addresses now connects directly (it does not enter the core)",
                        p.config, s.name
                    ));
                }
            }
            "global_xray" => {
                p.copy(s, "fragment_length", "fragment_lengths");
                p.copy(s, "fragment_delay", "fragment_delays");
            }
            "global_rules" | "subscribe_list" => update_schedule(&mut p, s),
            "global" => {
                if ne(s, "direct_dns_shunt") {
                    p.note(format!("{}.{}.direct_dns_shunt: no longer supported, ignored", p.config, s.name));
                }
            }
            "acl_rule" => plan_acl(&mut p, c, s),
            _ => {}
        }
    }
    p
}

fn plan_node(p: &mut Plan, s: &Section) {
    let ty = s.get("type").unwrap_or_default();
    let proto = s.get("protocol").unwrap_or_default();
    let n = s.name.clone();
    match ty.as_str() {
        "Xray" | "sing-box" => {
            if proto == "shadowsocks" {
                p.copy(s, "method", "ss_method");
            }
            if ty == "sing-box" && proto == "shadowsocksr" {
                p.copy(s, "method", "ssr_method");
            }
            p.copy(s, "tls_CertSha", "tls_pinSHA256");
        }
        // removed standalone types → their sing-box / SS-Rust equivalents
        "SS" => {
            p.set(&n, "type", "SS-Rust");
            p.note(format!("{}.{}: type SS (shadowsocks-libev) → SS-Rust", p.config, n));
        }
        "Hysteria2" => {
            p.set(&n, "type", "sing-box");
            p.set(&n, "protocol", "hysteria2");
            if let Some(o) = get(s, "hysteria2_obfs").filter(|_| !ne(s, "hysteria2_obfs_type")) {
                p.set(&n, "hysteria2_obfs_type", "salamander");
                p.set(&n, "hysteria2_obfs_password", &o);
            }
            p.copy(s, "hysteria2_tls_pinSHA256", "tls_pinSHA256");
            for (old, new) in [("hysteria2_recv_window", "hysteria2_stream_recv_win"), ("hysteria2_recv_window_conn", "hysteria2_conn_recv_win")] {
                if !ne(s, new) {
                    if let Some(mb) = get(s, old).and_then(|v| bytes_to_mb(&v)) {
                        p.set(&n, new, &mb);
                    }
                }
            }
            p.note(format!("{}.{}: type Hysteria2 → sing-box hysteria2", p.config, n));
        }
        "Naiveproxy" => {
            p.set(&n, "type", "sing-box");
            p.set(&n, "protocol", "naive");
            p.set(&n, "naive_quic", if proto == "quic" { "1" } else { "0" });
            p.set(&n, "tls", "1");
            p.note(format!("{}.{}: type Naiveproxy → sing-box naive", p.config, n));
        }
        "TUIC" => {
            p.set(&n, "type", "sing-box");
            p.set(&n, "protocol", "tuic");
            p.copy(s, "tuic_password", "password");
            p.copy(s, "tuic_tls_alpn", "tuic_alpn");
            p.copy(s, "tuic_disable_sni", "tls_disable_sni");
            p.note(format!("{}.{}: type TUIC → sing-box tuic", p.config, n));
        }
        _ => {}
    }
}

/// A rule without `mode` is 26.4-era: unset/`default` ports meant "global value", an
/// unset/`default` node meant "global node", both no-redir lists `1:65535` meant "no proxy".
fn plan_acl(p: &mut Plan, c: &Config, s: &Section) {
    if s.has("mode") {
        return;
    }
    let gf = |k: &str| clean_ports(c.get("@global_forwarding[0]", k));
    let mut resolved = vec![];
    for k in ["tcp_no_redir_ports", "udp_no_redir_ports", "tcp_redir_ports", "udp_redir_ports"] {
        let v = s.get(k);
        let inherit = v.as_deref().is_none_or(|x| x.is_empty() || x == "default");
        let r = if inherit {
            let g = gf(k);
            match &g {
                Some(gv) => p.set(&s.name, k, gv),
                None if v.is_some() => p.del(&s.name, k),
                None => {}
            }
            g
        } else {
            clean_ports(v)
        };
        resolved.push(r);
    }
    let mode = legacy_acl_mode(resolved[0].as_deref(), resolved[1].as_deref(), s.get("node").as_deref());
    p.set(&s.name, "mode", mode);
    p.note(format!("{}.{}: legacy ACL rule converted (mode {}, ports resolved from the global settings)", p.config, s.name, mode));
}

/// Migration plan for `/etc/config/passwall2_server`.
pub fn plan_server(c: &Config) -> Plan {
    let mut p = Plan::new(&c.name);
    for s in &c.sections {
        // 26.4: section type `user` = a server instance; 26.11: `server` (and `user` = a
        // credential record, which never has these options)
        let legacy = s.stype == "user" && ["type", "protocol", "port", "enable", "log"].iter().any(|k| s.has(k));
        if legacy {
            plan_server_section(&mut p, s);
        }
    }
    p
}

fn plan_server_section(p: &mut Plan, s: &Section) {
    let n = s.name.clone();
    p.ops.push(Op::Set(format!("{}.{}", p.config, n), "server".into()));
    p.note(format!("{}.{}: section type user → server", p.config, n));
    let mut ty = s.get("type").unwrap_or_default();
    let mut proto = s.get("protocol").unwrap_or_default();
    match ty.as_str() {
        "SS" => {
            ty = "SS-Rust".into();
            p.set(&n, "type", &ty);
        }
        "Hysteria2" => {
            ty = "sing-box".into();
            proto = "hysteria2".into();
            p.set(&n, "type", &ty);
            p.set(&n, "protocol", &proto);
            if let Some(o) = get(s, "obfs").or_else(|| get(s, "hysteria2_obfs")).filter(|_| !ne(s, "hysteria2_obfs_type")) {
                p.set(&n, "hysteria2_obfs_type", "salamander");
                p.set(&n, "hysteria2_obfs_password", &o);
            }
        }
        _ => {}
    }
    if proto == "dokodemo-door" {
        p.set(&n, "protocol", "tunnel");
    }
    let mut new_users: Vec<Vec<(&str, String)>> = vec![];
    if ty == "Xray" || ty == "sing-box" {
        if proto == "shadowsocks" {
            p.copy(s, "method", "ss_method");
            p.copy(s, "password", "ss_password");
        }
        if !ne(s, "users") {
            match proto.as_str() {
                "vmess" | "vless" => new_users.extend(s.list("uuid").into_iter().filter(|u| !u.is_empty()).map(|u| vec![("uuid", u)])),
                "trojan" => new_users.extend(s.list("uuid").into_iter().filter(|u| !u.is_empty()).map(|u| vec![("password", u)])),
                "socks" | "http" | "mixed" if s.get("auth").as_deref() == Some("1") => {
                    if let Some(u) = get(s, "username") {
                        new_users.push(vec![("username", u), ("password", s.get("password").unwrap_or_default())]);
                    }
                }
                "hysteria2" => {
                    if let Some(pw) = get(s, "hysteria2_auth_password").or_else(|| get(s, "auth_password")) {
                        new_users.push(vec![("password", pw)]);
                    }
                }
                "hysteria" => {
                    if let Some(pw) = get(s, "hysteria_auth_password") {
                        new_users.push(vec![("password", pw)]);
                    }
                }
                _ => {}
            }
        }
    }
    let users_path = p.path(&n, "users");
    for u in new_users {
        let id = uci::gen_id(32);
        p.ops.push(Op::Set(format!("{}.{}", p.config, id), "user".into()));
        for (k, v) in u {
            p.set(&id, k, &v);
        }
        p.ops.push(Op::AddList(users_path.clone(), id));
    }
    if (ty == "SS-Rust" || ty == "SSR") && !ne(s, "user") {
        if let Some(pw) = get(s, "password") {
            let id = uci::gen_id(32);
            p.ops.push(Op::Set(format!("{}.{}", p.config, id), "user".into()));
            p.set(&id, "password", &pw);
            p.set(&n, "user", &id);
        }
    }
    // 26.4: bind_local != 1 opened the port in the firewall; 26.11: firewall_allow
    if !s.has("firewall_allow") {
        let local = s.get("bind_local").as_deref() == Some("1");
        p.set(&n, "firewall_allow", if local { "0" } else { "1" });
        if !local && !s.has("firewall_allow_src") {
            p.set(&n, "firewall_allow_src", "wan");
        }
        if local {
            p.note(format!("{}.{}: bind_local is gone, the server now listens on all interfaces (firewall port stays closed)", p.config, n));
        }
    }
}

/// Uncommitted changes staged for the `uci` CLI exist for `config` (a commit would publish
/// them). LuCI/rpcd session deltas live elsewhere and are unaffected by our commit.
fn has_pending(config: &str) -> bool {
    if std::env::var("PASSWALL2_UCI_DIR").is_ok() {
        return false;
    }
    std::fs::metadata(format!("/tmp/.uci/{}", config)).is_ok_and(|m| m.len() > 0)
}

/// Migrate both configs. Returns the notes of the applied changes. `reason` goes to the log.
pub fn run(reason: &str) -> Vec<String> {
    let mut applied = vec![];
    for (name, plan) in [(util::CONFIG, plan_client(&Config::load(util::CONFIG))), (util::CONFIG_SERVER, plan_server(&Config::load(util::CONFIG_SERVER)))] {
        if plan.is_empty() {
            // notes without writes = legacy options that have no equivalent: warn every run
            for n in &plan.notes {
                util::log(1, &format!("Legacy option ignored: {}", n));
            }
            continue;
        }
        if has_pending(name) {
            util::log(1, &format!("Legacy config migration of {} deferred: it has uncommitted changes.", name));
            continue;
        }
        let mut b = Batch::new();
        plan.batch(&mut b);
        if b.commit().is_ok() {
            util::log(0, &format!("Migrated legacy {} options ({}):", name, reason));
            for n in &plan.notes {
                util::log(1, n);
            }
            applied.extend(plan.notes.iter().cloned());
        }
    }
    applied
}

/// `passwall2 migrate [--dry-run] [reason]`
pub fn cli(args: &[String]) -> i32 {
    if args.first().map(|s| s.as_str()) == Some("--dry-run") {
        for plan in [plan_client(&Config::load(util::CONFIG)), plan_server(&Config::load(util::CONFIG_SERVER))] {
            for n in &plan.notes {
                println!("{}", n);
            }
            for op in &plan.ops {
                match op {
                    Op::Set(p, v) => println!("set {}={}", p, uci::quote(v)),
                    Op::Del(p) => println!("delete {}", p),
                    Op::AddList(p, v) => println!("add_list {}={}", p, uci::quote(v)),
                }
            }
        }
        return 0;
    }
    let reason = args.first().cloned().unwrap_or_else(|| "manual".into());
    for n in run(&reason) {
        println!("{}", n);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic 26.4-era config with the shapes of a real router config (no real data).
    pub const LEGACY: &str = "\
config global
\toption enabled '1'
\toption node 'ss1'
\toption direct_dns_protocol 'auto'

config global_forwarding
\toption tcp_no_redir_ports 'disable'
\toption udp_no_redir_ports 'disable'
\toption tcp_redir_ports '22,25,53,80,443'
\toption udp_redir_ports '1:65535'

config global_xray
\toption fragment_length '100-200'

config global_rules
\toption auto_update '1'
\toption week_update '7'
\toption time_update '3'

config nodes 'ss1'
\toption type 'Xray'
\toption protocol 'shadowsocks'
\toption method 'chacha20-ietf-poly1305'
\toption password 'pw'
\toption address '203.0.113.1'
\toption port '1044'

config nodes 'ss2'
\toption type 'Xray'
\toption protocol 'shadowsocks'
\toption method 'aes-128-gcm'
\toption ss_method '2022-blake3-aes-256-gcm'

config nodes 'v1'
\toption type 'Xray'
\toption protocol 'vless'
\toption tls '1'
\toption tls_CertSha 'abcd'

config nodes 'old'
\toption type 'Hysteria2'
\toption hysteria2_obfs 'ob'
\toption hysteria2_recv_window '8388608'

config acl_rule 'r1'
\toption enabled '1'
\toption node 'default'

config acl_rule 'r2'
\toption enabled '1'
\toption node 'v1'
\toption tcp_no_redir_ports '1:65535'
\toption udp_no_redir_ports '1:65535'

config acl_rule 'r3'
\toption enabled '1'
\toption mode '1'
\toption node 'v1'
";

    fn has(p: &Plan, op: Op) -> bool {
        p.ops.contains(&op)
    }
    fn set(path: &str, v: &str) -> Op {
        Op::Set(path.into(), v.into())
    }

    #[test]
    fn client_plan() {
        let c = Config::parse("passwall2", LEGACY);
        let p = plan_client(&c);
        assert!(has(&p, set("passwall2.ss1.ss_method", "chacha20-ietf-poly1305")));
        // ss_method already set: untouched; legacy option never deleted
        assert!(!p.ops.iter().any(|o| matches!(o, Op::Set(x, _) | Op::Del(x) if x.starts_with("passwall2.ss2."))));
        assert!(!p.ops.iter().any(|o| matches!(o, Op::Del(x) if x.ends_with(".method"))));
        assert!(has(&p, set("passwall2.v1.tls_pinSHA256", "abcd")));
        let gf = &c.section("@global_forwarding[0]").unwrap().name;
        assert!(has(&p, Op::Del(format!("passwall2.{}.tcp_no_redir_ports", gf))));
        assert!(has(&p, Op::Del(format!("passwall2.{}.udp_no_redir_ports", gf))));
        let gx = &c.section("@global_xray[0]").unwrap().name;
        assert!(has(&p, set(&format!("passwall2.{}.fragment_lengths", gx), "100-200")));
        let gr = &c.section("@global_rules[0]").unwrap().name;
        assert!(has(&p, set(&format!("passwall2.{}.update_week_mode", gr), "7")));
        assert!(has(&p, set(&format!("passwall2.{}.update_time_mode", gr), "3:00")));
        assert!(has(&p, set("passwall2.old.type", "sing-box")));
        assert!(has(&p, set("passwall2.old.hysteria2_obfs_type", "salamander")));
        assert!(has(&p, set("passwall2.old.hysteria2_stream_recv_win", "8")));
        // ACLs: r1 → global node, ports inherited; r2 → no proxy; r3 (new schema) untouched
        assert!(has(&p, set("passwall2.r1.mode", "2")));
        assert!(has(&p, set("passwall2.r1.tcp_redir_ports", "22,25,53,80,443")));
        assert!(!p.ops.iter().any(|o| matches!(o, Op::Set(x, _) if x == "passwall2.r1.tcp_no_redir_ports")));
        assert!(has(&p, set("passwall2.r2.mode", "0")));
        assert!(!p.ops.iter().any(|o| matches!(o, Op::Set(x, _) | Op::Del(x) if x.starts_with("passwall2.r3."))));
    }

    #[test]
    fn client_plan_is_idempotent() {
        // apply the plan to the parsed config and plan again: nothing left to do
        let mut c = Config::parse("passwall2", LEGACY);
        for op in plan_client(&c).ops {
            let (path, v) = match &op {
                Op::Set(p, v) | Op::AddList(p, v) => (p.clone(), Some(v.clone())),
                Op::Del(p) => (p.clone(), None),
            };
            let parts: Vec<&str> = path.splitn(3, '.').collect();
            let s = c.sections.iter_mut().find(|s| s.name == parts[1]).unwrap();
            match v {
                Some(v) => {
                    s.options.insert(parts[2].to_string(), UVal::Single(v));
                }
                None => {
                    s.options.shift_remove(parts[2]);
                }
            }
        }
        let p = plan_client(&c);
        assert!(p.is_empty(), "{:?}", p.ops);
    }

    #[test]
    fn server_plan() {
        let c = Config::parse(
            "passwall2_server",
            "config global 'global'\n\toption enable '0'\n\
             config user 'a'\n\toption enable '0'\n\toption log '1'\n\
             config user 'b'\n\toption enable '1'\n\toption type 'Xray'\n\toption protocol 'vless'\n\toption port '443'\n\tlist uuid 'u1'\n\tlist uuid 'u2'\n\
             config user 'c'\n\toption enable '1'\n\toption type 'Xray'\n\toption protocol 'shadowsocks'\n\toption method 'aes-128-gcm'\n\toption password 'p'\n\toption bind_local '1'\n\
             config user 'cred'\n\toption username 'x'\n\toption password 'y'\n",
        );
        let p = plan_server(&c);
        assert!(has(&p, set("passwall2_server.a", "server")));
        assert!(has(&p, set("passwall2_server.a.firewall_allow", "1")));
        assert!(has(&p, set("passwall2_server.b", "server")));
        assert_eq!(p.ops.iter().filter(|o| matches!(o, Op::AddList(x, _) if x == "passwall2_server.b.users")).count(), 2);
        assert!(has(&p, set("passwall2_server.c.ss_method", "aes-128-gcm")));
        assert!(has(&p, set("passwall2_server.c.ss_password", "p")));
        assert!(has(&p, set("passwall2_server.c.firewall_allow", "0")));
        // a 26.11 credential record is left alone
        assert!(!p.ops.iter().any(|o| matches!(o, Op::Set(x, _) if x.starts_with("passwall2_server.cred"))));
    }

    #[test]
    fn helpers() {
        assert_eq!(hour_to_hhmm("3"), "3:00");
        assert_eq!(hour_to_hhmm("23"), "23:00");
        assert_eq!(hour_to_hhmm("3:15"), "3:15");
        assert_eq!(bytes_to_mb("8388608").as_deref(), Some("8"));
        assert_eq!(bytes_to_mb("1").as_deref(), Some("1"));
        assert_eq!(bytes_to_mb("x"), None);
    }
}
