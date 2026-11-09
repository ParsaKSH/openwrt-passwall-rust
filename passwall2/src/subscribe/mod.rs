//! Node subscription (subscribe.lua). Spec: docs/spec/06-subscribe-rules.md §1.
//!
//! CLI (same arguments as `lua subscribe.lua ...`):
//! * `passwall2 subscribe start <cfgid[,cfgid...]|all> [manual|cron]` — fetch subscriptions
//! * `passwall2 subscribe add <group>` — import the links in `/tmp/links.conf` (rpc `link_add_node`)
//! * `passwall2 subscribe truncate [group]` — delete subscription nodes (one group / all)
//!
//! Library entry points for rpc: [`add_links`] (manual import of share links / Clash YAML),
//! [`truncate`], [`LINKS_FILE`]. [`acquire_update_lock`] is the lock shared with the rule
//! updater (`/var/lock/passwall2_sub_rule.lock`, lockf + one task-marker byte).

pub mod clash;
pub mod links;
pub mod yaml;

use crate::api;
use crate::uci::{self, Batch, Config, Section};
use crate::util;
use indexmap::IndexMap;
use links::{NVal, Node, ParseCtx};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};

/// `api.LOCK_PREFIX .. "_sub_rule.lock"`
pub const LOCK_FILE: &str = "/var/lock/passwall2_sub_rule.lock";
/// Manual import input written by `link_add_node`.
pub const LINKS_FILE: &str = "/tmp/links.conf";
/// Cached `-H` arguments for HWID headers.
pub const HEADERS_CACHE: &str = "/tmp/etc/passwall2_tmp/sub_curl_headers";

fn log(level: usize, msg: &str) {
    util::log(level, msg)
}
fn tr(s: &str) -> String {
    api::translate(s)
}
fn trf(s: &str, a: &[&str]) -> String {
    api::translatef(s, a)
}

// ============================================================================ update lock

/// Held update lock (released on drop / process exit, like lockf).
pub struct UpdateLock {
    _file: std::fs::File,
}

extern "C" {
    fn lockf(fd: i32, cmd: i32, len: i64) -> i32;
}
const F_LOCK: i32 = 1;
const F_TLOCK: i32 = 2;

/// Take the subscription/rule-update lock like upstream: `marker` is `b's'` (subscription)
/// or `b'r'` (rule update), `task` its translated name. When the lock is busy a manual run
/// (`wait == false`) logs and returns `Err(0)`; a cron run logs "[running] is running;
/// [task] is queued..." and blocks. `Err(1)` when the lock cannot be opened/acquired.
pub fn acquire_update_lock(marker: u8, task: &str, wait: bool) -> Result<UpdateLock, i32> {
    use std::os::unix::io::AsRawFd;
    util::mkdir(util::LOCK_PATH);
    let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(LOCK_FILE) else {
        log(0, &tr("Unable to open the subscription/rule update lock. Exiting."));
        return Err(1);
    };
    let fd = f.as_raw_fd();
    if unsafe { lockf(fd, F_TLOCK, 0) } != 0 {
        if !wait {
            log(0, &tr("A subscription or rule update is already running. Skipping this request."));
            return Err(0);
        }
        let mut b = [0u8; 1];
        let n = f.read(&mut b).unwrap_or(0);
        let running = match (n, b[0]) {
            (1, b's') => tr("Subscription"),
            (1, b'r') => tr("Rule Update"),
            _ => tr("Subscription/Rule Update"),
        };
        let _ = f.seek(SeekFrom::Start(0));
        log(0, &trf("[%s] is running; [%s] is queued and waiting...", &[&running, task]));
        if unsafe { lockf(fd, F_LOCK, 0) } != 0 {
            log(0, &tr("Unable to acquire the update lock. Scheduled task failed."));
            return Err(1);
        }
    }
    let _ = f.seek(SeekFrom::Start(0));
    let _ = f.write_all(&[marker]);
    let _ = f.seek(SeekFrom::Start(0));
    Ok(UpdateLock { _file: f })
}

// ============================================================================ UCI cursor

/// In-memory view of `/etc/config/passwall2` plus the staged `uci batch` commands
/// (the Lua cursor of upstream: reads see staged changes, nothing is written until commit).
struct Cursor {
    cfg: Config,
    batch: Batch,
    /// false in unit tests: never touch the real UCI
    live: bool,
}

/// uci batch input is line based; keep values on one line.
fn one_line(v: &str) -> String {
    if v.contains(['\n', '\r']) {
        v.replace(['\n', '\r'], " ")
    } else {
        v.to_string()
    }
}

impl Cursor {
    fn load() -> Cursor {
        Cursor { cfg: Config::load(util::CONFIG), batch: Batch::new(), live: true }
    }
    fn get_all(&self, id: &str) -> Option<Section> {
        if id.is_empty() {
            return None;
        }
        self.cfg.section(id).cloned()
    }
    fn get(&self, id: &str, opt: &str) -> Option<String> {
        self.cfg.section(id)?.get(opt)
    }
    fn stype(&self, id: &str) -> Option<String> {
        if id.is_empty() {
            return None;
        }
        self.cfg.stype(id)
    }
    fn sec_mut(&mut self, id: &str) -> Option<&mut Section> {
        let name = self.cfg.section(id)?.name.clone();
        self.cfg.sections.iter_mut().find(|s| s.name == name)
    }
    fn path(&self, id: &str, opt: &str) -> Option<String> {
        self.cfg.section(id).map(|s| format!("{}.{}.{}", util::CONFIG, s.name, opt))
    }
    /// `uci_set(id, opt, value)`: empty value deletes the option.
    fn set(&mut self, id: &str, opt: &str, value: &str) {
        if value.is_empty() {
            self.del_opt(id, opt);
            return;
        }
        let v = one_line(value);
        let Some(path) = self.path(id, opt) else { return };
        if let Some(s) = self.sec_mut(id) {
            s.options.insert(opt.to_string(), uci::Value::Single(v.clone()));
        }
        self.batch.set(&path, &v);
    }
    /// `uci_set(id, opt, table)`: empty list deletes the option.
    fn set_list(&mut self, id: &str, opt: &str, values: &[String]) {
        if values.is_empty() {
            self.del_opt(id, opt);
            return;
        }
        let Some(path) = self.path(id, opt) else { return };
        let vals: Vec<String> = values.iter().map(|v| one_line(v)).collect();
        let existed = self.cfg.section(id).is_some_and(|s| s.has(opt));
        if let Some(s) = self.sec_mut(id) {
            s.options.insert(opt.to_string(), uci::Value::List(vals.clone()));
        }
        if existed {
            self.batch.delete(&path);
        }
        for v in &vals {
            self.batch.add_list(&path, v);
        }
    }
    fn del_opt(&mut self, id: &str, opt: &str) {
        let Some(path) = self.path(id, opt) else { return };
        if let Some(s) = self.sec_mut(id) {
            if s.options.shift_remove(opt).is_some() {
                self.batch.delete(&path);
            }
        }
    }
    fn del_section(&mut self, id: &str) {
        let Some(name) = self.cfg.section(id).map(|s| s.name.clone()) else { return };
        self.cfg.sections.retain(|s| s.name != name);
        self.batch.delete(&format!("{}.{}", util::CONFIG, name));
    }
    /// `uci:section(config, stype, name)` (named section appended at the end).
    fn add_named(&mut self, name: &str, stype: &str) {
        let index = self.cfg.sections.iter().filter(|s| s.stype == stype).count();
        self.cfg.sections.push(Section { name: name.to_string(), stype: stype.to_string(), anonymous: false, index, options: IndexMap::new() });
        self.batch.section(util::CONFIG, name, stype);
    }
    fn sections_of(&self, stype: &str) -> Vec<Section> {
        self.cfg.sections_of(stype).cloned().collect()
    }
    /// `uci_save(true)`: apply staged changes and commit.
    fn commit(&mut self) {
        if !self.live {
            self.batch = Batch::new();
            return;
        }
        if let Err(e) = self.batch.commit() {
            log(1, &format!("uci: {}", e));
        }
        self.batch = Batch::new();
    }
}

// ============================================================================ references (CONFIG)

#[derive(Clone, Debug)]
enum Cur {
    Node(Section),
    /// a SOCKS section referenced from a balancer/urltest (kept verbatim)
    Socks(String),
    /// `uci_get(id) or {}` of a missing section
    Empty,
}

#[derive(Clone, Debug)]
enum Kind {
    Global,
    Socks { sid: String },
    Haproxy { sid: String, ip_port: bool },
    Acl { sid: String },
    Shunt { node: String, key: String },
    /// fallback_node / preproxy_node / to_node (with delete)
    NodeOpt { node: String, opt: String },
}

#[derive(Clone, Debug)]
struct Single {
    log: bool,
    remarks: String,
    cur: Option<Section>,
    kind: Kind,
}

#[derive(Clone, Debug)]
struct Child {
    log: bool,
    remarks: String,
    cur: Cur,
}

#[derive(Clone, Debug)]
struct List {
    remarks: String,
    children: Vec<Child>,
    new_nodes: Vec<String>,
    sid: String,
    opt: String,
}

#[derive(Clone, Debug)]
enum Entry {
    Single(Single),
    List(List),
}

/// `is_ip_port(lbss)`: `^([%d%.]+):(%d+)$`, valid IP, port ≤ 65535.
fn is_ip_port(s: Option<&str>) -> bool {
    let Some(s) = s else { return false };
    let Some((ip, port)) = s.rsplit_once(':') else { return false };
    !ip.is_empty()
        && ip.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && !port.is_empty()
        && port.bytes().all(|c| c.is_ascii_digit())
        && api::dt_ipaddr(ip)
        && port.parse::<u64>().is_ok_and(|p| p <= 65535)
}

/// One `select_node` priority: (log label, predicate on a candidate node).
type MatchStep<'a> = (&'static str, &'a dyn Fn(&Section) -> bool);

/// Result of parsing one subscription / import (`nodeResult` entry).
struct NodeResult {
    remark: String,
    list: Vec<Node>,
    sub: Option<Section>,
    md5: Option<String>,
}

/// Log sink with the optional buffer used while a subscription is parsed.
#[derive(Default)]
struct Logger {
    buffer: Option<Vec<(usize, String)>>,
}
impl Logger {
    fn log(&mut self, level: usize, msg: &str) {
        match &mut self.buffer {
            Some(b) => b.push((level, msg.to_string())),
            None => log(level, msg),
        }
    }
    fn flush(&mut self) {
        for (l, m) in self.buffer.take().unwrap_or_default() {
            log(l, &m);
        }
    }
}

/// One run of the subscription engine (state of subscribe.lua after its prologue).
struct Run {
    cur: Cursor,
    ctx: ParseCtx,
    /// (name, remarks) of the normal nodes at startup (fallback for SOCKS / single refs)
    nodes_table: Vec<(String, String)>,
    refs: Vec<Entry>,
    results: Vec<NodeResult>,
    /// cfgid → (expired_date, rem_traffic)
    sub_info: IndexMap<String, (String, String)>,
    info_from_headers: HashSet<String>,
    logger: Logger,
    restart_required: bool,
}

impl Run {
    /// Prologue: `uci revert`, core detection, defaults, nodes_table, CONFIG.
    fn init() -> Run {
        uci::revert(util::CONFIG);
        let cur = Cursor::load();
        let ctx = ParseCtx::detect(&cur.cfg);
        Self::with(cur, ctx)
    }

    fn with(cur: Cursor, ctx: ParseCtx) -> Run {
        let nodes_table = api::get_valid_nodes(&cur.cfg).into_iter().filter(|n| n.node_type == "normal").map(|n| (n.section.name.clone(), n.section.s("remarks"))).collect();
        let mut run = Run {
            cur,
            ctx,
            nodes_table,
            refs: vec![],
            results: vec![],
            sub_info: IndexMap::new(),
            info_from_headers: HashSet::new(),
            logger: Logger::default(),
            restart_required: false,
        };
        run.build_refs();
        run
    }

    fn build_refs(&mut self) {
        let c = &self.cur;
        let mut refs: Vec<Entry> = vec![];
        let node_sec = |id: Option<String>| id.and_then(|i| c.get_all(&i));
        // global node
        refs.push(Entry::Single(Single { log: true, remarks: trf("Node", &[]), cur: node_sec(c.get("@global[0]", "node")), kind: Kind::Global }));
        // socks
        for (i, t) in c.sections_of("socks").iter().enumerate() {
            let n = (i + 1).to_string();
            refs.push(Entry::Single(Single {
                log: true,
                remarks: trf("Socks node list [%s]", &[&n]),
                cur: node_sec(t.get("node")),
                kind: Kind::Socks { sid: t.name.clone() },
            }));
            let backups = t.list_raw("autoswitch_backup_node");
            if !backups.is_empty() {
                let flag = format!("{} {}", trf("Socks node list [%s]", &[&n]), trf("Backup node list", &[]));
                let mut children = vec![];
                for (k, id) in backups.iter().enumerate() {
                    if let Some(sec) = c.get_all(id).filter(|s| s.stype == "nodes") {
                        children.push(Child { log: true, remarks: format!("{}[{}]", flag, k + 1), cur: Cur::Node(sec) });
                    }
                }
                refs.push(Entry::List(List { remarks: flag, children, new_nodes: vec![], sid: t.name.clone(), opt: "autoswitch_backup_node".into() }));
            }
        }
        // haproxy
        for (i, t) in c.sections_of("haproxy_config").iter().enumerate() {
            let lbss = t.get("lbss");
            refs.push(Entry::Single(Single {
                log: true,
                remarks: trf("HAProxy node list [%s]", &[&(i + 1).to_string()]),
                cur: node_sec(lbss.clone()),
                kind: Kind::Haproxy { sid: t.name.clone(), ip_port: is_ip_port(lbss.as_deref()) },
            }));
        }
        // acl
        for (i, t) in c.sections_of("acl_rule").iter().enumerate() {
            refs.push(Entry::Single(Single { log: true, remarks: trf("ACL list [%s]", &[&(i + 1).to_string()]), cur: node_sec(t.get("node")), kind: Kind::Acl { sid: t.name.clone() } }));
        }
        // nodes
        let is_nodes = |id: &str| c.stype(id).as_deref() == Some("nodes");
        for node in c.sections_of("nodes") {
            let nid = node.name.clone();
            match node.get("protocol").as_deref() {
                Some("_shunt") => {
                    let mut rules: Vec<(String, String)> = vec![];
                    for e in c.sections_of("shunt_rules") {
                        if let Some(r) = e.get("remarks") {
                            rules.push((e.name.clone(), r.clone()));
                            rules.push((format!("{}_proxy_tag", e.name), format!("{} {}", r, tr("Preproxy"))));
                        }
                    }
                    rules.push(("default_node".into(), trf("Default", &[])));
                    rules.push(("default_proxy_tag".into(), format!("{} {}", trf("Default", &[]), tr("Preproxy"))));
                    for (key, remarks) in rules {
                        if let Some(id) = node.get(&key) {
                            if let Some(sec) = c.get_all(&id).filter(|s| s.stype == "nodes") {
                                refs.push(Entry::Single(Single {
                                    log: false,
                                    remarks: trf("Shunt [%s] node", &[&remarks]),
                                    cur: Some(sec),
                                    kind: Kind::Shunt { node: nid.clone(), key },
                                }));
                            }
                        }
                    }
                }
                Some(p @ ("_balancing" | "_urltest")) => {
                    let (opt, flag) = if p == "_balancing" {
                        ("balancing_node", trf("Xray Load Balancing node [%s] list", &[&nid]))
                    } else {
                        ("urltest_node", trf("Sing-Box URLTest node [%s] list", &[&nid]))
                    };
                    let children = node
                        .list_raw(opt)
                        .iter()
                        .map(|id| {
                            let cur = match c.get_all(id) {
                                Some(s) if s.stype == "socks" => Cur::Socks(id.clone()),
                                Some(s) => Cur::Node(s),
                                None => Cur::Empty,
                            };
                            Child { log: true, remarks: id.clone(), cur }
                        })
                        .collect();
                    refs.push(Entry::List(List { remarks: flag, children, new_nodes: vec![], sid: nid.clone(), opt: opt.into() }));
                    if p == "_balancing" {
                        if let Some(fb) = node.get("fallback_node").filter(|f| is_nodes(f)) {
                            refs.push(Entry::Single(Single {
                                log: true,
                                remarks: trf("Xray Load Balancing node [%s] backup node", &[&nid]),
                                cur: c.get_all(&fb),
                                kind: Kind::NodeOpt { node: nid.clone(), opt: "fallback_node".into() },
                            }));
                        }
                    }
                }
                _ => {
                    for (opt, fmt) in [("preproxy_node", "Node [%s] preproxy node"), ("to_node", "Node [%s] landing node")] {
                        if let Some(id) = node.get(opt).filter(|f| is_nodes(f)) {
                            refs.push(Entry::Single(Single {
                                log: true,
                                remarks: trf(fmt, &[&nid]),
                                cur: c.get_all(&id),
                                kind: Kind::NodeOpt { node: nid.clone(), opt: opt.into() },
                            }));
                        }
                    }
                }
            }
        }
        // post-filter: single entries pointing to nothing are deleted (haproxy / chain refs) and dropped
        let mut kept = vec![];
        for e in refs {
            match e {
                Entry::Single(s) if s.cur.is_none() => self.single_delete(&s),
                other => kept.push(other),
            }
        }
        self.refs = kept;
    }

    fn has_delete(kind: &Kind) -> bool {
        matches!(kind, Kind::Haproxy { .. } | Kind::NodeOpt { .. })
    }

    fn single_delete(&mut self, s: &Single) {
        match &s.kind {
            Kind::Haproxy { sid, ip_port } if !ip_port => self.cur.del_section(sid),
            Kind::NodeOpt { node, opt } => self.cur.del_opt(node, opt),
            _ => {}
        }
    }

    fn single_set(&mut self, s: &Single, server: &str) {
        match &s.kind {
            Kind::Global => self.cur.set("@global[0]", "node", server),
            Kind::Socks { sid } => {
                let mut server = server.to_string();
                if server.is_empty() {
                    if let Some((n, _)) = self.nodes_table.first() {
                        server = n.clone();
                    }
                }
                self.cur.set(sid, "node", &server);
            }
            Kind::Haproxy { sid, ip_port } => {
                if !ip_port {
                    self.cur.set(sid, "lbss", server);
                }
            }
            Kind::Acl { sid } => self.cur.set(sid, "node", server),
            Kind::Shunt { node, key } => self.cur.set(node, key, server),
            Kind::NodeOpt { node, opt } => self.cur.set(node, opt, server),
        }
    }

    /// `select_node` matching: the new section name for a reference, with logging.
    fn find_server(&mut self, nodes: &[Section], cur: &Cur, do_log: bool, remarks: &str, has_parent: bool) -> Option<String> {
        let level = if has_parent { 2 } else { 1 };
        let sec = match cur {
            Cur::Socks(id) => return Some(id.clone()),
            Cur::Empty => return None,
            Cur::Node(s) => s,
        };
        let say = |logger: &mut Logger, what: &str, node: &Section| {
            if do_log {
                logger.log(level, &format!("{} {} {}", trf("Update [%s]", &[remarks]), trf(what, &[]), node.s("remarks")));
            }
        };
        if let Some(n) = nodes.iter().find(|n| n.name == sec.name) {
            say(&mut self.logger, "Matching node:", n);
            return Some(n.name.clone());
        }
        let g = |s: &Section, k: &str| s.get(k);
        let ap = |s: &Section| -> Option<String> { Some(format!("{}:{}", g(s, "address")?, g(s, "port")?)) };
        let steps: [MatchStep; 5] = [
            ("First Matching node:", &|n: &Section| {
                g(sec, "type").is_some() && g(sec, "remarks").is_some() && ap(sec).is_some()
                    && g(n, "type").is_some() && g(n, "remarks").is_some() && ap(n).is_some()
                    && g(n, "type") == g(sec, "type") && g(n, "remarks") == g(sec, "remarks") && ap(n) == ap(sec) && g(n, "group") == g(sec, "group")
            }),
            ("Second Matching node:", &|n: &Section| {
                g(sec, "type").is_some() && ap(sec).is_some() && g(n, "type").is_some() && ap(n).is_some() && g(n, "type") == g(sec, "type") && ap(n) == ap(sec) && g(n, "group") == g(sec, "group")
            }),
            ("Third Matching node:", &|n: &Section| ap(sec).is_some() && ap(n).is_some() && ap(n) == ap(sec) && g(n, "group") == g(sec, "group")),
            ("Fourth Matching node:", &|n: &Section| g(sec, "address").is_some() && g(n, "address").is_some() && g(n, "address") == g(sec, "address") && g(n, "group") == g(sec, "group")),
            ("Fifth Matching node:", &|n: &Section| g(sec, "remarks").is_some() && g(n, "remarks").is_some() && g(n, "remarks") == g(sec, "remarks") && g(n, "group") == g(sec, "group")),
        ];
        for (what, pred) in steps.iter() {
            if let Some(n) = nodes.iter().find(|n| pred(n)) {
                say(&mut self.logger, what, n);
                return Some(n.name.clone());
            }
        }
        if !has_parent {
            if let Some((name, rem)) = self.nodes_table.first().cloned() {
                if do_log {
                    self.logger.log(level, &format!("{} {} {}", trf("Update [%s]", &[remarks]), trf("Unable to find the best matching node, now replaced with:", &[]), rem));
                }
                return Some(name);
            }
        }
        None
    }

    /// `update_node(manual)`: 0 = subscription (replaces the groups' subscription nodes),
    /// 1 = manual import. Returns false when there is nothing to write.
    fn update_node(&mut self, manual: u8) -> bool {
        if self.results.is_empty() {
            self.logger.log(1, &trf("No node information updates are available.", &[]));
            return false;
        }
        let groups: HashSet<String> = self.results.iter().map(|r| r.remark.to_lowercase()).collect();
        if manual == 0 && !groups.is_empty() {
            for n in self.cur.sections_of("nodes") {
                if n.is("add_mode", "2") && n.get("group").is_some_and(|g| groups.contains(&g.to_lowercase())) {
                    self.cur.del_section(&n.name);
                }
            }
        }
        let results = std::mem::take(&mut self.results);
        for r in &results {
            let mut dr = None;
            let mut drd = None;
            let mut drh = None;
            let mut ds = None;
            let (mut pre, mut to, mut ifc, mut chain_type) = (String::new(), String::new(), String::new(), String::new());
            if let Some(sub) = &r.sub {
                dr = sub.get("domain_resolver");
                drd = sub.get("domain_resolver_dns");
                drh = sub.get("domain_resolver_dns_https");
                ds = sub.get("domain_strategy").filter(|d| d == "UseIPv4" || d == "UseIPv6");
                let mut valid_chain = |id: Option<String>| -> String {
                    let Some(id) = id else { return String::new() };
                    let cp = self.cur.get(&id, "chain_proxy").unwrap_or_default();
                    let am = self.cur.get(&id, "add_mode").unwrap_or_else(|| "0".into());
                    chain_type = if cp.is_empty() && am != "2" { self.cur.get(&id, "type").unwrap_or_default() } else { String::new() };
                    if chain_type != "Xray" && chain_type != "sing-box" {
                        chain_type.clear();
                        return String::new();
                    }
                    id
                };
                let cp = sub.get("chain_proxy");
                if cp.as_deref() == Some("1") {
                    pre = valid_chain(sub.get("preproxy_node"));
                }
                if cp.as_deref() == Some("2") {
                    to = valid_chain(sub.get("to_node"));
                }
                if cp.as_deref() == Some("3") {
                    ifc = sub.get("outbound_iface").unwrap_or_default();
                }
                if !ifc.is_empty() {
                    chain_type = "iface".into();
                }
            }
            for node in &r.list {
                let mut id = api::gen_random_char(8);
                while id.is_empty() || self.cur.cfg.section(&id).is_some() {
                    id = api::gen_random_char(8);
                }
                self.cur.add_named(&id, "nodes");
                for (k, v) in node.0.iter() {
                    match v {
                        NVal::L(l) if !l.is_empty() => self.cur.set_list(&id, k, l),
                        NVal::L(_) => {}
                        NVal::S(s) => {
                            if !(k == "group" && s == "default") {
                                self.cur.set(&id, k, s);
                            }
                            if k == "type" && (s == "Xray" || s == "sing-box") {
                                if let Some(d) = dr.as_deref().filter(|d| !d.is_empty() && *d != "disable") {
                                    self.cur.set(&id, "domain_resolver", d);
                                    if d == "https" {
                                        if let Some(h) = &drh {
                                            self.cur.set(&id, "domain_resolver_dns_https", h);
                                        }
                                    } else if d == "udp" || d == "tcp" {
                                        if let Some(x) = &drd {
                                            self.cur.set(&id, "domain_resolver_dns", x);
                                        }
                                    }
                                }
                                if let Some(d) = &ds {
                                    // upstream quirk: the converted value leaked into later nodes
                                    // of the same subscription; convert per node instead
                                    let v = if s == "sing-box" {
                                        match d.as_str() {
                                            "UseIPv4" => "ipv4_only",
                                            "UseIPv6" => "ipv6_only",
                                            x => x,
                                        }
                                    } else {
                                        d.as_str()
                                    };
                                    self.cur.set(&id, "domain_strategy", v);
                                }
                                if !chain_type.is_empty() {
                                    if !pre.is_empty() {
                                        self.cur.set(&id, "chain_proxy", "1");
                                        self.cur.set(&id, "preproxy_node", &pre);
                                    } else if !to.is_empty() {
                                        self.cur.set(&id, "chain_proxy", "2");
                                        self.cur.set(&id, "to_node", &to);
                                    } else if !ifc.is_empty() {
                                        self.cur.set(&id, "chain_proxy", "3");
                                        self.cur.set(&id, "outbound_iface", &ifc);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        self.results = results;
        if !self.refs.is_empty() {
            let nodes = self.cur.sections_of("nodes");
            let mut refs = std::mem::take(&mut self.refs);
            for e in refs.iter_mut() {
                match e {
                    Entry::List(l) if !l.children.is_empty() => {
                        if l.children[0].log {
                            self.logger.log(1, &trf("Update [%s]", &[&l.remarks]));
                        }
                        for ch in l.children.clone() {
                            if let Some(s) = self.find_server(&nodes, &ch.cur, ch.log, &ch.remarks, true) {
                                if s != "nil" {
                                    l.new_nodes.push(s);
                                }
                            }
                        }
                        let (sid, opt, nn) = (l.sid.clone(), l.opt.clone(), l.new_nodes.clone());
                        self.cur.set_list(&sid, &opt, &nn);
                        if nn.is_empty() {
                            self.logger.log(1, &format!("{} {}", trf("[%s]", &[&l.remarks]), tr("Unable to find a new node. Please confirm and process manually.")));
                        }
                    }
                    Entry::List(l) => {
                        // select_node on a list entry without children: set(config, "") deletes the option
                        let (sid, opt) = (l.sid.clone(), l.opt.clone());
                        self.cur.del_opt(&sid, &opt);
                    }
                    Entry::Single(s) => {
                        let s = s.clone();
                        match &s.cur {
                            Some(sec) => {
                                if let Some(server) = self.find_server(&nodes, &Cur::Node(sec.clone()), s.log, &s.remarks, false) {
                                    self.single_set(&s, &server);
                                }
                            }
                            None => self.single_set(&s, ""),
                        }
                    }
                }
            }
            self.refs = refs;
        }
        true
    }

    /// `update_subscribe_info()`: write changed expiry / traffic info; returns changed cfgids.
    fn update_subscribe_info(&mut self) -> HashSet<String> {
        let mut changed = HashSet::new();
        for (cfgid, (exp, rem)) in self.sub_info.clone() {
            for (key, value) in [("expired_date", exp), ("rem_traffic", rem)] {
                let v = if value.is_empty() { None } else { Some(value) };
                if self.cur.get(&cfgid, key) != v {
                    match &v {
                        Some(v) => self.cur.set(&cfgid, key, v),
                        None => self.cur.del_opt(&cfgid, key),
                    }
                    changed.insert(cfgid.clone());
                }
            }
        }
        changed
    }

    /// `get_subscribe_info(cfgid, remarks)`
    fn subscribe_info_from_remarks(&mut self, cfgid: &str, remarks: &str) {
        if cfgid.is_empty() {
            return;
        }
        let (exp, rem) = links::subscribe_info_from_remarks(remarks);
        let e = self.sub_info.entry(cfgid.to_string()).or_insert((String::new(), String::new()));
        if let Some(x) = exp {
            e.0 = x;
        }
        if let Some(x) = rem {
            e.1 = x;
        }
    }

    /// `parse_link` + nodeResult bookkeeping for manual imports.
    fn parse_link(&mut self, raw: &str, add_mode: &str, group: Option<&str>, sub: Option<&Section>) -> links::LinkOutcome {
        let ctx = self.ctx.clone();
        let logger = &mut self.logger;
        let out = links::parse_link(&ctx, raw, add_mode, group, sub, &mut |l, m| logger.log(l, &m));
        if add_mode == "2" {
            let cfgid = sub.map(|s| s.name.clone()).unwrap_or_default();
            if !self.info_from_headers.contains(&cfgid) {
                for r in &out.remarks_seen {
                    self.subscribe_info_from_remarks(&cfgid, r);
                }
            }
        } else if !out.nodes.is_empty() {
            self.results.push(NodeResult { remark: group.unwrap_or("").to_string(), list: out.nodes.clone(), sub: sub.cloned(), md5: None });
        }
        out
    }

    // ------------------------------------------------------------------------ modes

    /// `add <group>`: import links (or a Clash document) manually. Returns (added, failed).
    fn add(&mut self, raw: &str, group: Option<&str>) -> (usize, usize) {
        let (raw, _) = clash::parse_clash_node(raw, group.unwrap_or(""), false);
        let out = self.parse_link(&raw, "1", group, None);
        if self.update_node(1) {
            self.cur.commit();
        }
        let ok = out.nodes.len();
        (ok, out.candidates.saturating_sub(ok))
    }

    /// `truncate [group]`: delete subscription nodes and fix the references.
    fn truncate(&mut self, group: Option<&str>) {
        let gl = group.map(|g| g.to_lowercase());
        let matches = |s: &Section| s.is("add_mode", "2") && gl.as_ref().is_none_or(|g| *g == s.s("group").to_lowercase());
        let refs = std::mem::take(&mut self.refs);
        for e in &refs {
            match e {
                Entry::List(l) if !l.children.is_empty() => {
                    let remove: HashSet<String> = l.children.iter().filter_map(|c| if let Cur::Node(s) = &c.cur { if matches(s) { Some(s.name.clone()) } else { None } } else { None }).collect();
                    // upstream quirk: SOCKS children / missing sections have no name and are dropped
                    let new: Vec<String> = l.children.iter().filter_map(|c| if let Cur::Node(s) = &c.cur { Some(s.name.clone()) } else { None }).filter(|n| !remove.contains(n)).collect();
                    self.cur.set_list(&l.sid, &l.opt, &new);
                }
                Entry::List(_) => {}
                Entry::Single(s) => {
                    if let Some(sec) = &s.cur {
                        if matches(sec) {
                            if Self::has_delete(&s.kind) {
                                self.single_delete(s);
                            } else {
                                self.single_set(s, "");
                            }
                        }
                    }
                }
            }
        }
        self.refs = refs;
        for n in self.cur.sections_of("nodes") {
            if matches(&n) {
                self.cur.del_section(&n.name);
            }
        }
        for s in self.cur.sections_of("subscribe_list") {
            if gl.as_ref().is_none_or(|g| *g == s.s("remark").to_lowercase()) {
                self.cur.del_opt(&s.name, "md5");
            }
        }
        self.cur.commit();
    }

    /// `start <ids|all> [manual|cron]`
    fn start(&mut self, ids: Option<&str>, manual: bool) {
        log(0, &tr("Start subscribing..."));
        if let Err(e) = self.execute(ids, manual) {
            self.logger.flush();
            log(1, &e);
            log(1, &tr("An error occurred during subscription."));
        }
        log(0, &format!("{}\n", tr("Subscription complete...")));
    }

    fn execute(&mut self, ids: Option<&str>, manual: bool) -> Result<(), String> {
        let ids = ids.ok_or_else(|| "bad argument #1 to 'gsub' (string expected, got nil)".to_string())?;
        let list: Vec<Section> = if ids == "all" {
            self.cur.sections_of("subscribe_list")
        } else {
            // upstream crashes on unknown ids; skip them
            ids.split(',').filter(|w| !w.is_empty()).filter_map(|w| self.cur.get_all(w)).collect()
        };
        let mut fail: Vec<(String, String)> = vec![];
        for value in list.iter() {
            let mut value = value.clone();
            let cfgid = value.name.clone();
            let remark = value.s("remark");
            let url = value.s("url");
            let mut http_code: Option<String> = None;
            let mut headers = String::new();
            let url_is_local = !url.is_empty() && std::path::Path::new(&url).exists();
            let tmp_file;
            if url_is_local {
                log(1, &trf("Start subscribing: %s", &[&format!("【{}】{}", remark, url)]));
                tmp_file = url.clone();
            } else {
                let label = match value.get("access_mode").as_deref() {
                    Some("direct") => trf("Direct", &[]),
                    Some("proxy") => trf("Proxy", &[]),
                    _ => trf("Auto", &[]),
                };
                log(1, &trf("Start subscribing: %s", &[&format!("【{}】{} [{}]", remark, url, label)]));
                tmp_file = format!("/tmp/{}", cfgid);
                let (rc, code, hdrs) = curl(&url, &tmp_file, value.get("user_agent").as_deref(), value.get("access_mode").as_deref(), value.get("hwid").as_deref());
                http_code = Some(code);
                headers = hdrs;
                if rc != 0 {
                    fail.push((remark.clone(), http_code.clone().unwrap_or_else(|| "nil".into())));
                    let _ = std::fs::remove_file(&tmp_file);
                }
            }
            if !util::exists(&tmp_file) {
                continue;
            }
            match remove_blank_lines(&tmp_file) {
                Some(content) => {
                    let raw = api::trim(&content);
                    let auto_dns = value.get("domain_resolver").is_none_or(|d| d.is_empty());
                    let (raw, resolver) = clash::parse_clash_node(&raw, &remark, auto_dns);
                    if auto_dns {
                        if let Some(r) = resolver {
                            // only this run's sub_cfg; the subscription keeps its Auto setting
                            let o = &mut value.options;
                            o.insert("domain_resolver".into(), uci::Value::Single(r.domain_resolver));
                            match r.domain_resolver_dns {
                                Some(v) => o.insert("domain_resolver_dns".into(), uci::Value::Single(v)),
                                None => o.shift_remove("domain_resolver_dns"),
                            };
                            match r.domain_resolver_dns_https {
                                Some(v) => o.insert("domain_resolver_dns_https".into(), uci::Value::Single(v)),
                                None => o.shift_remove("domain_resolver_dns_https"),
                            };
                        }
                    }
                    if !headers.is_empty() {
                        if let Some(info) = clash::parse_clash_sub_info(&headers) {
                            self.sub_info.insert(cfgid.clone(), (info.expired_date, info.rem_traffic));
                            self.info_from_headers.insert(cfgid.clone());
                        }
                    }
                    self.logger.buffer = Some(vec![]);
                    let out = self.parse_link(&raw, "2", Some(&remark), Some(&value));
                    let mut md5_content = serde_json::Value::Array(out.nodes.iter().map(|n| n.canonical_json()).collect()).to_string();
                    if let Some(p) = value.get("domain_resolver").filter(|d| !d.is_empty() && d != "disable") {
                        let dns = if p == "udp" || p == "tcp" { value.s("domain_resolver_dns") } else { String::new() };
                        let doh = if p == "https" { value.s("domain_resolver_dns_https") } else { String::new() };
                        md5_content.push_str(&serde_json::json!([p, dns, doh]).to_string());
                    }
                    let new_md5 = if out.nodes.is_empty() { String::new() } else { api::md5_string(&md5_content) };
                    if !manual && !new_md5.is_empty() && value.s("md5") == new_md5 {
                        self.logger.buffer = None;
                        log(1, &trf("Subscription: [%s] No changes, no update required.", &[&remark]));
                    } else {
                        self.logger.flush();
                        if !out.nodes.is_empty() {
                            self.results.push(NodeResult { remark: remark.clone(), list: out.nodes, sub: Some(value.clone()), md5: Some(new_md5) });
                        }
                    }
                }
                None => fail.push((remark.clone(), http_code.clone().unwrap_or_else(|| "nil".into()))),
            }
            if !url_is_local {
                let _ = std::fs::remove_file(&tmp_file);
            }
        }
        for (remark, code) in &fail {
            log(1, &trf("[%s] Subscription failed. This could be due to an invalid subscription address or a network issue. Please diagnose the problem! [%s]", &[remark, code]));
        }
        let nodes_changed = self.update_node(0);
        let info_changed = self.update_subscribe_info();
        let md5s: Vec<(String, String)> = self.results.iter().filter_map(|r| Some((r.sub.as_ref()?.name.clone(), r.md5.clone()?))).collect();
        for (id, md5) in md5s {
            self.cur.set(&id, "md5", &md5);
        }
        if nodes_changed || !info_changed.is_empty() {
            self.cur.commit();
            self.restart_required = nodes_changed;
            for v in &list {
                if info_changed.contains(&v.name) {
                    log(1, &trf("Refresh subscription [%s] account usage and expiration information.", &[&v.s("remark")]));
                }
            }
        }
        Ok(())
    }
}

/// `[ -f F ] && sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' F`: the cleaned content, or None.
fn remove_blank_lines(path: &str) -> Option<String> {
    if !std::path::Path::new(path).is_file() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        if body.chars().all(|c| c == ' ' || c == '\t') {
            continue;
        }
        out.push_str(line);
    }
    if out.len() != text.len() && std::fs::write(path, &out).is_err() {
        return None;
    }
    Some(out)
}

/// `get_headers()`: `-H` arguments with the device/HWID headers (cached until reboot).
fn get_headers() -> String {
    if util::exists(HEADERS_CACHE) {
        return util::read(HEADERS_CACHE);
    }
    let readfile = |p: &str| -> Option<String> { std::fs::read_to_string(p).ok().map(|c| api::trim(&c)) };
    let mut headers = vec!["x-device-os: OpenWrt".to_string()];
    if let Some(rel) = readfile("/etc/openwrt_release") {
        if let Some(i) = rel.find("DISTRIB_RELEASE='") {
            let rest = &rel[i + 17..];
            if let Some(j) = rest.find('\'') {
                if j > 0 {
                    headers.push(format!("x-ver-os: {}", &rest[..j]));
                }
            }
        }
    }
    let model = readfile("/tmp/sysinfo/model");
    if let Some(m) = &model {
        headers.push(format!("x-device-model: {}", m));
    }
    if let (Some(mac), Some(m)) = (readfile("/sys/class/net/eth0/address"), &model) {
        let (_, out) = util::cmd_stdin("sha256sum", &[], &format!("{}-{}", mac, m));
        let hash: String = out.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        if !hash.is_empty() {
            headers.push(format!("x-hwid: {}", hash));
        }
    }
    let s = headers.iter().map(|h| format!("-H {}", util::shq(h))).collect::<Vec<_>>().join(" ");
    util::write(HEADERS_CACHE, &s);
    s
}

/// `curl(url, file, ua, mode, hwid)` → (exit code, http code, response headers).
fn curl(url: &str, file: &str, ua: Option<&str>, mode: Option<&str>, hwid: Option<&str>) -> (i32, String, String) {
    if url.is_empty() {
        return (22, "404".into(), String::new());
    }
    let mut args: Vec<String> = ["-fskL", "--retry 3", "--connect-timeout 3", "-H 'Accept: */*'", "-H 'Accept-Encoding: identity'", "--dump-header -", "-w '\\n%{http_code}'"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(ua) = ua.filter(|u| !u.is_empty() && *u != "curl") {
        let ua = if ua == "passwall2" { format!("passwall2/{}", api::get_version().split('-').next().unwrap_or("")) } else { ua.to_string() };
        // upstream wraps the UA in double quotes unescaped; quote it safely
        args.push(format!("--user-agent {}", util::shq(&ua)));
    }
    if hwid == Some("1") {
        args.push(get_headers());
    }
    let cookie = format!("/tmp/cookie_{}", api::gen_random_char(5));
    args.push(format!("-c {} -b {}", util::shq(&cookie), util::shq(&cookie)));
    let res = match mode {
        Some("direct") => Some(api::curl_direct(url, Some(file), &args)),
        Some("proxy") => api::curl_proxy(url, Some(file), &args),
        _ => Some(api::curl_auto(url, Some(file), &args)),
    };
    let _ = std::fs::remove_file(&cookie);
    let Some((rc, out)) = res else { return (-1, "0".into(), String::new()) };
    let (code, headers) = split_curl_output(&out);
    (rc, code, headers)
}

/// `result:match("^(.-)%s*([0-9]+)$")` → (http code, headers without `\r`).
fn split_curl_output(out: &str) -> (String, String) {
    let digits = out.len() - out.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if out.is_empty() || digits == 0 {
        return ("0".into(), String::new());
    }
    let (body, code) = out.split_at(out.len() - digits);
    let body = body.trim_end_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let code = code.parse::<u64>().map(|c| c.to_string()).unwrap_or_else(|_| "0".into());
    (code, body.replace('\r', ""))
}

// ============================================================================ public API

/// Manual import (rpc `link_add_node`): parse share links (one per line) or a Clash YAML
/// document and add them as nodes of `group` (`add_mode=1`; group `default` = no group).
/// Takes the update lock like `subscribe add` and commits. Returns `(added, failed)`;
/// `Err` when another subscription/rule update holds the lock.
pub fn add_links(links_text: &str, group: &str) -> Result<(usize, usize), String> {
    let _lock = acquire_update_lock(b's', &tr("Subscription"), false).map_err(|_| tr("A subscription or rule update is already running. Skipping this request."))?;
    let mut run = Run::init();
    let g = if group.is_empty() { None } else { Some(group) };
    Ok(run.add(links_text, g))
}

/// `subscribe truncate [group]` as a library call (rpc `subscribe_del_node` /
/// `subscribe_del_all`). False when the lock is busy.
pub fn truncate(group: Option<&str>) -> bool {
    let Ok(_lock) = acquire_update_lock(b's', &tr("Subscription"), false) else { return false };
    let mut run = Run::init();
    run.truncate(group);
    true
}

/// `passwall2 subscribe <start|add|truncate> ...` (upstream `subscribe.lua` arguments).
pub fn cli(args: &[String]) -> i32 {
    let Some(cmd) = args.first() else { return 0 };
    let a2 = args.get(1).map(|s| s.as_str());
    let a3 = args.get(2).map(|s| s.as_str());
    let lock = match acquire_update_lock(b's', &tr("Subscription"), a3 == Some("cron")) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let mut run = Run::init();
    let mut rc = 0;
    match cmd.as_str() {
        "start" => run.start(a2, a3 == Some("manual")),
        "add" => match std::fs::read(LINKS_FILE) {
            Ok(b) => {
                let raw = String::from_utf8_lossy(&b).to_string();
                let (ok, failed) = run.add(&raw, a2);
                let _ = std::fs::remove_file(LINKS_FILE);
                println!("{{\"added\":{},\"failed\":{}}}", ok, failed);
            }
            Err(e) => {
                eprintln!("subscribe: {}: {}", LINKS_FILE, e);
                rc = 1;
            }
        },
        "truncate" => run.truncate(a2),
        _ => {}
    }
    drop(lock);
    if run.restart_required {
        let action = if a3 == Some("cron") { " cron" } else { "" };
        util::sh(&format!("/etc/init.d/passwall2 restart{} > /dev/null 2>&1 &", action));
    }
    rc
}

#[cfg(test)]
mod tests {
    use super::links::{Cores, KeywordFilter};
    use super::*;

    const CFG: &str = r#"
config global
	option node 'old1'

config global_other
	option show_node_info '0'

config socks 'sk'
	option node 'gone'
	list autoswitch_backup_node 'old2'
	list autoswitch_backup_node 'manual1'

config haproxy_config 'hp1'
	option lbss 'missing'

config haproxy_config 'hp2'
	option lbss '1.2.3.4:443'

config acl_rule 'acl1'
	option node 'old2'

config shunt_rules 'rule1'
	option remarks 'R1'

config nodes 'manual1'
	option type 'Xray'
	option protocol 'vless'
	option remarks 'Manual'
	option address 'm.com'
	option port '443'

config nodes 'old1'
	option type 'Xray'
	option protocol 'trojan'
	option remarks 'HK 01'
	option address 'hk.example.com'
	option port '443'
	option add_mode '2'
	option group 'MySub'

config nodes 'old2'
	option type 'Xray'
	option protocol 'trojan'
	option remarks 'JP old name'
	option address 'jp.example.com'
	option port '443'
	option add_mode '2'
	option group 'MySub'

config nodes 'shunt'
	option type 'Xray'
	option protocol '_shunt'
	option rule1 'old1'
	option default_node 'old2'

config nodes 'bal'
	option type 'Xray'
	option protocol '_balancing'
	list balancing_node 'old1'
	list balancing_node 'sk'
	list balancing_node 'nonexistent'
	option fallback_node 'old2'

config subscribe_list 'sub1'
	option remark 'MySub'
	option md5 'abc'
"#;

    fn run_with(cfg: &str) -> Run {
        let c = Cursor { cfg: Config::parse("passwall2", cfg), batch: Batch::new(), live: false };
        let ctx = ParseCtx {
            cores: Cores::all(),
            ss_type: Some("xray".into()),
            trojan_type: Some("xray".into()),
            vmess_type: Some("xray".into()),
            vless_type: Some("xray".into()),
            hysteria2_type: Some("sing-box".into()),
            filter: KeywordFilter { mode: "0".into(), ..Default::default() },
        };
        Run::with(c, ctx)
    }

    fn opt(r: &Run, id: &str, o: &str) -> Option<String> {
        r.cur.get(id, o)
    }

    #[test]
    fn refs_built_and_post_filtered() {
        let r = run_with(CFG);
        // socks node 'gone' dropped, haproxy hp1 → missing: section deleted; hp2 ip:port kept but no ref
        assert!(r.cur.cfg.section("hp1").is_none());
        assert!(r.cur.cfg.section("hp2").is_some());
        let singles = r.refs.iter().filter(|e| matches!(e, Entry::Single(_))).count();
        // global, acl, shunt rule1, shunt default_node, bal fallback
        assert_eq!(singles, 5);
        let lists: Vec<&List> = r.refs.iter().filter_map(|e| if let Entry::List(l) = e { Some(l) } else { None }).collect();
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].opt, "autoswitch_backup_node");
        assert_eq!(lists[0].children.len(), 2);
        assert_eq!(lists[1].children.len(), 3);
        assert!(matches!(lists[1].children[1].cur, Cur::Socks(_)));
        assert!(matches!(lists[1].children[2].cur, Cur::Empty));
    }

    #[test]
    fn subscription_update_repoints_references() {
        let mut r = run_with(CFG);
        let sub = r.cur.get_all("sub1").unwrap();
        let raw = api::base64_encode(b"trojan://p@hk.example.com:443#HK 01\ntrojan://p@jp.example.com:443#JP new name\ntrojan://p@kr.example.com:443#KR");
        r.logger.buffer = Some(vec![]);
        let out = r.parse_link(&raw, "2", Some("MySub"), Some(&sub));
        assert_eq!(out.nodes.len(), 3);
        r.results.push(NodeResult { remark: "MySub".into(), list: out.nodes, sub: Some(sub), md5: Some("x".into()) });
        assert!(r.update_node(0));
        // old subscription nodes deleted, 3 new ones + manual1 + shunt + bal
        let nodes = r.cur.sections_of("nodes");
        assert_eq!(nodes.len(), 6);
        assert!(r.cur.cfg.section("old1").is_none());
        let hk = nodes.iter().find(|n| n.is("remarks", "HK 01")).unwrap();
        let jp = nodes.iter().find(|n| n.is("remarks", "JP new name")).unwrap();
        assert_eq!(hk.get("group").as_deref(), Some("MySub"));
        assert_eq!(hk.get("add_mode").as_deref(), Some("2"));
        assert_eq!(hk.name.len(), 8);
        // global → First match (type+remarks+addr:port+group)
        assert_eq!(opt(&r, "@global[0]", "node").as_deref(), Some(hk.name.as_str()));
        // acl → old2 matched by type+addr:port+group (Second)
        assert_eq!(opt(&r, "acl1", "node").as_deref(), Some(jp.name.as_str()));
        assert_eq!(opt(&r, "shunt", "rule1").as_deref(), Some(hk.name.as_str()));
        assert_eq!(opt(&r, "shunt", "default_node").as_deref(), Some(jp.name.as_str()));
        assert_eq!(opt(&r, "bal", "fallback_node").as_deref(), Some(jp.name.as_str()));
        // balancer keeps socks reference, drops the missing one
        assert_eq!(r.cur.cfg.section("bal").unwrap().list_raw("balancing_node"), vec![hk.name.clone(), "sk".to_string()]);
        // socks backup: old2 → new jp, manual1 kept
        assert_eq!(r.cur.cfg.section("sk").unwrap().list_raw("autoswitch_backup_node"), vec![jp.name.clone(), "manual1".to_string()]);
    }

    #[test]
    fn truncate_group() {
        let mut r = run_with(CFG);
        r.truncate(Some("mysub"));
        assert!(r.cur.cfg.section("old1").is_none());
        assert!(r.cur.cfg.section("old2").is_none());
        assert!(r.cur.cfg.section("manual1").is_some());
        // global/acl/shunt options deleted, fallback deleted, socks backup keeps manual1
        assert_eq!(opt(&r, "@global[0]", "node"), None);
        assert_eq!(opt(&r, "acl1", "node"), None);
        assert_eq!(opt(&r, "shunt", "rule1"), None);
        assert_eq!(opt(&r, "bal", "fallback_node"), None);
        assert_eq!(r.cur.cfg.section("sk").unwrap().list_raw("autoswitch_backup_node"), vec!["manual1".to_string()]);
        // upstream quirk: socks children of balancers are dropped by truncate
        assert!(r.cur.cfg.section("bal").unwrap().list_raw("balancing_node").is_empty());
        assert_eq!(opt(&r, "sub1", "md5"), None);
    }

    #[test]
    fn manual_add() {
        let mut r = run_with(CFG);
        let (ok, fail) = r.add("vless://u@a.com:443?security=tls#A\nnot a link\nsocks://x\n", Some("default"));
        assert_eq!((ok, fail), (1, 2));
        let a = r.cur.sections_of("nodes").into_iter().find(|n| n.is("remarks", "A")).unwrap();
        assert_eq!(a.get("group"), None);
        assert_eq!(a.get("add_mode").as_deref(), Some("1"));
        // existing references stay on their own nodes
        assert_eq!(opt(&r, "@global[0]", "node").as_deref(), Some("old1"));
    }

    #[test]
    fn domain_strategy_and_chain() {
        let cfg = format!("{}\nconfig subscribe_list 'sub2'\n\toption remark 'S2'\n\toption domain_strategy 'UseIPv4'\n\toption domain_resolver 'udp'\n\toption domain_resolver_dns '1.1.1.1:53'\n\toption chain_proxy '1'\n\toption preproxy_node 'manual1'\n", CFG);
        let mut r = run_with(&cfg);
        let sub = r.cur.get_all("sub2").unwrap();
        let mut a = Node::default();
        a.set("type", "sing-box");
        a.set("remarks", "a");
        let mut b = Node::default();
        b.set("type", "Xray");
        b.set("remarks", "b");
        r.results.push(NodeResult { remark: "S2".into(), list: vec![a, b], sub: Some(sub), md5: None });
        r.update_node(0);
        let nodes = r.cur.sections_of("nodes");
        let a = nodes.iter().find(|n| n.is("remarks", "a")).unwrap();
        let b = nodes.iter().find(|n| n.is("remarks", "b")).unwrap();
        assert_eq!(a.get("domain_strategy").as_deref(), Some("ipv4_only"));
        assert_eq!(b.get("domain_strategy").as_deref(), Some("UseIPv4"));
        assert_eq!(a.get("domain_resolver_dns").as_deref(), Some("1.1.1.1:53"));
        assert_eq!(b.get("chain_proxy").as_deref(), Some("1"));
        assert_eq!(b.get("preproxy_node").as_deref(), Some("manual1"));
    }

    #[test]
    fn helpers() {
        assert!(is_ip_port(Some("1.2.3.4:443")));
        assert!(!is_ip_port(Some("1.2.3.4:70000")));
        assert!(!is_ip_port(Some("abc")));
        assert_eq!(split_curl_output("HTTP/1.1 200 OK\r\nA: b\r\n\r\n\n200"), ("200".into(), "HTTP/1.1 200 OK\nA: b".into()));
        assert_eq!(split_curl_output(""), ("0".into(), String::new()));
    }
}
