//! sing-box config generator — port of upstream `luasrc/passwall2/util_sing-box.lua`.
//! Spec: docs/spec/04-singbox-config.md
//!
//! * [`gen_config`]        client config (socks/http/redirect/tproxy/dns inbounds, shunt, DNS, fakeip)
//! * [`gen_proto_config`]  minimal socks/http → upstream socks/http bridge
//! * [`gen_config_server`] server config for a `passwall2_server` section
//! * [`geo_convert_srs`]   geosite/geoip `.dat` category → sing-box `.srs` via geoview
//!
//! CLI: `passwall2 sing-box <gen_config|gen_proto_config|geo_convert_srs> '<json>'` and
//! `passwall2 sing-box gen_config_server <server_section_id>` print the result like upstream.
//!
//! Lua globals / module state (`NO_RUN`, `TMP_PORT`, `ech_domain`, `GLOBAL.DNS_SERVER`,
//! `GEO_VAR` tags, the shunt `rules`, ...) live in the per-generation [`Gen`] context.

use crate::api;
use crate::uci::{self, Config, Section};
use crate::util::{self, Args, ArgsExt};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::sync::OnceLock;

type M = Map<String, Value>;

/// `GEO_VAR.TO_SRS_PATH` (trailing slash).
pub const TO_SRS_PATH: &str = "/tmp/etc/passwall2_tmp/singbox_srss/";
const CACHE_PATH: &str = api::CACHE_PATH;

// ====================================================================== small JSON helpers

/// Lua number → JSON (integral values rendered as integers like luci.jsonc).
fn num(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
    }
}
/// Lua `tostring(number)`.
fn num_str(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        format!("{}", f as i64)
    } else {
        format!("{}", f)
    }
}
/// Lua `tonumber(x)` (nil-safe).
fn tonum(v: Option<&str>) -> Option<f64> {
    v.and_then(api::lua_tonumber)
}
fn set(m: &mut M, k: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(k.to_string(), v);
    }
}
fn del(m: &mut M, k: &str) {
    m.shift_remove(k);
}
fn obj(pairs: Vec<(&str, Option<Value>)>) -> M {
    let mut m = M::new();
    for (k, v) in pairs {
        set(&mut m, k, v);
    }
    m
}
fn sv(s: &str) -> Option<Value> {
    Some(Value::String(s.to_string()))
}
fn ov(s: Option<&str>) -> Option<Value> {
    s.map(|x| Value::String(x.to_string()))
}
fn bv(b: bool) -> Option<Value> {
    Some(Value::Bool(b))
}
/// Lua `cond and true or nil`.
fn tv(b: bool) -> Option<Value> {
    if b {
        Some(Value::Bool(true))
    } else {
        None
    }
}
fn nv(f: Option<f64>) -> Option<Value> {
    f.map(num)
}
fn arr<S: AsRef<str>>(v: &[S]) -> Value {
    Value::Array(v.iter().map(|s| Value::String(s.as_ref().to_string())).collect())
}
fn mv(m: M) -> Option<Value> {
    Some(Value::Object(m))
}
fn tag_of(m: &M) -> Option<&str> {
    m.get("tag").and_then(|t| t.as_str())
}
/// Lua `string.gsub(s, '[^<seps>]+', ...)`: non-empty runs of chars not in `seps`.
fn gsplit(s: &str, seps: &[char]) -> Vec<String> {
    s.split(|c| seps.contains(&c)).filter(|x| !x.is_empty()).map(|x| x.to_string()).collect()
}
/// Lua `s:match("^%d+")` → leading digits as number.
fn leading_digits(s: &str) -> Option<f64> {
    let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if d.is_empty() {
        None
    } else {
        d.parse::<f64>().ok()
    }
}
/// `api.split(str:gsub("\\n", "\n"), "\n")` — literal backslash-n → newline, then lines.
fn pem_lines(s: &str) -> Value {
    arr(&api::split(&s.replace("\\n", "\n"), "\n"))
}
/// `get_log_level`: "warning" → "warn".
fn get_log_level(s: Option<&str>) -> Option<String> {
    s.map(|v| if v == "warning" { "warn".to_string() } else { v.to_string() })
}
fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

// ====================================================================== node table

/// One value of a Lua UCI section table: string option or list option.
#[derive(Clone, Debug, PartialEq)]
pub enum NV {
    S(String),
    L(Vec<String>),
}

/// A UCI section as the Lua code sees it (`uci:get_all`): `.name`, `.type` + options.
/// Presence follows Lua truthiness (an empty string is present).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Node(pub IndexMap<String, NV>);

impl Node {
    pub fn from_section(s: &Section) -> Node {
        let mut m = IndexMap::new();
        m.insert(".name".to_string(), NV::S(s.name.clone()));
        m.insert(".type".to_string(), NV::S(s.stype.clone()));
        for (k, v) in &s.options {
            let nv = match v {
                uci::Value::Single(x) => NV::S(x.clone()),
                uci::Value::List(l) => NV::L(l.clone()),
            };
            m.insert(k.clone(), nv);
        }
        Node(m)
    }
    /// String option (lists → None, like a table in a string context).
    pub fn g(&self, k: &str) -> Option<&str> {
        match self.0.get(k) {
            Some(NV::S(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    /// String option, list options space-joined (MultiValue may be stored either way).
    pub fn joined(&self, k: &str) -> Option<String> {
        match self.0.get(k) {
            Some(NV::S(s)) => Some(s.clone()),
            Some(NV::L(l)) => Some(l.join(" ")),
            None => None,
        }
    }
    pub fn is(&self, k: &str, v: &str) -> bool {
        self.g(k) == Some(v)
    }
    /// Lua truthiness of `node.k`.
    pub fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    /// Lua-truthy flag, except that an explicit "0" counts as off.
    // upstream quirk: upstream tests `node.hysteria2_realms` / `node.plugin_enabled` by Lua
    // truthiness, so a stored "0" (written by LuCI JS Flag widgets) would enable them.
    pub fn flag_on(&self, k: &str) -> bool {
        self.has(k) && self.g(k) != Some("0")
    }
    pub fn set(&mut self, k: &str, v: &str) {
        self.0.insert(k.to_string(), NV::S(v.to_string()));
    }
    pub fn del(&mut self, k: &str) {
        self.0.shift_remove(k);
    }
    pub fn name(&self) -> Option<&str> {
        self.g(".name")
    }
    /// Raw value as JSON (string or array of strings).
    pub fn raw(&self, k: &str) -> Option<Value> {
        match self.0.get(k)? {
            NV::S(s) => Some(Value::String(s.clone())),
            NV::L(l) => Some(arr(l)),
        }
    }
    /// List option (a single string option is split on whitespace).
    pub fn list(&self, k: &str) -> Vec<String> {
        match self.0.get(k) {
            Some(NV::L(l)) => l.clone(),
            Some(NV::S(s)) => s.split_whitespace().map(|x| x.to_string()).collect(),
            None => vec![],
        }
    }
    fn from_pairs(pairs: &[(&str, Option<&str>)]) -> Node {
        let mut n = Node::default();
        for (k, v) in pairs {
            if let Some(v) = v {
                n.set(k, v);
            }
        }
        n
    }
}

// ====================================================================== versions

/// sing-box version dependent branches (spec §8).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Versions {
    pub ge_1_13_16: bool,
    pub ge_1_14_0: bool,
    pub ge_1_15_0: bool,
}

impl Versions {
    /// From a version string as printed by `sing-box version` (leading `v` stripped like
    /// upstream `:match("[^v]+")`). Empty/unknown → all false.
    pub fn from_version(v: &str) -> Versions {
        let local: String = v.chars().skip_while(|c| *c == 'v').take_while(|c| *c != 'v').collect();
        Versions {
            ge_1_13_16: api::compare_versions(&local, ">=", "1.13.16"),
            ge_1_14_0: api::compare_versions(&local, ">=", "1.14.0"),
            ge_1_15_0: api::compare_versions(&local, ">=", "1.15.0"),
        }
    }
    /// Installed sing-box version (cached per process). `PASSWALL2_SINGBOX_VERSION` overrides.
    pub fn detect() -> Versions {
        static V: OnceLock<Versions> = OnceLock::new();
        *V.get_or_init(|| {
            let v = std::env::var("PASSWALL2_SINGBOX_VERSION").unwrap_or_else(|_| api::get_app_version("sing-box", None));
            Versions::from_version(&v)
        })
    }
}

// ====================================================================== geo → srs

/// Geo categories referenced by a generated config (`GEO_VAR.SITE_TAGS` / `IP_TAGS`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoTags {
    pub site: Vec<String>,
    pub ip: Vec<String>,
}
impl GeoTags {
    pub fn is_empty(&self) -> bool {
        self.site.is_empty() && self.ip.is_empty()
    }
}

/// Result of a successful [`check_geoview`].
#[derive(Clone, Debug, PartialEq)]
pub struct GeoPaths {
    pub dir: String,
    pub site_path: String,
    pub ip_path: String,
}

/// `GEO_VAR.DIR` from `v2ray_location_asset`: everything before the last `/`
/// ("/usr/share/v2ray/" → "/usr/share/v2ray", "/usr/share/v2ray" → "/usr/share").
pub fn geo_dir(asset: &str) -> String {
    match asset.rfind('/') {
        Some(i) => asset[..i].to_string(),
        // upstream would crash (nil concat); use the value as the directory
        None => asset.to_string(),
    }
}

/// `check_geoview()`: geoview ≥ 0.1.10 present → paths (and srs dir created); else logs the
/// warning (on every call, like upstream) and returns None.
pub fn check_geoview() -> Option<GeoPaths> {
    static OK: OnceLock<bool> = OnceLock::new();
    let ok = *OK.get_or_init(|| api::finded_com("geoview").is_some() && api::compare_versions(&api::get_app_version("geoview", None), ">=", "0.1.10"));
    if !ok {
        api::log(0, &api::translate("!!! Note: Geo rules cannot be used if the Geoview component is missing or the version is too low."));
        return None;
    }
    let cfg = Config::load(util::CONFIG);
    let dir = geo_dir(&cfg.get_or("@global_rules[0]", "v2ray_location_asset", "/usr/share/v2ray/"));
    if !util::exists(TO_SRS_PATH) {
        util::mkdir(TO_SRS_PATH);
    }
    Some(GeoPaths { site_path: format!("{}/geosite.dat", dir), ip_path: format!("{}/geoip.dat", dir), dir })
}

/// `geo_convert_srs({geo_path, prefix, rule_name})`: convert one category with geoview unless
/// the `.srs` already exists.
pub fn geo_convert_srs(var: &Args) {
    if check_geoview().is_none() {
        return;
    }
    let geo_path = var.s("geo_path");
    let prefix = var.s("prefix");
    let rule_name = var.s("rule_name");
    let out_file = format!("{}{}-{}.srs", TO_SRS_PATH, prefix, rule_name);
    let Some(bin) = api::finded_com("geoview") else { return };
    if util::exists(&out_file) {
        return;
    }
    // upstream quirk: upstream quotes with Lua %q (double quotes, `$` not escaped); we
    // single-quote every argument so names cannot inject shell commands.
    let cmd = format!(
        "{} -type {} -action convert -input {} -list {} -output {} -lowmem=true",
        util::shq(&bin),
        util::shq(&prefix),
        util::shq(&geo_path),
        util::shq(&rule_name),
        util::shq(&out_file)
    );
    let (code, out) = api::exec_call(&cmd);
    if code != 0 || !util::exists(&out_file) {
        api::log(0, &format!("  - {}:{} convert to srs {} [{}]", prefix, rule_name, "failed!", out));
    }
}

/// `convert_geofile()`: convert every referenced geosite/geoip category.
pub fn convert_geofile(tags: &GeoTags) {
    let Some(p) = check_geoview() else { return };
    for (path, prefix, list) in [(&p.site_path, "geosite", &tags.site), (&p.ip_path, "geoip", &tags.ip)] {
        if list.is_empty() || !util::exists(path) {
            continue;
        }
        for k in list {
            let mut a = Args::new();
            a.insert("geo_path".into(), path.clone());
            a.insert("prefix".into(), prefix.into());
            a.insert("rule_name".into(), k.clone());
            geo_convert_srs(&a);
        }
    }
}

/// `parse_rule_set(w, rs)`: `local:/path/name.srs|json` / `remote:https://.../name.srs|json`.
pub fn parse_rule_set(w: &str, rs: bool) -> Option<M> {
    if w.is_empty() || !(w.starts_with("local:") || w.starts_with("remote:")) {
        return None;
    }
    let i = w.find(':')?;
    let typ = &w[..i];
    let rest = &w[i + 1..];
    let filename = match rest.rfind('/') {
        Some(j) => &rest[j + 1..],
        None => rest,
    };
    let suffix = match filename.rfind('.') {
        Some(j) => &filename[j + 1..],
        None => "",
    };
    let format = match suffix {
        "srs" => "binary",
        "json" => "source",
        _ => return None,
    };
    let tag = &filename[..filename.find('.')?];
    if tag.is_empty() {
        return None;
    }
    let tag = if rs { format!("rs_{}", tag) } else { tag.to_string() };
    Some(obj(vec![
        ("type", sv(typ)),
        ("tag", sv(&tag)),
        ("format", sv(format)),
        ("path", if typ == "local" { sv(rest) } else { None }),
        ("url", if typ == "remote" { sv(rest) } else { None }),
    ]))
}

/// `geo_rule_set(prefix, name)` → local binary rule-set in [`TO_SRS_PATH`].
pub fn geo_rule_set(prefix: &str, name: &str) -> Option<M> {
    parse_rule_set(&format!("local:{}{}-{}.srs", TO_SRS_PATH, prefix, name), false)
}

/// ECH `get_ech_domain`: xray-compatible "domain+DNS" form → domain.
fn get_ech_domain(s: &str) -> Option<String> {
    let (domain, dns) = s.split_once('+')?;
    if domain.is_empty() || dns.is_empty() {
        return None;
    }
    if !["http://", "https://", "tcp://", "udp://", "h2c://"].iter().any(|p| dns.starts_with(p)) {
        return None;
    }
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return None;
    }
    let dot = domain.rfind('.')?;
    let tld = &domain[dot + 1..];
    if dot == 0 || tld.is_empty() || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(domain.to_string())
}

/// Lua `s:match("%-+%s*BEGIN")` (and END).
fn has_pem_marker(s: &str, word: &str) -> bool {
    let mut from = 0;
    while let Some(i) = s[from..].find(word) {
        let idx = from + i;
        let before = s[..idx].trim_end_matches(|c: char| c.is_ascii_whitespace());
        if before.ends_with('-') {
            return true;
        }
        from = idx + word.len();
    }
    false
}

// ====================================================================== generation context

/// `proxy_table` argument of gen_outbound / gen_outbound_get_tag.
#[derive(Clone, Debug, Default)]
struct ProxyTable {
    tag: Option<String>,
    fragment: bool,
    record_fragment: bool,
    chain_proxy: Option<String>,
    preproxy_node: Option<String>,
    to_node: Option<String>,
}

enum Ut {
    Existing(usize),
    New(M),
}

/// Per-generation state (upstream module globals + gen_config locals shared by closures).
pub struct Gen {
    cfg: Config,
    ver: Versions,
    /// `NO_RUN`: dry run (no sub-processes, fake ports from 3001).
    no_run: bool,
    tmp_port: Option<u32>,
    ech_domain: Vec<String>,
    /// `GLOBAL.DNS_SERVER`: node id → (dns server, node domain)
    dns_server: IndexMap<String, (M, String)>,
    geo: GeoTags,
    outbounds: Vec<M>,
    inbounds: Vec<Value>,
    /// shunt `rules` (Lua global)
    rules: Vec<Value>,
    rule_set_table: IndexMap<String, M>,
    default_node_address: Option<String>,
    default_node_port: Option<String>,
    sb_fragment: bool,
    sb_record_fragment: bool,
    flag: String,
    /// real side effects (spawn run_socks, iface touch, cache files, ipset flush, port alloc)
    fx: bool,
    test_port: u16,
}

impl Gen {
    fn new(cfg: Config, ver: Versions) -> Gen {
        let sb = cfg.section("@global_singbox[0]");
        let sb_fragment = sb.is_some_and(|s| s.is("fragment", "1"));
        let sb_record_fragment = sb.is_some_and(|s| s.is("record_fragment", "1"));
        Gen {
            cfg,
            ver,
            no_run: false,
            tmp_port: None,
            ech_domain: vec![],
            dns_server: IndexMap::new(),
            geo: GeoTags::default(),
            outbounds: vec![],
            inbounds: vec![],
            rules: vec![],
            rule_set_table: IndexMap::new(),
            default_node_address: None,
            default_node_port: None,
            sb_fragment,
            sb_record_fragment,
            flag: String::new(),
            fx: true,
            test_port: 20000,
        }
    }

    /// `api.get_new_port()` (auto, tcp+udp).
    fn new_port(&mut self) -> u16 {
        if self.fx {
            api::get_new_port(None, "")
        } else {
            self.test_port += 1;
            self.test_port
        }
    }

    /// `/usr/share/passwall2/app.sh run_socks "flag=.. node=.. ..."` → our binary.
    fn run_socks(&self, port: &str, node_id: &str, config_file: &str, relay_port: &str) {
        if !self.fx {
            return;
        }
        let bin = if util::is_executable(util::SELF_BIN) {
            util::SELF_BIN.to_string()
        } else {
            std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| util::SELF_BIN.to_string())
        };
        let _ = std::process::Command::new(bin)
            .args([
                "app".to_string(),
                "run_socks".to_string(),
                format!("flag={}", port),
                format!("node={}", node_id),
                "bind=127.0.0.1".to_string(),
                format!("socks_port={}", port),
                format!("config_file={}", config_file),
                format!("relay_port={}", relay_port),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status();
    }

    /// `mkdir -p /tmp/etc/passwall2/iface && touch /tmp/etc/passwall2/iface/<iface>`
    fn touch_iface(&self, iface: &str) {
        if !self.fx || iface.contains('/') {
            return;
        }
        util::mkdir(api::TMP_IFACE_PATH);
        let p = format!("{}/{}", api::TMP_IFACE_PATH, iface);
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(p);
    }

    // ------------------------------------------------------------------ gen_outbound

    /// `gen_outbound(flag, node, tag, proxy_table)` (spec §3).
    fn gen_outbound(&mut self, flag: Option<&str>, node: Option<Node>, tag: Option<&str>, pt: Option<&ProxyTable>) -> Option<M> {
        let mut node = node?;
        let node_id: Option<String> = node.name().map(|s| s.to_string());
        let tag: Option<String> = tag.map(|s| s.to_string()).or_else(|| node_id.clone());
        let remarks = node.g("remarks").map(|s| s.to_string());

        let mut proxy_tag: Option<String> = None;
        let (mut fragment, mut record_fragment) = (false, false);
        if let Some(pt) = pt {
            proxy_tag = pt.tag.clone();
            let excluded = node.is("protocol", "naive") || node.is("protocol", "masque") || node.flag_on("hysteria2_realms");
            fragment = pt.fragment && !excluded;
            record_fragment = pt.record_fragment && !excluded;
        }

        if !node.is("type", "sing-box") {
            let id = node_id.clone().unwrap_or_default();
            let mut new_port: Option<String> = None;
            if self.no_run {
                let p = self.tmp_port.map(|p| p + 1).unwrap_or(3001);
                self.tmp_port = Some(p);
                new_port = Some(p.to_string());
            } else {
                let relay_port = if proxy_tag.is_some() { node.g("port").unwrap_or("").to_string() } else { String::new() };
                let mut run = true;
                if relay_port.is_empty() && self.fx {
                    if let Some(c) = api::get_socks_port_by_cache(&id) {
                        new_port = Some(c);
                        run = false;
                    }
                }
                if run {
                    let p = self.new_port().to_string();
                    let mut config_file = format!("nodesocks_{}_{}.json", id, p);
                    if let Some(t) = &tag {
                        if node_id.is_some() && !t.contains(&id) {
                            config_file = format!("nodesocks_{}_{}_{}.json", t, id, p);
                        }
                    }
                    self.run_socks(&p, &id, &config_file, &relay_port);
                    if relay_port.is_empty() && self.fx {
                        api::set_socks_port_to_cache(&id, &p);
                    }
                    new_port = Some(p);
                }
            }
            if let Some(p) = new_port {
                node = Node::from_pairs(&[("protocol", Some("socks")), ("address", Some("127.0.0.1")), ("port", Some(&p))]);
                proxy_tag = Some(format!("socks <- {}", id));
            }
        } else if let Some(p) = &proxy_tag {
            node.set("detour", p);
        }

        let tag = match &remarks {
            Some(r) => format!("{}:{}", tag.unwrap_or_default(), r),
            None => tag.unwrap_or_default(),
        };

        let address = node.g("address").unwrap_or("").to_lowercase();
        node.set("address", &address);

        let mut result = obj(vec![
            ("_id", ov(node_id.as_deref())),
            ("_flag", ov(flag)),
            ("_flag_proxy_tag", ov(proxy_tag.as_deref())),
            ("tag", sv(&tag)),
            ("type", ov(node.g("protocol"))),
            ("server", sv(&address)),
            ("server_port", nv(tonum(node.g("port")))),
            ("domain_resolver", mv(obj(vec![("server", sv("local")), ("strategy", ov(node.g("domain_strategy")))]))),
            ("detour", ov(node.g("detour"))),
        ]);

        // per-node domain resolver
        if api::dt_hostname(&address) && node.has("domain_resolver") && (node.has("domain_resolver_dns") || node.has("domain_resolver_dns_https")) {
            let id = node_id.clone().unwrap_or_default();
            let dns_tag = format!("{}_dns", id);
            let dns_proto = node.g("domain_resolver").unwrap_or("").to_string();
            let mut server_address: Option<String> = None;
            let mut server_port: Option<f64> = None;
            let mut server_path: Option<String> = None;
            if dns_proto == "https" {
                if let Some(u) = node.g("domain_resolver_dns_https").and_then(api::parse_url) {
                    server_address = Some(u.hostname.clone());
                    server_port = Some(u.port.map(|p| p as f64).unwrap_or(443.0));
                    server_path = u.pathname.clone();
                }
            } else if let Some(a) = node.g("domain_resolver_dns") {
                server_address = Some(a.to_string());
                server_port = Some(53.0);
                let parts = api::split(a, ":");
                if parts.len() > 1 {
                    server_address = Some(parts[0].clone());
                    server_port = tonum(parts.last().map(|s| s.as_str()));
                }
            }
            let server = obj(vec![
                ("tag", sv(&dns_tag)),
                ("type", sv(&dns_proto)),
                ("server", ov(server_address.as_deref())),
                ("server_port", nv(server_port)),
                ("path", ov(server_path.as_deref())),
                ("domain_resolver", sv("local")),
                ("detour", sv("direct")),
            ]);
            self.dns_server.insert(id, (server, address.clone()));
            if let Some(Value::Object(dr)) = result.get_mut("domain_resolver") {
                dr.insert("server".into(), Value::String(dns_tag));
            }
        }

        // TLS
        let protocol = node.g("protocol").unwrap_or("").to_string();
        if protocol == "masque" {
            for k in ["alpn", "utls", "reality", "transport", "mux"] {
                node.del(k);
            }
        }
        if ["hysteria", "hysteria2", "tuic", "naive", "masque"].contains(&protocol.as_str()) {
            node.set("tls", "1");
        }
        let mut tls: Option<M> = None;
        if node.is("tls", "1") {
            let alpn = match node.g("alpn") {
                Some(a) if a != "default" => Some(arr(&gsplit(a, &[',']))),
                _ => None,
            };
            let certificate = if node.is("tls_certificate", "1") {
                // upstream crashes on a missing pem; treat as empty
                node.g("tls_certificate_pem").filter(|p| !p.is_empty()).map(pem_lines)
            } else {
                None
            };
            let cipher_suites = match node.0.get("cipherSuites") {
                Some(NV::L(l)) => Some(arr(l)),
                Some(NV::S(s)) if !s.is_empty() => Some(arr(&api::split(s, ":"))),
                _ => None,
            };
            let ech = if node.is("ech", "1") { mv(self.ech(&node)) } else { None };
            let utls = if node.is("utls", "1") || node.is("reality", "1") {
                mv(obj(vec![("enabled", bv(true)), ("fingerprint", sv(node.g("fingerprint").unwrap_or("chrome")))]))
            } else {
                None
            };
            let reality = if node.is("reality", "1") {
                mv(obj(vec![("enabled", bv(true)), ("public_key", ov(node.g("reality_publicKey"))), ("short_id", ov(node.g("reality_shortId")))]))
            } else {
                None
            };
            let mut t = obj(vec![
                ("enabled", bv(true)),
                ("disable_sni", bv(node.is("tls_disable_sni", "1"))),
                ("server_name", ov(node.g("tls_serverName"))),
                ("insecure", bv(node.is("tls_allowInsecure", "1"))),
                ("alpn", alpn),
                ("fragment", tv(fragment)),
                ("record_fragment", tv(record_fragment)),
                ("certificate", certificate),
                ("cipher_suites", cipher_suites),
                ("ech", ech),
                ("utls", utls),
                ("reality", reality),
            ]);
            // legacy (26.4) name: tls_CertSha, read when the new option is unset/empty (like
            // xray.rs and `passwall2 migrate`, which copies it in that case)
            let pin = node.g("tls_pinSHA256").filter(|p| !p.is_empty()).or_else(|| node.g("tls_CertSha").filter(|p| !p.is_empty()));
            if self.ver.ge_1_15_0 {
                if let Some(p) = pin {
                    t.insert("certificate_sha256".into(), arr(&[api::sha256_xray_sb(p)]));
                }
            } else {
                // Lua: `allowInsecure == "1" or (pin and pin ~= "")` → true, false (empty pin) or
                // nil (no pin: the key is absent).
                if node.is("tls_allowInsecure", "1") || pin.is_some() {
                    t.insert("insecure".into(), Value::Bool(true));
                } else if node.g("tls_pinSHA256").is_some() {
                    t.insert("insecure".into(), Value::Bool(false));
                } else {
                    t.remove("insecure");
                }
            }
            tls = Some(t);
        }
        let tls_v = || tls.clone().map(Value::Object);

        // multiplex
        let mux = if node.is("mux", "1") {
            let brutal = node.is("tcpbrutal", "1");
            mv(obj(vec![
                ("enabled", bv(true)),
                ("protocol", sv(node.g("mux_type").unwrap_or("h2mux"))),
                ("max_connections", Some(num(if brutal { 1.0 } else { tonum(node.g("mux_concurrency")).unwrap_or(4.0) }))),
                ("padding", bv(node.is("mux_padding", "1"))),
                (
                    "brutal",
                    mv(obj(vec![
                        ("enabled", bv(brutal)),
                        ("up_mbps", Some(num(tonum(node.g("tcpbrutal_up_mbps")).unwrap_or(10.0)))),
                        ("down_mbps", Some(num(tonum(node.g("tcpbrutal_down_mbps")).unwrap_or(50.0)))),
                    ])),
                ),
            ]))
        } else {
            None
        };

        // v2ray transport
        let ua_headers = || node.g("user_agent").map(|ua| Value::Object(obj(vec![("User-Agent", sv(ua))])));
        let transport_kind = node.g("transport").unwrap_or("");
        let mut transport: Option<Value> = None;
        if transport_kind == "tcp" && node.is("tcp_guise", "http") && node.has("tcp_guise_http_host") && node.g("tcp_guise_http_host") != Some("") {
            let path = match node.0.get("tcp_guise_http_path") {
                Some(NV::L(l)) => l.first().filter(|f| !f.is_empty()).cloned().unwrap_or_else(|| "/".into()),
                Some(NV::S(s)) if !s.is_empty() => s.clone(),
                _ => "/".into(),
            };
            transport = mv(obj(vec![("type", sv("http")), ("host", node.raw("tcp_guise_http_host")), ("path", sv(&path)), ("headers", ua_headers())]));
        }
        match transport_kind {
            "http" => {
                let hc = node.is("http_h2_health_check", "1");
                transport = mv(obj(vec![
                    ("type", sv("http")),
                    ("host", Some(node.raw("http_host").unwrap_or(Value::Array(vec![])))),
                    ("path", sv(node.g("http_path").unwrap_or("/"))),
                    ("headers", ua_headers()),
                    ("idle_timeout", if hc { sv(&api::format_go_time(node.g("http_h2_read_idle_timeout"), Some("15s"))) } else { None }),
                    ("ping_timeout", if hc { sv(&api::format_go_time(node.g("http_h2_health_check_timeout"), Some("15s"))) } else { None }),
                ]));
            }
            "ws" => {
                let headers = if node.has("ws_host") || node.has("user_agent") {
                    mv(obj(vec![("Host", ov(node.g("ws_host"))), ("User-Agent", ov(node.g("user_agent")))]))
                } else {
                    None
                };
                transport = mv(obj(vec![
                    ("type", sv("ws")),
                    ("path", sv(node.g("ws_path").unwrap_or("/"))),
                    ("headers", headers),
                    ("max_early_data", nv(tonum(node.g("ws_maxEarlyData")))),
                    ("early_data_header_name", ov(node.g("ws_earlyDataHeaderName"))),
                ]));
            }
            "httpupgrade" => {
                transport = mv(obj(vec![
                    ("type", sv("httpupgrade")),
                    ("host", ov(node.g("httpupgrade_host"))),
                    ("path", sv(node.g("httpupgrade_path").unwrap_or("/"))),
                    ("headers", ua_headers()),
                ]));
            }
            "quic" => transport = mv(obj(vec![("type", sv("quic"))])),
            "grpc" => {
                let hc = node.is("grpc_health_check", "1");
                transport = mv(obj(vec![
                    ("type", sv("grpc")),
                    ("service_name", ov(node.g("grpc_serviceName"))),
                    ("idle_timeout", if hc { sv(&api::format_go_time(node.g("grpc_idle_timeout"), Some("15s"))) } else { None }),
                    ("ping_timeout", if hc { sv(&api::format_go_time(node.g("grpc_health_check_timeout"), Some("15s"))) } else { None }),
                    ("permit_without_stream", tv(node.is("grpc_permit_without_stream", "1"))),
                ]));
            }
            _ => {}
        }

        let user_pass = node.has("username") && node.has("password");
        let uot = || if node.is("uot", "1") { mv(obj(vec![("enabled", bv(true)), ("version", Some(num(2.0)))])) } else { None };
        let pt_fields: Option<M> = match protocol.as_str() {
            "socks" => Some(obj(vec![
                ("version", sv("5")),
                ("username", if user_pass { ov(node.g("username")) } else { None }),
                ("password", if user_pass { ov(node.g("password")) } else { None }),
                ("udp_over_tcp", uot()),
            ])),
            "http" => Some(obj(vec![
                ("username", if user_pass { ov(node.g("username")) } else { None }),
                ("password", if user_pass { ov(node.g("password")) } else { None }),
                ("tls", tls_v()),
            ])),
            "shadowsocks" => {
                let pe = node.flag_on("plugin_enabled");
                Some(obj(vec![
                    // legacy (26.4 and older) configs store the cipher in `method`
                    ("method", ov(node.g("ss_method").filter(|m| !m.is_empty()).or(node.g("method")))),
                    ("password", sv(node.g("password").unwrap_or(""))),
                    ("plugin", if pe { ov(node.g("plugin")) } else { None }),
                    ("plugin_opts", if pe { ov(node.g("plugin_opts")) } else { None }),
                    ("udp_over_tcp", uot()),
                    ("multiplex", mux.clone()),
                ]))
            }
            "shadowsocksr" => Some(obj(vec![
                ("method", ov(node.g("ssr_method").filter(|m| !m.is_empty()).or(node.g("method")))),
                ("password", sv(node.g("password").unwrap_or(""))),
                ("obfs", ov(node.g("ssr_obfs"))),
                ("obfs_param", ov(node.g("ssr_obfs_param"))),
                ("protocol", ov(node.g("ssr_protocol"))),
                ("protocol_param", ov(node.g("ssr_protocol_param"))),
            ])),
            "trojan" => Some(obj(vec![("password", ov(node.g("password"))), ("tls", tls_v()), ("multiplex", mux.clone()), ("transport", transport.clone())])),
            "vmess" => Some(obj(vec![
                ("uuid", ov(node.g("uuid"))),
                ("security", ov(node.g("security"))),
                ("alter_id", Some(num(if node.has("alter_id") { tonum(node.g("alter_id")).unwrap_or(0.0) } else { 0.0 }))),
                ("global_padding", bv(node.is("global_padding", "1"))),
                ("authenticated_length", bv(node.is("authenticated_length", "1"))),
                ("tls", tls_v()),
                ("packet_encoding", sv("")),
                ("multiplex", mux.clone()),
                ("transport", transport.clone()),
            ])),
            "vless" => Some(obj(vec![
                ("uuid", ov(node.g("uuid"))),
                ("flow", if node.is("tls", "1") { ov(node.g("flow")) } else { None }),
                ("tls", tls_v()),
                ("packet_encoding", sv("xudp")),
                ("multiplex", mux.clone()),
                ("transport", transport.clone()),
            ])),
            "wireguard" => {
                let reserved = node.g("wireguard_reserved").and_then(|r| {
                    let bytes: Vec<Value> = if r.chars().all(|c| c.is_ascii_digit() || c == ',') {
                        gsplit(r, &[',']).iter().filter_map(|b| b.parse::<f64>().ok()).map(num).collect()
                    } else {
                        api::base64_decode(r).bytes().map(|b| Value::from(b as i64)).collect()
                    };
                    if bytes.is_empty() {
                        None
                    } else {
                        Some(Value::Array(bytes))
                    }
                });
                Some(obj(vec![
                    ("system_interface", bv(node.is("wireguard_system_interface", "1"))),
                    ("interface_name", ov(node.g("wireguard_interface_name"))),
                    ("local_address", node.raw("wireguard_local_address")),
                    ("private_key", ov(node.g("wireguard_secret_key"))),
                    ("peer_public_key", ov(node.g("wireguard_public_key"))),
                    ("pre_shared_key", ov(node.g("wireguard_preSharedKey"))),
                    ("reserved", reserved),
                    ("mtu", nv(tonum(node.g("wireguard_mtu")))),
                ]))
            }
            "hysteria" => {
                let mut server_ports: Vec<String> = vec![];
                if let Some(hop) = node.g("hysteria_hop") {
                    server_ports = hop_ranges(hop);
                    del(&mut result, "server_port");
                }
                let hop_interval = if server_ports.is_empty() {
                    None
                } else {
                    let v = leading_digits(node.g("hysteria_hop_interval").unwrap_or("30"));
                    Some(match v {
                        Some(v) if v >= 5.0 => format!("{}s", num_str(v)),
                        _ => "30s".to_string(),
                    })
                };
                let at = node.g("hysteria_auth_type");
                Some(obj(vec![
                    ("server_ports", if server_ports.is_empty() { None } else { Some(arr(&server_ports)) }),
                    ("hop_interval", ov(hop_interval.as_deref())),
                    ("up_mbps", nv(tonum(node.g("hysteria_up_mbps")))),
                    ("down_mbps", nv(tonum(node.g("hysteria_down_mbps")))),
                    ("obfs", ov(node.g("hysteria_obfs"))),
                    ("auth", if at == Some("base64") { ov(node.g("hysteria_auth_password")) } else { None }),
                    ("auth_str", if at == Some("string") { ov(node.g("hysteria_auth_password")) } else { None }),
                    ("stream_receive_window", nv(tonum(node.g("hysteria_recv_window_conn")))),
                    ("connection_receive_window", nv(tonum(node.g("hysteria_recv_window")))),
                    ("disable_path_mtu_discovery", bv(node.is("hysteria_disable_mtu_discovery", "1"))),
                    ("tls", tls_v()),
                ]))
            }
            "shadowtls" => {
                let v = node.g("shadowtls_version");
                Some(obj(vec![
                    ("version", nv(tonum(v))),
                    ("password", if v == Some("2") || v == Some("3") { ov(node.g("password")) } else { None }),
                    ("tls", tls_v()),
                ]))
            }
            "tuic" => {
                let ta = match node.g("tuic_alpn") {
                    Some(a) if a != "default" => a.to_string(),
                    _ => "h3".to_string(),
                };
                let alpn = gsplit(&ta, &[',']);
                let mut t = tls.clone().unwrap_or_default();
                if !alpn.is_empty() {
                    t.insert("alpn".into(), arr(&alpn));
                }
                Some(obj(vec![
                    ("uuid", ov(node.g("uuid"))),
                    ("password", ov(node.g("password"))),
                    ("congestion_control", sv(node.g("tuic_congestion_control").unwrap_or("cubic"))),
                    ("udp_relay_mode", sv(node.g("tuic_udp_relay_mode").unwrap_or("native"))),
                    ("udp_over_stream", bv(false)),
                    ("zero_rtt_handshake", bv(node.is("tuic_zero_rtt_handshake", "1"))),
                    ("heartbeat", sv(&format!("{}s", num_str(tonum(node.g("tuic_heartbeat")).unwrap_or(3.0))))),
                    ("tls", mv(t)),
                ]))
            }
            "hysteria2" => {
                let realms = node.flag_on("hysteria2_realms");
                let mut server_ports: Vec<String> = vec![];
                if let Some(hop) = node.g("hysteria2_hop") {
                    server_ports = hop_ranges(hop);
                    del(&mut result, "server_port");
                }
                if realms {
                    server_ports.clear();
                }
                let (mut interval, mut interval_max): (Option<String>, Option<String>) = (None, None);
                if !server_ports.is_empty() {
                    interval = Some("30s".into());
                    let t = node.g("hysteria2_hop_interval").unwrap_or("30s");
                    if t.contains('-') {
                        if let Some((a, b)) = t.split_once('-') {
                            let dig = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
                            if dig(a) && dig(b) {
                                let mut min: f64 = a.parse().unwrap_or(0.0);
                                let mut max: f64 = b.parse().unwrap_or(0.0);
                                min = if min >= 5.0 { min } else { 5.0 };
                                max = if max >= min { max } else { min };
                                interval = Some(format!("{}s", num_str(min)));
                                interval_max = Some(format!("{}s", num_str(max)));
                            }
                        }
                    } else {
                        let v = match leading_digits(t) {
                            Some(v) if v >= 5.0 => v,
                            _ => 30.0,
                        };
                        interval = Some(format!("{}s", num_str(v)));
                    }
                }
                let obfs = hy2_obfs(&node);
                let idle_timeout = if self.ver.ge_1_14_0 {
                    Some(match leading_digits(node.g("hysteria2_idle_timeout").unwrap_or("30")) {
                        Some(t) if (4.0..=120.0).contains(&t) => format!("{}s", num_str(t)),
                        _ => "30s".to_string(),
                    })
                } else {
                    None
                };
                let keep_alive = if self.ver.ge_1_14_0 {
                    match leading_digits(node.g("hysteria2_keep_alive_period").unwrap_or("0")) {
                        Some(t) if (2.0..=60.0).contains(&t) => Some(format!("{}s", num_str(t))),
                        _ => None,
                    }
                } else {
                    None
                };
                let mb = |k: &str| tonum(node.g(k)).map(|n| Value::String(format!("{} MB", num_str(n))));
                let realm = if realms {
                    del(&mut result, "server");
                    del(&mut result, "server_port");
                    realm_obj(&node, false)
                } else {
                    None
                };
                Some(obj(vec![
                    ("server_ports", if server_ports.is_empty() { None } else { Some(arr(&server_ports)) }),
                    ("hop_interval", ov(interval.as_deref())),
                    ("hop_interval_max", ov(interval_max.as_deref())),
                    ("up_mbps", nv(tonum(node.g("hysteria2_up_mbps")))),
                    ("down_mbps", nv(tonum(node.g("hysteria2_down_mbps")))),
                    ("obfs", obfs),
                    ("password", ov(node.g("hysteria2_auth_password"))),
                    ("idle_timeout", ov(idle_timeout.as_deref())),
                    ("keep_alive_period", ov(keep_alive.as_deref())),
                    ("stream_receive_window", mb("hysteria2_stream_recv_win")),
                    ("connection_receive_window", mb("hysteria2_conn_recv_win")),
                    // Lua `ge14 and (x == "1") or nil` → true or absent
                    ("disable_path_mtu_discovery", tv(self.ver.ge_1_14_0 && node.is("hysteria2_disable_mtu_discovery", "1"))),
                    ("tls", tls_v()),
                    ("realm", realm),
                ]))
            }
            "anytls" => Some(obj(vec![
                ("password", sv(node.g("password").unwrap_or(""))),
                ("idle_session_check_interval", sv("30s")),
                ("idle_session_timeout", sv("30s")),
                ("min_idle_session", Some(num(5.0))),
                ("disable_reuse", tv(node.is("anytls_disable_reuse", "1"))),
                ("client_metadata", if self.ver.ge_1_13_16 { sv("anytls/0.0.13") } else { None }),
                ("tls", tls_v()),
            ])),
            "ssh" => Some(obj(vec![
                ("user", sv(node.g("username").filter(|u| !u.is_empty()).unwrap_or("root"))),
                ("password", sv(node.g("password").unwrap_or(""))),
                ("private_key", ov(node.g("ssh_priv_key"))),
                ("private_key_passphrase", ov(node.g("ssh_priv_key_pp"))),
                ("host_key", node.raw("ssh_host_key")),
                ("host_key_algorithms", node.raw("ssh_host_key_algo")),
                ("client_version", ov(node.g("ssh_client_version"))),
            ])),
            "naive" => {
                let ic = tonum(node.g("naive_insecure_concurrency")).unwrap_or(0.0);
                let quic = node.is("naive_quic", "1");
                Some(obj(vec![
                    ("username", sv(node.g("username").unwrap_or(""))),
                    ("password", sv(node.g("password").unwrap_or(""))),
                    ("insecure_concurrency", Some(num(if ic > 0.0 { ic } else { 0.0 }))),
                    ("udp_over_tcp", Some(uot().unwrap_or(Value::Bool(false)))),
                    ("extra_headers", ua_headers()),
                    ("quic", bv(quic)),
                    ("quic_congestion_control", if quic { ov(node.g("naive_congestion_control")) } else { None }),
                    ("tls", tls_v()),
                ]))
            }
            "masque" => {
                let mut headers: IndexMap<String, String> = IndexMap::new();
                if let Some(ua) = node.g("user_agent").filter(|u| !u.is_empty()) {
                    headers.insert("user-agent".into(), ua.to_string());
                }
                let text = node.g("masque_headers").unwrap_or("").replace("\\n", "\n");
                for line in gsplit(&text, &['\r', '\n']) {
                    if let Some((k, v)) = parse_header_line(&line) {
                        headers.insert(k, v);
                    }
                }
                let has_auth = headers.contains_key("authorization");
                let hv = if headers.is_empty() {
                    None
                } else {
                    let mut h = M::new();
                    for (k, v) in &headers {
                        h.insert(k.clone(), arr(&[v]));
                    }
                    mv(h)
                };
                Some(obj(vec![
                    ("type", sv("masque-client")),
                    ("username", if has_auth { None } else { ov(node.g("username")) }),
                    ("password", if has_auth { None } else { ov(node.g("password")) }),
                    ("path", ov(node.g("masque_path").filter(|p| !p.is_empty()))),
                    ("headers", hv),
                    ("tls", tls_v()),
                ]))
            }
            "snell" => {
                let v = node.g("snell_version");
                Some(obj(vec![
                    ("version", nv(tonum(v))),
                    ("psk", ov(node.g("snell_psk"))),
                    ("userkey", ov(node.g("password"))),
                    ("reuse", bv(node.is("snell_reuse", "1"))),
                    ("network", ov(node.g("snell_network"))),
                    ("obfs_mode", if v == Some("4") { ov(node.g("snell_obfs_mode")) } else { None }),
                    ("obfs_host", if v == Some("4") { ov(node.g("snell_obfs_host")) } else { None }),
                    ("mode", if v == Some("6") { ov(node.g("snell_mode")) } else { None }),
                ]))
            }
            _ => None,
        };
        if let Some(p) = pt_fields {
            for (k, v) in p {
                result.insert(k, v);
            }
        }
        Some(result)
    }

    /// ECH sub-table of the client TLS block.
    fn ech(&mut self, node: &Node) -> M {
        let mut ech = obj(vec![("enabled", bv(true))]);
        let mut config = node.g("ech_config").map(|s| s.to_string());
        let mut qname = node.g("ech_query_server_name").map(|s| s.to_string());
        if let (Some(c), None) = (&config, &qname) {
            qname = get_ech_domain(c);
            if qname.is_none() && !(has_pem_marker(c, "BEGIN") && has_pem_marker(c, "END")) {
                let compact: String = c.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
                config = Some(format!("-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----", compact));
            }
        }
        if let Some(q) = qname {
            ech.insert("query_server_name".into(), Value::String(q.clone()));
            push_unique(&mut self.ech_domain, &q);
        } else if let Some(c) = config {
            ech.insert("config".into(), pem_lines(&c));
        } else if let Some(sn) = node.g("tls_serverName").filter(|s| !s.is_empty()) {
            push_unique(&mut self.ech_domain, sn);
        }
        ech
    }

    // ------------------------------------------------------------------ gen_config helpers

    /// `get_node_by_id(id)`: `socks` sections become a local socks node; `nodes` as is.
    fn get_node_by_id(&self, id: &str) -> Option<Node> {
        if id.is_empty() || id == "nil" {
            return None;
        }
        let sec = self.cfg.section(id)?;
        match sec.stype.as_str() {
            "socks" => {
                let port = sec.get("port");
                let remarks = format!("socks[{}]", port.clone().unwrap_or_default());
                Some(Node::from_pairs(&[
                    (".name", Some(&sec.name)),
                    ("remarks", Some(&remarks)),
                    ("type", Some("sing-box")),
                    ("protocol", Some("socks")),
                    ("address", Some("127.0.0.1")),
                    ("port", port.as_deref()),
                    ("uot", Some("1")),
                ]))
            }
            "nodes" => Some(Node::from_section(sec)),
            _ => None,
        }
    }

    fn find_outbound(&self, tag: &str) -> Option<usize> {
        self.outbounds.iter().position(|o| tag_of(o) == Some(tag))
    }

    /// `gen_urltest_outbound(_node)` → existing index or a new (not inserted) outbound.
    fn gen_urltest_outbound(&mut self, n: &Node) -> Option<Ut> {
        let ut_tag = format!("urltest-{}", n.name().unwrap_or(""));
        if let Some(i) = self.find_outbound(&ut_tag) {
            return Some(Ut::Existing(i));
        }
        let ut_nodes: Vec<String> = if n.is("node_add_mode", "batch") {
            api::get_batch_nodes(&self.cfg, n.joined("node_group").as_deref(), n.g("node_match_rule"))
        } else {
            n.list("urltest_node")
        };
        let mut valid: Vec<String> = vec![];
        for id in ut_nodes {
            let prefix = format!("ut-{}", id);
            if let Some(t) = self.outbounds.iter().filter_map(|o| tag_of(o)).find(|t| t.starts_with(&prefix)) {
                valid.push(t.to_string());
                continue;
            }
            let mut pt = ProxyTable { fragment: self.sb_fragment, record_fragment: self.sb_record_fragment, ..Default::default() };
            let flag = self.flag.clone();
            if let Some(t) = self.gen_outbound_get_tag(Some(&flag), Some(&id), Some(&prefix), &mut pt) {
                valid.push(t);
            }
        }
        if valid.is_empty() {
            return None;
        }
        let interval = api::format_go_time(n.g("urltest_interval"), None);
        let idle = api::format_go_time(n.g("urltest_idle_timeout"), None);
        let tol = tonum(n.g("urltest_tolerance")).filter(|t| *t > 0.0).unwrap_or(50.0);
        let iec = n.g("urltest_interrupt_exist_connections");
        Some(Ut::New(obj(vec![
            ("type", sv("urltest")),
            ("tag", sv(&ut_tag)),
            ("outbounds", Some(arr(&valid))),
            ("url", sv(n.g("urltest_url").unwrap_or("https://www.gstatic.com/generate_204"))),
            ("interval", sv(if interval != "0s" { &interval } else { "3m" })),
            ("tolerance", Some(num(tol))),
            ("idle_timeout", sv(if idle != "0s" { &idle } else { "30m" })),
            ("interrupt_exist_connections", bv(iec == Some("true") || iec == Some("1"))),
        ])))
    }

    /// `set_outbound_detour(node, outbound, outbounds)` → (default tag, outbound to insert after).
    fn set_outbound_detour(&mut self, node: &Node, outbound: &mut M) -> (Option<String>, Option<M>) {
        let mut default_tag = tag_of(outbound).map(|s| s.to_string());
        let mut last: Option<M> = None;

        if node.is("shadowtls", "1") {
            let v = node.g("shadowtls_version");
            let st = Node::from_pairs(&[
                ("type", Some("sing-box")),
                ("protocol", Some("shadowtls")),
                ("shadowtls_version", v),
                ("password", if v == Some("2") || v == Some("3") { node.g("shadowtls_password") } else { None }),
                ("address", node.g("address")),
                ("port", node.g("port")),
                ("tls", Some("1")),
                ("tls_serverName", node.g("shadowtls_serverName")),
                ("utls", node.g("shadowtls_utls")),
                ("fingerprint", node.g("shadowtls_fingerprint")),
            ]);
            let st_tag = format!("{}_shadowtls", tag_of(outbound).unwrap_or(""));
            if let Some(o) = self.gen_outbound(None, Some(st), Some(&st_tag), None) {
                last = Some(o);
                outbound.insert("detour".into(), Value::String(st_tag));
                del(outbound, "server");
                del(outbound, "server_port");
            }
        }

        if node.is("chain_proxy", "1") && node.has("preproxy_node") && !outbound.contains_key("_flag_proxy_tag") {
            if let Some(pre) = node.g("preproxy_node").and_then(|id| self.get_node_by_id(id)) {
                let (po, exist): (Option<M>, bool) = if pre.is("protocol", "_urltest") {
                    match self.gen_urltest_outbound(&pre) {
                        Some(Ut::Existing(i)) => (Some(self.outbounds[i].clone()), true),
                        Some(Ut::New(m)) => (Some(m), false),
                        None => (None, false),
                    }
                } else {
                    (self.gen_outbound(node.name(), Some(pre), None, None), false)
                };
                if let Some(po) = po {
                    let pt = tag_of(&po).unwrap_or("").to_string();
                    let nt = format!("{} -> {}", pt, tag_of(outbound).unwrap_or(""));
                    outbound.insert("tag".into(), Value::String(nt.clone()));
                    outbound.insert("detour".into(), Value::String(pt));
                    if !exist {
                        last = Some(po);
                    }
                    default_tag = Some(nt);
                }
            }
        }

        if node.is("chain_proxy", "2") && node.has("to_node") {
            let to = node.g("to_node").and_then(|id| self.get_node_by_id(id)).filter(|t| !t.g("protocol").unwrap_or("").starts_with('_'));
            if let Some(mut to) = to {
                let ot = tag_of(outbound).unwrap_or("").to_string();
                let chained = format!(
                    "{} -> {}{}",
                    ot,
                    to.name().unwrap_or(""),
                    to.g("remarks").map(|r| format!(":{}", r)).unwrap_or_default()
                );
                if self.find_outbound(&chained).is_some() {
                    return (Some(chained), last);
                }
                let is_sb = to.is("type", "sing-box");
                let to_outbound = if !is_sb {
                    let tag = to.name().unwrap_or("").to_string();
                    let new_port = self.new_port();
                    self.inbounds.push(Value::Object(obj(vec![
                        ("type", sv("direct")),
                        ("tag", sv(&tag)),
                        ("listen", sv("127.0.0.1")),
                        ("listen_port", Some(Value::from(new_port))),
                        ("override_address", ov(to.g("address"))),
                        ("override_port", nv(tonum(to.g("port")))),
                    ])));
                    self.rules.insert(0, Value::Object(obj(vec![("action", sv("route")), ("inbound", Some(arr(&[&tag]))), ("outbound", sv(&ot))])));
                    if !to.has("tls_serverName") {
                        if let Some(a) = to.g("address").map(|s| s.to_string()) {
                            to.set("tls_serverName", &a);
                        }
                    }
                    to.set("address", "127.0.0.1");
                    to.set("port", &new_port.to_string());
                    let pt = ProxyTable { tag: Some(tag.clone()), ..Default::default() };
                    self.gen_outbound(node.name(), Some(to), Some(&tag), Some(&pt))
                } else {
                    self.gen_outbound(node.name(), Some(to), None, None)
                };
                if let Some(mut t) = to_outbound {
                    let nt = format!("{} -> {}", ot, tag_of(&t).unwrap_or(""));
                    t.insert("tag".into(), Value::String(nt.clone()));
                    if is_sb {
                        t.insert("detour".into(), Value::String(ot));
                    }
                    self.outbounds.push(t);
                    default_tag = Some(nt);
                }
            }
        }

        if node.is("chain_proxy", "3") {
            if let Some(iface) = node.g("outbound_iface") {
                del(outbound, "detour");
                outbound.insert("bind_interface".into(), Value::String(iface.to_string()));
            }
        }
        (default_tag, last)
    }

    /// `gen_outbound_get_tag(flag, node_id, tag, proxy_table)` → outbound tag to route to.
    fn gen_outbound_get_tag(&mut self, flag: Option<&str>, node_id: Option<&str>, tag: Option<&str>, pt: &mut ProxyTable) -> Option<String> {
        let id = node_id.filter(|s| *s != "nil")?;
        let mut node = self.get_node_by_id(id)?;
        let tag: String = tag.map(|s| s.to_string()).or_else(|| node.name().map(|s| s.to_string())).unwrap_or_default();
        if let Some(cp) = pt.chain_proxy.clone().filter(|c| c == "1" || c == "2") {
            node.set("chain_proxy", &cp);
            match (cp == "1").then(|| pt.preproxy_node.clone()).flatten() {
                Some(v) => node.set("preproxy_node", &v),
                None => node.del("preproxy_node"),
            }
            match (cp == "2").then(|| pt.to_node.clone()).flatten() {
                Some(v) => node.set("to_node", &v),
                None => node.del("to_node"),
            }
            pt.chain_proxy = None;
            pt.preproxy_node = None;
            pt.to_node = None;
        }
        let mut existing: Option<usize> = None;
        let mut outbound: Option<M> = None;
        match node.g("protocol") {
            Some("_urltest") => match self.gen_urltest_outbound(&node) {
                Some(Ut::Existing(i)) => {
                    if !node.has("chain_proxy") {
                        return tag_of(&self.outbounds[i]).map(|s| s.to_string());
                    }
                    existing = Some(i);
                    outbound = Some(self.outbounds[i].clone());
                }
                Some(Ut::New(m)) => outbound = Some(m),
                None => {}
            },
            Some("_iface") => {
                if let Some(iface) = node.g("iface") {
                    outbound = Some(obj(vec![("tag", sv(&tag)), ("type", sv("direct")), ("bind_interface", sv(iface)), ("routing_mark", Some(num(255.0)))]));
                    self.touch_iface(iface);
                }
            }
            _ => {
                if tag == "default" {
                    if let (Some(a), Some(p)) = (self.default_node_address.clone(), self.default_node_port.clone()) {
                        node.set("address", &a);
                        node.set("port", &p);
                    }
                }
                let pat = format!("socks <- {}", node.name().unwrap_or(""));
                if let Some(o) = self.outbounds.iter().find(|o| o.get("_flag_proxy_tag").and_then(|v| v.as_str()).is_some_and(|s| s.contains(&pat))) {
                    let mut c = o.clone();
                    c.insert("tag".into(), Value::String(tag.clone()));
                    outbound = Some(c);
                }
                if outbound.is_none() {
                    outbound = self.gen_outbound(flag, Some(node.clone()), Some(&tag), Some(pt));
                }
            }
        }
        let mut ob = outbound?;
        let (dtag, last) = self.set_outbound_detour(&node, &mut ob);
        match existing {
            Some(i) => self.outbounds[i] = ob,
            None => self.outbounds.push(ob),
        }
        if let Some(l) = last {
            self.outbounds.push(l);
        }
        dtag
    }

    fn add_rule_set(&mut self, t: &M) {
        if let Some(tag) = tag_of(t) {
            if !self.rule_set_table.contains_key(tag) {
                self.rule_set_table.insert(tag.to_string(), t.clone());
            }
        }
    }

    /// `gen_shunt_node(rule_name, _node_id)` inside the `_shunt` branch.
    fn gen_shunt_node(&mut self, shunt: &Node, rule_name: &str, node_id: Option<&str>) -> Option<String> {
        let nid: Option<String> = node_id.map(|s| s.to_string()).or_else(|| shunt.g(rule_name).map(|s| s.to_string()));
        let nid = nid?;
        match nid.as_str() {
            "_direct" => return Some("direct".into()),
            "_blackhole" => return Some("block".into()),
            "_default" if rule_name != "default" => return Some("default".into()),
            _ => {}
        }
        let mut pt = ProxyTable { fragment: self.sb_fragment, record_fragment: self.sb_record_fragment, ..Default::default() };
        let pre = shunt.g(&format!("{}_proxy_tag", rule_name)).filter(|p| *p != nid).map(|s| s.to_string());
        let flag = self.flag.clone();
        match pre {
            Some(pre) => {
                pt.chain_proxy = Some("2".into());
                pt.to_node = Some(nid.clone());
                self.gen_outbound_get_tag(Some(&flag), Some(&pre), Some(rule_name), &mut pt)
            }
            None => self.gen_outbound_get_tag(Some(&flag), Some(&nid), Some(rule_name), &mut pt),
        }
    }
}

/// Port hopping list: `-` → `:`, comma separated, keep `^\d+:\d+$`.
fn hop_ranges(hop: &str) -> Vec<String> {
    let h = hop.replace('-', ":");
    gsplit(&h, &[','])
        .into_iter()
        .filter(|r| match r.split_once(':') {
            Some((a, b)) => !a.is_empty() && !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()),
            None => false,
        })
        .collect()
}

/// hysteria2 `obfs` (client & server, incl. gecko packet size clamp).
fn hy2_obfs(node: &Node) -> Option<Value> {
    let t = node.g("hysteria2_obfs_type").filter(|t| !t.is_empty())?;
    let mut o = obj(vec![("type", sv(t)), ("password", ov(node.g("hysteria2_obfs_password")))]);
    if t == "gecko" {
        let mut min = tonum(node.g("hysteria2_obfs_MinPacketSize")).unwrap_or(512.0);
        let mut max = tonum(node.g("hysteria2_obfs_MaxPacketSize")).unwrap_or(1200.0);
        if min <= 0.0 || min > max || max > 2048.0 {
            min = 512.0;
            max = 1200.0;
        }
        o.insert("min_packet_size".into(), num(min));
        o.insert("max_packet_size".into(), num(max));
    }
    mv(o)
}

/// hysteria2 `realm` table (client; `server` adds `stun_domain_resolver`).
fn realm_obj(node: &Node, server: bool) -> Option<Value> {
    let r = api::parse_realm_uri(node.g("hysteria2_realm_url")?)?;
    let server_url = format!("{}{}", if r.scheme == "realm+http" { "http://" } else { "https://" }, r.server_url);
    let stun = match &r.stun_servers {
        Some(s) => Some(arr(s)),
        None => node.raw("hysteria2_realm_stun"),
    };
    mv(obj(vec![
        ("token", sv(&r.token)),
        ("server_url", sv(&server_url)),
        ("realm_id", sv(&r.realm_id)),
        ("stun_servers", stun),
        ("stun_domain_resolver", if server { sv("direct") } else { None }),
        ("port_mapping", if node.is("hysteria2_realm_upnp", "1") { mv(obj(vec![("enabled", bv(true))])) } else { None }),
    ]))
}

/// masque header line `^\s*([^:]+):\s*(.-)\s*$` → (lowercased trimmed key, trimmed value).
fn parse_header_line(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    if k.is_empty() {
        return None;
    }
    let key = api::trim(k).to_lowercase();
    let val = v.trim_matches(|c: char| c.is_ascii_whitespace()).to_string();
    Some((key, val))
}

/// Lua strategy mapping UseIPv4/UseIPv6 → ipv4_only/ipv6_only, else prefer_ipv6.
fn strategy(s: Option<&str>) -> &'static str {
    match s {
        Some("UseIPv4") => "ipv4_only",
        Some("UseIPv6") => "ipv6_only",
        _ => "prefer_ipv6",
    }
}

/// `domain_table` collected for DNS rules (one per shunt rule with domains).
#[derive(Clone, Debug, Default)]
struct DnsDomainRule {
    shunt_tag: Option<String>,
    outbound_tag: String,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<String>,
    rule_set: Vec<String>,
    fakedns: bool,
    invert: bool,
}

fn opt_list(v: &[String]) -> Option<Value> {
    if v.is_empty() {
        None
    } else {
        Some(arr(v))
    }
}

/// Domains of all `*address` options in passwall2 ending with a letter (sorted, unique,
/// lowercased) — `uci show passwall2 | grep ".address=" | cut -d "'" -f 2 | grep "[a-zA-Z]$" | sort -u`.
fn nodes_domains(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for s in &cfg.sections {
        for (k, val) in &s.options {
            if !k.ends_with("address") {
                continue;
            }
            let first = match val {
                uci::Value::Single(x) => x.clone(),
                uci::Value::List(l) => l.first().cloned().unwrap_or_default(),
            };
            // `cut -d "'" -f 2` stops at an embedded quote
            let first = first.split('\'').next().unwrap_or("").to_string();
            if first.chars().last().is_some_and(|c| c.is_ascii_alphabetic()) {
                v.push(first);
            }
        }
    }
    v.sort();
    v.dedup();
    v.into_iter().map(|s| s.to_lowercase()).collect()
}

/// DNS hosts text → (host, ip) pairs: first two whitespace fields, shell comments dropped.
fn parse_hosts_line(line: &str) -> Option<(String, String)> {
    let mut it = line.split_whitespace().take_while(|w| !w.starts_with('#'));
    let h = it.next()?;
    let k = it.next()?;
    Some((h.to_string(), k.to_string()))
}

// ====================================================================== gen_config

/// Result of [`generate`]: the config plus the geo categories it references.
pub struct Generated {
    pub config: Value,
    pub geo: GeoTags,
    pub no_run: bool,
}

/// `gen_config(var)` client config. Geo `.srs` conversion is done here too (after generation,
/// unless `no_run`), so the caller only writes the file and starts sing-box.
pub fn gen_config(var: &Args) -> Option<Value> {
    let g = generate(var)?;
    if !g.geo.is_empty() && !g.no_run {
        convert_geofile(&g.geo);
    }
    Some(g.config)
}

/// Generate a client config without running the geo conversion.
pub fn generate(var: &Args) -> Option<Generated> {
    let mut g = Gen::new(Config::load(util::CONFIG), Versions::detect());
    Some(g.gen_config(var))
}

impl Gen {
    fn gen_config(&mut self, var: &Args) -> Generated {
        let mut flag = var.s("flag");
        self.flag = flag.clone();
        let log = var.g("log").unwrap_or("0");
        let loglevel = var.g("loglevel").unwrap_or("warn");
        let logfile = var.g("logfile").unwrap_or("/dev/null");
        let node_id = var.g("node");
        let server_host = var.g("server_host");
        let server_port = var.g("server_port");
        let tcp_proxy_way = var.g("tcp_proxy_way");
        let redir_port = var.g("redir_port");
        let local_socks_address = var.g("local_socks_address").unwrap_or("0.0.0.0");
        let local_socks_port = var.g("local_socks_port");
        let local_http_address = var.g("local_http_address").unwrap_or("0.0.0.0");
        let local_http_port = var.g("local_http_port");
        let dns_listen_port = var.g("dns_listen_port");
        let direct_dns_udp_server = var.g("direct_dns_udp_server");
        let direct_dns_tcp_server = var.g("direct_dns_tcp_server");
        let direct_ipset = var.g("direct_ipset");
        let direct_nftset = var.g("direct_nftset");
        let remote_dns_detour = var.g("remote_dns_detour");
        let mut remote_dns_fake = var.contains_key("remote_dns_fake");
        let remote_rewrite_ttl = var.g("remote_rewrite_ttl").unwrap_or("30");
        let dns_cache = var.g("dns_cache");
        self.no_run = var.contains_key("no_run");

        let mut dns_domain_rules: Vec<DnsDomainRule> = vec![];
        let mut default_outbound_tag: Option<String> = None;
        let cache_text_file = format!("{}/cache_{}.txt", CACHE_PATH, flag);
        let mut route_rules: Vec<Value> = vec![];
        let mut experimental: Option<M> = None;
        let mut inner_fakedns: Option<String> = None;
        let mut remote_server_domain_resolver: Option<&str> = None;
        let mut dns_final: Option<M> = None;

        let node: Option<Node> = node_id.and_then(|id| self.cfg.section(id)).map(Node::from_section);

        let sniff = |tag: &str| Value::Object(obj(vec![("action", sv("sniff")), ("inbound", sv(tag))]));
        let users = |u: Option<&str>, p: Option<&str>| match (u, p) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some(Value::Array(vec![Value::Object(obj(vec![("username", sv(u)), ("password", sv(p))]))])),
            _ => None,
        };

        if let Some(p) = local_socks_port {
            self.inbounds.push(Value::Object(obj(vec![
                ("type", sv("socks")),
                ("tag", sv("socks-in")),
                ("listen", sv(local_socks_address)),
                ("listen_port", nv(tonum(Some(p)))),
                ("users", users(var.g("local_socks_username"), var.g("local_socks_password"))),
            ])));
            route_rules.push(sniff("socks-in"));
        }
        if let Some(p) = local_http_port {
            self.inbounds.push(Value::Object(obj(vec![
                ("type", sv("http")),
                ("tag", sv("http-in")),
                ("listen", sv(local_http_address)),
                ("listen_port", nv(tonum(Some(p)))),
                ("users", users(var.g("local_http_username"), var.g("local_http_password"))),
            ])));
        }
        if let Some(p) = redir_port {
            let mut tproxy = obj(vec![("type", sv("tproxy")), ("tag", sv("tproxy")), ("listen", sv("::")), ("listen_port", nv(tonum(Some(p))))]);
            if tcp_proxy_way != Some("tproxy") {
                self.inbounds.push(Value::Object(obj(vec![
                    ("type", sv("redirect")),
                    ("tag", sv("redirect_tcp")),
                    ("listen", sv("::")),
                    ("listen_port", nv(tonum(Some(p)))),
                ])));
                route_rules.push(sniff("redirect_tcp"));
                tproxy.insert("tag".into(), Value::String("tproxy_udp".into()));
                tproxy.insert("network".into(), Value::String("udp".into()));
            }
            let t = tag_of(&tproxy).unwrap_or("").to_string();
            self.inbounds.push(Value::Object(tproxy));
            route_rules.push(sniff(&t));
        }

        if let Some(mut node) = node {
            if !node.is("protocol", "_shunt") {
                let mut tmp = Node::from_pairs(&[
                    ("remarks", node.g("remarks")),
                    ("type", Some("sing-box")),
                    ("protocol", Some("_shunt")),
                    ("default_node", node.name()),
                ]);
                if let Some(f) = var.g("remote_dns_fake") {
                    tmp.set("fakedns", f);
                    tmp.set("default_fakedns", f);
                }
                node = tmp;
            }
            if let (Some(h), Some(p)) = (server_host, server_port) {
                self.default_node_address = Some(h.to_string());
                self.default_node_port = Some(p.to_string());
            }
            self.rules.clear();

            if node.is("protocol", "_shunt") {
                let inner = node.g("fakedns").unwrap_or("0").to_string();
                inner_fakedns = Some(inner.clone());
                let default_node_id = node.g("default_node").unwrap_or("_direct").to_string();
                default_outbound_tag = self.gen_shunt_node(&node, "default", Some(&default_node_id));
                if inner == "1" && node.is("default_fakedns", "1") {
                    remote_dns_fake = true;
                }

                let shunt_rules: Vec<Node> = self.cfg.sections_of("shunt_rules").map(Node::from_section).collect();
                for e in shunt_rules {
                    if node.g("shunt_group") != e.g("group") {
                        continue;
                    }
                    let ename = e.name().unwrap_or("").to_string();
                    let Some(mut out) = self.gen_shunt_node(&node, &ename, None) else { continue };
                    if !e.has("remarks") {
                        continue;
                    }
                    if out == "default" {
                        match &default_outbound_tag {
                            Some(d) => out = d.clone(),
                            None => {
                                // Lua: outboundTag becomes nil → rule without outbound
                                out = String::new();
                            }
                        }
                    }
                    let out_opt: Option<&str> = if out.is_empty() { None } else { Some(&out) };
                    let protocols = e.joined("protocol").filter(|p| !p.is_empty()).map(|p| arr(&gsplit(&p, &[' '])));
                    let inbound_tag = e.joined("inbound").filter(|i| !i.is_empty()).map(|i| {
                        let mut t: Vec<String> = vec![];
                        if i.contains("tproxy") && redir_port.is_some() {
                            if tcp_proxy_way == Some("tproxy") {
                                t.push("tproxy".into());
                            } else {
                                t.push("redirect_tcp".into());
                                t.push("tproxy_udp".into());
                            }
                        }
                        if i.contains("socks") && local_socks_port.is_some() {
                            t.push("socks-in".into());
                        }
                        arr(&t)
                    });
                    let mut rule = obj(vec![("action", sv("route")), ("inbound", inbound_tag), ("outbound", ov(out_opt)), ("protocol", protocols)]);
                    if out_opt == Some("block") {
                        rule.insert("action".into(), Value::String("reject".into()));
                        del(&mut rule, "outbound");
                    }
                    if let Some(n) = e.g("network") {
                        rule.insert("network".into(), arr(&gsplit(n, &[','])));
                    }
                    if let Some(src) = e.joined("source") {
                        let mut cidr: Vec<String> = vec![];
                        let mut private = false;
                        for w in gsplit(&src, &[' ']) {
                            if let Some(g) = w.strip_prefix("geoip:") {
                                if g == "private" {
                                    private = true;
                                }
                            } else {
                                cidr.push(w);
                            }
                        }
                        set(&mut rule, "source_ip_cidr", opt_list(&cidr));
                        set(&mut rule, "source_ip_is_private", tv(private));
                    }
                    if let Some(p) = e.g("port") {
                        let mut port: Vec<Value> = vec![];
                        let mut range: Vec<String> = vec![];
                        for w in gsplit(p, &[',']) {
                            match api::lua_tonumber(&w) {
                                Some(n) if (1.0..=65535.0).contains(&n) => port.push(num(n)),
                                // upstream quirk: upstream passes "1000-2000" (the Xray syntax the
                                // shared shunt rule form suggests) through, which sing-box rejects
                                // ("bad port range"); sing-box needs "1000:2000".
                                _ => range.push(w.replace('-', ":")),
                            }
                        }
                        if !port.is_empty() {
                            rule.insert("port".into(), Value::Array(port));
                        }
                        set(&mut rule, "port_range", opt_list(&range));
                    }
                    let mut rule_set: Vec<String> = vec![];
                    if let Some(dl) = e.g("domain_list") {
                        let mut dt = DnsDomainRule { shunt_tag: Some(ename.clone()), outbound_tag: out.clone(), invert: e.is("invert", "1"), ..Default::default() };
                        for w in gsplit(dl, &['\r', '\n']) {
                            if w.starts_with('#') {
                                continue;
                            }
                            if let Some(gs) = w.strip_prefix("geosite:") {
                                if let Some(t) = geo_rule_set("geosite", gs) {
                                    push_unique(&mut self.geo.site, gs);
                                    self.add_rule_set(&t);
                                    let tg = tag_of(&t).unwrap_or("").to_string();
                                    rule_set.push(tg.clone());
                                    dt.rule_set.push(tg);
                                }
                            } else if let Some(x) = w.strip_prefix("regexp:") {
                                dt.domain_regex.push(x.into());
                            } else if let Some(x) = w.strip_prefix("full:") {
                                dt.domain.push(x.into());
                            } else if let Some(x) = w.strip_prefix("domain:") {
                                dt.domain_suffix.push(x.into());
                            } else if w.starts_with("rule-set:") || w.starts_with("rs:") {
                                let spec = &w[w.find(':').map(|i| i + 1).unwrap_or(0)..];
                                if let Some(t) = parse_rule_set(spec, true) {
                                    self.add_rule_set(&t);
                                    let tg = tag_of(&t).unwrap_or("").to_string();
                                    rule_set.push(tg.clone());
                                    dt.rule_set.push(tg);
                                }
                            } else {
                                dt.domain_keyword.push(w);
                            }
                        }
                        set(&mut rule, "domain", opt_list(&dt.domain));
                        set(&mut rule, "domain_suffix", opt_list(&dt.domain_suffix));
                        set(&mut rule, "domain_keyword", opt_list(&dt.domain_keyword));
                        set(&mut rule, "domain_regex", opt_list(&dt.domain_regex));
                        set(&mut rule, "rule_set", opt_list(&dt.rule_set));
                        if inner == "1" && node.is(&format!("{}_fakedns", ename), "1") {
                            dt.fakedns = true;
                        }
                        let any = !(dt.domain.is_empty() && dt.domain_suffix.is_empty() && dt.domain_keyword.is_empty() && dt.domain_regex.is_empty() && dt.rule_set.is_empty());
                        if out_opt.is_some() && any {
                            dns_domain_rules.push(dt);
                        }
                    }
                    if let Some(il) = e.g("ip_list") {
                        let mut cidr: Vec<String> = vec![];
                        let mut private = false;
                        for w in gsplit(il, &['\r', '\n']) {
                            if w.starts_with('#') {
                                continue;
                            }
                            if let Some(gi) = w.strip_prefix("geoip:") {
                                if gi == "private" {
                                    private = true;
                                } else if let Some(t) = geo_rule_set("geoip", gi) {
                                    push_unique(&mut self.geo.ip, gi);
                                    self.add_rule_set(&t);
                                    rule_set.push(tag_of(&t).unwrap_or("").to_string());
                                }
                            } else if w.starts_with("rule-set:") || w.starts_with("rs:") {
                                let spec = &w[w.find(':').map(|i| i + 1).unwrap_or(0)..];
                                if let Some(t) = parse_rule_set(spec, true) {
                                    self.add_rule_set(&t);
                                    rule_set.push(tag_of(&t).unwrap_or("").to_string());
                                }
                            } else {
                                cidr.push(w);
                            }
                        }
                        set(&mut rule, "ip_is_private", tv(private));
                        set(&mut rule, "ip_cidr", opt_list(&cidr));
                    }
                    match opt_list(&rule_set) {
                        Some(v) => {
                            rule.insert("rule_set".into(), v);
                        }
                        None => del(&mut rule, "rule_set"),
                    }
                    set(&mut rule, "invert", tv(e.is("invert", "1")));
                    self.rules.push(Value::Object(rule));
                }
            }
            route_rules.append(&mut self.rules);
        }

        let mut route = M::new();
        if let Some(d) = &default_outbound_tag {
            route.insert("final".into(), Value::String(d.clone()));
        }

        let mut dns_servers: Vec<Value> = vec![];
        let mut dns_rules: Vec<Value> = vec![];
        dns_servers.push(Value::Object(obj(vec![("type", sv("local")), ("tag", sv("local"))])));
        route.insert("default_domain_resolver".into(), Value::Object(obj(vec![("server", sv("local"))])));

        let direct_dns = direct_dns_udp_server.is_some() || direct_dns_tcp_server.is_some();
        if let Some(s) = direct_dns_udp_server {
            dns_servers.push(Value::Object(obj(vec![
                ("tag", sv("direct")),
                ("type", sv("udp")),
                ("server", sv(s)),
                ("server_port", Some(num(tonum(var.g("direct_dns_udp_port")).unwrap_or(53.0)))),
                ("detour", sv("direct")),
            ])));
        } else if let Some(s) = direct_dns_tcp_server {
            dns_servers.push(Value::Object(obj(vec![
                ("tag", sv("direct")),
                ("type", sv("tcp")),
                ("server", sv(s)),
                ("server_port", Some(num(tonum(var.g("direct_dns_tcp_port")).unwrap_or(53.0)))),
                ("detour", sv("direct")),
            ])));
        }
        for (_, (server, domain)) in self.dns_server.iter_mut() {
            if direct_dns {
                server.insert("domain_resolver".into(), Value::String("direct".into()));
            }
            dns_servers.push(Value::Object(server.clone()));
            dns_rules.push(Value::Object(obj(vec![("action", sv("route")), ("server", Some(server["tag"].clone())), ("domain", sv(domain))])));
        }
        let direct_strategy = strategy(var.g("direct_dns_query_strategy"));

        if let Some(dlp) = dns_listen_port {
            let dns_host: String = if flag == "global" {
                self.cfg.s("@global[0]", "dns_hosts")
            } else {
                flag = flag.replace("acl_", "");
                match self.cfg.get(&flag, "dns_hosts_mode").as_deref().unwrap_or("default") {
                    "default" => self.cfg.s("@global[0]", "dns_hosts"),
                    "custom" => self.cfg.s(&flag, "dns_hosts"),
                    _ => String::new(),
                }
            };
            if !dns_host.is_empty() {
                let mut domains: Vec<String> = vec![];
                let mut predefined = M::new();
                for w in gsplit(&dns_host, &['\r', '\n']) {
                    if let Some((h, k)) = parse_hosts_line(&w) {
                        predefined.insert(h.clone(), Value::String(k));
                        domains.push(h);
                    }
                }
                let doh_host = var.g("remote_dns_doh_host");
                if let (Some(ip), Some(h)) = (var.g("remote_dns_doh_ip"), doh_host) {
                    if h != ip && !api::is_ip(h) {
                        predefined.insert(h.to_string(), Value::String(ip.to_string()));
                        domains.push(h.to_string());
                        remote_server_domain_resolver = Some("hosts");
                    }
                }
                if !predefined.is_empty() {
                    dns_servers.push(Value::Object(obj(vec![("tag", sv("hosts")), ("type", sv("hosts")), ("predefined", mv(predefined))])));
                    dns_rules.push(Value::Object(obj(vec![("query_type", Some(arr(&["A", "AAAA"]))), ("domain", Some(arr(&domains))), ("server", sv("hosts"))])));
                }
            }

            if direct_dns {
                let nd = nodes_domains(&self.cfg);
                if !nd.is_empty() {
                    dns_domain_rules.insert(0, DnsDomainRule { outbound_tag: "direct".into(), domain: nd, ..Default::default() });
                }
            }

            let remote_strategy = strategy(var.g("remote_dns_query_strategy"));
            let mut remote = obj(vec![
                ("tag", sv("remote")),
                ("domain_resolver", sv(remote_server_domain_resolver.unwrap_or("direct"))),
                ("detour", ov(default_outbound_tag.as_deref())),
            ]);
            if remote_dns_detour == Some("direct") {
                remote.insert("detour".into(), Value::String("direct".into()));
            }
            if let Some(s) = var.g("remote_dns_udp_server") {
                remote.insert("type".into(), Value::String("udp".into()));
                remote.insert("server".into(), Value::String(s.into()));
                remote.insert("server_port".into(), num(tonum(var.g("remote_dns_udp_port")).unwrap_or(53.0)));
                if var.contains_key("remote_dns_quic") {
                    remote.insert("type".into(), Value::String("quic".into()));
                    remote.insert("server_port".into(), num(853.0));
                }
            } else if let Some(s) = var.g("remote_dns_tcp_server") {
                remote.insert("type".into(), Value::String("tcp".into()));
                remote.insert("server".into(), Value::String(s.into()));
                remote.insert("server_port".into(), num(tonum(var.g("remote_dns_tcp_port")).unwrap_or(53.0)));
                if var.contains_key("remote_dns_tls") {
                    remote.insert("type".into(), Value::String("tls".into()));
                    remote.insert("server_port".into(), num(853.0));
                }
            } else if let Some(u) = var.g("remote_dns_doh_url").and_then(api::parse_url) {
                remote.insert("type".into(), Value::String(if var.contains_key("remote_dns_http3") { "h3" } else { "https" }.into()));
                remote.insert("server".into(), Value::String(u.hostname.clone()));
                remote.insert("server_port".into(), num(u.port.map(|p| p as f64).unwrap_or(443.0)));
                set(&mut remote, "path", ov(u.pathname.as_deref()));
            }
            dns_servers.push(Value::Object(remote.clone()));

            let fakedns_tag = "remote_fakeip";
            if remote_dns_fake || inner_fakedns.as_deref() == Some("1") {
                dns_servers.push(Value::Object(obj(vec![
                    ("tag", sv(fakedns_tag)),
                    ("type", sv("fakeip")),
                    ("inet4_range", sv("198.18.0.0/16")),
                    ("inet6_range", sv("2001:2::/48")),
                ])));
                let ex = experimental.get_or_insert_with(M::new);
                ex.insert(
                    "cache_file".into(),
                    Value::Object(obj(vec![("enabled", bv(true)), ("store_fakeip", bv(true)), ("path", sv(&format!("{}/singbox_{}.db", CACHE_PATH, flag)))])),
                );
            }

            let mut default_dns_flag = "remote";
            if let (Some(id), Some(_)) = (node_id, redir_port) {
                if let Some(n) = self.get_node_by_id(id) {
                    if n.is("protocol", "_shunt") && n.is("default_node", "_direct") {
                        default_dns_flag = "direct";
                    }
                }
            } else {
                default_dns_flag = "direct";
            }
            let mut dns_final_strategy = M::new();
            dns_final_strategy.insert("final".into(), Value::String(default_dns_flag.into()));
            dns_final_strategy.insert("strategy".into(), Value::String("prefer_ipv6".into()));

            let rewrite_ttl = tonum(Some(remote_rewrite_ttl));
            for v in &dns_domain_rules {
                let any = !(v.domain.is_empty() && v.domain_suffix.is_empty() && v.domain_keyword.is_empty() && v.domain_regex.is_empty() && v.rule_set.is_empty());
                if v.outbound_tag.is_empty() || !any {
                    continue;
                }
                let mut r = obj(vec![
                    ("action", sv("route")),
                    ("server", sv(&v.outbound_tag)),
                    ("domain", opt_list(&v.domain)),
                    ("domain_suffix", opt_list(&v.domain_suffix)),
                    ("domain_keyword", opt_list(&v.domain_keyword)),
                    ("domain_regex", opt_list(&v.domain_regex)),
                    ("rule_set", opt_list(&v.rule_set)),
                    ("disable_cache", bv(false)),
                    ("invert", tv(v.invert)),
                ]);
                let predefined = |mut b: M, qt: &[&str], drop_ttl: bool| -> Value {
                    b.insert("query_type".into(), arr(qt));
                    b.insert("action".into(), Value::String("predefined".into()));
                    b.insert("rcode".into(), Value::String("NOERROR".into()));
                    del(&mut b, "disable_cache");
                    del(&mut b, "server");
                    if drop_ttl {
                        del(&mut b, "rewrite_ttl");
                    }
                    Value::Object(b)
                };
                if v.outbound_tag == "block" {
                    r.insert("action".into(), Value::String("predefined".into()));
                    r.insert("rcode".into(), Value::String("NOERROR".into()));
                    del(&mut r, "disable_cache");
                    del(&mut r, "server");
                }
                if v.outbound_tag == "direct" {
                    match direct_strategy {
                        "ipv4_only" => dns_rules.push(predefined(r.clone(), &["AAAA"], false)),
                        "ipv6_only" => dns_rules.push(predefined(r.clone(), &["A"], false)),
                        _ => {}
                    }
                }
                if v.outbound_tag != "block" && v.outbound_tag != "direct" {
                    r.insert("server".into(), Value::String("remote".into()));
                    match rewrite_ttl {
                        Some(t) => {
                            r.insert("rewrite_ttl".into(), num(t));
                        }
                        None => del(&mut r, "rewrite_ttl"),
                    }
                    match remote_strategy {
                        "ipv4_only" => dns_rules.push(predefined(r.clone(), &["AAAA"], true)),
                        "ipv6_only" => dns_rules.push(predefined(r.clone(), &["A"], true)),
                        _ => {}
                    }
                    set(&mut r, "client_subnet", ov(var.g("remote_dns_client_ip")));
                    if Some(v.outbound_tag.as_str()) != default_outbound_tag.as_deref() && remote.contains_key("server") && remote_dns_detour != Some("direct") {
                        let mut s = remote.clone();
                        let st = v.shunt_tag.clone().unwrap_or_default();
                        s.insert("tag".into(), Value::String(st.clone()));
                        s.insert("detour".into(), Value::String(v.outbound_tag.clone()));
                        dns_servers.push(Value::Object(s));
                        r.insert("server".into(), Value::String(st));
                    }
                    if v.fakedns {
                        let mut f = r.clone();
                        let qt: &[&str] = match remote_strategy {
                            "ipv4_only" => &["A"],
                            "ipv6_only" => &["AAAA"],
                            _ => &["A", "AAAA"],
                        };
                        f.insert("query_type".into(), arr(qt));
                        f.insert("server".into(), Value::String(fakedns_tag.into()));
                        f.insert("rewrite_ttl".into(), num(1.0));
                        f.insert("disable_cache".into(), Value::Bool(true));
                        del(&mut f, "client_subnet");
                        dns_rules.push(Value::Object(f));
                    }
                }
                dns_rules.push(Value::Object(r));
            }
            if default_dns_flag == "remote" {
                let mut qt: &[&str] = &["A", "AAAA"];
                match remote_strategy {
                    "ipv4_only" => {
                        dns_rules.push(Value::Object(obj(vec![("query_type", Some(arr(&["AAAA"]))), ("action", sv("predefined")), ("rcode", sv("NOERROR"))])));
                        qt = &["A"];
                    }
                    "ipv6_only" => {
                        dns_rules.push(Value::Object(obj(vec![("query_type", Some(arr(&["A"]))), ("action", sv("predefined")), ("rcode", sv("NOERROR"))])));
                        qt = &["AAAA"];
                    }
                    _ => {}
                }
                if remote_dns_fake {
                    dns_rules.push(Value::Object(obj(vec![
                        ("query_type", Some(arr(qt))),
                        ("server", sv(fakedns_tag)),
                        ("disable_cache", bv(true)),
                        ("rewrite_ttl", Some(num(1.0))),
                    ])));
                }
                dns_rules.push(Value::Object(obj(vec![("server", sv("remote")), ("disable_cache", bv(true)), ("rewrite_ttl", nv(rewrite_ttl))])));
            }
            self.inbounds.push(Value::Object(obj(vec![
                ("type", sv("direct")),
                ("tag", sv("dns-in")),
                ("listen", sv("127.0.0.1")),
                ("listen_port", nv(tonum(Some(dlp)))),
            ])));
            route_rules.insert(0, sniff("dns-in"));
            route_rules.insert(0, Value::Object(obj(vec![("action", sv("hijack-dns")), ("inbound", sv("dns-in"))])));

            // flush direct ipset/nftset when the routing changed
            let content = format!("{}{}{}", flag, node_id.unwrap_or(""), serde_json::to_string(&route_rules).unwrap_or_default());
            if self.fx {
                util::mkdir(CACHE_PATH);
                if !api::cache_file_compare_to_logic(&cache_text_file, &content) {
                    let nid = node_id.unwrap_or("");
                    if let Some(ds) = direct_ipset {
                        for w in gsplit(ds, &[',']) {
                            util::sh(&format!("ipset -q -F {}", util::shq(&w)));
                        }
                        let list = util::sh(&format!("ipset list | grep 'Name: ' | grep {} | awk '{{print $2}}'", util::shq(&format!("psw2_{}_", nid))));
                        for w in gsplit(&list, &['\r', '\n']) {
                            util::sh(&format!("ipset -q -F {}", util::shq(&w)));
                        }
                    }
                    if let Some(dn) = direct_nftset {
                        for w in gsplit(dn, &[',']) {
                            let p = api::split(&w, "#");
                            if p.len() > 3 {
                                util::sh(&format!("nft flush set {} {} {} 2>/dev/null", util::shq(&p[1]), util::shq(&p[2]), util::shq(&p[3])));
                            }
                        }
                        let list = util::sh(&format!(
                            "nft -a list sets | grep -E {} | awk -F 'set ' '{{print $2}}' | awk '{{print $1}}'",
                            util::shq(&format!("psw2_{}_", nid))
                        ));
                        for w in gsplit(&list, &['\r', '\n']) {
                            util::sh(&format!("nft flush set inet passwall2 {} 2>/dev/null", util::shq(&w)));
                        }
                    }
                }
            }
            // dns.final / dns.strategy are only set in DNS mode
            dns_final = Some(dns_final_strategy);
        }

        if !self.ech_domain.is_empty() {
            dns_servers.push(Value::Object(obj(vec![("tag", sv("ech-dns")), ("type", sv("https")), ("server", sv("223.5.5.5"))])));
            dns_rules.insert(0, Value::Object(obj(vec![("domain", Some(arr(&self.ech_domain))), ("server", sv("ech-dns"))])));
        }

        if default_outbound_tag.as_deref() == Some("block") {
            del(&mut route, "final");
            route_rules.push(Value::Object(obj(vec![("action", sv("reject"))])));
        }

        let mut route_out = M::new();
        route_out.insert("rules".into(), Value::Array(route_rules));
        for (k, v) in route {
            route_out.insert(k, v);
        }
        if !self.rule_set_table.is_empty() {
            route_out.insert("rule_set".into(), Value::Array(self.rule_set_table.values().cloned().map(Value::Object).collect()));
        }

        let mut dns = obj(vec![
            ("servers", Some(Value::Array(dns_servers))),
            ("rules", Some(Value::Array(dns_rules))),
            ("disable_cache", bv(dns_cache == Some("0"))),
            ("disable_expire", bv(false)),
            ("independent_cache", bv(false)),
            ("reverse_mapping", bv(true)),
        ]);
        if let Some(f) = dns_final {
            for (k, v) in f {
                dns.insert(k, v);
            }
        }

        // outbounds post-processing
        self.outbounds.push(obj(vec![("type", sv("direct")), ("tag", sv("direct")), ("routing_mark", Some(num(255.0)))]));
        let mut outbounds = std::mem::take(&mut self.outbounds);
        for o in outbounds.iter_mut() {
            let has = |o: &M, k: &str| o.get(k).is_some_and(|v| !v.is_null());
            if !has(o, "_flag_proxy_tag") && !has(o, "detour") && has(o, "_id") && has(o, "server") && has(o, "server_port") && !self.no_run && self.fx {
                if let Some(id) = o.get("_id").and_then(|v| v.as_str()) {
                    util::append_file(&format!("{}/direct_node_list", util::TMP_PATH), id);
                }
            }
            if !has(o, "detour") && !has(o, "bind_interface") && has(o, "server") {
                o.insert("detour".into(), Value::String("direct".into()));
            }
            if let Some(s) = o.get("server").and_then(|v| v.as_str()) {
                if !api::dt_hostname(s) && !has(o, "realm") {
                    del(o, "domain_resolver");
                }
            }
            o.retain(|k, _| !k.starts_with('_'));
        }
        let mut endpoints: Vec<Value> = vec![];
        let mut i = outbounds.len();
        while i > 0 {
            i -= 1;
            match outbounds[i].get("type").and_then(|v| v.as_str()) {
                Some("wireguard") => {
                    let v = outbounds.remove(i);
                    let g = |k: &str| v.get(k).cloned();
                    let peer = obj(vec![
                        ("address", g("server")),
                        ("port", g("server_port")),
                        ("public_key", g("peer_public_key")),
                        ("pre_shared_key", g("pre_shared_key")),
                        ("allowed_ips", Some(arr(&["0.0.0.0/0"]))),
                        ("reserved", g("reserved")),
                    ]);
                    endpoints.push(Value::Object(obj(vec![
                        ("type", g("type")),
                        ("tag", g("tag")),
                        ("system", g("system_interface")),
                        ("name", g("interface_name")),
                        ("mtu", g("mtu")),
                        ("address", g("local_address")),
                        ("private_key", g("private_key")),
                        ("peers", Some(Value::Array(vec![Value::Object(peer)]))),
                        ("domain_resolver", g("domain_resolver")),
                        ("detour", g("detour")),
                    ])));
                }
                Some("masque-client") => {
                    endpoints.push(Value::Object(outbounds.remove(i)));
                }
                _ => {}
            }
        }

        let mut config = obj(vec![
            (
                "log",
                mv(obj(vec![
                    ("disabled", bv(log == "0")),
                    ("level", ov(get_log_level(Some(loglevel)).as_deref())),
                    ("timestamp", bv(true)),
                    ("output", sv(logfile)),
                ])),
            ),
            ("dns", mv(dns)),
            ("inbounds", Some(Value::Array(std::mem::take(&mut self.inbounds)))),
            ("outbounds", Some(Value::Array(outbounds.into_iter().map(Value::Object).collect()))),
            ("route", mv(route_out)),
            ("experimental", experimental.map(Value::Object)),
        ]);
        if !endpoints.is_empty() {
            config.insert("endpoints".into(), Value::Array(endpoints));
        }
        Generated { config: Value::Object(config), geo: self.geo.clone(), no_run: self.no_run }
    }
}

// ====================================================================== gen_proto_config

/// `gen_proto_config(var)`: socks/http inbounds → one upstream socks/http outbound `out`.
pub fn gen_proto_config(var: &Args) -> Option<Value> {
    let mut inbounds: Vec<Value> = vec![];
    let users = |u: Option<&str>, p: Option<&str>| match (u, p) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some(Value::Array(vec![Value::Object(obj(vec![("username", sv(u)), ("password", sv(p))]))])),
        _ => None,
    };
    if let Some(p) = var.g("local_socks_port") {
        inbounds.push(Value::Object(obj(vec![
            ("type", sv("socks")),
            ("tag", sv("socks-in")),
            ("listen", sv(var.g("local_socks_address").unwrap_or("0.0.0.0"))),
            ("listen_port", nv(tonum(Some(p)))),
            // upstream quirk: upstream emits `users` as a single object here, which sing-box
            // rejects; we emit the array form like every other inbound.
            ("users", users(var.g("local_socks_username"), var.g("local_socks_password"))),
        ])));
    }
    if let Some(p) = var.g("local_http_port") {
        inbounds.push(Value::Object(obj(vec![
            ("type", sv("http")),
            ("tag", sv("http-in")),
            ("listen", sv(var.g("local_http_address").unwrap_or("0.0.0.0"))),
            ("listen_port", nv(tonum(Some(p)))),
            ("users", users(var.g("local_http_username"), var.g("local_http_password"))),
        ])));
    }
    let mut outbounds: Vec<Value> = vec![];
    let (proto, addr, port) = (var.g("server_proto"), var.g("server_address"), var.g("server_port"));
    if proto != Some("nil") && addr != Some("nil") && port != Some("nil") {
        let up = var.contains_key("server_username") && var.contains_key("server_password");
        outbounds.push(Value::Object(obj(vec![
            ("type", ov(proto)),
            ("tag", sv("out")),
            ("server", ov(addr)),
            ("server_port", nv(tonum(port))),
            ("username", if up { ov(var.g("server_username")) } else { None }),
            ("password", if up { ov(var.g("server_password")) } else { None }),
        ])));
    }
    Some(Value::Object(obj(vec![
        ("log", mv(obj(vec![("disabled", bv(true)), ("level", sv("warn")), ("timestamp", bv(true))]))),
        ("inbounds", Some(Value::Array(inbounds))),
        ("outbounds", Some(Value::Array(outbounds))),
    ])))
}

// ====================================================================== gen_config_server

/// Server config for the `passwall2_server` section `user_id` (as server_app.lua passes it).
pub fn gen_config_server(user_id: &str) -> Option<Value> {
    let scfg = Config::load(util::CONFIG_SERVER);
    let sec = scfg.section(user_id)?;
    let node = Node::from_section(sec);
    let mut g = Gen::new(Config::load(util::CONFIG), Versions::detect());
    Some(g.gen_config_server(&node, &scfg))
}

/// Server config from an already loaded `passwall2_server` section.
pub fn gen_config_server_section(sec: &Section) -> Value {
    let scfg = Config::load(util::CONFIG_SERVER);
    let mut g = Gen::new(Config::load(util::CONFIG), Versions::detect());
    g.gen_config_server(&Node::from_section(sec), &scfg)
}

impl Gen {
    fn gen_config_server(&mut self, node_in: &Node, scfg: &Config) -> Value {
        let mut node = node_in.clone();
        let mut endpoints: Vec<Value> = vec![];
        let mut inbounds: Vec<Value> = vec![];
        let mut outbounds: Vec<M> = vec![obj(vec![("type", sv("direct")), ("tag", sv("direct"))])];
        let protocol = node.g("protocol").unwrap_or("").to_string();
        if protocol == "masque" {
            node.set("tls", "1");
            node.del("reality");
        }
        let use_pem = node.is("tls_use_pem", "1");
        let alpn = match node.g("alpn") {
            Some(a) if a != "default" => opt_list(&gsplit(a, &[','])),
            _ => None,
        };
        let mut tls = obj(vec![
            ("enabled", bv(true)),
            ("certificate_path", if !use_pem { ov(node.g("tls_certificateFile")) } else { None }),
            ("key_path", if !use_pem { ov(node.g("tls_keyFile")) } else { None }),
            ("certificate", if use_pem { node.g("tls_certificate").map(pem_lines) } else { None }),
            ("key", if use_pem { node.g("tls_key").map(pem_lines) } else { None }),
            ("alpn", alpn),
        ]);
        if node.is("tls", "1") && node.is("reality", "1") {
            for k in ["certificate_path", "key_path", "certificate", "key"] {
                del(&mut tls, k);
            }
            set(&mut tls, "server_name", ov(node.g("reality_handshake_server")));
            tls.insert(
                "reality".into(),
                Value::Object(obj(vec![
                    ("enabled", bv(true)),
                    ("private_key", ov(node.g("reality_private_key"))),
                    ("short_id", Some(Value::Array(node.g("reality_shortId").map(|s| vec![Value::String(s.into())]).unwrap_or_default()))),
                    (
                        "handshake",
                        mv(obj(vec![("server", ov(node.g("reality_handshake_server"))), ("server_port", nv(tonum(node.g("reality_handshake_server_port"))))])),
                    ),
                ])),
            );
        }
        if node.is("tls", "1") && node.is("ech", "1") {
            tls.insert("ech".into(), Value::Object(obj(vec![("enabled", bv(true)), ("key", node.g("ech_key").map(pem_lines))])));
        }

        let mux = if node.is("mux", "1") {
            mv(obj(vec![
                ("enabled", bv(true)),
                ("padding", bv(node.is("mux_padding", "1"))),
                (
                    "brutal",
                    mv(obj(vec![
                        ("enabled", bv(node.is("tcpbrutal", "1"))),
                        ("up_mbps", Some(num(tonum(node.g("tcpbrutal_up_mbps")).unwrap_or(10.0)))),
                        ("down_mbps", Some(num(tonum(node.g("tcpbrutal_down_mbps")).unwrap_or(50.0)))),
                    ])),
                ),
            ]))
        } else {
            None
        };

        let transport = match node.g("transport").unwrap_or("") {
            "http" => mv(obj(vec![
                ("type", sv("http")),
                ("host", Some(node.raw("http_host").unwrap_or(Value::Array(vec![])))),
                ("path", sv(node.g("http_path").unwrap_or("/"))),
            ])),
            "ws" => mv(obj(vec![
                ("type", sv("ws")),
                ("path", sv(node.g("ws_path").unwrap_or("/"))),
                ("headers", node.g("ws_host").map(|h| Value::Object(obj(vec![("Host", sv(h))])))),
                ("early_data_header_name", ov(node.g("ws_earlyDataHeaderName"))),
            ])),
            "httpupgrade" => mv(obj(vec![
                ("type", sv("httpupgrade")),
                ("host", ov(node.g("httpupgrade_host"))),
                ("path", sv(node.g("httpupgrade_path").unwrap_or("/"))),
            ])),
            "quic" => mv(obj(vec![("type", sv("quic"))])),
            "grpc" => mv(obj(vec![("type", sv("grpc")), ("service_name", ov(node.g("grpc_serviceName")))])),
            _ => None,
        };

        let mut inbound = obj(vec![("type", ov(node.g("protocol"))), ("tag", sv("inbound")), ("listen", sv("::")), ("listen_port", nv(tonum(node.g("port"))))]);

        // users
        let mut users: Option<Value> = None;
        let ids = node.list("users");
        if !ids.is_empty() {
            let mut list: Vec<Value> = vec![];
            for id in ids {
                let Some(us) = scfg.section(&id) else { continue };
                if us.stype != "user" {
                    continue;
                }
                let user = Node::from_section(us);
                let u = |k: &str| ov(user.g(k));
                let o = match protocol.as_str() {
                    "mixed" | "socks" | "http" | "naive" | "masque" => obj(vec![("username", u("username")), ("password", u("password"))]),
                    "shadowsocks" | "trojan" | "hysteria2" | "anytls" => obj(vec![("name", u("username")), ("password", u("password"))]),
                    "vmess" => obj(vec![("name", u("username")), ("uuid", u("uuid")), ("alterId", Some(num(0.0)))]),
                    "vless" => obj(vec![("name", u("username")), ("uuid", u("uuid")), ("flow", ov(node.g("flow")))]),
                    "hysteria" => obj(vec![("name", u("username")), ("auth_str", u("password"))]),
                    "tuic" => obj(vec![("name", u("username")), ("password", u("password")), ("uuid", u("uuid"))]),
                    "wireguard" => obj(vec![
                        ("public_key", u("wireguard_public_key")),
                        ("pre_shared_key", u("wireguard_pre_shared_key")),
                        ("allowed_ips", Some(user.raw("allowed_ips").unwrap_or(Value::Array(vec![])))),
                        ("persistent_keepalive_interval", Some(num(0.0))),
                    ]),
                    "snell" => obj(vec![("name", u("username")), ("userkey", u("password"))]),
                    _ => M::new(),
                };
                list.push(Value::Object(o));
            }
            if !list.is_empty() {
                users = Some(Value::Array(list));
            }
        }
        let tls_on = node.is("tls", "1");
        let tls_if = |t: &M| if tls_on { Some(Value::Object(t.clone())) } else { None };
        let pt: Option<M> = match protocol.as_str() {
            "masque" => {
                del(&mut tls, "alpn");
                Some(obj(vec![
                    ("type", sv("masque-server")),
                    ("users", users.clone()),
                    ("path", ov(node.g("masque_path").filter(|p| !p.is_empty()))),
                    ("address", node.raw("masque_address")),
                    ("mtu", nv(tonum(Some(node.g("masque_mtu").unwrap_or("1280"))))),
                    ("tls", mv(tls.clone())),
                ]))
            }
            "mixed" => Some(obj(vec![("users", users.clone()), ("set_system_proxy", bv(false))])),
            "socks" => Some(obj(vec![("users", users.clone())])),
            "http" => Some(obj(vec![("users", users.clone()), ("tls", tls_if(&tls))])),
            "shadowsocks" => Some(obj(vec![
                // legacy (26.4) server sections: method / password
                ("method", ov(node.g("ss_method").filter(|m| !m.is_empty()).or(node.g("method")))),
                ("password", ov(node.g("ss_password").filter(|m| !m.is_empty()).or(node.g("password")))),
                ("users", users.clone()),
                ("multiplex", mux.clone()),
            ])),
            "vmess" | "vless" | "trojan" if users.is_some() => {
                Some(obj(vec![("users", users.clone()), ("tls", tls_if(&tls)), ("multiplex", mux.clone()), ("transport", transport.clone())]))
            }
            "naive" | "anytls" if users.is_some() => Some(obj(vec![("users", users.clone()), ("tls", mv(tls.clone()))])),
            "hysteria" => {
                let up = node.g("hysteria_up_mbps");
                let down = node.g("hysteria_down_mbps");
                Some(obj(vec![
                    // upstream crashes when up/down are missing; we omit them
                    ("up", up.map(|v| Value::String(format!("{} Mbps", v)))),
                    ("down", down.map(|v| Value::String(format!("{} Mbps", v)))),
                    ("up_mbps", nv(tonum(up))),
                    ("down_mbps", nv(tonum(down))),
                    ("obfs", ov(node.g("hysteria_obfs"))),
                    ("users", users.clone()),
                    ("stream_receive_window", nv(tonum(node.g("hysteria_recv_window_conn")))),
                    ("connection_receive_window", nv(tonum(node.g("hysteria_recv_window_client")))),
                    ("max_concurrent_streams", nv(tonum(node.g("hysteria_max_conn_client")))),
                    ("disable_path_mtu_discovery", bv(node.is("hysteria_disable_mtu_discovery", "1"))),
                    ("tls", mv(tls.clone())),
                ]))
            }
            "tuic" => {
                match node.g("tuic_alpn") {
                    Some(a) if a != "default" => match opt_list(&gsplit(a, &[','])) {
                        Some(v) => {
                            tls.insert("alpn".into(), v);
                        }
                        None => del(&mut tls, "alpn"),
                    },
                    _ => del(&mut tls, "alpn"),
                }
                Some(obj(vec![
                    ("users", users.clone()),
                    ("congestion_control", sv(node.g("tuic_congestion_control").unwrap_or("cubic"))),
                    ("zero_rtt_handshake", bv(node.is("tuic_zero_rtt_handshake", "1"))),
                    ("heartbeat", sv(&format!("{}s", num_str(tonum(node.g("tuic_heartbeat")).unwrap_or(3.0))))),
                    ("tls", mv(tls.clone())),
                ]))
            }
            "hysteria2" => {
                let ignore = node.is("hysteria2_ignore_client_bandwidth", "1");
                Some(obj(vec![
                    ("up_mbps", if ignore { None } else { nv(tonum(node.g("hysteria2_up_mbps"))) }),
                    ("down_mbps", if ignore { None } else { nv(tonum(node.g("hysteria2_down_mbps"))) }),
                    ("obfs", hy2_obfs(&node)),
                    ("users", users.clone()),
                    ("ignore_client_bandwidth", bv(ignore)),
                    ("tls", mv(tls.clone())),
                    ("realm", if node.flag_on("hysteria2_realms") { realm_obj(&node, true) } else { None }),
                ]))
            }
            "snell" => {
                let v = node.g("snell_version");
                Some(obj(vec![
                    ("users", users.clone()),
                    ("version", nv(tonum(v))),
                    ("psk", ov(node.g("snell_psk"))),
                    ("obfs_mode", if v == Some("5") { ov(node.g("snell_obfs_mode")) } else { None }),
                    ("mode", if v == Some("6") { ov(node.g("snell_mode")) } else { None }),
                ]))
            }
            "direct" => Some(obj(vec![
                ("network", if node.g("d_protocol") != Some("TCP,UDP") { ov(node.g("d_protocol")) } else { None }),
                ("override_address", ov(node.g("d_address"))),
                ("override_port", nv(tonum(node.g("d_port")))),
            ])),
            _ => None,
        };
        if protocol == "wireguard" {
            del(&mut inbound, "listen");
            inbound.insert("system".into(), Value::Bool(node.is("wireguard_system_interface", "1")));
            inbound.insert("name".into(), Value::String(format!("sbwg_{}", node.name().unwrap_or(""))));
            set(&mut inbound, "mtu", nv(tonum(Some(node.g("wireguard_mtu").unwrap_or("1408")))));
            set(&mut inbound, "address", node.raw("wireguard_local_address"));
            set(&mut inbound, "private_key", ov(node.g("wireguard_private_key")));
            set(&mut inbound, "peers", users.clone());
        }
        if let Some(p) = pt {
            for (k, v) in p {
                inbound.insert(k, v);
            }
        }
        if protocol == "wireguard" || protocol == "masque" {
            endpoints.push(Value::Object(inbound));
        } else {
            inbounds.push(Value::Object(inbound));
        }

        let accept_lan = node.is("accept_lan", "1");
        let mut route = obj(vec![(
            "rules",
            Some(Value::Array(vec![Value::Object(obj(vec![
                ("ip_is_private", bv(true)),
                ("action", sv(if accept_lan { "route" } else { "reject" })),
                ("outbound", if accept_lan { sv("direct") } else { None }),
            ]))])),
        )]);

        if let Some(on) = node.g("outbound_node").map(|s| s.to_string()) {
            let outbound: Option<M>;
            if on == "_iface" && node.has("outbound_node_iface") {
                let iface = node.g("outbound_node_iface").unwrap_or("").to_string();
                outbound = Some(obj(vec![("type", sv("direct")), ("tag", sv("outbound")), ("bind_interface", sv(&iface)), ("routing_mark", Some(num(255.0)))]));
                self.touch_iface(&iface);
            } else {
                let t: Option<Node> = if on == "_socks" || on == "_http" {
                    let port = tonum(node.g("outbound_node_port")).map(num_str);
                    Some(Node::from_pairs(&[
                        ("type", node.g("type")),
                        ("protocol", Some(&on.replace('_', ""))),
                        ("address", node.g("outbound_node_address")),
                        ("port", port.as_deref()),
                        ("username", node.g("outbound_node_username").filter(|v| !v.is_empty())),
                        ("password", node.g("outbound_node_password").filter(|v| !v.is_empty())),
                    ]))
                } else {
                    self.cfg.section(&on).map(Node::from_section)
                };
                outbound = self.gen_outbound(None, t, Some("outbound"), None);
            }
            if let Some(o) = outbound {
                if let Some(t) = tag_of(&o) {
                    route.insert("final".into(), Value::String(t.to_string()));
                }
                outbounds.insert(0, o);
            }
        }

        for o in outbounds.iter_mut() {
            o.retain(|k, _| !k.starts_with('_'));
        }
        let mut i = outbounds.len();
        while i > 0 {
            i -= 1;
            if outbounds[i].get("type").and_then(|v| v.as_str()) == Some("masque-client") {
                endpoints.push(Value::Object(outbounds.remove(i)));
            }
        }

        Value::Object(obj(vec![
            (
                "log",
                mv(obj(vec![
                    ("disabled", bv(node.is("log", "0"))),
                    ("level", sv(&get_log_level(node.g("loglevel")).unwrap_or_else(|| "info".into()))),
                    ("timestamp", bv(true)),
                ])),
            ),
            ("dns", mv(obj(vec![("servers", Some(Value::Array(vec![Value::Object(obj(vec![("type", sv("local")), ("tag", sv("local"))]))])))]))),
            ("endpoints", Some(Value::Array(endpoints))),
            ("inbounds", Some(Value::Array(inbounds))),
            ("outbounds", Some(Value::Array(outbounds.into_iter().map(Value::Object).collect()))),
            ("route", mv(route)),
        ]))
    }
}

// ====================================================================== CLI

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// `passwall2 sing-box <func> '<json>'` (upstream `lua util_sing-box.lua <func> '<json>'`).
pub fn cli(args: &[String]) -> i32 {
    let Some(func) = args.first().map(|s| s.as_str()) else {
        eprintln!("usage: passwall2 sing-box <gen_config|gen_proto_config|geo_convert_srs> '<json>' | gen_config_server <server_id>");
        return 1;
    };
    let raw = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let var = util::args_from_json(raw);
    match func {
        "gen_config" => {
            let Some(g) = generate(&var) else {
                println!("nil");
                return 0;
            };
            println!("{}", pretty(&g.config));
            // like upstream: convert after the config is printed
            if !g.geo.is_empty() && !g.no_run {
                convert_geofile(&g.geo);
            }
            0
        }
        "gen_proto_config" => {
            match gen_proto_config(&var) {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("nil"),
            }
            0
        }
        "geo_convert_srs" => {
            geo_convert_srs(&var);
            println!();
            0
        }
        "gen_config_server" => {
            // accepts a plain section id or {"id": "..."} / {"node": "..."}
            let id = ArgsExt::ne(&var, "id").or(ArgsExt::ne(&var, "node")).or(ArgsExt::ne(&var, ".name")).map(|s| s.to_string()).unwrap_or_else(|| raw.to_string());
            match gen_config_server(&id) {
                Some(v) => {
                    println!("{}", pretty(&v));
                    0
                }
                None => {
                    println!("nil");
                    1
                }
            }
        }
        _ => {
            eprintln!("unknown function: {}", func);
            1
        }
    }
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const V112: Versions = Versions { ge_1_13_16: false, ge_1_14_0: false, ge_1_15_0: false };
    const V115: Versions = Versions { ge_1_13_16: true, ge_1_14_0: true, ge_1_15_0: true };

    fn gen(conf: &str, ver: Versions) -> Gen {
        let mut cfg = Config::parse("passwall2", conf);
        // multi-line TextValues (domain_list/ip_list) are written with literal \n in fixtures
        for s in cfg.sections.iter_mut() {
            for (_, v) in s.options.iter_mut() {
                if let uci::Value::Single(x) = v {
                    *x = x.replace("\\n", "\n");
                }
            }
        }
        let mut g = Gen::new(cfg, ver);
        g.fx = false;
        g
    }
    fn args(v: Value) -> Args {
        util::args_from_json(&v.to_string())
    }
    fn node(pairs: &[(&str, &str)]) -> Node {
        let mut n = Node::default();
        for (k, v) in pairs {
            n.set(k, v);
        }
        n
    }
    fn ob<'a>(cfg: &'a Value, tag: &str) -> &'a Value {
        cfg["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap_or_else(|| panic!("no outbound {tag}: {cfg:#}"))
    }

    #[test]
    fn versions() {
        assert_eq!(Versions::from_version("1.12.3"), V112);
        assert_eq!(Versions::from_version("v1.15.0"), V115);
        assert_eq!(Versions::from_version(""), V112);
        let v = Versions::from_version("1.14.0-beta.1");
        assert!(v.ge_1_14_0 && v.ge_1_13_16 && !v.ge_1_15_0);
    }

    #[test]
    fn tls_insecure_pre_1_15() {
        type Case<'a> = (&'a [(&'a str, &'a str)], Option<bool>);
        let cases: [Case; 4] = [
            (&[], None),
            (&[("tls_allowInsecure", "0")], None),
            (&[("tls_allowInsecure", "1")], Some(true)),
            (&[("tls_pinSHA256", "")], Some(false)),
        ];
        for (extra, want) in cases {
            let mut g = gen("", V112);
            let mut n = node(&[(".name", "n1"), ("type", "sing-box"), ("protocol", "trojan"), ("address", "1.2.3.4"), ("port", "1"), ("tls", "1")]);
            for (k, v) in extra {
                n.set(k, v);
            }
            let o = Value::Object(g.gen_outbound(None, Some(n), None, None).unwrap());
            assert_eq!(o["tls"].get("insecure").and_then(|v| v.as_bool()), want, "{extra:?}");
        }
    }

    #[test]
    fn rule_set_parse() {
        let t = parse_rule_set("remote:https://x.y/rule-set/geosite-netflix.srs", true).unwrap();
        assert_eq!(Value::Object(t), json!({"type":"remote","tag":"rs_geosite-netflix","format":"binary","url":"https://x.y/rule-set/geosite-netflix.srs"}));
        let t = parse_rule_set("local:/etc/a.b.json", false).unwrap();
        assert_eq!(Value::Object(t), json!({"type":"local","tag":"a","format":"source","path":"/etc/a.b.json"}));
        assert!(parse_rule_set("local:/etc/a.txt", false).is_none());
        assert!(parse_rule_set("http://x/a.srs", false).is_none());
        assert!(parse_rule_set("local:/etc/.srs", false).is_none());
        let g = geo_rule_set("geosite", "cn").unwrap();
        assert_eq!(g["path"], "/tmp/etc/passwall2_tmp/singbox_srss/geosite-cn.srs");
        assert_eq!(g["tag"], "geosite-cn");
        assert_eq!(geo_dir("/usr/share/v2ray/"), "/usr/share/v2ray");
        assert_eq!(geo_dir("/usr/share/v2ray"), "/usr/share");
    }

    #[test]
    fn ech_and_helpers() {
        assert_eq!(get_ech_domain("cloudflare-ech.com+https://1.1.1.1/dns-query").as_deref(), Some("cloudflare-ech.com"));
        assert_eq!(get_ech_domain("a.com+8.8.8.8"), None);
        assert_eq!(get_ech_domain("a.c0m+udp://8.8.8.8"), None);
        assert!(has_pem_marker("-----BEGIN ECH", "BEGIN") && has_pem_marker("--- END", "END"));
        assert!(!has_pem_marker("BEGIN", "BEGIN"));
        assert_eq!(hop_ranges("20000-30000,40000:50000,bad,1"), vec!["20000:30000", "40000:50000"]);
        assert_eq!(parse_header_line("  Authorization : Bearer x  "), Some(("authorization".into(), "Bearer x".into())));
        assert_eq!(parse_header_line(":x"), None);
        assert_eq!(parse_hosts_line("a.com 1.2.3.4 # c"), Some(("a.com".into(), "1.2.3.4".into())));
        assert_eq!(parse_hosts_line("# a.com 1.2.3.4"), None);
        assert_eq!(parse_hosts_line("a.com #1.2.3.4"), None);
    }

    #[test]
    fn vless_reality_ws() {
        let mut g = gen("", V112);
        let n = node(&[
            (".name", "n1"),
            ("type", "sing-box"),
            ("protocol", "vless"),
            ("address", "Example.COM"),
            ("port", "443"),
            ("uuid", "u"),
            ("flow", "xtls-rprx-vision"),
            ("tls", "1"),
            ("reality", "1"),
            ("reality_publicKey", "pk"),
            ("tls_serverName", "sni.com"),
            ("tls_pinSHA256", "aa"),
            ("transport", "ws"),
            ("ws_host", "h.com"),
            ("remarks", "R"),
        ]);
        let o = Value::Object(g.gen_outbound(Some("global"), Some(n), Some("default"), None).unwrap());
        assert_eq!(o["tag"], "default:R");
        assert_eq!(o["server"], "example.com");
        assert_eq!(o["server_port"], 443);
        assert_eq!(o["flow"], "xtls-rprx-vision");
        assert_eq!(o["packet_encoding"], "xudp");
        assert_eq!(o["tls"]["utls"], json!({"enabled":true,"fingerprint":"chrome"}));
        assert_eq!(o["tls"]["reality"]["public_key"], "pk");
        assert_eq!(o["tls"]["insecure"], true, "pin without 1.15 → insecure");
        assert!(o["tls"].get("certificate_sha256").is_none());
        assert_eq!(o["transport"], json!({"type":"ws","path":"/","headers":{"Host":"h.com"}}));
        assert_eq!(o["domain_resolver"], json!({"server":"local"}));

        let mut g = gen("", V115);
        let pin = "AA:".repeat(31) + "AA";
        let n = node(&[(".name", "n1"), ("type", "sing-box"), ("protocol", "trojan"), ("address", "1.2.3.4"), ("port", "1"), ("tls", "1"), ("tls_pinSHA256", &pin)]);
        let o = Value::Object(g.gen_outbound(None, Some(n), None, None).unwrap());
        assert_eq!(o["tls"]["insecure"], false);
        assert_eq!(o["tls"]["certificate_sha256"][0], api::sha256_xray_sb(&pin));
        // 26.4-era name
        let n = node(&[(".name", "n1"), ("type", "sing-box"), ("protocol", "trojan"), ("address", "1.2.3.4"), ("port", "1"), ("tls", "1"), ("tls_CertSha", &pin)]);
        let o = Value::Object(g.gen_outbound(None, Some(n), None, None).unwrap());
        assert_eq!(o["tls"]["certificate_sha256"][0], api::sha256_xray_sb(&pin));
    }

    #[test]
    fn hysteria2_versions_and_hop() {
        let n = node(&[
            (".name", "h"),
            ("type", "sing-box"),
            ("protocol", "hysteria2"),
            ("address", "a.com"),
            ("port", "443"),
            ("hysteria2_hop", "20000-30000"),
            ("hysteria2_hop_interval", "3-20"),
            ("hysteria2_obfs_type", "gecko"),
            ("hysteria2_obfs_MinPacketSize", "3000"),
            ("hysteria2_stream_recv_win", "8"),
            ("hysteria2_disable_mtu_discovery", "1"),
            ("hysteria2_idle_timeout", "500"),
            ("hysteria2_keep_alive_period", "10"),
        ]);
        let o = Value::Object(gen("", V112).gen_outbound(None, Some(n.clone()), None, None).unwrap());
        assert!(o.get("server_port").is_none());
        assert_eq!(o["server_ports"], json!(["20000:30000"]));
        assert_eq!(o["hop_interval"], "5s");
        assert_eq!(o["hop_interval_max"], "20s");
        assert_eq!(o["obfs"]["min_packet_size"], 512);
        assert_eq!(o["obfs"]["max_packet_size"], 1200);
        assert_eq!(o["stream_receive_window"], "8 MB");
        assert!(o.get("idle_timeout").is_none() && o.get("disable_path_mtu_discovery").is_none());
        assert_eq!(o["tls"]["enabled"], true, "hysteria2 forces tls");
        let o = Value::Object(gen("", V115).gen_outbound(None, Some(n), None, None).unwrap());
        assert_eq!(o["idle_timeout"], "30s");
        assert_eq!(o["keep_alive_period"], "10s");
        assert_eq!(o["disable_path_mtu_discovery"], true);
    }

    #[test]
    fn misc_protocols() {
        let mut g = gen("", V115);
        let o = Value::Object(
            g.gen_outbound(
                None,
                Some(node(&[(".name", "w"), ("type", "sing-box"), ("protocol", "wireguard"), ("address", "1.1.1.1"), ("port", "51820"), ("wireguard_reserved", "1,2,3")])),
                None,
                None,
            )
            .unwrap(),
        );
        assert_eq!(o["reserved"], json!([1, 2, 3]));
        let o = Value::Object(
            g.gen_outbound(None, Some(node(&[(".name", "w"), ("type", "sing-box"), ("protocol", "wireguard"), ("wireguard_reserved", "AQID")])), None, None).unwrap(),
        );
        assert_eq!(o["reserved"], json!([1, 2, 3]));
        let o = Value::Object(
            g.gen_outbound(None, Some(node(&[(".name", "t"), ("type", "sing-box"), ("protocol", "tuic"), ("alpn", "h2"), ("tuic_heartbeat", "10")])), None, None).unwrap(),
        );
        assert_eq!(o["tls"]["alpn"], json!(["h3"]));
        assert_eq!(o["heartbeat"], "10s");
        let o = Value::Object(g.gen_outbound(None, Some(node(&[(".name", "a"), ("type", "sing-box"), ("protocol", "anytls")])), None, None).unwrap());
        assert_eq!(o["client_metadata"], "anytls/0.0.13");
        let o = Value::Object(
            g.gen_outbound(
                None,
                Some(node(&[
                    (".name", "m"),
                    ("type", "sing-box"),
                    ("protocol", "masque"),
                    ("username", "u"),
                    ("password", "p"),
                    ("user_agent", "UA"),
                    ("masque_headers", "Authorization: Bearer t\\nX-A:  b "),
                    ("mux", "1"),
                ])),
                None,
                None,
            )
            .unwrap(),
        );
        assert_eq!(o["type"], "masque-client");
        assert!(o.get("username").is_none());
        assert_eq!(o["headers"], json!({"user-agent":["UA"],"authorization":["Bearer t"],"x-a":["b"]}));
        let o = Value::Object(
            g.gen_outbound(None, Some(node(&[(".name", "s"), ("type", "sing-box"), ("protocol", "shadowsocks"), ("plugin_enabled", "0"), ("plugin", "obfs-local")])), None, None)
                .unwrap(),
        );
        assert!(o.get("plugin").is_none());
        assert_eq!(o["password"], "");
        let o = Value::Object(g.gen_outbound(None, Some(node(&[(".name", "n"), ("type", "sing-box"), ("protocol", "naive"), ("uot", "1")])), None, None).unwrap());
        assert_eq!(o["udp_over_tcp"], json!({"enabled":true,"version":2}));
        assert_eq!(o["insecure_concurrency"], 0);
    }

    #[test]
    fn non_singbox_node_no_run() {
        let mut g = gen("", V112);
        g.no_run = true;
        let n = node(&[(".name", "x1"), ("type", "Xray"), ("protocol", "vless"), ("address", "a.com"), ("port", "1"), ("remarks", "X")]);
        let o = Value::Object(g.gen_outbound(Some("f"), Some(n.clone()), Some("default"), None).unwrap());
        assert_eq!(o["server"], "127.0.0.1");
        assert_eq!(o["server_port"], 3001);
        assert_eq!(o["type"], "socks");
        assert_eq!(o["tag"], "default:X");
        assert_eq!(o["_flag_proxy_tag"], "socks <- x1");
        let o = Value::Object(g.gen_outbound(Some("f"), Some(n), None, None).unwrap());
        assert_eq!(o["server_port"], 3002);
    }

    const CONF: &str = "
config global
	option dns_hosts 'h.com 1.1.1.1'

config global_singbox
	option fragment '1'

config nodes 'n1'
	option type 'sing-box'
	option protocol 'vmess'
	option remarks 'N1'
	option address 'n1.example.com'
	option port '443'
	option uuid 'u'
	option tls '1'
	option tls_serverName 'sni.com'
	option ech '1'

config nodes 'n2'
	option type 'sing-box'
	option protocol 'socks'
	option remarks 'N2'
	option address '2.2.2.2'
	option port '1080'

config nodes 'ut'
	option type 'sing-box'
	option protocol '_urltest'
	option remarks 'UT'
	list urltest_node 'n1'
	list urltest_node 'n2'

config nodes 'sh'
	option type 'sing-box'
	option protocol '_shunt'
	option remarks 'SH'
	option default_node 'n1'
	option fakedns '1'
	option r1 'ut'
	option r1_fakedns '1'
	option r2 '_direct'
	option r3 '_blackhole'
	option r4 'n2'
	option r4_proxy_tag 'n1'

config shunt_rules 'r1'
	option remarks 'R1'
	option domain_list 'geosite:netflix\\nfull:a.com\\n#c\\nkeyword:x'
	option ip_list 'geoip:private\\ngeoip:netflix\\n10.0.0.0/8'
	option network 'tcp,udp'
	option port '443,1000-2000'

config shunt_rules 'r2'
	option remarks 'R2'
	option domain_list 'domain:cn\\nrs:remote:https://x/y.srs'
	option source 'geoip:private 192.168.1.2 geoip:cn'

config shunt_rules 'r3'
	option remarks 'R3'
	option domain_list 'regexp:ads'

config shunt_rules 'r4'
	option remarks 'R4'
	option ip_list '9.9.9.9'
	option inbound 'tproxy socks'
";

    fn full_args() -> Args {
        args(json!({
            "flag": "global", "node": "sh", "redir_port": "1041", "tcp_proxy_way": "redirect",
            "local_socks_port": "1070", "dns_listen_port": "15353",
            "direct_dns_udp_server": "223.5.5.5", "direct_dns_udp_port": "53",
            "direct_dns_query_strategy": "UseIPv4",
            "remote_dns_tcp_server": "1.1.1.1", "remote_dns_tcp_port": "53", "remote_dns_tls": "1",
            "remote_dns_query_strategy": "UseIPv4", "remote_dns_client_ip": "1.2.3.0/24",
            "loglevel": "warning", "log": "1", "logfile": "/tmp/x.log"
        }))
    }

    #[test]
    fn shunt_config() {
        let mut g = gen(CONF, V112);
        let c = g.gen_config(&full_args()).config;
        // inbounds
        let tags: Vec<&str> = c["inbounds"].as_array().unwrap().iter().map(|i| i["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, vec!["socks-in", "redirect_tcp", "tproxy_udp", "dns-in"]);
        assert_eq!(c["log"]["level"], "warn");
        // outbounds
        assert_eq!(ob(&c, "default:N1")["detour"], "direct");
        assert_eq!(ob(&c, "default:N1")["tls"]["fragment"], true);
        assert_eq!(ob(&c, "ut-n1:N1")["type"], "vmess");
        assert_eq!(ob(&c, "urltest-ut")["outbounds"], json!(["ut-n1:N1", "ut-n2:N2"]));
        assert_eq!(ob(&c, "urltest-ut")["interval"], "3m");
        // r4: pre-proxy n1 then landing n2
        let land = ob(&c, "r4:N1 -> n2:N2");
        assert_eq!(land["detour"], "r4:N1");
        assert!(ob(&c, "ut-n2:N2").get("domain_resolver").is_none(), "IP server → no resolver");
        let last = c["outbounds"].as_array().unwrap().last().unwrap();
        assert_eq!(last["tag"], "direct");
        assert!(c["outbounds"].as_array().unwrap().iter().all(|o| o.as_object().unwrap().keys().all(|k| !k.starts_with('_'))));
        // route rules
        let rules = c["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0], json!({"action":"hijack-dns","inbound":"dns-in"}));
        assert_eq!(rules[1], json!({"action":"sniff","inbound":"dns-in"}));
        let r1 = rules.iter().find(|r| r["outbound"] == "urltest-ut").unwrap();
        assert_eq!(r1["network"], json!(["tcp", "udp"]));
        assert_eq!(r1["port"], json!([443]));
        assert_eq!(r1["port_range"], json!(["1000:2000"]));
        assert_eq!(r1["domain"], json!(["a.com"]));
        assert_eq!(r1["domain_keyword"], json!(["keyword:x"]));
        assert_eq!(r1["rule_set"], json!(["geosite-netflix", "geoip-netflix"]));
        assert_eq!(r1["ip_is_private"], true);
        assert_eq!(r1["ip_cidr"], json!(["10.0.0.0/8"]));
        let r2 = rules.iter().find(|r| r["outbound"] == "direct").unwrap();
        assert_eq!(r2["source_ip_is_private"], true);
        assert_eq!(r2["source_ip_cidr"], json!(["192.168.1.2"]));
        assert_eq!(r2["rule_set"], json!(["rs_y"]));
        let r3 = rules.iter().find(|r| r["action"] == "reject").unwrap();
        assert!(r3.get("outbound").is_none());
        let r4 = rules.iter().find(|r| r["outbound"] == "r4:N1 -> n2:N2").unwrap();
        assert_eq!(r4["inbound"], json!(["redirect_tcp", "tproxy_udp", "socks-in"]));
        assert_eq!(c["route"]["final"], "default:N1");
        assert_eq!(c["route"]["rule_set"].as_array().unwrap().len(), 3);
        assert_eq!(g.geo, GeoTags { site: vec!["netflix".into()], ip: vec!["netflix".into()] });
        // dns
        let servers = c["dns"]["servers"].as_array().unwrap();
        let remote = servers.iter().find(|s| s["tag"] == "remote").unwrap();
        assert_eq!(remote["type"], "tls");
        assert_eq!(remote["server_port"], 853);
        assert_eq!(remote["detour"], "default:N1");
        assert!(servers.iter().any(|s| s["tag"] == "remote_fakeip"));
        assert!(servers.iter().any(|s| s["tag"] == "hosts" && s["predefined"]["h.com"] == "1.1.1.1"));
        let r1dns = servers.iter().find(|s| s["tag"] == "r1").unwrap();
        assert_eq!(r1dns["detour"], "urltest-ut");
        assert_eq!(servers.last().unwrap()["tag"], "ech-dns");
        let drules = c["dns"]["rules"].as_array().unwrap();
        assert_eq!(drules[0], json!({"domain":["sni.com"],"server":"ech-dns"}));
        // node domains → direct (+ AAAA block for ipv4_only)
        assert!(drules.iter().any(|r| r["server"] == "direct" && r["domain"] == json!(["n1.example.com"])));
        assert!(drules.iter().any(|r| r["action"] == "predefined" && r["domain"] == json!(["n1.example.com"]) && r["query_type"] == json!(["AAAA"])));
        let fake = drules.iter().find(|r| r["server"] == "remote_fakeip" && r.get("rule_set").is_some()).unwrap();
        assert_eq!(fake["query_type"], json!(["A"]));
        assert_eq!(fake["rewrite_ttl"], 1);
        assert!(fake.get("client_subnet").is_none());
        let r1r = drules.iter().find(|r| r["server"] == "r1").unwrap();
        assert_eq!(r1r["client_subnet"], "1.2.3.0/24");
        assert_eq!(r1r["rewrite_ttl"], 30);
        assert!(drules.iter().any(|r| r["action"] == "predefined" && r["domain_regex"] == json!(["ads"]) && r.get("query_type").is_none()));
        assert_eq!(drules.last().unwrap(), &json!({"server":"remote","disable_cache":true,"rewrite_ttl":30}));
        assert_eq!(c["dns"]["final"], "remote");
        assert_eq!(c["dns"]["strategy"], "prefer_ipv6");
        assert_eq!(c["experimental"]["cache_file"]["path"], "/tmp/etc/passwall2_tmp/singbox_global.db");
    }

    #[test]
    fn plain_socks_instance() {
        let mut g = gen(CONF, V112);
        let a = args(json!({"flag":"acl_x","node":"n2","local_socks_address":"127.0.0.1","local_socks_port":"1081","local_http_port":"1082",
            "local_http_username":"u","local_http_password":"p"}));
        let c = g.gen_config(&a).config;
        assert_eq!(c["route"]["final"], "default:N2");
        assert_eq!(ob(&c, "default:N2")["version"], "5");
        assert_eq!(c["inbounds"][1]["users"], json!([{"username":"u","password":"p"}]));
        assert_eq!(c["route"]["rules"], json!([{"action":"sniff","inbound":"socks-in"}]));
        assert!(c["dns"].get("final").is_none());
        assert!(c.get("experimental").map(|e| e.is_null()).unwrap_or(true));
        assert_eq!(c["log"]["disabled"], true);
        assert_eq!(c["log"]["output"], "/dev/null");
    }

    #[test]
    fn blackhole_default_and_wireguard_endpoint() {
        let conf = "
config nodes 'sh'
	option type 'sing-box'
	option protocol '_shunt'
	option default_node '_blackhole'

config nodes 'wg'
	option type 'sing-box'
	option protocol 'wireguard'
	option address 'wg.com'
	option port '51820'
	list wireguard_local_address '10.0.0.2/32'
";
        let mut g = gen(conf, V112);
        let c = g.gen_config(&args(json!({"flag":"global","node":"sh"}))).config;
        assert!(c["route"].get("final").is_none());
        assert_eq!(c["route"]["rules"].as_array().unwrap().last().unwrap(), &json!({"action":"reject"}));

        let mut g = gen(conf, V112);
        let c = g.gen_config(&args(json!({"flag":"global","node":"wg"}))).config;
        let ep = &c["endpoints"][0];
        assert_eq!(ep["type"], "wireguard");
        assert_eq!(ep["tag"], "default");
        assert_eq!(ep["address"], json!(["10.0.0.2/32"]));
        assert_eq!(ep["peers"][0]["address"], "wg.com");
        assert_eq!(ep["peers"][0]["port"], 51820);
        assert_eq!(ep["detour"], "direct");
        assert_eq!(ep["domain_resolver"], json!({"server":"local"}));
        assert_eq!(c["outbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn node_domain_resolver_and_shadowtls() {
        let conf = "
config nodes 'n'
	option type 'sing-box'
	option protocol 'shadowsocks'
	option address 'ss.com'
	option port '8388'
	option ss_method 'aes-128-gcm'
	option password 'p'
	option domain_resolver 'https'
	option domain_resolver_dns_https 'https://dns.google/dns-query'
	option shadowtls '1'
	option shadowtls_version '3'
	option shadowtls_password 'stp'
	option shadowtls_serverName 'st.com'
";
        let mut g = gen(conf, V112);
        let c = g.gen_config(&args(json!({"flag":"global","node":"n","direct_dns_udp_server":"1.1.1.1"}))).config;
        let main = ob(&c, "default");
        assert_eq!(main["detour"], "default_shadowtls");
        assert!(main.get("server").is_none());
        let st = ob(&c, "default_shadowtls");
        assert_eq!(st["type"], "shadowtls");
        assert_eq!(st["password"], "stp");
        assert_eq!(st["tls"]["server_name"], "st.com");
        assert_eq!(main["domain_resolver"]["server"], "n_dns", "no server → resolver kept");
        let s = c["dns"]["servers"].as_array().unwrap().iter().find(|s| s["tag"] == "n_dns").unwrap();
        assert_eq!(s, &json!({"tag":"n_dns","type":"https","server":"dns.google","server_port":443,"path":"/dns-query","domain_resolver":"direct","detour":"direct"}));
        assert!(c["dns"]["rules"].as_array().unwrap().contains(&json!({"action":"route","server":"n_dns","domain":"ss.com"})));
    }

    #[test]
    fn proto_config() {
        let c = gen_proto_config(&args(json!({"local_http_port":"1082","server_proto":"socks","server_address":"127.0.0.1","server_port":"1081"}))).unwrap();
        assert_eq!(
            c,
            json!({"log":{"disabled":true,"level":"warn","timestamp":true},
                "inbounds":[{"type":"http","tag":"http-in","listen":"0.0.0.0","listen_port":1082}],
                "outbounds":[{"type":"socks","tag":"out","server":"127.0.0.1","server_port":1081}]})
        );
        let c = gen_proto_config(&args(json!({"local_socks_port":"1","local_socks_username":"a","local_socks_password":"b","server_proto":"nil"}))).unwrap();
        assert_eq!(c["inbounds"][0]["users"], json!([{"username":"a","password":"b"}]));
        assert_eq!(c["outbounds"], json!([]));
    }

    #[test]
    fn server_configs() {
        let s = "
config user 'srv'
	option type 'sing-box'
	option protocol 'vless'
	option port '443'
	option flow 'xtls-rprx-vision'
	option tls '1'
	option reality '1'
	option reality_private_key 'pk'
	option reality_shortId 'ab'
	option reality_handshake_server 'h.com'
	option reality_handshake_server_port '443'
	option tls_certificateFile '/c'
	option transport 'grpc'
	option grpc_serviceName 'svc'
	list users 'u1'
	list users 'missing'
	option accept_lan '1'
	option log '0'
	option outbound_node '_socks'
	option outbound_node_address '1.2.3.4'
	option outbound_node_port '1080'

config user 'u1'
	option username 'alice'
	option uuid 'uuid1'

config user 'wg'
	option type 'sing-box'
	option protocol 'wireguard'
	option port '51820'
	option wireguard_private_key 'k'
	list wireguard_local_address '10.0.0.1/24'
	list users 'u1'
";
        let scfg = Config::parse("passwall2_server", s);
        let mut g = gen("", V112);
        let c = g.gen_config_server(&Node::from_section(scfg.section("srv").unwrap()), &scfg);
        let ib = &c["inbounds"][0];
        assert_eq!(ib["users"], json!([{"name":"alice","uuid":"uuid1","flow":"xtls-rprx-vision"}]));
        assert_eq!(ib["tls"]["server_name"], "h.com");
        assert_eq!(ib["tls"]["reality"]["short_id"], json!(["ab"]));
        assert!(ib["tls"].get("certificate_path").is_none());
        assert_eq!(ib["transport"], json!({"type":"grpc","service_name":"svc"}));
        assert_eq!(c["route"]["rules"][0], json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
        assert_eq!(c["route"]["final"], "outbound");
        assert_eq!(c["outbounds"][0], json!({"tag":"outbound","type":"socks","server":"1.2.3.4","server_port":1080,"domain_resolver":{"server":"local"},"version":"5"}));
        assert_eq!(c["log"]["disabled"], true);
        assert_eq!(c["log"]["level"], "info");
        assert_eq!(c["endpoints"], json!([]));

        let c = g.gen_config_server(&Node::from_section(scfg.section("wg").unwrap()), &scfg);
        let ep = &c["endpoints"][0];
        assert!(ep.get("listen").is_none());
        assert_eq!(ep["name"], "sbwg_wg");
        assert_eq!(ep["mtu"], 1408);
        assert_eq!(ep["peers"][0]["allowed_ips"], json!([]));
        assert_eq!(c["route"]["rules"][0], json!({"ip_is_private":true,"action":"reject"}));
    }
}
