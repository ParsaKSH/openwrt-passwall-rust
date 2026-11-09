//! Share-link parsers of `subscribe.lua` (`processData` / `parse_link`): vmess, vless, ss,
//! ssr, trojan, hysteria, hysteria2/hy2, tuic, anytls, naive+https/naive+quic, snell and the
//! whole-document `ssd://` format → UCI `nodes` options. Spec: docs/spec/06 §1.4–§1.7.
//!
//! A parser returns `Err(LuaError)` where upstream raises a Lua error inside `processData`
//! (the caller logs "Parsing error, skip this node."), `Ok(None)` where upstream returns nil
//! (already logged) and `Ok(Some(node))` otherwise. The node still goes through
//! [`node_filter`] (error_msg / missing binary / keyword filter / invalid address).

use crate::api;
use crate::uci::{Config, Section};
use indexmap::IndexMap;
use serde_json::Value as J;

/// A Lua runtime error inside a parser (upstream: caught by `xpcall` → "Parsing error").
#[derive(Debug, Clone, PartialEq)]
pub struct LuaError;

pub type PResult = Result<Option<Node>, LuaError>;

/// Log sink: `(level, message)` (upstream `log(level, ...)`).
pub type Log<'a> = &'a mut dyn FnMut(usize, String);

// ------------------------------------------------------------------------------ node table

/// One option value of a parsed node (UCI option or list).
#[derive(Clone, Debug, PartialEq)]
pub enum NVal {
    S(String),
    L(Vec<String>),
}

/// The Lua `result` table: option name → value, in assignment order. Assigning Lua `nil`
/// removes the key; empty strings are kept here (they are skipped when written to UCI).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Node(pub IndexMap<String, NVal>);

impl Node {
    /// `result[k] = v` (None = nil).
    pub fn put(&mut self, k: &str, v: Option<String>) {
        match v {
            Some(v) => {
                self.0.insert(k.to_string(), NVal::S(v));
            }
            None => {
                self.0.shift_remove(k);
            }
        }
    }
    pub fn set(&mut self, k: &str, v: &str) {
        self.0.insert(k.to_string(), NVal::S(v.to_string()));
    }
    /// `result[k] = (v and v ~= "") and { v } or nil`
    pub fn list1(&mut self, k: &str, v: Option<String>) {
        match v.filter(|x| !x.is_empty()) {
            Some(v) => {
                self.0.insert(k.to_string(), NVal::L(vec![v]));
            }
            None => {
                self.0.shift_remove(k);
            }
        }
    }
    pub fn del(&mut self, k: &str) {
        self.0.shift_remove(k);
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        match self.0.get(k) {
            Some(NVal::S(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    pub fn is(&self, k: &str, v: &str) -> bool {
        self.get(k) == Some(v)
    }
    /// Deterministic JSON (sorted keys) used for the subscription md5.
    pub fn canonical_json(&self) -> J {
        let mut keys: Vec<&String> = self.0.keys().collect();
        keys.sort();
        let mut m = serde_json::Map::new();
        for k in keys {
            let v = match &self.0[k] {
                NVal::S(s) => J::String(s.clone()),
                NVal::L(l) => J::Array(l.iter().map(|x| J::String(x.clone())).collect()),
            };
            m.insert(k.clone(), v);
        }
        J::Object(m)
    }
}

// ------------------------------------------------------------------------------ context

/// Installed cores (upstream `has_ss_rust`, `has_ssr`, `has_singbox`, `has_xray`).
#[derive(Clone, Debug, Default)]
pub struct Cores {
    pub ss_rust: bool,
    pub ssr: bool,
    pub singbox: bool,
    pub xray: bool,
}

impl Cores {
    pub fn detect() -> Cores {
        Cores {
            ss_rust: api::is_finded("sslocal"),
            ssr: api::is_finded("ssr-local") && api::is_finded("ssr-redir"),
            singbox: api::finded_com("sing-box").is_some(),
            xray: api::finded_com("xray").is_some(),
        }
    }
    pub fn all() -> Cores {
        Cores { ss_rust: true, ssr: true, singbox: true, xray: true }
    }
    /// `core_has[name]`
    pub fn has(&self, name: &str) -> bool {
        match name {
            "xray" => self.xray,
            "sing-box" => self.singbox,
            "shadowsocks-rust" => self.ss_rust,
            _ => false,
        }
    }
}

/// Keyword filter (`prepare_keyword_filter`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeywordFilter {
    pub mode: String,
    pub discard: Vec<String>,
    pub keep: Vec<String>,
}

/// `split_filter_keywords(list)`: every row split on `|`, empty pieces and duplicates dropped,
/// spaces preserved.
pub fn split_filter_keywords(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for row in list {
        for kw in row.split('|').filter(|x| !x.is_empty()) {
            if !out.iter().any(|x| x == kw) {
                out.push(kw.to_string());
            }
        }
    }
    out
}

fn match_filter_keywords(value: &str, kws: &[String]) -> bool {
    kws.iter().any(|k| value.contains(k.as_str()))
}

impl KeywordFilter {
    /// `is_filter_keyword(filter, value)`: true → discard.
    pub fn discards(&self, value: &str) -> bool {
        match self.mode.as_str() {
            "1" => match_filter_keywords(value, &self.discard),
            "2" => !match_filter_keywords(value, &self.keep),
            "3" => match_filter_keywords(value, &self.discard) && !match_filter_keywords(value, &self.keep),
            "4" => match_filter_keywords(value, &self.discard) || !match_filter_keywords(value, &self.keep),
            _ => false,
        }
    }
}

/// Global parsing context built once per run (defaults from `@global_subscribe[0]`).
#[derive(Clone, Debug, Default)]
pub struct ParseCtx {
    pub cores: Cores,
    pub ss_type: Option<String>,
    pub trojan_type: Option<String>,
    pub vmess_type: Option<String>,
    pub vless_type: Option<String>,
    pub hysteria2_type: Option<String>,
    pub filter: KeywordFilter,
}

impl ParseCtx {
    pub fn new(cfg: &Config, cores: Cores) -> ParseCtx {
        let c = &cores;
        let gs = "@global_subscribe[0]";
        ParseCtx {
            ss_type: api::get_core(cfg, "ss_type", &[(c.ss_rust, "shadowsocks-rust"), (c.singbox, "sing-box"), (c.xray, "xray")]),
            trojan_type: api::get_core(cfg, "trojan_type", &[(c.singbox, "sing-box"), (c.xray, "xray")]),
            vmess_type: api::get_core(cfg, "vmess_type", &[(c.xray, "xray"), (c.singbox, "sing-box")]),
            vless_type: api::get_core(cfg, "vless_type", &[(c.xray, "xray"), (c.singbox, "sing-box")]),
            hysteria2_type: api::get_core(cfg, "hysteria2_type", &[(c.singbox, "sing-box"), (c.xray, "xray")]),
            filter: KeywordFilter {
                mode: cfg.get(gs, "filter_keyword_mode").unwrap_or_else(|| "0".into()),
                discard: split_filter_keywords(&cfg.list_raw(gs, "filter_discard_list")),
                keep: split_filter_keywords(&cfg.list_raw(gs, "filter_keep_list")),
            },
            cores,
        }
    }
    /// Context of the running system (binary detection + current config).
    pub fn detect(cfg: &Config) -> ParseCtx {
        ParseCtx::new(cfg, Cores::detect())
    }
    /// `prepare_keyword_filter(sub_cfg)`: modes 0..4 of the subscription, else the global one.
    pub fn keyword_filter(&self, sub: Option<&Section>) -> KeywordFilter {
        if let Some(s) = sub {
            if let Some(m) = s.get("filter_keyword_mode").filter(|m| matches!(m.as_str(), "0" | "1" | "2" | "3" | "4")) {
                return KeywordFilter { mode: m, discard: split_filter_keywords(&s.list_raw("filter_discard_list")), keep: split_filter_keywords(&s.list_raw("filter_keep_list")) };
            }
        }
        self.filter.clone()
    }
}

/// Per-subscription overrides computed at the top of `processData`.
struct SubOpts {
    insecure: bool,
    ss: Option<String>,
    trojan: Option<String>,
    vmess: Option<String>,
    vless: Option<String>,
    hy2: Option<String>,
    hy_up: Option<String>,
    hy_down: Option<String>,
}

fn sub_opts(ctx: &ParseCtx, sub: Option<&Section>) -> SubOpts {
    let mut o = SubOpts {
        insecure: true,
        ss: ctx.ss_type.clone(),
        trojan: ctx.trojan_type.clone(),
        vmess: ctx.vmess_type.clone(),
        vless: ctx.vless_type.clone(),
        hy2: ctx.hysteria2_type.clone(),
        hy_up: None,
        hy_down: None,
    };
    if let Some(s) = sub {
        if s.get("allowInsecure").is_some_and(|v| v != "1") {
            o.insecure = false;
        }
        let pick = |opt: &str, def: &mut Option<String>| {
            let v = s.get(opt).unwrap_or_else(|| "global".into());
            if v != "global" && ctx.cores.has(&v) {
                *def = Some(v);
            }
        };
        pick("ss_type", &mut o.ss);
        pick("trojan_type", &mut o.trojan);
        pick("vmess_type", &mut o.vmess);
        pick("vless_type", &mut o.vless);
        pick("hysteria2_type", &mut o.hy2);
        o.hy_up = s.get("hysteria_up_mbps");
        o.hy_down = s.get("hysteria_down_mbps");
    }
    o
}

// ------------------------------------------------------------------------------ helpers

/// Lua `tostring(number)` (`%.14g`).
pub fn lua_num(f: f64) -> String {
    if f.is_nan() {
        return if f.is_sign_negative() { "-nan".into() } else { "nan".into() };
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let e = format!("{:.13e}", f);
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    if !(-4..14).contains(&exp) {
        let m = mant.trim_end_matches('0').trim_end_matches('.');
        return format!("{}e{}{:02}", m, if exp < 0 { '-' } else { '+' }, exp.abs());
    }
    let prec = (13 - exp).max(0) as usize;
    let s = format!("{:.*}", prec, f);
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// JSON scalar → Lua string value (strings, numbers); other types → None.
pub fn jv_str(v: &J) -> Option<String> {
    match v {
        J::String(s) => Some(s.clone()),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                n.as_f64().map(lua_num)
            }
        }
        _ => None,
    }
}

/// Lua `a or b or ...`: first present value ("" counts as present).
fn or(vals: &[Option<&String>]) -> Option<String> {
    vals.iter().flatten().next().map(|s| s.to_string())
}

/// `x and x ~= ""`
fn ne(v: Option<&String>) -> Option<String> {
    v.filter(|s| !s.is_empty()).cloned()
}

/// `INSECURE(x)`
fn insecure(v: Option<String>, sub_insecure: bool) -> String {
    match v.as_deref() {
        Some("1") => "1".into(),
        Some("0") => "0".into(),
        _ => if sub_insecure { "1".into() } else { "0".into() },
    }
}

type Params = IndexMap<String, String>;

#[derive(Clone, Copy, PartialEq)]
enum Q {
    /// values URL-decoded
    Decode,
    /// values raw
    Raw,
    /// keys lowercased, values URL-decoded
    LowerKey,
    /// keys URL-decoded + lowercased, values URL-decoded
    DecodeLowerKey,
}

/// The query loop shared by every parser (spec 06 §0.9). Last value wins.
fn qparse(q: Option<&str>, mode: Q) -> Params {
    let mut p = Params::new();
    let Some(q) = q else { return p };
    for v in api::split(q, "&") {
        if let Some(s) = v.find('=') {
            if s >= 1 {
                let (k, val) = (&v[..s], &v[s + 1..]);
                let key = match mode {
                    Q::Decode | Q::Raw => k.to_string(),
                    Q::LowerKey => k.to_lowercase(),
                    Q::DecodeLowerKey => api::url_decode(k).to_lowercase(),
                };
                let val = if mode == Q::Raw { val.to_string() } else { api::url_decode(val) };
                p.insert(key, val);
            }
        }
    }
    p
}

/// `parse_host_port(host_port, default_port)` (spec 06 §0.10).
pub fn parse_host_port(hp: Option<&str>, default_port: Option<&str>) -> (String, Option<String>) {
    let s = hp.unwrap_or("");
    let authority = match s.find('/') {
        Some(i) => &s[..i],
        None => s,
    };
    let mut address: Option<String> = None;
    let mut port: Option<String> = None;
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(j) = rest.find(']') {
            if j > 0 {
                let inner = &rest[..j];
                let after = &rest[j + 1..];
                if let Some(p) = after.strip_prefix(':') {
                    address = Some(inner.to_string());
                    port = Some(p.to_string());
                } else if after.is_empty() {
                    address = Some(inner.to_string());
                }
            }
        }
    }
    if address.is_none() {
        if let Some(i) = authority.find(':') {
            if i > 0 {
                address = Some(authority[..i].to_string());
                port = Some(authority[i + 1..].to_string());
            }
        }
    }
    let port = match port {
        Some(p) if !p.is_empty() => Some(p),
        _ => default_port.map(|s| s.to_string()),
    };
    (address.unwrap_or_else(|| authority.to_string()), port)
}

/// Text after the first `#` (UrlDecoded) and the text before it.
fn split_alias(content: &str) -> (String, String) {
    match content.find('#') {
        Some(i) => (api::url_decode(&content[i + 1..]), content[..i].to_string()),
        None => (String::new(), content.to_string()),
    }
}

/// sing-box WS early data in the path (`?ed=N`) → (path before `?`, N).
fn ws_early_data(path: &str) -> Result<Option<(Option<String>, String)>, LuaError> {
    let dat = api::split(path, "?");
    let mut params: IndexMap<String, Option<String>> = IndexMap::new();
    if let Some(q) = dat.get(1) {
        for v in api::split(q, "&") {
            let t = api::split(&v, "=");
            // `ws_path_params[t[1]] = t[2]` with t[1] == nil: "table index is nil"
            let Some(k) = t.first() else { return Err(LuaError) };
            params.insert(k.clone(), t.get(1).cloned());
        }
    }
    if let Some(Some(ed)) = params.get("ed") {
        if let Some(n) = api::lua_tonumber(ed) {
            return Ok(Some((dat.first().cloned(), lua_num(n))));
        }
    }
    Ok(None)
}

fn apply_ws(r: &mut Node, host: Option<String>, path: Option<String>, singbox: bool) -> Result<(), LuaError> {
    r.put("ws_host", host);
    r.put("ws_path", path.clone());
    if singbox {
        if let Some(p) = path {
            if let Some((wp, ed)) = ws_early_data(&p)? {
                r.put("ws_path", wp);
                r.set("ws_enableEarlyData", "1");
                r.set("ws_maxEarlyData", &ed);
                r.set("ws_earlyDataHeaderName", "Sec-WebSocket-Protocol");
            }
        }
    }
    Ok(())
}

/// `download_address` from an xhttp `extra` JSON (`extra.downloadSettings.address` or
/// `downloadSettings.address`).
fn download_address(extra: Option<&String>) -> Option<Option<String>> {
    let data: J = serde_json::from_str(extra?).ok()?;
    if data.is_null() {
        return None;
    }
    let pick = |d: &J| d.get("downloadSettings").and_then(|x| x.get("address")).cloned();
    let addr = data.get("extra").and_then(pick).or_else(|| pick(&data));
    Some(match addr {
        Some(J::String(s)) if !s.is_empty() => Some(s),
        Some(J::Number(n)) => jv_str(&J::Number(n)),
        _ => None,
    })
}

fn finalmask(r: &mut Node, fm: Option<&String>) {
    let fm = ne(fm);
    r.put("use_finalmask", fm.as_ref().map(|_| "1".to_string()));
    r.put("finalmask", fm.map(|f| api::base64_encode(f.as_bytes())));
}

/// Which branch set of the common transport mapping.
#[derive(Clone, Copy, PartialEq)]
enum Variant {
    Ss,
    Trojan,
    Vless,
}

/// NET normalisation (spec 06 §1.6): lowercases, swaps raw/tcp per core, h2/http → http;
/// sets `transport`. Returns the normalised type.
fn net(r: &mut Node, t: &str) -> String {
    let mut t = t.to_lowercase();
    let core = r.get("type").unwrap_or("").to_string();
    if core == "sing-box" && t == "raw" {
        t = "tcp".into();
    } else if core == "Xray" && t == "tcp" {
        t = "raw".into();
    }
    if t == "h2" || t == "http" {
        t = "http".into();
        r.set("transport", if core == "Xray" { "xhttp" } else { "http" });
    } else {
        r.set("transport", &t);
    }
    t
}

/// TRANSPORT(params) for ss (non SS-Rust), trojan and vless.
fn transport(r: &mut Node, p: &Params, t: &str, v: Variant) -> Result<(), LuaError> {
    let core = r.get("type").unwrap_or("").to_string();
    let g = |k: &str| p.get(k).cloned();
    match t {
        "ws" => apply_ws(r, g("host"), g("path"), core == "sing-box")?,
        "http" => {
            if core == "sing-box" {
                r.set("transport", "http");
                r.list1("http_host", g("host"));
                r.put("http_path", g("path"));
            } else if core == "Xray" {
                r.set("transport", "xhttp");
                r.set("xhttp_mode", "stream-one");
                r.put("xhttp_host", g("host"));
                r.put("xhttp_path", g("path"));
            }
        }
        "raw" | "tcp" => {
            r.put("tcp_guise", Some(g("headerType").unwrap_or_else(|| "none".into())));
            r.list1("tcp_guise_http_host", g("host"));
            r.list1("tcp_guise_http_path", g("path"));
        }
        "kcp" | "mkcp" => {
            r.set("transport", "mkcp");
            r.put("mkcp_guise", Some(g("headerType").unwrap_or_else(|| "none".into())));
            r.put("mkcp_seed", g("seed"));
        }
        "quic" => {
            r.put("quic_guise", Some(g("headerType").unwrap_or_else(|| "none".into())));
            r.put("quic_key", g("key"));
            r.put("quic_security", Some(g("quicSecurity").unwrap_or_else(|| "none".into())));
        }
        "grpc" => {
            if let Some(sn) = or(&[p.get("serviceName"), p.get("path")]) {
                r.set("grpc_serviceName", &sn);
            }
            r.set("grpc_mode", &g("mode").unwrap_or_else(|| "gun".into()));
        }
        _ => {}
    }
    let xhttp = t == "xhttp" || (v == Variant::Vless && t == "splithttp");
    if xhttp {
        if v == Variant::Ss && core != "Xray" {
            r.set("error_msg", &api::translatef("Please replace %s to support %s transmission method.", &["Xray", "xhttp"]));
        }
        r.put("xhttp_host", g("host"));
        r.put("xhttp_path", g("path"));
        if v != Variant::Trojan {
            r.set("xhttp_mode", &g("mode").unwrap_or_else(|| "auto".into()));
            let extra = ne(p.get("extra"));
            r.put("use_xhttp_extra", extra.as_ref().map(|_| "1".to_string()));
            r.put("xhttp_extra", extra.map(|e| api::base64_encode(e.as_bytes())));
            if let Some(addr) = download_address(p.get("extra")) {
                // address:gsub("^%[", ""):gsub("%]$", "")
                r.put(
                    "download_address",
                    addr.map(|a| {
                        let a = a.strip_prefix('[').unwrap_or(&a);
                        a.strip_suffix(']').unwrap_or(a).to_string()
                    }),
                );
            }
        }
    }
    if t == "httpupgrade" && v != Variant::Ss {
        r.put("httpupgrade_host", g("host"));
        r.put("httpupgrade_path", g("path"));
    }
    Ok(())
}

/// TLS block of ss (with `type=`) and vless (`security` tls/reality).
fn tls_full(r: &mut Node, p: &Params) {
    r.set("tls", "1");
    r.put("tls_serverName", ne(p.get("sni")).or_else(|| p.get("host").cloned()));
    r.put("alpn", p.get("alpn").cloned());
    if let Some(fp) = ne(p.get("fp")) {
        r.set("utls", "1");
        r.set("fingerprint", &fp);
    }
    if let Some(ech) = ne(p.get("ech")) {
        r.set("ech", "1");
        r.set("ech_config", &ech);
    }
    r.put("tls_pinSHA256", p.get("pcs").cloned());
    r.put("tls_CertByName", p.get("vcn").cloned());
    if p.get("security").map(|s| s.as_str()) == Some("reality") {
        r.set("reality", "1");
        r.put("reality_publicKey", p.get("pbk").cloned());
        r.put("reality_shortId", p.get("sid").cloned());
        r.put("reality_spiderX", p.get("spx").cloned());
        r.put("use_mldsa65Verify", ne(p.get("pqv")).map(|_| "1".to_string()));
        r.put("reality_mldsa65Verify", p.get("pqv").cloned());
    }
}

fn skip_core(log: Log, a: &str, b: &str) -> PResult {
    log(2, api::translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", &[a, b]));
    Ok(None)
}

fn skip_missing(log: Log, a: &str, b: &str) -> PResult {
    log(2, api::translatef("Skip the %s node because the %s core program is not installed.", &[a, b]));
    Ok(None)
}

fn singbox_reject(r: &Node, sz: &str, log: Log) -> bool {
    let t = r.get("transport").unwrap_or("");
    if r.is("type", "sing-box") && (t == "mkcp" || t == "xhttp") {
        log(
            2,
            api::translatef(
                "Skip node: %s. Because Sing-Box does not support the %s protocol's %s transmission method, Xray needs to be used instead.",
                &[r.get("remarks").unwrap_or(""), sz, t],
            ),
        );
        return true;
    }
    false
}

/// `set_ss_implementation(ss_type, result)`
fn set_ss_impl(ctx: &ParseCtx, ss_type: Option<&str>, r: &mut Node, log: Log) -> bool {
    let c = &ctx.cores;
    match ss_type {
        Some("shadowsocks-rust") if c.ss_rust => r.set("type", "SS-Rust"),
        Some("xray") if c.xray => {
            r.set("type", "Xray");
            r.set("protocol", "shadowsocks");
            r.set("transport", "raw");
        }
        Some("sing-box") if c.singbox => {
            r.set("type", "sing-box");
            r.set("protocol", "shadowsocks");
        }
        _ => {
            log(2, api::translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", &["SS", "SS"]));
            return false;
        }
    }
    true
}

// ------------------------------------------------------------------------------ processData

/// `processData(szType, content, add_mode, group, sub_cfg)` for URI links. `content` is the
/// text after `://` (already base64-decoded for vmess/ssr, `&amp;`/`#` normalised otherwise).
pub fn process_data(ctx: &ParseCtx, sz: &str, content: &str, add_mode: &str, group: Option<&str>, sub: Option<&Section>, log: Log) -> PResult {
    let so = sub_opts(ctx, sub);
    let mut r = Node::default();
    r.set("timeout", "60");
    r.set("add_mode", add_mode);
    r.put("group", group.map(|g| g.to_string()));
    let res = match sz {
        "ssr" => ssr(ctx, content, r, log)?,
        "vmess" => vmess(ctx, &so, content, r, log)?,
        "ss" => ss(ctx, &so, content, r, log)?,
        "trojan" => trojan(ctx, &so, content, r, log)?,
        "vless" => vless(ctx, &so, content, r, log)?,
        "hysteria" => hysteria(ctx, &so, content, r, log)?,
        "hysteria2" | "hy2" => hysteria2(ctx, &so, content, r, log)?,
        "tuic" => tuic(ctx, &so, content, r, log)?,
        "anytls" => anytls(ctx, &so, content, r, log)?,
        "naive+https" | "naive+quic" => naive(ctx, sz, content, r, log)?,
        "snell" => snell(ctx, content, r, log)?,
        _ => {
            log(2, api::translatef("%s type node subscriptions are not currently supported, skip this node.", &[sz]));
            return Ok(None);
        }
    };
    Ok(res.map(fallback_remarks))
}

/// `processData("ssd", server, ...)`: one server object (already inheriting the root's
/// `airport`, `port`, `encryption`, `password`).
pub fn process_ssd(ctx: &ParseCtx, server: &serde_json::Map<String, J>, add_mode: &str, group: Option<&str>, sub: Option<&Section>, log: Log) -> PResult {
    let so = sub_opts(ctx, sub);
    let mut r = Node::default();
    r.set("timeout", "60");
    r.set("add_mode", add_mode);
    r.put("group", group.map(|g| g.to_string()));
    if !set_ss_impl(ctx, so.ss.as_deref(), &mut r, log) {
        return Ok(None);
    }
    let g = |k: &str| server.get(k).and_then(jv_str);
    r.put("address", g("server"));
    r.put("port", g("port"));
    r.put("password", g("password"));
    r.put("method", g("encryption"));
    r.put("ss_method", g("encryption"));
    r.put("plugin", g("plugin"));
    r.put("plugin_opts", g("plugin_options"));
    r.put("group", g("airport"));
    r.put("remarks", g("remarks"));
    Ok(Some(fallback_remarks(r)))
}

fn fallback_remarks(mut r: Node) -> Node {
    if r.get("remarks").is_none_or(|s| s.is_empty()) {
        let v = match (r.get("address"), r.get("port")) {
            (Some(a), Some(p)) => format!("{}:{}", a, p),
            _ => "NULL".to_string(),
        };
        r.set("remarks", &v);
    }
    r
}

/// ssr: `host:port:protocol:method:obfs:b64pass/?obfsparam=..&protoparam=..&remarks=..`
fn ssr(ctx: &ParseCtx, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.ssr {
        return skip_core(log, "SSR", "shadowsocksr-libev");
    }
    r.set("type", "SSR");
    let dat = api::split(&content.replace("/?", "?"), "?");
    let d1 = dat.first().cloned().ok_or(LuaError)?; // dat[1]:match on nil errors
    let host_info = api::split(&d1, ":");
    let n = host_info.len() as i64;
    let hi = |k: i64| -> Option<String> {
        if k >= 1 && k <= n {
            Some(host_info[(k - 1) as usize].clone())
        } else {
            None
        }
    };
    let bracket = d1.find('[').and_then(|i| d1[i + 1..].rfind(']').map(|j| d1[i + 1..i + 1 + j].to_string()));
    match bracket {
        Some(b) => r.set("address", &b),
        None => r.put("address", hi(n - 5)),
    }
    r.put("port", hi(n - 4));
    r.put("protocol", hi(n - 3));
    r.put("method", hi(n - 2));
    r.put("obfs", hi(n - 1));
    r.put("password", Some(hi(n).map(|p| api::base64_decode(&p)).unwrap_or_default()));
    let params = qparse(dat.get(1).map(|s| s.as_str()), Q::Raw);
    let b64 = |k: &str| params.get(k).map(|v| api::base64_decode(v)).unwrap_or_default();
    r.set("obfs_param", &b64("obfsparam"));
    r.set("protocol_param", &b64("protoparam"));
    r.set("remarks", &b64("remarks"));
    Ok(Some(r))
}

/// vmess: v2rayN JSON or legacy Shadowrocket `base64(security:uuid@host:port)?params`.
fn vmess(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    let c = &ctx.cores;
    match so.vmess.as_deref() {
        Some("sing-box") if c.singbox => r.set("type", "sing-box"),
        Some("xray") if c.xray => r.set("type", "Xray"),
        _ => return skip_core(log, "VMess", "VMess"),
    }
    let mut info: IndexMap<String, String> = IndexMap::new();
    match serde_json::from_str::<J>(content) {
        Ok(J::Object(m)) => {
            for (k, v) in m.iter() {
                if let Some(s) = jv_str(v) {
                    info.insert(k.clone(), s);
                } else if k == "extra" && v.is_object() {
                    // xhttp extra given as a JSON object instead of a JSON string
                    info.insert(k.clone(), v.to_string());
                }
            }
        }
        Ok(J::Array(_)) => {}
        Ok(J::Null) | Err(_) => {
            if !content.contains('?') {
                // upstream: translatef("Skipping %s node. ...") without an argument raises
                // a format error, which ends up as "Parsing error, skip this node."
                return Err(LuaError);
            }
            let parts = api::split(&content.replace("/?", "?"), "?");
            let sp = api::split(&api::base64_decode(parts.first().map(|s| s.as_str()).unwrap_or("")), "@");
            let id_info = sp.first().map(|s| api::split(s, ":")).unwrap_or_default();
            let sec = if id_info.len() > 1 && !id_info[0].is_empty() { id_info[0].clone() } else { "auto".into() };
            info.insert("security".into(), sec);
            if let Some(id) = id_info.last() {
                info.insert("id".into(), id.clone());
            }
            let (add, port) = parse_host_port(sp.get(1).map(|s| s.as_str()), Some("443"));
            info.insert("add".into(), add);
            if let Some(p) = port {
                info.insert("port".into(), p);
            }
            let params = qparse(parts.get(1).map(|s| s.as_str()), Q::Decode);
            let mut put = |k: &str, v: Option<String>| {
                if let Some(v) = v {
                    info.insert(k.to_string(), v);
                }
            };
            put("ps", or(&[params.get("remark"), params.get("remarks")]));
            put("net", Some(if params.get("obfs").map(|s| s.as_str()) == Some("websocket") { "ws".into() } else { params.get("obfs").cloned().unwrap_or_else(|| "tcp".into()) }));
            put("path", params.get("path").cloned());
            put("aid", Some(params.get("alterId").cloned().unwrap_or_else(|| "0".into())));
            put("tls", params.get("tls").cloned());
            put("sni", params.get("peer").cloned());
            put("tfo", params.get("tfo").cloned());
            // upstream quirk: jsonParse(nil) raises when obfsParam is absent (every such link
            // failed); treat a missing obfsParam as "no host" instead.
            if let Some(op) = params.get("obfsParam") {
                match serde_json::from_str::<J>(op) {
                    Ok(J::Object(o)) => {
                        put("type", o.get("header").and_then(jv_str));
                        put("host", o.get("Host").and_then(jv_str));
                    }
                    Ok(J::Array(_)) | Ok(J::String(_)) => {}
                    Ok(J::Number(_)) | Ok(J::Bool(_)) => return Err(LuaError),
                    Ok(J::Null) | Err(_) => put("host", Some(op.clone())),
                }
            }
            put("allowinsecure", params.get("allowInsecure").cloned());
        }
        Ok(_) => return Err(LuaError),
    }
    let g = |k: &str| info.get(k).cloned();
    r.put("address", g("add"));
    r.put("port", g("port"));
    r.set("protocol", "vmess");
    r.put("alter_id", g("aid"));
    r.put("uuid", g("id"));
    r.put("remarks", g("ps"));
    let path = ne(info.get("path")).map(|p| api::url_decode(&p));
    let host = g("host");
    let mut ty = g("type");
    let core = r.get("type").unwrap_or("").to_string();
    let n = net(&mut r, &g("net").unwrap_or_else(|| "tcp".into()));
    match n.as_str() {
        "ws" => apply_ws(&mut r, host.clone(), path.clone(), core == "sing-box")?,
        "http" => {
            if core == "Xray" {
                r.set("xhttp_mode", "stream-one");
                r.put("xhttp_host", host.clone());
                r.put("xhttp_path", path.clone());
            } else {
                r.list1("http_host", host.clone());
                r.put("http_path", path.clone());
            }
        }
        "raw" | "tcp" => {
            if ty.as_deref().is_some_and(|t| t != "http") {
                ty = Some("none".into());
            }
            r.put("tcp_guise", ty.clone());
            r.list1("tcp_guise_http_host", host.clone());
            r.list1("tcp_guise_http_path", path.clone());
        }
        "kcp" | "mkcp" => {
            // upstream quirk: `transport` stayed "kcp" for net=kcp (not a valid transport);
            // store the normalised "mkcp" like every other parser.
            r.set("transport", "mkcp");
            r.put("mkcp_guise", ty.clone());
            r.put("mkcp_seed", g("seed"));
        }
        "quic" => {
            r.put("quic_guise", ty.clone());
            r.put("quic_key", g("key"));
            r.put("quic_security", g("securty"));
        }
        "grpc" => r.put("grpc_serviceName", path.clone()),
        "xhttp" | "splithttp" => {
            // upstream bug: read `params.mode`/`params.extra` (undefined there, every such link
            // failed); the intended source is the vmess JSON itself.
            r.put("xhttp_host", host.clone());
            r.put("xhttp_path", path.clone());
            r.set("xhttp_mode", &g("mode").unwrap_or_else(|| "auto".into()));
            // stored like the vless/ss parsers (base64 + use_xhttp_extra) so the generators
            // can read it; upstream would have stored the raw JSON text.
            let extra = ne(info.get("extra"));
            r.put("use_xhttp_extra", extra.as_ref().map(|_| "1".to_string()));
            r.put("xhttp_extra", extra.as_ref().map(|e| api::base64_encode(e.as_bytes())));
            r.put(
                "download_address",
                download_address(extra.as_ref()).flatten().map(|a| {
                    let a = a.strip_prefix('[').unwrap_or(&a);
                    a.strip_suffix(']').unwrap_or(a).to_string()
                }),
            );
        }
        "httpupgrade" => {
            r.put("httpupgrade_host", host.clone());
            r.put("httpupgrade_path", path.clone());
        }
        _ => {}
    }
    r.set("security", &or(&[info.get("security"), info.get("scy")]).unwrap_or_else(|| "auto".into()));
    let tls = g("tls");
    if tls.as_deref() == Some("tls") || tls.as_deref() == Some("1") {
        r.set("tls", "1");
        r.put("alpn", g("alpn"));
        if let Some(fp) = ne(info.get("fp")) {
            r.set("utls", "1");
            r.set("fingerprint", &fp);
        }
        r.put("tls_serverName", ne(info.get("sni")).or(host.clone()));
        r.put("tls_pinSHA256", g("pcs"));
        r.put("tls_CertByName", g("vcn"));
        let ins = or(&[info.get("allowinsecure"), info.get("allowInsecure"), info.get("insecure")]);
        r.set("tls_allowInsecure", &insecure(ins, so.insecure));
    } else {
        r.set("tls", "0");
    }
    if let Some(ech) = ne(info.get("ech")) {
        r.set("ech", "1");
        r.set("ech_config", &ech);
    }
    r.put("tcp_fast_open", g("tfo"));
    let fm = ne(info.get("fm")).map(|f| api::url_decode(&f));
    finalmask(&mut r, fm.as_ref());
    if singbox_reject(&r, "vmess", log) {
        return Ok(None);
    }
    Ok(Some(r))
}

/// SIP003 plugin_opts rewrite for ShadowTLS subscriptions.
fn rewrite_plugin_opts(s: &str) -> String {
    let mut o = s.to_string();
    if let Some(rest) = o.strip_prefix("password=") {
        o = format!("passwd={}", rest);
    }
    o = o.replace(";password=", ";passwd=");
    let b = o.as_bytes();
    if o.starts_with("version=") && b.len() > 8 && matches!(b[8], b'1' | b'2' | b'3') {
        o = format!("v{}=1{}", b[8] as char, &o[9..]);
    }
    let mut out = String::new();
    let mut rest = o.as_str();
    while let Some(i) = rest.find(";version=") {
        let after = &rest[i + 9..];
        match after.as_bytes().first() {
            Some(c @ (b'1' | b'2' | b'3')) => {
                out.push_str(&rest[..i]);
                out.push_str(&format!(";v{}=1", *c as char));
                rest = &after[1..];
            }
            _ => {
                out.push_str(&rest[..i + 9]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `parseShadowTLSParams(b64)`: the decoded JSON object and its opts string.
fn shadow_tls_params(b64: &str) -> Result<(Option<serde_json::Map<String, J>>, String), LuaError> {
    let data = match serde_json::from_str::<J>(&api::base64_decode(b64)) {
        Ok(J::Object(m)) => m,
        Ok(J::Array(_)) => serde_json::Map::new(),
        _ => return Ok((None, String::new())),
    };
    let tostr = |v: &J| -> Result<String, LuaError> {
        match v {
            J::Bool(b) => Ok(b.to_string()),
            _ => jv_str(v).ok_or(LuaError),
        }
    };
    let mut t = vec![];
    if let Some(v) = data.get("version") {
        t.push(format!("v{}=1", jv_str(v).ok_or(LuaError)?));
    }
    if let Some(v) = data.get("password") {
        t.push(format!("passwd={}", jv_str(v).ok_or(LuaError)?));
    }
    for (k, v) in data.iter() {
        if k != "version" && k != "password" {
            if v.is_null() {
                continue;
            }
            t.push(format!("{}={}", k, tostr(v).unwrap_or_default()));
        }
    }
    Ok((Some(data), t.join(";")))
}

fn ss(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    let c = &ctx.cores;
    if !set_ss_impl(ctx, so.ss.as_deref(), &mut r, log) {
        return Ok(None);
    }
    let (alias, before) = split_alias(content);
    r.set("remarks", &alias);
    let mut info = before.replace("/?", "?");
    let mut params = Params::new();
    if let Some(qi) = info.find('?') {
        let query = api::split(&info, "?");
        params = qparse(query.get(1).map(|s| s.as_str()), Q::Decode);
        if let Some(pi) = params.get("plugin").cloned() {
            match pi.find(';') {
                Some(i) => {
                    r.set("plugin", &pi[..i]);
                    r.set("plugin_opts", &rewrite_plugin_opts(&pi[i + 1..]));
                }
                None => r.set("plugin", &pi),
            }
        }
        if r.is("plugin", "simple-obfs") {
            r.set("plugin", "obfs-local");
        }
        info = info[..qi].to_string();
    }
    let host_info = api::split(&api::base64_decode(&api::url_decode(&info)), "@");
    if host_info.is_empty() {
        return Ok(Some(r));
    }
    let (addr, port) = parse_host_port(host_info.last().map(|s| s.as_str()), None);
    r.set("address", &addr);
    r.put("port", port);
    let userinfo = if host_info.len() > 2 { host_info[..host_info.len() - 1].join("@") } else { api::base64_decode(&host_info[0]) };
    let (method, password) = match userinfo.find(':') {
        Some(i) => (Some(userinfo[..i].to_string()), userinfo[i + 1..].to_string()),
        None => (None, host_info[0].clone()),
    };
    let m = method.unwrap_or_else(|| "none".into()).to_lowercase();
    let m = match m.as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        _ => m,
    };
    r.set("method", &m);
    r.set("ss_method", &m);
    r.set("password", &password);
    r.put("tcp_fast_open", params.get("tfo").cloned());
    finalmask(&mut r, params.get("fm"));

    let ptype = params.get("type").cloned();
    let need_upgrade = !r.is("type", "Xray")
        && !r.is("type", "sing-box")
        && ptype.as_deref().is_some_and(|t| t != "tcp")
        && params.get("headerType").is_some_and(|h| h != "none");
    if c.xray && (need_upgrade || ptype.as_deref() == Some("xhttp")) {
        r.set("type", "Xray");
        r.set("protocol", "shadowsocks");
    } else if c.singbox && need_upgrade {
        r.set("type", "sing-box");
        r.set("protocol", "shadowsocks");
    }

    if let Some(plugin) = r.get("plugin").map(|s| s.to_string()) {
        let core = r.get("type").unwrap_or("").to_string();
        if core == "Xray" {
            if plugin != "obfs-local" {
                r.set("error_msg", &api::translatef("%s unsupport SS %s plugin.", &["Xray", &plugin]));
            } else {
                // `result.plugin_opts:match` on nil raises
                let opts = r.get("plugin_opts").ok_or(LuaError)?.to_string();
                let find = |key: &str| -> String {
                    match opts.find(key) {
                        Some(i) => opts[i + key.len()..].split(';').next().unwrap_or("").to_string(),
                        None => String::new(),
                    }
                };
                let obfs = find("obfs=");
                let obfs_host = find("obfs-host=");
                if obfs.is_empty() || obfs_host.is_empty() {
                    r.set("error_msg", &format!("SS {} {}", plugin, api::translatef("Plugin options Incomplete.", &[])));
                }
                if obfs == "http" {
                    r.set("transport", "raw");
                    r.set("tcp_guise", "http");
                    r.list1("tcp_guise_http_host", Some(obfs_host.clone()));
                    r.0.insert("tcp_guise_http_path".into(), NVal::L(vec!["/".into()]));
                } else if obfs == "tls" {
                    r.set("tls", "1");
                    r.set("tls_serverName", &obfs_host);
                    r.set("tls_allowInsecure", "1");
                }
                r.del("plugin");
                r.del("plugin_opts");
            }
        } else if core == "sing-box" {
            if plugin != "obfs-local" && plugin != "v2ray-plugin" && plugin != "shadow-tls" {
                r.set("error_msg", &api::translatef("%s unsupport SS %s plugin.", &["Sing-Box", &plugin]));
            } else {
                r.set("plugin_enabled", "1");
                if plugin == "shadow-tls" {
                    let opts = r.get("plugin_opts").ok_or(LuaError)?.to_string();
                    for item in opts.split(';').filter(|x| !x.is_empty()) {
                        // `key:match(...)` with key == nil (no '=') raises
                        let (k, v) = item.split_once('=').ok_or(LuaError)?;
                        if k.is_empty() {
                            return Err(LuaError);
                        }
                        if k == "host" {
                            r.set("shadowtls_serverName", v);
                        }
                        if k == "passwd" {
                            r.set("shadowtls_password", v);
                        }
                        if matches!(k, "v1" | "v2" | "v3") {
                            r.set("shadowtls_version", &k[1..]);
                        }
                    }
                    r.set("shadowtls", "1");
                    r.del("plugin_opts");
                    r.del("plugin_enabled");
                }
            }
        } else {
            r.set("plugin_enabled", "1");
        }
    }

    if let Some(pt) = ptype {
        let t = net(&mut r, &pt);
        if !r.is("type", "SS-Rust") {
            transport(&mut r, &params, &t, Variant::Ss)?;
            r.set("tls", "0");
            let sec = params.get("security").map(|s| s.as_str());
            if sec == Some("tls") || sec == Some("reality") {
                tls_full(&mut r, &params);
            }
            let ins = or(&[params.get("allowinsecure"), params.get("allowInsecure"), params.get("insecure")]);
            r.set("tls_allowInsecure", &insecure(ins, so.insecure));
            r.put("uot", params.get("udp").cloned());
        } else {
            r.set("error_msg", &api::translatef("Please replace Xray or Sing-Box to support more transmission methods in Shadowsocks.", &[]));
        }
    }

    if let Some(st) = params.get("shadow-tls").cloned() {
        let core = r.get("type").unwrap_or("").to_string();
        if core != "sing-box" && core != "SS-Rust" {
            r.set("error_msg", &format!("{} {}", so.ss.clone().unwrap_or_default(), api::translatef("unsupport %s plugin.", &["shadow-tls"])));
        } else if core == "SS-Rust" {
            let (_, opts) = shadow_tls_params(&st)?;
            r.set("plugin_enabled", "1");
            r.set("plugin", "shadow-tls");
            r.set("plugin_opts", &opts);
        } else {
            let (data, _) = shadow_tls_params(&st)?;
            if let Some(d) = data.filter(|d| !d.is_empty()) {
                let g = |k: &str| d.get(k).and_then(jv_str);
                r.set("shadowtls", "1");
                r.set("shadowtls_version", &g("version").unwrap_or_else(|| "1".into()));
                r.put("shadowtls_password", g("password"));
                r.put("shadowtls_serverName", g("host"));
                if let Some(fp) = d.get("fingerprint").filter(|v| !v.is_null() && *v != &J::Bool(false)) {
                    r.set("shadowtls_utls", "1");
                    r.set("shadowtls_fingerprint", &jv_str(fp).unwrap_or_else(|| "chrome".into()));
                }
            }
        }
    }
    Ok(Some(r))
}

/// `user@host:port?query` split shared by trojan/vless/anytls: (userinfo, host_port, query).
fn split_at_user(content: &str) -> (String, Option<String>, Option<String>) {
    let info = api::split(content, "@");
    let user = info.first().cloned().unwrap_or_default();
    let rest = info.get(1).cloned().unwrap_or_default().replace("/?", "?");
    let q = api::split(&rest, "?");
    (user, q.first().cloned(), q.get(1).cloned())
}

fn trojan(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    let c = &ctx.cores;
    match so.trojan.as_deref() {
        Some("sing-box") if c.singbox => r.set("type", "sing-box"),
        Some("xray") if c.xray => r.set("type", "Xray"),
        _ => return skip_core(log, "Trojan", "Trojan"),
    }
    r.set("protocol", "trojan");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    if content.contains('@') {
        let (user, hp, q) = split_at_user(&content);
        r.set("password", &api::url_decode(&user));
        let mut p = qparse(q.as_deref(), Q::Decode);
        let (addr, port) = parse_host_port(hp.as_deref(), Some("443"));
        r.set("address", &addr);
        r.put("port", port);
        let sec = p.get("security").cloned().unwrap_or_else(|| "tls".into());
        p.insert("security".into(), sec.clone());
        if sec == "tls" || sec == "reality" {
            r.set("tls", "1");
            r.set("tls_serverName", &or(&[p.get("peer"), p.get("sni")]).unwrap_or_default());
            r.put("alpn", p.get("alpn").cloned());
            if let Some(fp) = ne(p.get("fp")) {
                r.set("utls", "1");
                r.set("fingerprint", &fp);
            }
            if sec == "reality" {
                r.set("reality", "1");
                r.put("reality_publicKey", p.get("pbk").cloned());
                r.put("reality_shortId", p.get("sid").cloned());
            }
            if let Some(ech) = ne(p.get("ech")) {
                r.set("ech", "1");
                r.set("ech_config", &ech);
            }
            r.put("tls_pinSHA256", p.get("pcs").cloned());
            r.put("tls_CertByName", p.get("vcn").cloned());
            let ins = or(&[p.get("allowinsecure"), p.get("allowInsecure"), p.get("insecure")]);
            r.set("tls_allowInsecure", &insecure(ins, so.insecure));
        }
        let t = net(&mut r, p.get("type").map(|s| s.as_str()).unwrap_or("tcp"));
        transport(&mut r, &p, &t, Variant::Trojan)?;
        r.put("tcp_fast_open", p.get("tfo").cloned());
        finalmask(&mut r, p.get("fm"));
        if singbox_reject(&r, "trojan", log) {
            return Ok(None);
        }
    }
    Ok(Some(r))
}

fn vless(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    let c = &ctx.cores;
    match so.vless.as_deref() {
        Some("sing-box") if c.singbox => r.set("type", "sing-box"),
        Some("xray") if c.xray => r.set("type", "Xray"),
        _ => return skip_core(log, "VLESS", "VLESS"),
    }
    r.set("protocol", "vless");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    if content.contains('@') {
        let (user, hp, q) = split_at_user(&content);
        r.set("uuid", &api::url_decode(&user));
        let mut p = qparse(q.as_deref(), Q::Decode);
        let (addr, port) = parse_host_port(hp.as_deref(), Some("443"));
        r.set("address", &addr);
        let ty = p.get("type").cloned().unwrap_or_else(|| "tcp".into()).to_lowercase();
        if matches!(ty.as_str(), "xhttp" | "kcp" | "mkcp") && !r.is("type", "Xray") && c.xray {
            r.set("type", "Xray");
        }
        let t = net(&mut r, &ty);
        transport(&mut r, &p, &t, Variant::Vless)?;
        r.set("encryption", &p.get("encryption").cloned().unwrap_or_else(|| "none".into()));
        r.put("flow", p.get("flow").cloned());
        if p.get("security").is_none_or(|s| s.is_empty()) && p.contains_key("flow") {
            p.insert("security".into(), "tls".into());
        }
        r.set("tls", "0");
        let sec = p.get("security").map(|s| s.as_str());
        if sec == Some("tls") || sec == Some("reality") {
            tls_full(&mut r, &p);
            let ins = or(&[p.get("allowinsecure"), p.get("allowInsecure"), p.get("insecure")]);
            r.set("tls_allowInsecure", &insecure(ins, so.insecure));
        }
        r.put("port", port);
        r.put("tcp_fast_open", p.get("tfo").cloned());
        finalmask(&mut r, p.get("fm"));
        if singbox_reject(&r, "vless", log) {
            return Ok(None);
        }
    }
    Ok(Some(r))
}

fn hysteria(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.singbox {
        return skip_missing(log, "Hysteria", "Sing-Box");
    }
    r.set("type", "sing-box");
    r.set("protocol", "hysteria");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    let q = api::split(&content.replace("/?", "?"), "?");
    // values are never URL-decoded for hysteria v1
    let p = qparse(q.get(1).map(|s| s.as_str()), Q::Raw);
    let (addr, port) = parse_host_port(q.first().map(|s| s.as_str()), Some("443"));
    r.set("address", &addr);
    r.put("port", port);
    r.put("hysteria_obfs", p.get("obfsParam").cloned());
    r.set("hysteria_auth_type", "string");
    r.put("hysteria_auth_password", p.get("auth").cloned());
    r.set("tls_serverName", &or(&[p.get("peer"), p.get("sni")]).unwrap_or_default());
    r.put("tls_pinSHA256", or(&[p.get("pcs"), p.get("pinSHA256")]));
    let ins = or(&[p.get("allowinsecure"), p.get("allowInsecure"), p.get("insecure")]);
    r.set("tls_allowInsecure", &insecure(ins, so.insecure));
    r.put("alpn", p.get("alpn").cloned());
    r.put("hysteria_up_mbps", or(&[p.get("upmbps"), so.hy_up.as_ref()]));
    r.put("hysteria_down_mbps", or(&[p.get("downmbps"), so.hy_down.as_ref()]));
    r.put("hysteria_hop", p.get("mport").cloned());
    Ok(Some(r))
}

fn hysteria2(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    let mut info = content.clone();
    if content.contains('@') {
        let parts = api::split(&content, "@");
        r.set("hysteria2_auth_password", &api::url_decode(parts.first().map(|s| s.as_str()).unwrap_or("")));
        info = parts.get(1).cloned().unwrap_or_default().replace("/?", "?");
    }
    let q = api::split(&info, "?");
    let p = qparse(q.get(1).map(|s| s.as_str()), Q::LowerKey);
    let (addr, port) = parse_host_port(q.first().map(|s| s.as_str()), Some("443"));
    r.set("address", &addr);
    r.put("port", port);
    r.put("tls_serverName", p.get("sni").cloned());
    r.put("tls_pinSHA256", or(&[p.get("pcs"), p.get("pinsha256")]));
    r.put("tls_CertByName", p.get("vcn").cloned());
    let ins = or(&[p.get("allowinsecure"), p.get("insecure")]);
    r.set("tls_allowInsecure", &insecure(ins, so.insecure));
    r.put("hysteria2_up_mbps", or(&[p.get("upmbps"), so.hy_up.as_ref()]));
    r.put("hysteria2_down_mbps", or(&[p.get("downmbps"), so.hy_down.as_ref()]));
    r.put("hysteria2_hop", p.get("mport").cloned());
    if let Some(pw) = or(&[p.get("obfs-password"), p.get("obfs_password")]) {
        r.set("hysteria2_obfs_type", &p.get("obfs").cloned().unwrap_or_else(|| "salamander".into()));
        r.set("hysteria2_obfs_password", &pw);
    }
    if p.get("obfs").map(|s| s.as_str()) == Some("gecko") {
        r.set("hysteria2_obfs_MinPacketSize", &p.get("minpacketsize").cloned().unwrap_or_else(|| "512".into()));
        r.set("hysteria2_obfs_MaxPacketSize", &p.get("maxpacketsize").cloned().unwrap_or_else(|| "1200".into()));
    }
    let c = &ctx.cores;
    let t = so.hy2.as_deref();
    if (t == Some("sing-box") && c.singbox) || (t == Some("xray") && c.xray) {
        r.set("type", if t == Some("sing-box") && c.singbox { "sing-box" } else { "Xray" });
        r.set("protocol", "hysteria2");
        finalmask(&mut r, p.get("fm"));
        Ok(Some(r))
    } else {
        skip_core(log, "Hysteria2", "Hysteria2")
    }
}

fn tuic(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.singbox {
        return skip_missing(log, "Tuic", "Sing-Box");
    }
    r.set("type", "sing-box");
    r.set("protocol", "tuic");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    let mut info = content.clone();
    if content.contains('@') {
        let parts = api::split(&content, "@");
        let mut auth = parts.first().cloned().unwrap_or_default();
        let mut idx = auth.find(':');
        if idx.is_none() {
            auth = api::url_decode(&auth);
            idx = auth.find(':');
        }
        if let Some(i) = idx {
            r.set("uuid", &api::url_decode(&auth[..i]));
            r.set("password", &api::url_decode(&auth[i + 1..]));
        }
        info = parts.get(1).cloned().unwrap_or_default().replace("/?", "?");
    }
    let q = api::split(&info, "?");
    let p = qparse(q.get(1).map(|s| s.as_str()), Q::LowerKey);
    let (addr, port) = parse_host_port(q.first().map(|s| s.as_str()), Some("443"));
    r.set("address", &addr);
    r.put("port", port);
    r.put("tls_serverName", p.get("sni").cloned());
    r.put("tls_disable_sni", p.get("disable_sni").cloned());
    r.put("tls_pinSHA256", or(&[p.get("pcs"), p.get("pinsha256")]));
    r.set("tuic_alpn", &p.get("alpn").cloned().unwrap_or_else(|| "h3".into()));
    r.set("tuic_congestion_control", &p.get("congestion_control").cloned().unwrap_or_else(|| "cubic".into()));
    r.set("tuic_udp_relay_mode", &p.get("udp_relay_mode").cloned().unwrap_or_else(|| "native".into()));
    let ins = or(&[p.get("allowinsecure"), p.get("insecure"), p.get("allow_insecure")]);
    r.set("tls_allowInsecure", &insecure(ins, so.insecure));
    Ok(Some(r))
}

fn anytls(ctx: &ParseCtx, so: &SubOpts, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.singbox {
        return skip_missing(log, "AnyTLS", "Sing-Box 1.12");
    }
    r.set("type", "sing-box");
    r.set("protocol", "anytls");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    if content.contains('@') {
        let (user, hp, q) = split_at_user(&content);
        r.set("password", &api::url_decode(&user));
        let p = qparse(q.as_deref(), Q::LowerKey);
        let (addr, port) = parse_host_port(hp.as_deref(), Some("443"));
        r.set("address", &addr);
        r.set("tls", "0");
        let sec = ne(p.get("security")).unwrap_or_else(|| "tls".into());
        if sec == "tls" || sec == "reality" {
            r.set("tls", "1");
            r.put("tls_serverName", or(&[p.get("sni"), p.get("peer")]));
            r.put("tls_pinSHA256", or(&[p.get("pcs"), p.get("pinsha256")]));
            r.put("alpn", p.get("alpn").cloned());
            if let Some(fp) = ne(p.get("fp")) {
                r.set("utls", "1");
                r.set("fingerprint", &fp);
            }
            if sec == "reality" {
                r.set("reality", "1");
                r.put("reality_publicKey", p.get("pbk").cloned());
                r.put("reality_shortId", p.get("sid").cloned());
            }
            if let Some(ech) = ne(p.get("ech")) {
                r.set("ech", "1");
                r.set("ech_config", &ech);
            }
        }
        r.put("port", port);
        let ins = or(&[p.get("allowinsecure"), p.get("insecure")]);
        r.set("tls_allowInsecure", &insecure(ins, so.insecure));
    }
    Ok(Some(r))
}

fn naive(ctx: &ParseCtx, sz: &str, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.singbox {
        return skip_missing(log, "NaïveProxy", "Sing-Box");
    }
    r.set("type", "sing-box");
    r.set("protocol", "naive");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    let mut info = content.clone();
    if content.contains('@') {
        let parts = api::split(&content, "@");
        let auth = parts.first().cloned().unwrap_or_default();
        match auth.find(':') {
            Some(i) => {
                r.set("username", &api::url_decode(&auth[..i]));
                r.set("password", &api::url_decode(&auth[i + 1..]));
            }
            None => {
                r.set("username", "");
                r.set("password", &api::url_decode(&auth));
            }
        }
        info = parts.get(1).cloned().unwrap_or_default().replace("/?", "?");
    }
    let q = api::split(&info, "?");
    let p = qparse(q.get(1).map(|s| s.as_str()), Q::Decode);
    let (addr, port) = parse_host_port(q.first().map(|s| s.as_str()), Some("443"));
    r.set("address", &addr);
    r.put("port", port);
    r.put("tls_serverName", p.get("sni").cloned());
    r.put("uot", p.get("uot").cloned());
    r.set("naive_insecure_concurrency", &p.get("insecure-concurrency").cloned().unwrap_or_else(|| "0".into()));
    if let Some(ech) = ne(p.get("ech")) {
        r.set("ech", "1");
        r.set("ech_config", &ech);
    }
    if sz == "naive+quic" {
        r.set("naive_quic", "1");
        r.set("naive_congestion_control", &p.get("congestion_control").cloned().unwrap_or_else(|| "bbr".into()));
    }
    Ok(Some(r))
}

fn snell(ctx: &ParseCtx, content: &str, mut r: Node, log: Log) -> PResult {
    if !ctx.cores.singbox {
        return skip_missing(log, "Snell", "Sing-Box 1.14");
    }
    r.set("type", "sing-box");
    r.set("protocol", "snell");
    let (alias, content) = split_alias(content);
    r.set("remarks", &alias);
    let mut info = Some(content.clone());
    if content.contains('@') {
        let parts = api::split(&content, "@");
        r.set("snell_psk", &api::url_decode(parts.first().map(|s| s.as_str()).unwrap_or("")));
        info = parts.get(1).cloned();
    }
    let info = info.unwrap_or_default().replace("/?", "?");
    let q = api::split(&info, "?");
    let p = qparse(q.get(1).map(|s| s.as_str()), Q::DecodeLowerKey);
    let (addr, port) = parse_host_port(q.first().map(|s| s.as_str()), Some("443"));
    r.set("address", &addr);
    r.put("port", port);
    let psk = p.get("psk").cloned().or_else(|| r.get("snell_psk").map(|s| s.to_string()));
    r.put("snell_psk", psk);
    r.put("password", p.get("userkey").cloned());
    let ver = p.get("version").cloned().unwrap_or_else(|| "4".into());
    r.set("snell_version", &ver);
    if ver == "4" {
        r.set("snell_obfs_mode", &p.get("obfs").cloned().unwrap_or_else(|| "none".into()));
        r.put("snell_obfs_host", or(&[p.get("obfs-host"), p.get("obfs_host")]));
    } else {
        r.set("snell_mode", &p.get("mode").cloned().unwrap_or_else(|| "default".into()));
    }
    r.set("snell_reuse", if p.get("reuse").map(|s| s.as_str()) == Some("1") { "1" } else { "0" });
    Ok(Some(r))
}

// ------------------------------------------------------------------------------ parse_link

/// Result of [`parse_link`].
#[derive(Debug, Default)]
pub struct LinkOutcome {
    /// accepted nodes, in order
    pub nodes: Vec<Node>,
    /// remarks of every parsed node handed to nodeFilter (kept or not), in order — the
    /// caller feeds them to `get_subscribe_info` for subscriptions
    pub remarks_seen: Vec<String>,
    /// number of non-blank entries examined (links / ssd servers)
    pub candidates: usize,
}

/// `nodeFilter(node)`: Some(log line) when the node is discarded.
pub fn node_filter(node: &Node, add_mode: &str, filter: Option<&KeywordFilter>) -> Option<String> {
    let remarks = node.get("remarks").unwrap_or("");
    if let Some(e) = node.get("error_msg") {
        return Some(format!("{} {}", api::translatef("Discard node: %s, Reason:", &[remarks]), e));
    }
    let Some(ty) = node.get("type") else {
        return Some(format!("{} {}", api::translatef("Discard node: %s, Reason:", &[remarks]), api::translatef("No usable binary was found.", &[])));
    };
    let addr = node.get("address");
    let filtered = (add_mode == "2" && filter.is_some_and(|f| f.discards(remarks)))
        || addr.is_none()
        || remarks == "NULL"
        || addr == Some("127.0.0.1")
        || addr.is_some_and(|a| !api::dt_hostname(a) && !api::is_ip(a));
    if filtered {
        return Some(api::translatef("Discard filter nodes: %s type node %s", &[ty, remarks]));
    }
    None
}

/// `parse_link(raw, add_mode, group, sub_cfg)` minus the `nodeResult` bookkeeping (done by
/// the caller). Subscriptions (`add_mode == "2"`) base64-decode the body; manual imports
/// (`"1"`) take it line by line as is.
pub fn parse_link(ctx: &ParseCtx, raw: &str, add_mode: &str, group: Option<&str>, sub: Option<&Section>, log: Log) -> LinkOutcome {
    let mut out = LinkOutcome::default();
    let gname = group.unwrap_or("");
    if raw.is_empty() {
        if add_mode == "2" {
            log(
                2,
                api::translatef(
                    "Get subscription content for [%s] is empty. This may be due to an invalid subscription address or a network problem. Please diagnose the issue!",
                    &[gname],
                ),
            );
        }
        return out;
    }
    let filter = if add_mode == "2" { Some(ctx.keyword_filter(sub)) } else { None };
    let accept = |res: PResult, entry: &str, out: &mut LinkOutcome, log: Log<'_>| match res {
        Err(LuaError) => log(2, format!("{} {}", entry, api::translatef("Parsing error, skip this node.", &[]))),
        Ok(None) => {}
        Ok(Some(node)) => {
            match node_filter(&node, add_mode, filter.as_ref()) {
                Some(msg) => log(2, msg),
                None => out.nodes.push(node.clone()),
            }
            out.remarks_seen.push(node.get("remarks").unwrap_or("").to_string());
        }
    };
    if let Some(i) = raw.find("ssd://") {
        let json = api::base64_decode(&raw[i + 6..]);
        // upstream crashes the whole run on an invalid ssd document; treat it as empty
        let doc: Option<serde_json::Map<String, J>> = match serde_json::from_str::<J>(&json) {
            Ok(J::Object(m)) => Some(m),
            _ => None,
        };
        match doc.as_ref().and_then(|d| d.get("servers").and_then(|s| s.as_array()).map(|a| (d, a))) {
            Some((d, servers)) => {
                for s in servers {
                    let Some(obj) = s.as_object() else {
                        out.candidates += 1;
                        log(2, format!("{} {}", s, api::translatef("Parsing error, skip this node.", &[])));
                        continue;
                    };
                    out.candidates += 1;
                    let mut m = obj.clone();
                    for k in ["airport", "port", "encryption", "password"] {
                        if !m.contains_key(k) || m[k].is_null() {
                            if let Some(v) = d.get(k) {
                                m.insert(k.to_string(), v.clone());
                            }
                        }
                    }
                    let res = process_ssd(ctx, &m, add_mode, group, sub, log);
                    accept(res, &J::Object(obj.clone()).to_string(), &mut out, log);
                }
            }
            None => log(2, format!("ssd:// {}", api::translatef("Parsing error, skip this node.", &[]))),
        }
    } else {
        let lines = if add_mode == "1" { api::split(raw, "\n") } else { api::split(&api::base64_decode(raw).replace("\r\n", "\n"), "\n") };
        for v in lines {
            if v.chars().all(|c| c.is_ascii_whitespace() || c == '\x0b') {
                continue;
            }
            out.candidates += 1;
            let line = api::trim(&v);
            let dat = api::split(&line, "://");
            let res = if let (Some(t), Some(rest)) = (dat.first(), dat.get(1)) {
                if t == "vmess" || t == "ssr" {
                    let link = match rest.find('#') {
                        Some(i) => &rest[..i],
                        None => rest.as_str(),
                    };
                    process_data(ctx, t, &api::base64_decode(&api::trim(link)), add_mode, group, sub, log)
                } else {
                    let link = normalize_hash(&rest.replace("&amp;", "&"));
                    process_data(ctx, t, &link, add_mode, group, sub, log)
                }
            } else {
                Ok(None)
            };
            accept(res, &v, &mut out, log);
        }
    }
    log(2, api::translatef("Successfully resolved the [%s] node, number: %s", &[gname, &out.nodes.len().to_string()]));
    out
}

/// Lua `gsub("%s*#%s*", "#")`.
fn normalize_hash(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i] == '#' {
            // find a run of whitespace followed by '#'
            let mut j = i;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j] == '#' {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                out.push('#');
                i = j;
                continue;
            }
            out.push(b[i]);
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `get_subscribe_info(cfgid, remarks)` matcher: (expired_date, rem_traffic) found in remarks.
pub fn subscribe_info_from_remarks(remarks: &str) -> (Option<String>, Option<String>) {
    let v: String = remarks.chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')).collect();
    let find = |pats: &[&str]| -> Option<String> {
        let mut last = None;
        for p in pats {
            if let Some(i) = v.find(p) {
                let rest = &v[i + p.len()..];
                if !rest.is_empty() {
                    last = Some(rest.to_string());
                }
            }
        }
        last
    };
    (
        find(&["套餐到期：", "过期时间：", "有效期至：", "到期时间：", "截止日期："]),
        find(&["剩余流量：", "流量剩余：", "可用流量：", "套餐剩余："]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ParseCtx {
        ParseCtx {
            cores: Cores::all(),
            ss_type: Some("xray".into()),
            trojan_type: Some("xray".into()),
            vmess_type: Some("xray".into()),
            vless_type: Some("xray".into()),
            hysteria2_type: Some("sing-box".into()),
            filter: KeywordFilter { mode: "0".into(), ..Default::default() },
        }
    }
    fn sb_ctx() -> ParseCtx {
        let mut c = ctx();
        c.ss_type = Some("sing-box".into());
        c.trojan_type = Some("sing-box".into());
        c.vmess_type = Some("sing-box".into());
        c.vless_type = Some("sing-box".into());
        c
    }
    fn parse(c: &ParseCtx, link: &str) -> Option<Node> {
        let mut logs = vec![];
        let out = parse_link(c, link, "1", Some("default"), None, &mut |l, m| logs.push((l, m)));
        out.nodes.into_iter().next()
    }
    fn parse_logs(c: &ParseCtx, link: &str) -> (Option<Node>, Vec<String>) {
        let mut logs = vec![];
        let out = parse_link(c, link, "1", Some("default"), None, &mut |_, m| logs.push(m));
        (out.nodes.into_iter().next(), logs)
    }
    fn s<'a>(n: &'a Node, k: &str) -> Option<&'a str> {
        n.get(k)
    }
    fn l(n: &Node, k: &str) -> Option<Vec<String>> {
        match n.0.get(k) {
            Some(NVal::L(v)) => Some(v.clone()),
            _ => None,
        }
    }

    #[test]
    fn host_port() {
        assert_eq!(parse_host_port(Some("a.com:8443/x"), Some("443")), ("a.com".into(), Some("8443".into())));
        assert_eq!(parse_host_port(Some("[::1]:80"), None), ("::1".into(), Some("80".into())));
        assert_eq!(parse_host_port(Some("[::1]"), Some("443")), ("::1".into(), Some("443".into())));
        assert_eq!(parse_host_port(Some("a.com"), Some("443")), ("a.com".into(), Some("443".into())));
        assert_eq!(parse_host_port(Some("a.com:"), None), ("a.com".into(), None));
        assert_eq!(parse_host_port(None, Some("443")), ("".into(), Some("443".into())));
    }

    #[test]
    fn lua_numbers() {
        assert_eq!(lua_num(2048.0), "2048");
        assert_eq!(lua_num(0.5), "0.5");
        assert_eq!(lua_num(1e15), "1e+15");
        assert_eq!(lua_num(123.25), "123.25");
    }

    #[test]
    fn vless_reality_xray() {
        let n = parse(&ctx(), "vless://uuid-1@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.x.com&fp=chrome&pbk=PUB&sid=ab&spx=%2F&type=tcp&headerType=none#My%20Node").unwrap();
        assert_eq!(s(&n, "type"), Some("Xray"));
        assert_eq!(s(&n, "protocol"), Some("vless"));
        assert_eq!(s(&n, "uuid"), Some("uuid-1"));
        assert_eq!(s(&n, "address"), Some("example.com"));
        assert_eq!(s(&n, "port"), Some("443"));
        assert_eq!(s(&n, "transport"), Some("raw"));
        assert_eq!(s(&n, "tcp_guise"), Some("none"));
        assert_eq!(s(&n, "tls"), Some("1"));
        assert_eq!(s(&n, "reality"), Some("1"));
        assert_eq!(s(&n, "reality_publicKey"), Some("PUB"));
        assert_eq!(s(&n, "reality_shortId"), Some("ab"));
        assert_eq!(s(&n, "reality_spiderX"), Some("/"));
        assert_eq!(s(&n, "utls"), Some("1"));
        assert_eq!(s(&n, "fingerprint"), Some("chrome"));
        assert_eq!(s(&n, "tls_serverName"), Some("www.x.com"));
        assert_eq!(s(&n, "flow"), Some("xtls-rprx-vision"));
        assert_eq!(s(&n, "encryption"), Some("none"));
        assert_eq!(s(&n, "tls_allowInsecure"), Some("1"));
        assert_eq!(s(&n, "remarks"), Some("My Node"));
        assert_eq!(s(&n, "add_mode"), Some("1"));
        assert_eq!(s(&n, "timeout"), Some("60"));
        assert_eq!(s(&n, "group"), Some("default"));
    }

    #[test]
    fn vless_ws_singbox_early_data_and_flow_security() {
        let n = parse(&sb_ctx(), "vless://u@[2001:db8::1]:8443?type=ws&host=cdn.x.com&path=%2Fws%3Fed%3D2048&security=tls&sni=&allowInsecure=0#n").unwrap();
        assert_eq!(s(&n, "type"), Some("sing-box"));
        assert_eq!(s(&n, "address"), Some("2001:db8::1"));
        assert_eq!(s(&n, "transport"), Some("ws"));
        assert_eq!(s(&n, "ws_host"), Some("cdn.x.com"));
        assert_eq!(s(&n, "ws_path"), Some("/ws"));
        assert_eq!(s(&n, "ws_enableEarlyData"), Some("1"));
        assert_eq!(s(&n, "ws_maxEarlyData"), Some("2048"));
        assert_eq!(s(&n, "ws_earlyDataHeaderName"), Some("Sec-WebSocket-Protocol"));
        assert_eq!(s(&n, "tls_serverName"), Some("cdn.x.com"));
        assert_eq!(s(&n, "tls_allowInsecure"), Some("0"));
        // flow without security implies tls
        let n = parse(&ctx(), "vless://u@h.com:443?flow=xtls-rprx-vision#n").unwrap();
        assert_eq!(s(&n, "tls"), Some("1"));
        // vless with xhttp forces Xray even when vless_type=sing-box
        let n = parse(&sb_ctx(), "vless://u@h.com:443?type=xhttp&mode=packet-up&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22%5B::2%5D%22%7D%7D#n").unwrap();
        assert_eq!(s(&n, "type"), Some("Xray"));
        assert_eq!(s(&n, "transport"), Some("xhttp"));
        assert_eq!(s(&n, "xhttp_mode"), Some("packet-up"));
        assert_eq!(s(&n, "use_xhttp_extra"), Some("1"));
        assert_eq!(s(&n, "download_address"), Some("::2"));
        assert_eq!(api::base64_decode(s(&n, "xhttp_extra").unwrap()), r#"{"downloadSettings":{"address":"[::2]"}}"#);
        assert_eq!(s(&n, "tls"), Some("0"));
    }

    #[test]
    fn vless_http_grpc_kcp() {
        let n = parse(&ctx(), "vless://u@h.com?type=h2&host=a.com&path=/p#n").unwrap();
        assert_eq!(s(&n, "transport"), Some("xhttp"));
        assert_eq!(s(&n, "xhttp_mode"), Some("stream-one"));
        assert_eq!(s(&n, "xhttp_host"), Some("a.com"));
        assert_eq!(s(&n, "port"), Some("443"));
        let n = parse(&sb_ctx(), "vless://u@h.com:1?type=http&host=a.com&path=/p#n").unwrap();
        assert_eq!(s(&n, "transport"), Some("http"));
        assert_eq!(l(&n, "http_host"), Some(vec!["a.com".to_string()]));
        let n = parse(&ctx(), "vless://u@h.com:1?type=grpc&path=p1&serviceName=svc#n").unwrap();
        assert_eq!(s(&n, "grpc_serviceName"), Some("svc"));
        assert_eq!(s(&n, "grpc_mode"), Some("gun"));
        let n = parse(&ctx(), "vless://u@h.com:1?type=kcp&seed=s#n").unwrap();
        assert_eq!(s(&n, "transport"), Some("mkcp"));
        assert_eq!(s(&n, "mkcp_guise"), Some("none"));
        assert_eq!(s(&n, "mkcp_seed"), Some("s"));
        let n = parse(&ctx(), "vless://u@h.com:1?type=httpupgrade&host=a&path=%2Fu#n").unwrap();
        assert_eq!(s(&n, "httpupgrade_path"), Some("/u"));
    }

    #[test]
    fn vmess_xhttp_extra() {
        let j = r#"{"ps":"x","add":"a.com","port":"443","id":"u","net":"xhttp","path":"/x","mode":"packet-up","extra":{"downloadSettings":{"address":"[::9]"}}}"#;
        let n = parse(&ctx(), &format!("vmess://{}", api::base64_encode(j.as_bytes()))).unwrap();
        assert_eq!(s(&n, "transport"), Some("xhttp"));
        assert_eq!(s(&n, "xhttp_mode"), Some("packet-up"));
        assert_eq!(s(&n, "use_xhttp_extra"), Some("1"));
        assert_eq!(api::base64_decode(s(&n, "xhttp_extra").unwrap()), r#"{"downloadSettings":{"address":"[::9]"}}"#);
        assert_eq!(s(&n, "download_address"), Some("::9"));
    }

    #[test]
    fn vmess_json() {
        let j = r#"{"v":"2","ps":"vm","add":"1.2.3.4","port":443,"id":"uuid","aid":0,"scy":"auto","net":"ws","type":"none","host":"h.com","path":"%2Fpath","tls":"tls","sni":"","alpn":"h2","fp":"chrome","fm":"x%20y"}"#;
        let link = format!("vmess://{}", api::base64_encode(j.as_bytes()));
        let n = parse(&ctx(), &link).unwrap();
        assert_eq!(s(&n, "type"), Some("Xray"));
        assert_eq!(s(&n, "protocol"), Some("vmess"));
        assert_eq!(s(&n, "port"), Some("443"));
        assert_eq!(s(&n, "alter_id"), Some("0"));
        assert_eq!(s(&n, "ws_path"), Some("/path"));
        assert_eq!(s(&n, "ws_host"), Some("h.com"));
        assert_eq!(s(&n, "security"), Some("auto"));
        assert_eq!(s(&n, "tls_serverName"), Some("h.com"));
        assert_eq!(s(&n, "utls"), Some("1"));
        assert_eq!(s(&n, "alpn"), Some("h2"));
        assert_eq!(s(&n, "use_finalmask"), Some("1"));
        assert_eq!(api::base64_decode(s(&n, "finalmask").unwrap()), "x y");
        // tcp + http header type
        let j = r#"{"ps":"t","add":"a.com","port":"80","id":"u","net":"tcp","type":"http","host":"x.com","path":"/a"}"#;
        let n = parse(&ctx(), &format!("vmess://{}", api::base64_encode(j.as_bytes()))).unwrap();
        assert_eq!(s(&n, "transport"), Some("raw"));
        assert_eq!(s(&n, "tcp_guise"), Some("http"));
        assert_eq!(l(&n, "tcp_guise_http_host"), Some(vec!["x.com".to_string()]));
        assert_eq!(s(&n, "tls"), Some("0"));
        // sing-box rejects kcp
        let j = r#"{"ps":"k","add":"a.com","port":"80","id":"u","net":"kcp"}"#;
        let (n, logs) = parse_logs(&sb_ctx(), &format!("vmess://{}", api::base64_encode(j.as_bytes())));
        assert!(n.is_none());
        assert!(logs[0].contains("Sing-Box does not support"));
    }

    #[test]
    fn vmess_legacy() {
        let b = api::base64_encode(b"auto:uuid-9@1.1.1.1:8080");
        let n = parse(&ctx(), &format!("vmess://{}?remarks=Old&obfs=websocket&path=%2Fw&obfsParam=%7B%22Host%22%3A%22h.com%22%7D&tls=1&peer=s.com", b)).unwrap();
        assert_eq!(s(&n, "uuid"), Some("uuid-9"));
        assert_eq!(s(&n, "security"), Some("auto"));
        assert_eq!(s(&n, "address"), Some("1.1.1.1"));
        assert_eq!(s(&n, "port"), Some("8080"));
        assert_eq!(s(&n, "transport"), Some("ws"));
        assert_eq!(s(&n, "ws_host"), Some("h.com"));
        assert_eq!(s(&n, "tls_serverName"), Some("s.com"));
        assert_eq!(s(&n, "remarks"), Some("Old"));
        // not JSON and no '?' → parse error
        let (n, logs) = parse_logs(&ctx(), &format!("vmess://{}", api::base64_encode(b"garbage")));
        assert!(n.is_none());
        assert!(logs[0].ends_with("Parsing error, skip this node."));
    }

    #[test]
    fn ss_variants() {
        // SIP002 with plugin, Xray converts obfs-local http
        let n = parse(&ctx(), "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#name").unwrap();
        assert_eq!(s(&n, "type"), Some("Xray"));
        assert_eq!(s(&n, "protocol"), Some("shadowsocks"));
        assert_eq!(s(&n, "method"), Some("aes-256-gcm"));
        assert_eq!(s(&n, "ss_method"), Some("aes-256-gcm"));
        assert_eq!(s(&n, "password"), Some("pass"));
        assert_eq!(s(&n, "tcp_guise"), Some("http"));
        assert_eq!(l(&n, "tcp_guise_http_host"), Some(vec!["bing.com".to_string()]));
        assert_eq!(l(&n, "tcp_guise_http_path"), Some(vec!["/".to_string()]));
        assert!(!n.has("plugin"));
        // plain method:pass, 2022 key with '%' encoding
        let n = parse(&ctx(), "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3").unwrap();
        assert_eq!(s(&n, "method"), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(s(&n, "password"), Some("YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="));
        // whole base64
        let b = api::base64_encode(b"chacha20-poly1305:pw@a.com:443");
        let n = parse(&ctx(), &format!("ss://{}#x", b)).unwrap();
        assert_eq!(s(&n, "method"), Some("chacha20-ietf-poly1305"));
        assert_eq!(s(&n, "address"), Some("a.com"));
        // v2rayN extended ws + tls
        let n = parse(&ctx(), "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss").unwrap();
        assert_eq!(s(&n, "transport"), Some("ws"));
        assert_eq!(s(&n, "ws_path"), Some("/testpath"));
        assert_eq!(s(&n, "tls"), Some("1"));
        assert_eq!(s(&n, "alpn"), Some("h3,h2,http/1.1"));
        assert!(!n.has("utls"));
        assert_eq!(s(&n, "remarks"), Some("test-1@ss"));
        // SS-Rust with type= is discarded
        let mut c = ctx();
        c.ss_type = Some("shadowsocks-rust".into());
        let (n, logs) = parse_logs(&c, "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?type=tcp#r");
        assert!(n.is_none());
        assert!(logs.iter().any(|m| m.contains("Please replace Xray or Sing-Box")));
        // SS-Rust keeps plugin
        let n = parse(&c, "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=v2ray-plugin%3Bserver#r").unwrap();
        assert_eq!(s(&n, "type"), Some("SS-Rust"));
        assert_eq!(s(&n, "plugin"), Some("v2ray-plugin"));
        assert_eq!(s(&n, "plugin_opts"), Some("server"));
        assert_eq!(s(&n, "plugin_enabled"), Some("1"));
    }

    #[test]
    fn ss_shadow_tls() {
        let st = api::base64_encode(br#"{"version":"3","password":"stpw","host":"apple.com","fingerprint":"chrome"}"#);
        let n = parse(&sb_ctx(), &format!("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?shadow-tls={}#st", api::url_encode(&st))).unwrap();
        assert_eq!(s(&n, "type"), Some("sing-box"));
        assert_eq!(s(&n, "shadowtls"), Some("1"));
        assert_eq!(s(&n, "shadowtls_version"), Some("3"));
        assert_eq!(s(&n, "shadowtls_password"), Some("stpw"));
        assert_eq!(s(&n, "shadowtls_serverName"), Some("apple.com"));
        assert_eq!(s(&n, "shadowtls_utls"), Some("1"));
        assert_eq!(s(&n, "shadowtls_fingerprint"), Some("chrome"));
        // SIP003 shadow-tls plugin on sing-box
        let n = parse(&sb_ctx(), "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=shadow-tls%3Bhost%3Da.com%3Bpassword%3Dp%3Bversion%3D3#x").unwrap();
        assert_eq!(s(&n, "plugin"), Some("shadow-tls"));
        assert_eq!(s(&n, "shadowtls_version"), Some("3"));
        assert_eq!(s(&n, "shadowtls_password"), Some("p"));
        assert!(!n.has("plugin_opts"));
        // Xray: shadow-tls unsupported
        let (n, logs) = parse_logs(&ctx(), &format!("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?shadow-tls={}#st", api::url_encode(&st)));
        assert!(n.is_none());
        assert!(logs[0].contains("xray unsupport shadow-tls plugin."));
        // SS-Rust gets the opts string
        let mut c = ctx();
        c.ss_type = Some("shadowsocks-rust".into());
        let n = parse(&c, &format!("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?shadow-tls={}#st", api::url_encode(&st))).unwrap();
        assert_eq!(s(&n, "plugin_opts"), Some("v3=1;passwd=stpw;host=apple.com;fingerprint=chrome"));
        assert_eq!(rewrite_plugin_opts("version=2;host=a;password=b;version=3"), "v2=1;host=a;passwd=b;v3=1");
    }

    #[test]
    fn trojan_variants() {
        let n = parse(&ctx(), "trojan://p%40ss@t.com:443?peer=p.com&sni=s.com&type=grpc&serviceName=gs#T").unwrap();
        assert_eq!(s(&n, "password"), Some("p@ss"));
        assert_eq!(s(&n, "tls"), Some("1"));
        assert_eq!(s(&n, "tls_serverName"), Some("p.com"));
        assert_eq!(s(&n, "grpc_serviceName"), Some("gs"));
        assert_eq!(s(&n, "transport"), Some("grpc"));
        let n = parse(&ctx(), "trojan://p@t.com?security=none#T").unwrap();
        assert!(!n.has("tls"));
        assert_eq!(s(&n, "transport"), Some("raw"));
        assert_eq!(s(&n, "port"), Some("443"));
        // spaces around '#' and &amp;
        let n = parse(&ctx(), "trojan://p@t.com:1?allowInsecure=0&amp;sni=x.com  #  Name").unwrap();
        assert_eq!(s(&n, "remarks"), Some("Name"));
        assert_eq!(s(&n, "tls_allowInsecure"), Some("0"));
        assert_eq!(s(&n, "tls_serverName"), Some("x.com"));
    }

    #[test]
    fn ssr_link() {
        let inner = format!(
            "1.2.3.4:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{}/?obfsparam={}&protoparam=&remarks={}&group=Zw",
            api::base64_encode(b"pw").trim_end_matches('='),
            api::base64_encode(b"o.com").trim_end_matches('='),
            api::base64_encode("节点".as_bytes())
        );
        let link = format!("ssr://{}", api::base64_encode(inner.as_bytes()).replace('+', "-").replace('/', "_"));
        let n = parse(&ctx(), &link).unwrap();
        assert_eq!(s(&n, "type"), Some("SSR"));
        assert_eq!(s(&n, "address"), Some("1.2.3.4"));
        assert_eq!(s(&n, "port"), Some("8388"));
        assert_eq!(s(&n, "protocol"), Some("auth_aes128_md5"));
        assert_eq!(s(&n, "method"), Some("aes-256-cfb"));
        assert_eq!(s(&n, "obfs"), Some("tls1.2_ticket_auth"));
        assert_eq!(s(&n, "password"), Some("pw"));
        assert_eq!(s(&n, "obfs_param"), Some("o.com"));
        assert_eq!(s(&n, "protocol_param"), Some(""));
        assert_eq!(s(&n, "remarks"), Some("节点"));
    }

    #[test]
    fn hysteria_family() {
        let n = parse(&ctx(), "hysteria://h.com:1234?auth=a%40b&upmbps=10&downmbps=50&obfsParam=o&peer=p.com&insecure=1&mport=2000-3000#H1").unwrap();
        assert_eq!(s(&n, "protocol"), Some("hysteria"));
        assert_eq!(s(&n, "hysteria_auth_password"), Some("a%40b"));
        assert_eq!(s(&n, "hysteria_auth_type"), Some("string"));
        assert_eq!(s(&n, "hysteria_hop"), Some("2000-3000"));
        assert_eq!(s(&n, "tls_serverName"), Some("p.com"));
        assert!(!n.has("tls"));
        let n = parse(&ctx(), "hy2://pass%2F1@h.com:443/?SNI=s.com&obfs=salamander&obfs-password=op&pinSHA256=AB&mport=443,8443#H2").unwrap();
        assert_eq!(s(&n, "type"), Some("sing-box"));
        assert_eq!(s(&n, "protocol"), Some("hysteria2"));
        assert_eq!(s(&n, "hysteria2_auth_password"), Some("pass/1"));
        assert_eq!(s(&n, "tls_serverName"), Some("s.com"));
        assert_eq!(s(&n, "hysteria2_obfs_type"), Some("salamander"));
        assert_eq!(s(&n, "hysteria2_obfs_password"), Some("op"));
        assert_eq!(s(&n, "tls_pinSHA256"), Some("AB"));
        let n = parse(&ctx(), "hysteria2://p@h.com?obfs=gecko&obfs_password=x#g").unwrap();
        assert_eq!(s(&n, "hysteria2_obfs_type"), Some("gecko"));
        assert_eq!(s(&n, "hysteria2_obfs_MinPacketSize"), Some("512"));
        assert_eq!(s(&n, "hysteria2_obfs_MaxPacketSize"), Some("1200"));
        assert_eq!(s(&n, "port"), Some("443"));
    }

    #[test]
    fn tuic_anytls_naive_snell() {
        let n = parse(&ctx(), "tuic://uuid%3Apw@t.com:443?congestion_control=bbr&ALPN=h3&sni=s&allow_insecure=0#T").unwrap();
        assert_eq!(s(&n, "uuid"), Some("uuid"));
        assert_eq!(s(&n, "password"), Some("pw"));
        assert_eq!(s(&n, "tuic_congestion_control"), Some("bbr"));
        assert_eq!(s(&n, "tuic_udp_relay_mode"), Some("native"));
        assert_eq!(s(&n, "tuic_alpn"), Some("h3"));
        assert_eq!(s(&n, "tls_allowInsecure"), Some("0"));
        let n = parse(&ctx(), "anytls://pw@a.com:8443?security=reality&pbk=K&sid=1&SNI=s.com#A").unwrap();
        assert_eq!(s(&n, "protocol"), Some("anytls"));
        assert_eq!(s(&n, "reality"), Some("1"));
        assert_eq!(s(&n, "tls_serverName"), Some("s.com"));
        assert_eq!(s(&n, "tls"), Some("1"));
        let n = parse(&ctx(), "naive+quic://user:p%40ss@n.com:443?insecure-concurrency=2#N").unwrap();
        assert_eq!(s(&n, "username"), Some("user"));
        assert_eq!(s(&n, "password"), Some("p@ss"));
        assert_eq!(s(&n, "naive_quic"), Some("1"));
        assert_eq!(s(&n, "naive_congestion_control"), Some("bbr"));
        assert_eq!(s(&n, "naive_insecure_concurrency"), Some("2"));
        let n = parse(&ctx(), "naive+https://onlypass@n.com#N").unwrap();
        assert_eq!(s(&n, "username"), Some(""));
        assert_eq!(s(&n, "password"), Some("onlypass"));
        let n = parse(&ctx(), "snell://psk1@s.com:6000?version=4&obfs=http&obfs-host=b.com&reuse=1#S").unwrap();
        assert_eq!(s(&n, "snell_psk"), Some("psk1"));
        assert_eq!(s(&n, "snell_obfs_mode"), Some("http"));
        assert_eq!(s(&n, "snell_obfs_host"), Some("b.com"));
        assert_eq!(s(&n, "snell_reuse"), Some("1"));
        let n = parse(&ctx(), "snell://s.com:6000?psk=k&version=5&mode=m#S").unwrap();
        assert_eq!(s(&n, "snell_psk"), Some("k"));
        assert_eq!(s(&n, "snell_mode"), Some("m"));
        assert!(!n.has("snell_obfs_mode"));
    }

    #[test]
    fn filters_and_fallbacks() {
        // missing remarks → address:port; 127.0.0.1 discarded; unsupported scheme logged
        let n = parse(&ctx(), "trojan://p@t.com:9").unwrap();
        assert_eq!(s(&n, "remarks"), Some("t.com:9"));
        assert!(parse(&ctx(), "trojan://p@127.0.0.1:9#x").is_none());
        let (n, logs) = parse_logs(&ctx(), "socks://abc#x");
        assert!(n.is_none());
        assert!(logs[0].contains("socks type node subscriptions are not currently supported"));
        // core missing
        let mut c = ctx();
        c.cores.singbox = false;
        let (n, logs) = parse_logs(&c, "tuic://a:b@h.com#t");
        assert!(n.is_none());
        assert!(logs[0].contains("Tuic"));
        // keyword filter only for subscriptions
        let mut c = ctx();
        c.filter = KeywordFilter { mode: "1".into(), discard: vec!["Expire".into()], keep: vec![] };
        let raw = api::base64_encode(b"trojan://p@a.com:1#Expire 2026\ntrojan://p@b.com:1#HK");
        let out = parse_link(&c, &raw, "2", Some("sub"), None, &mut |_, _| {});
        assert_eq!(out.nodes.len(), 1);
        assert_eq!(out.remarks_seen.len(), 2);
        assert_eq!(out.nodes[0].get("group"), Some("sub"));
        let f = KeywordFilter { mode: "3".into(), discard: split_filter_keywords(&["a|b".into(), "b".into()]), keep: vec!["keep".into()] };
        assert_eq!(f.discard, vec!["a".to_string(), "b".to_string()]);
        assert!(f.discards("xa"));
        assert!(!f.discards("xa keep"));
        assert!(!KeywordFilter { mode: "2".into(), discard: vec![], keep: vec!["HK".into()] }.discards("HK 1"));
    }

    #[test]
    fn ssd_document() {
        let doc = r#"{"airport":"AP","port":8388,"encryption":"aes-128-gcm","password":"root","servers":[{"server":"a.com","remarks":"S1"},{"server":"b.com","port":"9","password":"own"}]}"#;
        let raw = format!("ssd://{}", api::base64_encode(doc.as_bytes()));
        let out = parse_link(&ctx(), &raw, "2", Some("grp"), None, &mut |_, _| {});
        assert_eq!(out.nodes.len(), 2);
        assert_eq!(out.nodes[0].get("port"), Some("8388"));
        assert_eq!(out.nodes[0].get("method"), Some("aes-128-gcm"));
        assert_eq!(out.nodes[0].get("group"), Some("AP"));
        assert_eq!(out.nodes[1].get("password"), Some("own"));
        assert_eq!(out.nodes[1].get("remarks"), Some("b.com:9"));
    }

    #[test]
    fn subscribe_info_remarks() {
        assert_eq!(subscribe_info_from_remarks("套餐到期： 2026-01-01"), (Some("2026-01-01".into()), None));
        assert_eq!(subscribe_info_from_remarks("剩余流量：10 GB"), (None, Some("10GB".into())));
        assert_eq!(subscribe_info_from_remarks("HK 01"), (None, None));
    }
}
