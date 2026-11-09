//! Minimal UCI implementation.
//!
//! Reading: a native parser of `/etc/config/<name>` (or `$PASSWALL2_UCI_DIR/<name>`),
//! including uncommitted changes is NOT supported (LuCI commits before calling us,
//! and upstream scripts also only read committed config via `uci -q get`... which
//! actually includes /tmp/.uci deltas; we fall back to `uci show` when a delta exists).
//!
//! Writing: always through the `uci` CLI (`uci -q batch`) so locking / delta
//! semantics stay identical to stock OpenWrt tools.

use indexmap::IndexMap;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Single(String),
    List(Vec<String>),
}

impl Value {
    /// Upstream shell (`uci get`) returns lists space-joined.
    pub fn as_string(&self) -> String {
        match self {
            Value::Single(s) => s.clone(),
            Value::List(l) => l.join(" "),
        }
    }
    pub fn as_list(&self) -> Vec<String> {
        match self {
            Value::Single(s) => s.split_whitespace().map(|x| x.to_string()).collect(),
            Value::List(l) => l.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub stype: String,
    pub anonymous: bool,
    /// index among sections of the same type (for `@type[n]`)
    pub index: usize,
    pub options: IndexMap<String, Value>,
}

impl Section {
    pub fn get(&self, opt: &str) -> Option<String> {
        self.options.get(opt).map(|v| v.as_string())
    }
    /// value or "" (Lua `x or ""` idiom)
    pub fn s(&self, opt: &str) -> String {
        self.get(opt).unwrap_or_default()
    }
    /// value or default if missing OR empty
    pub fn get_or(&self, opt: &str, def: &str) -> String {
        match self.get(opt) {
            Some(v) if !v.is_empty() => v,
            _ => def.to_string(),
        }
    }
    pub fn list(&self, opt: &str) -> Vec<String> {
        self.options.get(opt).map(|v| v.as_list()).unwrap_or_default()
    }
    /// Raw list (does not split single values on whitespace).
    pub fn list_raw(&self, opt: &str) -> Vec<String> {
        match self.options.get(opt) {
            Some(Value::List(l)) => l.clone(),
            Some(Value::Single(s)) => vec![s.clone()],
            None => vec![],
        }
    }
    pub fn is(&self, opt: &str, val: &str) -> bool {
        self.get(opt).as_deref() == Some(val)
    }
    /// `opt == "1"`
    pub fn flag(&self, opt: &str) -> bool {
        self.is(opt, "1")
    }
    pub fn has(&self, opt: &str) -> bool {
        self.options.contains_key(opt)
    }
    /// Section as a JSON object (LuCI-like: `.name`, `.type`, `.anonymous`, `.index`).
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert(".name".into(), self.name.clone().into());
        m.insert(".type".into(), self.stype.clone().into());
        m.insert(".anonymous".into(), self.anonymous.into());
        m.insert(".index".into(), self.index.into());
        for (k, v) in &self.options {
            match v {
                Value::Single(s) => m.insert(k.clone(), s.clone().into()),
                Value::List(l) => m.insert(k.clone(), l.clone().into()),
            };
        }
        serde_json::Value::Object(m)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub name: String,
    pub sections: Vec<Section>,
}

pub fn conf_dir() -> String {
    std::env::var("PASSWALL2_UCI_DIR").unwrap_or_else(|_| "/etc/config".to_string())
}

fn uci_cmd() -> Command {
    let mut c = Command::new("uci");
    if let Ok(d) = std::env::var("PASSWALL2_UCI_DIR") {
        c.arg("-c").arg(d);
    }
    c
}

/// The id libuci gives an anonymous section (`uci_fixup_section` in list.c):
/// `cfg%02x%04x` of the package's section counter and `djbhash(type) % 65536`. The hash is
/// taken when the section is allocated, before any option exists, so it covers the type only.
/// (`str[i]` is a plain `char`: for non-ASCII types the result depends on the target's char
/// signedness — `load` asks uci in that case; here bytes are treated as signed, like x86/MIPS.)
pub fn libuci_anon_name(counter: usize, stype: &str) -> String {
    let mut h: u32 = 5381;
    for &b in stype.as_bytes() {
        h = (h << 5).wrapping_add(h).wrapping_add(b as i8 as i32 as u32);
    }
    let h = h & 0x7FFF_FFFF;
    format!("cfg{:02x}{:04x}", counter, h % (1 << 16))
}

impl Config {
    /// Load a config. Missing file => empty config.
    pub fn load(name: &str) -> Config {
        // Pending deltas (uncommitted changes) exist under /tmp/.uci/<name>;
        // `uci -q export` merges them, so prefer it when available.
        let delta = std::path::Path::new("/tmp/.uci").join(name);
        if std::env::var("PASSWALL2_UCI_DIR").is_err() && delta.exists() {
            if let Ok(out) = uci_cmd().args(["-q", "export", name]).output() {
                if out.status.success() {
                    let mut cfg = Self::parse(name, &String::from_utf8_lossy(&out.stdout));
                    // Anonymous names are assigned when libuci parses the *committed* file and
                    // then survive the delta replay (which may add/remove sections), so they
                    // cannot be derived from the merged export: ask uci.
                    if cfg.sections.iter().any(|s| s.anonymous) {
                        cfg.fix_anonymous_names();
                    }
                    return cfg;
                }
            }
        }
        let path = format!("{}/{}", conf_dir(), name);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut cfg = Self::parse(name, &text);
        // `parse` already reproduces libuci's anonymous names; only a non-ASCII section type
        // (whose hash depends on the target's char signedness) needs uci itself.
        if cfg.sections.iter().any(|s| s.anonymous && !s.stype.is_ascii()) {
            cfg.fix_anonymous_names();
        }
        cfg
    }

    /// Replace the anonymous ids with the ones `uci -X show` reports (forks `uci`; only
    /// needed when the native naming in [`Config::parse`] cannot be trusted).
    pub fn fix_anonymous_names(&mut self) {
        if !self.sections.iter().any(|s| s.anonymous) {
            return;
        }
        let Ok(out) = uci_cmd().args(["-q", "-X", "show", &self.name]).output() else { return };
        let text = String::from_utf8_lossy(&out.stdout);
        let prefix = format!("{}.", self.name);
        let names: Vec<String> = text
            .lines()
            .filter_map(|l| {
                let rest = l.strip_prefix(&prefix)?;
                let (sec, _) = rest.split_once('=')?;
                if sec.contains('.') {
                    None
                } else {
                    Some(sec.to_string())
                }
            })
            .collect();
        if names.len() == self.sections.len() {
            for (s, n) in self.sections.iter_mut().zip(names) {
                s.name = n;
            }
        }
    }

    pub fn parse(name: &str, text: &str) -> Config {
        let mut cfg = Config { name: name.to_string(), sections: vec![] };
        // libuci's per-package section counter: bumped for every *newly allocated* section
        // (a repeated `config <type> '<name>'` reopens the existing one and does not count).
        let mut alloc_counter = 0usize;
        let mut named_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut type_count: IndexMap<String, usize> = IndexMap::new();
        for toks in tokenize_stmts(text) {
            if toks.is_empty() {
                continue;
            }
            match toks[0].as_str() {
                "package" => {}
                "config" => {
                    let stype = toks.get(1).cloned().unwrap_or_default();
                    let (sname, anon) = match toks.get(2) {
                        Some(n) if !n.is_empty() => {
                            if named_seen.insert(n.clone()) {
                                alloc_counter += 1;
                            }
                            (n.clone(), false)
                        }
                        _ => {
                            alloc_counter += 1;
                            (libuci_anon_name(alloc_counter, &stype), true)
                        }
                    };
                    let idx = type_count.entry(stype.clone()).or_insert(0);
                    let index = *idx;
                    *idx += 1;
                    cfg.sections.push(Section { name: sname, stype, anonymous: anon, index, options: IndexMap::new() });
                }
                "option" => {
                    if let (Some(sec), Some(k)) = (cfg.sections.last_mut(), toks.get(1)) {
                        let v = toks.get(2).cloned().unwrap_or_default();
                        sec.options.insert(k.clone(), Value::Single(v));
                    }
                }
                "list" => {
                    if let (Some(sec), Some(k)) = (cfg.sections.last_mut(), toks.get(1)) {
                        let v = toks.get(2).cloned().unwrap_or_default();
                        match sec.options.get_mut(k) {
                            Some(Value::List(l)) => l.push(v),
                            _ => {
                                sec.options.insert(k.clone(), Value::List(vec![v]));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        cfg
    }

    /// Resolve `name` or `@type[idx]` (negative idx allowed).
    pub fn section(&self, sref: &str) -> Option<&Section> {
        if let Some(rest) = sref.strip_prefix('@') {
            let (t, idx) = rest.split_once('[')?;
            let idx: i64 = idx.trim_end_matches(']').parse().ok()?;
            let list: Vec<&Section> = self.sections.iter().filter(|s| s.stype == t).collect();
            let i = if idx < 0 { list.len() as i64 + idx } else { idx };
            if i < 0 {
                return None;
            }
            return list.get(i as usize).copied();
        }
        self.sections.iter().find(|s| s.name == sref)
    }

    pub fn get(&self, sref: &str, opt: &str) -> Option<String> {
        self.section(sref)?.get(opt)
    }
    /// `uci -q get` with default when missing or empty.
    pub fn get_or(&self, sref: &str, opt: &str, def: &str) -> String {
        match self.get(sref, opt) {
            Some(v) if !v.is_empty() => v,
            _ => def.to_string(),
        }
    }
    pub fn s(&self, sref: &str, opt: &str) -> String {
        self.get(sref, opt).unwrap_or_default()
    }
    /// `config_t_get TYPE OPTION DEFAULT` on `@TYPE[0]`.
    pub fn t_get(&self, stype: &str, opt: &str, def: &str) -> String {
        self.get_or(&format!("@{}[0]", stype), opt, def)
    }
    pub fn list(&self, sref: &str, opt: &str) -> Vec<String> {
        self.section(sref).map(|s| s.list(opt)).unwrap_or_default()
    }
    pub fn list_raw(&self, sref: &str, opt: &str) -> Vec<String> {
        self.section(sref).map(|s| s.list_raw(opt)).unwrap_or_default()
    }
    pub fn sections_of<'a>(&'a self, stype: &'a str) -> impl Iterator<Item = &'a Section> + 'a {
        self.sections.iter().filter(move |s| s.stype == stype)
    }
    pub fn first_of(&self, stype: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.stype == stype)
    }
    pub fn stype(&self, sref: &str) -> Option<String> {
        self.section(sref).map(|s| s.stype.clone())
    }
}

/// Split a whole config text into statements (token lists). Newlines end a
/// statement only outside quotes, so multi-line quoted values are preserved
/// (as libuci does).
#[allow(unused_assignments)]
fn tokenize_stmts(text: &str) -> Vec<Vec<String>> {
    let mut stmts = vec![];
    let mut toks: Vec<String> = vec![];
    let mut cur = String::new();
    let mut in_tok = false;
    let mut chars = text.chars().peekable();
    macro_rules! end_tok {
        () => {
            if in_tok {
                toks.push(std::mem::take(&mut cur));
                in_tok = false;
            }
        };
    }
    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                end_tok!();
                if !toks.is_empty() {
                    stmts.push(std::mem::take(&mut toks));
                }
            }
            '#' if !in_tok => {
                // comment to end of line
                while let Some(&n) = chars.peek() {
                    if n == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            ' ' | '\t' | '\r' => end_tok!(),
            '\'' => {
                in_tok = true;
                for c2 in chars.by_ref() {
                    if c2 == '\'' {
                        break;
                    }
                    cur.push(c2);
                }
            }
            '"' => {
                in_tok = true;
                while let Some(c2) = chars.next() {
                    match c2 {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                if n != '\n' {
                                    cur.push(n)
                                }
                            }
                        }
                        _ => cur.push(c2),
                    }
                }
            }
            '\\' => {
                in_tok = true;
                if let Some(n) = chars.next() {
                    if n != '\n' {
                        cur.push(n)
                    }
                }
            }
            _ => {
                in_tok = true;
                cur.push(c)
            }
        }
    }
    end_tok!();
    if !toks.is_empty() {
        stmts.push(toks);
    }
    stmts
}

/// Quote a value for `uci batch` (single-quote style).
pub fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Builder for `uci -q batch` writes. Commands are applied in order; call
/// `commit()` to run them and commit the touched configs.
#[derive(Default)]
pub struct Batch {
    lines: Vec<String>,
    configs: Vec<String>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }
    fn touch(&mut self, path: &str) {
        let c = path.split('.').next().unwrap_or("").to_string();
        if !c.is_empty() && !self.configs.contains(&c) {
            self.configs.push(c);
        }
    }
    /// `set config.section.option=value` or `set config.section=type`
    pub fn set(&mut self, path: &str, value: &str) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("set {}={}", path, quote(value)));
        self
    }
    pub fn delete(&mut self, path: &str) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("delete {}", path));
        self
    }
    pub fn add_list(&mut self, path: &str, value: &str) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("add_list {}={}", path, quote(value)));
        self
    }
    pub fn del_list(&mut self, path: &str, value: &str) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("del_list {}={}", path, quote(value)));
        self
    }
    /// Replace a list option entirely.
    pub fn set_list(&mut self, path: &str, values: &[String]) -> &mut Self {
        self.delete(path);
        for v in values {
            self.add_list(path, v);
        }
        self
    }
    /// Named section create: `set config.name=type`
    pub fn section(&mut self, config: &str, name: &str, stype: &str) -> &mut Self {
        self.set(&format!("{}.{}", config, name), stype)
    }
    pub fn rename(&mut self, path: &str, newname: &str) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("rename {}={}", path, newname));
        self
    }
    pub fn reorder(&mut self, path: &str, pos: usize) -> &mut Self {
        self.touch(path);
        self.lines.push(format!("reorder {}={}", path, pos));
        self
    }
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
    /// Run the batch (without commit).
    pub fn apply(&self) -> std::io::Result<()> {
        if self.lines.is_empty() {
            return Ok(());
        }
        let mut child = uci_cmd().args(["-q", "batch"]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn()?;
        {
            let stdin = child.stdin.as_mut().unwrap();
            for l in &self.lines {
                writeln!(stdin, "{}", l)?;
            }
        }
        child.wait()?;
        Ok(())
    }
    pub fn commit(&self) -> std::io::Result<()> {
        self.apply()?;
        for c in &self.configs {
            commit(c);
        }
        Ok(())
    }
}

/// `uci add <config> <type>` → returns new anonymous section id.
pub fn add(config: &str, stype: &str) -> Option<String> {
    let out = uci_cmd().args(["-q", "add", config, stype]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn commit(config: &str) {
    let _ = uci_cmd().args(["-q", "commit", config]).status();
}

pub fn revert(config: &str) {
    let _ = uci_cmd().args(["-q", "revert", config]).status();
}

/// Generate a uci-style random section id (`cfg` + 6 hex) or a 32 hex node id.
pub fn gen_id(len: usize) -> String {
    let mut buf = vec![0u8; len.div_ceil(2)];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    let mut s: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    s.truncate(len);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_basic() {
        let t = "config global\n\toption enabled '0'\n\tlist x 'a b'\n\tlist x \"c\"\n\nconfig nodes 'abc'\n\toption remarks 'it''s'\n";
        let c = Config::parse("passwall2", t);
        assert_eq!(c.get("@global[0]", "enabled").as_deref(), Some("0"));
        assert_eq!(c.list_raw("@global[0]", "x"), vec!["a b".to_string(), "c".to_string()]);
        assert_eq!(c.section("abc").unwrap().stype, "nodes");
        assert_eq!(c.section("@nodes[-1]").unwrap().name, "abc");
        let m = Config::parse("p", "config shunt_rules 'r'\n\toption domain_list 'a.com\nb.com\n'\n\toption x '1' # c\n");
        assert_eq!(m.s("r", "domain_list"), "a.com\nb.com\n");
        assert_eq!(m.s("r", "x"), "1");
    }

    #[test]
    fn anonymous_names_match_libuci() {
        // expected ids taken from `uci -X show` on OpenWrt 24.10 / 25.12
        let t = "config global\n\toption enabled '0'\n\nconfig nodes 'myshunt'\n\toption remarks 'x'\n\nconfig global_delay\n\toption start_daemon '1'\n\nconfig global_rules\n\tlist x 'q'\n\nconfig acl_rule\n\toption remarks 'a'\n\nconfig acl_rule\n";
        let c = Config::parse("t1", t);
        let names: Vec<&str> = c.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["cfg013fd6", "myshunt", "cfg032924", "cfg0446c0", "cfg0530ec", "cfg0630ec"]);
        assert!(c.sections[0].anonymous && !c.sections[1].anonymous);
        // a reopened named section does not consume a counter value; `config c ''` is anonymous
        let c = Config::parse("t4", "config a 'x'\n\nconfig b\n\nconfig a 'x'\n\nconfig c\n\nconfig c ''\n\nconfig d\n");
        let anon: Vec<&str> = c.sections.iter().filter(|s| s.anonymous).map(|s| s.name.as_str()).collect();
        assert_eq!(anon, ["cfg02b607", "cfg03b608", "cfg04b608", "cfg05b609"]);
        // counter above 0xff widens (printf %02x), no wrap
        assert_eq!(libuci_anon_name(1, "sub"), "cfg01ab8f");
        assert_eq!(libuci_anon_name(0x100, "sub"), "cfg100ab8f");
        assert_eq!(libuci_anon_name(0x12c, "sub"), "cfg12cab8f");
        assert_eq!(libuci_anon_name(1, "dnsmasq"), "cfg01411c");
        assert_eq!(libuci_anon_name(10, "global_singbox"), "cfg0a5c2f");
        assert_eq!(c.section("cfg05b609").map(|s| s.stype.as_str()), Some("d"));
    }
}
