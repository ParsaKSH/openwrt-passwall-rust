//! The controller's LuCI uci cursor: reads see earlier writes of the same request (like
//! `uci_get` after `uci_set` on one cursor), writes are queued in a `uci batch` and committed
//! by [`Store::save`] (`api.uci_save`).

use crate::uci::{Batch, Config, Section, Value as UVal};
use serde_json::{Map, Value};

pub struct Store {
    pub cfg: Config,
    pub batch: Batch,
    conf: String,
}

impl Store {
    pub fn load(conf: &str) -> Store {
        Store::from_config(Config::load(conf))
    }
    pub fn from_config(cfg: Config) -> Store {
        let conf = cfg.name.clone();
        Store { cfg, batch: Batch::new(), conf }
    }

    fn idx(&self, sref: &str) -> Option<usize> {
        let s = self.cfg.section(sref)?;
        let name = s.name.clone();
        self.cfg.sections.iter().position(|x| x.name == name)
    }
    /// uci path of a section for the batch: `@type[N]` refs are kept (stable for singletons and
    /// independent of synthetic anonymous names), others use the section name.
    fn path(&self, sref: &str) -> String {
        if sref.starts_with('@') {
            format!("{}.{}", self.conf, sref)
        } else {
            match self.cfg.section(sref) {
                Some(s) => format!("{}.{}", self.conf, s.name),
                None => format!("{}.{}", self.conf, sref),
            }
        }
    }

    pub fn exists(&self, sref: &str) -> bool {
        self.cfg.section(sref).is_some()
    }
    pub fn section(&self, sref: &str) -> Option<&Section> {
        self.cfg.section(sref)
    }
    pub fn get(&self, sref: &str, opt: &str) -> Option<String> {
        self.cfg.get(sref, opt)
    }
    /// List option as a table (single value → one element), like the cursor's `get`.
    pub fn list(&self, sref: &str, opt: &str) -> Vec<String> {
        self.cfg.list_raw(sref, opt)
    }
    /// Names of the sections of `stype` (uci_foreach order).
    pub fn names_of(&self, stype: &str) -> Vec<String> {
        self.cfg.sections_of(stype).map(|s| s.name.clone()).collect()
    }

    /// `api.uci_set(section, option, value)`: empty value deletes the option.
    pub fn set(&mut self, sref: &str, opt: &str, val: &str) {
        if val.is_empty() {
            self.del(sref, opt);
            return;
        }
        let Some(i) = self.idx(sref) else { return };
        self.cfg.sections[i].options.insert(opt.to_string(), UVal::Single(val.to_string()));
        let p = format!("{}.{}", self.path(sref), opt);
        self.batch.set(&p, val);
    }
    /// `api.uci_set(section, option, table)`: empty table deletes the option.
    pub fn set_list(&mut self, sref: &str, opt: &str, vals: &[String]) {
        if vals.is_empty() {
            self.del(sref, opt);
            return;
        }
        let Some(i) = self.idx(sref) else { return };
        self.cfg.sections[i].options.insert(opt.to_string(), UVal::List(vals.to_vec()));
        let p = format!("{}.{}", self.path(sref), opt);
        self.batch.set_list(&p, vals);
    }
    /// `uci_set` with a parsed JSON value (controller `update_config`): arrays → list,
    /// numbers → string, booleans → "1"/"0", null/""/[] → delete.
    pub fn set_value(&mut self, sref: &str, opt: &str, v: &Value) {
        match v {
            Value::Array(a) => {
                let l: Vec<String> = a.iter().map(plain).collect();
                self.set_list(sref, opt, &l)
            }
            // upstream quirk: a JSON object / boolean makes Lua's `#value` fail; we store text
            v => self.set(sref, opt, &plain(v)),
        }
    }
    /// `uci_del(section, option)`.
    pub fn del(&mut self, sref: &str, opt: &str) {
        let Some(i) = self.idx(sref) else { return };
        if self.cfg.sections[i].options.shift_remove(opt).is_some() {
            let p = format!("{}.{}", self.path(sref), opt);
            self.batch.delete(&p);
        }
    }
    /// `uci_del(section)`.
    pub fn del_section(&mut self, sref: &str) {
        let Some(i) = self.idx(sref) else { return };
        let p = self.path(sref);
        self.cfg.sections.remove(i);
        self.batch.delete(&p);
    }
    /// `uci:section(config, stype, name)`: create (or retype) a named section, appended last.
    pub fn add_section(&mut self, name: &str, stype: &str) {
        if let Some(i) = self.idx(name) {
            self.cfg.sections[i].stype = stype.to_string();
        } else {
            let index = self.cfg.sections_of(stype).count();
            self.cfg.sections.push(Section { name: name.to_string(), stype: stype.to_string(), anonymous: false, index, options: Default::default() });
        }
        self.batch.section(&self.conf.clone(), name, stype);
    }
    /// `uci reorder config.name=pos`.
    pub fn reorder(&mut self, name: &str, pos: usize) {
        let Some(i) = self.idx(name) else { return };
        let s = self.cfg.sections.remove(i);
        let pos = pos.min(self.cfg.sections.len());
        self.cfg.sections.insert(pos, s);
        let p = self.path(name);
        self.batch.reorder(&p, pos);
    }

    /// `api.uci_save(cursor, config, commit, apply)` on modern (ucode) LuCI: always commits;
    /// `apply` additionally reloads the service like LuCI's apply (`/etc/init.d/<cfg> reload`).
    pub fn save(&self, apply: bool) {
        let _ = self.batch.commit();
        if self.batch.is_empty() {
            crate::uci::commit(&self.conf);
        }
        if apply {
            let init = format!("/etc/init.d/{}", self.conf);
            if crate::util::exists(&init) {
                crate::util::spawn_bg(&init, &["reload".to_string()], "/dev/null");
            }
        }
    }
}

fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
        o => o.to_string(),
    }
}

/// A section as LuCI's cursor returns it: `.name`, `.type`, `.anonymous`, (`.index` = position
/// in the whole config, only for `foreach` results), then the options (lists → arrays).
pub fn section_json(s: &Section, global_index: Option<usize>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(".anonymous".into(), s.anonymous.into());
    m.insert(".type".into(), s.stype.clone().into());
    m.insert(".name".into(), s.name.clone().into());
    if let Some(i) = global_index {
        m.insert(".index".into(), i.into());
    }
    for (k, v) in &s.options {
        match v {
            UVal::Single(x) => m.insert(k.clone(), x.clone().into()),
            UVal::List(l) => m.insert(k.clone(), l.clone().into()),
        };
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn st() -> Store {
        Store::from_config(Config::parse(
            "passwall2",
            "config global\n\toption enabled '1'\n\nconfig nodes 'n1'\n\toption remarks 'a'\n\tlist l 'x'\n\tlist l 'y'\n\nconfig nodes 'n2'\n",
        ))
    }

    #[test]
    fn set_get_del() {
        let mut s = st();
        s.set("@global[0]", "node", "n1");
        assert_eq!(s.get("@global[0]", "node").as_deref(), Some("n1"));
        s.set("@global[0]", "node", "");
        assert_eq!(s.get("@global[0]", "node"), None);
        assert_eq!(s.list("n1", "l"), vec!["x", "y"]);
        s.set_list("n1", "l", &[]);
        assert!(!s.section("n1").unwrap().has("l"));
        s.set_value("n2", "arr", &json!(["1", 2]));
        assert_eq!(s.list("n2", "arr"), vec!["1", "2"]);
        s.set_value("n2", "num", &json!(5));
        assert_eq!(s.get("n2", "num").as_deref(), Some("5"));
        s.set_value("n2", "num", &json!(null));
        assert_eq!(s.get("n2", "num"), None);
        s.set("missing", "x", "1");
        assert!(!s.exists("missing"));
    }

    #[test]
    fn sections() {
        let mut s = st();
        s.add_section("n3", "nodes");
        assert_eq!(s.names_of("nodes"), vec!["n1", "n2", "n3"]);
        s.del_section("n1");
        assert_eq!(s.names_of("nodes"), vec!["n2", "n3"]);
        assert_eq!(s.section("@nodes[0]").unwrap().name, "n2");
        s.reorder("n3", 0);
        assert_eq!(s.cfg.sections[0].name, "n3");
    }

    #[test]
    fn json_shape() {
        let s = st();
        let m = section_json(s.section("n1").unwrap(), Some(1));
        assert_eq!(m[".name"], json!("n1"));
        assert_eq!(m[".type"], json!("nodes"));
        assert_eq!(m[".index"], json!(1));
        assert_eq!(m["l"], json!(["x", "y"]));
        assert!(section_json(s.section("n1").unwrap(), None).get(".index").is_none());
    }
}
