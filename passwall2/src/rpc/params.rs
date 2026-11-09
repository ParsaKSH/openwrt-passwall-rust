//! Request parameters (`http.formvalue` equivalent) and input validators.

use serde_json::{Map, Value};

/// JSON params of one call. Accessors mimic `http.formvalue(name)`: every scalar is a string
/// (numbers are printed, booleans become `"1"`/`"0"`), `null`/missing is `None`.
#[derive(Clone, Debug, Default)]
pub struct Params(pub Map<String, Value>);

impl Params {
    /// Parse stdin; anything but a JSON object → no params.
    pub fn from_json(s: &str) -> Params {
        match serde_json::from_str::<Value>(s.trim()) {
            Ok(Value::Object(m)) => Params(m),
            _ => Params::default(),
        }
    }
    pub fn raw(&self, k: &str) -> Option<&Value> {
        self.0.get(k).filter(|v| !v.is_null())
    }
    /// `formvalue(k)`.
    pub fn get(&self, k: &str) -> Option<String> {
        self.raw(k).map(scalar)
    }
    /// `formvalue(k) or ""`.
    pub fn s(&self, k: &str) -> String {
        self.get(k).unwrap_or_default()
    }
    /// `formvalue(k) or def` (only a missing value takes the default, like Lua `or`).
    pub fn or(&self, k: &str, def: &str) -> String {
        self.get(k).unwrap_or_else(|| def.to_string())
    }
    /// Non-empty value.
    pub fn ne(&self, k: &str) -> Option<String> {
        self.get(k).filter(|v| !v.is_empty())
    }
    /// Lua `tonumber(formvalue(k))`.
    pub fn num(&self, k: &str) -> Option<f64> {
        match self.raw(k)? {
            Value::Number(n) => n.as_f64(),
            v => crate::api::lua_tonumber(&scalar(v)),
        }
    }
    pub fn set(&mut self, k: &str, v: &str) {
        self.0.insert(k.to_string(), Value::String(v.to_string()));
    }
    pub fn remove(&mut self, k: &str) {
        self.0.remove(k);
    }
    pub fn to_value(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
        Value::Null => String::new(),
        Value::Number(n) => n.to_string(),
        o => o.to_string(),
    }
}

/// UCI section / option name: `[A-Za-z0-9_]+`.
pub fn is_sid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Section reference: a name or `@type[N]` (N may be negative).
pub fn is_sref(s: &str) -> bool {
    if is_sid(s) {
        return true;
    }
    let Some(rest) = s.strip_prefix('@') else { return false };
    let Some((t, idx)) = rest.split_once('[') else { return false };
    let Some(idx) = idx.strip_suffix(']') else { return false };
    let digits = idx.strip_prefix('-').unwrap_or(idx);
    is_sid(t) && !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit())
}

/// Safe single path component (file names under /tmp): `[A-Za-z0-9._+-]+`, no leading `.`.
pub fn is_safe_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.starts_with('.') && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
}

/// `string.gsub(ids, '[^,]+', f)` / `gmatch("([^,]+)")`: non-empty comma separated items.
pub fn split_nonempty(s: &str) -> Vec<String> {
    s.split(',').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect()
}

/// `luci.util.split(s, ",")`: keeps empty fields (`"a,,b"` → `["a","","b"]`; `""` → `[""]`).
pub fn split_keep_empty(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coercion() {
        let p = Params::from_json(r#"{"a":"x","n":3,"f":1.5,"b":true,"z":null,"o":{"k":1}}"#);
        assert_eq!(p.get("a").as_deref(), Some("x"));
        assert_eq!(p.get("n").as_deref(), Some("3"));
        assert_eq!(p.get("f").as_deref(), Some("1.5"));
        assert_eq!(p.get("b").as_deref(), Some("1"));
        assert_eq!(p.get("z"), None);
        assert_eq!(p.get("missing"), None);
        assert_eq!(p.get("o").as_deref(), Some(r#"{"k":1}"#));
        assert_eq!(p.num("n"), Some(3.0));
        assert_eq!(p.num("a"), None);
        assert_eq!(p.or("missing", "d"), "d");
        assert_eq!(Params::from_json(r#"{"e":""}"#).or("e", "d"), "");
        assert!(Params::from_json("[1,2]").0.is_empty());
        assert!(Params::from_json("").0.is_empty());
        assert_eq!(Params::from_json(r#"{"n":" 7 "}"#).num("n"), Some(7.0));
    }

    #[test]
    fn validators() {
        assert!(is_sid("abc_DEF123"));
        assert!(!is_sid(""));
        assert!(!is_sid("a.b"));
        assert!(!is_sid("a b"));
        assert!(!is_sid("a'b"));
        assert!(is_sref("@global[0]"));
        assert!(is_sref("@nodes[-1]"));
        assert!(is_sref("node1"));
        assert!(!is_sref("@global[]"));
        assert!(!is_sref("@glo bal[0]"));
        assert!(!is_sref("@global[0].x"));
        assert!(is_safe_name("passwall2-2611091530-backup.tar.gz"));
        assert!(!is_safe_name("../etc/passwd"));
        assert!(!is_safe_name("a/b"));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name(""));
    }

    #[test]
    fn splitting() {
        assert_eq!(split_nonempty("a,,b,"), vec!["a", "b"]);
        assert!(split_nonempty("").is_empty());
        assert_eq!(split_keep_empty("a,,b"), vec!["a", "", "b"]);
        assert_eq!(split_keep_empty(""), vec![""]);
    }
}
