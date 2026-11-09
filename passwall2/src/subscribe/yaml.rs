//! Minimal YAML loader replacing `lyaml.load` for Clash subscriptions.
//!
//! Supports what Clash/mihomo documents use: block mappings and sequences (including compact
//! `- key: v` items), flow collections (`{..}`, `[..]`, JSON), plain / single / double quoted
//! scalars with line folding and escapes, literal and folded block scalars (`|`, `>`, chomping
//! and indentation indicators), comments, anchors / aliases, `<<` merge keys, tags (`!!str`
//! forces a string, other tags are ignored), `%` directives and `---` / `...` markers.
//! Only the first document is returned (like `lyaml.load` without `all`).
//!
//! Implicit scalar typing follows lyaml (YAML 1.1 flavoured): `~`/empty/`null` → Null,
//! case-insensitive `true|false|yes|no|on|off` → Bool, ints/floats/hex/octal → Num. Numbers keep
//! their original spelling (`Num(raw)`); see [`Yaml::num`] for the numeric value.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    Null,
    Bool(bool),
    /// numeric plain scalar, original text
    Num(String),
    Str(String),
    Seq(Vec<Yaml>),
    /// mapping, document order; keys are scalars converted to text
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    /// `t[key]` for mappings; YAML null counts as absent (Lua nil).
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v).filter(|v| !matches!(v, Yaml::Null)),
            _ => None,
        }
    }
    pub fn is_table(&self) -> bool {
        matches!(self, Yaml::Map(_) | Yaml::Seq(_))
    }
    pub fn as_map(&self) -> Option<&Vec<(String, Yaml)>> {
        match self {
            Yaml::Map(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_seq(&self) -> Option<&Vec<Yaml>> {
        match self {
            Yaml::Seq(s) => Some(s),
            _ => None,
        }
    }
    /// Lua truthiness of a present value (everything except `false`).
    pub fn truthy(&self) -> bool {
        !matches!(self, Yaml::Null | Yaml::Bool(false))
    }
    /// Lua string value: strings and numbers (`type(v) == "string"` or a number).
    pub fn scalar_text(&self) -> Option<String> {
        match self {
            Yaml::Str(s) => Some(s.clone()),
            Yaml::Num(s) => Some(num_text(s)),
            _ => None,
        }
    }
    /// Lua `tonumber(v)` for strings and numbers.
    pub fn num(&self) -> Option<f64> {
        match self {
            Yaml::Num(s) => num_value(s),
            Yaml::Str(s) => crate::api::lua_tonumber(s),
            _ => None,
        }
    }
    /// Convert to JSON (numbers as JSON numbers, maps keep order).
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            Yaml::Null => J::Null,
            Yaml::Bool(b) => J::Bool(*b),
            Yaml::Num(s) => match num_value(s) {
                Some(f) => num_json(f),
                None => J::String(s.clone()),
            },
            Yaml::Str(s) => J::String(s.clone()),
            Yaml::Seq(v) => J::Array(v.iter().map(|x| x.to_json()).collect()),
            Yaml::Map(m) => {
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    o.insert(k.clone(), v.to_json());
                }
                J::Object(o)
            }
        }
    }
}

/// A Lua number as JSON (integers without fraction, like luci.jsonc).
pub fn num_json(f: f64) -> serde_json::Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 {
        serde_json::Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null)
    }
}

/// Numeric value of a YAML number spelling (`0x`, `0o`, `0b`, `_` separators, `.inf`, `.nan`).
pub fn num_value(raw: &str) -> Option<f64> {
    let s: String = raw.chars().filter(|c| *c != '_').collect();
    let (neg, body) = match s.strip_prefix('-') {
        Some(r) => (true, r.to_string()),
        None => (false, s.strip_prefix('+').unwrap_or(&s).to_string()),
    };
    let v = if let Some(h) = body.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()? as f64
    } else if let Some(o) = body.strip_prefix("0o") {
        u64::from_str_radix(o, 8).ok()? as f64
    } else if let Some(b) = body.strip_prefix("0b") {
        u64::from_str_radix(b, 2).ok()? as f64
    } else if matches!(body.as_str(), ".inf" | ".Inf" | ".INF") {
        f64::INFINITY
    } else if matches!(body.as_str(), ".nan" | ".NaN" | ".NAN") {
        f64::NAN
    } else if body.len() > 1 && body.starts_with('0') && body.bytes().all(|c| c.is_ascii_digit()) {
        // YAML 1.1 octal (lyaml)
        u64::from_str_radix(&body[1..], 8).ok().map(|v| v as f64).or_else(|| body.parse().ok())?
    } else {
        body.parse::<f64>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// Lua `tostring()` of a YAML number as lyaml loads it: `0x1bb` → `443`, `1.50` → `1.5`,
/// `+5` → `5`. Plain decimal integers keep their spelling.
// upstream quirk: lyaml also turns `0123` into 83 and long digit strings into `1.2345e+16`
// (it is a Lua number); those keep their original text here so passwords/ids survive.
pub fn num_text(raw: &str) -> String {
    let b = raw.strip_prefix('-').unwrap_or(raw);
    if !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()) {
        return raw.to_string();
    }
    match num_value(raw) {
        Some(f) => crate::subscribe::links::lua_num(f),
        None => raw.to_string(),
    }
}

fn is_int(s: &str) -> bool {
    let b = s.strip_prefix(['-', '+']).unwrap_or(s);
    if let Some(h) = b.strip_prefix("0x") {
        return !h.is_empty() && h.bytes().all(|c| c.is_ascii_hexdigit() || c == b'_');
    }
    if let Some(o) = b.strip_prefix("0o") {
        return !o.is_empty() && o.bytes().all(|c| (b'0'..=b'7').contains(&c) || c == b'_');
    }
    if let Some(o) = b.strip_prefix("0b") {
        return !o.is_empty() && o.bytes().all(|c| c == b'0' || c == b'1' || c == b'_');
    }
    !b.is_empty() && b.as_bytes()[0].is_ascii_digit() && b.bytes().all(|c| c.is_ascii_digit() || c == b'_')
}

fn is_float(s: &str) -> bool {
    let b = s.strip_prefix(['-', '+']).unwrap_or(s);
    if matches!(b, ".inf" | ".Inf" | ".INF") || matches!(s, ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    // [0-9_]*(\.[0-9_]*)?([eE][-+]?[0-9]+)? with at least one digit
    let bytes = b.as_bytes();
    let mut i = 0;
    let mut digits = 0;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
        if bytes[i].is_ascii_digit() {
            digits += 1;
        }
        i += 1;
    }
    let mut dot = false;
    if i < bytes.len() && bytes[i] == b'.' {
        dot = true;
        i += 1;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
            if bytes[i].is_ascii_digit() {
                digits += 1;
            }
            i += 1;
        }
    }
    if digits == 0 {
        return false;
    }
    let mut exp = false;
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        exp = true;
        i += 1;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            i += 1;
        }
        let st = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == st {
            return false;
        }
    }
    i == bytes.len() && (dot || exp)
}

/// Implicit typing of an untagged plain scalar.
pub fn resolve_plain(s: &str) -> Yaml {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Yaml::Null,
        _ => {}
    }
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => return Yaml::Bool(true),
        "false" | "no" | "off" => return Yaml::Bool(false),
        _ => {}
    }
    if is_int(s) || is_float(s) {
        return Yaml::Num(s.to_string());
    }
    Yaml::Str(s.to_string())
}

fn key_text(k: &Yaml) -> Result<String, String> {
    Ok(match k {
        Yaml::Null => String::new(),
        Yaml::Bool(b) => b.to_string(),
        Yaml::Num(s) | Yaml::Str(s) => s.clone(),
        _ => return Err("complex mapping keys are not supported".into()),
    })
}

fn map_insert(m: &mut Vec<(String, Yaml)>, k: String, v: Yaml) {
    if k == "<<" {
        let mut srcs = vec![];
        match &v {
            Yaml::Map(_) => srcs.push(v.clone()),
            Yaml::Seq(items) => srcs.extend(items.iter().filter(|x| matches!(x, Yaml::Map(_))).cloned()),
            _ => {
                m.push((k, v));
                return;
            }
        }
        for s in srcs {
            if let Yaml::Map(sm) = s {
                for (sk, sv) in sm {
                    if !m.iter().any(|(x, _)| *x == sk) {
                        m.push((sk, sv));
                    }
                }
            }
        }
        return;
    }
    if let Some(e) = m.iter_mut().find(|(x, _)| *x == k) {
        e.1 = v;
    } else {
        m.push((k, v));
    }
}

struct P {
    s: Vec<char>,
    i: usize,
    anchors: HashMap<String, Yaml>,
}

type R<T> = Result<T, String>;

fn is_flow_ind(c: char) -> bool {
    matches!(c, ',' | '[' | ']' | '{' | '}')
}

impl P {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }
    fn eof(&self) -> bool {
        self.i >= self.s.len()
    }
    fn err<T>(&self, msg: &str) -> R<T> {
        let line = self.s[..self.i.min(self.s.len())].iter().filter(|c| **c == '\n').count() + 1;
        Err(format!("{} at line {}", msg, line))
    }
    fn col(&self) -> i64 {
        let mut j = self.i;
        while j > 0 && self.s[j - 1] != '\n' {
            j -= 1;
        }
        (self.i - j) as i64
    }
    fn is_ws_at(&self, k: usize) -> bool {
        matches!(self.at(k), None | Some(' ') | Some('\t') | Some('\n'))
    }
    fn at_eol(&self) -> bool {
        matches!(self.peek(), None | Some('\n'))
    }
    fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.i += 1;
        }
    }
    fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !self.at_eol() {
                self.i += 1;
            }
        }
    }
    /// at the start of a line: `---` or `...` followed by whitespace/EOF
    fn at_doc_marker(&self) -> bool {
        if self.col() != 0 {
            return false;
        }
        let m: String = self.s[self.i..(self.i + 3).min(self.s.len())].iter().collect();
        (m == "---" || m == "...") && self.is_ws_at(3)
    }
    /// skip spaces, comments and line breaks
    fn skip_blank(&mut self) {
        loop {
            self.skip_inline_ws();
            self.skip_comment();
            if self.peek() == Some('\n') {
                self.i += 1;
                continue;
            }
            break;
        }
    }
    fn is_seq_entry(&self) -> bool {
        self.peek() == Some('-') && self.is_ws_at(1)
    }

    fn document(&mut self) -> R<Yaml> {
        if self.peek() == Some('\u{feff}') {
            self.i += 1;
        }
        // directives and the document start marker
        loop {
            self.skip_blank();
            if self.col() == 0 && self.peek() == Some('%') {
                while !self.at_eol() {
                    self.i += 1;
                }
                continue;
            }
            break;
        }
        if self.at_doc_marker() && self.peek() == Some('-') {
            self.i += 3;
        }
        self.skip_blank();
        if self.eof() || self.at_doc_marker() {
            return Ok(Yaml::Null);
        }
        let v = self.node(-1, false, false)?;
        self.skip_blank();
        if !self.eof() && !self.at_doc_marker() {
            return self.err("did not find expected <document start>");
        }
        Ok(v)
    }

    /// Properties (`&anchor`, `!tag`) before a node.
    fn properties(&mut self) -> R<(Option<String>, Option<String>)> {
        let mut anchor = None;
        let mut tag = None;
        loop {
            match self.peek() {
                Some('&') if anchor.is_none() => {
                    self.i += 1;
                    let st = self.i;
                    while let Some(c) = self.peek() {
                        if c == ' ' || c == '\t' || c == '\n' || is_flow_ind(c) {
                            break;
                        }
                        self.i += 1;
                    }
                    anchor = Some(self.s[st..self.i].iter().collect());
                    self.skip_inline_ws();
                }
                Some('!') if tag.is_none() => {
                    let st = self.i;
                    while let Some(c) = self.peek() {
                        if c == ' ' || c == '\t' || c == '\n' || is_flow_ind(c) {
                            break;
                        }
                        self.i += 1;
                    }
                    tag = Some(self.s[st..self.i].iter().collect());
                    self.skip_inline_ws();
                }
                _ => break,
            }
        }
        Ok((anchor, tag))
    }

    fn finish(&mut self, v: Yaml, anchor: Option<String>, tag: Option<String>) -> Yaml {
        let v = match (tag.as_deref(), v) {
            (Some("!!str") | Some("!"), Yaml::Num(s)) => Yaml::Str(s),
            (Some("!!str") | Some("!"), Yaml::Bool(b)) => Yaml::Str(b.to_string()),
            (Some("!!str") | Some("!"), Yaml::Null) => Yaml::Str(String::new()),
            (_, v) => v,
        };
        if let Some(a) = anchor {
            self.anchors.insert(a, v.clone());
        }
        v
    }

    fn alias(&mut self) -> R<Yaml> {
        self.i += 1;
        let st = self.i;
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\n' || is_flow_ind(c) {
                break;
            }
            self.i += 1;
        }
        let name: String = self.s[st..self.i].iter().collect();
        match self.anchors.get(&name) {
            Some(v) => Ok(v.clone()),
            None => self.err("found undefined alias"),
        }
    }

    /// A block node whose parent has indentation `parent`. `seq_at_parent`: a block sequence at
    /// the parent's column is accepted (mapping values). `inline`: the node starts on the line of
    /// a mapping key, so no implicit block collection may start here.
    fn node(&mut self, parent: i64, seq_at_parent: bool, inline: bool) -> R<Yaml> {
        if !inline {
            self.skip_blank();
            if self.eof() || self.at_doc_marker() {
                return Ok(Yaml::Null);
            }
            let col = self.col();
            if col < parent || (col == parent && !(seq_at_parent && self.is_seq_entry())) {
                return Ok(Yaml::Null);
            }
        }
        let col = self.col();
        let (anchor, tag) = self.properties()?;
        if (anchor.is_some() || tag.is_some()) && (self.at_eol() || self.peek() == Some('#')) {
            // node continues on the following lines
            self.skip_comment();
            let v = self.node(parent, seq_at_parent, false)?;
            return Ok(self.finish(v, anchor, tag));
        }
        let c = match self.peek() {
            Some(c) => c,
            None => return Ok(self.finish(Yaml::Null, anchor, tag)),
        };
        let v = if c == '-' && self.is_ws_at(1) {
            if inline {
                return self.err("block sequence entries are not allowed in this context");
            }
            self.block_seq(col)?
        } else if c == '[' || c == '{' {
            let v = self.flow_node()?;
            self.skip_inline_ws();
            if self.peek() == Some(':') && self.is_ws_at(1) {
                return self.err("complex mapping keys are not supported");
            }
            v
        } else if c == '|' || c == '>' {
            self.block_scalar(parent)?
        } else if c == '*' {
            let v = self.alias()?;
            self.skip_inline_ws();
            if self.peek() == Some(':') && self.is_ws_at(1) {
                if inline {
                    return self.err("mapping values are not allowed in this context");
                }
                let k = key_text(&v)?;
                return self.block_map(col, Some(k));
            }
            v
        } else if c == '"' || c == '\'' {
            let s = if c == '"' { self.double_quoted()? } else { self.single_quoted()? };
            self.skip_inline_ws();
            if self.peek() == Some(':') && self.is_ws_at(1) {
                if inline {
                    return self.err("mapping values are not allowed in this context");
                }
                let v = self.block_map(col, Some(s))?;
                return Ok(self.finish(v, anchor, tag));
            }
            Yaml::Str(s)
        } else if c == '?' && self.is_ws_at(1) {
            return self.err("complex mapping keys are not supported");
        } else {
            if matches!(c, '@' | '`') || (matches!(c, ']' | '}' | ',')) || ((c == ':') && self.is_ws_at(1)) {
                return self.err("found character that cannot start any token");
            }
            let first = self.plain_line(false);
            if self.peek() == Some(':') && self.is_ws_at(1) {
                if inline {
                    return self.err("mapping values are not allowed in this context");
                }
                let v = self.block_map(col, Some(first))?;
                return Ok(self.finish(v, anchor, tag));
            }
            let text = self.plain_continue(first, parent)?;
            if tag.is_some() {
                Yaml::Str(text)
            } else {
                resolve_plain(&text)
            }
        };
        Ok(self.finish(v, anchor, tag))
    }

    /// Scan one line of a plain scalar (block context). Stops before `: `, ` #`, EOL.
    fn plain_line(&mut self, flow: bool) -> String {
        let st = self.i;
        let mut end = self.i;
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            if c == ':' && (self.is_ws_at(1) || (flow && self.at(1).is_some_and(is_flow_ind))) {
                break;
            }
            if flow && is_flow_ind(c) {
                break;
            }
            if c == '#' && self.i > st && matches!(self.s[self.i - 1], ' ' | '\t') {
                break;
            }
            self.i += 1;
            if c != ' ' && c != '\t' {
                end = self.i;
            }
        }
        let s: String = self.s[st..end].iter().collect();
        // leave the position right after the last non-blank char + trailing blanks consumed
        s
    }

    /// Continuation lines of a multi-line plain scalar (indented more than `parent`).
    fn plain_continue(&mut self, first: String, parent: i64) -> R<String> {
        let mut out = first;
        loop {
            self.skip_inline_ws();
            if self.peek() == Some('#') || self.peek() != Some('\n') {
                // comment or something else on this line ends the scalar
                break;
            }
            // look ahead over blank lines
            let save = self.i;
            let mut j = self.i;
            let mut breaks = 0;
            let next_start;
            loop {
                if j >= self.s.len() {
                    next_start = None;
                    break;
                }
                if self.s[j] == '\n' {
                    breaks += 1;
                    j += 1;
                    let mut k = j;
                    while k < self.s.len() && (self.s[k] == ' ' || self.s[k] == '\t') {
                        k += 1;
                    }
                    if k < self.s.len() && self.s[k] != '\n' {
                        next_start = Some((j, k));
                        break;
                    }
                    j = k;
                    continue;
                }
                j += 1;
            }
            let Some((line_start, content)) = next_start else {
                self.i = save;
                break;
            };
            let indent = (content - line_start) as i64;
            self.i = content;
            if indent <= parent || self.at_doc_marker() || self.peek() == Some('#') {
                self.i = save;
                break;
            }
            let piece = self.plain_line(false);
            if piece.is_empty() {
                self.i = save;
                break;
            }
            if self.peek() == Some(':') && self.is_ws_at(1) {
                return self.err("mapping values are not allowed in this context");
            }
            if breaks > 1 {
                for _ in 1..breaks {
                    out.push('\n');
                }
            } else {
                out.push(' ');
            }
            out.push_str(&piece);
        }
        Ok(out)
    }

    fn block_map(&mut self, col: i64, first_key: Option<String>) -> R<Yaml> {
        let mut m: Vec<(String, Yaml)> = vec![];
        let mut pending = first_key;
        loop {
            let key = match pending.take() {
                Some(k) => k,
                None => {
                    self.skip_blank();
                    if self.eof() || self.at_doc_marker() {
                        break;
                    }
                    let c = self.col();
                    if c < col {
                        break;
                    }
                    if c > col {
                        return self.err("bad indentation of a mapping entry");
                    }
                    if self.is_seq_entry() {
                        break;
                    }
                    let (_anchor, _tag) = self.properties()?;
                    match self.peek() {
                        Some('"') => self.double_quoted()?,
                        Some('\'') => self.single_quoted()?,
                        Some('*') => {
                            let v = self.alias()?;
                            key_text(&v)?
                        }
                        Some('?') if self.is_ws_at(1) => return self.err("complex mapping keys are not supported"),
                        Some('[') | Some('{') => return self.err("complex mapping keys are not supported"),
                        _ => self.plain_line(false),
                    }
                }
            };
            self.skip_inline_ws();
            if !(self.peek() == Some(':') && self.is_ws_at(1)) {
                return self.err("could not find expected ':'");
            }
            self.i += 1;
            self.skip_inline_ws();
            let v = if self.at_eol() || self.peek() == Some('#') {
                self.skip_comment();
                self.node(col, true, false)?
            } else {
                self.node(col, false, true)?
            };
            map_insert(&mut m, key, v);
        }
        Ok(Yaml::Map(m))
    }

    fn block_seq(&mut self, col: i64) -> R<Yaml> {
        let mut out = vec![];
        loop {
            self.skip_blank();
            if self.eof() || self.at_doc_marker() {
                break;
            }
            let c = self.col();
            if c < col {
                break;
            }
            if c > col {
                return self.err("bad indentation of a sequence entry");
            }
            if !self.is_seq_entry() {
                break;
            }
            self.i += 1;
            self.skip_inline_ws();
            let v = if self.at_eol() || self.peek() == Some('#') {
                self.skip_comment();
                self.node(col, false, false)?
            } else {
                // compact form: the item starts on this line at a deeper column
                self.node(col, false, false)?
            };
            out.push(v);
        }
        Ok(Yaml::Seq(out))
    }

    fn block_scalar(&mut self, parent: i64) -> R<Yaml> {
        let literal = self.peek() == Some('|');
        self.i += 1;
        let mut chomp = 'c';
        let mut explicit: Option<i64> = None;
        for _ in 0..2 {
            match self.peek() {
                Some('-') => {
                    chomp = '-';
                    self.i += 1;
                }
                Some('+') => {
                    chomp = '+';
                    self.i += 1;
                }
                Some(d) if d.is_ascii_digit() && d != '0' => {
                    explicit = Some(d as i64 - '0' as i64);
                    self.i += 1;
                }
                _ => {}
            }
        }
        self.skip_inline_ws();
        self.skip_comment();
        if !self.at_eol() {
            return self.err("did not find expected comment or line break");
        }
        // collect raw lines
        let base = if parent < 0 { 0 } else { parent };
        let mut indent: Option<i64> = explicit.map(|e| base + e);
        let mut lines: Vec<(i64, String)> = vec![]; // (indent, text) ; text without indentation
        let mut trailing_breaks = 0usize;
        while self.peek() == Some('\n') {
            let save = self.i;
            self.i += 1;
            let ls = self.i;
            while self.peek() == Some(' ') {
                self.i += 1;
            }
            let ind = (self.i - ls) as i64;
            if self.at_eol() {
                // empty line
                lines.push((-1, String::new()));
                continue;
            }
            if self.at_doc_marker() {
                self.i = save;
                break;
            }
            let need = match indent {
                Some(n) => n,
                None => {
                    if ind <= parent {
                        self.i = save;
                        break;
                    }
                    indent = Some(ind);
                    ind
                }
            };
            if ind < need {
                self.i = save;
                break;
            }
            let content_start = ls + need as usize;
            self.i = content_start;
            while !self.at_eol() {
                self.i += 1;
            }
            let text: String = self.s[content_start..self.i].iter().collect();
            lines.push((ind - need, text));
        }
        // the last consumed position is at the end of the last content line; trailing empty
        // lines that were pushed must be accounted for in chomping
        while lines.last().is_some_and(|l| l.0 == -1) {
            lines.pop();
            trailing_breaks += 1;
        }
        let mut out = String::new();
        if literal {
            for (n, (_, t)) in lines.iter().enumerate() {
                if n > 0 {
                    out.push('\n');
                }
                out.push_str(t);
            }
        } else {
            let mut prev_more = false;
            let mut prev_empty = false;
            for (n, (extra, t)) in lines.iter().enumerate() {
                // `t` already carries the extra indentation of more-indented lines
                let empty = *extra == -1;
                let more = !empty && (t.starts_with(' ') || t.starts_with('\t'));
                if n > 0 {
                    if empty {
                        out.push('\n');
                    } else if prev_empty || more || prev_more {
                        if !prev_empty || more || prev_more {
                            out.push('\n');
                        }
                    } else {
                        out.push(' ');
                    }
                }
                if !empty {
                    out.push_str(t);
                }
                prev_more = more;
                prev_empty = empty;
            }
        }
        if !lines.is_empty() {
            match chomp {
                '-' => {}
                '+' => {
                    out.push('\n');
                    for _ in 0..trailing_breaks {
                        out.push('\n');
                    }
                }
                _ => out.push('\n'),
            }
        } else if chomp == '+' {
            for _ in 0..trailing_breaks {
                out.push('\n');
            }
        }
        Ok(Yaml::Str(out))
    }

    /// Fold the line break(s) inside a quoted scalar starting at a `\n`.
    fn fold_quoted(&mut self, out: &mut String) {
        // trim trailing whitespace already pushed
        while out.ends_with(' ') || out.ends_with('\t') {
            out.pop();
        }
        let mut breaks = 0;
        while self.peek() == Some('\n') {
            breaks += 1;
            self.i += 1;
            self.skip_inline_ws();
        }
        if breaks == 1 {
            out.push(' ');
        } else {
            for _ in 1..breaks {
                out.push('\n');
            }
        }
    }

    fn single_quoted(&mut self) -> R<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return self.err("found unexpected end of stream while scanning a quoted scalar"),
                Some('\'') => {
                    if self.at(1) == Some('\'') {
                        out.push('\'');
                        self.i += 2;
                    } else {
                        self.i += 1;
                        break;
                    }
                }
                Some('\n') => self.fold_quoted(&mut out),
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        Ok(out)
    }

    fn hex_escape(&mut self, n: usize) -> R<char> {
        let h: String = self.s[self.i..(self.i + n).min(self.s.len())].iter().collect();
        if h.len() != n {
            return self.err("found unknown escape character");
        }
        self.i += n;
        u32::from_str_radix(&h, 16).ok().and_then(char::from_u32).map_or_else(|| self.err("found invalid Unicode character escape code"), Ok)
    }

    fn double_quoted(&mut self) -> R<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return self.err("found unexpected end of stream while scanning a quoted scalar"),
                Some('"') => {
                    self.i += 1;
                    break;
                }
                Some('\\') => {
                    self.i += 1;
                    let Some(e) = self.peek() else { return self.err("found unexpected end of stream") };
                    self.i += 1;
                    match e {
                        '0' => out.push('\0'),
                        'a' => out.push('\x07'),
                        'b' => out.push('\x08'),
                        't' | '\t' => out.push('\t'),
                        'n' => out.push('\n'),
                        'v' => out.push('\x0b'),
                        'f' => out.push('\x0c'),
                        'r' => out.push('\r'),
                        'e' => out.push('\x1b'),
                        ' ' => out.push(' '),
                        '"' => out.push('"'),
                        '/' => out.push('/'),
                        '\\' => out.push('\\'),
                        'N' => out.push('\u{85}'),
                        '_' => out.push('\u{a0}'),
                        'L' => out.push('\u{2028}'),
                        'P' => out.push('\u{2029}'),
                        'x' => out.push(self.hex_escape(2)?),
                        'u' => out.push(self.hex_escape(4)?),
                        'U' => out.push(self.hex_escape(8)?),
                        '\n' => {
                            // escaped line break: join without a space
                            self.skip_inline_ws();
                            while self.peek() == Some('\n') {
                                out.push('\n');
                                self.i += 1;
                                self.skip_inline_ws();
                            }
                        }
                        _ => return self.err("found unknown escape character"),
                    }
                }
                Some('\n') => self.fold_quoted(&mut out),
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------- flow context

    fn skip_flow_blank(&mut self) {
        loop {
            match self.peek() {
                Some(' ') | Some('\t') | Some('\n') => self.i += 1,
                Some('#') if self.i == 0 || matches!(self.s[self.i - 1], ' ' | '\t' | '\n') => self.skip_comment(),
                _ => break,
            }
        }
    }

    fn flow_scalar_plain(&mut self) -> String {
        let mut out = self.plain_line(true);
        // multi-line plain scalar inside a flow collection
        loop {
            let save = self.i;
            self.skip_inline_ws();
            if self.peek() != Some('\n') {
                self.i = save;
                break;
            }
            let mut breaks = 0;
            while matches!(self.peek(), Some('\n') | Some(' ') | Some('\t')) {
                if self.peek() == Some('\n') {
                    breaks += 1;
                }
                self.i += 1;
            }
            match self.peek() {
                Some(c) if !is_flow_ind(c) && c != '#' && !(c == ':' && (self.is_ws_at(1) || self.at(1).is_some_and(is_flow_ind))) => {
                    let piece = self.plain_line(true);
                    if piece.is_empty() {
                        self.i = save;
                        break;
                    }
                    if breaks > 1 {
                        for _ in 1..breaks {
                            out.push('\n');
                        }
                    } else {
                        out.push(' ');
                    }
                    out.push_str(&piece);
                }
                _ => {
                    self.i = save;
                    break;
                }
            }
        }
        out
    }

    fn flow_node(&mut self) -> R<Yaml> {
        self.skip_flow_blank();
        let (anchor, tag) = self.properties()?;
        self.skip_flow_blank();
        let v = match self.peek() {
            None => return self.err("found unexpected end of stream"),
            Some('[') => {
                self.i += 1;
                let mut out = vec![];
                loop {
                    self.skip_flow_blank();
                    match self.peek() {
                        None => return self.err("did not find expected ',' or ']'"),
                        Some(']') => {
                            self.i += 1;
                            break;
                        }
                        _ => {}
                    }
                    let item = self.flow_node()?;
                    self.skip_flow_blank();
                    let item = if self.peek() == Some(':') {
                        // single pair mapping inside a sequence
                        self.i += 1;
                        self.skip_flow_blank();
                        let v = if matches!(self.peek(), Some(',') | Some(']')) { Yaml::Null } else { self.flow_node()? };
                        self.skip_flow_blank();
                        Yaml::Map(vec![(key_text(&item)?, v)])
                    } else {
                        item
                    };
                    out.push(item);
                    match self.peek() {
                        Some(',') => self.i += 1,
                        Some(']') => {}
                        _ => return self.err("did not find expected ',' or ']'"),
                    }
                }
                Yaml::Seq(out)
            }
            Some('{') => {
                self.i += 1;
                let mut m = vec![];
                loop {
                    self.skip_flow_blank();
                    match self.peek() {
                        None => return self.err("did not find expected ',' or '}'"),
                        Some('}') => {
                            self.i += 1;
                            break;
                        }
                        Some('?') if self.is_ws_at(1) => {
                            self.i += 1;
                        }
                        _ => {}
                    }
                    let k = self.flow_node()?;
                    self.skip_flow_blank();
                    let v = if self.peek() == Some(':') {
                        self.i += 1;
                        self.skip_flow_blank();
                        if matches!(self.peek(), Some(',') | Some('}')) {
                            Yaml::Null
                        } else {
                            self.flow_node()?
                        }
                    } else {
                        Yaml::Null
                    };
                    self.skip_flow_blank();
                    map_insert(&mut m, key_text(&k)?, v);
                    match self.peek() {
                        Some(',') => self.i += 1,
                        Some('}') => {}
                        _ => return self.err("did not find expected ',' or '}'"),
                    }
                }
                Yaml::Map(m)
            }
            Some('"') => Yaml::Str(self.double_quoted()?),
            Some('\'') => Yaml::Str(self.single_quoted()?),
            Some('*') => self.alias()?,
            Some(c) if is_flow_ind(c) => Yaml::Null,
            Some(_) => {
                let s = self.flow_scalar_plain();
                if tag.is_some() {
                    Yaml::Str(s)
                } else {
                    resolve_plain(&s)
                }
            }
        };
        Ok(self.finish(v, anchor, tag))
    }
}

/// `lyaml.load(text)`: first document, or an error message.
pub fn load(text: &str) -> Result<Yaml, String> {
    let s: Vec<char> = text.chars().filter(|c| *c != '\r').collect();
    let mut p = P { s, i: 0, anchors: HashMap::new() };
    p.document()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Yaml {
        Yaml::Str(x.into())
    }

    #[test]
    fn scalars_and_typing() {
        assert_eq!(load("abc").unwrap(), s("abc"));
        assert_eq!(load("443").unwrap(), Yaml::Num("443".into()));
        assert_eq!(load("~").unwrap(), Yaml::Null);
        assert_eq!(load("").unwrap(), Yaml::Null);
        assert_eq!(load("Yes").unwrap(), Yaml::Bool(true));
        assert_eq!(load("'443'").unwrap(), s("443"));
        assert_eq!(load("1.5e3").unwrap(), Yaml::Num("1.5e3".into()));
        assert_eq!(load("1.2.3.4").unwrap(), s("1.2.3.4"));
        assert_eq!(num_value("0x1F"), Some(31.0));
        assert_eq!(num_value("010"), Some(8.0));
    }

    #[test]
    fn multiline_plain_root_is_a_string() {
        let t = "vmess://eyJhIjoiYiJ9\nvless://u@h:443?type=ws#name\ntrojan://p@h:443#x";
        assert_eq!(load(t).unwrap(), s("vmess://eyJhIjoiYiJ9 vless://u@h:443?type=ws#name trojan://p@h:443#x"));
        // base64 blob over several lines
        assert!(matches!(load("dm1lc3M6Ly9h\nYmNk\n").unwrap(), Yaml::Str(_)));
        // a ': ' in a continuation line is an error
        assert!(load("vless://a#b\nss://x#Traffic: 1GB").is_err());
    }

    #[test]
    fn clash_document() {
        let t = r#"
port: 7890
dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - "https://dns.alidns.com/dns-query"
proxies:
  - {name: "HK 01", server: hk.example.com, port: 443, type: vmess, uuid: abc, alterId: 0, cipher: auto, tls: true}
  - name: JP
    type: trojan
    server: 1.2.3.4
    port: "8443"
    password: 'pa''ss'
    sni: jp.example.com # comment
    alpn:
      - h2
      - http/1.1
    ws-opts:
      path: /ws
      headers: {Host: cdn.example.com}
  -   name: list in seq
      type: ss
      plugin-opts:
        mode: tls
proxy-groups:
  - name: g
    proxies: [HK 01, JP]
"#;
        let y = load(t).unwrap();
        let px = y.get("proxies").unwrap().as_seq().unwrap();
        assert_eq!(px.len(), 3);
        assert_eq!(px[0].get("name"), Some(&s("HK 01")));
        assert_eq!(px[0].get("tls"), Some(&Yaml::Bool(true)));
        assert_eq!(px[0].get("port"), Some(&Yaml::Num("443".into())));
        assert_eq!(px[1].get("password"), Some(&s("pa'ss")));
        assert_eq!(px[1].get("sni"), Some(&s("jp.example.com")));
        assert_eq!(px[1].get("alpn").unwrap().as_seq().unwrap().len(), 2);
        assert_eq!(px[1].get("ws-opts").unwrap().get("headers").unwrap().get("Host"), Some(&s("cdn.example.com")));
        assert_eq!(px[2].get("plugin-opts").unwrap().get("mode"), Some(&s("tls")));
        assert_eq!(y.get("dns").unwrap().get("enable"), Some(&Yaml::Bool(true)));
        assert_eq!(y.get("proxy-groups").unwrap().as_seq().unwrap()[0].get("proxies").unwrap().as_seq().unwrap()[1], s("JP"));
    }

    #[test]
    fn seq_at_key_indent_anchors_merge_block_scalars() {
        let t = "base: &b\n  type: ss\n  port: 1\nproxies:\n- name: a\n  <<: *b\n  port: 2\n- name: b\n  note: |\n    line1\n    line2\n  folded: >-\n    a\n    b\n";
        let y = load(t).unwrap();
        let px = y.get("proxies").unwrap().as_seq().unwrap();
        assert_eq!(px[0].get("type"), Some(&s("ss")));
        assert_eq!(px[0].get("port"), Some(&Yaml::Num("2".into())));
        assert_eq!(px[1].get("note"), Some(&s("line1\nline2\n")));
        assert_eq!(px[1].get("folded"), Some(&s("a b")));
    }

    #[test]
    fn number_text_like_lua() {
        assert_eq!(num_text("0x1bb"), "443");
        assert_eq!(num_text("1.50"), "1.5");
        assert_eq!(num_text("+5"), "5");
        assert_eq!(num_text("1_000"), "1000");
        assert_eq!(num_text("443"), "443");
        assert_eq!(num_text("0123"), "0123");
        assert_eq!(num_text("123456789012345678"), "123456789012345678");
    }

    #[test]
    fn json_and_quotes() {
        let y = load(r#"{"proxies":[{"name":"xA","port":1}],"a":"b\tc"}"#).unwrap();
        assert_eq!(y.get("proxies").unwrap().as_seq().unwrap()[0].get("name"), Some(&s("xA")));
        assert_eq!(y.get("a"), Some(&s("b\tc")));
        let y = load("k: \"a\n  b\"\nk2: 'x\n\n  y'").unwrap();
        assert_eq!(y.get("k"), Some(&s("a b")));
        assert_eq!(y.get("k2"), Some(&s("x\ny")));
    }

    #[test]
    fn errors() {
        assert!(load("a: b: c").is_err());
        assert!(load("a: 1\n  b: 2").is_err());
        assert!(load("k: [a, b").is_err());
        assert!(load("@x").is_err());
    }
}
