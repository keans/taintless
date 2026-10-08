//! A small C / C++ preprocessor: it resolves what the front ends cannot see through.
//!
//! Object-like and function-like macros (`#define`, `#undef`, `#` and `##`, `__VA_ARGS__`) are
//! expanded in the code, and `#if` / `#ifdef` / `#elif` / `#else` groups whose condition depends
//! only on known macros pick their branch. Macros defined in a header that a file includes with
//! `#include "x.h"` (or `<x.h>`) count, when the header is part of the project ([`Project`]).
//!
//! The text keeps its line structure: every input line gives one output line, so findings point
//! at the right line (columns after an expansion can differ). `#include` lines stay, and so do
//! conditional groups that depend on a macro nobody defines (both branches are analyzed, as
//! without preprocessing). `#define` / `#undef` lines and discarded branches become blank lines.
//! A processed text ends with a marker, which makes processing it again a no-op.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MARK: &str = "// taintless: preprocessed\n";
/// Longest text one expansion may produce, and the deepest nesting of expansions.
const MAX_EXPANSION: usize = 1 << 16;
const MAX_DEPTH: usize = 24;
/// Lines a macro call may be spread over.
const MAX_JOIN: usize = 64;

struct Macro {
    /// `None`: object-like.
    params: Option<Vec<String>>,
    variadic: bool,
    body: String,
}

impl Macro {
    fn object(body: &str) -> Arc<Self> {
        Arc::new(Self { params: None, variadic: false, body: body.into() })
    }
}

/// The macros a piece of code has defined (and the names it explicitly undefined).
#[derive(Clone, Default)]
struct Defs {
    macros: HashMap<String, Arc<Macro>>,
    undefined: HashSet<String>,
}

impl Defs {
    fn merge(&mut self, other: &Defs) {
        for (k, m) in &other.macros {
            self.undefined.remove(k);
            self.macros.insert(k.clone(), m.clone());
        }
        for u in &other.undefined {
            self.macros.remove(u);
            self.undefined.insert(u.clone());
        }
    }
}

/// The C / C++ files of a project, for finding the headers that `#include` names.
pub struct Project {
    /// Files by name, for resolving includes.
    by_name: HashMap<String, Vec<PathBuf>>,
    /// The macros each header defines (with those of its own includes), once computed.
    memo: Mutex<HashMap<(PathBuf, bool), Arc<Defs>>>,
}

impl Project {
    pub fn new<'a>(files: impl IntoIterator<Item = &'a Path>) -> Self {
        let mut by_name: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for f in files {
            if let Some(n) = f.file_name() {
                by_name.entry(n.to_string_lossy().into_owned()).or_default().push(f.to_path_buf());
            }
        }
        for v in by_name.values_mut() {
            v.sort();
        }
        Self { by_name, memo: Mutex::new(HashMap::new()) }
    }

    /// `src`, the text of `path`, with its macros resolved (see the module docs).
    pub fn preprocess<'s>(&self, path: &Path, cpp: bool, src: &'s str) -> Cow<'s, str> {
        process(src, cpp, Some((self, path)))
    }

    /// The file an `#include name` in `from` means: the project file whose path ends with `name`,
    /// the one next to `from` or else the nearest.
    fn resolve(&self, from: &Path, name: &str) -> Option<PathBuf> {
        let rel: PathBuf = Path::new(name).components().filter(|c| matches!(c, std::path::Component::Normal(_))).collect();
        let base = rel.file_name()?.to_string_lossy().into_owned();
        let dir = from.parent().unwrap_or(Path::new(""));
        let shared = |p: &Path| p.parent().unwrap_or(Path::new("")).components().zip(dir.components()).take_while(|(a, b)| a == b).count();
        self.by_name
            .get(&base)?
            .iter()
            .filter(|p| p.as_path() != from && p.ends_with(&rel))
            .max_by_key(|p| (shared(p), p.parent() == Some(dir)))
            .cloned()
    }

    /// The macros `header` defines, reading it on first use. `visiting` guards include cycles.
    fn defs_of(&self, header: &Path, cpp: bool, visiting: &mut Vec<PathBuf>) -> Option<Arc<Defs>> {
        let key = (header.to_path_buf(), cpp);
        if let Some(d) = self.memo.lock().ok().and_then(|m| m.get(&key).cloned()) {
            return Some(d);
        }
        if visiting.iter().any(|v| v == header) {
            return None;
        }
        let text = std::fs::read_to_string(header).ok()?;
        visiting.push(header.to_path_buf());
        let mut pp = Pass::new(cpp, Some((self, header)), visiting);
        pp.run(&text, false);
        let defs = Arc::new(pp.defs);
        visiting.pop();
        if let Ok(mut m) = self.memo.lock() {
            m.insert(key, defs.clone());
        }
        Some(defs)
    }
}

/// `src` with its macros resolved using only what the text itself defines.
pub fn preprocess_alone(cpp: bool, src: &str) -> Cow<'_, str> {
    process(src, cpp, None)
}

fn process<'s>(src: &'s str, cpp: bool, project: Option<(&Project, &Path)>) -> Cow<'s, str> {
    if src.ends_with(MARK) || !has_directives(src, project.is_some()) {
        return Cow::Borrowed(src);
    }
    let mut visiting = project.map(|(_, p)| vec![p.to_path_buf()]).unwrap_or_default();
    let mut pass = Pass::new(cpp, project, &mut visiting);
    let out = pass.run(src, true);
    if out == src {
        Cow::Borrowed(src)
    } else {
        Cow::Owned(out + MARK)
    }
}

/// Is there a directive that can change the text (a macro, a conditional, or with a project an
/// include)?
fn has_directives(src: &str, includes: bool) -> bool {
    src.lines().any(|l| {
        let l = l.trim_start();
        l.strip_prefix('#').is_some_and(|r| {
            let w = r.trim_start();
            ["define", "undef", "if", "elif", "else", "endif"].iter().any(|d| w.starts_with(d)) || (includes && w.starts_with("include"))
        })
    })
}

/// One conditional group: `#if` ... `#elif` ... `#else` ... `#endif`.
struct Group {
    /// Whether the code around the group is live.
    parent_live: bool,
    /// Whether the current branch is live.
    branch: bool,
    /// A branch was already chosen.
    taken: bool,
    /// The group depends on an unknown macro: its directives stay and every branch is live.
    kept: bool,
}

impl Group {
    fn live(&self) -> bool {
        self.parent_live && self.branch
    }
}

struct Pass<'a> {
    defs: Defs,
    cpp: bool,
    project: Option<(&'a Project, &'a Path)>,
    visiting: &'a mut Vec<PathBuf>,
}

impl<'a> Pass<'a> {
    fn new(cpp: bool, project: Option<(&'a Project, &'a Path)>, visiting: &'a mut Vec<PathBuf>) -> Self {
        let mut defs = Defs::default();
        if cpp {
            defs.macros.insert("__cplusplus".into(), Macro::object("201703L"));
        } else {
            defs.undefined.insert("__cplusplus".into());
        }
        Self { defs, cpp, project, visiting }
    }

    /// Process `src`; with `expand`, the result is the text with macros resolved, otherwise only
    /// the definitions are collected.
    fn run(&mut self, src: &str, expand: bool) -> String {
        let lines: Vec<&str> = src.split('\n').collect();
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        let mut groups: Vec<Group> = vec![];
        let mut in_comment = false;
        let mut i = 0;
        while i < lines.len() {
            let live = groups.last().is_none_or(Group::live);
            let line = lines[i];
            let directive = if in_comment { None } else { split_directive(line).map(|d| d.0) };
            let Some(name) = directive else {
                let (text, used) = if !live {
                    (String::new(), 1)
                } else if !expand {
                    in_comment = scan_comment(line, in_comment);
                    (String::new(), 1)
                } else {
                    self.expand_lines(&lines[i..], &mut in_comment)
                };
                out.push(text);
                out.extend(std::iter::repeat_n(String::new(), used - 1));
                i += used;
                continue;
            };
            // the directive may continue on the next lines
            let mut used = 1;
            let mut logical = line.trim_end_matches('\r').to_string();
            while logical.ends_with('\\') && i + used < lines.len() {
                logical.pop();
                logical.push(' ');
                logical.push_str(lines[i + used].trim_end_matches('\r'));
                used += 1;
            }
            let verbatim = || lines[i..i + used].iter().map(|l| l.to_string()).collect::<Vec<_>>();
            let blank = || vec![String::new(); used];
            let rest = strip_comments(split_directive(&logical).map_or("", |d| d.1));
            let rest = rest.trim();
            let emitted = match name {
                "define" => {
                    if live {
                        self.define(rest);
                    }
                    blank()
                }
                "undef" => {
                    if live {
                        let n = rest.split_whitespace().next().unwrap_or("");
                        self.defs.macros.remove(n);
                        self.defs.undefined.insert(n.to_string());
                    }
                    blank()
                }
                "include" => {
                    if !live {
                        blank()
                    } else {
                        self.include(rest);
                        verbatim()
                    }
                }
                "if" | "ifdef" | "ifndef" => {
                    let parent_live = live;
                    let value = if parent_live { self.condition(name, rest) } else { Some(false) };
                    groups.push(Group { parent_live, branch: value.unwrap_or(true), taken: value == Some(true), kept: parent_live && value.is_none() });
                    if groups.last().is_some_and(|g| g.kept) { verbatim() } else { blank() }
                }
                "elif" | "else" => match groups.last().map(|g| (g.parent_live, g.kept, g.taken)) {
                    None => verbatim(),
                    Some((false, ..)) => blank(),
                    Some((true, true, _)) => {
                        if let Some(g) = groups.last_mut() {
                            g.branch = true;
                        }
                        verbatim()
                    }
                    Some((true, false, taken)) => {
                        let value = if taken {
                            Some(false)
                        } else if name == "else" {
                            Some(true)
                        } else {
                            self.condition("elif", rest)
                        };
                        let mut emitted = blank();
                        if let Some(g) = groups.last_mut() {
                            match value {
                                Some(v) => {
                                    g.branch = v;
                                    g.taken |= v;
                                }
                                None => {
                                    // an unknown condition after known ones: from here on the group is kept
                                    g.kept = true;
                                    g.branch = true;
                                    emitted[0] = format!("#if {rest}");
                                }
                            }
                        }
                        emitted
                    }
                },
                "endif" => match groups.pop() {
                    Some(g) if g.kept => verbatim(),
                    Some(_) => blank(),
                    None => verbatim(),
                },
                _ => {
                    if live { verbatim() } else { blank() }
                }
            };
            out.extend(emitted);
            i += used;
        }
        out.join("\n")
    }

    /// The code `lines[0]` starts, with macros expanded, and the number of lines it used (a macro
    /// call can span several).
    fn expand_lines(&self, lines: &[&str], in_comment: &mut bool) -> (String, usize) {
        let mut text = lines[0].to_string();
        let mut used = 1;
        loop {
            let mut comment = *in_comment;
            let mut out = String::with_capacity(text.len());
            if self.defs.expand(&text, &mut vec![], 0, &mut comment, &mut out, true) {
                *in_comment = comment;
                return (out.replace('\n', " "), used);
            }
            if used >= lines.len() || used >= MAX_JOIN {
                *in_comment = scan_comment(lines[0], *in_comment);
                return (lines[0].to_string(), 1);
            }
            text.push('\n');
            text.push_str(lines[used]);
            used += 1;
        }
    }

    fn define(&mut self, rest: &str) {
        let name_end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
        let name = &rest[..name_end];
        if name.is_empty() {
            return;
        }
        let after = &rest[name_end..];
        let mac = if let Some(args) = after.strip_prefix('(') {
            let Some(close) = args.find(')') else { return };
            let mut variadic = false;
            let mut params = vec![];
            for p in args[..close].split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if p == "..." {
                    variadic = true;
                    params.push("__VA_ARGS__".to_string());
                } else if let Some(n) = p.strip_suffix("...") {
                    variadic = true;
                    params.push(n.trim().to_string());
                } else {
                    params.push(p.to_string());
                }
            }
            Macro { params: Some(params), variadic, body: args[close + 1..].trim().to_string() }
        } else {
            Macro { params: None, variadic: false, body: after.trim().to_string() }
        };
        self.defs.undefined.remove(name);
        self.defs.macros.insert(name.to_string(), Arc::new(mac));
    }

    /// `#include "x.h"` / `<x.h>`: the macros of a header of the project count from here on.
    fn include(&mut self, rest: &str) {
        let Some((project, from)) = self.project else { return };
        let name = match rest.chars().next() {
            Some('"') => rest[1..].split('"').next(),
            Some('<') => rest[1..].split('>').next(),
            _ => None,
        };
        let Some(header) = name.and_then(|n| project.resolve(from, n)) else { return };
        if let Some(defs) = project.defs_of(&header, self.cpp, self.visiting) {
            self.defs.merge(&defs);
        }
    }

    /// The value of a condition; `None` when it depends on a macro nothing defines.
    fn condition(&self, directive: &str, rest: &str) -> Option<bool> {
        match directive {
            "ifdef" | "ifndef" => {
                let n = rest.split_whitespace().next().unwrap_or("");
                let known = if self.defs.macros.contains_key(n) {
                    Some(true)
                } else if self.defs.undefined.contains(n) {
                    Some(false)
                } else {
                    None
                };
                known.map(|k| k == (directive == "ifdef"))
            }
            _ => self.eval(rest).map(|v| v != 0),
        }
    }

    fn eval(&self, expr: &str) -> Option<i64> {
        // `defined X` and `defined(X)` first: the name must not be expanded
        let mut text = String::new();
        let mut rest = expr;
        while let Some(p) = find_word(rest, "defined") {
            text.push_str(&rest[..p]);
            let after = rest[p + "defined".len()..].trim_start();
            let (name, tail) = match after.strip_prefix('(') {
                Some(inner) => {
                    let c = inner.find(')')?;
                    (inner[..c].trim(), &inner[c + 1..])
                }
                None => {
                    let e = after.find(|c: char| !is_ident_char(c)).unwrap_or(after.len());
                    (&after[..e], &after[e..])
                }
            };
            text.push_str(if self.defs.macros.contains_key(name) {
                " 1 "
            } else if self.defs.undefined.contains(name) {
                " 0 "
            } else {
                " __unknown__ "
            });
            rest = tail;
        }
        text.push_str(rest);
        let mut expanded = String::new();
        let mut comment = false;
        if !self.defs.expand(&text, &mut vec![], 0, &mut comment, &mut expanded, false) {
            return None;
        }
        let toks = tokenize(&expanded, self.cpp);
        let mut parser = Expr { toks: &toks, at: 0 };
        let v = parser.ternary();
        if parser.at < toks.len() { None } else { v }
    }
}

/// The directive a line holds and what follows its name (`define`, `X 1` for `# define X 1`).
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let r = line.trim_start().strip_prefix('#')?.trim_start();
    let e = r.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(r.len());
    (e > 0).then(|| (&r[..e], &r[e..]))
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || !c.is_ascii()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// The position of `word` as a whole identifier in `s`.
fn find_word(s: &str, word: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut from = 0;
    while let Some(p) = s[from..].find(word) {
        let at = from + p;
        let end = at + word.len();
        if (at == 0 || !is_ident_byte(b[at - 1])) && (end >= b.len() || !is_ident_byte(b[end])) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// `s` without `/* */` and `//` comments.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("/*").into_iter().chain(rest.find("//")).min() {
        out.push_str(&rest[..p]);
        if rest[p..].starts_with("//") {
            return out;
        }
        match rest[p + 2..].find("*/") {
            Some(e) => {
                out.push(' ');
                rest = &rest[p + 2 + e + 2..];
            }
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Whether a block comment is open after `line`, given whether one was open before it.
fn scan_comment(line: &str, mut open: bool) -> bool {
    let mut rest = line;
    loop {
        if open {
            match rest.find("*/") {
                Some(e) => {
                    open = false;
                    rest = &rest[e + 2..];
                }
                None => return true,
            }
        } else {
            let b = rest.as_bytes();
            let mut i = 0;
            while i < b.len() {
                match b[i] {
                    b'/' if b.get(i + 1) == Some(&b'/') => return false,
                    b'/' if b.get(i + 1) == Some(&b'*') => {
                        open = true;
                        rest = &rest[i + 2..];
                        break;
                    }
                    b'"' | b'\'' => i = skip_quoted(b, i),
                    _ => i += 1,
                }
            }
            if !open {
                return false;
            }
        }
    }
}

/// The index after the string or character literal that starts at `start`.
fn skip_quoted(b: &[u8], start: usize) -> usize {
    let q = b[start];
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            c if c == q => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

impl Defs {
    /// Append `text` with its macros expanded to `out`. `false`: a macro call is not complete in
    /// `text` (only when `top`, so that the caller can add the next line).
    fn expand(&self, text: &str, hide: &mut Vec<String>, depth: usize, comment: &mut bool, out: &mut String, top: bool) -> bool {
        let b = text.as_bytes();
        let mut i = 0;
        if *comment {
            match text.find("*/") {
                Some(e) => {
                    out.push_str(&text[..e + 2]);
                    i = e + 2;
                    *comment = false;
                }
                None => {
                    out.push_str(text);
                    return true;
                }
            }
        }
        while i < b.len() {
            let c = b[i];
            if c == b'/' && b.get(i + 1) == Some(&b'/') {
                out.push_str(&text[i..]);
                return true;
            }
            if c == b'/' && b.get(i + 1) == Some(&b'*') {
                match text[i + 2..].find("*/") {
                    Some(e) => {
                        let end = i + 2 + e + 2;
                        out.push_str(&text[i..end]);
                        i = end;
                    }
                    None => {
                        out.push_str(&text[i..]);
                        *comment = true;
                        return true;
                    }
                }
                continue;
            }
            if c == b'"' || c == b'\'' {
                let end = skip_quoted(b, i);
                out.push_str(&text[i..end]);
                i = end;
                continue;
            }
            if c.is_ascii_digit() {
                // a number, with its suffix and exponent (`1e+5`, `0x1F`)
                let s = i;
                while i < b.len() && (is_ident_byte(b[i]) || b[i] == b'.' || (matches!(b[i], b'+' | b'-') && matches!(b[i - 1], b'e' | b'E' | b'p' | b'P'))) {
                    i += 1;
                }
                out.push_str(&text[s..i]);
                continue;
            }
            if !(c.is_ascii_alphabetic() || c == b'_' || c >= 0x80) {
                let ch = text[i..].chars().next().unwrap_or(' ');
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
            let s = i;
            while i < b.len() && is_ident_byte(b[i]) {
                i += 1;
            }
            let name = &text[s..i];
            let Some(mac) = self.macros.get(name).filter(|_| depth < MAX_DEPTH && !hide.iter().any(|h| h == name)) else {
                out.push_str(name);
                continue;
            };
            let mut produced = String::new();
            let end = match &mac.params {
                None => {
                    hide.push(name.to_string());
                    let ok = self.expand(&mac.body, hide, depth + 1, &mut false, &mut produced, false);
                    hide.pop();
                    ok.then_some(i)
                }
                Some(_) => {
                    let mut j = i;
                    while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r') {
                        j += 1;
                    }
                    if b.get(j) != Some(&b'(') {
                        if j >= b.len() && top {
                            return false;
                        }
                        out.push_str(name);
                        continue;
                    }
                    let Some((args, end)) = parse_args(text, j) else {
                        if top {
                            return false;
                        }
                        out.push_str(name);
                        continue;
                    };
                    self.call(name, mac, args, hide, depth, &mut produced).then_some(end)
                }
            };
            match end {
                Some(end) if produced.len() <= MAX_EXPANSION => {
                    out.push_str(&produced);
                    i = end;
                }
                _ => out.push_str(name),
            }
        }
        true
    }

    /// The expansion of a call of a function-like macro (`false`: the call does not fit).
    fn call(&self, name: &str, mac: &Macro, mut args: Vec<String>, hide: &mut Vec<String>, depth: usize, out: &mut String) -> bool {
        let params = mac.params.as_deref().unwrap_or_default();
        if params.is_empty() && args.len() == 1 && args[0].trim().is_empty() {
            args.clear();
        }
        if args.len() > params.len() && !mac.variadic {
            return false;
        }
        // the variadic parameter takes every remaining argument
        if mac.variadic && args.len() >= params.len() {
            let tail = args.split_off(params.len() - 1).join(",");
            args.push(tail);
        }
        args.resize(params.len(), String::new());
        let raw: HashMap<&str, &str> = params.iter().map(String::as_str).zip(args.iter().map(String::as_str)).collect();
        let b = mac.body.as_bytes();
        let mut sub = String::new();
        let mut i = 0;
        // whether the last thing written was a `##`
        let mut pasting = false;
        while i < b.len() {
            let c = b[i];
            if c == b'"' || c == b'\'' {
                let end = skip_quoted(b, i);
                sub.push_str(&mac.body[i..end]);
                i = end;
                pasting = false;
                continue;
            }
            if c == b'#' && b.get(i + 1) == Some(&b'#') {
                let trimmed = sub.trim_end().len();
                sub.truncate(trimmed);
                i += 2;
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                pasting = true;
                continue;
            }
            if c == b'#' {
                // `#param`: the argument as a string
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                let s = j;
                while j < b.len() && is_ident_byte(b[j]) {
                    j += 1;
                }
                if let Some(arg) = raw.get(&mac.body[s..j]).filter(|_| j > s) {
                    sub.push('"');
                    sub.push_str(&arg.trim().replace('\\', "\\\\").replace('"', "\\\""));
                    sub.push('"');
                    i = j;
                    pasting = false;
                    continue;
                }
            }
            if is_ident_byte(c) && !c.is_ascii_digit() {
                let s = i;
                while i < b.len() && is_ident_byte(b[i]) {
                    i += 1;
                }
                let word = &mac.body[s..i];
                match raw.get(word) {
                    Some(arg) => {
                        let mut k = i;
                        while k < b.len() && b[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        let pasted = pasting || b[k.min(b.len())..].starts_with(b"##");
                        if pasted {
                            sub.push_str(arg.trim());
                        } else {
                            let mut comment = false;
                            self.expand(arg, hide, depth + 1, &mut comment, &mut sub, false);
                        }
                    }
                    None => sub.push_str(word),
                }
                pasting = false;
                continue;
            }
            let ch = mac.body[i..].chars().next().unwrap_or(' ');
            sub.push(ch);
            i += ch.len_utf8();
            if !ch.is_whitespace() {
                pasting = false;
            }
        }
        // the result is scanned again, without this macro
        hide.push(name.to_string());
        let ok = self.expand(&sub, hide, depth + 1, &mut false, out, false);
        hide.pop();
        ok
    }
}

/// The arguments of the call whose `(` is at `open`, and the index after its `)`.
fn parse_args(text: &str, open: usize) -> Option<(Vec<String>, usize)> {
    let b = text.as_bytes();
    let mut depth = 0usize;
    let mut args = vec![];
    let mut start = open + 1;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => {
                i = skip_quoted(b, i);
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    args.push(text[start..i].to_string());
                    return Some((args, i + 1));
                }
            }
            b',' if depth == 1 => {
                args.push(text[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum Tok {
    Num(i64),
    Unknown,
    Op(&'static str),
}

const OPS: &[&str] = &["<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", "<", ">", "&", "|", "^", "!", "~", "?", ":", "(", ")"];

fn tokenize(s: &str, cpp: bool) -> Vec<Tok> {
    let b = s.as_bytes();
    let mut toks = vec![];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let st = i;
            while i < b.len() && is_ident_byte(b[i]) {
                i += 1;
            }
            let t = s[st..i].trim_end_matches(['u', 'U', 'l', 'L']);
            let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i64::from_str_radix(h, 16).ok()
            } else if let Some(bin) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
                i64::from_str_radix(bin, 2).ok()
            } else if t.len() > 1 && t.starts_with('0') {
                i64::from_str_radix(&t[1..], 8).ok()
            } else {
                t.parse().ok()
            };
            toks.push(v.map_or(Tok::Unknown, Tok::Num));
        } else if c == b'\'' {
            let end = skip_quoted(b, i);
            let body = &s[i + 1..end.saturating_sub(1).max(i + 1)];
            let v = match body.as_bytes() {
                [x] => Some(*x as i64),
                [b'\\', b'n'] => Some(10),
                [b'\\', b't'] => Some(9),
                [b'\\', b'0'] => Some(0),
                _ => None,
            };
            toks.push(v.map_or(Tok::Unknown, Tok::Num));
            i = end;
        } else if is_ident_byte(c) {
            let st = i;
            while i < b.len() && is_ident_byte(b[i]) {
                i += 1;
            }
            let name = &s[st..i];
            // a call of something unknown (`__has_include(x)`) is unknown as a whole
            let mut j = i;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if b.get(j) == Some(&b'(') && let Some((_, end)) = parse_args(s, j) {
                i = end;
                toks.push(Tok::Unknown);
                continue;
            }
            toks.push(match (name, cpp) {
                ("true", true) => Tok::Num(1),
                ("false", true) => Tok::Num(0),
                _ => Tok::Unknown,
            });
        } else if let Some(op) = OPS.iter().find(|o| s[i..].starts_with(**o)) {
            toks.push(Tok::Op(op));
            i += op.len();
        } else {
            toks.push(Tok::Unknown);
            i += 1;
        }
    }
    toks
}

struct Expr<'a> {
    toks: &'a [Tok],
    at: usize,
}

impl Expr<'_> {
    fn peek(&self) -> Option<Tok> {
        self.toks.get(self.at).copied()
    }

    fn eat(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Op(o)) if o == op) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn ternary(&mut self) -> Option<i64> {
        let cond = self.binary(1);
        if !self.eat("?") {
            return cond;
        }
        let yes = self.ternary();
        if !self.eat(":") {
            return None;
        }
        let no = self.ternary();
        match cond {
            Some(c) => if c != 0 { yes } else { no },
            None => None,
        }
    }

    fn binary(&mut self, min: u8) -> Option<i64> {
        let mut lhs = self.unary();
        while let Some(Tok::Op(op)) = self.peek() {
            let prec = match op {
                "||" => 1,
                "&&" => 2,
                "|" => 3,
                "^" => 4,
                "&" => 5,
                "==" | "!=" => 6,
                "<" | ">" | "<=" | ">=" => 7,
                "<<" | ">>" => 8,
                "+" | "-" => 9,
                "*" | "/" | "%" => 10,
                _ => break,
            };
            if prec < min {
                break;
            }
            self.at += 1;
            let rhs = self.binary(prec + 1);
            lhs = match (op, lhs, rhs) {
                // a known operand can decide these on its own
                ("&&", Some(0), _) | ("&&", _, Some(0)) => Some(0),
                ("||", Some(l), _) if l != 0 => Some(1),
                ("||", _, Some(r)) if r != 0 => Some(1),
                (_, Some(l), Some(r)) => apply(op, l, r),
                _ => None,
            };
        }
        lhs
    }

    fn unary(&mut self) -> Option<i64> {
        match self.peek()? {
            Tok::Op("!") => {
                self.at += 1;
                self.unary().map(|v| (v == 0) as i64)
            }
            Tok::Op("~") => {
                self.at += 1;
                self.unary().map(|v| !v)
            }
            Tok::Op("-") => {
                self.at += 1;
                self.unary().map(i64::wrapping_neg)
            }
            Tok::Op("+") => {
                self.at += 1;
                self.unary()
            }
            Tok::Op("(") => {
                self.at += 1;
                let v = self.ternary();
                if !self.eat(")") {
                    return None;
                }
                v
            }
            Tok::Num(n) => {
                self.at += 1;
                Some(n)
            }
            Tok::Unknown => {
                self.at += 1;
                None
            }
            Tok::Op(_) => None,
        }
    }
}

fn apply(op: &str, l: i64, r: i64) -> Option<i64> {
    Some(match op {
        "||" => (l != 0 || r != 0) as i64,
        "&&" => (l != 0 && r != 0) as i64,
        "|" => l | r,
        "^" => l ^ r,
        "&" => l & r,
        "==" => (l == r) as i64,
        "!=" => (l != r) as i64,
        "<" => (l < r) as i64,
        ">" => (l > r) as i64,
        "<=" => (l <= r) as i64,
        ">=" => (l >= r) as i64,
        "<<" => l.checked_shl(u32::try_from(r).ok()?)?,
        ">>" => l.checked_shr(u32::try_from(r).ok()?)?,
        "+" => l.wrapping_add(r),
        "-" => l.wrapping_sub(r),
        "*" => l.wrapping_mul(r),
        "/" => l.checked_div(r)?,
        "%" => l.checked_rem(r)?,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pp(src: &str) -> String {
        preprocess_alone(false, src).into_owned()
    }

    fn code(src: &str) -> Vec<String> {
        pp(src).lines().filter(|l| !l.trim().is_empty() && !l.starts_with("// taintless")).map(|l| l.trim().to_string()).collect()
    }

    #[test]
    fn object_and_function_like_macros() {
        let out = code("#define SHELL system\n#define RUN(c) SHELL(c)\nint f(char *x) { RUN(x); return 0; }\n");
        assert_eq!(out, ["int f(char *x) { system(x); return 0; }"]);
    }

    #[test]
    fn stringify_paste_and_variadic() {
        let out = code("#define S(x) #x\n#define CAT(a,b) a##b\n#define LOG(...) printf(__VA_ARGS__)\nS(a b); CAT(sys, tem)(c); LOG(\"%d\", 1);\n");
        assert_eq!(out, ["\"a b\"; system(c); printf(\"%d\", 1);"]);
    }

    #[test]
    fn recursion_and_literals_are_left_alone() {
        let out = code("#define foo foo + 1\n#define N 3\nint a = foo; char *s = \"N\"; // N\n/* N */ int b = N;\n");
        assert_eq!(out, ["int a = foo + 1; char *s = \"N\"; // N", "/* N */ int b = 3;"]);
    }

    #[test]
    fn multi_line_calls_keep_the_line_count() {
        let src = "#define ADD(a,b) a+b\nint x = ADD(1,\n  2);\nint y;\n";
        let out = pp(src);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1].trim(), "int x = 1+   2;");
        assert_eq!(lines[3], "int y;");
    }

    #[test]
    fn known_conditions_choose_a_branch() {
        let src = "#define V 2\n#if V > 1 && !defined(OLD)\nint a;\n#else\nint b;\n#endif\n#if 0\nint c;\n#endif\n#ifdef V\nint d;\n#endif\n";
        // OLD is unknown, so the first group stays whole
        let out = code(src);
        assert!(out.contains(&"int a;".to_string()) && out.contains(&"int b;".to_string()), "{out:?}");
        let out = code("#define V 2\n#if V > 1\nint a;\n#else\nint b;\n#endif\n#if 0\nint c;\n#endif\n#ifdef V\nint d;\n#endif\n");
        assert_eq!(out, ["int a;", "int d;"]);
    }

    #[test]
    fn unknown_conditions_keep_both_branches() {
        let out = code("#ifdef _WIN32\nint a;\n#elif defined(X)\nint b;\n#else\nint c;\n#endif\n");
        assert_eq!(out, ["#ifdef _WIN32", "int a;", "#elif defined(X)", "int b;", "#else", "int c;", "#endif"]);
        // a known branch before an unknown one
        let out = code("#if 0\nint a;\n#elif FOO\nint b;\n#endif\n");
        assert_eq!(out, ["#if FOO", "int b;", "#endif"]);
    }

    #[test]
    fn processing_twice_changes_nothing() {
        let once = pp("#define A B\nint x = A;\n");
        assert_eq!(pp(&once), once);
    }

    #[test]
    fn cpp_knows_its_version() {
        let out = preprocess_alone(true, "#ifdef __cplusplus\nint a;\n#else\nint b;\n#endif\n");
        assert_eq!(out.lines().filter(|l| !l.trim().is_empty() && !l.starts_with("//")).collect::<Vec<_>>(), ["int a;"]);
    }
}
