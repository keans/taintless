//! Project manifests that tell import resolution where modules live:
//! `tsconfig.json` / `jsconfig.json` (`baseUrl`, `paths`), `go.mod` (the module
//! path, `go.work` / `replace` directories), `Cargo.toml` (crate names, `[lib]` /
//! `[[bin]]` roots), `package.json` (workspaces, `exports`, `main`) and
//! `pyproject.toml` (source roots). They are found next to the scanned files or
//! in a parent directory.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct TsConfig {
    /// `baseUrl`, joined to the config's directory.
    pub base_url: Option<PathBuf>,
    /// Directory the `paths` targets are relative to.
    pub paths_base: PathBuf,
    /// `"@app/*": ["src/app/*"]`
    pub paths: Vec<(String, Vec<String>)>,
}

impl TsConfig {
    /// Directories to try for a non-relative module name, in order of preference:
    /// the `paths` match with the longest literal prefix, then `baseUrl`.
    pub fn candidates(&self, module: &str) -> Vec<PathBuf> {
        let mut best: Option<(usize, &Vec<String>, String)> = None;
        for (pat, targets) in &self.paths {
            let hit = match pat.split_once('*') {
                Some((pre, post)) => {
                    (module.len() >= pre.len() + post.len() && module.starts_with(pre) && module.ends_with(post))
                        .then(|| (pre.len(), module[pre.len()..module.len() - post.len()].to_string()))
                }
                None => (pat == module).then(|| (pat.len() + 1, String::new())),
            };
            if let Some((len, cap)) = hit
                && best.as_ref().is_none_or(|b| len > b.0)
            {
                best = Some((len, targets, cap));
            }
        }
        let mut out: Vec<PathBuf> = best
            .into_iter()
            .flat_map(|(_, targets, cap)| targets.iter().map(move |t| self.paths_base.join(t.replace('*', &cap))))
            .collect();
        if let Some(b) = &self.base_url {
            out.push(b.join(module));
        }
        out
    }
}

/// JSON with comments and trailing commas, as `tsconfig.json` is written.
fn strip_jsonc(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut in_str = false;
    while i < c.len() {
        let ch = c[i];
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < c.len() {
                out.push(c[i + 1]);
                i += 1;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if ch == ',' {
            let next = c[i + 1..].iter().find(|x| !x.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

fn read_tsconfig(file: &Path, depth: usize) -> Option<TsConfig> {
    let text = crate::inputs::note(&file, std::fs::read_to_string(&file)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&strip_jsonc(&text)).ok()?;
    let dir = file.parent().unwrap_or(Path::new("")).to_path_buf();
    // a relative `extends` supplies what this file does not set
    let mut cfg = match v["extends"].as_str().filter(|e| e.starts_with('.') && depth < 5) {
        Some(e) => {
            let mut p = dir.join(e);
            if p.extension().is_none() {
                p.set_extension("json");
            }
            read_tsconfig(&p, depth + 1).unwrap_or_default()
        }
        None => TsConfig::default(),
    };
    let opts = &v["compilerOptions"];
    if let Some(b) = opts["baseUrl"].as_str() {
        cfg.base_url = Some(dir.join(b));
    }
    if let Some(paths) = opts["paths"].as_object() {
        cfg.paths = paths
            .iter()
            .map(|(k, v)| (k.clone(), v.as_array().into_iter().flatten().filter_map(|t| t.as_str().map(String::from)).collect()))
            .collect();
        cfg.paths_base = cfg.base_url.clone().unwrap_or_else(|| dir.clone());
    }
    Some(cfg)
}

#[derive(Default)]
pub struct Manifests {
    ts: HashMap<PathBuf, TsConfig>,
    /// `(module path, directory)` of every `go.mod`.
    pub go_modules: Vec<(String, PathBuf)>,
    /// Crate name (with `_`) -> its library root file.
    pub crates: HashMap<String, PathBuf>,
    /// Root files of crates (`[lib] path`, `[[bin]] path`, `src/lib.rs`, `src/main.rs`).
    pub rust_roots: Vec<PathBuf>,
    /// npm packages by name.
    pub js_packages: HashMap<String, JsPackage>,
    /// Python import roots (`src`, `package-dir`, `where`, `pythonpath`), nearest project last.
    pub py_roots: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone)]
pub struct JsPackage {
    pub dir: PathBuf,
    /// `exports` (a string stands for `"."`): subpath -> conditions in file order.
    pub exports: Vec<(String, Vec<String>)>,
    /// `module`, `main`, `types` / `typings`.
    pub entries: Vec<String>,
}

impl JsPackage {
    /// Candidate paths for `sub` (`""` or `"x/y"`), most specific first. They may lack an extension.
    pub fn candidates(&self, sub: &str) -> Vec<PathBuf> {
        let key = if sub.is_empty() { ".".to_string() } else { format!("./{sub}") };
        let mut out = vec![];
        if !self.exports.is_empty() {
            for (pat, targets) in &self.exports {
                let cap = match pat.split_once('*') {
                    Some((pre, post)) => (key.len() >= pre.len() + post.len() && key.starts_with(pre) && key.ends_with(post))
                        .then(|| key[pre.len()..key.len() - post.len()].to_string()),
                    None => (*pat == key).then(String::new),
                };
                if let Some(cap) = cap {
                    out.extend(targets.iter().map(|t| self.dir.join(t.replace('*', &cap))));
                    return out; // `exports` hides everything it does not list
                }
            }
            return out;
        }
        if sub.is_empty() {
            out.extend(self.entries.iter().map(|e| self.dir.join(e)));
            out.push(self.dir.clone());
        } else {
            out.push(self.dir.join(sub));
        }
        out
    }
}

/// Flatten an `exports` target: a string, an array, or conditions (`import`, `require`, ..).
fn export_targets(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| export_targets(x, out)),
        serde_json::Value::Object(o) => {
            // conditions in the author's order, type-only ones last
            for (k, x) in o {
                if k != "types" {
                    export_targets(x, out);
                }
            }
            if let Some(x) = o.get("types") {
                export_targets(x, out);
            }
        }
        _ => {}
    }
}

impl Manifests {
    /// Look for manifests in the directories of `files` and their parents.
    pub fn discover<'a>(files: impl Iterator<Item = &'a Path>) -> Self {
        let mut m = Self::default();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        for f in files {
            let mut d = f.parent().map(Path::to_path_buf);
            for _ in 0..40 {
                let Some(dir) = d else { break };
                if !seen.insert(dir.clone()) {
                    break; // this directory and its parents are done
                }
                m.read_dir(&dir);
                d = if dir.as_os_str().is_empty() { None } else { dir.parent().map(Path::to_path_buf) };
            }
        }
        m
    }

    fn read_dir(&mut self, dir: &Path) {
        for name in ["tsconfig.json", "jsconfig.json"] {
            if !self.ts.contains_key(dir)
                && let Some(c) = read_tsconfig(&dir.join(name), 0)
            {
                self.ts.insert(dir.to_path_buf(), c);
            }
        }
        if let Ok(text) = crate::inputs::note(&dir.join("go.mod"), std::fs::read_to_string(&dir.join("go.mod"))) {
            if let Some(m) = go_module_name(&text) {
                self.add_go_module(m, dir);
            }
            self.add_go_replaces(&text, dir);
        }
        if let Ok(text) = crate::inputs::note(&dir.join("go.work"), std::fs::read_to_string(&dir.join("go.work"))) {
            for u in go_directive(&text, "use") {
                let d = dir.join(u.trim_matches('"'));
                if let Ok(t) = crate::inputs::note(&d.join("go.mod"), std::fs::read_to_string(&d.join("go.mod")))
                    && let Some(m) = go_module_name(&t)
                {
                    self.add_go_module(m, &d);
                }
            }
            self.add_go_replaces(&text, dir);
        }
        self.read_package_json(dir, true);
        self.read_pyproject(dir);
        if let Ok(text) = crate::inputs::note(&dir.join("Cargo.toml"), std::fs::read_to_string(&dir.join("Cargo.toml")))
            && let Ok(v) = text.parse::<toml::Table>()
            && let Some(pkg) = v.get("package").and_then(|p| p.as_table())
        {
            let lib = v.get("lib").and_then(|l| l.as_table());
            let name = lib
                .and_then(|l| l.get("name"))
                .or_else(|| pkg.get("name"))
                .and_then(|n| n.as_str())
                .map(|n| n.replace('-', "_"));
            let root = dir.join(lib.and_then(|l| l.get("path")).and_then(|p| p.as_str()).unwrap_or("src/lib.rs"));
            if let Some(name) = name {
                self.crates.insert(name, root.clone());
            }
            self.rust_roots.push(root);
            let mut bins: Vec<String> = vec![];
            for b in v.get("bin").and_then(|b| b.as_array()).into_iter().flatten() {
                bins.extend(b.get("path").and_then(|p| p.as_str()).map(String::from));
            }
            if bins.is_empty() {
                bins.push("src/main.rs".into());
            }
            self.rust_roots.extend(bins.into_iter().map(|b| dir.join(b)));
        }
    }

    /// `replace example.com/x [v1] => ../x`: a local directory stands for the module.
    fn add_go_replaces(&mut self, text: &str, dir: &Path) {
        for r in go_directive(text, "replace") {
            let Some((from, to)) = r.split_once("=>") else { continue };
            let to = to.split_whitespace().next().unwrap_or("").trim_matches('"');
            if to.starts_with('.') || to.starts_with('/') {
                let module = from.split_whitespace().next().unwrap_or("").trim_matches('"').to_string();
                self.add_go_module(module, &dir.join(to));
            }
        }
    }

    fn add_go_module(&mut self, module: String, dir: &Path) {
        if !module.is_empty() && !self.go_modules.iter().any(|(m, d)| *m == module && d == dir) {
            self.go_modules.push((module, dir.to_path_buf()));
        }
    }

    /// `name`, `exports`, `main`; with `workspaces` the member packages too.
    fn read_package_json(&mut self, dir: &Path, expand: bool) {
        let Ok(text) = crate::inputs::note(&dir.join("package.json"), std::fs::read_to_string(&dir.join("package.json"))) else { return };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return };
        if let Some(name) = v["name"].as_str() {
            let mut pkg = JsPackage { dir: dir.to_path_buf(), ..Default::default() };
            match &v["exports"] {
                serde_json::Value::Null => {}
                serde_json::Value::Object(o) if o.keys().any(|k| k.starts_with('.')) => {
                    for (k, x) in o {
                        let mut t = vec![];
                        export_targets(x, &mut t);
                        pkg.exports.push((k.clone(), t));
                    }
                }
                // a string, an array, or conditions without subpaths stand for "."
                e => {
                    let mut t = vec![];
                    export_targets(e, &mut t);
                    pkg.exports.push((".".into(), t));
                }
            }
            for k in ["module", "main", "types", "typings"] {
                pkg.entries.extend(v[k].as_str().map(String::from));
            }
            self.js_packages.entry(name.to_string()).or_insert(pkg);
        }
        if !expand {
            return;
        }
        let patterns: Vec<&str> = match &v["workspaces"] {
            serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
            serde_json::Value::Object(o) => o.get("packages").and_then(|p| p.as_array()).into_iter().flatten().filter_map(|x| x.as_str()).collect(),
            _ => vec![],
        };
        for pat in patterns.into_iter().filter(|p| !p.starts_with('!')) {
            for d in expand_glob(dir, pat) {
                self.read_package_json(&d, false);
            }
        }
    }

    /// Import roots of a Python project: `src` and what the build config names.
    fn read_pyproject(&mut self, dir: &Path) {
        let Ok(text) = crate::inputs::note(&dir.join("pyproject.toml"), std::fs::read_to_string(&dir.join("pyproject.toml"))) else { return };
        let Ok(v) = text.parse::<toml::Table>() else { return };
        let mut roots: Vec<PathBuf> = vec![dir.to_path_buf(), dir.join("src")];
        let tool = v.get("tool").and_then(|t| t.as_table());
        let strs = |x: Option<&toml::Value>| -> Vec<String> {
            x.and_then(|a| a.as_array()).into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect()
        };
        if let Some(st) = tool.and_then(|t| t.get("setuptools")).and_then(|s| s.as_table()) {
            // `package-dir = {"" = "lib"}`
            if let Some(d) = st.get("package-dir").and_then(|p| p.as_table()).and_then(|p| p.get("")).and_then(|d| d.as_str()) {
                roots.push(dir.join(d));
            }
            let find = st.get("packages").and_then(|p| p.as_table()).and_then(|p| p.get("find")).and_then(|f| f.as_table());
            roots.extend(strs(find.and_then(|f| f.get("where"))).into_iter().map(|w| dir.join(w)));
        }
        // poetry: `packages = [{ include = "pkg", from = "lib" }]`
        if let Some(ps) = tool.and_then(|t| t.get("poetry")).and_then(|p| p.get("packages")).and_then(|p| p.as_array()) {
            roots.extend(ps.iter().filter_map(|p| p.get("from")).filter_map(|f| f.as_str()).map(|f| dir.join(f)));
        }
        // pytest: `pythonpath = ["lib"]`
        roots.extend(strs(tool.and_then(|t| t.get("pytest")).and_then(|p| p.get("ini_options")).and_then(|p| p.get("pythonpath"))).into_iter().map(|p| dir.join(p)));
        // hatch / pdm: `sources = ["lib"]`, `package-dir = "lib"`
        roots.extend(strs(tool.and_then(|t| t.get("hatch")).and_then(|h| h.get("build")).and_then(|b| b.get("sources"))).into_iter().map(|p| dir.join(p)));
        if let Some(d) = tool.and_then(|t| t.get("pdm")).and_then(|p| p.get("build")).and_then(|b| b.get("package-dir")).and_then(|d| d.as_str()) {
            roots.push(dir.join(d));
        }
        for r in roots {
            if !self.py_roots.contains(&r) {
                self.py_roots.push(r);
            }
        }
    }

    /// The nearest tsconfig at or above `dir`.
    pub fn tsconfig(&self, dir: &Path) -> Option<&TsConfig> {
        let mut d = Some(dir);
        while let Some(x) = d {
            if let Some(c) = self.ts.get(x) {
                return Some(c);
            }
            d = if x.as_os_str().is_empty() { None } else { x.parent() };
        }
        None
    }
}

/// The `module` path of a go.mod.
fn go_module_name(text: &str) -> Option<String> {
    go_directive(text, "module").into_iter().next().map(|m| m.trim_matches('"').to_string())
}

/// Values of a go.mod / go.work directive, in both `use ./a` and block form.
fn go_directive(text: &str, key: &str) -> Vec<String> {
    let mut out = vec![];
    let mut in_block = false;
    for l in text.lines() {
        let l = l.split("//").next().unwrap_or("").trim();
        if in_block {
            if l == ")" {
                in_block = false;
            } else if !l.is_empty() {
                out.push(l.to_string());
            }
        } else if let Some(r) = l.strip_prefix(key).filter(|r| r.starts_with(char::is_whitespace) || r.starts_with('(')) {
            let r = r.trim();
            if r == "(" {
                in_block = true;
            } else if !r.is_empty() {
                out.push(r.to_string());
            }
        }
    }
    out
}

/// Directories matching a workspace pattern: literal paths, or `*` / `**` as a segment.
fn expand_glob(base: &Path, pat: &str) -> Vec<PathBuf> {
    let mut dirs = vec![base.to_path_buf()];
    for seg in pat.trim_matches('/').split('/').filter(|s| *s != ".") {
        let mut next = vec![];
        for d in &dirs {
            if seg == "*" || seg == "**" {
                match crate::inputs::subdirs(d) {
                    Some(subs) => {
                        crate::inputs::record_listing(d, &subs);
                        next.extend(subs);
                    }
                    None => crate::inputs::record_missing_listing(d),
                }
            } else {
                next.push(d.join(seg));
            }
        }
        dirs = next;
    }
    dirs
}
