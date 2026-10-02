//! Joins what files declare to what other files implement: struct / class fields to
//! the methods defined elsewhere (a Go struct in one file and its methods in another, a
//! C++ class in a header and `Svc::go` in the `.cpp`), and type aliases to the types
//! they stand for.

use super::callgraph::class_of;
use crate::ir::Cfg;
use crate::lang::Language;
use crate::lang::common::{Declarations, simple_name, type_name};
use std::collections::HashMap;

/// How far an alias chain (`A = B`, `B = C`, ...) is followed.
const ALIAS_DEPTH: usize = 8;

/// Fill in the declared field types of methods from struct / class definitions anywhere in
/// the project, and replace type aliases by their targets in every declared type.
pub fn link_declarations(files: &mut [(Language, &mut Vec<Cfg>, &Declarations)]) {
    let mut aliases: HashMap<(u8, String), String> = HashMap::new();
    let mut types: HashMap<(u8, String), Vec<(String, String)>> = HashMap::new();
    for (lang, _, d) in files.iter() {
        let fam = lang.family();
        for (alias, target) in &d.aliases {
            let target = type_name(target);
            if !target.is_empty() && target != *alias {
                aliases.insert((fam, alias.clone()), target);
            }
        }
        for (name, fields) in &d.types {
            types.entry((fam, name.clone())).or_default().extend(fields.iter().cloned());
        }
    }
    let mut interfaces: HashMap<(u8, String), (Vec<String>, Vec<String>)> = HashMap::new();
    for (lang, _, d) in files.iter() {
        for (name, methods, embeds) in &d.interfaces {
            let e = interfaces.entry((lang.family(), name.clone())).or_default();
            e.0.extend(methods.iter().cloned());
            e.1.extend(embeds.iter().cloned());
        }
    }
    // `type R T`: R has T's fields / interface methods (not T's methods); chains need a few rounds
    for _ in 0..ALIAS_DEPTH {
        for (lang, _, d) in files.iter() {
            let fam = lang.family();
            for (name, base) in &d.defined {
                let base = type_name(base);
                if let Some(f) = types.get(&(fam, base.clone())).cloned() {
                    types.entry((fam, name.clone())).or_insert(f);
                }
                if let Some(i) = interfaces.get(&(fam, base)).cloned() {
                    interfaces.entry((fam, name.clone())).or_insert(i);
                }
            }
        }
    }
    // the methods an interface requires, with those of the interfaces it embeds
    let methods_of = |fam: u8, name: &str| -> Option<Vec<String>> {
        interfaces.get(&(fam, name.to_string()))?;
        let (mut out, mut queue, mut seen) = (vec![], vec![name.to_string()], vec![]);
        while let Some(i) = queue.pop() {
            if seen.contains(&i) {
                continue;
            }
            seen.push(i.clone());
            if let Some((m, e)) = interfaces.get(&(fam, i)) {
                out.extend(m.iter().cloned());
                queue.extend(e.iter().cloned());
            }
        }
        out.sort();
        out.dedup();
        Some(out)
    };
    // embedded types: a struct has the methods of what it embeds
    let mut embeds: HashMap<(u8, String), Vec<String>> = HashMap::new();
    for (lang, _, d) in files.iter() {
        for (name, embedded) in &d.embeds {
            let e = embeds.entry((lang.family(), name.clone())).or_default();
            e.extend(embedded.iter().map(|t| type_name(t)).filter(|t| !t.is_empty()));
        }
    }
    let resolve = |fam: u8, t: &str| -> String {
        let mut t = t.to_string();
        for _ in 0..ALIAS_DEPTH {
            match aliases.get(&(fam, t.clone())) {
                Some(next) => t = next.clone(),
                None => break,
            }
        }
        t
    };
    let go_classes: Vec<(String, Vec<String>)> = types
        .keys()
        .filter(|(fam, _)| *fam == Language::Go.family())
        .map(|(_, name)| {
            let bases = embeds
                .get(&(Language::Go.family(), name.clone()))
                .into_iter()
                .flatten()
                .map(|base| resolve(Language::Go.family(), base))
                .collect();
            (name.clone(), bases)
        })
        .collect();
    for (lang, cfgs, _) in files.iter_mut() {
        let fam = lang.family();
        for cfg in cfgs.iter_mut() {
            if *lang == Language::Go {
                cfg.class_decls = go_classes.clone();
            }
            // fields the method's class declares, possibly in another file
            if cfg.receiver.is_some()
                && let Some(class) = class_of(&cfg.name)
                && let Some(fields) = types.get(&(fam, simple_name(&class).to_string()))
            {
                for (field, t) in fields {
                    let t = type_name(t);
                    if !t.is_empty() && !cfg.field_types.iter().any(|(f, _)| f == field) {
                        cfg.field_types.push((field.clone(), t));
                    }
                }
            }
            if !aliases.is_empty() {
                for (_, t) in cfg.param_types.iter_mut().chain(&mut cfg.local_types).chain(&mut cfg.field_types) {
                    *t = resolve(fam, t);
                }
                for t in cfg.ret_type.iter_mut().chain(&mut cfg.class_bases) {
                    *t = resolve(fam, t);
                }
            }
            if cfg.receiver.is_some()
                && let Some(class) = class_of(&cfg.name)
                && let Some(embedded) = embeds.get(&(fam, simple_name(&class).to_string()))
            {
                for e in embedded {
                    let e = resolve(fam, e);
                    if !cfg.class_bases.contains(&e) {
                        cfg.class_bases.push(e);
                    }
                }
            }
            if !interfaces.is_empty() {
                let mut found: Vec<(String, Vec<String>)> = vec![];
                for (_, t) in cfg.param_types.iter().chain(&cfg.local_types).chain(&cfg.field_types) {
                    if !found.iter().any(|(n, _)| n == t)
                        && let Some(m) = methods_of(fam, t)
                    {
                        found.push((t.clone(), m));
                    }
                }
                cfg.iface_methods = found;
            }
        }
    }
}

/// One source file after parsing and linking.
pub struct Analyzed {
    pub lang: Language,
    pub cfgs: Vec<Cfg>,
    pub imports: Vec<crate::lang::common::Import>,
}

/// Parse files (`(path, source)`) and link their declarations: what library users should call
/// instead of `lang::build_cfgs` + [`link_declarations`]. Files of unsupported languages or
/// that fail to parse are `None`; the result is in input order.
pub fn analyze_sources(files: &[(&std::path::Path, &str)]) -> Vec<Option<Analyzed>> {
    let mut parsed: Vec<Option<(Analyzed, Declarations)>> = files
        .iter()
        .map(|(p, src)| {
            let lang = Language::detect_with_source(p, src)?;
            let cfgs = crate::lang::build_cfgs(lang, src).ok()?;
            let imports = crate::lang::imports(lang, src).unwrap_or_default();
            let decls = crate::lang::declarations(lang, src).unwrap_or_default();
            Some((Analyzed { lang, cfgs, imports }, decls))
        })
        .collect();
    let mut linked: Vec<_> = parsed.iter_mut().flatten().map(|(a, d)| (a.lang, &mut a.cfgs, &*d)).collect();
    link_declarations(&mut linked);
    parsed.into_iter().map(|p| p.map(|(a, _)| a)).collect()
}
