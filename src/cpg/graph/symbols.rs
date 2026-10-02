//! Symbols: the lexical scope tree, the fields of classes, what every name refers to,
//! and which class inherits from which.
//!
//! * `Scope` edges link a method or class to the scope around it (file, class, method,
//!   closure). A method's `Param` and `Local` nodes belong to its scope; a class's
//!   `Field` nodes belong to its `TypeDecl`.
//! * `Field` nodes stand for the fields a class declares (`field_types`) or assigns through
//!   its receiver (`self.f = ..`); `TypeOf` links them to their declared `Type`.
//! * `Ref` edges link an identifier to the `Param` or `Local` it names, looking outwards
//!   through enclosing functions (a variable of an outer function is a captured variable),
//!   then to a `Field` of the class (a bare name in a Java / C++ method). A member access
//!   `self.f` / `this.f`, or `x.f` where `x` is declared with a class, links to that class's `Field`.
//! * `Inherits` edges link a class declaration to those of its bases, when each name is unique:
//!   the bases named in its declaration (so also for a class without methods), and in Go the
//!   types it embeds and the interfaces it satisfies by shape (its methods, with those
//!   promoted from embedded types, include all the interface's).
//!
//! Names are resolved without flow sensitivity: a variable is the one its function declares,
//! whichever statement comes first.

use super::*;
use crate::analysis::callgraph::{class_of, simple_name};

/// A class: `(language family, simple name)`.
type Class = (u8, String);

impl Cpg {
    pub(super) fn add_symbols(&mut self, files: &[SourceFile], seen: &mut EdgeSet) {
        let cfgs: Vec<&Cfg> = files.iter().flat_map(|f| f.cfgs.iter()).collect();
        let fn_file: Vec<usize> = files.iter().enumerate().flat_map(|(fi, f)| f.cfgs.iter().map(move |_| fi)).collect();
        let fam = |fi: usize| files[fi].lang.family();
        let fn_of: HashMap<NodeIndex, usize> = self.methods.iter().enumerate().rev().map(|(i, &m)| (m, i)).collect();

        // class declarations by name
        let mut decls: HashMap<Class, Vec<NodeIndex>> = HashMap::new();
        for (fi, info) in self.files.iter().enumerate() {
            for (i, n) in info.ast.nodes.iter().enumerate().filter(|(_, n)| n.kind == NodeKind::TypeDecl) {
                if let Some(name) = &n.name {
                    decls.entry((fam(fi), simple_name(name).to_string())).or_default().push(info.nodes[i]);
                }
            }
        }
        let decl_of = |c: &Class| decls.get(c).filter(|d| d.len() == 1).map(|d| d[0]);

        self.add_scopes(seen);

        // fields, by class
        let mut fields: HashMap<(Class, String), NodeIndex> = HashMap::new();
        for (i, cfg) in cfgs.iter().enumerate() {
            let (Some(recv), Some(class)) = (&cfg.receiver, class_of(&cfg.name)) else { continue };
            let class: Class = (fam(fn_file[i]), simple_name(&class).to_string());
            let mut names: Vec<(&str, Option<&str>)> = cfg.field_types.iter().map(|(f, t)| (f.as_str(), Some(t.as_str()))).collect();
            for a in cfg.graph.node_weights().flat_map(|b| &b.stmts).flat_map(|s| &s.assigns) {
                if let Some(rest) = a.target.strip_prefix(recv.as_str()).and_then(|r| r.strip_prefix('.')) {
                    names.push((rest.split(['.', '[']).next().unwrap_or(rest), None));
                }
            }
            for (name, ty) in names {
                let key = (class.clone(), name.to_string());
                let node = match fields.get(&key) {
                    Some(&n) => n,
                    None => {
                        let fi = fn_file[i];
                        let owner = decl_of(&class).filter(|d| self.graph[*d].file == fi).unwrap_or(self.files[fi].nodes[0]);
                        let n = self.synthetic(fi, NodeKind::Field, owner, name.to_string(), seen);
                        self.graph[n].name = Some(name.to_string());
                        fields.insert(key, n);
                        n
                    }
                };
                if let Some(ty) = ty.and_then(|t| self.type_node(self.graph[node].file, t, node, seen)) {
                    self.edge(node, ty, EdgeKind::TypeOf, None, seen);
                }
            }
        }

        // base classes by class (names as written)
        let mut bases: HashMap<Class, Vec<String>> = HashMap::new();
        for (i, cfg) in cfgs.iter().enumerate() {
            if let Some(class) = class_of(&cfg.name) {
                let e = bases.entry((fam(fn_file[i]), simple_name(&class).to_string())).or_default();
                for b in &cfg.class_bases {
                    if !e.contains(b) {
                        e.push(b.clone());
                    }
                }
            }
        }
        // the field `name` of `class`, or of the nearest base class that has it
        let find_field = |class: &Class, name: &str| -> Option<NodeIndex> {
            let mut seen_classes: Vec<Class> = vec![];
            let mut queue = vec![class.clone()];
            while let Some(c) = queue.pop() {
                if seen_classes.contains(&c) {
                    continue;
                }
                if let Some(&f) = fields.get(&(c.clone(), name.to_string())) {
                    return Some(f);
                }
                queue.extend(bases.get(&c).into_iter().flatten().map(|b| (c.0, simple_name(b).to_string())));
                seen_classes.push(c);
            }
            None
        };

        // the locals of each function
        let locals: Vec<HashMap<String, NodeIndex>> = self
            .methods
            .clone()
            .into_iter()
            .map(|m| {
                self.out(m, EdgeKind::Contains)
                    .filter(|&n| self.graph[n].kind == NodeKind::Local)
                    .filter_map(|n| Some((self.graph[n].name.clone()?, n)))
                    .collect()
            })
            .collect();
        // a declared class of a parameter or local, through its `TypeOf` edge
        let class_of_var = |cpg: &Cpg, v: NodeIndex| -> Option<String> {
            cpg.out(v, EdgeKind::TypeOf).find_map(|t| cpg.graph[t].name.clone()).map(|t| simple_name(&t).to_string())
        };

        let mut refs: Vec<(NodeIndex, NodeIndex)> = vec![];
        for fi in 0..self.files.len() {
            let info = &self.files[fi];
            for (i, n) in info.ast.nodes.iter().enumerate() {
                if !matches!(n.kind, NodeKind::Identifier | NodeKind::FieldAccess) {
                    continue;
                }
                // the functions around the node, innermost first, ending with the file's top-level code
                let mut chain: Vec<usize> = vec![];
                let mut up = n.parent;
                while let Some(p) = up {
                    if info.ast.nodes[p].kind == NodeKind::Method
                        && let Some(&f) = fn_of.get(&info.nodes[p])
                    {
                        chain.push(f);
                    }
                    up = info.ast.nodes[p].parent;
                }
                if let Some(&f) = fn_of.get(&info.nodes[0]) {
                    chain.push(f);
                }
                let own_class = |cpg: &Cpg| -> Option<(usize, Class)> {
                    let f = *chain.iter().find(|&&f| cpg.receivers[f].is_some())?;
                    Some((f, (fam(fn_file[f]), simple_name(&class_of(&cfgs[f].name)?).to_string())))
                };
                let target = match n.kind {
                    NodeKind::Identifier => {
                        let Some(name) = &n.name else { continue };
                        let parent = n.parent.map(|p| &info.ast.nodes[p]);
                        // `a.b`: `b` is a member, not a variable; `f(k=v)`: `k` names an argument
                        let member = parent.is_some_and(|p| p.kind == NodeKind::FieldAccess && p.children.len() >= 2 && p.children.last() == Some(&i));
                        let keyword = n.parent.is_some_and(|p| {
                            let k = info.ast.raw_kind(p);
                            (k.contains("keyword_argument") || k.contains("named_argument")) && info.ast.nodes[p].children.first() == Some(&i)
                        });
                        if member || keyword || parent.is_some_and(|p| matches!(p.kind, NodeKind::Param | NodeKind::TypeDecl | NodeKind::Method) && p.children.first() == Some(&i) && p.kind != NodeKind::Method) {
                            continue;
                        }
                        chain
                            .iter()
                            .find_map(|&f| self.param_nodes[f].get(name).or_else(|| locals[f].get(name)).copied())
                            .or_else(|| own_class(self).and_then(|(_, c)| find_field(&c, name)))
                    }
                    _ => {
                        let (Some(member), Some(&obj)) = (&n.name, n.children.first()) else { continue };
                        let obj = &info.ast.nodes[obj];
                        if obj.kind != NodeKind::Identifier {
                            continue;
                        }
                        let oname = obj.name.as_deref().unwrap_or("");
                        let class = if let Some((f, c)) = own_class(self).filter(|(f, _)| self.receivers[*f].as_deref() == Some(oname)) {
                            let _ = f;
                            Some(c)
                        } else {
                            let var = chain.iter().find_map(|&f| self.param_nodes[f].get(oname).or_else(|| locals[f].get(oname)).copied());
                            var.and_then(|v| class_of_var(self, v)).map(|c| (fam(fi), c))
                        };
                        class.and_then(|c| find_field(&c, member))
                    }
                };
                if let Some(t) = target {
                    refs.push((info.nodes[i], t));
                }
            }
        }
        for (from, to) in refs {
            self.edge(from, to, EdgeKind::Ref, None, seen);
        }

        // inheritance: the bases the methods of a class record, and those its declaration names
        // (a class without methods has no other trace of them)
        for ((f, class), bs) in bases {
            let Some(sub) = decl_of(&(f, class)) else { continue };
            for b in bs {
                if let Some(sup) = decl_of(&(f, simple_name(&b).to_string())).filter(|&s| s != sub) {
                    self.edge(sub, sup, EdgeKind::Inherits, None, seen);
                }
            }
        }
        let mut declared: Vec<(NodeIndex, u8, String)> = vec![];
        for (fi, info) in self.files.iter().enumerate() {
            for n in info.ast.nodes.iter().enumerate().filter(|(_, n)| n.kind == NodeKind::TypeDecl) {
                declared.extend(n.1.bases.iter().map(|b| (info.nodes[n.0], fam(fi), b.clone())));
            }
        }
        for (sub, f, b) in declared {
            if let Some(sup) = decl_of(&(f, simple_name(&b).to_string())).filter(|&s| s != sub) {
                self.edge(sub, sup, EdgeKind::Inherits, None, seen);
            }
        }
        self.add_go_inheritance(&decl_of, seen);
    }

    /// Go: a struct inherits from the types it embeds, and from every interface whose methods
    /// it has (its own, or promoted from what it embeds): a type satisfies an interface by shape.
    fn add_go_inheritance(&mut self, decl_of: &dyn Fn(&Class) -> Option<NodeIndex>, seen: &mut EdgeSet) {
        let go = Language::Go.family();
        // declarations: struct -> embedded types, interface -> (methods, embedded interfaces)
        let mut embeds: HashMap<String, Vec<String>> = HashMap::new();
        let mut ifaces: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
        let mut structs: Vec<(String, NodeIndex)> = vec![];
        for info in self.files.iter().filter(|f| f.lang.family() == go) {
            for (i, n) in info.ast.nodes.iter().enumerate().filter(|(_, n)| n.kind == NodeKind::TypeDecl) {
                let Some(name) = n.name.clone() else { continue };
                let Some(&body) = n.children.iter().find(|&&c| matches!(info.ast.raw_kind(c), "struct_type" | "interface_type")) else { continue };
                let is_struct = info.ast.raw_kind(body) == "struct_type";
                let (mut methods, mut embedded) = (vec![], vec![]);
                for e in info.ast.subtree(body).into_iter().skip(1) {
                    let code = info.ast.nodes[e].code.trim();
                    match info.ast.raw_kind(e) {
                        "method_elem" => methods.extend(code.split('(').next().map(|m| m.trim().to_string())),
                        "type_elem" => embedded.push(code.trim_start_matches('*').to_string()),
                        // an embedded field has a type and no name: one bare identifier
                        "field_declaration" if !code.contains(char::is_whitespace) => embedded.push(code.trim_start_matches('*').to_string()),
                        _ => {}
                    }
                }
                if is_struct {
                    embeds.insert(name.clone(), embedded);
                    structs.push((name, info.nodes[i]));
                } else {
                    ifaces.insert(name, (methods, embedded));
                }
            }
        }
        // methods declared on each type
        let mut own: HashMap<String, Vec<String>> = HashMap::new();
        for &m in &self.methods {
            let (Some(name), true) = (self.graph[m].name.as_deref(), self.files[self.graph[m].file].lang.family() == go) else { continue };
            if let Some(class) = class_of(name) {
                own.entry(simple_name(&class).to_string()).or_default().push(simple_name(name).to_string());
            }
        }
        let methods_of = |s: &str| -> HashSet<String> {
            let (mut out, mut queue, mut seen) = (HashSet::new(), vec![s.to_string()], HashSet::new());
            while let Some(t) = queue.pop() {
                if seen.insert(t.clone()) {
                    out.extend(own.get(&t).into_iter().flatten().cloned());
                    queue.extend(embeds.get(&t).into_iter().flatten().cloned());
                }
            }
            out
        };
        let required = |i: &str| -> HashSet<String> {
            let (mut out, mut queue, mut seen) = (HashSet::new(), vec![i.to_string()], HashSet::new());
            while let Some(t) = queue.pop() {
                if seen.insert(t.clone())
                    && let Some((m, e)) = ifaces.get(&t)
                {
                    out.extend(m.iter().cloned());
                    queue.extend(e.iter().cloned());
                }
            }
            out
        };
        let mut links = vec![];
        for (name, node) in &structs {
            for e in embeds.get(name).into_iter().flatten() {
                links.push((*node, e.clone()));
            }
            let have = methods_of(name);
            for i in ifaces.keys() {
                let need = required(i);
                if !need.is_empty() && need.is_subset(&have) {
                    links.push((*node, i.clone()));
                }
            }
        }
        links.sort_by_key(|(n, t)| (n.index(), t.clone()));
        for (sub, t) in links {
            if let Some(sup) = decl_of(&(go, t)).filter(|&s| s != sub) {
                self.edge(sub, sup, EdgeKind::Inherits, None, seen);
            }
        }
    }

    /// `Scope` edges: every method and class to the nearest method or class around it, else its file.
    fn add_scopes(&mut self, seen: &mut EdgeSet) {
        let mut pairs = vec![];
        for info in &self.files {
            for (i, n) in info.ast.nodes.iter().enumerate().filter(|(_, n)| matches!(n.kind, NodeKind::Method | NodeKind::TypeDecl)) {
                let mut up = n.parent;
                while let Some(p) = up.filter(|&p| !matches!(info.ast.nodes[p].kind, NodeKind::Method | NodeKind::TypeDecl) && p != 0) {
                    up = info.ast.nodes[p].parent;
                }
                pairs.push((info.nodes[i], info.nodes[up.unwrap_or(0)]));
            }
        }
        for (inner, outer) in pairs {
            self.edge(inner, outer, EdgeKind::Scope, None, seen);
        }
    }
}
