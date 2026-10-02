//! What variables, containers and fields hold, for the call graph: the functions put in
//! them (`handlers = {"a": f}`, `hs.append(g)`) and the classes of the objects
//! (`rs = [R(), S()]`). A container is one value: `xs`, `xs[i]` and `for x in xs` all hold
//! whatever was ever put into `xs`; a literal index (`xs[0]`) keeps its own entry.

use super::callgraph::{Resolved, Resolver, call_class, class_of};
use super::taint::arg_for;
use crate::ir::{Cfg, Flow};
use crate::lang::Language;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Calls that put their arguments into the container they are called on.
const ADDERS: &[&str] =
    &["append", "add", "push", "push_back", "push_front", "insert", "put", "extend", "appendleft", "offer", "set", "setdefault", "register"];

/// Calls that hand out the elements of the container they are called on.
const ELEMENTS: &[&str] =
    &["values", "copy", "clone", "iter", "iter_mut", "into_iter", "cloned", "to_vec", "stream", "elements", "items", "iteritems", "itervalues", "entries"];

/// Calls that hand out one element of the container they are called on (functions only: the
/// result may as well be a different kind of object, `session.get(url)`).
const GETTERS: &[&str] = &["get", "pop", "getOrDefault", "at", "first", "last", "next", "peek", "poll", "unwrap", "remove"];

/// Calls (or constructors) that create an empty container.
const EMPTY: &[&str] = &[
    "dict", "list", "set", "deque", "defaultdict", "OrderedDict", "ArrayList", "LinkedList", "HashMap", "HashSet", "TreeMap", "Map", "Set",
    "Array", "make", "Vec.new", "Vec.with_capacity", "HashMap.new", "BTreeMap.new", "VecDeque.new",
];

/// A call that may reach more functions than this is not followed for what it returns or receives.
const MAX_CALLEES: usize = 3;

/// What a variable may hold. `unknown` when something else may also be in it.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Held {
    pub fns: BTreeSet<usize>,
    pub classes: BTreeSet<String>,
    unknown: bool,
}

impl Held {
    fn unknown() -> Self {
        Self { unknown: true, ..Self::default() }
    }

    /// Adds `other`; true if that changed anything.
    fn merge(&mut self, other: &Held) -> bool {
        let before = (self.fns.len(), self.classes.len(), self.unknown);
        self.fns.extend(other.fns.iter().copied());
        self.classes.extend(other.classes.iter().cloned());
        self.unknown |= other.unknown;
        before != (self.fns.len(), self.classes.len(), self.unknown)
    }

    /// Something is known and nothing unknown may be mixed in.
    pub fn known(&self) -> bool {
        !self.unknown && !(self.fns.is_empty() && self.classes.is_empty())
    }
}

/// `a[i].b['k']` -> `a.b`
pub(crate) fn strip_keys(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut depth = 0usize;
    for c in p.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// The statement ends with an empty container literal (`xs = []`, `m := map[string]func(){}`).
fn is_empty_literal(text: &str) -> bool {
    let t = text.trim().trim_end_matches(';').trim_end();
    ["{}", "[]", "()", "{ }", "[ ]"].iter().any(|e| t.ends_with(e))
}

/// In a statement like `for k, v in d.items()`, is `target` the first name of the pair?
fn is_pair_key(text: &str, target: &str) -> bool {
    let head = text.split([' ', '\t']).take_while(|w| !matches!(*w, "in" | "of")).collect::<Vec<_>>().join(" ");
    let mut from = 0;
    while let Some(i) = head[from..].find(target) {
        let (s, e) = (from + i, from + i + target.len());
        let word = |c: char| c.is_alphanumeric() || c == '_';
        let before_ok = !head[..s].chars().next_back().is_some_and(word);
        let after = &head[e..];
        if before_ok && !after.chars().next().is_some_and(word) && after.trim_start().starts_with(',') {
            return true;
        }
        from = e;
    }
    false
}

/// Where a value is stored.
enum Slot {
    Local(String),
    /// `(class, field)`
    Field(String),
}

struct Info {
    file: usize,
    class: Option<String>,
    receiver: Option<String>,
    /// Names the function assigns or takes as parameters.
    declared: HashSet<String>,
}

type Env = HashMap<String, Held>;
type Fields = HashMap<(String, String), Held>;

pub(crate) struct Values {
    locals: Vec<Env>,
    fields: Fields,
    /// Per file, what its `<module>` code holds.
    globals: Vec<Env>,
    info: Vec<Info>,
    /// What each function may return.
    rets: Vec<Held>,
    /// Per function, what its callers pass for each parameter name (none: not called, so unknown).
    passed: Vec<HashMap<String, Held>>,
    /// Per function, what it adds to the container each parameter names (`def fill(hs): hs.append(f)`).
    adds: Vec<HashMap<String, Held>>,
}

/// What `path` holds in `env`. A literal key (`xs[0]`, `d['a']`) reads that element when it was
/// stored on its own, plus whatever was stored at an unknown position (`xs.append(f)`,
/// `xs[i] = f`); any other key, or an element never stored by key, reads the whole container.
fn read_env(env: &Env, path: &str) -> Option<Held> {
    let s = strip_keys(path);
    if path != s
        && let Some(exact) = env.get(path)
        && !env.get(&s).is_some_and(|b| b.unknown)
    {
        let mut h = exact.clone();
        if let Some(w) = env.get(&format!("{s}[*]")) {
            h.merge(w);
        }
        return Some(h);
    }
    env.get(&s).cloned()
}

/// What a call hands back and takes in, found while computing a function's locals.
struct Computed {
    env: Env,
    ret: Held,
    /// `(callee, parameter name, what is passed)` for every call to a scanned function.
    passed: Vec<(usize, String, Held)>,
    /// What the function stores into each of its parameters at a position that is not a literal.
    adds: HashMap<String, Held>,
}

struct Ctx<'a> {
    fns: &'a [(usize, Language, &'a Cfg)],
    resolver: &'a Resolver,
    /// Lambdas and closures by `(file, line, column)`.
    closures: &'a HashMap<(usize, usize, usize), usize>,
    /// What each callee text resolves to in each file, and the class it constructs or returns.
    resolved: RefCell<ResolveCache>,
}

type ResolveCache = HashMap<(usize, String), (Resolved, Option<String>)>;

impl Values {
    pub(crate) fn infer(fns: &[(usize, Language, &Cfg)], resolver: &Resolver) -> Self {
        let closures: HashMap<(usize, usize, usize), usize> =
            fns.iter().enumerate().filter(|(_, f)| f.2.col > 0).map(|(n, f)| ((f.0, f.2.line, f.2.col), n)).collect();
        let cx = Ctx { fns, resolver, closures: &closures, resolved: RefCell::new(HashMap::new()) };
        let info: Vec<Info> = fns
            .iter()
            .map(|&(file, _, cfg)| Info {
                file,
                class: cfg.receiver.as_ref().and_then(|_| class_of(&cfg.name)),
                receiver: cfg.receiver.clone(),
                declared: cfg
                    .graph
                    .node_weights()
                    .flat_map(|b| &b.stmts)
                    .flat_map(|s| &s.assigns)
                    .map(|a| strip_keys(&a.target))
                    .chain(cfg.params.iter().flatten().cloned())
                    .collect(),
            })
            .collect();
        let nfiles = fns.iter().map(|f| f.0 + 1).max().unwrap_or(0);
        let module_of: HashMap<usize, usize> = fns.iter().enumerate().filter(|(_, f)| f.2.name == "<module>").map(|(n, f)| (f.0, n)).collect();
        let mut v = Self {
            locals: vec![Env::new(); fns.len()],
            fields: Fields::new(),
            globals: vec![Env::new(); nfiles],
            info,
            rets: vec![Held::unknown(); fns.len()],
            passed: vec![HashMap::new(); fns.len()],
            adds: vec![HashMap::new(); fns.len()],
        };
        // module variables, fields, returns and arguments feed the functions that read them,
        // which feed them back: each round learns one more step
        for _ in 0..5 {
            let mut fields = Fields::new();
            let mut locals = Vec::with_capacity(fns.len());
            let mut rets = Vec::with_capacity(fns.len());
            let mut adds = Vec::with_capacity(fns.len());
            let mut passed: Vec<HashMap<String, Held>> = vec![HashMap::new(); fns.len()];
            for n in 0..fns.len() {
                let c = cx.compute(n, &v, &mut fields);
                locals.push(c.env);
                rets.push(c.ret);
                adds.push(c.adds);
                for (id, name, h) in c.passed {
                    passed[id].entry(name).or_default().merge(&h);
                }
            }
            let mut globals = vec![Env::new(); nfiles];
            for (&file, &n) in &module_of {
                globals[file] = locals[n].clone();
            }
            let same = fields == v.fields && globals == v.globals && locals == v.locals && rets == v.rets && passed == v.passed && adds == v.adds;
            v.locals = locals;
            v.fields = fields;
            v.globals = globals;
            v.rets = rets;
            v.passed = passed;
            v.adds = adds;
            if same {
                break;
            }
        }
        v
    }

    /// What the variable, field or container named `path` (as a call writes its callee,
    /// possibly with literal keys) holds in function `n`, if that is known.
    pub(crate) fn lookup(&self, n: usize, path: &str) -> Option<Held> {
        self.find(n, path).filter(|h| h.known())
    }

    fn find(&self, n: usize, path: &str) -> Option<Held> {
        let s = strip_keys(path);
        let info = &self.info[n];
        if let Some(h) = read_env(&self.locals[n], path) {
            return Some(h);
        }
        if let (Some(c), Some(r)) = (&info.class, &info.receiver)
            && let Some(f) = s.strip_prefix(r.as_str()).and_then(|x| x.strip_prefix('.')).filter(|f| !f.contains('.'))
        {
            return self.fields.get(&(c.clone(), f.to_string())).cloned();
        }
        let root = s.split('.').next().unwrap_or(&s);
        if info.declared.contains(root) { None } else { read_env(&self.globals[info.file], path) }
    }
}

impl Ctx<'_> {
    /// The function a value names: a lambda written at `<fn@line:col>` or a free function.
    fn fn_value(&self, p: &str, n: usize) -> Option<usize> {
        let file = self.fns[n].0;
        let at = p.strip_prefix("<fn@").and_then(|r| r.strip_suffix('>')).and_then(|r| r.split_once(':'));
        if let Some((l, c)) = at
            && let (Ok(l), Ok(c)) = (l.parse(), c.parse())
            && let Some(&id) = self.closures.get(&(file, l, c))
        {
            return Some(id);
        }
        self.resolver.free_function(p, file)
    }

    /// What the callee of `c` resolves to from file `fi`, and the class it makes (cached).
    fn resolve(&self, c: &crate::ir::CallFlow, fi: usize) -> (Resolved, Option<String>) {
        let key = (fi, c.callee.clone());
        if let Some(r) = self.resolved.borrow().get(&key) {
            return r.clone();
        }
        let r = (self.resolver.resolve(&c.callee, fi), call_class(self.resolver, self.fns, c, fi));
        self.resolved.borrow_mut().insert(key, r.clone());
        r
    }

    fn eval(&self, n: usize, flow: &Flow, v: &Values, env: &Env) -> Held {
        match flow {
            Flow::Clean => Held::default(),
            Flow::Join(parts) => {
                let mut h = Held::default();
                for p in parts {
                    h.merge(&self.eval(n, p, v, env));
                }
                h
            }
            Flow::Path(p) => {
                let s = strip_keys(p);
                if let Some(h) = read_env(env, p) {
                    return h;
                }
                let info = &v.info[n];
                if let (Some(c), Some(r)) = (&info.class, &info.receiver)
                    && let Some(f) = s.strip_prefix(r.as_str()).and_then(|x| x.strip_prefix('.')).filter(|f| !f.contains('.'))
                {
                    return v.fields.get(&(c.clone(), f.to_string())).cloned().unwrap_or_else(Held::unknown);
                }
                let root = s.split('.').next().unwrap_or(&s);
                if !info.declared.contains(root) {
                    if let Some(h) = read_env(&v.globals[info.file], p) {
                        return h;
                    }
                    if let Some(id) = self.fn_value(&s, n).or_else(|| self.fn_value(p, n)) {
                        return Held { fns: BTreeSet::from([id]), ..Held::default() };
                    }
                }
                Held::unknown()
            }
            Flow::Call(c) => {
                let (head, last) = c.callee.rsplit_once('.').unwrap_or(("", &c.callee));
                let fi = self.fns[n].0;
                let (r, class) = self.resolve(c, fi);
                let own = r.ids.is_empty();
                // `Object.values(x)`, `list(x)`, `enumerate(x)`: the elements of the argument
                if own
                    && c.args.len() == 1
                    && (matches!(last, "values" | "entries" | "items" | "from")
                        || (head.is_empty() && matches!(last, "list" | "tuple" | "set" | "sorted" | "reversed" | "iter" | "enumerate")))
                {
                    return self.eval(n, &c.args[0], v, env);
                }
                if let Some(recv) = &c.recv {
                    if ELEMENTS.contains(&last) {
                        return self.eval(n, recv, v, env);
                    }
                    if own && GETTERS.contains(&last) {
                        let mut h = self.eval(n, recv, v, env);
                        h.classes.clear();
                        return h;
                    }
                }
                if own && (EMPTY.contains(&c.callee.as_str()) || (head.is_empty() && matches!(last, "list" | "tuple" | "set" | "sorted") && c.args.is_empty())) {
                    return Held::default();
                }
                // Go: `hs = append(hs, f)`
                if own && head.is_empty() && last == "append" {
                    let mut h = Held::default();
                    for arg in &c.args {
                        h.merge(&self.eval(n, arg, v, env));
                    }
                    return h;
                }
                if let Some(class) = class {
                    return Held { classes: BTreeSet::from([class]), ..Held::default() };
                }
                // what the scanned function(s) return
                if r.exact && (1..=MAX_CALLEES).contains(&r.ids.len()) {
                    let mut h = Held::default();
                    for &id in &r.ids {
                        h.merge(&v.rets[id]);
                    }
                    return h;
                }
                Held::unknown()
            }
        }
    }

    /// The locals of function `n`; what it stores in fields goes to `fields`.
    fn compute(&self, n: usize, v: &Values, fields: &mut Fields) -> Computed {
        let cfg = self.fns[n].2;
        let fi = self.fns[n].0;
        let info = &v.info[n];
        // `wild`: the position is not a literal (`xs.append(f)`, `xs[i] = f`), so the value may
        // be at any key; it is kept apart as `xs[*]`
        let slots = |target: &str, wild: bool| -> Vec<Slot> {
            let s = strip_keys(target);
            if s.contains('.') {
                let field = info.receiver.as_ref().and_then(|r| s.strip_prefix(r.as_str())).and_then(|x| x.strip_prefix('.')).filter(|f| !f.contains('.'));
                return field.into_iter().map(|f| Slot::Field(f.to_string())).collect();
            }
            let exact = (s != target).then(|| Slot::Local(target.to_string()));
            let any = wild.then(|| Slot::Local(format!("{s}[*]")));
            exact.into_iter().chain(any).chain([Slot::Local(s)]).collect()
        };
        let stmts = || cfg.graph.node_weights().flat_map(|b| &b.stmts);
        // a name stored whole twice cannot keep the elements of either
        let mut wholes: HashMap<&str, usize> = HashMap::new();
        for a in stmts().flat_map(|s| &s.assigns).filter(|a| a.strong && !a.target.contains(['[', '.'])) {
            *wholes.entry(a.target.as_str()).or_default() += 1;
        }
        // what is stored where: assignments, and arguments added to containers
        let mut stores: Vec<(Vec<Slot>, Vec<&Flow>, bool, Held)> = vec![];
        for st in stmts() {
            for a in st.assigns.iter().chain(&st.elems) {
                let keyed = a.target.contains('[');
                // `cb = None` replaces what `cb` held; `tbl = {}` starts a container
                let replaced = a.strong && !keyed && matches!(a.value, Flow::Clean) && !is_empty_literal(&st.text);
                let wild = !keyed && !a.target.contains('.') && (!a.strong || wholes.get(a.target.as_str()).is_some_and(|&c| c > 1));
                // `for k, v in d.items()`: the key (or index) is not what the container holds
                if is_pair_key(&st.text, &a.target) && matches!(&a.value, Flow::Call(c) if matches!(c.callee.rsplit('.').next(), Some("items" | "iteritems" | "entries" | "enumerate"))) {
                    stores.push((slots(&a.target, false), vec![], false, Held::default()));
                    continue;
                }
                stores.push((slots(&a.target, wild), vec![&a.value], replaced, Held::default()));
            }
            for c in &st.calls {
                if let Some((head, m)) = c.callee.rsplit_once('.')
                    && ADDERS.contains(&m)
                    && info.receiver.as_deref() != Some(head)
                {
                    let target = c.recv.as_ref().and_then(|r| if let Flow::Path(p) = r { Some(p.as_str()) } else { None }).unwrap_or(head);
                    stores.push((slots(target, true), c.args.iter().collect(), false, Held::default()));
                }
                // `fill(hs)`: what the callee adds to the container it is given
                let (r, _) = self.resolve(c, fi);
                if r.exact && (1..=MAX_CALLEES).contains(&r.ids.len()) {
                    for &id in &r.ids {
                        let params = &self.fns[id].2.params;
                        for (j, names) in params.iter().enumerate() {
                            if let Some(Flow::Path(arg)) = arg_for(c, j, params) {
                                for h in names.iter().filter_map(|name| v.adds[id].get(name)) {
                                    stores.push((slots(arg, true), vec![], false, h.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
        // a name is empty until something is stored in it; a parameter holds what its callers pass
        let mut env = Env::new();
        for a in stmts().flat_map(|s| &s.assigns) {
            let s = strip_keys(&a.target);
            if !s.contains('.') {
                env.entry(s).or_default();
            }
        }
        for p in cfg.params.iter().flatten() {
            // the functions some caller passes are held even if other callers pass something
            // we cannot see; for objects that would hide the by-name guess, so any unknown wins
            let h = match v.passed[n].get(p) {
                Some(h) if h.unknown && !h.fns.is_empty() => Held { fns: h.fns.clone(), ..Held::default() },
                Some(h) => h.clone(),
                None => Held::unknown(),
            };
            env.entry(p.clone()).or_default().merge(&h);
        }
        let mut mine = Fields::new();
        for _ in 0..4 {
            let mut changed = false;
            for (targets, values, replaced, extra) in &stores {
                let mut h = if *replaced { Held::unknown() } else { extra.clone() };
                for f in values {
                    h.merge(&self.eval(n, f, v, &env));
                }
                for t in targets {
                    changed |= match t {
                        Slot::Local(name) => env.entry(name.clone()).or_default().merge(&h),
                        Slot::Field(f) => {
                            let Some(c) = &info.class else { continue };
                            mine.entry((c.clone(), f.clone())).or_default().merge(&h)
                        }
                    };
                }
            }
            if !changed {
                break;
            }
        }
        for (k, h) in mine {
            fields.entry(k).or_default().merge(&h);
        }
        let mut ret = Held::default();
        for r in stmts().filter_map(|s| s.ret.as_ref()) {
            ret.merge(&self.eval(n, r, v, &env));
        }
        // what this function hands to the scanned functions it calls
        let mut passed = vec![];
        for c in stmts().flat_map(|s| &s.calls) {
            let (r, _) = self.resolve(c, fi);
            if !r.exact || !(1..=MAX_CALLEES).contains(&r.ids.len()) {
                continue;
            }
            for id in r.ids {
                let params = &self.fns[id].2.params;
                for (j, names) in params.iter().enumerate() {
                    if let Some(arg) = arg_for(c, j, params) {
                        let h = self.eval(n, arg, v, &env);
                        passed.extend(names.iter().map(|name| (id, name.clone(), h.clone())));
                    }
                }
            }
        }
        let adds = cfg.params.iter().flatten().filter_map(|p| Some((p.clone(), env.get(&format!("{p}[*]"))?.clone()))).collect();
        Computed { env, ret, passed, adds }
    }
}
