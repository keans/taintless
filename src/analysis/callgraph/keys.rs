//! Possible literal container keys at each call site. Unknown keys stay unknown so
//! the values analysis reads the whole container.

use super::Resolver;
use crate::ir::{CallFlow, Cfg, Flow, Stmt};
use crate::lang::Language;
use petgraph::Direction;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

const MAX_KEYS: usize = 16;
const MAX_ROUNDS: usize = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Keys {
    #[default]
    Bottom,
    Known(BTreeSet<String>),
    Unknown,
}

impl Keys {
    fn join(&mut self, other: &Self) {
        match (&mut *self, other) {
            (Self::Unknown, _) | (_, Self::Bottom) => {}
            (this @ Self::Bottom, value) => *this = value.clone(),
            (Self::Known(a), Self::Known(b)) => {
                a.extend(b.iter().cloned());
                if a.len() > MAX_KEYS {
                    *self = Self::Unknown;
                }
            }
            (_, Self::Unknown) => *self = Self::Unknown,
        }
    }
}

type State = HashMap<String, Keys>;
type AtCalls = HashMap<(usize, usize), State>;

fn merge(into: &mut State, from: &State) -> bool {
    let before = into.clone();
    let names: HashSet<String> = into.keys().chain(from.keys()).cloned().collect();
    for name in names {
        let mut value = into.get(&name).cloned().unwrap_or(Keys::Unknown);
        value.join(&from.get(&name).cloned().unwrap_or(Keys::Unknown));
        if value == Keys::Unknown {
            into.remove(&name);
        } else {
            into.insert(name, value);
        }
    }
    *into != before
}

fn literal(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(';').trim();
    let value = value.rsplit_once('=').map_or(value, |(_, v)| v.trim());
    if let Some(inner) = value
        .strip_prefix(['\'', '"'])
        .and_then(|v| v.strip_suffix(['\'', '"']))
    {
        return (!inner.is_empty()
            && inner.len() <= 32
            && inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        .then(|| format!("['{inner}']"));
    }
    (!value.is_empty() && value.len() <= 6 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("[{value}]"))
}

/// The raw argument strings of a call within a statement. IR values deliberately
/// collapse literals to `Flow::Clean`, so their spelling comes from source text.
fn argument_texts(stmt: &Stmt, call: &CallFlow) -> Vec<String> {
    let simple = call.callee.rsplit('.').next().unwrap_or(&call.callee);
    let needle = format!("{simple}(");
    let Some(open) = stmt
        .text
        .find(&needle)
        .map(|i| i + needle.len() - 1)
        .or_else(|| stmt.text.find('('))
    else {
        return vec![];
    };
    let mut result = vec![];
    let base = open + 1;
    let mut start = base;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, ch) in stmt.text[base..].char_indices() {
        let i = base + offset;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' if depth == 0 => {
                result.push(stmt.text[start..i].trim().to_string());
                return result;
            }
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(stmt.text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    vec![]
}

fn value(cfg: &Cfg, line: usize, flow: &Flow, state: &State, literal_text: Option<&str>) -> Keys {
    match flow {
        Flow::Path(path) => state
            .get(&cfg.type_key(path, line))
            .cloned()
            .unwrap_or(Keys::Unknown),
        Flow::Clean => literal_text
            .and_then(literal)
            .map_or(Keys::Unknown, |key| Keys::Known(BTreeSet::from([key]))),
        _ => Keys::Unknown,
    }
}

fn scan(cfg: &Cfg, seeds: &[Keys]) -> AtCalls {
    let mut entry = State::new();
    for (param, seed) in cfg.params.iter().zip(seeds) {
        for name in param {
            entry.insert(name.clone(), seed.clone());
        }
    }
    let mut before = HashMap::from([(cfg.entry, entry)]);
    let mut queue = VecDeque::from([cfg.entry]);
    let mut calls = AtCalls::new();
    while let Some(block) = queue.pop_front() {
        let mut state = before[&block].clone();
        for stmt in &cfg.graph[block].stmts {
            for call in &stmt.calls {
                let site = (call.line, call.col);
                match calls.get_mut(&site) {
                    Some(old) => {
                        merge(old, &state);
                    }
                    None => {
                        calls.insert(site, state.clone());
                    }
                }
            }
            for assign in &stmt.assigns {
                if !assign.strong || assign.target.contains(['.', '[']) {
                    continue;
                }
                let text = (stmt.assigns.len() == 1)
                    .then(|| stmt.text.split_once('=').map(|(_, v)| v))
                    .flatten();
                let result = value(cfg, stmt.line, &assign.value, &state, text);
                let target = cfg.type_key(&assign.target, stmt.line);
                if result == Keys::Unknown {
                    state.remove(&target);
                } else {
                    state.insert(target, result);
                }
            }
        }
        for next in cfg.graph.neighbors_directed(block, Direction::Outgoing) {
            match before.get_mut(&next) {
                Some(old) => {
                    if merge(old, &state) {
                        queue.push_back(next);
                    }
                }
                None => {
                    before.insert(next, state.clone());
                    queue.push_back(next);
                }
            }
        }
    }
    calls
}

pub(super) struct KeyFacts {
    calls: Vec<AtCalls>,
}

impl KeyFacts {
    pub(super) fn infer(fns: &[(usize, Language, &Cfg)], resolver: &Resolver) -> Self {
        let mut seeds: Vec<Vec<Keys>> = fns
            .iter()
            .map(|(_, _, cfg)| vec![Keys::Bottom; cfg.params.len()])
            .collect();
        let mut calls = vec![];
        for _ in 0..MAX_ROUNDS {
            calls = fns
                .iter()
                .enumerate()
                .map(|(n, (_, _, cfg))| scan(cfg, &seeds[n]))
                .collect();
            let mut next: Vec<Vec<Keys>> = fns
                .iter()
                .map(|(_, _, cfg)| vec![Keys::Bottom; cfg.params.len()])
                .collect();
            for (caller, (file, _, cfg)) in fns.iter().enumerate() {
                for stmt in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
                    for call in &stmt.calls {
                        let Some(state) = calls[caller].get(&(call.line, call.col)) else {
                            continue;
                        };
                        let texts = argument_texts(stmt, call);
                        for callee in resolver.resolve(&call.callee, *file).ids {
                            for (j, names) in fns[callee].2.params.iter().enumerate() {
                                let Some(arg) =
                                    super::super::taint::arg_for(call, j, &fns[callee].2.params)
                                else {
                                    continue;
                                };
                                let position = call.args.iter().position(|a| std::ptr::eq(a, arg));
                                let raw = position.and_then(|i| texts.get(i)).map(String::as_str);
                                let fact = value(cfg, call.line, arg, state, raw);
                                if !names.is_empty() {
                                    next[callee][j].join(&fact);
                                }
                            }
                        }
                    }
                }
            }
            if next == seeds {
                return Self { calls };
            }
            seeds = next;
        }
        Self {
            calls: fns
                .iter()
                .enumerate()
                .map(|(n, (_, _, cfg))| scan(cfg, &seeds[n]))
                .collect(),
        }
    }

    pub(super) fn paths(&self, n: usize, cfg: &Cfg, call: &CallFlow) -> Vec<String> {
        let base = call.callee_key.as_deref().unwrap_or(&call.callee);
        let Some(state) = self.calls[n].get(&(call.line, call.col)) else {
            return vec![base.to_string()];
        };
        let mut paths = vec![String::new()];
        let mut rest = base;
        while let Some((before, after)) = rest.split_once('[') {
            for path in &mut paths {
                path.push_str(before);
            }
            let Some((key, tail)) = after.split_once(']') else {
                return vec![base.to_string()];
            };
            let values = match state.get(&cfg.type_key(key, call.line)) {
                Some(Keys::Known(keys)) if !keys.is_empty() => {
                    keys.iter().cloned().collect::<Vec<_>>()
                }
                _ => vec![format!("[{key}]")],
            };
            if paths.len() * values.len() > MAX_KEYS {
                return vec![base.to_string()];
            }
            paths = paths
                .into_iter()
                .flat_map(|path| values.iter().map(move |value| format!("{path}{value}")))
                .collect();
            rest = tail;
        }
        for path in &mut paths {
            path.push_str(rest);
        }
        paths
    }
}
