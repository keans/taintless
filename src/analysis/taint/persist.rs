//! Summaries kept between runs. After the first pass (the one that knows no tainted fields) the
//! summaries and the per-group results are stored with fingerprints; the next run starts from them
//! as the "previous pass" that `run_pass` already knows how to reuse: a group is reused when its
//! functions and what they read are unchanged, and a function whose recomputed summary equals the
//! stored one keeps its version, so the groups that read it stay valid. A change that leaves a
//! summary as it was does not travel to the callers; one that changes it does, until it stops.
//!
//! What a result depends on besides the functions' code is covered by two fingerprints: one for the
//! whole project (the functions that exist, the class hierarchy, visibility, what is known of
//! classes and of functions stored in fields) and one per function (the classes of its variables, the
//! function that created it when it is a closure). The project fingerprint changing drops
//! everything; the stored result is also dropped when a configuration file read for the run changed.

use super::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// The state of an analysis after its first pass.
#[derive(Serialize, Deserialize)]
pub struct Persisted {
    global: String,
    /// The functions of that run, by id.
    fns: Vec<FnRec>,
    summaries: Vec<Option<Summary>>,
    versions: Vec<u64>,
    comps: Vec<CompRec>,
}

#[derive(Serialize, Deserialize)]
struct FnRec {
    id: String,
    content: String,
    env: String,
}

#[derive(Serialize, Deserialize)]
struct CompRec {
    reads: Reads,
    results: Vec<(usize, FnResult)>,
}

impl Persisted {
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_stdvec(self).ok()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

fn digest(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
        h.update(b"\0");
    }
    h.finalize().to_hex().to_string()
}

/// The path of every file index in `fns`, as text.
fn file_paths(fns: &[FnInfo]) -> BTreeMap<usize, String> {
    fns.iter().map(|f| (f.file_idx, f.file.display().to_string())).collect()
}

/// A text of the files each file can see, by path: the file indexes of one run mean nothing in the next.
pub(super) fn visibility_text(fns: &[FnInfo], visible: Option<&Vec<HashSet<usize>>>) -> String {
    let Some(visible) = visible else { return String::new() };
    let paths = file_paths(fns);
    let mut rows: Vec<(String, Vec<&String>)> = vec![];
    for (fi, set) in visible.iter().enumerate() {
        let Some(path) = paths.get(&fi) else { continue };
        let mut seen: Vec<&String> = set.iter().filter_map(|o| paths.get(o)).collect();
        seen.sort();
        rows.push((path.clone(), seen));
    }
    rows.sort();
    format!("{rows:?}")
}

/// What identifies a function between runs, and what its analysis depends on.
pub(super) struct Fingerprints {
    ids: Vec<String>,
    content: Vec<String>,
    env: Vec<String>,
    global: String,
}

impl Fingerprints {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        fns: &[FnInfo],
        visibility: &str,
        types: &Types,
        classes: &HashMap<String, String>,
        closures: &HashMap<(usize, usize, usize), usize>,
        field_fns: &FieldFns,
        creators: &HashMap<usize, usize>,
    ) -> Self {
        let paths = file_paths(fns);
        let mut counts: HashMap<(usize, &str), usize> = HashMap::new();
        let ids: Vec<String> = fns
            .iter()
            .map(|f| {
                let n = counts.entry((f.file_idx, f.cfg.name.as_str())).or_default();
                *n += 1;
                format!("{}\0{}\0{n}", paths[&f.file_idx], f.cfg.name)
            })
            .collect();
        let content = fns
            .par_iter()
            .map(|f| {
                let mut h = blake3::Hasher::new();
                h.update(format!("{:?}\0{}\0", f.lang, paths[&f.file_idx]).as_bytes());
                // the function's graph goes straight into the hasher, with no buffer in between
                let mut h = postcard::to_io(f.cfg, h).unwrap_or_else(|_| blake3::Hasher::new());
                h.update(b"\0");
                h.update(f.aliases.map(|b| b.fingerprint()).unwrap_or_default().as_bytes());
                h.finalize().to_hex().to_string()
            })
            .collect();
        let env = (0..fns.len())
            .map(|i| {
                let creator = creators.get(&i).map(|c| ids[*c].as_str()).unwrap_or("");
                digest(&[types.fingerprint(i).as_bytes(), creator.as_bytes()])
            })
            .collect();
        let mut rows: Vec<String> = fns.iter().enumerate().map(|(i, f)| format!("{}|{}|{:?}|{:?}", ids[i], f.lang.family(), f.cfg.class_bases, f.cfg.receiver)).collect();
        rows.sort();
        let mut closure_rows: Vec<String> = closures.iter().map(|((fi, l, c), id)| format!("{}:{l}:{c}={}", paths.get(fi).cloned().unwrap_or_default(), ids[*id])).collect();
        closure_rows.sort();
        let mut class_rows: Vec<(&String, &String)> = classes.iter().collect();
        class_rows.sort();
        let field_rows: Vec<(&FieldKey, Vec<&String>)> = field_fns
            .iter()
            .map(|(k, v)| {
                let mut names: Vec<&String> = v.iter().map(|id| &ids[*id]).collect();
                names.sort();
                (k, names)
            })
            .collect();
        // the configuration and manifests read, with what they held: other rules, other results
        let inputs: Vec<u8> = crate::inputs::snapshot().iter().flat_map(|(p, h)| format!("{}\0{}\0", p.display(), h.as_deref().unwrap_or("-")).into_bytes()).collect();
        let global = digest(&[
            &inputs,
            format!("{rows:?}").as_bytes(),
            visibility.as_bytes(),
            types.global_fingerprint().as_bytes(),
            format!("{class_rows:?}").as_bytes(),
            format!("{closure_rows:?}").as_bytes(),
            format!("{field_rows:?}").as_bytes(),
        ]);
        Self { ids, content, env, global }
    }
}

/// Give the function ids inside `s` their numbers in this run; `None` when one is gone.
fn remap_summary(s: &mut Summary, map: &HashMap<usize, usize>) -> Option<()> {
    let one = |set: &BTreeSet<usize>| set.iter().map(|f| map.get(f).copied()).collect::<Option<BTreeSet<usize>>>();
    s.ret_fns = one(&s.ret_fns)?;
    for (direct, _) in s.callable_writes.values_mut() {
        *direct = one(direct)?;
    }
    Some(())
}

/// The state of the first pass, ready to store.
pub(super) fn capture(fp: &Fingerprints, carry: &Carry) -> Persisted {
    let comps = carry
        .cache
        .iter()
        .flatten()
        .map(|c| CompRec { reads: c.reads.clone(), results: c.results.clone() })
        .collect();
    Persisted {
        global: fp.global.clone(),
        fns: (0..fp.ids.len()).map(|i| FnRec { id: fp.ids[i].clone(), content: fp.content[i].clone(), env: fp.env[i].clone() }).collect(),
        summaries: carry.summaries.clone(),
        versions: carry.versions.clone(),
        comps,
    }
}

/// The first pass's starting point from a stored state: every summary that can be matched to a
/// function (so an unchanged recomputed summary keeps its version), and the groups whose functions,
/// membership and environment are the same as when they were stored.
pub(super) fn seed(mut prior: Persisted, fp: &Fingerprints, comps: &[Vec<NodeIndex>], comp_of: &[usize], counter: &AtomicU64) -> Carry {
    let n = fp.ids.len();
    let mut carry = Carry { cache: vec![None; comps.len()], summaries: vec![None; n], versions: vec![0; n] };
    if prior.global != fp.global {
        return carry;
    }
    let new_of: HashMap<&str, usize> = fp.ids.iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect();
    let map: HashMap<usize, usize> = prior.fns.iter().enumerate().filter_map(|(o, r)| new_of.get(r.id.as_str()).map(|&nw| (o, nw))).collect();
    let unchanged: HashSet<usize> = map.iter().filter(|(o, nw)| prior.fns[**o].content == fp.content[**nw] && prior.fns[**o].env == fp.env[**nw]).map(|(o, _)| *o).collect();
    // versions of the stored run, renumbered so that they cannot meet a number this run hands out
    let max_old = prior.versions.iter().copied().max().unwrap_or(0);
    let base = counter.fetch_add(max_old + 1, Ordering::Relaxed);
    let renumber = |v: u64| if v == 0 { 0 } else { base + v };
    for (&o, &nw) in &map {
        if let Some(mut s) = prior.summaries.get_mut(o).and_then(Option::take)
            && remap_summary(&mut s, &map).is_some()
        {
            carry.summaries[nw] = Some(s);
            carry.versions[nw] = renumber(prior.versions[o]);
        }
    }
    for rec in prior.comps {
        if !rec.results.iter().all(|(o, _)| unchanged.contains(o)) {
            continue;
        }
        let Some(mut members) = rec.results.iter().map(|(o, _)| map.get(o).copied()).collect::<Option<Vec<usize>>>() else { continue };
        members.sort_unstable();
        let Some(&first) = members.first() else { continue };
        let ci = comp_of[first];
        let mut want: Vec<usize> = comps[ci].iter().map(|x| x.index()).collect();
        want.sort_unstable();
        if want != members {
            continue;
        }
        let remapped = || -> Option<Cached> {
            let CompRec { mut reads, results } = rec;
            reads.summaries = reads.summaries.iter().map(|(f, v)| map.get(f).map(|nw| (*nw, renumber(*v)))).collect::<Option<_>>()?;
            reads.outer = reads.outer.into_iter().map(|(f, v)| map.get(&f).map(|nw| (*nw, v))).collect::<Option<_>>()?;
            let results = results
                .into_iter()
                .map(|(o, mut r)| {
                    remap_summary(&mut r.summary, &map)?;
                    Some((*map.get(&o)?, r))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(Cached { reads, results })
        };
        if let Some(cached) = remapped() {
            carry.cache[ci] = Some(cached);
        }
    }
    carry
}
