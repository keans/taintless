//! A baseline records the findings that exist today so that only new ones are
//! reported. Entries ignore line numbers, so code moving around does not
//! resurrect old findings; a count handles several identical findings in one
//! function. Entries also carry a fingerprint of the source line, so a finding
//! is recognized after its function was renamed and its file moved, and an
//! optional review date after which an entry stops hiding anything.

use super::{Finding, rel_path};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub rule: String,
    pub file: String,
    pub function: String,
    pub message: String,
    pub count: usize,
    /// Hash of the finding's source line (whitespace-normalized): lets an entry
    /// match after the function was renamed *and* the file moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Last day the entry hides its findings (`YYYY-MM-DD`); after it they are reported again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub findings: Vec<Entry>,
}

type Key = (String, String, String, String);

fn key(f: &Finding) -> Key {
    (f.rule.to_string(), rel_path(&f.file), f.function.clone(), f.message.clone())
}

/// FNV-1a: stable across Rust versions and platforms, unlike `DefaultHasher`.
fn fnv(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Hashes the source line of each finding; files are read once.
struct Fingerprints<'r> {
    read: &'r dyn Fn(&Path) -> Option<String>,
    files: HashMap<PathBuf, Option<Vec<String>>>,
}

impl<'r> Fingerprints<'r> {
    fn new(read: &'r dyn Fn(&Path) -> Option<String>) -> Self {
        Self { read, files: HashMap::new() }
    }

    fn of(&mut self, f: &Finding) -> Option<String> {
        let lines = self
            .files
            .entry(f.file.clone())
            .or_insert_with(|| (self.read)(&f.file).map(|t| t.lines().map(str::to_string).collect()))
            .as_ref()?;
        let text = lines.get(f.line.checked_sub(1)?)?;
        let norm = text.split_whitespace().collect::<Vec<_>>().join(" ");
        (!norm.is_empty()).then(|| fnv(&format!("{}\0{}\0{norm}", f.rule, f.message)))
    }
}

/// Stable ids for `findings`: a hash of rule, message and the normalized source line (or of
/// file and function when the line is unavailable), numbered when several findings share one.
pub fn finding_ids(findings: &[Finding], read: &dyn Fn(&Path) -> Option<String>) -> Vec<String> {
    let mut fp = Fingerprints::new(read);
    let mut seen: HashMap<String, usize> = HashMap::new();
    findings
        .iter()
        .map(|f| {
            let base = fp.of(f).unwrap_or_else(|| fnv(&format!("{}\0{}\0{}\0{}", f.rule, f.message, rel_path(&f.file), f.function)));
            let n = seen.entry(base.clone()).or_default();
            *n += 1;
            if *n == 1 { base } else { format!("{base}-{n}") }
        })
        .collect()
}

impl Baseline {
    /// Entries without fingerprints (what older versions wrote).
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::build(findings, &|_| None, None)
    }

    /// Entries with a fingerprint of the source line; with `review_in_days` they stop
    /// hiding their findings after that many days.
    pub fn build(findings: &[Finding], read: &dyn Fn(&Path) -> Option<String>, review_in_days: Option<u64>) -> Self {
        let mut fp = Fingerprints::new(read);
        let mut counts: BTreeMap<(Key, Option<String>), usize> = BTreeMap::new();
        for f in findings {
            *counts.entry((key(f), fp.of(f))).or_default() += 1;
        }
        let review_by = review_in_days.map(super::suppress::date_after);
        let findings = counts
            .into_iter()
            .map(|(((rule, file, function, message), fingerprint), count)| Entry {
                rule,
                file,
                function,
                message,
                count,
                fingerprint,
                review_by: review_by.clone(),
            })
            .collect();
        Self { version: 1, findings }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading baseline {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing baseline {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)? + "\n").with_context(|| format!("writing baseline {}", path.display()))
    }

    /// The findings that are not in the baseline, and how many were.
    pub fn filter(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let (new, known, _) = self.filter_on(findings, &|_| None, &super::suppress::today());
        (new, known)
    }

    /// Like `filter`, as of `today`, using source lines for fingerprints; also returns how many
    /// findings are reported only because the baseline entry covering them is past its review date.
    ///
    /// An entry matches on rule, file, function, message and source line; what is left over
    /// then matches without the line, without the function (renamed), without the file (moved),
    /// and finally by rule, message and source line alone (renamed *and* moved).
    pub fn filter_on(
        &self,
        findings: Vec<Finding>,
        read: &dyn Fn(&Path) -> Option<String>,
        today: &str,
    ) -> (Vec<Finding>, usize, usize) {
        struct Slot {
            key: Key,
            fp: Option<String>,
            left: usize,
            expired: bool,
        }
        let mut slots: Vec<Slot> = self
            .findings
            .iter()
            .map(|e| Slot {
                key: (e.rule.clone(), e.file.clone(), e.function.clone(), e.message.clone()),
                fp: e.fingerprint.clone(),
                left: e.count,
                expired: e.review_by.as_deref().is_some_and(|d| d < today),
            })
            .collect();
        type Same = fn(&Key, &Option<String>, &Key, &Option<String>) -> bool;
        let tiers: [Same; 5] = [
            |a, fa, b, fb| a == b && fa.is_some() && fa == fb,
            |a, _, b, _| a == b,
            |a, _, b, _| (&a.0, &a.1, &a.3) == (&b.0, &b.1, &b.3),
            |a, _, b, _| (&a.0, &a.2, &a.3) == (&b.0, &b.2, &b.3),
            |a, fa, b, fb| (&a.0, &a.3) == (&b.0, &b.3) && fa.is_some() && fa == fb,
        ];
        let mut fp = Fingerprints::new(read);
        let mut pending: Vec<(Finding, Option<String>)> = findings.into_iter().map(|f| {
            let p = fp.of(&f);
            (f, p)
        }).collect();
        let (mut known, mut expired) = (0, 0);
        let mut reported: Vec<Finding> = vec![];
        for same in tiers {
            let mut rest = vec![];
            for (f, p) in pending {
                let k = key(&f);
                match slots.iter_mut().find(|s| s.left > 0 && same(&s.key, &s.fp, &k, &p)) {
                    Some(s) => {
                        s.left -= 1;
                        if s.expired {
                            expired += 1;
                            reported.push(f);
                        } else {
                            known += 1;
                        }
                    }
                    None => rest.push((f, p)),
                }
            }
            pending = rest;
        }
        reported.extend(pending.into_iter().map(|(f, _)| f));
        (reported, known, expired)
    }
}
