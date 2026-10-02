//! Suppression comments, in whatever comment syntax the language uses:
//!
//! ```text
//! os.system(cmd)   # taintless: ignore                  this line, every rule
//! # taintless: ignore[command-injection, sql-injection]  the next line, those rules
//! // taintless: ignore-file[weak-crypto]                 the whole file
//! os.system(cmd)   # taintless: ignore[command-injection] until=2026-12-31
//! ```
//!
//! With `until=YYYY-MM-DD` a suppression is a review date: from the day after it
//! stops hiding findings, which show up again (and are counted as expired).

use super::Finding;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

struct Marker {
    rules: Vec<String>,
    /// Nothing but a comment on the line (so it applies to the next line).
    comment_only: bool,
    /// Last day the suppression holds, `YYYY-MM-DD`.
    until: Option<String>,
}

impl Marker {
    fn covers(&self, f: &Finding) -> bool {
        self.rules.is_empty() || self.rules.iter().any(|r| r == f.rule)
    }

    fn expired(&self, today: &str) -> bool {
        self.until.as_deref().is_some_and(|d| d < today)
    }
}

/// `YYYY-MM-DD` after `until=` (or `until `) in `s`.
fn parse_until(s: &str) -> Option<String> {
    let i = s.find("until")?;
    let d: String = s[i + 5..].trim_start_matches(['=', ' ', ':']).chars().take(10).collect();
    let ok = d.len() == 10
        && d.char_indices().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() });
    ok.then_some(d)
}

/// Today's date (UTC) as `YYYY-MM-DD`.
pub fn today() -> String {
    date_after(0)
}

/// The date `days` from now (UTC) as `YYYY-MM-DD`.
pub fn date_after(days: u64) -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // days since 1970-01-01 -> civil date (Howard Hinnant's algorithm)
    let z = (secs / 86_400 + days) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `(is file-level, marker)` if the line has a `taintless: ignore...` comment.
fn parse(line: &str) -> Option<(bool, Marker)> {
    let pos = line.find("taintless:")?;
    let rest = line[pos + "taintless:".len()..].trim_start();
    let (file, rest) = if let Some(r) = rest.strip_prefix("ignore-file") {
        (true, r)
    } else {
        (false, rest.strip_prefix("ignore")?)
    };
    let rules = rest
        .trim_start()
        .strip_prefix('[')
        .map(|inner| inner.split(']').next().unwrap_or("").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let before = line[..pos].trim();
    let comment_only = before.is_empty() || ["#", "//", "/*", "*", "--", "<!--", ";"].contains(&before);
    Some((file, Marker { rules, comment_only, until: parse_until(&line[pos..]) }))
}

#[derive(Default)]
struct FileMarkers {
    by_line: HashMap<usize, Marker>,
    whole_file: Vec<Marker>,
}

impl FileMarkers {
    fn of(text: &str) -> Self {
        let mut m = Self::default();
        for (i, line) in text.lines().enumerate() {
            match parse(line) {
                Some((true, marker)) => m.whole_file.push(marker),
                Some((false, marker)) => {
                    m.by_line.insert(i + 1, marker);
                }
                None => {}
            }
        }
        m
    }

    fn suppresses(&self, f: &Finding, today: &str) -> Verdict {
        let here = self.by_line.get(&f.line);
        let above = (f.line > 1).then(|| self.by_line.get(&(f.line - 1)).filter(|m| m.comment_only)).flatten();
        let covering: Vec<&Marker> =
            self.whole_file.iter().chain(here).chain(above).filter(|m| m.covers(f)).collect();
        if covering.iter().any(|m| !m.expired(today)) {
            Verdict::Suppressed
        } else if covering.is_empty() {
            Verdict::Reported
        } else {
            Verdict::Expired
        }
    }
}

enum Verdict {
    Suppressed,
    Reported,
    /// A suppression covers it, but its `until` date has passed.
    Expired,
}

/// Drop the findings the source suppresses; returns the rest and how many were dropped.
pub fn apply(findings: Vec<Finding>, read: &dyn Fn(&Path) -> Option<String>) -> (Vec<Finding>, usize) {
    let (kept, dropped, _) = apply_on(findings, read, &today());
    (kept, dropped)
}

/// Like `apply`, as of `today` (`YYYY-MM-DD`); also returns how many findings
/// are shown only because their suppression expired.
pub fn apply_on(findings: Vec<Finding>, read: &dyn Fn(&Path) -> Option<String>, today: &str) -> (Vec<Finding>, usize, usize) {
    let mut cache: HashMap<PathBuf, FileMarkers> = HashMap::new();
    let mut kept = vec![];
    let (mut dropped, mut expired) = (0, 0);
    for f in findings {
        let markers = cache.entry(f.file.clone()).or_insert_with(|| FileMarkers::of(&read(&f.file).unwrap_or_default()));
        match markers.suppresses(&f, today) {
            Verdict::Suppressed => dropped += 1,
            Verdict::Reported => kept.push(f),
            Verdict::Expired => {
                expired += 1;
                kept.push(f);
            }
        }
    }
    (kept, dropped, expired)
}
