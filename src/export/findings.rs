use crate::analysis::{Finding, Severity, rules::RULE_INFO};
use serde_json::{Value, json};
use std::fmt::Write;

/// A finding hidden because it was triaged as accepted or a false positive.
pub struct Triaged {
    pub finding: Finding,
    pub id: String,
    pub status: String,
    pub reason: Option<String>,
}

/// What the findings store adds: the stable id of each reported finding (parallel to the
/// findings), and the triaged findings that are not reported (SARIF lists them as suppressed).
#[derive(Default)]
pub struct Stored {
    pub ids: Vec<String>,
    pub triaged: Vec<Triaged>,
}

/// `path:line:col: severity [rule] message` with the taint origin underneath.
pub fn to_text(findings: &[Finding]) -> String {
    to_text_with(findings, &Stored::default())
}

/// Like [`to_text`], ending each finding's line with its stored `id=`.
pub fn to_text_with(findings: &[Finding], stored: &Stored) -> String {
    let mut s = String::new();
    for (i, f) in findings.iter().enumerate() {
        let id = stored.ids.get(i).map(|id| format!(" id={id}")).unwrap_or_default();
        let _ = writeln!(
            s,
            "{}:{}:{}: {} [{}] {} (in `{}`, {}){id}",
            f.file.display(),
            f.line,
            f.col,
            f.severity.as_str(),
            f.rule,
            f.message,
            f.function,
            f.cwe
        );
        if let Some(o) = &f.origin {
            let _ = writeln!(s, "    untrusted input from {o}");
        }
    }
    s
}

pub fn to_json(findings: &[Finding]) -> Value {
    to_json_with(findings, &Stored::default())
}

/// Like [`to_json`], with an `id` on each finding when the store knows it.
pub fn to_json_with(findings: &[Finding], stored: &Stored) -> Value {
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut v = json!({
                "rule": f.rule, "cwe": f.cwe, "severity": f.severity.as_str(),
                "message": f.message, "file": f.file.display().to_string(),
                "function": f.function, "line": f.line, "column": f.col, "origin": f.origin,
            });
            if let Some(id) = stored.ids.get(i) {
                v["id"] = json!(id);
            }
            v
        })
        .collect()
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// SARIF 2.1.0, as consumed by GitHub code scanning and most IDEs.
pub fn to_sarif(findings: &[Finding]) -> Value {
    to_sarif_with(findings, &Stored::default())
}

fn sarif_result(f: &Finding, id: Option<&str>, triage: Option<(&str, Option<&str>)>) -> Value {
    let mut text = f.message.clone();
    if let Some(o) = &f.origin {
        let _ = write!(text, " (untrusted input from {o})");
    }
    let mut v = json!({
        "ruleId": f.rule,
        "level": level(f.severity),
        "message": { "text": text },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": f.file.display().to_string().replace('\\', "/") },
                "region": { "startLine": f.line, "startColumn": f.col },
            },
            "logicalLocations": [{ "name": f.function, "kind": "function" }],
        }],
        "properties": { "cwe": f.cwe, "severity": f.severity.as_str() },
    });
    if let Some(id) = id {
        v["partialFingerprints"] = json!({ "taintlessId/v1": id });
    }
    if let Some((status, reason)) = triage {
        let why = reason.map_or_else(|| status.to_string(), |r| format!("{status}: {r}"));
        v["suppressions"] = json!([{ "kind": "external", "status": "accepted", "justification": why }]);
    }
    v
}

/// Like [`to_sarif`], with the stored ids as fingerprints and the triaged findings listed as
/// externally suppressed results (code scanning shows them as dismissed).
pub fn to_sarif_with(findings: &[Finding], stored: &Stored) -> Value {
    let rules: Vec<Value> = RULE_INFO
        .iter()
        .map(|(id, title, cwe)| {
            json!({
                "id": id, "name": title, "shortDescription": { "text": title },
                "properties": { "tags": ["security", cwe] },
            })
        })
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| sarif_result(f, stored.ids.get(i).map(String::as_str), None))
        .chain(stored.triaged.iter().map(|t| sarif_result(&t.finding, Some(&t.id), Some((&t.status, t.reason.as_deref())))))
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "taintless",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/",
                "rules": rules,
            } },
            "results": results,
        }],
    })
}
