use crate::analysis::{Finding, Severity, rules::RULE_INFO};
use serde_json::{Value, json};
use std::fmt::Write;

/// `path:line:col: severity [rule] message` with the taint origin underneath.
pub fn to_text(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        let _ = writeln!(
            s,
            "{}:{}:{}: {} [{}] {} (in `{}`, {})",
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
    findings
        .iter()
        .map(|f| {
            json!({
                "rule": f.rule, "cwe": f.cwe, "severity": f.severity.as_str(),
                "message": f.message, "file": f.file.display().to_string(),
                "function": f.function, "line": f.line, "column": f.col, "origin": f.origin,
            })
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
        .map(|f| {
            let mut text = f.message.clone();
            if let Some(o) = &f.origin {
                let _ = write!(text, " (untrusted input from {o})");
            }
            json!({
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
            })
        })
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
