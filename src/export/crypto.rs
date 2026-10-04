use crate::analysis::{
    crypto::{CryptoUse, Declared, Kind},
    rel_path,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write;

/// Libraries first (with the files that import them), then the crypto calls
/// grouped by primitive. Broken algorithms are marked `[weak]`.
pub fn to_text(uses: &[CryptoUse], declared: &[Declared]) -> String {
    let mut s = String::new();
    let mut libs: BTreeMap<&str, Vec<&CryptoUse>> = BTreeMap::new();
    for u in uses.iter().filter(|u| u.kind == Kind::Import) {
        libs.entry(&u.library).or_default().push(u);
    }
    let _ = writeln!(s, "libraries ({}):", libs.len());
    for (lib, imports) in &libs {
        let at: Vec<String> = imports.iter().map(|u| format!("{}:{}", rel_path(&u.file), u.line)).collect();
        let _ = writeln!(s, "  {lib}  ({})", at.join(", "));
    }
    if !declared.is_empty() {
        let _ = writeln!(s, "\ndeclared in manifests ({}):", declared.len());
        for d in declared {
            let note = match (d.used, d.lock) {
                (true, false) => "",
                (true, true) => "  [lock file]",
                (false, false) => "  [not imported]",
                (false, true) => "  [lock file, not imported]",
            };
            let _ = writeln!(s, "  {}  ({})  {}:{}{note}", d.name, d.library, rel_path(&d.manifest), d.line);
        }
    }
    let mut prims: BTreeMap<&str, Vec<&CryptoUse>> = BTreeMap::new();
    for u in uses.iter().filter(|u| matches!(u.kind, Kind::Call | Kind::Method)) {
        prims.entry(&u.primitive).or_default().push(u);
    }
    let calls = uses.iter().filter(|u| u.kind == Kind::Call).count();
    let methods = uses.iter().filter(|u| u.kind == Kind::Method).count();
    let _ = writeln!(s, "\ncrypto calls ({calls}) and methods of crypto objects ({methods}):");
    for (prim, calls) in &prims {
        let _ = writeln!(s, "  {prim}");
        for u in calls {
            let mut flag = if u.weak { format!(" [weak: {}]", u.reason) } else { String::new() };
            if !u.issues.is_empty() {
                let _ = write!(flag, " [{}]", u.issues.join("; "));
            }
            if !u.quantum.is_empty() {
                let _ = write!(flag, " [quantum: {}]", u.quantum);
            }
            if u.kind == Kind::Method {
                let _ = write!(flag, " (method{})", if u.origin_line > 0 { format!(" of the object from line {}", u.origin_line) } else { String::new() });
            }
            let library = if u.library.is_empty() { String::new() } else { format!(" [{}]", u.library) };
            let _ = writeln!(s, "    {}:{}:{}  {}({})  {}{library}{flag}  (in {})", rel_path(&u.file), u.line, u.col, u.name, u.args, u.algorithm, u.function);
        }
    }
    let files: Vec<&CryptoUse> = uses.iter().filter(|u| u.kind == Kind::File).collect();
    if !files.is_empty() {
        let _ = writeln!(s, "\nkey material, settings and embedded implementations in files ({}):", files.len());
        for u in files {
            let mut flag = if u.weak { format!(" [weak: {}]", u.reason) } else { String::new() };
            if !u.issues.is_empty() {
                let _ = write!(flag, " [{}]", u.issues.join("; "));
            }
            if !u.quantum.is_empty() {
                let _ = write!(flag, " [quantum: {}]", u.quantum);
            }
            let _ = writeln!(s, "  {}:{}  {}  {}{flag}", rel_path(&u.file), u.line, u.name, u.algorithm);
        }
    }
    s
}

pub fn to_json(uses: &[CryptoUse], declared: &[Declared]) -> Value {
    let item = |u: &CryptoUse| {
        json!({
            "file": rel_path(&u.file), "line": u.line, "col": u.col, "name": u.name,
            "library": u.library, "primitive": u.primitive, "algorithm": u.algorithm,
            "weak": u.weak, "reason": u.reason, "issues": u.issues, "origin_line": u.origin_line, "quantum": u.quantum, "severity": u.severity().map(|s| s.as_str()), "args": u.args, "function": u.function,
        })
    };
    let manifest = |d: &Declared| json!({ "manifest": rel_path(&d.manifest), "line": d.line, "name": d.name, "library": d.library, "used": d.used, "lock": d.lock });
    json!({
        "declared": declared.iter().map(manifest).collect::<Vec<_>>(),
        "libraries": uses.iter().filter(|u| u.kind == Kind::Import).map(item).collect::<Vec<_>>(),
        "calls": uses.iter().filter(|u| u.kind == Kind::Call).map(item).collect::<Vec<_>>(),
        "methods": uses.iter().filter(|u| u.kind == Kind::Method).map(item).collect::<Vec<_>>(),
        "files": uses.iter().filter(|u| u.kind == Kind::File).map(item).collect::<Vec<_>>(),
    })
}

/// CycloneDX 1.6 bill of materials: the libraries as `library` components and each distinct
/// algorithm as a `cryptographic-asset` with the places it is used.
pub fn to_cbom(uses: &[CryptoUse], declared: &[Declared]) -> Value {
    let mut libraries: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for u in uses.iter().filter(|u| u.kind == Kind::Import) {
        libraries.entry(&u.library).or_default().push(json!({ "location": rel_path(&u.file), "line": u.line }));
    }
    for d in declared {
        libraries.entry(&d.library).or_default().push(json!({ "location": rel_path(&d.manifest), "line": d.line }));
    }
    let mut components: Vec<Value> = libraries
        .iter()
        .map(|(name, occurrences)| json!({ "type": "library", "bom-ref": format!("lib:{name}"), "name": name, "evidence": { "occurrences": occurrences } }))
        .collect();
    let mut algorithms: BTreeMap<(&str, &str), Vec<&CryptoUse>> = BTreeMap::new();
    for u in uses.iter().filter(|u| matches!(u.kind, Kind::Call | Kind::Method)) {
        algorithms.entry((&u.primitive, &u.algorithm)).or_default().push(u);
    }
    for ((primitive, algorithm), found) in algorithms {
        let level = found.iter().find(|u| !u.quantum.is_empty()).map(|u| u.quantum.as_str()).unwrap_or("");
        let mut props = json!({ "primitive": cdx_primitive(primitive) });
        if level == "vulnerable" {
            props["nistQuantumSecurityLevel"] = json!(0);
        }
        let occurrences: Vec<Value> = found.iter().map(|u| json!({ "location": rel_path(&u.file), "line": u.line, "additionalContext": u.name })).collect();
        let mut c = json!({
            "type": "cryptographic-asset",
            "bom-ref": format!("alg:{primitive}:{algorithm}"),
            "name": algorithm,
            "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": props },
            "evidence": { "occurrences": occurrences },
        });
        let weak: Vec<&str> = found.iter().filter(|u| u.weak).map(|u| u.reason.as_str()).collect();
        if !weak.is_empty() {
            c["properties"] = json!([{ "name": "taintless:weak", "value": weak[0] }]);
        }
        components.push(c);
    }
    for (n, u) in uses.iter().filter(|u| u.kind == Kind::File && matches!(u.primitive.as_str(), "key-material" | "certificate")).enumerate() {
        let props = if u.primitive == "certificate" {
            json!({ "assetType": "certificate", "certificateProperties": { "certificateFormat": "X.509" } })
        } else {
            let t = if u.issues.iter().any(|i| i.contains("private key")) { "private-key" } else if u.name.contains("PUBLIC") { "public-key" } else { "other" };
            json!({ "assetType": "related-crypto-material", "relatedCryptoMaterialProperties": { "type": t } })
        };
        components.push(json!({
            "type": "cryptographic-asset",
            "bom-ref": format!("file:{n}"),
            "name": format!("{} ({})", u.name, u.algorithm),
            "cryptoProperties": props,
            "evidence": { "occurrences": [{ "location": rel_path(&u.file), "line": u.line }] },
        }));
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": { "tools": { "components": [{ "type": "application", "name": "taintless" }] } },
        "components": components,
    })
}

/// A CycloneDX `algorithmProperties.primitive` value.
fn cdx_primitive(p: &str) -> &'static str {
    match p {
        "hash" => "hash",
        "cipher" => "block-cipher",
        "mac" => "mac",
        "kdf" => "kdf",
        "signature" => "signature",
        "asymmetric" => "pke",
        "key-exchange" => "key-agree",
        "random" => "drbg",
        "kem" => "kem",
        _ => "other",
    }
}

/// SARIF 2.1.0: one result for every weak algorithm and every problem found in the arguments.
pub fn to_sarif(uses: &[CryptoUse]) -> Value {
    // (rule id, CWE, description, level)
    const RULES: &[(&str, &str, &str, &str)] = &[
        ("weak-crypto-algorithm", "CWE-327", "Broken or deprecated cryptographic algorithm, mode or key size", "warning"),
        ("hardcoded-crypto-key", "CWE-321", "Hardcoded cryptographic key, secret or password", "error"),
        ("static-iv", "CWE-329", "Static or zero initialization vector", "warning"),
        ("static-salt", "CWE-760", "Static or zero salt", "warning"),
        ("low-work-factor", "CWE-916", "Too few iterations or too low a cost for password hashing", "warning"),
        ("constant-prng-seed", "CWE-336", "Constant seed for a pseudo-random number generator", "warning"),
        ("weak-prng", "CWE-338", "Non-cryptographic pseudo-random number generator", "note"),
    ];
    let rule_of = |issue: &str| match issue {
        i if i.starts_with("hardcoded") || i == "all-zero key" => 1,
        "static IV" | "zero IV" => 2,
        "static salt" | "zero salt" => 3,
        i if i.starts_with("low ") => 4,
        "constant PRNG seed" => 5,
        _ => 6,
    };
    let mut results = vec![];
    for u in uses.iter().filter(|u| u.kind != Kind::Import) {
        let mut hits: Vec<(usize, String)> = u.issues.iter().map(|i| (rule_of(i), i.clone())).collect();
        if u.weak {
            hits.push((0, format!("{} ({})", u.reason, u.name)));
        }
        for (r, text) in hits {
            results.push(json!({
                "ruleId": RULES[r].0,
                "level": RULES[r].3,
                "message": { "text": format!("{text} in {}", u.name) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": rel_path(&u.file) },
                    "region": { "startLine": u.line, "startColumn": u.col.max(1) },
                } }],
            }));
        }
    }
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "taintless",
                "rules": RULES.iter().map(|(id, cwe, text, level)| json!({
                    "id": id, "shortDescription": { "text": text },
                    "properties": { "tags": [cwe] }, "defaultConfiguration": { "level": level },
                })).collect::<Vec<_>>(),
            } },
            "results": results,
        }],
    })
}
