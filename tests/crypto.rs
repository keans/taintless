mod common;

#[test]
fn lists_libraries_and_calls() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let libs: Vec<&str> = v["libraries"].as_array().unwrap().iter().map(|l| l["library"].as_str().unwrap()).collect();
    for want in [
        "cryptography", "hashlib", "Go crypto", "node:crypto", "OpenSSL",
        "Tink", "libsodium", "StableLib", "aws-lc-rs", "RustCrypto hkdf",
        "curve25519-dalek", "CIRCL", "Conscrypt", "BearSSL", "Monocypher",
    ] {
        assert!(libs.contains(&want), "missing library {want}: {libs:?}");
    }
    let calls = v["calls"].as_array().unwrap();
    let weak: Vec<&str> = calls.iter().filter(|c| c["weak"] == true).map(|c| c["name"].as_str().unwrap()).collect();
    assert!(weak.contains(&"hashlib.md5") && weak.contains(&"md5.Sum"), "{weak:?}");
    assert!(calls.iter().any(|c| c["name"] == "EVP_CIPHER_CTX_new" && c["primitive"] == "(OpenSSL EVP)"));
    assert!(calls.iter().any(|c| c["name"] == "AES.new" && c["reason"] == "ECB mode"));
    assert!(calls.iter().any(|c| c["name"] == "Cipher.getInstance" && c["reason"] == "default ECB mode"));
    assert!(calls.iter().any(|c| c["name"] == "crypto.createHash" && c["algorithm"] == "sha1" && c["weak"] == true));
    assert!(calls.iter().any(|c| c["name"] == "MessageDigest.getInstance" && c["algorithm"] == "SHA-256" && c["weak"] == false));
}

#[test]
fn lists_declared_dependencies() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let declared = v["declared"].as_array().unwrap();
    let mut names: Vec<&str> = declared.iter().map(|d| d["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["aes", "chacha20poly1305", "crypto-js", "sha2"]);
    assert!(declared.iter().all(|d| d["used"] == false));
    // `sha2` is declared in Cargo.toml, so its lock entry adds nothing; `aes` is only in the lock file
    assert!(declared.iter().any(|d| d["name"] == "aes" && d["lock"] == true));
    assert!(declared.iter().any(|d| d["name"] == "sha2" && d["lock"] == false));
}

#[test]
fn reads_arguments_constants_and_objects() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let find = |list: &str, file: &str, name: &str| v[list].as_array().unwrap().iter().find(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).cloned().unwrap_or_else(|| panic!("no {name} in {file}"));
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // constants resolve: `Cipher.getInstance(ALGO)` with `ALGO = "AES/ECB/.."`
    let c = find("calls", "Const.java", "Cipher.getInstance");
    assert_eq!(c["algorithm"], "AES/ECB/PKCS5Padding");
    assert_eq!(c["reason"], "ECB mode");
    // methods of the object it returned carry the algorithm
    let m = find("methods", "Const.java", "c.doFinal");
    assert_eq!(m["reason"], "ECB mode");
    assert_eq!(m["origin_line"], 5);
    // `h = hashlib.new(ALGO)` with `ALGO = "md5"`
    assert_eq!(find("calls", "detect.py", "hashlib.new")["algorithm"], "md5");
    assert_eq!(find("methods", "detect.py", "h.update")["reason"], "MD5");
    assert!(find("methods", "detect.py", "Fernet.decrypt")["origin_line"] == 0);
    // hardcoded secrets, static IV, iterations, PRNG seed, TLS version
    assert!(issues(&find("calls", "detect.py", "Fernet")).contains(&"hardcoded key".to_string()));
    assert!(issues(&find("calls", "detect.py", "AES.new")).contains(&"static IV".to_string()));
    let kdf = issues(&find("calls", "detect.py", "hashlib.pbkdf2_hmac"));
    assert!(kdf.iter().any(|i| i.starts_with("low PBKDF2 iterations (1000")) && kdf.contains(&"static salt".to_string()), "{kdf:?}");
    assert!(issues(&find("calls", "detect.py", "random.seed")).contains(&"constant PRNG seed".to_string()));
    assert_eq!(find("calls", "detect.py", "ssl.SSLContext")["reason"], "TLS 1.0/1.1");
}

#[test]
fn quantum_tags_and_exports() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let tag = |name: &str| v["calls"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()["quantum"].clone();
    assert_eq!(tag("RSA.generate"), "vulnerable");
    assert_eq!(tag("oqs.KeyEncapsulation"), "safe");
    assert_eq!(tag("hashlib.new"), "");

    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "cbom"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.6");
    let rsa = v["components"].as_array().unwrap().iter().find(|c| c["name"] == "RSA").unwrap();
    assert_eq!(rsa["type"], "cryptographic-asset");
    assert_eq!(rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"], 0);

    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "sarif"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["runs"][0]["results"].as_array().unwrap().iter().map(|r| r["ruleId"].as_str().unwrap()).collect();
    for want in ["weak-crypto-algorithm", "hardcoded-crypto-key", "static-iv", "static-salt", "low-work-factor", "constant-prng-seed"] {
        assert!(ids.contains(&want), "{want}: {ids:?}");
    }
}

#[test]
fn only_weak_and_exit_status() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--only-weak", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["libraries"].as_array().unwrap().is_empty() && v["declared"].as_array().unwrap().is_empty());
    assert!(v["calls"].as_array().unwrap().iter().all(|c| c["weak"] == true || !c["issues"].as_array().unwrap().is_empty()));
    assert_eq!(common::taintless(&["--no-cache", "crypto", "tests/crypto", "--fail-on-weak"]).status.code(), Some(1));
    // a clean file passes
    assert!(common::taintless(&["--no-cache", "crypto", "tests/crypto/app.c", "--fail-on-weak"]).status.success());
}

#[test]
fn config_extends_the_tables() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_cfg", "--format", "json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["libraries"][0]["library"], "mycorp-crypto");
    let call = &v["calls"][0];
    assert_eq!((call["name"].as_str(), call["algorithm"].as_str(), call["weak"].as_bool()), (Some("mycorp.crypto.seal"), Some("ROT13"), Some(true)));
    // a bad table is an error, not silently ignored
    let bad = common::taintless(&["--no-cache", "crypto", "tests/crypto_cfg/app.py", "--config", "tests/config/bad_field.toml"]);
    assert!(!bad.status.success());
}

#[test]
fn builtin_tables_parse() {
    let t = taintless::analysis::crypto::tables::builtin();
    assert!(t.library.len() > 50 && t.call.len() > 200 && !t.secret.is_empty() && !t.limit.is_empty() && !t.prng.is_empty() && !t.dependency.is_empty());
}

#[test]
fn resolves_aliases_and_wildcard_imports() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_alias", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let find = |file: &str, name: &str| calls.iter().find(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).unwrap_or_else(|| panic!("{name} in {file} not found")).clone();
    // Python: `import hashlib as h`, `from hashlib import md5`, `... sha256 as s2`, `from hashlib import *`
    assert_eq!(find("a.py", "h.md5")["algorithm"], "MD5");
    assert_eq!(find("a.py", "md5")["weak"], true);
    assert_eq!(find("a.py", "s2")["algorithm"], "SHA-256");
    assert_eq!(find("a.py", "sha1")["reason"], "SHA-1");
    // JavaScript: a renamed require, a named import, a namespace import
    assert_eq!(find("b.js", "ch")["algorithm"], "md5");
    assert_eq!(find("b.js", "createHash")["algorithm"], "sha1");
    assert_eq!(find("b.js", "cr.createHash")["algorithm"], "sha1");
    // Go: an aliased package; Rust: `use md5 as m`; Java: a static import
    assert_eq!(find("c.go", "m.Sum")["algorithm"], "MD5");
    assert_eq!(find("d.rs", "m.compute")["algorithm"], "MD5");
    assert_eq!(find("E.java", "getInstance")["algorithm"], "SHA-1");
}

#[test]
fn finds_key_material_and_weak_settings_in_files() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_files", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let at = |file: &str| files.iter().filter(|f| f["file"].as_str().unwrap().ends_with(file)).cloned().collect::<Vec<_>>();
    let issues = |f: &serde_json::Value| f["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // key material, also inside source code; a mention in documentation is not a key
    assert!(issues(&at("fake_private.pem")[0]).contains(&"hardcoded private key".to_string()));
    assert!(issues(&at("embedded.py")[0]).contains(&"hardcoded private key".to_string()));
    assert_eq!(at("fake_cert.pem")[0]["primitive"], "certificate");
    assert!(at("NOTES.md").is_empty());
    assert!(issues(&at("server.jks")[0]).contains(&"hardcoded keystore".to_string()));
    // settings: weak protocols and ciphers are flagged, switched-off and deny-listed ones are not
    assert_eq!(at("nginx.conf").iter().map(|f| f["reason"].as_str().unwrap()).collect::<Vec<_>>(), ["TLS 1.0/1.1", "RC4"]);
    assert!(at("modern.conf").is_empty());
    assert_eq!(at("sshd_config").len(), 2);
    assert_eq!(at("app.properties").len(), 1, "the deny list is not a finding");
    assert_eq!(at("settings.yml").len(), 1);
    // XML attributes and several JSON pairs on a line; comments and modern settings are fine
    assert_eq!(at("server.xml").iter().map(|f| f["name"].as_str().unwrap()).collect::<Vec<_>>(), ["ciphers", "sslProtocol"]);
    assert_eq!(at("tls.json").iter().map(|f| f["name"].as_str().unwrap()).collect::<Vec<_>>(), ["server.ssl_protocols"]);
    // nested keys give their path (`tls.min_version`), lists and element text are values, and an
    // unrelated `version` or a `name` element is not a finding
    let named = |file: &str| at(file).iter().map(|f| f["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(named("nested.yml"), ["server.tls.min_version", "server.ssl_protocols"]);
    assert_eq!(named("nested.toml"), ["server.tls.min_version"]);
    assert_eq!(named("nested.json"), ["tls.min_version", "tls.protocols"]);
    assert_eq!(named("text.xml"), ["sslProtocol", "ciphers"]);
    // a value continued with a backslash; `..._CBC_SHA` names a MAC and is not flagged by itself
    assert_eq!(at("cont.properties")[0]["reason"], "RC4");
    assert_eq!(at("deploy.sh").len(), 2, "1024-bit keys only");
    // they fail a CI run, and appear in the other formats
    assert_eq!(common::taintless(&["--no-cache", "crypto", "tests/crypto_files", "--fail-on-weak"]).status.code(), Some(1));
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_files", "--format", "cbom"]);
    let bom: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(bom["components"].as_array().unwrap().iter().any(|c| c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "private-key"));
}

#[test]
fn covers_more_libraries() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_more", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let find = |file: &str, name: &str| calls.iter().find(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).unwrap_or_else(|| panic!("{name} in {file} not found")).clone();
    let weak = |file: &str, name: &str| find(file, name)["weak"] == true;
    // weak ones
    for (file, name) in [("Spring.java", "StandardPasswordEncoder"), ("Spring.java", "BasicTextEncryptor"), ("Spring.java", "DigestUtils.sha1Hex"), ("more.c", "EVP_md5"), ("more.c", "EVP_aes_128_ecb"), ("more.c", "mbedtls_md5_starts"), ("more.rs", "Cipher.aes_128_ecb"), ("more.rs", "MessageDigest.md5"), ("more.py", "hashes.SHA1"), ("more.py", "ssl._create_unverified_context"), ("more.py", "MD5.new"), ("more.go", "blowfish.NewCipher"), ("more.go", "dsa.GenerateKey"), ("more.go", "ssh.InsecureIgnoreHostKey"), ("more.js", "md5")] {
        assert!(weak(file, name), "{name} in {file} should be weak");
    }
    // strong ones are listed but not flagged (the specific entries come before the `EVP_*` / `mbedtls_*` ones)
    for (file, name) in [("Spring.java", "DigestUtils.sha256Hex"), ("more.c", "EVP_sha256"), ("more.c", "mbedtls_sha256_starts"), ("more.rs", "Cipher.aes_256_gcm"), ("more.py", "hashes.SHA256")] {
        assert!(!weak(file, name), "{name} in {file} should not be weak");
    }
    // arguments
    assert!(find("Spring.java", "BCryptPasswordEncoder")["issues"][0].as_str().unwrap().starts_with("low bcrypt cost (4"));
    assert_eq!(find("more.rs", "Nonce.from_slice")["issues"][0], "static IV");
}

#[test]
fn finds_embedded_implementations_by_their_constants() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_const", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let found = |file: &str| files.iter().filter(|f| f["file"].as_str().unwrap().rsplit('/').next() == Some(file)).map(|f| f["algorithm"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(found("sha256.c"), ["SHA-256"]);
    assert_eq!(found("sha1.py"), ["SHA-1"], "the fifth word tells SHA-1 from MD5");
    assert_eq!(found("sbox.go"), ["AES S-box"]);
    assert_eq!(found("chacha.rs"), ["ChaCha / Salsa20"]);
    assert_eq!(found("firmware.bin"), ["SHA-256"], "constants in a binary, little-endian");
    assert!(found("other.c").is_empty(), "two shared words are not an implementation");
    assert_eq!(found("keccak.c"), ["SHA-3 / Keccak"]);
    assert_eq!(found("sm3.rs"), ["SM3"]);
    assert_eq!(found("inv_sbox.go"), ["AES S-box (inverse)"], "a table written in decimal");
    assert_eq!(found("des.py"), ["DES"], "the DES permutation table, in decimal");
    assert!(found("numbers.c").is_empty(), "ordinary numbers are not a table");
    assert!(files.iter().any(|f| f["file"].as_str().unwrap().ends_with("sha1.py") && f["weak"] == true));
}

#[test]
fn finds_disabled_verification_and_key_sizes_of_generators() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_tls", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let names = |file: &str| files.iter().filter(|f| f["file"].as_str().unwrap().ends_with(file)).map(|f| f["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(names("srv.go"), ["InsecureSkipVerify", "MinVersion"], "TLS 1.2 is fine");
    assert_eq!(names("client.py"), ["verify=False", "check_hostname=False", "ssl.CERT_NONE"], "a comment is not a finding");
    assert_eq!(names("c.js"), ["rejectUnauthorized", "NODE_TLS_REJECT_UNAUTHORIZED"]);
    assert_eq!(names("fetch.sh"), ["curl --insecure", "--no-check-certificate"]);
    assert_eq!(names("c.rs"), ["danger_accept_invalid_certs"]);
    assert!(files.iter().all(|f| f["weak"] == true));
    // key sizes given to a key generator's methods
    let methods = v["methods"].as_array().unwrap();
    let m = |name: &str| methods.iter().find(|m| m["name"] == name).unwrap_or_else(|| panic!("no {name}")).clone();
    assert_eq!(m("kpg.initialize")["reason"], "1024-bit key");
    assert_eq!(m("ok.initialize")["weak"], false);
    assert_eq!(m("kg.init")["reason"], "64-bit key");
}

#[test]
fn untrusted_input_reaching_algorithm_key_or_iv_is_a_finding() {
    let out = common::taintless(&["--no-cache", "security", "tests/crypto_taint", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let found: Vec<(String, String, String)> = v.as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["file"].as_str().unwrap().rsplit('/').next().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |rule: &str, file: &str, function: &str| found.iter().any(|(r, f, func)| r == rule && f == file && func == function);
    assert!(has("crypto-algorithm-from-input", "app.py", "algo"), "{found:?}");
    assert!(has("crypto-algorithm-from-input", "App.java", "App.f"));
    assert!(has("crypto-algorithm-from-input", "app.js", "f"));
    assert!(has("crypto-iv-from-input", "app.py", "iv"));
    assert!(has("crypto-key-from-input", "app.py", "key"));
    // a key from the environment and constant algorithms are fine
    // keyword arguments: `hashlib.new(name=x)`, `jwt.decode(.., algorithms=[x])`, `iv=x`, `key=x`
    assert!(has("crypto-algorithm-from-input", "kw.py", "by_name"), "{found:?}");
    assert!(has("crypto-algorithm-from-input", "kw.py", "jwt_algorithms"));
    assert!(has("crypto-iv-from-input", "kw.py", "by_iv_keyword"));
    assert!(has("crypto-key-from-input", "kw.py", "by_key_keyword"));
    assert!(!found.iter().any(|(_, f, func)| f == "kw.py" && func == "constant"));
    assert_eq!(found.len(), 9, "{found:?}");
    assert_eq!(out.status.code(), Some(1));
    // the rules can be switched off like any other
    let cfg = common::taintless(&["--no-cache", "security", "tests/crypto_taint", "--config", "tests/crypto_taint_off.toml", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&cfg.stdout).unwrap();
    assert!(v.as_array().unwrap().is_empty(), "{v}");
}

#[test]
fn resolves_constants_defined_in_other_files() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_project", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let find = |file: &str, name: &str| calls.iter().find(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).unwrap().clone();
    assert_eq!(find("use.py", "hashlib.new")["algorithm"], "md5");
    assert_eq!(find("use.py", "AES.new")["issues"][0], "hardcoded key");
    assert_eq!(find("Use.java", "Cipher.getInstance")["algorithm"], "DES/ECB/PKCS5Padding");
    // a name defined nowhere stays unknown
    let unknown = calls.iter().find(|c| c["args"] == "settings.UNKNOWN").unwrap();
    assert_eq!(unknown["weak"], false);
}

#[test]
fn severities_and_minimum_severity() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_tls", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let sev = |name: &str| v["files"].as_array().unwrap().iter().find(|f| f["name"] == name).unwrap()["severity"].clone();
    assert_eq!(sev("InsecureSkipVerify"), "high");
    assert_eq!(sev("MinVersion"), "medium");
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let call = |name: &str| v["calls"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()["severity"].clone();
    assert_eq!(call("hashlib.md5"), "medium");
    assert_eq!(call("crypto.createHash"), "low", "SHA-1");
    assert_eq!(call("hmac.new"), "high", "hardcoded key");
    assert!(call("hashlib.sha256").is_null());
    // --min-severity keeps only what is at least that serious
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto", "--format", "json", "--min-severity", "high"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let all: Vec<&serde_json::Value> = ["calls", "methods", "files"].iter().flat_map(|k| v[*k].as_array().unwrap()).collect();
    assert!(!all.is_empty() && all.iter().all(|u| u["severity"] == "high"), "{all:?}");
    assert!(v["libraries"].as_array().unwrap().is_empty());
}

#[test]
fn follows_crypto_objects_through_functions() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_flow", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let methods = v["methods"].as_array().unwrap();
    let find = |file: &str, name: &str| methods.iter().filter(|m| m["file"].as_str().unwrap().ends_with(file) && m["name"] == name).cloned().collect::<Vec<_>>();
    // returned from a function (another file): `c = make_cipher(); c.encrypt(d)`
    let m = find("client.py", "c.encrypt");
    assert_eq!((m.len(), m[0]["reason"].as_str(), m[0]["origin_line"].as_u64()), (1, Some("ECB mode"), Some(5)));
    assert_eq!(find("client.py", "h.update")[0]["reason"], "MD5");
    // passed to a function: the method inside it gets the algorithm of the object passed in
    let inside = find("factory.py", "cipher.encrypt");
    assert_eq!(inside.len(), 1, "{inside:?}");
    assert_eq!(inside[0]["weak"], false, "the caller passes a CBC cipher");
    assert_eq!(inside[0]["origin_line"], 9);
    assert_eq!(find("factory.py", "h.update")[0]["reason"], "MD5", "digest_with(h, ..) passes the md5 object");
    // Java: returned and passed
    assert_eq!(find("Svc.java", "c.init")[0]["reason"], "DES");
    assert_eq!(find("Svc.java", "c.doFinal")[0]["reason"], "DES");
}

#[test]
fn a_configured_sink_can_name_a_keyword_argument() {
    let out = common::taintless(&["--no-cache", "security", "tests/crypto_taint/kwsink.py", "--config", "tests/crypto_taint_sink.toml", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let lines: Vec<u64> = v.as_array().unwrap().iter().map(|f| f["line"].as_u64().unwrap()).collect();
    assert_eq!(lines, [4], "only the `q=` argument is the sink: {v}");
}

#[test]
fn keyword_arguments_are_sinks_wherever_they_stand() {
    let out = common::taintless(&["--no-cache", "security", "tests/crypto_taint_kw", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with("reordered.py")).map(|f| (f["rule"].as_str().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    // `iv=` comes second here and `key=` first: only their names tell them apart from the others
    assert_eq!(found, [("crypto-iv-from-input".to_string(), "iv_by_keyword".to_string()), ("crypto-key-from-input".to_string(), "key_by_keyword".to_string())], "{found:?}");
}

#[test]
fn rules_match_through_import_aliases() {
    let out = common::taintless(&["--no-cache", "security", "tests/taint_alias", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let found: Vec<(String, String, String)> = v.as_array().unwrap().iter().map(|f| (f["file"].as_str().unwrap().rsplit('/').next().unwrap().to_string(), f["function"].as_str().unwrap().to_string(), f["rule"].as_str().unwrap().to_string())).collect();
    let has = |file: &str, function: &str, rule: &str| found.iter().any(|(f, func, r)| f == file && func == function && r == rule);
    // `import os as o`, `from os import system`, `from subprocess import run as r`
    assert!(has("app.py", "via_module_alias", "command-injection"), "{found:?}");
    assert!(has("app.py", "via_from_import", "command-injection"));
    assert!(has("app.py", "via_renamed_import", "command-injection"));
    assert!(has("app.py", "crypto_through_alias", "crypto-algorithm-from-input"));
    // a constant argument stays clean
    assert!(!found.iter().any(|(_, func, _)| func == "constant" || func == "c"), "{found:?}");
    // JavaScript: a renamed require, a destructured and renamed member; Go: an aliased package
    assert!(has("app.js", "a", "command-injection") && has("app.js", "b", "command-injection"));
    assert!(has("app.go", "h", "command-injection"));
    assert_eq!(found.len(), 7, "{found:?}");
}

#[test]
fn reads_the_algorithm_and_size_of_keys_and_certificates() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_keys", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let get = |name: &str| files.iter().find(|f| f["file"].as_str().unwrap().ends_with(name)).unwrap_or_else(|| panic!("no {name}")).clone();
    let alg = |name: &str| get(name)["algorithm"].as_str().unwrap().to_string();
    assert_eq!(alg("rsa1024_pkcs1.pem"), "RSA 1024-bit");
    assert_eq!(get("rsa1024_pkcs1.pem")["reason"], "1024-bit key");
    assert_eq!(alg("rsa2048_pkcs8.pem"), "RSA 2048-bit", "PKCS#8 wraps the RSA key");
    assert_eq!(get("rsa2048_pkcs8.pem")["weak"], false);
    assert_eq!(alg("rsa2048_pub.pem"), "RSA 2048-bit");
    assert_eq!(alg("ec256.pem"), "EC prime256v1");
    assert_eq!(get("ec192.pem")["reason"], "EC curve prime192v1");
    assert_eq!(alg("ed25519.pem"), "Ed25519");
    // certificates: the key inside and a weak signature
    assert_eq!(alg("cert_sha1_rsa1024.pem"), "X.509 RSA 1024-bit");
    assert_eq!(get("cert_sha1_rsa1024.pem")["reason"], "1024-bit key, SHA-1 signature");
    assert_eq!(get("cert_sha256_rsa2048.pem")["weak"], false);
    // a committed private key is still high, whatever its size
    assert_eq!(get("rsa2048_pkcs8.pem")["severity"], "high");
    assert!(get("cert_sha256_rsa2048.pem")["severity"].is_null());
}

#[test]
fn covers_siphash_argon2_costs_and_non_cryptographic_hashes() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_hashes", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let all = |file: &str, name: &str| calls.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).cloned().collect::<Vec<_>>();
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // SipHash is a keyed hash: a literal key is a hardcoded key; a key variable is not
    let sip = all("hashes.py", "siphash.SipHash_2_4");
    assert!(sip.iter().all(|c| c["primitive"] == "mac" && c["algorithm"] == "SipHash-2-4 (keyed hash)"));
    assert_eq!(sip.iter().filter(|c| issues(c).contains(&"hardcoded key".to_string())).count(), 1);
    assert_eq!(all("h.c", "crypto_shorthash")[0]["algorithm"], "SipHash-2-4 (libsodium)", "before the generic libsodium entry");
    assert_eq!(all("sip.rs", "SipHasher24.new_with_key")[0]["issues"][0], "hardcoded key");
    // Argon2: memory below 19 MiB is low, by position and by keyword, in every language
    let low = |file: &str, name: &str| all(file, name).iter().map(|c| issues(c).iter().any(|i| i.starts_with("low Argon2 memory cost"))).collect::<Vec<_>>();
    assert_eq!(low("hashes.py", "PasswordHasher"), [true, false]);
    assert_eq!(low("sip.rs", "Params.new"), [true, false]);
    assert_eq!(low("Hashes.java", "Argon2PasswordEncoder"), [true, false]);
    assert_eq!(low("h.go", "argon2.IDKey"), [true, true], "`8*1024` is a product and is read");
    assert_eq!(low("h.go", "argon2.Key"), [false]);
    assert_eq!(low("h.c", "argon2id_hash_raw"), [true, false]);
    // non-cryptographic hashes are listed with a hint, not flagged
    for (file, name) in [("hashes.py", "xxhash.xxh64"), ("hashes.py", "zlib.crc32"), ("Hashes.java", "Hashing.murmur3_128"), ("h.go", "fnv.New32a"), ("h.c", "XXH64")] {
        let c = &all(file, name)[0];
        assert_eq!(issues(c), ["non-cryptographic hash"], "{name}");
        assert_eq!(c["weak"], false, "{name}");
        assert!(c["severity"].is_null(), "{name}: a hint is not flagged");
    }
    assert!(issues(&all("Hashes.java", "Hashing.sha256")[0]).is_empty());
}

#[test]
fn reads_keys_in_der_base64_and_jwk_form() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_keys", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let of = |name: &str| files.iter().filter(|f| f["file"].as_str().unwrap().rsplit('/').next() == Some(name)).cloned().collect::<Vec<_>>();
    let issues = |f: &serde_json::Value| f["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // binary DER: a certificate, a PKCS#8 key and an RSA key, told apart by their shape
    let cert = &of("cert_sha1.crt")[0];
    assert_eq!((cert["name"].as_str(), cert["reason"].as_str()), (Some("CERTIFICATE (DER)"), Some("1024-bit key, SHA-1 signature")));
    assert_eq!(of("rsa2048.p8")[0]["algorithm"], "RSA 2048-bit");
    assert_eq!(of("rsa1024.der")[0]["reason"], "1024-bit key");
    assert!(issues(&of("rsa1024.der")[0]).contains(&"hardcoded private key".to_string()));
    // one line of base64 inside a config file; a run that only starts like DER is not a key
    let env = of("keys.env");
    assert_eq!(env.len(), 1, "{env:?}");
    assert_eq!((env[0]["algorithm"].as_str(), env[0]["line"].as_u64()), (Some("EC prime256v1"), Some(2)));
    // JSON Web Keys: sizes from the modulus and the key, private and symmetric keys are secrets
    let jwk = of("jwks.json");
    let summary: Vec<(String, bool, Vec<String>)> = jwk.iter().map(|k| (k["algorithm"].as_str().unwrap().to_string(), k["weak"] == true, issues(k))).collect();
    let s = |a: &str, w: bool, i: &[&str]| (a.to_string(), w, i.iter().map(|x| x.to_string()).collect::<Vec<_>>());
    assert_eq!(
        summary,
        [
            s("RSA 1024-bit", true, &["hardcoded private key"]),
            s("RSA 2048-bit", false, &[]),
            s("EC P-256", false, &["hardcoded private key"]),
            s("symmetric 64-bit", true, &["hardcoded key"]),
            s("symmetric 256-bit", false, &["hardcoded key"]),
        ]
    );
}

#[test]
fn reads_more_manifest_formats() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_manifests", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let declared = v["declared"].as_array().unwrap();
    let mut got: Vec<(String, String)> = declared.iter().map(|d| (d["manifest"].as_str().unwrap().rsplit('/').next().unwrap().to_string(), d["library"].as_str().unwrap().to_string())).collect();
    got.sort();
    let want = [
        ("CMakeLists.txt", "OpenSSL"), // find_package(OpenSSL) and OpenSSL::Crypto: one library
        ("Pipfile", "PyJWT"),
        ("Pipfile", "bcrypt"),
        ("conanfile.py", "mbedTLS"),
        ("conanfile.py", "wolfSSL"),
        ("conanfile.txt", "OpenSSL"),
        ("conanfile.txt", "libsodium"),
        ("libs.versions.toml", "Bouncy Castle"),
        ("libs.versions.toml", "Tink"),
        ("libs.versions.toml", "jjwt"),
        ("setup.cfg", "PyNaCl"),
        ("setup.py", "PyCryptodome"),
        ("setup.py", "argon2-cffi"),
        ("setup.py", "cryptography"),
        ("vcpkg.json", "GnuTLS"),
        ("vcpkg.json", "libgcrypt"),
    ];
    let want: Vec<(String, String)> = want.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    assert_eq!(got, want, "requests, click, flask, fmt, zlib, junit and Threads are not crypto");
}

#[test]
fn resolves_default_import_names_nested_use_groups_and_containers() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_alias", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let find = |list: &str, file: &str, name: &str| v[list].as_array().unwrap().iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["name"] == name).cloned().collect::<Vec<_>>();
    // `import CJ from 'crypto-js'`, a named member, and the nested Rust group
    assert_eq!(find("calls", "cj.js", "CJ.AES.encrypt")[0]["algorithm"], "AES");
    assert_eq!(find("calls", "cj.js", "CJ.MD5")[0]["reason"], "MD5");
    assert_eq!(find("calls", "cj.js", "sha1")[0]["reason"], "SHA-1");
    assert_eq!(find("calls", "nested.rs", "C.aes_128_ecb")[0]["weak"], true);
    assert_eq!(find("calls", "nested.rs", "MD.md5")[0]["weak"], true);
    assert_eq!(find("calls", "nested.rs", "MD.sha256")[0]["weak"], false);
    // objects through a copy, a list, a loop and `append`
    let methods = |name: &str| find("methods", "containers.py", name);
    assert_eq!(methods("z.encrypt")[0]["reason"], "ECB mode");
    assert_eq!(methods("xs.encrypt")[0]["reason"], "ECB mode");
    assert_eq!(methods("h.encrypt")[0]["reason"], "ECB mode");
    assert_eq!(methods("ys.update")[0]["reason"], "MD5");
    assert!(methods("ys.append").is_empty(), "putting an object into a list is not a use");
    // a list that holds different objects: a literal index gets the object at that index
    assert_eq!(methods("ms.encrypt")[0]["reason"], "ECB mode");
}

#[test]
fn finds_crypto_in_compiled_programs() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_bin", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let of = |file: &str| files.iter().filter(|f| f["file"].as_str().unwrap().rsplit('/').next() == Some(file)).cloned().collect::<Vec<_>>();
    let get = |file: &str, name: &str| of(file).into_iter().find(|f| f["name"] == name).unwrap_or_else(|| panic!("no {name} in {file}"));
    // a real Mach-O executable linked against OpenSSL: the library and the functions it imports
    assert_eq!(get("openssl_demo.bin", "linked library")["algorithm"], "OpenSSL");
    assert_eq!(get("openssl_demo.bin", "EVP_md5")["reason"], "MD5");
    assert_eq!(get("openssl_demo.bin", "EVP_aes_128_ecb")["reason"], "AES-128-ECB");
    assert_eq!(get("openssl_demo.bin", "EVP_CIPHER_CTX_new")["weak"], false);
    assert!(of("openssl_demo.bin").iter().all(|f| f["name"] != "___stack_chk_fail" && f["name"] != "stack_chk_fail"));
    // a Go program: the packages it links
    assert_eq!(get("demo_go.bin", "linked Go package crypto/md5")["weak"], true);
    assert_eq!(get("demo_go.bin", "linked Go package crypto/sha256")["weak"], false);
    // a Java class: algorithm names in its constant pool
    let algs: Vec<(String, bool)> = of("Synthetic.class").iter().map(|f| (f["algorithm"].as_str().unwrap().to_string(), f["weak"] == true)).collect();
    assert!(algs.contains(&("MD5".to_string(), true)) && algs.contains(&("DES/ECB/PKCS5Padding".to_string(), true)) && algs.contains(&("AES".to_string(), false)), "{algs:?}");
}

#[test]
fn the_call_graph_tells_same_named_functions_apart() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_resolve", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let methods = v["methods"].as_array().unwrap();
    let find = |name: &str| methods.iter().filter(|m| m["name"] == name && !m["file"].as_str().unwrap().ends_with("chain.py")).cloned().collect::<Vec<_>>();
    // two `build` methods in two classes: each call gets the cipher of the class it names
    let (a, b) = (&find("a.init"), &find("b.init"));
    assert_eq!((a.len(), b.len()), (1, 1), "{methods:?}");
    assert_eq!(a[0]["reason"], "DES");
    assert_eq!(b[0]["algorithm"], "AES/GCM/NoPadding");
    assert_eq!(b[0]["weak"], false);
    // two `seal` methods: the object passed to `e.seal` reaches `Encryptor.seal`, not `Decryptor.seal`
    let enc = find("cipher.encrypt");
    let dec = find("cipher.decrypt");
    assert_eq!((enc.len(), dec.len()), (1, 1), "{methods:?}");
    assert_eq!(enc[0]["reason"], "ECB mode");
    assert_eq!(dec[0]["weak"], false);
    assert_eq!(dec[0]["origin_line"], 16);
}

#[test]
fn follows_an_object_through_several_functions() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_resolve/chain.py", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let m = v["methods"].as_array().unwrap();
    // `run` passes the cipher to `encrypt_outer`, which hands it to `encrypt_middle`, then `encrypt_inner`
    assert_eq!(m.len(), 1, "{m:?}");
    assert_eq!((m[0]["name"].as_str(), m[0]["reason"].as_str(), m[0]["origin_line"].as_u64()), (Some("cipher.encrypt"), Some("ECB mode"), Some(13)));
}

#[test]
fn properties_of_object_and_struct_literals_are_sinks() {
    let out = common::taintless(&["--no-cache", "security", "tests/crypto_taint_kw", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let found: Vec<(String, String)> = v.as_array().unwrap().iter().filter(|f| !f["file"].as_str().unwrap().ends_with("reordered.py")).map(|f| (f["file"].as_str().unwrap().rsplit('/').next().unwrap().to_string(), f["function"].as_str().unwrap().to_string())).collect();
    let has = |file: &str, function: &str| found.iter().any(|(f, func)| f == file && func == function);
    // `{ algorithms: [x] }`, `{ algorithm: x }`, `{ minVersion: x }` and Go's `&tls.Config{MinVersion: x}`
    assert!(has("props.js", "algorithm_from_request"), "{found:?}");
    assert!(has("props.js", "signing_algorithm"));
    assert!(has("props.js", "tls_version"));
    assert!(has("props.go", "fromRequest"));
    // an object nested one level deeper
    assert!(has("props.js", "nested_options"));
    // another property holding untrusted data is not the algorithm
    assert!(!has("props.js", "other_option_is_tainted") && !has("props.js", "constant_options") && !has("props.go", "other"), "{found:?}");
    assert_eq!(found.len(), 5, "{found:?}");
}

#[test]
fn options_built_in_a_variable_are_followed_by_security() {
    let out = common::taintless(&["--no-cache", "security", "tests/security_only", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let functions: Vec<&str> = v.as_array().unwrap().iter().map(|f| f["function"].as_str().unwrap()).collect();
    // `opts = { algorithms: [x] }; jwt.verify(t, k, opts)`; the other property being tainted is no finding
    assert_eq!(functions, ["options_in_a_variable"], "{functions:?}");
}

#[test]
fn covers_csharp_crypto() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/csharp_crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let find = |name: &str| calls.iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no {name}")).clone();
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // hashes and ciphers, an alias (`using Md = ..MD5`) and a constant (`HashAlgorithm.Create(Algo)`)
    assert_eq!(find("MD5.Create")["reason"], "MD5");
    assert_eq!(find("SHA1CryptoServiceProvider")["reason"], "SHA-1");
    assert_eq!(find("SHA256.Create")["weak"], false);
    assert_eq!(find("Md.Create")["reason"], "MD5");
    assert_eq!(find("HashAlgorithm.Create")["algorithm"], "MD5");
    assert_eq!(find("DES.Create")["reason"], "DES");
    assert_eq!(find("RSACryptoServiceProvider")["reason"], "1024-bit key");
    // parameters: hardcoded password, zero salt, few iterations, a literal HMAC key, a constant seed
    let kdf = issues(&find("Rfc2898DeriveBytes"));
    assert!(kdf.contains(&"hardcoded secret".to_string()) && kdf.contains(&"zero salt".to_string()) && kdf.iter().any(|i| i.starts_with("low PBKDF2 iterations (1000")), "{kdf:?}");
    assert!(issues(&find("HMACSHA256")).contains(&"hardcoded key".to_string()));
    assert!(issues(&find("Random")).contains(&"constant PRNG seed".to_string()));
    // methods and properties of an object: `aes.Key = Key;`, `aes.IV = new byte[16];`
    let methods = v["methods"].as_array().unwrap();
    let m = |name: &str| methods.iter().find(|m| m["name"] == name).unwrap_or_else(|| panic!("no {name}")).clone();
    assert_eq!(m("md5.ComputeHash")["reason"], "MD5");
    assert!(issues(&m("aes.Key =")).contains(&"hardcoded key".to_string()));
    assert!(issues(&m("aes.IV =")).contains(&"zero IV".to_string()));
    // settings in source: ECB, TLS 1.0, a validation callback that accepts everything
    let files = v["files"].as_array().unwrap();
    let reason = |name: &str| files.iter().find(|f| f["name"] == name).unwrap_or_else(|| panic!("no {name}"))["reason"].clone();
    assert_eq!(reason("CipherMode.ECB"), "ECB mode");
    assert_eq!(reason("SslProtocols.Tls"), "TLS 1.0/1.1");
    assert_eq!(reason("ServerCertificateValidationCallback"), "certificate verification disabled");
    assert_eq!(files.iter().filter(|f| f["name"].as_str().unwrap().starts_with("SslProtocols")).count(), 1, "Tls12 | Tls13 is fine");
    // NuGet manifests: crypto packages only, case-insensitively
    let mut declared: Vec<(String, String)> = v["declared"].as_array().unwrap().iter().map(|d| (d["manifest"].as_str().unwrap().rsplit('/').next().unwrap().to_string(), d["library"].as_str().unwrap().to_string())).collect();
    declared.sort();
    let want: Vec<(String, String)> = [("App.csproj", "BCrypt.Net"), ("App.csproj", "Bouncy Castle"), ("App.csproj", "Konscious Argon2"), ("packages.config", "Bouncy Castle")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    assert_eq!(declared, want, "Newtonsoft.Json and NUnit are not crypto");
}

#[test]
fn covers_kotlin_crypto() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/kotlin_crypto", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let find = |name: &str| calls.iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no {name}")).clone();
    let issues = |c: &serde_json::Value| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // `import javax.crypto.Cipher as C`, a `const val` algorithm and a byte-array key
    assert_eq!(find("C.getInstance")["reason"], "DES");
    assert_eq!(find("MessageDigest.getInstance")["algorithm"], "MD5");
    let keys: Vec<serde_json::Value> = calls.iter().filter(|c| c["name"] == "SecretKeySpec").cloned().collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| issues(k).contains(&"hardcoded key".to_string())), "`.toByteArray()` and `byteArrayOf(..)` are literal keys");
    assert_eq!(keys[0]["algorithm"], "DES", "the algorithm is the literal, not the key constant");
    assert!(issues(&find("IvParameterSpec")).contains(&"zero IV".to_string()), "ByteArray(8) is eight zero bytes");
    let methods = v["methods"].as_array().unwrap();
    assert!(methods.iter().any(|m| m["name"] == "c.doFinal" && m["reason"] == "DES"));
}

#[test]
fn declared_types_and_constants_through_assignments_and_calls() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_typed", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let methods = v["methods"].as_array().unwrap();
    let calls = v["calls"].as_array().unwrap();
    let at = |list: &Vec<serde_json::Value>, file: &str, line: u64, name: &str| list.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line && c["name"] == name).cloned().collect::<Vec<_>>();
    // `Cipher c` as a parameter says only what the class says ...
    let seal = at(methods, "Typed.java", 11, "c.doFinal");
    assert_eq!((seal.len(), seal[0]["algorithm"].as_str(), seal[0]["weak"].as_bool()), (1, Some("(by transformation)"), Some(false)));
    // ... unless a caller passes a concrete object: then that is the report, and the declared one goes
    let open = at(methods, "Typed.java", 16, "c.doFinal");
    assert_eq!((open.len(), open[0]["reason"].as_str()), (1, Some("DES")));
    // constants through assignments: ALIAS2 = ALIAS = BASE = "MD5"
    assert_eq!(at(calls, "Typed.java", 21, "MessageDigest.getInstance")[0]["algorithm"], "MD5");
    // a parameter is what its callers pass: one caller, or callers that agree; not callers that differ
    assert_eq!(at(calls, "Typed.java", 27, "MessageDigest.getInstance")[0]["algorithm"], "MD5");
    assert_eq!(at(calls, "Typed.java", 31, "MessageDigest.getInstance")[0]["algorithm"], "(by name)");
    assert_eq!(at(calls, "wrap.py", 4, "hashlib.new")[0]["algorithm"], "sha1");
}

#[test]
fn constants_built_from_parts_or_returned_by_functions() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_parts", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let alg = |file: &str, line: u64| {
        let c: Vec<_> = calls.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line).collect();
        assert_eq!(c.len(), 1, "{file}:{line}");
        (c[0]["algorithm"].as_str().unwrap().to_string(), c[0]["weak"].as_bool().unwrap())
    };
    // `"MD" + "5"`, a constant built that way, and a function returning a literal
    assert_eq!(alg("parts.py", 17), ("MD5".into(), true));
    assert_eq!(alg("parts.py", 18), ("md5".into(), true));
    assert_eq!(alg("parts.py", 19), ("sha1".into(), true));
    assert_eq!(alg("parts.py", 20), ("sha256".into(), false));
    // a part that is not a literal leaves the algorithm unresolved
    assert!(!alg("parts.py", 21).1);
    assert_eq!(alg("Parts.java", 11), ("MD5".into(), true));
    assert_eq!(alg("Parts.java", 12), ("SHA-1".into(), true));
    assert_eq!(alg("Parts.java", 13), ("DES/ECB/PKCS5Padding".into(), true));
    assert!(!alg("Parts.java", 14).1);
}

#[test]
fn settings_in_flow_style_anchors_includes_and_keystores() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_settings", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    let found = |file: &str| -> Vec<(u64, String, String)> {
        files.iter().filter(|f| f["file"].as_str().unwrap().rsplit('/').next() == Some(file)).map(|f| (f["line"].as_u64().unwrap(), f["name"].as_str().unwrap().to_string(), f["reason"].as_str().unwrap().to_string())).collect()
    };
    let has = |list: &[(u64, String, String)], line: u64, name: &str, reason: &str| list.iter().any(|(l, n, r)| *l == line && n == name && r == reason);
    // several keys on one line, and a number as a value
    let json = found("one-line.json");
    assert_eq!(json.len(), 2);
    assert!(has(&json, 1, "ciphers", "RC4") && has(&json, 1, "server.tls_min_version", "TLS 1.0/1.1"));
    // an anchor reaches where it is merged (`<<: *tls`) or used (`tls: *tls`), at that line
    let yml = found("flow.yml");
    assert!(has(&yml, 2, "tls_defaults.min_version", "TLS 1.0/1.1"));
    assert!(has(&yml, 5, "prod_tls.min_version", "TLS 1.0/1.1") && has(&yml, 5, "prod_tls.ciphers", "RC4"));
    assert!(has(&yml, 8, "staging.tls.min_version", "TLS 1.0/1.1"));
    // flow collections, nested and over several lines
    assert!(has(&yml, 9, "inline.ssl_protocols", "SSLV3") && has(&yml, 9, "inline.other.tls_min_version", "TLS 1.0/1.1"));
    assert!(has(&yml, 12, "multi.tls.ciphers", "3DES"));
    assert_eq!(yml.len(), 12, "TLSv1.2, TLSv1.3 and an anchored safe value are not reported: {yml:?}");
    // an included file is read, and reported at its own place
    assert_eq!(found("legacy.conf").len(), 1);
    assert!(found("server.conf").is_empty());
    // the certificates of a Java keystore
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_keystore", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let certs: Vec<_> = v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with("legacy.jks") && f["name"].as_str().unwrap().contains("JKS")).collect();
    assert_eq!(certs.len(), 2);
    assert!(certs.iter().any(|c| c["name"].as_str().unwrap().contains("weakkey") && c["algorithm"].as_str().unwrap().contains("RSA 1024") && c["weak"] == true));
    assert!(certs.iter().any(|c| c["algorithm"].as_str().unwrap().contains("prime256v1") && c["weak"] == false));
}

#[test]
fn argon2_options_presets_and_more_non_cryptographic_hashes() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_argon", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let issues = |file: &str, line: u64| -> Vec<String> {
        let c: Vec<_> = calls.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line).collect();
        assert!(!c.is_empty(), "{file}:{line}");
        c.iter().flat_map(|c| c["issues"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string())).collect()
    };
    let low = |i: Vec<String>| i.iter().any(|x| x.starts_with("low Argon2"));
    // an options object, in either order, with a shift
    assert!(low(issues("a.js", 6)));
    assert!(!low(issues("a.js", 7)) && !low(issues("a.js", 8)));
    // libsodium presets (bytes) and products
    assert!(low(issues("a.js", 9)));
    assert!(!low(issues("a.c", 3)) && low(issues("a.c", 4)) && low(issues("a.c", 5)));
    assert!(!low(issues("a.go", 8)) && low(issues("a.go", 9)), "64*1024 KiB is enough, 8*1024 is not");
    // CityHash / FarmHash outside Java, HighwayHash, wyhash
    for (file, line) in [("a.js", 10), ("a.js", 11), ("a.go", 10), ("a.go", 11), ("b.cpp", 3)] {
        assert!(issues(file, line).contains(&"non-cryptographic hash".to_string()), "{file}:{line}");
    }
}

#[test]
fn values_from_other_files_containers_interpolation_and_option_variables() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_values", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let at = |file: &str, line: u64| {
        let c: Vec<_> = calls.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line).collect();
        assert_eq!(c.len(), 1, "{file}:{line}");
        (c[0]["algorithm"].as_str().unwrap().to_string(), c[0]["weak"].as_bool().unwrap(), c[0]["issues"].as_array().unwrap().len())
    };
    // returned by a function of another file
    assert_eq!(at("use.py", 11), ("md5".into(), true, 0));
    assert_eq!(at("use.py", 12), ("sha256".into(), false, 0));
    // interpolated constants
    assert_eq!(at("use.py", 13).0, "sha1");
    assert_eq!(at("use.py", 14).0, "md5");
    assert_eq!(at("use.js", 11).0, "md5");
    // entries of a dictionary, a list and an object
    assert_eq!(at("use.py", 15).0, "md5");
    assert_eq!(at("use.py", 16).0, "sha256");
    assert_eq!(at("use.py", 17).0, "sha1");
    assert_eq!(at("use.py", 18).0, "sha256");
    assert_eq!(at("use.js", 9).0, "md5");
    assert_eq!(at("use.js", 10).0, "sha256");
    // an options object held in a variable
    assert_eq!(at("use.js", 12).2, 1);
    assert_eq!(at("use.js", 13).2, 0);
}

#[test]
fn formatted_strings_and_containers_filled_key_by_key_or_in_other_files() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_values", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = v["calls"].as_array().unwrap();
    let alg = |file: &str, line: u64| {
        let c: Vec<_> = calls.iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line).collect();
        assert_eq!(c.len(), 1, "{file}:{line}");
        (c[0]["algorithm"].as_str().unwrap().to_string(), c[0]["weak"].as_bool().unwrap())
    };
    // `%`, `.format` with positions and names
    assert_eq!(alg("fmt.py", 15), ("sha1".into(), true));
    assert_eq!(alg("fmt.py", 16), ("md5".into(), true));
    assert_eq!(alg("fmt.py", 17), ("sha256".into(), false));
    assert_eq!(alg("fmt.py", 18), ("md5".into(), true));
    // a value that is not known leaves the template as it is
    assert_eq!(alg("fmt.py", 19), ("sha%s".into(), false));
    // `NAME[key] = value`, `NAME.append(value)`, and a table of another file
    assert_eq!(alg("fmt.py", 20), ("md5".into(), true));
    assert_eq!(alg("fmt.py", 21), ("sha256".into(), false));
    assert_eq!(alg("fmt.py", 22), ("sha1".into(), true));
    assert_eq!(alg("fmt.py", 23), ("sha1".into(), true));
    // a key stored with two values has none, and its name is not an algorithm
    assert_eq!(alg("fmt.py", 32), ("(by name)".into(), false));
    // `String.format`
    assert_eq!(alg("Fmt.java", 5), ("SHA-1".into(), true));
    assert_eq!(alg("Fmt.java", 6), ("SHA-256".into(), false));
}

#[test]
fn more_formats_constants_keystores_and_jars() {
    let run = |dir: &str| -> serde_json::Value {
        let out = common::taintless(&["--no-cache", "crypto", dir, "--format", "json"]);
        serde_json::from_slice(&out.stdout).unwrap()
    };
    // width, precision and fill in format specs
    let v = run("tests/crypto_values");
    let alg = |file: &str, line: u64| -> String {
        let c: Vec<_> = v["calls"].as_array().unwrap().iter().filter(|c| c["file"].as_str().unwrap().ends_with(file) && c["line"] == line).collect();
        assert_eq!(c.len(), 1, "{file}:{line}");
        c[0]["algorithm"].as_str().unwrap().to_string()
    };
    assert_eq!(alg("Spec.java", 5), "MD5");
    assert_eq!(alg("Spec.java", 6), "SHA-001");
    assert_eq!(alg("spec.py", 5), "md5");
    assert_eq!(alg("spec.py", 6), "sha001");
    assert_eq!(alg("spec.py", 7), "md5");
    // Whirlpool and Threefish / Serpent constants
    let v = run("tests/crypto_const");
    let found = |file: &str| -> Vec<String> { v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with(file)).map(|f| f["algorithm"].as_str().unwrap().to_string()).collect() };
    assert_eq!(found("whirlpool.c"), ["Whirlpool"]);
    let skein = found("skein.rs");
    assert!(skein.contains(&"Threefish / Skein".to_string()) && skein.contains(&"Serpent".to_string()), "{skein:?}");
    // a JCEKS keystore reads like a JKS one
    let v = run("tests/crypto_keystore");
    assert!(v["files"].as_array().unwrap().iter().any(|f| f["file"].as_str().unwrap().ends_with("legacy.jceks") && f["name"].as_str().unwrap().contains("JKS certificate") && f["weak"] == true));
    // the entry names of a jar
    let v = run("tests/crypto_jar");
    let names: Vec<String> = v["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap().to_string()).collect();
    assert!(names.contains(&"library in jar".to_string()) && names.contains(&"class MD5Digest in jar".to_string()) && names.contains(&"class DESEngine in jar".to_string()), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("SHA256")));
    // YAML flow collections in list items and anchors on lists
    let v = run("tests/crypto_settings");
    let at = |line: u64| v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with("list.yml") && f["line"] == line).count();
    assert_eq!((at(2), at(4), at(6), at(8)), (1, 1, 1, 1));
}

#[test]
fn options_objects_across_functions_fields_and_containers() {
    let out = common::taintless(&["--no-cache", "security", "tests/security_options", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut functions: Vec<&str> = v.as_array().unwrap().iter().map(|f| f["function"].as_str().unwrap()).collect();
    functions.sort();
    // passed to a wrapper (literal, variable, passed on), returned (literal, variable, key by key,
    // reassigned), kept in a field, nested in a container; clean ones stay silent
    assert_eq!(
        functions,
        ["Checker.check", "by_key_direct", "in_container", "key_by_key_here", "reassigned_direct", "returned_direct", "returned_variable", "verifyChain", "verifyLiteral", "verifyVariable"],
        "{functions:?}"
    );
}

#[test]
fn pkcs12_and_bks_keystores() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_keystore", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let of = |file: &str| -> Vec<(String, String, bool)> {
        v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with(file) && f["name"] != "keystore file").map(|f| (f["name"].as_str().unwrap().to_string(), f["algorithm"].as_str().unwrap().to_string(), f["weak"].as_bool().unwrap())).collect()
    };
    // encrypted: the algorithms that protect it, and the MAC
    let legacy = of("legacy.p12");
    assert!(legacy.iter().any(|(n, a, w)| n == "keystore encryption" && a == "pbeWithSHAAnd40BitRC2-CBC" && *w));
    assert!(legacy.iter().any(|(n, a, w)| n == "keystore encryption" && a == "pbeWithSHAAnd3-KeyTripleDES-CBC" && *w));
    assert!(legacy.iter().any(|(n, a, w)| n == "keystore MAC" && a == "SHA-1" && *w));
    let modern = of("modern.p12");
    assert_eq!(modern.iter().map(|(n, a, w)| (n.as_str(), a.as_str(), *w)).collect::<Vec<_>>(), [("keystore encryption", "PBES2", false), ("keystore MAC", "SHA-256", false)]);
    // in the clear: the certificate's key
    let plain = of("plain.p12");
    assert!(plain.iter().any(|(n, a, w)| n.contains("PKCS#12") && a.contains("RSA 1024") && *w), "{plain:?}");
    // BouncyCastle
    assert!(of("legacy.bks").iter().any(|(n, a, w)| n.contains("BKS certificate `old-ca`") && a.contains("RSA 1024") && *w));
}

#[test]
fn reassigned_mixed_and_keyed_objects() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_objects", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let at = |file: &str, line: u64| -> Vec<(String, bool)> {
        let mut found: Vec<(String, bool)> = v["methods"].as_array().unwrap().iter().filter(|m| m["file"].as_str().unwrap().ends_with(file) && m["line"] == line).map(|m| (m["algorithm"].as_str().unwrap().to_string(), m["weak"].as_bool().unwrap())).collect();
        found.sort();
        found
    };
    let (aes, des) = (("AES".to_string(), false), ("DES".to_string(), true));
    // a variable assigned again holds, at each call, what reaches that call
    assert_eq!(at("objects.py", 6), std::slice::from_ref(&des));
    assert_eq!(at("objects.py", 8), std::slice::from_ref(&aes));
    // both branches, both list elements
    assert_eq!(at("objects.py", 16), [aes.clone(), des.clone()]);
    assert_eq!(at("objects.py", 22), [aes.clone(), des.clone()]);
    // a dictionary: the object under that key, whether in the literal or stored later
    assert_eq!(at("objects.py", 27), std::slice::from_ref(&des));
    assert_eq!(at("objects.py", 28), std::slice::from_ref(&aes));
    assert_eq!(at("objects.py", 35), [des]);
    assert_eq!(at("objects.py", 36), [aes]);
    // the same in Java, and through a loop
    assert_eq!(at("Objects.java", 6), [("DES/ECB/PKCS5Padding".to_string(), true)]);
    assert_eq!(at("Objects.java", 8), [("AES/GCM/NoPadding".to_string(), false)]);
    assert_eq!(at("Objects.java", 14).len(), 2);
}

#[test]
fn symbol_tables_rust_symbols_and_jar_classes() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_objects_bin", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let of = |file: &str| -> Vec<(String, String)> {
        v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with(file)).map(|f| (f["name"].as_str().unwrap().to_string(), f["algorithm"].as_str().unwrap().to_string())).collect()
    };
    // a name that is only in a message is not an import (the old string search listed all three)
    assert!(of("msg.bin").is_empty(), "{:?}", of("msg.bin"));
    // Mach-O: imported symbols
    assert!(of("imp.o").iter().any(|(n, _)| n == "EVP_md5"));
    // ELF: the dynamic symbols and DT_NEEDED; an unrelated import is not listed
    let elf = of("imports.elf");
    assert!(elf.iter().any(|(n, a)| n == "linked library" && a == "OpenSSL") && elf.iter().any(|(n, _)| n == "EVP_des_ecb"));
    assert!(!elf.iter().any(|(n, _)| n.contains("unrelated")));
    // PE: the import table
    assert!(of("imports.exe").iter().any(|(n, a)| n == "linked library" && a == "Windows CNG"));
    // Rust: the crate and the function of a v0 symbol (the legacy scheme is covered by a unit test)
    assert!(of("md5_crate.o").iter().any(|(n, _)| n == "linked Rust crate md5"));
    assert!(of("md5_crate.o").iter().any(|(n, a)| n == "md5.compute" && a == "MD5"));
    assert!(of("md5_fn.o").iter().any(|(n, a)| n == "Md5.new" && a == "MD5"), "{:?}", of("md5_fn.o"));
    // a PE file's delay-load imports and a stripped Go binary (functions from its tables of names)
    assert!(of("delay.exe").iter().any(|(n, a)| n == "linked library" && a == "Windows CNG"));
    let go = of("stripped_go.bin");
    assert!(go.iter().any(|(n, _)| n == "md5.Sum") && go.iter().any(|(n, _)| n == "sha256.Sum256"), "{go:?}");
    // a deflated class inside a jar
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_jar", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let algs: Vec<&str> = v["files"].as_array().unwrap().iter().filter(|f| f["name"] == "algorithm name").map(|f| f["algorithm"].as_str().unwrap()).collect();
    assert!(algs.contains(&"MD5") && algs.contains(&"DES/ECB/PKCS5Padding"), "{algs:?}");
}

#[test]
fn t1ha_spookyhash_and_metrohash_are_non_cryptographic() {
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_argon", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let hits: Vec<(String, u64)> = v["calls"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["file"].as_str().unwrap().contains("more_hashes") && c["issues"].as_array().unwrap().iter().any(|i| i == "non-cryptographic hash"))
        .map(|c| (c["file"].as_str().unwrap().rsplit('.').next().unwrap().to_string(), c["line"].as_u64().unwrap()))
        .collect();
    // Python (3), Go (2), Rust (2), C++ (2)
    assert_eq!(hits.len(), 9, "{hits:?}");
}

#[test]
fn rust_trait_impls_generics_and_pe_ordinals() {
    // `<md5::Md5 as Digest>::update` and a generic instance, in a v0 symbol
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_objects_bin/md5_trait.o", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"linked Rust crate md5") && names.contains(&"Md5.update"), "{names:?}");
    // imports by number are named by the exports of the DLL next to the file ...
    let out = common::taintless(&["--no-cache", "crypto", "tests/crypto_ordinals", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let in_app: Vec<(&str, bool)> = v["files"].as_array().unwrap().iter().filter(|f| f["file"].as_str().unwrap().ends_with("app.exe")).map(|f| (f["name"].as_str().unwrap(), f["weak"].as_bool().unwrap())).collect();
    assert!(in_app.contains(&("EVP_md5", true)) && in_app.contains(&("EVP_des_ecb", true)), "{in_app:?}");
    // ... and stay unnamed when it is not there
    let alone = std::env::temp_dir().join("taintless_ordinals_alone");
    std::fs::create_dir_all(&alone).unwrap();
    std::fs::copy("tests/crypto_ordinals/app.exe", alone.join("app.exe")).unwrap();
    let out = common::taintless(&["--no-cache", "crypto", alone.to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!v["files"].as_array().unwrap().iter().any(|f| f["name"] == "EVP_md5"));
}

#[test]
fn ruby_php_and_swift_manifests() {
    let dir = std::env::temp_dir().join(format!("taintless-manifests-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Gemfile"), "source 'https://rubygems.org'\ngem 'rails'\ngem \"bcrypt\", '~> 3.1'\ngem 'jwt'\n").unwrap();
    std::fs::write(dir.join("composer.json"), r#"{"require": {"php": ">=8.1", "firebase/php-jwt": "^6.0"}, "require-dev": {"phpseclib/phpseclib": "^3"}}"#).unwrap();
    std::fs::write(dir.join("Package.swift"), "let package = Package(dependencies: [.package(url: \"https://github.com/krzyzanowskim/CryptoSwift.git\", from: \"1.8.0\")])\n").unwrap();
    std::fs::write(dir.join("Podfile"), "target 'App' do\n  pod 'CryptoSwift'\nend\n").unwrap();
    let out = common::taintless(&["--no-cache", "crypto", dir.to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let libs: Vec<&str> = v["declared"].as_array().unwrap().iter().map(|l| l["library"].as_str().unwrap()).collect();
    for want in ["bcrypt-ruby", "ruby-jwt", "firebase/php-jwt", "phpseclib", "CryptoSwift"] {
        assert!(libs.contains(&want), "{want} in {libs:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
