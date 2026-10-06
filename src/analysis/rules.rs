//! Built-in rule tables: what is a source, a sanitizer or a dangerous call,
//! per language family. Patterns are matched against normalized callees
//! (`os.system`, `Runtime.getRuntime.exec`, `Command.new`, ...):
//!
//! * `"eval"`        exactly the bare name,
//! * `"os.system"`   that dotted name, optionally behind more qualifiers,
//! * `"*.execute"`   any method named `execute`.

use super::Severity;
use crate::lang::Language;

#[derive(Clone, Copy)]
pub enum ArgSel {
    Any,
    /// Only the n-th argument (0-based): the query of `execute(query, params)`.
    At(usize),
    /// Only the argument passed by this keyword (`hashlib.new(name=x)`).
    Named(&'static str),
}

#[derive(Clone, Copy)]
pub enum Mode {
    /// Always reported (escalated when an argument is tainted).
    Always,
    /// Reported only when untrusted data reaches the selected argument(s).
    Tainted(ArgSel),
}

#[derive(Clone, Copy)]
pub struct CallRule {
    pub pattern: &'static str,
    pub id: &'static str,
    pub cwe: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    pub mode: Mode,
    /// Callees that look like this rule's pattern but are something else
    /// (`syscall.Exec` is not a database `Exec`).
    pub except: &'static [&'static str],
}

impl CallRule {
    const fn except(self, except: &'static [&'static str]) -> Self {
        Self { except, ..self }
    }
    const fn at(self, i: usize) -> Self {
        Self { mode: Mode::Tainted(ArgSel::At(i)), ..self }
    }
}

use Severity::{High, Low, Medium};

const fn tainted(pattern: &'static str, id: &'static str, cwe: &'static str, severity: Severity, message: &'static str) -> CallRule {
    CallRule { pattern, id, cwe, severity, message, mode: Mode::Tainted(ArgSel::Any), except: &[] }
}
const fn always(pattern: &'static str, id: &'static str, cwe: &'static str, severity: Severity, message: &'static str) -> CallRule {
    CallRule { pattern, id, cwe, severity, message, mode: Mode::Always, except: &[] }
}

const fn cmd(p: &'static str) -> CallRule {
    tainted(p, "command-injection", "CWE-78", High, "OS command built from untrusted input")
}
const fn code(p: &'static str) -> CallRule {
    tainted(p, "code-injection", "CWE-95", High, "dynamic code built from untrusted input")
}
const fn eval(p: &'static str) -> CallRule {
    always(p, "code-injection", "CWE-95", High, "dynamic code evaluation")
}
const fn sql(p: &'static str) -> CallRule {
    tainted(p, "sql-injection", "CWE-89", High, "SQL query built from untrusted input").at(0)
}
const fn path(p: &'static str) -> CallRule {
    tainted(p, "path-traversal", "CWE-22", Medium, "file path built from untrusted input").at(0)
}
const fn ssrf(p: &'static str) -> CallRule {
    tainted(p, "ssrf", "CWE-918", Medium, "request URL built from untrusted input").at(0)
}
const fn redirect(p: &'static str) -> CallRule {
    tainted(p, "open-redirect", "CWE-601", Medium, "redirect target from untrusted input")
}
const fn xss(p: &'static str) -> CallRule {
    tainted(p, "xss", "CWE-79", Medium, "untrusted data written into a page")
}
const fn deser(p: &'static str) -> CallRule {
    always(p, "insecure-deserialization", "CWE-502", High, "deserialization of untrusted data can run code")
}
const fn weak_hash(p: &'static str) -> CallRule {
    always(p, "weak-crypto", "CWE-327", Low, "weak hash algorithm")
}
const fn unsafe_fn(p: &'static str, msg: &'static str) -> CallRule {
    always(p, "unsafe-function", "CWE-676", Medium, msg)
}
const fn format_string(p: &'static str, arg: usize) -> CallRule {
    tainted(p, "format-string", "CWE-134", High, "format string controlled by untrusted input").at(arg)
}

/// Console output is never a page.
const STDOUT: &[&str] = &["System.out.println", "System.out.print", "System.err.println", "System.err.print"];

/// Methods that store their arguments in the receiver (`list.append(x)`): a
/// tainted argument taints the receiver.
pub const MUTATORS: &[&str] = &[
    "append", "extend", "add", "insert", "push", "push_back", "push_front", "push_str", "put", "putAll",
    "addAll", "update", "setdefault", "write", "writelines", "appendleft", "offer", "unshift", "set",
    "concat", "emplace_back", "WriteString", "Write",
];

/// Environment variables and system properties are set by whoever runs the
/// program, so they do not make a path, URL, redirect or page "untrusted"
/// (they still matter for commands and memory errors).
pub fn ignores_env_sources(rule_id: &str) -> bool {
    matches!(rule_id, "path-traversal" | "ssrf" | "open-redirect" | "xss" | "crypto-algorithm-from-input" | "crypto-key-from-input" | "crypto-iv-from-input")
}

/// A function whose parameters carry untrusted data (a request handler, ...).
#[derive(Clone, Copy)]
pub struct Entry {
    /// Function name; `*` matches anything (`handle_*`).
    pub pattern: &'static str,
    /// Only these parameters; empty = all of them.
    pub params: &'static [&'static str],
}

/// `*` wildcard match of the whole text.
pub fn wild(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some((b'*', rest)) => (0..=t.len()).any(|i| go(rest, &t[i..])),
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

pub struct RuleSet {
    pub entries: &'static [Entry],
    pub rules: &'static [CallRule],
    /// Calls whose result is untrusted.
    pub source_calls: &'static [&'static str],
    /// Variables / member paths that hold untrusted data.
    pub source_paths: &'static [&'static str],
    /// Lowercase fragments of the sources above that read the environment
    /// (`getenv`); `=x` matches only `x`. See [`ignores_env_sources`].
    pub env_sources: &'static [&'static str],
    /// Calls whose result is safe regardless of their arguments.
    pub sanitizers: &'static [&'static str],
    /// Custom explanations for configured sources: `(is a call pattern, pattern, message)`.
    pub source_notes: &'static [(bool, &'static str, &'static str)],
}

/// `pattern` against a normalized callee; see the module docs.
pub fn matches(pattern: &str, callee: &str) -> bool {
    if let Some(m) = pattern.strip_prefix("*.") {
        return callee.rsplit_once('.').is_some_and(|(_, last)| last == m);
    }
    if !pattern.contains('.') {
        return callee == pattern;
    }
    callee == pattern
        || (callee.len() > pattern.len()
            && callee.ends_with(pattern)
            && callee.as_bytes()[callee.len() - pattern.len() - 1] == b'.')
}

/// `path` without element keys: `request.args['q'].x` is `request.args.x`.
fn without_keys(path: &str) -> std::borrow::Cow<'_, str> {
    if !path.contains('[') {
        return path.into();
    }
    let mut out = String::with_capacity(path.len());
    let mut depth = 0;
    for c in path.chars() {
        match c {
            '[' => depth += 1,
            ']' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.into()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let path = &*without_keys(path);
    path == pattern
        || path.starts_with(&format!("{pattern}."))
        || path.ends_with(&format!(".{pattern}"))
        || path.contains(&format!(".{pattern}."))
}

impl RuleSet {
    /// Whether a source description names an environment-like origin.
    pub fn is_env_source(&self, desc: &str) -> bool {
        let d = if desc.bytes().any(|b| b.is_ascii_uppercase()) { std::borrow::Cow::Owned(desc.to_ascii_lowercase()) } else { desc.into() };
        self.env_sources.iter().any(|p| p.strip_prefix('=').map_or_else(|| d.contains(p), |x| d == x))
    }
    pub fn is_source_call(&self, callee: &str) -> bool {
        self.source_calls.iter().any(|p| matches(p, callee))
    }
    pub fn is_source_path(&self, path: &str) -> bool {
        self.source_paths.iter().any(|p| path_matches(p, path))
    }
    /// The configured explanation of why this call's result is untrusted.
    pub fn source_call_note(&self, callee: &str) -> Option<&'static str> {
        self.source_notes.iter().find(|(call, p, _)| *call && matches(p, callee)).map(|n| n.2)
    }
    pub fn source_path_note(&self, path: &str) -> Option<&'static str> {
        self.source_notes.iter().find(|(call, p, _)| !*call && path_matches(p, path)).map(|n| n.2)
    }
    pub fn is_sanitizer(&self, callee: &str) -> bool {
        self.sanitizers.iter().any(|p| matches(p, callee))
    }
}

fn builtin(lang: Language) -> &'static RuleSet {
    match lang {
        Language::Python => &PYTHON,
        Language::JavaScript | Language::TypeScript | Language::Tsx => &JAVASCRIPT,
        Language::Java | Language::Kotlin => &JAVA,
        Language::Go => &GO,
        Language::Rust => &RUST,
        Language::C | Language::Cpp => &C_FAMILY,
        Language::CSharp => &CSHARP,
        Language::Ruby => &RUBY,
        Language::Php => &PHP,
        Language::Swift => &SWIFT,
    }
}

/// Every built-in rule of every language (prototypes for configured sinks).
pub fn all_rules() -> impl Iterator<Item = &'static CallRule> {
    [&PYTHON, &JAVASCRIPT, &JAVA, &GO, &RUST, &C_FAMILY, &CSHARP, &RUBY, &PHP, &SWIFT].into_iter().flat_map(|r| r.rules.iter())
}

/// The rules for `lang`: the built-in ones plus those from the installed configuration.
pub fn rules_for(lang: Language) -> &'static RuleSet {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static MERGED: OnceLock<Mutex<HashMap<u8, &'static RuleSet>>> = OnceLock::new();
    let base = with_crypto(builtin(lang), lang.family());
    let Some(active) = super::config::installed() else { return base };
    let mut cache = MERGED.get_or_init(Default::default).lock().expect("rules cache");
    cache.entry(lang.family()).or_insert_with(|| super::config::extend(base, lang.family(), &active.config))
}

/// `base` plus the sinks of the crypto tables: untrusted data as the algorithm, key or IV of a
/// crypto call. Built once per language family, after the crypto tables are final.
/// Keyword names under which a key or an IV is passed (`AES.new(key=k, iv=v)`).
static KEY_WORDS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec!["key".to_string()]);
static IV_WORDS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec!["iv".to_string(), "nonce".to_string()]);

fn with_crypto(base: &'static RuleSet, fam: u8) -> &'static RuleSet {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use super::crypto::tables::active;
    static CACHE: OnceLock<Mutex<HashMap<u8, &'static RuleSet>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().expect("crypto rules cache");
    cache.entry(fam).or_insert_with(|| {
        let mut rules = base.rules.to_vec();
        let t = active();
        let mut sink = |pattern: &'static str, id: &'static str, cwe: &'static str, sev: Severity, msg: &'static str, index: Option<usize>, keywords: &'static [String]| {
            let sel = |sel: ArgSel| CallRule { pattern, id, cwe, severity: sev, message: msg, mode: Mode::Tainted(sel), except: &[] };
            rules.extend(index.map(|i| sel(ArgSel::At(i))));
            rules.extend(keywords.iter().map(|k| sel(ArgSel::Named(k))));
        };
        for a in t.algorithm.iter().filter(|a| a.lang.family() == fam) {
            sink(&a.pattern, "crypto-algorithm-from-input", "CWE-757", Medium, "cryptographic algorithm chosen from untrusted input", a.index, &a.keywords);
        }
        for s in t.secret.iter().filter(|s| s.lang.family() == fam) {
            for arg in &s.args {
                match arg.role.as_str() {
                    "key" => sink(&s.pattern, "crypto-key-from-input", "CWE-320", Low, "cryptographic key taken from untrusted input", Some(arg.index), &KEY_WORDS),
                    "iv" => sink(&s.pattern, "crypto-iv-from-input", "CWE-329", Medium, "IV or nonce taken from untrusted input", Some(arg.index), &IV_WORDS),
                    _ => {}
                }
            }
        }
        Box::leak(Box::new(RuleSet {
            entries: base.entries,
            rules: Box::leak(rules.into_boxed_slice()),
            source_calls: base.source_calls,
            source_paths: base.source_paths,
            env_sources: base.env_sources,
            sanitizers: base.sanitizers,
            source_notes: base.source_notes,
        }))
    })
}

/// Rule id -> (title, CWE) for reports.
pub const RULE_INFO: &[(&str, &str, &str)] = &[
    ("command-injection", "OS command injection", "CWE-78"),
    ("code-injection", "Code injection / dynamic evaluation", "CWE-95"),
    ("sql-injection", "SQL injection", "CWE-89"),
    ("path-traversal", "Path traversal", "CWE-22"),
    ("ssrf", "Server-side request forgery", "CWE-918"),
    ("open-redirect", "Open redirect", "CWE-601"),
    ("xss", "Cross-site scripting", "CWE-79"),
    ("insecure-deserialization", "Insecure deserialization", "CWE-502"),
    ("weak-crypto", "Weak cryptographic algorithm", "CWE-327"),
    ("crypto-algorithm-from-input", "Cryptographic algorithm chosen by untrusted input", "CWE-757"),
    ("crypto-key-from-input", "Cryptographic key taken from untrusted input", "CWE-320"),
    ("crypto-iv-from-input", "IV or nonce taken from untrusted input", "CWE-329"),
    ("unsafe-function", "Use of an unsafe function", "CWE-676"),
    ("format-string", "Format string vulnerability", "CWE-134"),
    ("insecure-temp-file", "Insecure temporary file", "CWE-377"),
    ("unreachable-code", "Unreachable code", "CWE-561"),
];

static PYTHON: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        eval("eval"),
        eval("exec"),
        code("compile").at(0),
        cmd("os.system"),
        cmd("os.popen"),
        cmd("os.execl"),
        cmd("os.execv"),
        cmd("os.execvp"),
        cmd("os.spawnl"),
        cmd("subprocess.run"),
        cmd("subprocess.call"),
        cmd("subprocess.check_call"),
        cmd("subprocess.check_output"),
        cmd("subprocess.Popen"),
        cmd("subprocess.getoutput"),
        cmd("subprocess.getstatusoutput"),
        deser("pickle.loads"),
        deser("pickle.load"),
        deser("cPickle.loads"),
        deser("marshal.loads"),
        deser("yaml.load"),
        deser("yaml.unsafe_load"),
        deser("shelve.open"),
        sql("*.execute"),
        sql("*.executemany"),
        sql("*.executescript"),
        sql("*.raw"),
        path("open"),
        path("os.remove"),
        path("os.unlink"),
        path("os.rmdir"),
        path("os.makedirs"),
        path("os.listdir"),
        path("shutil.rmtree"),
        path("shutil.copy"),
        path("send_file"),
        path("send_from_directory"),
        ssrf("requests.get"),
        ssrf("requests.post"),
        ssrf("requests.put"),
        ssrf("requests.delete"),
        ssrf("requests.request"),
        ssrf("urllib.request.urlopen"),
        ssrf("urlopen"),
        redirect("redirect"),
        xss("render_template_string"),
        xss("Markup"),
        xss("HttpResponse"),
        weak_hash("hashlib.md5"),
        weak_hash("hashlib.sha1"),
        always("tempfile.mktemp", "insecure-temp-file", "CWE-377", Low, "predictable temporary file name"),
    ],
    source_calls: &[
        "input", "raw_input", "os.getenv", "os.environ.get", "sys.stdin.read", "sys.stdin.readline",
        "request.args.get", "request.form.get", "request.values.get", "request.get_json",
        "request.GET.get", "request.POST.get", "*.recv", "*.recvfrom", "*.getlist",
    ],
    source_paths: &[
        "sys.argv", "os.environ", "request.args", "request.form", "request.values", "request.json",
        "request.data", "request.cookies", "request.headers", "request.GET", "request.POST", "request.body",
    ],
    env_sources: &["getenv", "environ"],
    sanitizers: &[
        "int", "float", "bool", "len", "shlex.quote", "html.escape", "markupsafe.escape", "escape",
        "re.escape", "os.path.basename", "secure_filename", "urllib.parse.quote", "quote", "bleach.clean",
    ],
};

static JAVASCRIPT: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        eval("eval"),
        eval("Function"),
        code("setTimeout").at(0),
        code("setInterval").at(0),
        code("vm.runInNewContext"),
        code("vm.runInThisContext"),
        code("vm.runInContext"),
        cmd("child_process.exec"),
        cmd("child_process.execSync"),
        cmd("child_process.spawn"),
        cmd("child_process.spawnSync"),
        cmd("child_process.execFile"),
        cmd("exec"),
        cmd("execSync"),
        cmd("spawn"),
        cmd("spawnSync"),
        xss("document.write"),
        xss("document.writeln"),
        xss("*.insertAdjacentHTML"),
        xss("res.send"),
        xss("res.write"),
        xss("res.end"),
        xss("response.send"),
        xss("response.write"),
        sql("*.query"),
        sql("*.execute"),
        sql("*.raw"),
        path("fs.readFile"),
        path("fs.readFileSync"),
        path("fs.writeFile"),
        path("fs.writeFileSync"),
        path("fs.createReadStream"),
        path("fs.unlink"),
        path("fs.unlinkSync"),
        path("fs.rm"),
        path("fs.rmSync"),
        path("*.sendFile"),
        path("*.download"),
        path("require"),
        ssrf("fetch"),
        ssrf("axios"),
        ssrf("axios.get"),
        ssrf("axios.post"),
        ssrf("http.get"),
        ssrf("https.get"),
        ssrf("request"),
        redirect("*.redirect"),
    ],
    source_calls: &[
        "prompt", "readline.question", "localStorage.getItem", "sessionStorage.getItem",
        "URLSearchParams.get", "*.getParameter",
    ],
    source_paths: &[
        "process.argv", "process.env", "req.body", "req.query", "req.params", "req.headers",
        "req.cookies", "request.body", "request.query", "request.params", "location.search",
        "location.hash", "location.href", "document.cookie", "document.referrer", "window.name",
    ],
    env_sources: &["process.env"],
    sanitizers: &[
        "parseInt", "parseFloat", "Number", "Boolean", "encodeURIComponent", "encodeURI", "escape",
        "path.basename", "validator.escape", "DOMPurify.sanitize", "sanitizeHtml", "escapeHtml",
        "_.escape", "shellEscape",
    ],
};

static CSHARP: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[Entry { pattern: "Main", params: &["args"] }],
    rules: &[
        cmd("Process.Start"),
        cmd("ProcessStartInfo"),
        sql("SqlCommand").at(0),
        sql("SqlDataAdapter").at(0),
        sql("OracleCommand").at(0),
        sql("MySqlCommand").at(0),
        sql("NpgsqlCommand").at(0),
        sql("SqliteCommand").at(0),
        sql("OleDbCommand").at(0),
        sql("OdbcCommand").at(0),
        sql("*.ExecuteSqlRaw"),
        sql("*.ExecuteSqlRawAsync"),
        sql("*.ExecuteSqlCommand"),
        sql("*.FromSqlRaw"),
        sql("*.SqlQuery"),
        path("File.ReadAllText"),
        path("File.ReadAllBytes"),
        path("File.ReadAllLines"),
        path("File.ReadLines"),
        path("File.WriteAllText"),
        path("File.WriteAllBytes"),
        path("File.WriteAllLines"),
        path("File.AppendAllText"),
        path("File.OpenRead"),
        path("File.OpenWrite"),
        path("File.Open"),
        path("File.Delete"),
        path("File.Copy"),
        path("File.Move"),
        path("File.Create"),
        path("Directory.GetFiles"),
        path("Directory.Delete"),
        path("Directory.CreateDirectory"),
        path("FileStream"),
        path("StreamReader"),
        path("StreamWriter"),
        path("*.PhysicalFile"),
        ssrf("*.GetAsync"),
        ssrf("*.GetStringAsync"),
        ssrf("*.GetStreamAsync"),
        ssrf("*.GetByteArrayAsync"),
        ssrf("*.PostAsync"),
        ssrf("*.DownloadString"),
        ssrf("*.DownloadFile"),
        ssrf("*.DownloadData"),
        ssrf("WebRequest.Create"),
        ssrf("HttpWebRequest.Create"),
        redirect("*.Redirect"),
        redirect("*.RedirectPermanent"),
        redirect("Response.Redirect"),
        xss("Response.Write"),
        xss("Response.WriteAsync"),
        xss("*.Html.Raw"),
        xss("HtmlString"),
        deser("BinaryFormatter"),
        deser("NetDataContractSerializer"),
        deser("SoapFormatter"),
        deser("LosFormatter"),
        deser("ObjectStateFormatter"),
        code("CSharpScript.EvaluateAsync"),
        code("CSharpScript.RunAsync"),
        tainted("Type.GetType", "code-injection", "CWE-470", Medium, "type loaded by untrusted name").at(0),
        tainted("Assembly.Load", "code-injection", "CWE-470", Medium, "assembly loaded by untrusted name").at(0),
        tainted("Assembly.LoadFrom", "code-injection", "CWE-470", Medium, "assembly loaded from an untrusted path").at(0),
        weak_hash("MD5.Create"),
        weak_hash("SHA1.Create"),
        weak_hash("MD5CryptoServiceProvider"),
        weak_hash("SHA1CryptoServiceProvider"),
        weak_hash("SHA1Managed"),
        weak_hash("MD5Cng"),
    ],
    source_calls: &[
        "Console.ReadLine", "Console.In.ReadLine", "Console.ReadKey", "Environment.GetEnvironmentVariable",
        "Environment.GetCommandLineArgs", "*.GetQueryString", "Request.QueryString.Get", "Request.Form.Get",
        "Request.Headers.Get", "Request.Query.TryGetValue",
    ],
    source_paths: &[
        "Request.Query", "Request.QueryString", "Request.Form", "Request.Headers", "Request.Cookies",
        "Request.Params", "Request.Path", "Request.PathInfo", "Request.RawUrl", "Request.Url", "Request.Body",
        "HttpContext.Request.Query", "HttpContext.Request.Form", "HttpContext.Request.Headers",
        "HttpContext.Request.Cookies", "context.Request.Query", "context.Request.Form",
    ],
    env_sources: &["getenv"],
    sanitizers: &[
        "int.Parse", "int.TryParse", "Int32.Parse", "Int32.TryParse", "long.Parse", "Int64.Parse", "Convert.ToInt32",
        "Convert.ToInt64", "Guid.Parse", "Guid.TryParse", "Path.GetFileName", "HttpUtility.HtmlEncode",
        "WebUtility.HtmlEncode", "HtmlEncoder.Default.Encode", "Uri.EscapeDataString", "Regex.Escape",
        "AntiXssEncoder.HtmlEncode", "HttpUtility.UrlEncode", "WebUtility.UrlEncode",
    ],
};

static RUBY: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        cmd("system"),
        cmd("exec"),
        cmd("spawn"),
        cmd("Kernel.system"),
        cmd("Kernel.exec"),
        cmd("Kernel.spawn"),
        cmd("Process.spawn"),
        cmd("IO.popen"),
        cmd("PTY.spawn"),
        cmd("Open3.capture2"),
        cmd("Open3.capture2e"),
        cmd("Open3.capture3"),
        cmd("Open3.popen2"),
        cmd("Open3.popen2e"),
        cmd("Open3.popen3"),
        cmd("Open3.pipeline"),
        code("eval"),
        code("Kernel.eval"),
        code("instance_eval"),
        code("class_eval"),
        code("module_eval"),
        code("*.instance_eval"),
        code("*.class_eval"),
        code("*.module_eval"),
        code("ERB.new"),
        sql("*.execute"),
        sql("*.exec_query"),
        sql("*.find_by_sql"),
        sql("*.select_all"),
        sql("*.select_rows"),
        sql("*.select_value"),
        sql("*.select_one"),
        sql("*.exec"),
        sql("*.query"),
        path("File.read"),
        path("File.binread"),
        path("File.readlines"),
        path("File.foreach"),
        path("File.open"),
        path("File.new"),
        path("File.write"),
        path("File.binwrite"),
        path("File.delete"),
        path("File.unlink"),
        path("File.rename"),
        path("IO.read"),
        path("IO.readlines"),
        path("IO.write"),
        path("FileUtils.rm"),
        path("FileUtils.rm_rf"),
        path("FileUtils.rm_r"),
        path("FileUtils.cp"),
        path("FileUtils.mv"),
        path("FileUtils.mkdir_p"),
        path("Dir.glob"),
        path("Dir.entries"),
        path("Dir.children"),
        path("Dir.mkdir"),
        path("send_file"),
        path("send_data"),
        ssrf("Net.HTTP.get"),
        ssrf("Net.HTTP.get_response"),
        ssrf("Net.HTTP.get_print"),
        ssrf("Net.HTTP.post"),
        ssrf("Net.HTTP.post_form"),
        ssrf("Net.HTTP.start"),
        ssrf("Net.HTTP.new"),
        ssrf("URI.open"),
        ssrf("HTTParty.get"),
        ssrf("HTTParty.post"),
        ssrf("RestClient.get"),
        ssrf("RestClient.post"),
        ssrf("Faraday.get"),
        ssrf("Faraday.post"),
        ssrf("Typhoeus.get"),
        ssrf("OpenURI.open_uri"),
        redirect("redirect_to"),
        redirect("*.redirect"),
        xss("raw"),
        xss("*.html_safe"),
        xss("render_to_string"),
        deser("Marshal.load"),
        deser("Marshal.restore"),
        deser("YAML.load"),
        deser("YAML.unsafe_load"),
        deser("Psych.load"),
        deser("Psych.unsafe_load"),
        deser("Oj.load"),
        deser("JSON.load"),
        weak_hash("Digest.MD5.hexdigest"),
        weak_hash("Digest.MD5.digest"),
        weak_hash("Digest.MD5.base64digest"),
        weak_hash("Digest.MD5.new"),
        weak_hash("Digest.SHA1.hexdigest"),
        weak_hash("Digest.SHA1.digest"),
        weak_hash("Digest.SHA1.base64digest"),
        weak_hash("Digest.SHA1.new"),
        weak_hash("OpenSSL.Digest.MD5.new"),
        weak_hash("OpenSSL.Digest.SHA1.new"),
    ],
    source_calls: &[
        "gets", "readline", "readlines", "Kernel.gets", "STDIN.gets", "STDIN.read", "STDIN.readline", "STDIN.readlines", "$stdin.gets",
        "$stdin.read", "ARGF.read", "ARGF.gets", "ENV.fetch", "request.body.read", "request.raw_post", "request.query_string",
    ],
    source_paths: &[
        "gets", "readline", "readlines", "params", "ARGV", "ENV", "cookies", "request.params", "request.query_parameters", "request.request_parameters",
        "request.headers", "request.env", "request.cookies", "request.GET", "request.POST", "request.path", "request.url",
    ],
    env_sources: &["env.fetch", "=env"],
    sanitizers: &[
        "Shellwords.escape", "Shellwords.shellescape", "*.shellescape", "ERB.Util.html_escape", "ERB.Util.h", "CGI.escapeHTML",
        "CGI.escape", "html_escape", "h", "sanitize", "*.sanitize", "File.basename", "Integer", "Float", "*.to_i", "*.to_f",
        "URI.encode_www_form_component", "Regexp.escape", "Rack.Utils.escape_html",
    ],
};

static PHP: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        cmd("system"),
        cmd("exec"),
        cmd("shell_exec"),
        cmd("passthru"),
        cmd("popen"),
        cmd("proc_open"),
        cmd("pcntl_exec"),
        code("eval"),
        code("assert"),
        code("create_function"),
        code("include"),
        code("include_once"),
        code("require"),
        code("require_once"),
        code("call_user_func"),
        code("call_user_func_array"),
        tainted("preg_replace", "code-injection", "CWE-95", High, "pattern with the `e` modifier from untrusted input").at(0),
        sql("mysql_query"),
        sql("mysqli_query").at(1),
        sql("mysqli_multi_query").at(1),
        sql("mysqli_real_query").at(1),
        sql("pg_query").at(1),
        sql("pg_send_query").at(1),
        sql("sqlite_query"),
        sql("*.query"),
        sql("*.exec"),
        sql("*.multi_query"),
        sql("*.real_query"),
        sql("*.unprepared"),
        sql("*.whereRaw"),
        sql("*.selectRaw"),
        sql("*.orderByRaw"),
        sql("DB.raw"),
        sql("DB.select"),
        sql("DB.statement"),
        path("file_get_contents"),
        path("file_put_contents"),
        path("fopen"),
        path("readfile"),
        path("file"),
        path("unlink"),
        path("copy"),
        path("rename"),
        path("mkdir"),
        path("rmdir"),
        path("scandir"),
        path("opendir"),
        path("glob"),
        path("fpassthru"),
        path("highlight_file"),
        path("show_source"),
        path("move_uploaded_file").at(1),
        path("SplFileObject"),
        ssrf("curl_init"),
        ssrf("fsockopen"),
        ssrf("get_headers"),
        ssrf("Http.get"),
        ssrf("Http.post"),
        ssrf("*.request"),
        redirect("header"),
        redirect("*.redirect"),
        redirect("redirect"),
        xss("echo"),
        xss("print"),
        xss("printf"),
        xss("print_r"),
        xss("vprintf"),
        deser("unserialize"),
        deser("maybe_unserialize"),
        weak_hash("md5"),
        weak_hash("sha1"),
        weak_hash("md5_file"),
        weak_hash("sha1_file"),
        weak_hash("crc32"),
    ],
    source_calls: &[
        "getenv", "readline", "fgets", "fgetc", "fread", "filter_input", "filter_input_array", "getallheaders", "apache_request_headers", "stream_get_contents",
    ],
    source_paths: &[
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$_ENV", "$argv", "$HTTP_RAW_POST_DATA", "STDIN",
    ],
    env_sources: &["getenv", "$_env"],
    sanitizers: &[
        "intval", "floatval", "absint", "boolval", "htmlspecialchars", "htmlentities", "escapeshellarg", "escapeshellcmd", "basename",
        "urlencode", "rawurlencode", "addslashes", "mysqli_real_escape_string", "mysql_real_escape_string", "pg_escape_string", "*.real_escape_string",
        "*.quote", "*.escape_string", "filter_var", "strip_tags", "ctype_digit", "esc_html", "esc_attr", "esc_url", "sanitize_text_field", "e", "Str.slug", "json_encode",
    ],
};

static SWIFT: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        cmd("system"),
        cmd("popen"),
        cmd("execl"),
        cmd("execlp"),
        cmd("execle"),
        cmd("execv"),
        cmd("execvp"),
        cmd("execve"),
        cmd("posix_spawn"),
        cmd("Process.launchedProcess"),
        cmd("NSTask.launchedTask"),
        code("NSExpression"),
        code("*.evaluateScript"),
        code("*.evaluateJavaScript"),
        sql("sqlite3_exec").at(1),
        sql("sqlite3_prepare").at(1),
        sql("sqlite3_prepare_v2").at(1),
        sql("sqlite3_prepare_v3").at(1),
        sql("*.execute"),
        sql("*.executeQuery"),
        sql("*.executeUpdate"),
        sql("*.prepare"),
        sql("*.scalar"),
        sql("*.fetchAll"),
        path("FileManager.default.contents"),
        path("FileManager.default.removeItem"),
        path("FileManager.default.createFile"),
        path("FileManager.default.copyItem"),
        path("FileManager.default.moveItem"),
        path("FileManager.default.contentsOfDirectory"),
        path("FileManager.default.createDirectory"),
        path("*.removeItem"),
        path("*.copyItem"),
        path("*.moveItem"),
        path("*.contentsOfDirectory"),
        path("fopen"),
        path("NSData.contentsOfFile"),
        path("NSString.contentsOfFile"),
        path("InputStream"),
        path("OutputStream"),
        ssrf("URL"),
        ssrf("URLRequest"),
        ssrf("NSURL"),
        ssrf("*.dataTask"),
        ssrf("*.downloadTask"),
        ssrf("*.uploadTask"),
        redirect("*.redirect"),
        xss("*.loadHTMLString"),
        xss("*.loadHTML"),
        deser("NSKeyedUnarchiver.unarchiveObject"),
        deser("NSKeyedUnarchiver.unarchiveTopLevelObjectWithData"),
        weak_hash("CC_MD5"),
        weak_hash("CC_SHA1"),
        weak_hash("Insecure.MD5.hash"),
        weak_hash("Insecure.SHA1.hash"),
        weak_hash("Insecure.MD5"),
        weak_hash("Insecure.SHA1"),
        weak_hash("*.md5"),
        weak_hash("*.sha1"),
    ],
    source_calls: &[
        "readLine", "CommandLine.arguments", "FileHandle.standardInput.readLine", "FileHandle.standardInput.readDataToEndOfFile", "UIPasteboard.general.string",
        "ProcessInfo.processInfo.environment", "ProcessInfo.processInfo.arguments", "UserDefaults.standard.string",
    ],
    source_paths: &[
        "CommandLine.arguments", "ProcessInfo.processInfo.environment", "ProcessInfo.processInfo.arguments", "req.query", "req.content",
        "req.parameters", "req.body", "req.headers", "request.query", "request.parameters", "request.body", "request.headers",
        "UIPasteboard.general.string",
    ],
    env_sources: &["processinfo.processinfo.environment"],
    sanitizers: &[
        "Int", "Double", "Float", "UInt", "*.addingPercentEncoding", "*.htmlEscaped", "*.escapingHTML", "*.sanitized",
        "URL.fileURLWithPath", "*.lastPathComponent", "*.standardizingPath", "NSRegularExpression.escapedPattern",
    ],
};

static JAVA: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[Entry { pattern: "main", params: &["args"] }],
    rules: &[
        cmd("Runtime.getRuntime.exec"),
        cmd("*.exec"),
        cmd("ProcessBuilder"),
        sql("*.executeQuery"),
        sql("*.executeUpdate"),
        sql("*.execute"),
        sql("*.prepareStatement"),
        sql("*.createQuery"),
        sql("*.createNativeQuery"),
        deser("*.readObject"),
        deser("XMLDecoder"),
        path("File"),
        path("FileInputStream"),
        path("FileOutputStream"),
        path("FileReader"),
        path("FileWriter"),
        path("Paths.get"),
        path("Files.readAllBytes"),
        path("Files.readString"),
        path("Files.newInputStream"),
        path("Files.write"),
        path("Files.delete"),
        code("*.eval"),
        tainted("Class.forName", "code-injection", "CWE-470", Medium, "class loaded by untrusted name").at(0),
        ssrf("URL"),
        redirect("*.sendRedirect"),
        xss("getWriter.println"),
        xss("getWriter.print"),
        xss("getWriter.write"),
        xss("out.println").except(STDOUT),
        xss("out.print").except(STDOUT),
    ],
    source_calls: &[
        "System.getenv", "System.getProperty", "*.getParameter", "*.getParameterValues", "*.getHeader",
        "*.getQueryString", "*.getCookies", "*.readLine", "*.nextLine", "*.getInputStream",
        // Kotlin
        "readLine", "readln", "readlnOrNull", "System.`in`.bufferedReader.readLine",
    ],
    source_paths: &[],
    env_sources: &["getenv", "getproperty"],
    sanitizers: &[
        "Integer.parseInt", "Long.parseLong", "Integer.valueOf", "Double.parseDouble",
        "Boolean.parseBoolean", "URLEncoder.encode", "*.escapeHtml4", "*.escapeHtml", "*.encodeForHTML",
        "FilenameUtils.getName", "Jsoup.clean", "HtmlUtils.htmlEscape",
    ],
};

static GO: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        cmd("exec.Command"),
        cmd("exec.CommandContext"),
        cmd("syscall.Exec").at(0),
        cmd("os.StartProcess").at(0),
        sql("*.Query"),
        sql("*.QueryRow"),
        sql("*.QueryContext"),
        sql("*.Exec").except(&["syscall.Exec", "unix.Exec"]),
        sql("*.ExecContext"),
        sql("*.Prepare"),
        path("os.Open"),
        path("os.OpenFile"),
        path("os.ReadFile"),
        path("os.WriteFile"),
        path("os.Remove"),
        path("os.RemoveAll"),
        path("os.Create"),
        path("os.MkdirAll"),
        path("ioutil.ReadFile"),
        path("ioutil.WriteFile"),
        path("filepath.Join"),
        ssrf("http.Get"),
        ssrf("http.Post"),
        ssrf("http.NewRequest").at(1),
        redirect("http.Redirect").at(2),
        xss("template.HTML"),
        weak_hash("md5.New"),
        weak_hash("md5.Sum"),
        weak_hash("sha1.New"),
        weak_hash("sha1.Sum"),
    ],
    source_calls: &[
        "os.Getenv", "os.LookupEnv", "*.FormValue", "*.PostFormValue", "URL.Query.Get", "Header.Get",
        "*.Cookie", "*.ReadString", "*.ReadLine", "flag.Arg",
    ],
    source_paths: &["os.Args", "URL.Path", "URL.RawQuery", "Form", "PostForm"],
    env_sources: &["getenv", "lookupenv"],
    sanitizers: &[
        "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool",
        "strconv.Quote", "filepath.Base", "path.Base", "html.EscapeString", "url.QueryEscape",
        "template.HTMLEscapeString", "shellescape.Quote",
    ],
};

static RUST: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        cmd("Command.new"),
        cmd("*.arg"),
        cmd("*.args"),
        sql("*.execute"),
        sql("*.query"),
        sql("*.query_row"),
        sql("*.prepare"),
        sql("sqlx.query"),
        path("File.open"),
        path("File.create"),
        path("fs.read"),
        path("fs.read_to_string"),
        path("fs.write"),
        path("fs.remove_file"),
        path("fs.remove_dir_all"),
        path("fs.create_dir_all"),
        ssrf("reqwest.get"),
        unsafe_fn("mem.transmute", "transmute bypasses the type system"),
        unsafe_fn("*.get_unchecked", "unchecked indexing can read out of bounds"),
        unsafe_fn("from_utf8_unchecked", "skips UTF-8 validation"),
        unsafe_fn("*.unwrap_unchecked", "undefined behavior if the value is absent"),
    ],
    source_calls: &[
        "env.args", "env.var", "env.args_os", "*.read_line", "*.read_to_string", "*.read_to_end",
    ],
    source_paths: &[],
    env_sources: &["env.var"],
    sanitizers: &["*.parse", "*.canonicalize", "html_escape.encode_text", "shell_escape.escape"],
};

static C_FAMILY: RuleSet = RuleSet {
    source_notes: &[],
    entries: &[],
    rules: &[
        always("gets", "unsafe-function", "CWE-242", High, "gets() cannot limit input size"),
        always("strcpy", "unsafe-function", "CWE-120", Medium, "unbounded copy (use strncpy/strlcpy)"),
        always("strcat", "unsafe-function", "CWE-120", Medium, "unbounded append (use strncat/strlcat)"),
        always("stpcpy", "unsafe-function", "CWE-120", Medium, "unbounded copy"),
        always("sprintf", "unsafe-function", "CWE-120", Medium, "unbounded formatting (use snprintf)"),
        always("vsprintf", "unsafe-function", "CWE-120", Medium, "unbounded formatting (use vsnprintf)"),
        cmd("system"),
        cmd("popen"),
        cmd("execl"),
        cmd("execlp"),
        cmd("execle"),
        cmd("execv"),
        cmd("execvp"),
        cmd("execve"),
        cmd("std.system"),
        format_string("printf", 0),
        format_string("fprintf", 1),
        format_string("snprintf", 2),
        format_string("syslog", 1),
        tainted("memcpy", "unsafe-function", "CWE-119", Medium, "copy size controlled by untrusted input").at(2),
        tainted("memmove", "unsafe-function", "CWE-119", Medium, "copy size controlled by untrusted input").at(2),
        tainted("malloc", "unsafe-function", "CWE-789", Medium, "allocation size controlled by untrusted input").at(0),
        path("fopen"),
        path("open"),
        path("unlink"),
        path("remove"),
        path("rename"),
        always("tmpnam", "insecure-temp-file", "CWE-377", Low, "predictable temporary file name"),
        always("tempnam", "insecure-temp-file", "CWE-377", Low, "predictable temporary file name"),
        always("mktemp", "insecure-temp-file", "CWE-377", Low, "predictable temporary file name"),
    ],
    source_calls: &[
        "getenv", "fgets", "gets", "scanf", "fscanf", "read", "recv", "recvfrom", "fread", "getchar",
        "getline", "readline", "std.getline",
    ],
    source_paths: &["argv"],
    env_sources: &["getenv"],
    sanitizers: &["atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtod", "strtoll", "basename"],
};
