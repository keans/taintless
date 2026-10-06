//! The name tables behind `taintless crypto`: libraries, crypto calls, secret-bearing arguments,
//! minimum work factors and non-cryptographic random generators. The built-in ones are in
//! `tables.toml`; a `.taintless.toml` adds entries of the same shape under `[crypto]`, which are
//! matched before the built-in ones.

use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Python,
    Javascript,
    Rust,
    Go,
    Java,
    C,
    Csharp,
    Ruby,
    Php,
    Swift,
}

impl Lang {
    /// The [`crate::lang::Language::family`] number of the language.
    pub fn family(self) -> u8 {
        match self {
            Self::Python => 0,
            Self::Javascript => 1,
            Self::Rust => 2,
            Self::Go => 3,
            Self::Java => 4,
            Self::C => 5,
            Self::Csharp => 6,
            Self::Ruby => 7,
            Self::Php => 8,
            Self::Swift => 9,
        }
    }
}

/// An imported module (prefix) and the library it belongs to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    pub lang: Lang,
    pub module: String,
    pub name: String,
    /// The name the call patterns use for the module (`CryptoJS` for `crypto-js`): whatever a file
    /// calls its default import (`import CJ from 'crypto-js'`), its calls are matched under this.
    pub alias: Option<String>,
}

/// A crypto call: `name`, `a.b`, `*.method` or `PREFIX_*`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub lang: Lang,
    pub pattern: String,
    pub primitive: String,
    pub algorithm: String,
    /// A broken or deprecated algorithm.
    #[serde(default)]
    pub weak: bool,
    /// Counts only in files that import this library.
    pub library: Option<String>,
}

/// A manifest dependency name that differs from the module it provides (`*` suffix: any prefix).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub lang: Lang,
    pub name: String,
    pub library: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretArg {
    pub index: usize,
    /// `key`, `iv`, `salt` or `secret`.
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    pub lang: Lang,
    pub pattern: String,
    pub args: Vec<SecretArg>,
}

/// An argument that names the algorithm (`Cipher.getInstance(name)`): untrusted data there is a
/// taint finding.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmArg {
    pub lang: Lang,
    pub pattern: String,
    /// The position of the argument (0-based) ...
    pub index: Option<usize>,
    /// ... and/or the keywords it can be passed by (`hashlib.new(name=x)`).
    #[serde(default)]
    pub keywords: Vec<String>,
}

/// A numeric argument with a recommended minimum (iterations, cost).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub lang: Lang,
    pub pattern: String,
    /// The position of the argument (0-based) ...
    pub index: Option<usize>,
    /// ... and/or the keywords it can be passed by (`PasswordHasher(memory_cost=..)`).
    #[serde(default)]
    pub keywords: Vec<String>,
    pub what: String,
    pub min: u64,
}

/// A non-cryptographic random generator.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prng {
    pub lang: Lang,
    pub pattern: String,
    /// Counts only when the file imports this module (Go's `math/rand` shares its package name
    /// with `crypto/rand`) ...
    pub with_import: Option<String>,
    /// ... and not this one.
    pub without_import: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tables {
    #[serde(default)]
    pub library: Vec<Library>,
    #[serde(default)]
    pub call: Vec<Call>,
    #[serde(default)]
    pub dependency: Vec<Dependency>,
    #[serde(default)]
    pub secret: Vec<Secret>,
    #[serde(default)]
    pub algorithm: Vec<AlgorithmArg>,
    #[serde(default)]
    pub limit: Vec<Limit>,
    #[serde(default)]
    pub prng: Vec<Prng>,
    /// Prefixes of algorithm constants that carry no meaning themselves (`kCCAlgorithm` in
    /// `kCCAlgorithmDES`).
    #[serde(default)]
    pub constant_prefix: Vec<String>,
    /// Literals of a signature's algorithm argument that mean "unsigned" (`none` in a JWT).
    #[serde(default)]
    pub unsigned_literal: Vec<String>,
}

impl Tables {
    /// These entries first, then `base`'s.
    pub fn on_top_of(mut self, base: Tables) -> Tables {
        self.library.extend(base.library);
        self.call.extend(base.call);
        self.dependency.extend(base.dependency);
        self.secret.extend(base.secret);
        self.algorithm.extend(base.algorithm);
        self.limit.extend(base.limit);
        self.prng.extend(base.prng);
        self.constant_prefix.extend(base.constant_prefix);
        self.unsigned_literal.extend(base.unsigned_literal);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.library.is_empty() && self.call.is_empty() && self.dependency.is_empty() && self.secret.is_empty() && self.algorithm.is_empty() && self.limit.is_empty() && self.prng.is_empty() && self.constant_prefix.is_empty() && self.unsigned_literal.is_empty()
    }
}

static ACTIVE: OnceLock<Tables> = OnceLock::new();

/// The tables shipped with taintless.
pub fn builtin() -> Tables {
    toml::from_str(include_str!("tables.toml")).expect("the built-in crypto tables parse")
}

/// The tables in use: the built-in ones, plus what [`install`] added.
pub fn active() -> &'static Tables {
    ACTIVE.get_or_init(builtin)
}

/// Add configured entries (matched before the built-in ones). Fails when the tables are already in use.
pub fn install(extra: Tables) -> Result<(), &'static str> {
    ACTIVE.set(extra.on_top_of(builtin())).map_err(|_| "the crypto tables are already in use")
}
