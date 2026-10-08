pub mod c;
pub mod common;
pub mod cpre;
pub mod csharp;
pub mod go;
pub mod java;
pub mod js;
pub mod php;
pub mod kotlin;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod swift;

use crate::ir::Cfg;
use anyhow::Result;
use std::path::Path;

/// The numbers of [`Language::family`], by name.
pub mod family {
    pub const PYTHON: u8 = 0;
    pub const JAVASCRIPT: u8 = 1;
    pub const RUST: u8 = 2;
    pub const GO: u8 = 3;
    pub const JAVA: u8 = 4;
    pub const C: u8 = 5;
    pub const CSHARP: u8 = 6;
    pub const RUBY: u8 = 7;
    pub const PHP: u8 = 8;
    pub const SWIFT: u8 = 9;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Rust,
    Go,
    Java,
    C,
    Cpp,
    CSharp,
    Kotlin,
    Ruby,
    Php,
    Swift,
}

impl Language {
    /// C++ rather than C (headers are sniffed by [`detect_with_source`](Self::detect_with_source)).
    pub fn is_cpp(self) -> bool {
        self == Self::Cpp
    }

    /// Does a literal's key `name` read as `.name` (JS, TS, Go) rather than `['name']`?
    pub fn dot_keys(self) -> bool {
        matches!(self, Self::JavaScript | Self::TypeScript | Self::Tsx | Self::Go)
    }

    /// Languages that can call / import each other's code (TypeScript with
    /// JavaScript, C with C++, Kotlin with Java); everything else is a separate world.
    pub fn family(self) -> u8 {
        match self {
            Self::Python => family::PYTHON,
            Self::JavaScript | Self::TypeScript | Self::Tsx => family::JAVASCRIPT,
            Self::Rust => family::RUST,
            Self::Go => family::GO,
            Self::Java | Self::Kotlin => family::JAVA,
            Self::C | Self::Cpp => family::C,
            Self::CSharp => family::CSHARP,
            Self::Ruby => family::RUBY,
            Self::Php => family::PHP,
            Self::Swift => family::SWIFT,
        }
    }

    /// Like [`detect`](Self::detect), but sniffs `.h` headers for C++ constructs.
    pub fn detect_with_source(path: &Path, src: &str) -> Option<Self> {
        let l = Self::detect(path)?;
        if l == Self::C && path.extension().is_some_and(|e| e == "h") && looks_like_cpp(src) {
            return Some(Self::Cpp);
        }
        Some(l)
    }

    /// A language (or file extension) name as written in a config file.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "python" | "py" => Self::Python,
            "javascript" | "js" => Self::JavaScript,
            "typescript" | "ts" => Self::TypeScript,
            "tsx" => Self::Tsx,
            "rust" | "rs" => Self::Rust,
            "go" => Self::Go,
            "java" => Self::Java,
            "c" => Self::C,
            "cpp" | "c++" => Self::Cpp,
            "csharp" | "c#" | "cs" => Self::CSharp,
            "kotlin" | "kt" => Self::Kotlin,
            "ruby" | "rb" => Self::Ruby,
            "php" => Self::Php,
            "swift" => Self::Swift,
            _ => return None,
        })
    }

    pub fn detect(path: &Path) -> Option<Self> {
        Some(match path.extension()?.to_str()? {
            "py" => Self::Python,
            "js" | "mjs" | "cjs" | "jsx" => Self::JavaScript,
            "ts" | "mts" | "cts" => Self::TypeScript,
            "tsx" => Self::Tsx,
            "rs" => Self::Rust,
            "go" => Self::Go,
            "java" => Self::Java,
            "c" | "h" => Self::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Self::Cpp,
            "cs" => Self::CSharp,
            "kt" | "kts" => Self::Kotlin,
            "rb" | "rake" | "gemspec" => Self::Ruby,
            "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" | "inc" => Self::Php,
            "swift" => Self::Swift,
            _ => return None,
        })
    }
}

/// Run `$body` once per language with that language's `$spec` and tree-sitter grammar `$g` bound.
macro_rules! with_grammar {
    ($lang:expr, |$spec:ident, $g:ident| $body:expr) => {
        match $lang {
            Language::Python => { let ($spec, $g) = (&python::Python, tree_sitter_python::LANGUAGE.into()); $body }
            Language::JavaScript => { let ($spec, $g) = (&js::Js, tree_sitter_javascript::LANGUAGE.into()); $body }
            Language::TypeScript => { let ($spec, $g) = (&js::Js, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()); $body }
            Language::Tsx => { let ($spec, $g) = (&js::Js, tree_sitter_typescript::LANGUAGE_TSX.into()); $body }
            Language::Rust => { let ($spec, $g) = (&rust::RustSpec, tree_sitter_rust::LANGUAGE.into()); $body }
            Language::Go => { let ($spec, $g) = (&go::Go, tree_sitter_go::LANGUAGE.into()); $body }
            Language::Java => { let ($spec, $g) = (&java::Java, tree_sitter_java::LANGUAGE.into()); $body }
            Language::C => { let ($spec, $g) = (&c::CLike, tree_sitter_c::LANGUAGE.into()); $body }
            Language::Cpp => { let ($spec, $g) = (&c::CLike, tree_sitter_cpp::LANGUAGE.into()); $body }
            Language::CSharp => { let ($spec, $g) = (&csharp::CSharp, tree_sitter_c_sharp::LANGUAGE.into()); $body }
            Language::Kotlin => { let ($spec, $g) = (&kotlin::Kotlin, tree_sitter_kotlin_ng::LANGUAGE.into()); $body }
            Language::Ruby => { let ($spec, $g) = (&ruby::Ruby, tree_sitter_ruby::LANGUAGE.into()); $body }
            Language::Php => { let ($spec, $g) = (&php::Php, tree_sitter_php::LANGUAGE_PHP.into()); $body }
            Language::Swift => { let ($spec, $g) = (&swift::Swift, tree_sitter_swift::LANGUAGE.into()); $body }
        }
    };
}

/// `src` with the macros of a C / C++ file resolved (see [`cpre`]); other languages are as written.
/// Text that the project-aware pass of the scanner already processed passes through.
fn resolved(lang: Language, src: &str) -> std::borrow::Cow<'_, str> {
    match lang {
        Language::C | Language::Cpp => cpre::preprocess_alone(lang.is_cpp(), src),
        _ => src.into(),
    }
}

/// Parse `src` and lower every function to a CFG.
pub fn build_cfgs(lang: Language, src: &str) -> Result<Vec<Cfg>> {
    let src = &*resolved(lang, src);
    let mut cfgs = with_grammar!(lang, |spec, g| common::lower(spec, g, src))?;
    let source: std::sync::Arc<str> = src.into();
    for cfg in &mut cfgs {
        cfg.source = source.clone();
    }
    Ok(cfgs)
}

/// Parse `src` and build its language-neutral AST (`file` is the id its nodes carry).
pub fn build_ast(lang: Language, file: u32, src: &str) -> Result<crate::cpg::ast::Ast> {
    let src = &*resolved(lang, src);
    with_grammar!(lang, |spec, g| crate::cpg::ast::build(spec, g, file, src))
}

fn looks_like_cpp(src: &str) -> bool {
    const MARKERS: &[&str] = &[
        "namespace ", "template<", "template <", "class ", "public:", "private:", "protected:",
        "std::", "#include <iostream>", "#include <vector>", "#include <string>", "nullptr", "constexpr",
    ];
    MARKERS.iter().any(|m| src.contains(m))
}

/// The struct / class definitions and type aliases of a file, as written in the source.
pub fn declarations(lang: Language, src: &str) -> Result<common::Declarations> {
    let src = &*resolved(lang, src);
    with_grammar!(lang, |spec, g| common::parse_declarations(spec, g, src))
}

/// The imports / includes / `use`s of a file, as written in the source.
pub fn imports(lang: Language, src: &str) -> Result<Vec<common::Import>> {
    let src = &*resolved(lang, src);
    with_grammar!(lang, |spec, g| common::parse_imports(spec, g, src))
}
