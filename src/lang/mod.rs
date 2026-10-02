pub mod c;
pub mod common;
pub mod go;
pub mod java;
pub mod js;
pub mod python;
pub mod rust;

use crate::ir::Cfg;
use anyhow::Result;
use std::path::Path;

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
}

impl Language {
    /// Languages that can call / import each other's code (TypeScript with
    /// JavaScript, C with C++); everything else is a separate world.
    pub fn family(self) -> u8 {
        match self {
            Self::Python => 0,
            Self::JavaScript | Self::TypeScript | Self::Tsx => 1,
            Self::Rust => 2,
            Self::Go => 3,
            Self::Java => 4,
            Self::C | Self::Cpp => 5,
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
        }
    };
}

/// Parse `src` and lower every function to a CFG.
pub fn build_cfgs(lang: Language, src: &str) -> Result<Vec<Cfg>> {
    with_grammar!(lang, |spec, g| common::lower(spec, g, src))
}

/// Parse `src` and build its language-neutral AST (`file` is the id its nodes carry).
pub fn build_ast(lang: Language, file: u32, src: &str) -> Result<crate::cpg::ast::Ast> {
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
    with_grammar!(lang, |spec, g| common::parse_declarations(spec, g, src))
}

/// The imports / includes / `use`s of a file, as written in the source.
pub fn imports(lang: Language, src: &str) -> Result<Vec<common::Import>> {
    with_grammar!(lang, |spec, g| common::parse_imports(spec, g, src))
}
