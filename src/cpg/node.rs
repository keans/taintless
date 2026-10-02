//! Node identity and kinds of the code property graph.

/// What a node stands for, independent of the language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKind {
    File,
    /// A function, method, lambda or closure.
    Method,
    /// Where a method's control flow ends (one per method, synthetic).
    MethodReturn,
    Call,
    /// `target = value` and `target += value`.
    Assign,
    Identifier,
    Literal,
    /// `object.member`.
    FieldAccess,
    /// `left op right`; `name` is the operator, the children are the operands in order.
    BinaryOp,
    /// A formal parameter of a method; `name` is the (first) name it binds.
    Param,
    /// A class, struct, interface, enum or trait declaration; `name` is its name.
    TypeDecl,
    /// A variable a function declares or first assigns (synthetic, one per name and function;
    /// `name` is the variable, its position that of the first definition). The method contains it.
    Local,
    /// A field a class declares or assigns through its receiver (synthetic; `name` is the field).
    /// The class's `TypeDecl` contains it (the file of its first method when there is none).
    Field,
    /// A type named by a parameter or local declaration (synthetic, one per name and file;
    /// `name` is the type as written without generics). The file contains it.
    Type,
    Return,
    /// `if`, loops, `switch` / `match`, `try`, ...
    Control,
    /// Any other named syntax node (blocks, operators, types, ...).
    Other,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Method => "method",
            Self::MethodReturn => "method_return",
            Self::Call => "call",
            Self::Assign => "assign",
            Self::Identifier => "identifier",
            Self::Literal => "literal",
            Self::FieldAccess => "field_access",
            Self::BinaryOp => "binary_op",
            Self::Param => "param",
            Self::TypeDecl => "type_decl",
            Self::Local => "local",
            Self::Field => "field",
            Self::Type => "type",
            Self::Return => "return",
            Self::Control => "control",
            Self::Other => "other",
        }
    }
}

/// Identity of a syntax node that survives re-parsing an unchanged file and
/// does not depend on how many nodes were built before it: the file, the byte
/// range and the grammar's node kind. `(line, col)` is not enough, since a
/// statement and its first expression start at the same place.
///
/// Two distinct nodes with the same range and kind can exist (a parenthesized
/// expression chain in some grammars); [`Ast`](super::ast::Ast) keeps the
/// outermost one and numbers the rest through `depth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    pub file: u32,
    pub start: u32,
    pub end: u32,
    /// The grammar's numeric node kind (stable for one grammar version).
    pub kind: u16,
    /// Nesting depth among nodes with identical range and kind (normally 0).
    pub depth: u16,
}
