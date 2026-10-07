use taintless::lang::{self, Language};

#[test]
fn unnamed_enum_with_underlying_type_is_valid() {
    let source = "enum : unsigned long long { flag = 1ull << 63 };\nint f() { return flag != 0; }";
    let cfgs = lang::build_cfgs(Language::Cpp, source).unwrap();
    assert_eq!(cfgs.len(), 1);
    assert_eq!(cfgs[0].name, "f");
    lang::build_ast(Language::Cpp, 0, source).unwrap();
    lang::imports(Language::Cpp, source).unwrap();
}

#[test]
fn invalid_enum_definitions_still_fail() {
    for source in [
        "enum class : unsigned { flag = 1 };",
        "enum : unsigned { flag = };",
        "enum : { flag = 1 };",
    ] {
        assert!(lang::build_cfgs(Language::Cpp, source).is_err(), "{source}");
        assert!(lang::build_ast(Language::Cpp, 0, source).is_err(), "{source}");
        assert!(lang::imports(Language::Cpp, source).is_err(), "{source}");
    }
}

#[test]
fn dependent_constructor_calls_keep_calls_and_source_positions() {
    let source = "template<class T> void f() {\n  sink(typename T::value_type(), input());\n}\n";
    let cfgs = lang::build_cfgs(Language::Cpp, source).unwrap();
    assert_eq!(cfgs.len(), 1);
    assert_eq!(cfgs[0].source.as_ref(), source);
    let calls: Vec<_> = cfgs[0].graph.node_weights()
        .flat_map(|b| &b.stmts).flat_map(|s| &s.calls).collect();
    for callee in ["sink", "T.value_type", "input"] {
        let call = calls.iter().find(|c| c.callee == callee).unwrap_or_else(|| {
            panic!("missing {callee}: {calls:?}")
        });
        assert_eq!(call.line, 2);
    }
    let ast = lang::build_ast(Language::Cpp, 0, source).unwrap();
    for statement in cfgs[0].graph.node_weights().flat_map(|b| &b.stmts) {
        if statement.span != (0, 0) {
            assert!(ast.find(statement.span, statement.node_kind).is_some());
        }
    }
    lang::imports(Language::Cpp, source).unwrap();
}

#[test]
fn incomplete_constructor_calls_still_fail() {
    for source in [
        "template<class T> void f() { sink(typename T::type(, 0)); }",
        "template<class T> void f() { sink(typename T::type(), 0) }",
        "void f() { sink(typename int(), 0); }",
    ] {
        assert!(lang::build_cfgs(Language::Cpp, source).is_err(), "{source}");
        assert!(lang::build_ast(Language::Cpp, 0, source).is_err(), "{source}");
        assert!(lang::imports(Language::Cpp, source).is_err(), "{source}");
    }
}

#[test]
fn dependent_constructor_on_template_type() {
    let source = "template<class Context> void f() { sink(typename basic_format_arg<Context>::handle(arg)); }";
    let cfgs = lang::build_cfgs(Language::Cpp, source).unwrap();
    assert_eq!(cfgs.len(), 1);
    assert_eq!(cfgs[0].name, "f");
    lang::build_ast(Language::Cpp, 0, source).unwrap();
    lang::imports(Language::Cpp, source).unwrap();
}

#[test]
fn single_function_lowering_rejects_incomplete_nodes() {
    let source: std::sync::Arc<str> = "void broken() { int x = 1 }".into();
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_cpp::LANGUAGE.into()).unwrap();
    let tree = parser.parse(source.as_bytes(), None).unwrap();
    let function = tree.root_node().named_child(0).unwrap();
    assert_eq!(function.kind(), "function_definition");
    assert!(lang::common::lower_function(&lang::c::CLike, source, function).is_err());
}
