use std::collections::HashSet;
use std::path::{Path, PathBuf};
use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
use taintless::cpg::node::NodeKind;
use taintless::lang::{Language, build_ast, build_cfgs};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn sources() -> Vec<(PathBuf, Language, String)> {
    let mut all = vec![];
    files(Path::new("tests"), &mut all);
    all.sort();
    all.into_iter()
        .filter_map(|p| {
            let src = std::fs::read_to_string(&p).ok()?;
            let lang = Language::detect_with_source(&p, &src)?;
            // files with syntax errors (GNU `case 1 ... 5:`) are rejected by the lowering: not part of the corpus here
            build_cfgs(lang, &src).ok()?;
            Some((p, lang, src))
        })
        .collect()
}

#[test]
fn node_ids_are_unique_and_parents_come_first() {
    for (path, lang, src) in sources() {
        let ast = build_ast(lang, 0, &src).unwrap();
        let ids: HashSet<_> = ast.nodes.iter().map(|n| n.id).collect();
        assert_eq!(
            ids.len(),
            ast.nodes.len(),
            "duplicate ids in {}",
            path.display()
        );
        assert_eq!(ast.root().kind, NodeKind::File);
        for (i, n) in ast.nodes.iter().enumerate() {
            if let Some(p) = n.parent {
                assert!(p < i, "{}: parent after child", path.display());
                assert_eq!(ast.nodes[p].children[n.order as usize], i);
            }
        }
    }
}

#[test]
fn ids_do_not_depend_on_other_files() {
    let (_, lang, src) = sources()
        .into_iter()
        .find(|(p, ..)| p.ends_with("vuln/app.py"))
        .unwrap();
    let a = build_ast(lang, 3, &src).unwrap();
    let b = build_ast(lang, 3, &src).unwrap();
    let ids = |x: &taintless::cpg::ast::Ast| x.nodes.iter().map(|n| n.id).collect::<Vec<_>>();
    assert_eq!(ids(&a), ids(&b));
    assert!(a.nodes.iter().all(|n| n.id.file == 3));
}

/// Every function of the CFG layer is a `Method` of the AST, and every
/// statement points at an AST node with the same source range.
#[test]
fn cfg_spans_resolve_to_ast_nodes() {
    let mut stmts = 0;
    for (path, lang, src) in sources() {
        let ast = build_ast(lang, 0, &src).unwrap();
        for cfg in build_cfgs(lang, &src).unwrap() {
            if cfg.name != "<module>" {
                let i = ast
                    .find(cfg.span, cfg.node_kind)
                    .unwrap_or_else(|| panic!("{}: no AST node for {}", path.display(), cfg.name));
                assert_eq!(
                    ast.nodes[i].kind,
                    NodeKind::Method,
                    "{}: {}",
                    path.display(),
                    cfg.name
                );
            }
            for st in cfg.graph.node_weights().flat_map(|b| &b.stmts) {
                if st.span == (0, 0) {
                    continue;
                }
                stmts += 1;
                let i = ast.find(st.span, st.node_kind).unwrap_or_else(|| {
                    panic!(
                        "{}:{}: no AST node for `{}`",
                        path.display(),
                        st.line,
                        st.text
                    )
                });
                assert_eq!(
                    ast.nodes[i].line,
                    st.line,
                    "{}:{} `{}`",
                    path.display(),
                    st.line,
                    st.text
                );
            }
        }
    }
    assert!(stmts > 500, "only {stmts} statements checked");
}

#[test]
fn python_nodes_are_classified() {
    let src = "import os\n\ndef f(a):\n    x = os.path.join(a, 'b')\n    if x:\n        return os.system(x)\n";
    let ast = build_ast(Language::Python, 0, src).unwrap();
    let names = |k| {
        ast.of_kind(k)
            .filter_map(|n| n.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(NodeKind::Method), ["f"]);
    assert_eq!(names(NodeKind::Call), ["os.path.join", "os.system"]);
    assert_eq!(ast.of_kind(NodeKind::Assign).count(), 1);
    assert_eq!(ast.of_kind(NodeKind::Control).count(), 1);
    assert_eq!(ast.of_kind(NodeKind::Return).count(), 1);
    assert_eq!(ast.of_kind(NodeKind::Literal).count(), 1);
    assert!(names(NodeKind::Identifier).contains(&"x".to_string()));
    assert!(names(NodeKind::FieldAccess).contains(&"path".to_string()));
}

/// `controller -kind-> dependent` as "line:text" strings, for the first function of `src`.
fn cdg(lang: Language, src: &str) -> Vec<String> {
    use taintless::cpg::{cdg::control_dependence, cfg::stmt_graph};
    let cfg = build_cfgs(lang, src).unwrap().remove(0);
    let g = stmt_graph(&cfg);
    let name = |n| {
        g.stmt(&cfg, n).map_or(format!("{:?}", g.graph[n]), |s| {
            format!("{}:{}", s.line, s.text)
        })
    };
    control_dependence(&g)
        .into_iter()
        .map(|(a, d, k)| format!("{} -{}-> {}", name(a), k.as_str(), name(d)))
        .collect()
}

#[test]
fn control_dependence_of_branches_and_loops() {
    let src = "def f(a):\n    x = 1\n    if a:\n        y = 2\n    else:\n        y = 3\n    z = y\n    while z:\n        z = z - 1\n    return z\n";
    let mut got = cdg(Language::Python, src);
    got.sort();
    assert_eq!(
        got,
        [
            "3:a -false-> 6:y = 3",
            "3:a -true-> 4:y = 2",
            "8:z -true-> 8:z",
            "8:z -true-> 9:z = z - 1",
            "Entry -normal-> 10:return z",
            "Entry -normal-> 2:x = 1",
            "Entry -normal-> 3:a",
            "Entry -normal-> 7:z = y",
        ]
    );
}

#[test]
fn early_return_controls_the_rest() {
    let src = "def f(a):\n    if a:\n        return 1\n    x = 2\n    return x\n";
    let got = cdg(Language::Python, src);
    assert!(got.contains(&"2:a -false-> 4:x = 2".to_string()), "{got:?}");
    assert!(
        got.contains(&"2:a -false-> 5:return x".to_string()),
        "{got:?}"
    );
    assert!(
        got.contains(&"2:a -true-> 3:return 1".to_string()),
        "{got:?}"
    );
}

#[test]
fn statements_are_chained_inside_blocks() {
    use taintless::cpg::cfg::{SNode, stmt_graph};
    for (path, lang, src) in sources() {
        for cfg in build_cfgs(lang, &src).unwrap() {
            let g = stmt_graph(&cfg);
            let stmts = cfg
                .graph
                .node_weights()
                .map(|b| b.stmts.len())
                .sum::<usize>();
            let nodes = g
                .graph
                .node_weights()
                .filter(|n| matches!(n, SNode::Stmt { .. }))
                .count();
            assert_eq!(stmts, nodes, "{}: {}", path.display(), cfg.name);
            assert_eq!(
                g.graph
                    .edges_directed(g.entry, petgraph::Direction::Incoming)
                    .count(),
                0
            );
            // Every reachable statement has at least one controller.
            let deps = taintless::cpg::cdg::control_dependence(&g);
            assert!(
                deps.iter().all(|&(a, d, _)| a != g.exit && d != g.entry),
                "{}: {}",
                path.display(),
                cfg.name
            );
        }
    }
}

mod unified {
    use super::*;
    use std::collections::BTreeSet;
    use taintless::analysis::{callgraph, deps};
    use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
    use taintless::ir::Cfg;
    use taintless::lang::common::Import;
    use taintless::lang::imports;

    type Loaded = Vec<(PathBuf, Language, String, Vec<Cfg>, Vec<Import>)>;

    fn load(dir: &str) -> Loaded {
        let mut all = vec![];
        files(Path::new(dir), &mut all);
        all.sort();
        all.into_iter()
            .filter_map(|p| {
                let src = std::fs::read_to_string(&p).ok()?;
                let lang = Language::detect_with_source(&p, &src)?;
                let cfgs = build_cfgs(lang, &src).ok()?;
                let imps = imports(lang, &src).unwrap_or_default();
                Some((p, lang, src, cfgs, imps))
            })
            .collect()
    }

    fn cpg_of(l: &Loaded) -> Cpg {
        let fs: Vec<SourceFile> = l
            .iter()
            .map(|(p, lang, src, cfgs, imps)| SourceFile {
                path: p,
                lang: *lang,
                src,
                cfgs,
                imports: imps,
            })
            .collect();
        Cpg::build(&fs).unwrap()
    }

    fn count(c: &Cpg, k: EdgeKind) -> usize {
        c.graph.edge_weights().filter(|e| e.kind == k).count()
    }

    #[test]
    fn ast_edges_and_methods() {
        let l = load("tests");
        let c = cpg_of(&l);
        let ast_nodes: usize = c.files.iter().map(|f| f.ast.nodes.len()).sum();
        assert_eq!(count(&c, EdgeKind::Ast), ast_nodes - c.files.len());
        assert_eq!(c.methods.len(), l.iter().map(|f| f.3.len()).sum::<usize>());
        // every function has a method node that starts a control flow
        for &m in &c.methods {
            assert!(
                c.out(m, EdgeKind::Cfg).next().is_some()
                    || c.out(m, EdgeKind::Contains).next().is_some()
            );
        }
        assert!(count(&c, EdgeKind::Cfg) > 500 && count(&c, EdgeKind::Cdg) > 500);
    }

    /// `call_graph()` and `dep_graph()` are what the standalone builders return: the CPG
    /// resolves imports and calls once and draws its edges from the same pass.
    #[test]
    fn views_equal_the_standalone_builders() {
        for dir in [
            "tests/callgraph",
            "tests/interproc",
            "tests/deps",
            "tests/manifests",
            "tests/workspaces",
            "tests/imports",
            "tests/hier",
            "tests",
        ] {
            let l = load(dir);
            let c = cpg_of(&l);
            // dependencies: edges with their imports, call counts and examples, and the externals
            let dep_files: Vec<deps::DepFile> = l
                .iter()
                .map(|f| deps::DepFile {
                    path: &f.0,
                    lang: f.1,
                    imports: f.4.clone(),
                    cfgs: &f.3,
                })
                .collect();
            let dg = deps::build(&dep_files);
            let edges = |g: &deps::DepGraph| -> BTreeSet<String> {
                g.graph
                    .edge_indices()
                    .map(|e| {
                        let (a, b) = g.graph.edge_endpoints(e).unwrap();
                        let w = &g.graph[e];
                        format!(
                            "{} -> {} {:?} {} {:?}",
                            a.index(),
                            b.index(),
                            w.imports,
                            w.calls,
                            w.examples
                        )
                    })
                    .collect()
            };
            assert_eq!(edges(c.dep_graph()), edges(&dg), "{dir}: deps");
            assert_eq!(
                c.dep_graph().external,
                dg.external,
                "{dir}: external modules"
            );
            // calls: the same edges with the same call sites; when no file imports anything the
            // call graph is built without visibility, as before
            let refs: Vec<(&Path, Language, &[Cfg])> = l
                .iter()
                .map(|f| (f.0.as_path(), f.1, f.3.as_slice()))
                .collect();
            let visible = (!l.iter().all(|f| f.4.is_empty())).then(|| deps::visibility(&dep_files));
            let cg = callgraph::build_refs(&refs, visible);
            let calls = |g: &callgraph::CallGraph| -> BTreeSet<String> {
                g.graph
                    .edge_indices()
                    .map(|e| {
                        let (a, b) = g.graph.edge_endpoints(e).unwrap();
                        let w = &g.graph[e];
                        format!(
                            "{} -> {} {:?} {:?}",
                            a.index(),
                            b.index(),
                            w.lines,
                            w.callback_lines
                        )
                    })
                    .collect()
            };
            assert_eq!(calls(c.call_graph()), calls(&cg), "{dir}: calls");
            let mut ext: Vec<_> = c.call_graph().external.iter().collect();
            let mut want: Vec<_> = cg.external.iter().collect();
            ext.sort();
            want.sort();
            assert_eq!(ext, want, "{dir}: external calls");
        }
    }

    /// The call edges of the CPG, seen at function level, are the call graph.
    #[test]
    fn call_edges_match_the_call_graph() {
        for dir in [
            "tests/callgraph",
            "tests/interproc",
            "tests/fields",
            "tests/types",
            "tests",
        ] {
            let l = load(dir);
            let c = cpg_of(&l);
            let refs: Vec<(&Path, Language, &[Cfg])> = l
                .iter()
                .map(|f| (f.0.as_path(), f.1, f.3.as_slice()))
                .collect();
            let dep_files: Vec<deps::DepFile> = l
                .iter()
                .map(|f| deps::DepFile {
                    path: &f.0,
                    lang: f.1,
                    imports: f.4.clone(),
                    cfgs: &f.3,
                })
                .collect();
            let visible = (!l.iter().all(|f| f.4.is_empty())).then(|| deps::visibility(&dep_files));
            let cg = callgraph::build_refs(&refs, visible);
            let want: BTreeSet<(usize, usize)> = cg
                .graph
                .edge_indices()
                .map(|e| {
                    let (a, b) = cg.graph.edge_endpoints(e).unwrap();
                    (a.index(), b.index())
                })
                .collect();
            let at = |n| {
                c.methods
                    .iter()
                    .position(|&m| m == n)
                    .unwrap_or_else(|| panic!("no function for {:?}", c.graph[n]))
            };
            let got: BTreeSet<(usize, usize)> = c
                .graph
                .edge_indices()
                // calls through a parameter (label `param`) are resolved from the callers, not in the call graph
                .filter(|&e| c.graph[e].kind == EdgeKind::Call && c.graph[e].label != Some("param"))
                .map(|e| {
                    let (from, to) = c.graph.edge_endpoints(e).unwrap();
                    assert_eq!(c.graph[from].kind, NodeKind::Call);
                    (at(c.enclosing_method(from)), at(to))
                })
                .collect();
            assert_eq!(got, want, "{dir}");
            assert!(dir != "tests/callgraph" || !got.is_empty());
        }
    }

    #[test]
    fn import_edges_match_deps() {
        let l = load("tests/imports");
        let c = cpg_of(&l);
        let dep_files: Vec<deps::DepFile> = l
            .iter()
            .map(|f| deps::DepFile {
                path: &f.0,
                lang: f.1,
                imports: f.4.clone(),
                cfgs: &f.3,
            })
            .collect();
        let dg = deps::build(&dep_files);
        let want = dg
            .graph
            .edge_indices()
            .filter(|&e| !dg.graph[e].imports.is_empty())
            .count();
        assert!(want > 0);
        assert_eq!(count(&c, EdgeKind::Imports), want);
    }

    /// The scanner's own sources: a larger Rust corpus must build without a panic, and stay sane.
    #[test]
    fn builds_on_own_sources() {
        let l = load("src");
        let c = cpg_of(&l);
        assert!(c.graph.node_count() > 20_000, "{}", c.graph.node_count());
        for n in c.graph.node_indices() {
            c.enclosing_method(n);
        }
        assert!(count(&c, EdgeKind::Call) > 300);
    }
}

mod calls {
    use super::*;
    use petgraph::visit::{EdgeRef, IntoEdgeReferences};
    use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};

    fn cpg(lang: Language, src: &str) -> Cpg {
        let cfgs = build_cfgs(lang, src).unwrap();
        let f = [SourceFile {
            path: Path::new("t"),
            lang,
            src,
            cfgs: &cfgs,
            imports: &[],
        }];
        Cpg::build(&f).unwrap()
    }

    /// Arguments of the call named `callee`, in order, as source text; plus its receiver.
    fn args_of(c: &Cpg, callee: &str) -> (Vec<String>, Option<String>) {
        let call = c
            .graph
            .node_indices()
            .find(|&n| {
                c.graph[n].kind == NodeKind::Call && c.graph[n].name.as_deref() == Some(callee)
            })
            .unwrap();
        let mut a: Vec<_> = c
            .graph
            .edges(call)
            .filter(|e| e.weight().kind == EdgeKind::Argument)
            .map(|e| (e.weight().order, c.graph[e.target()].code.clone()))
            .collect();
        a.sort();
        let r = c
            .out(call, EdgeKind::Receiver)
            .next()
            .map(|n| c.graph[n].code.clone());
        (a.into_iter().map(|x| x.1).collect(), r)
    }

    #[test]
    fn arguments_and_receivers() {
        let c = cpg(
            Language::Python,
            "def f(a, b):\n    cur.execute(a, b + 1)\n    run(x=a)\n",
        );
        assert_eq!(
            args_of(&c, "cur.execute"),
            (vec!["a".into(), "b + 1".into()], Some("cur".into()))
        );
        assert_eq!(args_of(&c, "run"), (vec!["a".into()], None));
        let c = cpg(Language::JavaScript, "function f(a) { db.query(a, 2); }");
        assert_eq!(
            args_of(&c, "db.query"),
            (vec!["a".into(), "2".into()], Some("db".into()))
        );
    }

    #[test]
    fn every_argument_belongs_to_its_call() {
        for (_, lang, src) in sources() {
            let c = cpg(lang, &src);
            for e in (&c.graph)
                .edge_references()
                .filter(|e| matches!(e.weight().kind, EdgeKind::Argument | EdgeKind::Receiver))
            {
                assert_eq!(c.graph[e.source()].kind, NodeKind::Call);
                // the argument sits inside the call's source range
                let (a, b) = (
                    c.graph[e.source()].id.unwrap(),
                    c.graph[e.target()].id.unwrap(),
                );
                assert!(
                    a.start <= b.start && b.end <= a.end,
                    "{:?} -> {:?}",
                    c.graph[e.source()].code,
                    c.graph[e.target()].code
                );
            }
        }
    }
}

mod reaching {
    use super::*;
    use taintless::cpg::{cfg::stmt_graph, ddg::reaching_definitions};

    /// `def -var-> use` as "line:text" strings, sorted, for the first function of `src`.
    fn reaching(src: &str) -> Vec<String> {
        let cfg = build_cfgs(Language::Python, src).unwrap().remove(0);
        let g = stmt_graph(&cfg);
        let name = |n| {
            g.stmt(&cfg, n)
                .map_or("Entry".to_string(), |s| format!("{}:{}", s.line, s.text))
        };
        let mut v: Vec<String> = reaching_definitions(&cfg, &g)
            .into_iter()
            .map(|(d, u, var)| format!("{} -{var}-> {}", name(d), name(u)))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn branches_merge_definitions() {
        let got =
            reaching("def f(a):\n    x = a\n    if a:\n        x = 1\n    y = x\n    return y\n");
        assert_eq!(
            got,
            [
                "2:x = a -x-> 5:y = x",
                "4:x = 1 -x-> 5:y = x",
                "5:y = x -y-> 6:return y",
                "Entry -a-> 2:x = a",
                "Entry -a-> 3:a",
            ]
        );
    }

    #[test]
    fn a_new_assignment_kills_the_old_one() {
        let got = reaching("def f():\n    x = 1\n    x = 2\n    return x\n");
        assert_eq!(got, ["3:x = 2 -x-> 4:return x"]);
    }

    #[test]
    fn loops_carry_definitions_around() {
        let got =
            reaching("def f(n):\n    i = 0\n    while i < n:\n        i = i + 1\n    return i\n");
        assert!(
            got.contains(&"4:i = i + 1 -i-> 4:i = i + 1".to_string()),
            "{got:?}"
        );
        assert!(
            got.contains(&"4:i = i + 1 -i-> 3:i < n".to_string()),
            "{got:?}"
        );
        assert!(got.contains(&"2:i = 0 -i-> 3:i < n".to_string()), "{got:?}");
        assert!(
            got.contains(&"4:i = i + 1 -i-> 5:return i".to_string()),
            "{got:?}"
        );
    }

    #[test]
    fn fields_and_mutators() {
        let got = reaching(
            "def f(v):\n    o = make()\n    o.a = v\n    xs = []\n    xs.append(v)\n    use(o.a, xs)\n",
        );
        // o.a reads the field write, which shadows `o = make()`; the append is a definition of xs
        assert!(
            got.contains(&"3:o.a = v -o.a-> 6:use(o.a, xs)".to_string()),
            "{got:?}"
        );
        assert!(
            got.contains(&"5:xs.append(v) -xs-> 6:use(o.a, xs)".to_string()),
            "{got:?}"
        );
        assert!(
            got.contains(&"4:xs = [] -xs-> 5:xs.append(v)".to_string()),
            "{got:?}"
        );
        assert!(
            !got.iter().any(|e| e.starts_with("2:o = make()")),
            "{got:?}"
        );
    }

    #[test]
    fn reaching_edges_are_in_the_cpg() {
        use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
        let src = "def f(a):\n    x = a\n    return x\n";
        let cfgs = build_cfgs(Language::Python, src).unwrap();
        let f = [SourceFile {
            path: Path::new("t"),
            lang: Language::Python,
            src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let c = Cpg::build(&f).unwrap();
        let mut e: Vec<_> = c
            .graph
            .edge_weights()
            .filter(|e| e.kind == EdgeKind::Reaching && e.label.is_none())
            .filter_map(|e| e.var.clone())
            .collect();
        e.sort();
        assert_eq!(e, ["a", "x"]);
    }
}

mod export {
    use super::*;
    use taintless::cpg::graph::{Cpg, EdgeKind, SourceFile};
    use taintless::export::cpg::{select, to_dot, to_graphml, to_json};

    fn cpg(src: &str) -> Cpg {
        let cfgs = build_cfgs(Language::Python, src).unwrap();
        let f = [SourceFile {
            path: Path::new("t.py"),
            lang: Language::Python,
            src,
            cfgs: &cfgs,
            imports: &[],
        }];
        Cpg::build(&f).unwrap()
    }

    const SRC: &str = "def f(a):\n    x = g(a)\n    return x\n\ndef g(b):\n    return b & 1\n";

    #[test]
    fn json_lists_selected_edges_and_their_nodes() {
        let c = cpg(SRC);
        let sel = select(&c, &[EdgeKind::Call], None);
        let v = to_json(&c, &sel);
        let edges = v["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["kind"], "call");
        let nodes = v["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        let kinds: Vec<_> = nodes.iter().map(|n| n["kind"].as_str().unwrap()).collect();
        assert!(
            kinds.contains(&"call") && kinds.contains(&"method"),
            "{kinds:?}"
        );
        // every edge endpoint is a listed node
        let ids: HashSet<_> = nodes.iter().map(|n| n["id"].as_u64().unwrap()).collect();
        assert!(
            edges
                .iter()
                .all(|e| ids.contains(&e["from"].as_u64().unwrap())
                    && ids.contains(&e["to"].as_u64().unwrap()))
        );
        assert_eq!(v["files"][0]["path"], "t.py");
    }

    #[test]
    fn function_filter_keeps_only_that_function() {
        let c = cpg(SRC);
        let sel = select(&c, &[EdgeKind::Reaching], Some("g"));
        let v = to_json(&c, &sel);
        let vars: Vec<_> = v["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["var"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(vars, ["b"]);
        assert!(select(&c, &[], Some("nonexistent")).edges.is_empty());
    }

    #[test]
    fn graphml_and_dot_agree_with_json() {
        let c = cpg("def f(a):\n    return a < 1 and 'x&y'\n");
        let sel = select(&c, &[], None);
        let g = to_graphml(&c, &sel);
        assert_eq!(g.matches("<node ").count(), sel.nodes.len());
        assert_eq!(g.matches("<edge ").count(), sel.edges.len());
        assert!(
            g.contains("&lt;") && g.contains("&amp;"),
            "special characters must be escaped"
        );
        let d = to_dot(&c, &sel);
        assert_eq!(d.matches(" -> ").count(), sel.edges.len());
    }

    #[test]
    fn edge_kind_names_round_trip() {
        for k in EdgeKind::ALL {
            assert_eq!(EdgeKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(EdgeKind::parse("nope"), None);
    }
}

mod taint_parity {
    use super::*;
    use std::collections::BTreeSet;
    use taintless::analysis::check_file;
    use taintless::cpg::graph::{Cpg, SourceFile};
    use taintless::cpg::taint::taint_flows;

    /// `(rule, line)` found by the existing analysis and by the CPG query, for one file.
    type Found = BTreeSet<(String, usize)>;

    fn both(path: &str) -> (Found, Found) {
        let src = std::fs::read_to_string(path).unwrap();
        let lang = Language::detect_with_source(Path::new(path), &src).unwrap();
        // linked, as the command line does: Go interfaces know their method sets
        let cfgs = taintless::analysis::link::analyze_sources(&[(Path::new(path), &src)])
            .remove(0)
            .unwrap()
            .cfgs;
        let old = check_file(lang, Path::new(path), &cfgs)
            .into_iter()
            .filter(|f| f.origin.is_some())
            .map(|f| (f.rule.to_string(), f.line))
            .collect();
        let f = [SourceFile {
            path: Path::new(path),
            lang,
            src: &src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let cpg = Cpg::build(&f).unwrap();
        let new = taint_flows(&cpg)
            .into_iter()
            .map(|t| (t.rule.to_string(), t.line))
            .collect();
        (old, new)
    }

    fn fixtures() -> Vec<String> {
        let mut all = vec![];
        files(Path::new("tests"), &mut all);
        all.sort();
        all.into_iter()
            // interface dispatch for the single-file analysis is still being built (`tests/iface`)
            .filter(|p| !p.starts_with("tests/iface"))
            .filter_map(|p| {
                let src = std::fs::read_to_string(&p).ok()?;
                let lang = Language::detect_with_source(&p, &src)?;
                build_cfgs(lang, &src).ok()?;
                p.to_str().map(String::from)
            })
            .collect()
    }

    /// Within one function the query finds exactly what the taint analysis finds.
    #[test]
    fn same_findings_as_the_taint_analysis_inside_functions() {
        for p in [
            "tests/vuln/app.py",
            "tests/vuln/app.js",
            "tests/vuln/App.java",
            "tests/vuln/app.go",
            "tests/vuln/app.rs",
            "tests/vuln/app.c",
            "tests/fixtures/python/flow.py",
        ] {
            let (old, new) = both(p);
            assert_eq!(new, old, "{p}");
        }
        let (_, new) = both("tests/vuln/app.py");
        assert!(new.len() >= 6, "{new:?}");
    }

    /// What one method stores in a field of its object, another one reads (`self.cmd`, `this.cmd`,
    /// bare `cmd` in Java / C++), field by field.
    #[test]
    fn same_findings_for_fields_shared_between_methods() {
        for p in [
            "tests/fields/fields.py",
            "tests/fields/Svc.java",
            "tests/fields/svc.go",
            "tests/fields/svc.js",
            "tests/fields/svc.rs",
            "tests/bare/Bare.java",
            "tests/bare/bare.cpp",
        ] {
            let (old, new) = both(p);
            assert_eq!(new, old, "{p}");
            assert!(!new.is_empty(), "{p}");
        }
        // other fields of the same object stay clean
        let (_, new) = both("tests/fields/fields.py");
        assert_eq!(new.iter().map(|f| f.1).collect::<Vec<_>>(), [11, 25, 34]);
    }

    /// The acceptance test of the code property graph: on every fixture file the query
    /// finds exactly what the taint analysis finds, aliases, closures, callbacks, objects
    /// built by constructors and element keys included.
    #[test]
    fn same_findings_as_the_taint_analysis_on_every_fixture() {
        let mut found = 0;
        for p in fixtures() {
            let (old, new) = both(&p);
            let extra: Vec<_> = new.difference(&old).collect();
            let missing: Vec<_> = old.difference(&new).collect();
            assert!(
                extra.is_empty() && missing.is_empty(),
                "{p}: only in the CPG: {extra:?}, only in the analysis: {missing:?}"
            );
            found += new.len();
        }
        assert!(found > 60, "{found}");
    }
}

mod taint_parity_dirs {
    use super::*;
    use std::collections::BTreeSet;
    use taintless::analysis::{ProjectFile, check_project};
    use taintless::cpg::graph::{Cpg, SourceFile};
    use taintless::cpg::taint::taint_flows;

    /// `(file, rule, line)` from the project-wide analysis and from the CPG query.
    type Found = BTreeSet<(String, String, usize)>;

    fn both(dir: &str) -> (Found, Found) {
        let mut paths = vec![];
        files(Path::new(dir), &mut paths);
        paths.sort();
        let mut loaded = vec![];
        for p in paths {
            let Ok(src) = std::fs::read_to_string(&p) else {
                continue;
            };
            let Some(lang) = Language::detect_with_source(&p, &src) else {
                continue;
            };
            let Ok(cfgs) = build_cfgs(lang, &src) else {
                continue;
            };
            let imps = taintless::lang::imports(lang, &src).unwrap_or_default();
            loaded.push((p, lang, src, cfgs, imps));
        }
        let pf: Vec<ProjectFile> = loaded
            .iter()
            .map(|l| ProjectFile {
                lang: l.1,
                file: &l.0,
                cfgs: &l.3,
                imports: &l.4,
            })
            .collect();
        let old = check_project(&pf, &|| {})
            .into_iter()
            .filter(|f| f.origin.is_some())
            .map(|f| (f.file.display().to_string(), f.rule.to_string(), f.line))
            .collect();
        let sf: Vec<SourceFile> = loaded
            .iter()
            .map(|l| SourceFile {
                path: &l.0,
                lang: l.1,
                src: &l.2,
                cfgs: &l.3,
                imports: &l.4,
            })
            .collect();
        let cpg = Cpg::build(&sf).unwrap();
        let new = taint_flows(&cpg)
            .into_iter()
            .map(|t| {
                (
                    cpg.files[t.file].path.display().to_string(),
                    t.rule.to_string(),
                    t.line,
                )
            })
            .collect();
        (old, new)
    }

    /// Across functions and files the query finds what the taint analysis finds in
    /// these projects.
    #[test]
    fn same_findings_across_functions_and_files() {
        for d in [
            "tests/interproc",
            "tests/types",
            "tests/hier",
            "tests/imports",
            "tests/bare",
        ] {
            let (old, new) = both(d);
            assert_eq!(new, old, "{d}");
            assert!(!new.is_empty(), "{d}");
        }
    }

    /// The acceptance test across files: every fixture directory, as one project.
    #[test]
    fn same_findings_in_every_directory() {
        let mut dirs: Vec<_> = std::fs::read_dir("tests")
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        let mut covered = 0;
        for d in dirs {
            let d = d.to_str().unwrap().to_string();
            let (old, new) = both(&d);
            let extra: Vec<_> = new.difference(&old).collect();
            let missing: Vec<_> = old.difference(&new).collect();
            assert!(
                extra.is_empty() && missing.is_empty(),
                "{d}: only in the CPG: {extra:?}, only in the analysis: {missing:?}"
            );
            covered += new.len();
        }
        assert!(covered > 60, "{covered}");
    }
}

mod entry_points {
    use super::*;
    use taintless::analysis::check_file;
    use taintless::cpg::graph::{Cpg, SourceFile};
    use taintless::cpg::taint::taint_flows;

    fn lines(src: &str) -> (Vec<usize>, Vec<usize>) {
        let lang = Language::Java;
        let cfgs = build_cfgs(lang, src).unwrap();
        let mut old: Vec<usize> = check_file(lang, Path::new("A.java"), &cfgs)
            .into_iter()
            .filter(|f| f.origin.is_some())
            .map(|f| f.line)
            .collect();
        let f = [SourceFile {
            path: Path::new("A.java"),
            lang,
            src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let mut new: Vec<usize> = taint_flows(&Cpg::build(&f).unwrap())
            .into_iter()
            .map(|t| t.line)
            .collect();
        old.sort();
        new.sort();
        (old, new)
    }

    #[test]
    fn java_main_args_are_untrusted() {
        let src = "class A {\n  static void main(String[] args) {\n    Runtime.getRuntime().exec(args[0]);\n  }\n  static void other(String[] args) {\n    Runtime.getRuntime().exec(args[0]);\n  }\n}\n";
        let (old, new) = lines(src);
        assert_eq!(old, [3]);
        assert_eq!(new, old);
    }

    #[test]
    fn entry_taint_follows_calls() {
        let src = "class A {\n  static void main(String[] args) {\n    run(args[0]);\n  }\n  static void run(String c) {\n    Runtime.getRuntime().exec(c);\n  }\n}\n";
        let (old, new) = lines(src);
        assert_eq!(old, [6]);
        assert_eq!(new, old);
    }
}

#[test]
fn sanitizers_only_clean_their_own_expression() {
    use taintless::cpg::{Cpg, SourceFile, taint::taint_flows};
    for (body, expected) in [
        ("x = input() + str(int(1))\n    os.system(x)", true),
        (
            "x = input()\n    y = x + str(int(1))\n    os.system(y)",
            true,
        ),
        ("os.system(input() + str(int(1)))", true),
        ("run(input() + str(int(1)))", true),
        ("x = source() + str(int(1))\n    os.system(x)", true),
        ("run(source() + str(int(1)))", true),
        ("x = str(int(input()))\n    os.system(x)", false),
        ("run(str(int(source())))", false),
        ("x = input()\n    run(str(int(x)))", false),
        // The nested sink still executes even though its result is sanitized.
        ("x = input()\n    int(run(x))", true),
    ] {
        let src = format!(
            "import os\ndef source():\n    return input()\ndef run(x):\n    os.system(x)\ndef f():\n    {body}\n"
        );
        let cfgs = build_cfgs(Language::Python, &src).unwrap();
        let files = [SourceFile {
            path: Path::new("test.py"),
            lang: Language::Python,
            src: &src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let cpg = Cpg::build(&files).unwrap();
        assert_eq!(
            taint_flows(&cpg)
                .iter()
                .any(|f| f.rule == "command-injection"),
            expected,
            "{body}"
        );
    }
}

#[test]
fn selected_sink_arguments_respect_sanitizers() {
    use taintless::cpg::{Cpg, SourceFile, taint::taint_flows};
    for (query, expected) in [
        ("int(input())", false),
        ("input()", true),
        ("int(input()) + input()", true),
        ("input() + int(input())", true),
    ] {
        let src = format!("import sqlite3\ndef f(db):\n    db.execute({query}, input())\n");
        let cfgs = build_cfgs(Language::Python, &src).unwrap();
        let files = [SourceFile {
            path: Path::new("test.py"),
            lang: Language::Python,
            src: &src,
            cfgs: &cfgs,
            imports: &[],
        }];
        let cpg = Cpg::build(&files).unwrap();
        let has_sql = taint_flows(&cpg).iter().any(|f| f.rule == "sql-injection");
        assert_eq!(has_sql, expected, "{query}");
    }
}

#[test]
fn cpg_direct_source_finding_matches_report_details() {
    use taintless::analysis::check_file;
    use taintless::cpg::{Cpg, SourceFile, taint::taint_flows};
    let src = "import os\ndef f():\n    os.system(input())\n";
    let path = Path::new("direct.py");
    let cfgs = build_cfgs(Language::Python, src).unwrap();
    let old = check_file(Language::Python, path, &cfgs)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    let files = [SourceFile {
        path,
        lang: Language::Python,
        src,
        cfgs: &cfgs,
        imports: &[],
    }];
    let cpg = Cpg::build(&files).unwrap();
    let flow = taint_flows(&cpg)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    assert_eq!(flow.finding(&cpg), old);
}

#[test]
fn cpg_local_source_finding_matches_report_details() {
    use taintless::analysis::check_file;
    use taintless::cpg::{Cpg, SourceFile, taint::taint_flows};
    let src = "import os\ndef f():\n    x = input()\n    y = x\n    os.system(y)\n";
    let path = Path::new("local.py");
    let cfgs = build_cfgs(Language::Python, src).unwrap();
    let old = check_file(Language::Python, path, &cfgs)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    let files = [SourceFile {
        path,
        lang: Language::Python,
        src,
        cfgs: &cfgs,
        imports: &[],
    }];
    let cpg = Cpg::build(&files).unwrap();
    let flow = taint_flows(&cpg)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    assert_eq!(flow.finding(&cpg), old);
}

#[test]
fn cpg_interprocedural_finding_exposes_call_chain() {
    use taintless::analysis::check_file;
    use taintless::cpg::{Cpg, SourceFile, taint::taint_flows};
    let src = "import os\ndef run(x):\n    os.system(x)\ndef main():\n    run(input())\n";
    let path = Path::new("chain.py");
    let cfgs = build_cfgs(Language::Python, src).unwrap();
    let old = check_file(Language::Python, path, &cfgs)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    let files = [SourceFile {
        path,
        lang: Language::Python,
        src,
        cfgs: &cfgs,
        imports: &[],
    }];
    let cpg = Cpg::build(&files).unwrap();
    let flow = taint_flows(&cpg)
        .into_iter()
        .find(|f| f.rule == "command-injection")
        .unwrap();
    assert_eq!(flow.finding(&cpg), old);
}

/// `(kind, name)` of the nodes of one kind, in source order.
fn named(lang: Language, src: &str, kind: NodeKind) -> Vec<String> {
    let ast = build_ast(lang, 0, src).unwrap();
    ast.nodes
        .iter()
        .filter(|n| n.kind == kind)
        .map(|n| n.name.clone().unwrap_or_default())
        .collect()
}

#[test]
fn binary_operators_keep_their_operands_in_order() {
    let ast = build_ast(Language::Python, 0, "x = a - b * 2\n").unwrap();
    let ops: Vec<_> = ast
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.kind == NodeKind::BinaryOp)
        .collect();
    assert_eq!(
        ops.iter()
            .map(|(_, n)| n.name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["-", "*"]
    );
    let operands = |i: usize| {
        ast.nodes[i]
            .children
            .iter()
            .map(|&c| ast.nodes[c].code.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(operands(ops[0].0), ["a", "b * 2"]);
    assert_eq!(operands(ops[1].0), ["b", "2"]);
    for (lang, src) in [
        (Language::JavaScript, "x = a + b;"),
        (Language::Rust, "fn f() { let x = a + b; }"),
        (Language::Go, "package p\nfunc f() { x := a + b }"),
        (Language::Java, "class C { void f() { int x = a + b; } }"),
        (Language::C, "void f() { int x = a + b; }"),
        (Language::Python, "x = a and b"),
    ] {
        let ops = named(lang, src, NodeKind::BinaryOp);
        assert_eq!(ops.len(), 1, "{lang:?}: {ops:?}");
    }
}

#[test]
fn parameters_are_nodes_named_after_what_they_bind() {
    let p = |lang, src| named(lang, src, NodeKind::Param);
    assert_eq!(
        p(
            Language::Python,
            "def f(self, a, b: int, c=1, *d, **e): pass"
        ),
        ["self", "a", "b", "c", "d", "e"]
    );
    assert_eq!(
        p(Language::JavaScript, "function f(a, {b}, c = 1) {}"),
        ["a", "b", "c"]
    );
    assert_eq!(
        p(Language::Rust, "fn f(&self, a: i32, mut b: String) {}"),
        ["self", "a", "b"]
    );
    // Go `a, b int` binds two names: one parameter node each
    assert_eq!(
        p(Language::Go, "package p\nfunc f(a, b int, c string) {}"),
        ["a", "b", "c"]
    );
    assert_eq!(
        p(Language::Go, "package p\nfunc f(int, string) {}"),
        ["int", "string"]
    );
    // a lambda with a single bare parameter
    assert_eq!(p(Language::JavaScript, "const g = x => x + 1;"), ["x"]);
    assert_eq!(
        p(Language::JavaScript, "const g = (x, y) => x + y;"),
        ["x", "y"]
    );
    assert_eq!(
        p(
            Language::Java,
            "class C { void f() { java.util.function.Function<Integer, Integer> g = x -> x + 1; } }"
        ),
        ["x"]
    );
    assert_eq!(p(Language::Python, "g = lambda x: x\n"), ["x"]);
    assert_eq!(p(Language::Rust, "fn f() { let g = |x| x + 1; }"), ["x"]);
    assert_eq!(
        p(Language::Java, "class C { void f(int a, String... b) {} }"),
        ["a", "b"]
    );
    assert_eq!(p(Language::C, "void f(int a, char *b) {}"), ["a", "b"]);
    // a call's arguments are not parameters
    assert!(p(Language::Python, "f(a, b)\n").is_empty());
}

#[test]
fn type_declarations_are_nodes() {
    let t = |lang, src| named(lang, src, NodeKind::TypeDecl);
    assert_eq!(
        t(Language::Python, "class A:\n    class B: pass\n"),
        ["A", "B"]
    );
    assert_eq!(
        t(Language::Java, "class A {} interface I {} enum E {}"),
        ["A", "I", "E"]
    );
    assert_eq!(
        t(
            Language::Rust,
            "struct S; struct T { x: i32 } enum E {} trait R {}"
        ),
        ["S", "T", "E", "R"]
    );
    assert_eq!(
        t(
            Language::Go,
            "package p\ntype S struct{}\ntype I interface{}"
        ),
        ["S", "I"]
    );
    assert_eq!(
        t(
            Language::Cpp,
            "struct S { int x; }; void f() { struct S *p; }"
        ),
        ["S"]
    );
}

/// Source files of one language as a project, to build a CPG from.
fn cpg_of(lang: Language, src: &str) -> Cpg {
    let cfgs = build_cfgs(lang, src).unwrap();
    let files = [SourceFile {
        path: Path::new("t"),
        lang,
        src,
        cfgs: &cfgs,
        imports: &[],
    }];
    Cpg::build(&files).unwrap()
}

fn names(c: &Cpg, nodes: impl Iterator<Item = petgraph::graph::NodeIndex>) -> Vec<String> {
    let mut v: Vec<String> = nodes
        .map(|n| c.graph[n].name.clone().unwrap_or_default())
        .collect();
    v.sort();
    v
}

#[test]
fn locals_are_nodes_of_the_method_that_declares_them() {
    let c = cpg_of(
        Language::Python,
        "def f(a):\n    x = a\n    y, z = x, 1\n    self.k = 2\n    for i in a:\n        x = i\n\ndef g():\n    w = 1\n",
    );
    let m = |name: &str| {
        c.methods
            .iter()
            .copied()
            .find(|&m| c.graph[m].name.as_deref() == Some(name))
            .unwrap()
    };
    // every assigned name once (`x` twice assigned), no parameters, no fields
    assert_eq!(
        names(
            &c,
            c.out(m("f"), EdgeKind::Contains)
                .filter(|&n| c.graph[n].kind == NodeKind::Local)
        ),
        ["i", "x", "y", "z"]
    );
    assert_eq!(
        names(
            &c,
            c.out(m("g"), EdgeKind::Contains)
                .filter(|&n| c.graph[n].kind == NodeKind::Local)
        ),
        ["w"]
    );
    // positioned at the first definition
    let x = c
        .out(m("f"), EdgeKind::Contains)
        .find(|&n| c.graph[n].name.as_deref() == Some("x"))
        .unwrap();
    assert_eq!((c.graph[x].line, c.graph[x].col), (2, 5));
    assert_eq!(c.enclosing_method(x), m("f"));
}

#[test]
fn declared_types_of_parameters_and_locals_are_type_nodes() {
    let c = cpg_of(
        Language::Java,
        "class A { void f(Runner r, int n) { Runner q = r; Other o = null; } void g(Runner s) {} }",
    );
    let ty = |n| {
        c.out(n, EdgeKind::TypeOf)
            .map(|t| c.graph[t].name.clone().unwrap())
            .collect::<Vec<_>>()
    };
    let var = |kind, name: &str| {
        c.graph
            .node_indices()
            .find(|&n| c.graph[n].kind == kind && c.graph[n].name.as_deref() == Some(name))
            .unwrap()
    };
    assert_eq!(ty(var(NodeKind::Param, "r")), ["Runner"]);
    assert_eq!(ty(var(NodeKind::Param, "n")), ["int"]);
    assert_eq!(ty(var(NodeKind::Local, "q")), ["Runner"]);
    assert_eq!(ty(var(NodeKind::Local, "o")), ["Other"]);
    // one node per type and file, shared by `f` and `g`
    let types: Vec<_> = c.nodes_of(NodeKind::Type).collect();
    assert_eq!(names(&c, types.iter().copied()), ["Other", "Runner", "int"]);
    let runner = types
        .iter()
        .copied()
        .find(|&t| c.graph[t].name.as_deref() == Some("Runner"))
        .unwrap();
    assert_eq!(Cpg::into(&c, runner, EdgeKind::TypeOf).count(), 3);
}

#[test]
fn parameters_are_defined_at_their_param_nodes() {
    let c = cpg_of(
        Language::Python,
        "import os\ndef f(a, b):\n    os.system(a)\n",
    );
    let param = |name: &str| {
        c.graph
            .node_indices()
            .find(|&n| {
                c.graph[n].kind == NodeKind::Param && c.graph[n].name.as_deref() == Some(name)
            })
            .unwrap()
    };
    let reaches = |p| {
        c.graph
            .edges_directed(p, petgraph::Direction::Outgoing)
            .filter(|e| e.weight().kind == EdgeKind::Reaching)
            .count()
    };
    assert_eq!(reaches(param("a")), 1);
    assert_eq!(reaches(param("b")), 0);
    assert_eq!(c.out(c.methods[0], EdgeKind::Reaching).count(), 0);
    assert_eq!(c.param_def(0, "a"), param("a"));
}
