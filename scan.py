"""Load the symbol graph of unpacked Python packages into FalkorDB.

Usage: python scan.py <graph> <src_dir> [<src_dir> ...]

Every symbol is a (:Sym {qn, kind}) node. Edges:
  ALIAS_OF {tc}   name binding -> what it names (imports, re-exports, `X = Y`); tc = only under TYPE_CHECKING
  INHERITS {i}    class -> base class
  CTOR            class -> the __init__ that runs when it is called (own __init__, else first base)
  CALLS {kws}     function or module -> called symbol, with the explicit keyword names passed (may be none);
                  a module's calls are its top-level code, which runs on import
  FORWARDS_KW     function -> called symbol it hands its own **kwargs to
No package-specific names: only general Python binding, inheritance and call rules.
"""
import ast
import sys
from pathlib import Path

from falkordb import FalkorDB

nodes = {}   # qn -> props
edges = []   # (type, src_qn, dst_qn, props)


def node(qn, kind, **props):
    if kind != "ref" or qn not in nodes:
        nodes[qn] = {"qn": qn, "kind": kind, **props}


def edge(etype, src, dst, **props):
    node(dst, "ref")
    edges.append((etype, src, dst, props))


def modules(src_dir):
    for path in sorted(Path(src_dir).rglob("*.py")):
        parts = path.relative_to(src_dir).with_suffix("").parts
        if not all(p.isidentifier() for p in parts):
            continue  # skips *.dist-info and similar
        is_pkg = parts[-1] == "__init__"
        name = ".".join(parts[:-1] if is_pkg else parts)
        if name:
            yield name, is_pkg, path


def is_type_checking(test):
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


class Module:
    def __init__(self, name, is_pkg, tree):
        self.name, self.tree = name, tree
        self.pkg = name if is_pkg else name.rpartition(".")[0]
        self.imports = {}  # local name -> qualified target, for resolving attribute chains
        self.stars = []    # (source module, tc)
        self.public = None  # names from a literal __all__

    def absolute(self, level, module):
        base = self.pkg.split(".")
        if level > 1:
            base = base[: len(base) - (level - 1)]
        return ".".join([*base, module] if module else base) if level else module

    def resolve(self, expr):
        """Qualified name an expression refers to, or None."""
        if isinstance(expr, ast.Name):
            return f"{self.name}.{expr.id}"
        if isinstance(expr, ast.Attribute):
            chain = []
            while isinstance(expr, ast.Attribute):
                chain.append(expr.attr)
                expr = expr.value
            if isinstance(expr, ast.Name):
                head = self.imports.get(expr.id, f"{self.name}.{expr.id}")
                return ".".join([head, *reversed(chain)])
        return None

    def scan_body(self, body, tc=False):
        for stmt in body:
            if isinstance(stmt, ast.If):
                self.scan_body(stmt.body, tc or is_type_checking(stmt.test))
                self.scan_body(stmt.orelse, tc)
            elif isinstance(stmt, ast.Try):
                for block in (stmt.body, stmt.orelse, stmt.finalbody, *[h.body for h in stmt.handlers]):
                    self.scan_body(block, tc)
            elif isinstance(stmt, ast.Import):
                for a in stmt.names:
                    local = a.asname or a.name.partition(".")[0]
                    target = a.name if a.asname else local
                    self.imports[local] = target
                    edge("ALIAS_OF", f"{self.name}.{local}", target, tc=tc)
                    node(f"{self.name}.{local}", "alias")
            elif isinstance(stmt, ast.ImportFrom):
                src = self.absolute(stmt.level, stmt.module)
                for a in stmt.names:
                    if a.name == "*":
                        self.stars.append((src, tc))
                        continue
                    local = a.asname or a.name
                    self.imports[local] = f"{src}.{a.name}"
                    node(f"{self.name}.{local}", "alias")
                    edge("ALIAS_OF", f"{self.name}.{local}", f"{src}.{a.name}", tc=tc)
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                if name == "__all__" and isinstance(stmt.value, (ast.List, ast.Tuple)):
                    self.public = [e.value for e in stmt.value.elts if isinstance(e, ast.Constant)]
                target = self.resolve(stmt.value)
                if target:
                    node(f"{self.name}.{name}", "alias")
                    edge("ALIAS_OF", f"{self.name}.{name}", target, tc=tc)
            elif isinstance(stmt, ast.ClassDef):
                self.scan_class(stmt)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_function(stmt, f"{self.name}.{stmt.name}", None)
            if not tc and not isinstance(stmt, (ast.If, ast.Try, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_calls(stmt, self.name)

    def scan_class(self, cls):
        qn = f"{self.name}.{cls.name}"
        node(qn, "class")
        bases = [b for b in map(self.resolve, cls.bases) if b]
        for i, b in enumerate(bases):
            edge("INHERITS", qn, b, i=i)
        has_init = False
        for stmt in cls.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_function(stmt, f"{qn}.{stmt.name}", bases)
                has_init |= stmt.name == "__init__"
        # shortcut: constructor lookup follows the first base only, not the full MRO; upgrade if multiple inheritance matters
        if has_init:
            edge("CTOR", qn, f"{qn}.__init__")
        elif bases:
            edge("CTOR", qn, bases[0])

    def scan_function(self, fn, qn, bases):
        a = fn.args
        params = [p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs]]
        var_kw = a.kwarg.arg if a.kwarg else None
        node(qn, "function", params=params, var_kw=bool(var_kw))
        self.scan_calls(fn, qn, var_kw, bases)

    def scan_calls(self, tree, qn, var_kw=None, bases=None):
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            f = call.func
            is_super = (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call)
                        and isinstance(f.value.func, ast.Name) and f.value.func.id == "super")
            if is_super:
                if f.attr != "__init__" or not bases:
                    continue
                target = bases[0]
            else:
                # shortcut: calls through self/instances are not resolved; only names and module attributes are
                target = self.resolve(f)
            if not target:
                continue
            edge("CALLS", qn, target, kws=[k.arg for k in call.keywords if k.arg])
            if var_kw and any(k.arg is None and isinstance(k.value, ast.Name) and k.value.id == var_kw
                              for k in call.keywords):
                edge("FORWARDS_KW", qn, target)


def scan(src_dirs):
    mods = {}
    for src in src_dirs:
        for name, is_pkg, path in modules(src):
            m = Module(name, is_pkg, ast.parse(path.read_text(encoding="utf-8"), str(path)))
            node(name, "module")
            m.scan_body(m.tree.body)
            mods[name] = m
    # Star imports need every module's names first.
    for m in mods.values():
        for src, tc in m.stars:
            s = mods.get(src)
            if not s:
                continue
            names = s.public if s.public is not None else [
                q.rpartition(".")[2] for q in nodes if q.rpartition(".")[0] == src and not q.rpartition(".")[2].startswith("_")]
            for n in names:
                node(f"{m.name}.{n}", "alias")
                edge("ALIAS_OF", f"{m.name}.{n}", f"{src}.{n}", tc=tc)


def load(graph_name, host="localhost", port=6380):
    g = FalkorDB(host=host, port=port).select_graph(graph_name)
    try:
        g.delete()
    except Exception:
        pass  # graph did not exist yet
    g.query("CREATE INDEX FOR (s:Sym) ON (s.qn)")
    rows = list(nodes.values())
    for i in range(0, len(rows), 2000):
        g.query("UNWIND $rows AS r CREATE (s:Sym) SET s = r", {"rows": rows[i:i + 2000]})
    by_type = {}
    for etype, src, dst, props in edges:
        by_type.setdefault(etype, []).append({"s": src, "d": dst, "p": props})
    for etype, rows in by_type.items():
        for i in range(0, len(rows), 2000):
            g.query(f"UNWIND $rows AS r MATCH (a:Sym {{qn: r.s}}), (b:Sym {{qn: r.d}}) "
                    f"CREATE (a)-[e:{etype}]->(b) SET e = r.p", {"rows": rows[i:i + 2000]})
    return g


if __name__ == "__main__":
    scan(sys.argv[2:])
    g = load(sys.argv[1])
    print(len(nodes), "nodes,", len(edges), "edges")
