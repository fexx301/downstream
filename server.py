"""DOWNSTREAM tools for the agent, served over MCP (stdio). The case file names the release and the dependent.

Run: DOWNSTREAM_CASE=cases/x.json uv run --with mcp --with falkordb python server.py
"""
import ast
import json
import os
import re
from pathlib import Path

from falkordb import FalkorDB
from mcp.server.mcpserver import MCPServer

import runner
import scan
from impact import EXPOSED, REACHES_REMOVED, REMOVED_PARAMS, UNRESOLVED

HERE = Path(__file__).parent
SUPPORTED = "Parameter was removed"
case = json.loads(Path(os.environ["DOWNSTREAM_CASE"]).read_text())
graph = FalkorDB(host="localhost", port=6380).select_graph(case["graph"])
mods = {name: path for src in case["src"] for name, _, path in scan.modules(HERE / src)}
server = MCPServer("downstream")


def plain(value):
    return json.loads(json.dumps(value, default=lambda o: getattr(o, "properties", str(o))))


def defs(body):
    """Classes and functions in a body, including those under if/try blocks."""
    for n in body:
        if isinstance(n, ast.If):
            yield from defs(n.body)
            yield from defs(n.orelse)
        elif isinstance(n, ast.Try):
            for block in (n.body, n.orelse, n.finalbody, *[h.body for h in n.handlers]):
                yield from defs(block)
        elif isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


@server.tool()
def breaking_changes() -> dict:
    """Removed parameters, from the graph's own diff of the two releases plus griffe's API diff (each
    entry says which found it). Only removed parameters can be traced through the symbol graph; every
    other kind griffe reports is listed as unsupported (not analysed)."""
    changes = json.loads((HERE / case["breaks"]).read_text())
    unsupported, removed = {}, {}
    for c in changes:
        if c["kind"] != SUPPORTED:
            unsupported.setdefault(c["kind"], []).append(c["path"])
        else:
            removed[(c["canonical"], c["name"])] = {"function": c["canonical"], "parameter": c["name"], "found_by": "griffe"}
    for fn, param, kwargs in graph.ro_query(REMOVED_PARAMS, {"lib": case["lib_module"]}).result_set:
        if fn.rpartition(".")[2].startswith("_") and not fn.endswith("__"):
            continue  # private helpers are not API
        entry = removed.setdefault((fn, param), {"function": fn, "parameter": param, "found_by": "graph diff"})
        if entry["found_by"] == "griffe":
            entry["found_by"] = "both"
        entry["new_signature_takes_kwargs"] = kwargs
    return {
        "removed_parameters": list(removed.values()),
        "unsupported": {k: {"count": len(v), "examples": v[:5]} for k, v in unsupported.items()},
    }


@server.tool()
def impact_paths(function: str = "", parameter: str = "") -> dict:
    """Call paths from the dependent's code whose explicit keyword reaches a removed parameter, through
    aliases, constructors and **kwargs forwarding. With no arguments, checks every removed parameter."""
    todo = [(function, parameter)] if function else [
        (c["function"], c["parameter"]) for c in breaking_changes()["removed_parameters"]]
    found, empty = [], 0
    for fn, param in todo:
        rows = graph.ro_query(REACHES_REMOVED, {"fn": fn, "param": param, "pkg": fn.partition(".")[0] + "."}).result_set
        found += [{"function": fn, "parameter": param, "chain": chain, "hops": hops} for chain, hops in rows]
        empty += not rows
    return {"paths": found, "removed_parameters_without_paths": empty}


@server.tool()
def exposed_paths(site: str) -> dict:
    """Code in the dependent that reaches a call site in another package (a chain start from impact_paths),
    through calls, imports and constructor lookup, including module code that runs on import.
    Shortest path per entry point, at most 50."""
    rows = graph.ro_query(EXPOSED, {"site": site, "pkg": case["dep_module"]}, timeout=30000).result_set
    return {"paths": [{"chain": chain, "hops": hops} for chain, hops in rows]}


@server.tool()
def unknown_calls() -> list:
    """Calls in the dependent that pass a removed keyword to a symbol the graph cannot resolve but whose
    name mentions the library, for example a vendored or runtime alias. Unknown, not safe: test them."""
    params = sorted({c["parameter"] for c in breaking_changes()["removed_parameters"]})
    rows = graph.ro_query(UNRESOLVED, {"pkg": case["dep_module"], "params": params, "lib": case["lib_module"]}).result_set
    return [{"caller": caller, "target": target, "keywords": kws} for caller, target, kws in rows]


def triage():
    """What the graph alone says about the dependent, before any agent runs."""
    mod, paths = case["dep_module"], impact_paths()["paths"]
    direct = [p for p in paths if p["chain"][0] == mod or p["chain"][0].startswith(mod + ".")]
    sites = sorted({p["chain"][0] for p in paths if p not in direct})
    return {"direct": direct, "exposed": [e for s in sites for e in exposed_paths(s)["paths"]],
            "unknown": unknown_calls()}


@server.tool()
def cypher(query: str) -> list:
    """Read-only Cypher over the symbol graph (first 50 rows). Nodes: (:Sym {qn, kind, params, var_kw}),
    kind is module/class/function/alias/ref. Edges: ALIAS_OF {tc}, INHERITS {i}, CTOR, CALLS {kws}, FORWARDS_KW."""
    return plain(graph.ro_query(query).result_set[:50])


@server.tool()
def source(qualified_name: str) -> str:
    """Source of a module, class or function from the scanned packages, with line numbers."""
    names = qualified_name.split(".")
    for i in range(len(names), 0, -1):
        path = mods.get(".".join(names[:i]))
        if path:
            break
    else:
        return f"no scanned module contains {qualified_name}"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    node, rest = ast.parse(text), names[i:]
    for name in rest:
        node = next((n for n in defs(node.body) if n.name == name), None)
        if node is None:
            return f"{name} is not a class or function in {path.name}; it may be bound by an import or assignment there"
    start = node.decorator_list[0].lineno if getattr(node, "decorator_list", None) else getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", None) or min(len(lines), 400)
    if end - start > 400:
        end = start + 400  # shortcut: long modules are cut at 400 lines; ask for a class or function instead
    return f"{path.relative_to(HERE)}\n" + "\n".join(f"{n:5} {lines[n - 1]}" for n in range(start, end + 1))


@server.tool()
def search(pattern: str, package: str = "") -> list:
    """Regex search over the scanned source (only modules under `package` if given). First 50 matches."""
    rx, out = re.compile(pattern), []
    for name, path in mods.items():
        if package and name != package and not name.startswith(package + "."):
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if rx.search(line):
                out.append(f"{name}:{n}: {line.strip()[:200]}")
                if len(out) == 50:
                    return out
    return out


@server.tool()
def run(code: str, version: str, shim: str = "") -> dict:
    """Run `python -I -c code` in a fresh container: no network, read-only except /tmp, 60 s limit. The
    dependent is installed with the library at version "old" or "new". `shim` (new only) is Python source
    appended to the end of the library's top-level __init__.py before running."""
    if version not in ("old", "new"):
        return {"error": "version must be 'old' or 'new'"}
    if shim and version != "new":
        return {"error": "a shim applies to the new version only"}
    return runner.run(case, case[version], code, shim or None)


if __name__ == "__main__":
    server.run()
