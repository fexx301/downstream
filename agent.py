"""Run the DOWNSTREAM agent on one case, then re-check its findings in fresh containers.

Usage: python agent.py <case.json> setup|run|verify [report.json]
  setup   griffe diff and symbol graph for the case
  run     headless Claude Code with only the downstream MCP tools; trace and report go to runs/, then verify
  verify  re-run each finding's reproduction on old, new and new+shim in fresh environments
"""
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from string import Template

import runner

HERE = Path(__file__).parent
MODEL = "claude-opus-5-5"
TRACED = {"Parameter was removed", "Public object was removed"}  # change kinds the graph traces
UV = ["uv", "run", "-q", "--python", "3.12"]


def fetch(case):
    """Download from PyPI and unpack each source directory the case reads, unless it is already there."""
    for d in sorted({*case["src"], *case["lib_src"]}):
        top = HERE / Path(*Path(d).parts[:2])  # src/<distribution>-<version>
        if top.exists():
            continue
        dist, version = top.name.rsplit("-", 1)
        files = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{dist}/{version}/json"))["urls"]
        # a pure-Python wheel if there is one, else any wheel, else the sdist
        f = min(files, key=lambda f: (f["packagetype"] != "bdist_wheel", not f["filename"].endswith("-none-any.whl")))
        data = urllib.request.urlopen(f["url"]).read()
        if hashlib.sha256(data).hexdigest() != f["digests"]["sha256"]:
            raise ValueError(f"checksum mismatch for {f['filename']}")
        if f["packagetype"] == "bdist_wheel":
            zipfile.ZipFile(io.BytesIO(data)).extractall(top)
        else:
            tarfile.open(fileobj=io.BytesIO(data)).extractall(top, filter="data")
        print("fetched", f["filename"])


def setup(case):
    fetch(case)
    with open(HERE / case["breaks"], "w") as out:
        subprocess.run([*UV, "--with", "griffe", "python", "breaks.py", case["lib_module"], *case["lib_src"]],
                       cwd=HERE, stdout=out, check=True)
    subprocess.run([*UV, "--with", "falkordb", "python", "scan.py", case["graph"], *case["src"],
                    "--new", case["lib_module"], case["lib_src"][1]], cwd=HERE, check=True)


def last_json(text):
    """The JSON object that ends the agent's final message."""
    dec = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, end = dec.raw_decode(text, m.start())
        except ValueError:
            continue
        if not text[end:].strip(" \n`"):
            return obj
    return None


def run_agent(case_path, case, control=False):
    """Investigate the dependent (or, with control, test the graph's exclusion of it); returns verification rows."""
    cwd = Path(tempfile.mkdtemp(prefix="downstream-"))  # no project instructions, memory or settings above it
    (cwd / "mcp.json").write_text(json.dumps({"mcpServers": {"downstream": {
        "command": "uv", "args": [*UV[1:], "--with", "mcp", "--with", "falkordb", "python", str(HERE / "server.py")],
        "env": {"DOWNSTREAM_CASE": str(case_path.resolve()), "PATH": os.environ["PATH"]}}}}))
    (HERE / "runs").mkdir(exist_ok=True)
    out = HERE / "runs" / f"{case['name']}{'-control' if control else ''}-{time.strftime('%Y%m%d-%H%M%S')}"
    template = (HERE / ("prompt-control.md" if control else "prompt.md")).read_text()
    prompt = Template(template).substitute(case, via=", ".join(case.get("pins", [])) or "none")
    task = (f"Test the graph's exclusion of {case['dep']}." if control
            else f"Investigate this release of {case['lib']} for its maintainer.")
    cmd = ["claude", "-p", task, "--system-prompt", prompt,
           "--model", MODEL, "--tools", "", "--strict-mcp-config", "--mcp-config", str(cwd / "mcp.json"),
           "--allowedTools", "mcp__downstream", "--setting-sources", "", "--no-session-persistence",
           "--output-format", "stream-json", "--verbose"]
    started = time.time()
    with open(f"{out}.jsonl", "w") as trace:
        try:
            subprocess.run(cmd, cwd=cwd, stdout=trace, stderr=subprocess.STDOUT, timeout=case["cap_s"])
        except subprocess.TimeoutExpired:
            print(f"cap of {case['cap_s']} s reached")
    print(f"trace {out}.jsonl, {time.time() - started:.0f} s")
    events = [json.loads(line) for line in open(f"{out}.jsonl") if line.startswith("{")]
    result = next((e for e in reversed(events) if e.get("type") == "result"), {})
    report = last_json(result.get("result") or "")
    if report is None:
        print("no JSON report in the final message")
        return None
    Path(f"{out}.report.json").write_text(json.dumps(report, indent=1))
    return (verify_control if control else verify)(case, report, out)


def passes_param(code, param):
    """Whether the code hands `param` over itself, as a call keyword or a dict key."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True  # unparseable code cannot be cleared
    return any((isinstance(n, ast.keyword) and n.arg == param) or
               (isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == param for k in n.keys))
               for n in ast.walk(tree))


def uses_name(code, name, lib):
    """Whether the code reaches the removed `name` of library `lib` itself: imports it from the library,
    or reads it off a library module. Other things that share the name do not count, such as a
    dependent's own re-export (`flask.escape` when `jinja2.escape` was removed)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True  # unparseable code cannot be cleared

    def in_lib(module):
        return module == lib or module.startswith(lib + ".")

    def root(expr):
        while isinstance(expr, ast.Attribute):
            expr = expr.value
        return expr.id if isinstance(expr, ast.Name) else None

    lib_names = {a.asname or a.name.partition(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names if in_lib(a.name)}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module and in_lib(n.module) and any(a.name == name for a in n.names):
            return True
        if isinstance(n, ast.Attribute) and n.attr == name and root(n.value) in lib_names:
            return True
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" and len(n.args) >= 2
                and root(n.args[0]) in lib_names and isinstance(n.args[1], ast.Constant) and n.args[1].value == name):
            return True
    return False


def through_dependent(code, stderr, case):
    """The failure is reached through the dependent: every package in between is on the failing traceback,
    and either the dependent's own code runs there or, when it only re-exports the affected code, the
    script reaches it by importing the dependent and none of the packages in between."""
    mod, via = case["dep_module"], case.get("via_modules", [])
    if not all(f"site-packages/{m}/" in stderr for m in via):
        return False
    if f"site-packages/{mod}/" in stderr:
        return True
    names = imported(code)
    return bool(via) and mod in names and not names & set(via)


def imported(code):
    """Top-level module names the code imports (empty if it does not parse)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    return ({a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} |
            {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module})


def text_hits(case, param):
    """Lines in the dependent's own source that mention `param`: the text-search baseline."""
    mod = case["dep_module"]
    return [f"{p.name}:{n}" for src in case["src"] for p in sorted((HERE / src / mod).rglob("*.py"))
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if re.search(rf"\b{param}\b", line)]


def verify(case, report, out):
    """Re-run the agent's evidence instead of trusting its report."""
    kinds = {c["kind"] for c in json.loads((HERE / case["breaks"]).read_text())} - TRACED
    rows = {"unsupported kinds all listed": sorted(kinds - set(report.get("unsupported", {}))) or True}
    mod = case["dep_module"]
    for i, f in enumerate(report.get("findings", [])):
        # a removed name is checked by its last part, the one an ImportError or AttributeError names
        code, param, name = f.get("reproduction") or "", (f.get("parameter") or "").rpartition(".")[2], f.get("kind") == "name"
        res = {"old": runner.run(case, case["old"], code, fresh=True),
               "new": runner.run(case, case["new"], code, fresh=True),
               "new+shim": runner.run(case, case["new"], code, f.get("shim") or None, fresh=True)}
        new_err = res["new"].get("stderr", "")
        rows[f"finding {i}: {f.get('function')}({param}{'' if name else '='}) via {f.get('evidence')}"] = {
            "imports the dependent": mod in imported(code),
            "does not pass or name it itself": not (uses_name(code, param, case["lib_module"]) if name else passes_param(code, param)),
            "dependent's source mentions the parameter": text_hits(case, param),
            "has an assertion": "assert" in code,
            "old passes": res["old"]["outcome"] == "pass",
            "new fails naming the parameter, through the dependent":
                res["new"]["outcome"] == "fail" and param in new_err and through_dependent(code, new_err, case),
            "has a shim": bool(f.get("shim")),
            "new+shim passes": res["new+shim"]["outcome"] == "pass",
            "outputs": res,
        }
    return save(rows, out)


def verify_control(case, report, out):
    """Re-run the control reproduction: the graph's exclusion holds only if it passes on both versions."""
    code = (report.get("control") or {}).get("reproduction") or ""
    res = {v: runner.run(case, case[v], code, fresh=True) for v in ("old", "new")}
    return save({"control": {
        "imports the dependent": case["dep_module"] in imported(code),
        "has an assertion": "assert" in code,
        "old passes": res["old"]["outcome"] == "pass",
        "new passes": res["new"]["outcome"] == "pass",
        "outputs": res,
    }}, out)


def save(rows, out):
    Path(f"{out}.verify.json").write_text(json.dumps(rows, indent=1))
    for k, v in rows.items():
        print(k, {c: r for c, r in v.items() if c != "outputs"} if isinstance(v, dict) else v)
    return rows


def passed(rows):
    """Every yes/no check of every row holds (the text-hit lists are information, not checks)."""
    return bool(rows) and all(r is True or (isinstance(r, dict) and all(x for x in r.values() if isinstance(x, bool)))
                              for r in rows.values())


def summary_row(dep, counts, other, rows):
    """One demo table row: what the graph said, what it did not cover, and what the re-run showed."""
    says = ", ".join(f"{n} {k}" for k, n in counts.items() if n) or "no exposure found"
    # a clean graph result covers removed parameters only, so the row always says what it did not cover
    unanalysed = f"{other} other API changes; behaviour changes" if other else "behaviour changes"
    if not rows:
        did, rerun = "no report from the agent", "nothing to re-run"
    elif "control" in rows:
        c = rows["control"]
        did, rerun = "exclusion test", ("holds: works on both" if passed(rows) else
                                        "FAILS on new: exclusion wrong" if c["old passes"] and not c["new passes"]
                                        else "inconclusive: no working test on old")
    else:
        found = [k for k in rows if k.startswith("finding")]
        did, rerun = f"{len(found)} break(s) reported", "all confirmed" if passed(rows) else "NOT all confirmed"
    return f"| {dep} | {says} | {unanalysed} | {did} | {rerun} |"


def demo(paths):
    """One release against several dependents: the graph sorts them, the agent tests each, the verifier re-runs."""
    lines = ["| Dependent | Graph says | Not analysed | Agent run | Re-run in fresh containers |", "|---|---|---|---|---|"]
    for path in paths:
        case = json.loads(path.read_text())
        setup(case)
        t = json.loads(subprocess.run([*UV, "--with", "mcp", "--with", "falkordb", "python", "-c",
                                       "import json, server; print(json.dumps(server.triage()))"],
                                      cwd=HERE, env={**os.environ, "DOWNSTREAM_CASE": str(path.resolve())},
                                      capture_output=True, text=True, check=True).stdout)
        counts = {k: len(v) for k, v in t.items()}
        other = sum(c["kind"] not in TRACED for c in json.loads((HERE / case["breaks"]).read_text()))
        rows = run_agent(path, case, control=not any(counts.values()))
        lines.append(summary_row(case["dep"], counts, other, rows))
    out = HERE / "runs" / f"demo-{time.strftime('%Y%m%d-%H%M%S')}.md"
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    if sys.argv[1] == "demo":
        demo([Path(p) for p in sys.argv[2:]])
        sys.exit()
    path = Path(sys.argv[1])
    case = json.loads(path.read_text())
    if sys.argv[2] == "setup":
        setup(case)
    elif sys.argv[2] == "run":
        run_agent(path, case)
    else:
        verify(case, json.loads(Path(sys.argv[3]).read_text()), Path(sys.argv[3]).with_suffix(""))
