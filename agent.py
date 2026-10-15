"""Run the DOWNSTREAM agent on one case, then re-check its findings in fresh containers.

Usage: python agent.py <case.json> setup|run|verify [report.json]
  setup   griffe diff and symbol graph for the case
  run     headless Claude Code with only the downstream MCP tools; trace and report go to runs/, then verify
  verify  re-run each finding's reproduction on old, new and new+shim in fresh environments
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from string import Template

import runner

HERE = Path(__file__).parent
MODEL = "claude-opus-5-5"
UV = ["uv", "run", "-q", "--python", "3.12"]


def setup(case):
    with open(HERE / case["breaks"], "w") as out:
        subprocess.run([*UV, "--with", "griffe", "python", "breaks.py", case["lib_module"], *case["lib_src"]],
                       cwd=HERE, stdout=out, check=True)
    subprocess.run([*UV, "--with", "falkordb", "python", "scan.py", case["graph"], *case["src"]], cwd=HERE, check=True)


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


def run_agent(case_path, case):
    cwd = Path(tempfile.mkdtemp(prefix="downstream-"))  # no project instructions, memory or settings above it
    (cwd / "mcp.json").write_text(json.dumps({"mcpServers": {"downstream": {
        "command": "uv", "args": [*UV[1:], "--with", "mcp", "--with", "falkordb", "python", str(HERE / "server.py")],
        "env": {"DOWNSTREAM_CASE": str(case_path.resolve()), "PATH": os.environ["PATH"]}}}}))
    (HERE / "runs").mkdir(exist_ok=True)
    out = HERE / "runs" / f"{case['name']}-{time.strftime('%Y%m%d-%H%M%S')}"
    prompt = Template((HERE / "prompt.md").read_text()).substitute(case, via=", ".join(case.get("pins", [])) or "none")
    cmd = ["claude", "-p", f"Investigate this release of {case['lib']} for its maintainer.", "--system-prompt", prompt,
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
        return
    Path(f"{out}.report.json").write_text(json.dumps(report, indent=1))
    verify(case, report, out)


def passes_param(code, param):
    """Whether the code hands `param` over itself, as a call keyword or a dict key."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True  # unparseable code cannot be cleared
    return any((isinstance(n, ast.keyword) and n.arg == param) or
               (isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == param for k in n.keys))
               for n in ast.walk(tree))


def through_dependent(code, stderr, case):
    """The failure is reached through the dependent: every package in between is on the failing traceback,
    and either the dependent's own code runs there or, when it only re-exports the affected code, the
    script reaches it by importing the dependent and none of the packages in between."""
    mod, via = case["dep_module"], case.get("via_modules", [])
    if not all(f"site-packages/{m}/" in stderr for m in via):
        return False
    if f"site-packages/{mod}/" in stderr:
        return True
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    imported = ({a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} |
                {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module})
    return bool(via) and mod in imported and not imported & set(via)


def text_hits(case, param):
    """Lines in the dependent's own source that mention `param`: the text-search baseline."""
    mod = case["dep_module"]
    return [f"{p.name}:{n}" for src in case["src"] for p in sorted((HERE / src / mod).rglob("*.py"))
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if re.search(rf"\b{param}\b", line)]


def verify(case, report, out):
    """Re-run the agent's evidence instead of trusting its report."""
    kinds = {c["kind"] for c in json.loads((HERE / case["breaks"]).read_text())} - {"Parameter was removed"}
    rows = {"unsupported kinds all listed": sorted(kinds - set(report.get("unsupported", {}))) or True}
    mod = case["dep_module"]
    for i, f in enumerate(report.get("findings", [])):
        code, param = f.get("reproduction") or "", f.get("parameter") or ""
        res = {"old": runner.run(case, case["old"], code, fresh=True),
               "new": runner.run(case, case["new"], code, fresh=True),
               "new+shim": runner.run(case, case["new"], code, f.get("shim") or None, fresh=True)}
        new_err = res["new"].get("stderr", "")
        rows[f"finding {i}: {f.get('function')}({param}=) via {f.get('evidence')}"] = {
            "imports the dependent": bool(re.search(rf"^\s*(from|import)\s+{mod}\b", code, re.M)),
            "does not pass the parameter itself": not passes_param(code, param),
            "dependent's source mentions the parameter": text_hits(case, param),
            "has an assertion": "assert" in code,
            "old passes": res["old"]["outcome"] == "pass",
            "new fails naming the parameter, through the dependent":
                res["new"]["outcome"] == "fail" and param in new_err and through_dependent(code, new_err, case),
            "has a shim": bool(f.get("shim")),
            "new+shim passes": res["new+shim"]["outcome"] == "pass",
            "outputs": res,
        }
    Path(f"{out}.verify.json").write_text(json.dumps(rows, indent=1))
    for k, v in rows.items():
        print(k, {c: r for c, r in v.items() if c != "outputs"} if isinstance(v, dict) else v)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    case = json.loads(path.read_text())
    if sys.argv[2] == "setup":
        setup(case)
    elif sys.argv[2] == "run":
        run_agent(path, case)
    else:
        verify(case, json.loads(Path(sys.argv[3]).read_text()), Path(sys.argv[3]).with_suffix(""))
