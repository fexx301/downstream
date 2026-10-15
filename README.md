# DOWNSTREAM

Find which Python packages a library release will break, directly or through other packages, and prove each break before the release ships.

Work in progress for Graph Hacks (FalkorDB × WeMakeDevs), Track 01: agents that act on connected data.

## How it works

1. `breaks.py` diffs the old and new release with [griffe](https://mkdocstrings.github.io/griffe/). `scan.py --new` also scans the new release and marks each old library symbol with what the new release still has. A Cypher query then reads removed parameters straight off the graph. This graph diff catches parameters dropped from functions that still take `**kwargs`, which griffe misses. The same diff also lists functions, classes and names the new release dropped. Both lists are the union of the graph diff and griffe's, and each entry records which diff found it.
2. `scan.py` loads the source of the library and its dependents into a FalkorDB symbol graph:
   - nodes are `(:Sym {qn, kind, params, var_kw})`
   - edges are `ALIAS_OF {tc}`, `INHERITS`, `CTOR`, `CALLS {kws}` and `FORWARDS_KW`
3. `impact.py` holds the two Cypher queries:
   - `REACHES_REMOVED`: call sites whose keyword travels through aliases, constructors and `**kwargs` forwarding to a removed parameter.
   - `EXPOSED`: dependent code that reaches one of those call sites, possibly through another package.
4. `server.py` gives these queries to an agent as MCP tools, alongside read-only Cypher, source reading, text search and `run`. The agent is Claude Code, run headless with no other tools (`agent.py`, `prompt.md`).
5. The agent writes a reproduction and runs it against the old and new release, then writes a deprecation shim and verifies it. `runner.py` executes each run in Docker, with no network, a read-only filesystem and a time limit.
6. `agent.py verify` re-runs every claim in fresh containers instead of trusting the agent's report.

## Graph model

Every node is a `Sym`: a module, class, function or name binding in one of the scanned packages. Each is keyed by its full dotted name (`qn`) and labelled with its `kind`. Function nodes also record their parameter names (`params`) and whether they accept `**kwargs` (`var_kw`).

The library's nodes carry the new release's side of the diff:
- `in_new`: whether the symbol still exists in the new release.
- `new_params` and `new_var_kw`: the parameter names a function takes in the new release, and whether it still accepts `**kwargs` there.

| Edge | Meaning | Comes from |
|---|---|---|
| `ALIAS_OF {tc}` | This name refers to that symbol. `tc` is true when the binding exists only under `if TYPE_CHECKING:`. | `import x`, `from x import Y`, `A = B`, and star imports through `__all__`. |
| `INHERITS {i}` | Class → its `i`-th base class. | `class C(Base)` |
| `CTOR` | Class → the `__init__` that runs when the class is called. | The class's own `__init__`, or else its first base. |
| `CALLS {kws}` | Function or module → what it calls, with the keyword names written at the call. A module's calls are the code that runs when it is imported. | Every call the scanner can resolve. |
| `FORWARDS_KW` | Function → the callee it hands its own `**kwargs` to. | `g(**kwargs)` inside a function that takes `**kwargs`. |

**Why a graph.** A keyword travels. It is written at a call in one package, then passes through an alias, a class constructor and a `**kwargs` hand-off before landing in another package. Each of those steps is an edge. So "does this call reach the parameter the release removed?" is a path query, and so is "which code in my dependents reaches that call?", run in the other direction. Text search sees only the first step, and only if the keyword is written out.

The Cypher that answers these questions is listed in full under [Cypher used](#cypher-used).

**What the graph cannot see**, and therefore must be reported as unknown, never as safe:
- calls through `self` or other instances;
- base classes after the first;
- `**kwargs` built at runtime;
- imports that only exist at runtime, such as `requests.packages.urllib3` or `importlib` loading.

## Cypher used

Every query below is in `impact.py` or `scan.py`. The agent calls them through MCP tools; it can also send its own read-only queries (FalkorDB `GRAPH.RO_QUERY`) through the `cypher` tool.

**0. Which parameters did the release remove?** (`REMOVED_PARAMS`, used by tool `breaking_changes`)

```cypher
MATCH (f:Sym {kind: 'function'})
WHERE f.qn STARTS WITH $lib + '.' AND f.new_params IS NOT NULL
WITH f, [p IN f.params WHERE NOT p IN f.new_params AND NOT p IN ['self', 'cls']] AS gone
WHERE size(gone) > 0
UNWIND gone AS param
RETURN f.qn AS function, param, f.new_var_kw AS still_takes_kwargs
ORDER BY function, param
```

This is the graph's own diff of the two releases. It counts a parameter as removed even when the new signature still takes `**kwargs`. That `**kwargs` accepts the keyword only for it to fail further in, as with Werkzeug 2.1's `Client.open(as_tuple=)`.

**0b. Which functions, classes and names did the release remove?** (`REMOVED_NAMES`, used by tool `breaking_changes`)

```cypher
MATCH (s:Sym)
WHERE s.qn STARTS WITH $lib + '.' AND s.in_new = false AND s.kind IN ['function', 'class', 'alias', 'module']
RETURN s.qn AS name, s.kind AS kind
ORDER BY name
```

These are library symbols the new release no longer has: functions, classes, imported names and modules. Python then drops private paths, and drops the members of a parent removed with them. The list is joined with griffe's "Public object was removed". This is how MarkupSafe 2.1's `soft_unicode` is caught after the replay; griffe's diff missed it.

**0c. Who uses a removed name?** (`REACHES_NAME`, inside tool `impact_paths`)

```cypher
MATCH p = (site:Sym)-[:ALIAS_OF|CALLS|INHERITS]->(:Sym)-[:ALIAS_OF*0..12]->(r:Sym {qn: $name})
WHERE NOT site.qn STARTS WITH $pkg
  AND all(x IN relationships(p) WHERE type(x) <> 'ALIAS_OF' OR x.tc = false)
RETURN [n IN nodes(p) | n.qn] AS chain, [x IN relationships(p) | type(x)] AS hops
```

This finds sites outside the library that import, call or subclass a removed name, possibly through aliases. A site in another package reaches the dependent through query 2.

**1. Which call sites reach a removed parameter?** (`REACHES_REMOVED`, tool `impact_paths`)

```cypher
MATCH p = (caller:Sym)-[c:CALLS]->(:Sym)-[:ALIAS_OF|CTOR|FORWARDS_KW*0..12]->(f:Sym {qn: $fn})
WHERE $param IN c.kws
  AND NOT caller.qn STARTS WITH $pkg
  AND all(r IN relationships(p) WHERE type(r) <> 'ALIAS_OF' OR r.tc = false)
  AND all(n IN nodes(p)[1..] WHERE n.kind <> 'function' OR n.qn = $fn OR (n.var_kw AND NOT $param IN n.params))
RETURN [n IN nodes(p) | n.qn] AS chain, [r IN relationships(p) | type(r)] AS hops
```

`$fn` and `$param` come from griffe ("Parameter was removed"), and `$pkg` is the library's own prefix.
- A path starts with a call that writes the keyword, then follows up to 12 alias, constructor and `**kwargs` hops to the function that lost it.
- Every function on the way must accept `**kwargs` and not name the parameter itself. Otherwise it consumes the keyword and the path stops there.
- Aliases that exist only for type checkers are skipped.
- The library's own callers are excluded, because they ship in the same release.

**2. Which code in the dependent reaches such a call site?** (`EXPOSED`, tool `exposed_paths`)

```cypher
MATCH p = (site:Sym {qn: $site})<-[:CALLS|ALIAS_OF|CTOR*1..10]-(entry:Sym)
WHERE (entry.qn = $pkg OR entry.qn STARTS WITH $pkg + '.')
  AND all(r IN relationships(p) WHERE type(r) <> 'ALIAS_OF' OR r.tc = false)
WITH entry, p ORDER BY length(p)
WITH entry, collect(p)[0] AS p
RETURN reverse([n IN nodes(p) | n.qn]) AS chain, reverse([r IN relationships(p) | type(r)]) AS hops
LIMIT 50
```

It walks backwards from a call site found by query 1, up to 10 hops, into the dependent's package (`$pkg`), possibly through another package. It keeps the shortest path for each entry point. Module nodes are included, so code that runs on import counts as an entry point.

**3. Which calls can the graph not resolve?** (`UNRESOLVED`, tool `unknown_calls`)

```cypher
MATCH (caller:Sym)-[c:CALLS]->(:Sym)-[:ALIAS_OF*0..12]->(end:Sym {kind: 'ref'})
WHERE (caller.qn = $pkg OR caller.qn STARTS WITH $pkg + '.')
  AND any(k IN c.kws WHERE k IN $params)
  AND end.qn CONTAINS $lib
RETURN DISTINCT caller.qn AS caller, end.qn AS target, [k IN c.kws WHERE k IN $params] AS keywords
```

These are calls in the dependent that pass a removed keyword to a symbol the graph cannot resolve, but whose name mentions the library. A typical example is a vendored or runtime alias such as `requests.packages.urllib3`. They are reported as unknown and tested, never cleared.

**Loading** (`scan.py`): one index, then batched writes of 2,000 rows at a time.

```cypher
CREATE INDEX FOR (s:Sym) ON (s.qn)
UNWIND $rows AS r CREATE (s:Sym) SET s = r
UNWIND $rows AS r MATCH (a:Sym {qn: r.s}), (b:Sym {qn: r.d}) CREATE (a)-[e:CALLS]->(b) SET e = r.p
```

The last statement runs once per edge type.

## Example: httpx 0.28.0 breaks aisuite, which never mentions the removed keyword

```
aisuite.providers.anthropic_provider.AnthropicProvider.__init__
  -CALLS-> anthropic.Anthropic -ALIAS_OF-> anthropic._client.Anthropic -CTOR-> ...
  -> anthropic._base_client.SyncAPIClient.__init__
  -CALLS {kws: proxies}-> SyncHttpxClientWrapper -> ... -> _DefaultHttpxClient.__init__
  -FORWARDS_KW-> httpx.Client -ALIAS_OF-> httpx._client.Client -CTOR-> httpx._client.Client.__init__   (proxies removed in 0.28.0)
```

Results are in `runs/aisuite-anthropic-httpx-20261015-061427.*`:
- With httpx 0.27.2 the agent's reproduction passes.
- With 0.28.0 it fails with `TypeError: Client.__init__() got an unexpected keyword argument 'proxies'`, raised through aisuite's and anthropic's code.
- With the agent's shim it passes again.

## Demo: httpx 0.27.2 → 0.28.0 against six dependents

`python3 agent.py demo cases/openai-httpx.json cases/anthropic-httpx.json cases/aisuite-anthropic-httpx.json cases/langchain-openai-httpx.json cases/openai-1.55.3-httpx.json cases/openai-1.56.1-httpx.json` took 11 minutes on Oct 15.

For each dependent the graph decides first. If it finds a path, the agent investigates. If it finds none, the agent must show that the dependent still works on the new release.

| Dependent | Graph says | Agent | Verified in fresh containers |
|---|---|---|---|
| openai 1.55.2 | 3 direct paths | 3 breaks: sync client, async client, CLI | yes |
| anthropic 0.30.1 | 2 direct paths | 2 breaks: sync and async client | yes (after a verifier fix, see `runs/demo-20261015-065144.md`) |
| aisuite 0.1.6 | 2 indirect paths, through anthropic | 1 break | yes |
| langchain-openai 0.2.10 | 12 indirect paths, through openai | 2 breaks | yes |
| openai 1.55.3 (fixed the client) | 1 direct path: the CLI still passes `proxies` | 1 break: `openai --proxy … api models.list` | yes |
| openai 1.56.1 (also fixed the CLI) | no exposure found | control: clients and chat calls work on both releases | yes. The 1.55.3 CLI reproduction, re-run afterwards as a mechanical check, also passes on both. |

A text search of openai 1.55.3 for `proxies` returns 20 lines. The graph flagged one path among them, the CLI, and the agent confirmed it breaks. The other 19 lines were not tested one by one; some build `proxies` at runtime, which the graph cannot see. A text search of aisuite and langchain-openai for `proxies` returns nothing, yet both break; the graph found them through the packages they depend on.

## Run it

You need Docker, [uv](https://docs.astral.sh/uv/), the Claude Code CLI (logged in) and FalkorDB on port 6380:

```sh
docker run -d --name downstream-falkordb -p 6380:6379 falkordb/falkordb:latest
python3 agent.py cases/aisuite-anthropic-httpx.json setup   # griffe diff + graph
python3 agent.py cases/aisuite-anthropic-httpx.json run     # agent, then verification
uv run --python 3.12 --with falkordb python -m unittest test_downstream
```

`setup` downloads the package sources it reads from PyPI into `src/`, checks their published SHA-256 checksums, and unpacks them. Nothing is installed or run on your machine; the contained runs install packages inside Docker.

## Limits found by frozen tests

- Only removed parameters are traced. Every other change kind is listed as unsupported, never as safe.
- frameioclient on urllib3 2.0 was a graph miss. It imports `Retry` through `requests.packages`, which the scanner cannot resolve, and the agent found the break by text search.
- docker on requests 2.32 is an unsupported change class: an overridden method that the library stopped calling.
- The scanner resolves names, module attributes, `super().method()` calls and members reached through import aliases. It does not resolve calls through `self` or other instances, and it follows only the first base class.
- Removed functions, classes and names are now diffed too. But importing a module that itself imports a removed name is not linked, because there are no module-to-import edges, so a break that only travels through module imports can be missed.
- Every demo case comes from one incident: httpx 0.28.0 removing `proxies`. The scanner was first developed on the openai case.
- The graph only traces parameters that griffe reports as removed, and griffe misses some. The frozen replay set below shows two:
  - **`as_tuple`, dropped from Werkzeug 2.1's `Client.open`.** griffe did not list it. The new signature still ends in `**kwargs`, which is the likely reason.
  - **MarkupSafe 2.1's removal of `soft_unicode`.** griffe did not list it. In 2.0.1 the name was only imported into `markupsafe/__init__.py`, inside a try/except and with no `__all__`, so griffe most likely did not count it as public API.

## Frozen replay set (cases picked by an independent model, code locked before the run)

`runs/demo-20261015-194305.md`:

| Dependent | Graph says | Agent run | Re-run in fresh containers | Against the predeclared criterion |
|---|---|---|---|---|
| Flask 2.0.2 on Werkzeug 2.0.3 → 2.1.0 (known break) | no exposure: griffe did not list `as_tuple` as removed (the new signature still takes `**kwargs`) | exclusion test | fails on new: `TypeError: EnvironBuilder.__init__() got an unexpected keyword argument 'as_tuple'`, through Flask's test client | **fail** (graph miss; the break was caught and diagnosed, but no shim was written) |
| Flask 2.0.3 on the same release (known to be unaffected) | no exposure | exclusion test | holds: works on both | pass: no false alarm |
| Jinja2 2.11.3 on MarkupSafe 2.0.1 → 2.1.0 (break of another kind) | no exposure: griffe listed only a changed `__version__` | exclusion test | fails on new: `ImportError: cannot import name 'soft_unicode'` | pass: not falsely cleared |

In none of the three did the graph have anything to trace, because griffe's diff reported neither real break. The exclusion test is what told the two real breaks apart from the safe release, and in both broken cases the agent's notes named the cause. One improvement follows from this, still untested: when an exclusion test fails, hand the dependent to a full investigation, so it gets a diagnosis and a verified shim.

**After the replay, not counted as a pass.** The graph diff and the `super()` resolution were added after the replay, then re-run on the replay's cases. The two Werkzeug cases (`runs/demo-20261015-202725.md`):
- **Flask 2.0.2:** the graph diff lists `Client.open(as_tuple)`, and the graph has a path through `FlaskClient.open` → `super().open()`. The agent confirmed the break, and its shim passes. Every check passed when re-run in fresh containers.
- **Flask 2.0.3:** the same path is flagged. The agent showed that ordinary use works on both releases, and that only callers still passing the deprecated `as_tuple` break. It reported no break.

- **Jinja2 2.11.3** (`runs/demo-20261015-204649.md`): removed names were added later. With them, the graph diff lists `markupsafe.soft_unicode`, which griffe missed, and finds 13 places in Jinja2 that import or call it. The agent's reproduction runs ordinary Jinja2 code without naming `soft_unicode` itself. It fails on MarkupSafe 2.1 with an ImportError that names it, and the agent's shim, which puts the name back, passes. Every check passed in fresh containers.

These three runs are development evidence. A fresh frozen pick is needed before the graph diff can claim a pass.

## AI use (rule 11)

Claude (`claude-opus-5-5`, through Claude Code) wrote the code and this README at Femi's direction.
- Femi chose the project direction and gave the go-ahead for each test.
- Claude wrote each test's pass criteria into the project's notes before the test ran.
- The test cases were picked by an independent model, relayed by Femi.
- Claude suggested the six demo dependents and Femi approved them. openai 1.56.1 was added as the control after the graph showed that 1.55.3 still breaks.

At runtime the agent itself is Claude Code, restricted to DOWNSTREAM's tools.
