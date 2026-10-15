# DOWNSTREAM

Find which Python packages a library release will break, directly or through other packages, and prove each break before the release ships.

Work in progress for Graph Hacks (FalkorDB × WeMakeDevs), Track 01: agents that act on connected data.

## How it works

1. `breaks.py` diffs the old and new release with [griffe](https://mkdocstrings.github.io/griffe/) and lists removed parameters.
2. `scan.py` loads the source of the library and its dependents into a FalkorDB symbol graph:
   - nodes are `(:Sym {qn, kind, params, var_kw})`
   - edges are `ALIAS_OF {tc}`, `INHERITS`, `CTOR`, `CALLS {kws}` and `FORWARDS_KW`
3. `impact.py` holds the two Cypher queries:
   - `REACHES_REMOVED`: call sites whose keyword travels through aliases, constructors and `**kwargs` forwarding to a removed parameter.
   - `EXPOSED`: dependent code that reaches one of those call sites, possibly through another package.
4. `server.py` gives these queries to an agent as MCP tools, alongside read-only Cypher, source reading, text search and `run`. The agent is Claude Code, run headless with no other tools (`agent.py`, `prompt.md`).
5. The agent writes a reproduction and runs it against the old and new release, then writes a deprecation shim and verifies it. `runner.py` executes each run in Docker, with no network, a read-only filesystem and a time limit.
6. `agent.py verify` re-runs every claim in fresh containers instead of trusting the agent's report.

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

## Run it

You need Docker, [uv](https://docs.astral.sh/uv/), the Claude Code CLI (logged in) and FalkorDB on port 6380:

```sh
docker run -d --name downstream-falkordb -p 6380:6379 falkordb/falkordb:latest
python3 agent.py cases/aisuite-anthropic-httpx.json setup   # griffe diff + graph
python3 agent.py cases/aisuite-anthropic-httpx.json run     # agent, then verification
uv run --python 3.12 --with falkordb python -m unittest test_downstream
```

`setup` expects the unpacked package sources under `src/`; a fetch step is still to be added.

## Limits found by frozen tests

- Only removed parameters are traced. Every other change kind is listed as unsupported, never as safe.
- frameioclient on urllib3 2.0 was a graph miss. It imports `Retry` through `requests.packages`, which the scanner cannot resolve, and the agent found the break by text search.
- docker on requests 2.32 is an unsupported change class: an overridden method that the library stopped calling.
- The scanner resolves names and module attributes, not calls through `self` or instances, and it follows only the first base class.

## AI use (rule 11)

Claude (`claude-opus-5-5`, through Claude Code) wrote the code in this repository at Femi's direction. Femi chose the direction, approved each test's pass criteria before it ran, and had the test cases picked by an independent model. Femi reviews the code. At runtime the agent itself is Claude Code, restricted to DOWNSTREAM's tools.
