"""For each removed parameter griffe reports, find call sites whose keyword reaches it.

Usage: python impact.py <graph> <breaks.json>
"""
import json
import sys

from falkordb import FalkorDB

# A keyword passed at a call site travels through runtime aliases, constructor lookup and
# **kwargs forwarding. It stops at the first function that names it, so every function on
# the way must take **kwargs and not name it; the function that lost it ends the path.
REACHES_REMOVED = """
MATCH p = (caller:Sym)-[c:CALLS]->(:Sym)-[:ALIAS_OF|CTOR|FORWARDS_KW*0..12]->(f:Sym {qn: $fn})
WHERE $param IN c.kws
  AND NOT caller.qn STARTS WITH $pkg
  AND all(r IN relationships(p) WHERE type(r) <> 'ALIAS_OF' OR r.tc = false)
  AND all(n IN nodes(p)[1..] WHERE n.kind <> 'function' OR n.qn = $fn OR (n.var_kw AND NOT $param IN n.params))
RETURN [n IN nodes(p) | n.qn] AS chain, [r IN relationships(p) | type(r)] AS hops
"""

# Parameters a library function takes in the old release but not in the new one, read off the graph's own
# diff of the two releases (scan.py --new). Unlike an API diff, it still counts a parameter as removed when
# the new signature takes **kwargs, which accepts the keyword only to fail further in.
REMOVED_PARAMS = """
MATCH (f:Sym {kind: 'function'})
WHERE f.qn STARTS WITH $lib + '.' AND f.new_params IS NOT NULL
WITH f, [p IN f.params WHERE NOT p IN f.new_params AND NOT p IN ['self', 'cls']] AS gone
WHERE size(gone) > 0
UNWIND gone AS param
RETURN f.qn AS function, param, f.new_var_kw AS still_takes_kwargs
ORDER BY function, param
"""

# Library symbols the new release no longer has, from the same diff: functions, classes, names and
# modules. A dependent that imports, calls or subclasses one of them breaks.
REMOVED_NAMES = """
MATCH (s:Sym)
WHERE s.qn STARTS WITH $lib + '.' AND s.in_new = false AND s.kind IN ['function', 'class', 'alias', 'module']
RETURN s.qn AS name, s.kind AS kind
ORDER BY name
"""

# Sites outside the library that import, call or subclass a removed name, possibly through aliases.
REACHES_NAME = """
MATCH p = (site:Sym)-[:ALIAS_OF|CALLS|INHERITS]->(:Sym)-[:ALIAS_OF*0..12]->(r:Sym {qn: $name})
WHERE NOT site.qn STARTS WITH $pkg
  AND all(x IN relationships(p) WHERE type(x) <> 'ALIAS_OF' OR x.tc = false)
RETURN [n IN nodes(p) | n.qn] AS chain, [x IN relationships(p) | type(x)] AS hops
"""


def public_tops(names, lib):
    """Removed names worth reporting: public paths only, and not the members of a parent removed with them."""
    def private(qn):
        return any(s.startswith("_") and not s.endswith("__") for s in qn[len(lib) + 1:].split("."))
    kept = sorted(n for n in names if not private(n))
    gone = set(kept)
    return [n for n in kept if not any(n.startswith(p + ".") for p in gone if p != n)]


# Code in package $pkg that reaches a call site (found above) in another package: through calls,
# runtime aliases (imports included) and constructor lookup. Shortest witness path per entry point.
EXPOSED = """
MATCH p = (site:Sym {qn: $site})<-[:CALLS|ALIAS_OF|CTOR*1..10]-(entry:Sym)
WHERE (entry.qn = $pkg OR entry.qn STARTS WITH $pkg + '.')
  AND all(r IN relationships(p) WHERE type(r) <> 'ALIAS_OF' OR r.tc = false)
WITH entry, p ORDER BY length(p)
WITH entry, collect(p)[0] AS p
RETURN reverse([n IN nodes(p) | n.qn]) AS chain, reverse([r IN relationships(p) | type(r)]) AS hops
LIMIT 50
"""

# Calls in package $pkg that pass a removed keyword to a symbol the graph cannot resolve (a ref, possibly
# behind aliases) whose name mentions the library, such as a vendored or runtime alias: unknown, not safe.
UNRESOLVED = """
MATCH (caller:Sym)-[c:CALLS]->(:Sym)-[:ALIAS_OF*0..12]->(end:Sym {kind: 'ref'})
WHERE (caller.qn = $pkg OR caller.qn STARTS WITH $pkg + '.')
  AND any(k IN c.kws WHERE k IN $params)
  AND end.qn CONTAINS $lib
RETURN DISTINCT caller.qn AS caller, end.qn AS target, [k IN c.kws WHERE k IN $params] AS keywords
"""


def main(graph, breaks_path):
    g = FalkorDB(host="localhost", port=6380).select_graph(graph)
    removed = [b for b in json.load(open(breaks_path)) if b["kind"] == "Parameter was removed"]
    for b in removed:
        # The changed package's own callers are updated in the same release; only dependents count.
        pkg = b["canonical"].partition(".")[0] + "."
        rows = g.ro_query(REACHES_REMOVED, {"fn": b["canonical"], "param": b["name"], "pkg": pkg}).result_set
        print(f"\n{b['canonical']}({b['name']}=) removed: {len(rows)} call path(s)")
        for chain, hops in rows:
            print("  " + chain[0])
            for hop, qn in zip(hops, chain[1:]):
                print(f"    -[{hop}]-> {qn}")


if __name__ == "__main__":
    main(*sys.argv[1:3])
