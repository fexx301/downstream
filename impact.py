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
