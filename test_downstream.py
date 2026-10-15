"""Self-check on made-up packages: forwarded keywords reach a removed parameter, absorbed ones don't.

Needs FalkorDB on localhost:6380. Run: uv run --python 3.12 --with falkordb python -m unittest test_downstream
"""
import tempfile
import unittest
from pathlib import Path

import scan
from impact import EXPOSED, REACHES_NAME, REACHES_REMOVED, REMOVED_NAMES, REMOVED_PARAMS, UNRESOLVED, public_tops

FILES = {
    "lib/__init__.py": "from ._core import *\n",
    "lib/_core.py": "__all__ = ['Client']\nclass Client:\n    def __init__(self, *, timeout=None, gone=None): ...\n",
    "app/__init__.py": """
from typing import TYPE_CHECKING
import lib

class _Base(lib.Client):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

if TYPE_CHECKING:
    Default = lib.Client
else:
    Default = _Base

class Wrapper(Default):
    pass

class Absorbs(lib.Client):
    def __init__(self, gone=None, **kwargs):
        super().__init__(**kwargs)

class _Other:
    def __init__(self, **kwargs): ...

if TYPE_CHECKING:
    TypeOnly = lib.Client
else:
    TypeOnly = _Other

class OnlyTyped(TypeOnly):
    pass

def type_only():
    return OnlyTyped(gone=1)

def forwarded():
    return Wrapper(gone=1)

def absorbed():
    return Absorbs(gone=1)
""",
}


class ReachesRemoved(unittest.TestCase):
    def test_paths(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in FILES.items():
                (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / name).write_text(text)
            scan.nodes.clear(), scan.edges.clear()
            scan.scan([d])
            g = scan.load("downstream_selftest")

        def callers(param):
            rows = g.ro_query(REACHES_REMOVED, {"fn": "lib._core.Client.__init__", "param": param, "pkg": "lib."}).result_set
            return sorted(chain[0] for chain, _ in rows)

        # absorbed() stops at Absorbs.__init__; type_only() reaches lib only through a TYPE_CHECKING alias
        self.assertEqual(callers("gone"), ["app.forwarded"])
        self.assertEqual(callers("timeout"), [])
        g.delete()


EXPOSURE_FILES = {
    "lib/__init__.py": "class Client:\n    def __init__(self, *, gone=None): ...\n",
    "mid/__init__.py": """
import lib

class Wrapper(lib.Client):
    pass

def make():
    return Wrapper(gone=1)

def other():
    return None
""",
    "app/__init__.py": """
from mid import make as build
import mid

client = build()

def entry():
    return build()

def safe():
    return mid.other()
""",
}


class Exposure(unittest.TestCase):
    def test_reaches_site_in_another_package(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in EXPOSURE_FILES.items():
                (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / name).write_text(text)
            scan.nodes.clear(), scan.edges.clear()
            scan.scan([d])
            g = scan.load("downstream_selftest_exposure")
        sites = g.ro_query(REACHES_REMOVED, {"fn": "lib.Client.__init__", "param": "gone", "pkg": "lib."}).result_set
        self.assertEqual([chain[0] for chain, _ in sites], ["mid.make"])
        entries = {chain[0] for chain, _ in g.ro_query(EXPOSED, {"site": "mid.make", "pkg": "app"}).result_set}
        # the import-time call and the function reach it; app.safe calls something else
        self.assertTrue({"app", "app.entry"} <= entries, entries)
        self.assertNotIn("app.safe", entries)
        g.delete()

    def test_pure_reexport(self):
        files = {
            "lib/__init__.py": "class Client:\n    def __init__(self, *, gone=None): ...\n",
            "mid/__init__.py": "import lib\n\nclass Thing(lib.Client):\n    def __init__(self):\n        super().__init__(gone=1)\n",
            "app/__init__.py": "from mid import Thing as Thing\n",
        }
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / name).write_text(text)
            scan.nodes.clear(), scan.edges.clear()
            scan.scan([d])
            g = scan.load("downstream_selftest_reexport")
        rows = g.ro_query(EXPOSED, {"site": "mid.Thing.__init__", "pkg": "app"}).result_set
        self.assertEqual([chain for chain, _ in rows], [["app.Thing", "mid.Thing", "mid.Thing.__init__"]])
        g.delete()

    def test_unresolved_call_is_unknown(self):
        files = {"app/__init__.py": "from vendored.lib.retry import Retry\n\ndef make():\n    return Retry(gone=1)\n\n"
                                    "def other():\n    return dict(gone=1)\n"}
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / name).write_text(text)
            scan.nodes.clear(), scan.edges.clear()
            scan.scan([d])
            g = scan.load("downstream_selftest_unresolved")
        rows = g.ro_query(UNRESOLVED, {"pkg": "app", "params": ["gone"], "lib": "lib"}).result_set
        # the vendored alias is unknown; a builtin that happens to take the same keyword is not
        self.assertEqual(rows, [["app.make", "vendored.lib.retry.Retry", ["gone"]]])
        g.delete()

    def test_imported(self):
        from agent import imported
        # the dependent need not be the first name on the import line
        self.assertEqual(imported("import httpx, anthropic\nfrom openai.cli import _cli"), {"httpx", "anthropic", "openai"})
        self.assertEqual(imported("not python ("), set())

    def test_through_dependent(self):
        from agent import through_dependent
        case = {"dep_module": "app", "via_modules": ["mid"]}
        mid_only = 'File "/env/v/lib/python3.12/site-packages/mid/__init__.py", line 5'
        both = mid_only + '\nFile "/env/v/lib/python3.12/site-packages/app/x.py", line 2'
        self.assertTrue(through_dependent("import app", both, case))
        # a pure re-export runs no app frame: allowed only when the script never imports mid itself
        self.assertTrue(through_dependent("from app import Thing\nThing()", mid_only, case))
        self.assertFalse(through_dependent("import app, mid\nmid.Thing()", mid_only, case))
        self.assertFalse(through_dependent("import app", 'File "<string>", line 1', case))


class GraphDiff(unittest.TestCase):
    def test_removed_parameter_behind_kwargs_reached_through_super(self):
        old = "class Client:\n    def open(self, *args, as_tuple=False, **kwargs): ...\n    def keep(self, x=1): ...\n"
        new = "class Client:\n    def open(self, *args, **kwargs): ...\n    def keep(self, x=1): ...\n"
        app = ("from lib import Client\n\nclass Mine(Client):\n    def open(self, *args, as_tuple=False, **kwargs):\n"
               "        return super().open(*args, as_tuple=as_tuple, **kwargs)\n")
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            for root, files in ((old_dir, {"lib/__init__.py": old, "app/__init__.py": app}), (new_dir, {"lib/__init__.py": new})):
                for name, text in files.items():
                    (Path(root) / name).parent.mkdir(parents=True, exist_ok=True)
                    (Path(root) / name).write_text(text)
            released = scan.release(new_dir)
            scan.scan([old_dir])
            scan.mark_new("lib", released)
            g = scan.load("downstream_selftest_diff")
        # an API diff sees no removal here, because **kwargs still accepts the keyword
        self.assertEqual(g.ro_query(REMOVED_PARAMS, {"lib": "lib"}).result_set, [["lib.Client.open", "as_tuple", True]])
        rows = g.ro_query(REACHES_REMOVED, {"fn": "lib.Client.open", "param": "as_tuple", "pkg": "lib."}).result_set
        self.assertEqual([chain for chain, _ in rows], [["app.Mine.open", "lib.Client.open"]])
        g.delete()


class RemovedNames(unittest.TestCase):
    def test_removed_names_and_who_uses_them(self):
        old = ("def soft_str(s):\n    return s\n\ndef soft_unicode(s):\n    return s\n\n"
               "class Gone:\n    def m(self): ...\n\ndef _private(): ...\n")
        new = "def soft_str(s):\n    return s\n"
        app = ("from lib import soft_unicode\nimport lib\n\nclass Mine(lib.Gone):\n    pass\n\n"
               "def fine(x):\n    return lib.soft_str(x)\n")
        with tempfile.TemporaryDirectory() as old_dir, tempfile.TemporaryDirectory() as new_dir:
            for root, files in ((old_dir, {"lib/__init__.py": old, "app/__init__.py": app}), (new_dir, {"lib/__init__.py": new})):
                for name, text in files.items():
                    (Path(root) / name).parent.mkdir(parents=True, exist_ok=True)
                    (Path(root) / name).write_text(text)
            released = scan.release(new_dir)
            scan.scan([old_dir])
            scan.mark_new("lib", released)
            g = scan.load("downstream_selftest_names")
        names = [n for n, _ in g.ro_query(REMOVED_NAMES, {"lib": "lib"}).result_set]
        self.assertEqual(names, ["lib.Gone", "lib.Gone.m", "lib._private", "lib.soft_unicode"])
        # report public names only, and a removed class without its methods
        self.assertEqual(public_tops(names, "lib"), ["lib.Gone", "lib.soft_unicode"])
        sites = lambda n: sorted(c[0] for c, _ in g.ro_query(REACHES_NAME, {"name": n, "pkg": "lib."}).result_set)
        self.assertEqual(sites("lib.soft_unicode"), ["app.soft_unicode"])  # the import itself
        self.assertEqual(sites("lib.Gone"), ["app.Mine"])  # the subclass
        g.delete()


class SummaryRow(unittest.TestCase):
    def test_rows_never_read_as_safe_without_saying_what_was_not_analysed(self):
        from agent import summary_row
        none = {"direct": 0, "exposed": 0, "unknown": 0}
        ok = {"imports the dependent": True, "has an assertion": True, "old passes": True}
        holds = {"control": {**ok, "new passes": True}}
        fails = {"control": {**ok, "new passes": False}}
        stuck = {"control": {**ok, "old passes": False, "new passes": False}}
        self.assertEqual(summary_row("b==1", none, 0, holds),
                         "| b==1 | no exposure found | behaviour changes | exclusion test | holds: works on both |")
        self.assertIn("FAILS on new", summary_row("b==1", none, 3, fails))
        self.assertIn("3 other API changes", summary_row("b==1", none, 3, fails))
        self.assertIn("inconclusive", summary_row("b==1", none, 0, stuck))
        self.assertIn("no report from the agent", summary_row("b==1", none, 0, None))
        found = {"unsupported kinds all listed": True, "finding 0: f(x=)": {"old passes": True, "new+shim passes": False}}
        self.assertIn("1 break(s) reported | NOT all confirmed", summary_row("b==1", {**none, "direct": 2}, 0, found))


class Readme(unittest.TestCase):
    def test_cypher_in_readme_matches_code(self):
        import impact
        readme = (Path(__file__).parent / "README.md").read_text()
        for name in ("REMOVED_PARAMS", "REMOVED_NAMES", "REACHES_REMOVED", "REACHES_NAME", "EXPOSED", "UNRESOLVED"):
            self.assertIn(getattr(impact, name).strip(), readme, name)


class FinalReport(unittest.TestCase):
    def test_last_json(self):
        from agent import last_json
        # the report is the object that ends the message, even after an earlier object and inside a fence
        self.assertEqual(last_json('saw {"a": 1} then\n```json\n{"b": {"c": 2}}\n```'), {"b": {"c": 2}})
        self.assertIsNone(last_json('{"a": 1} trailing prose'))

    def test_passes_param(self):
        from agent import passes_param
        self.assertTrue(passes_param("f(gone=1)", "gone"))
        self.assertTrue(passes_param("f(**{'gone': 1})", "gone"))
        # naming it in a string, such as an expected warning, is not passing it
        self.assertFalse(passes_param("assert 'gone' in str(w)", "gone"))

    def test_uses_name(self):
        from agent import uses_name
        self.assertTrue(uses_name("from markupsafe import soft_unicode", "soft_unicode"))
        self.assertTrue(uses_name("import markupsafe\nmarkupsafe.soft_unicode('x')", "soft_unicode"))
        # mentioning it in a string, such as an expected error message, is not using it
        self.assertFalse(uses_name("import jinja2\nassert 'soft_unicode' not in str(e)", "soft_unicode"))


if __name__ == "__main__":
    unittest.main()
