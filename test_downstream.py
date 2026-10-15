"""Self-check on made-up packages: forwarded keywords reach a removed parameter, absorbed ones don't.

Needs FalkorDB on localhost:6380. Run: uv run --python 3.12 --with falkordb python -m unittest test_downstream
"""
import tempfile
import unittest
from pathlib import Path

import scan
from impact import EXPOSED, REACHES_REMOVED

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


if __name__ == "__main__":
    unittest.main()
