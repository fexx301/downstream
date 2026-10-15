"""List breaking API changes between two unpacked versions of a package, as JSON.

Usage: python breaks.py <package> <old_dir> <new_dir>
"""
import json
import sys

import griffe


def load(package, path):
    # A fresh loader per version, so the two versions don't share griffe's module cache.
    return griffe.GriffeLoader(search_paths=[path]).load(package)


def canonical(obj):
    try:
        return obj.canonical_path
    except griffe.AliasResolutionError:
        return obj.path  # an alias into a module griffe did not load, such as the stdlib


def main(package, old_dir, new_dir):
    old, new = load(package, old_dir), load(package, new_dir)
    out = []
    for b in griffe.find_breaking_changes(old, new):
        out.append({
            "kind": b.kind.value,
            "path": b.obj.path,
            "canonical": canonical(b.obj),
            "name": getattr(b.old_value, "name", None),
            "explain": b.explain(),
        })
    json.dump(out, sys.stdout, indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:4])
