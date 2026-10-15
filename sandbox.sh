#!/bin/sh
# Prove a reported break: run one reproduction against the old release, the new release,
# and the new release plus a deprecation shim, each in a fresh uv environment.
# Usage: sandbox.sh <dependent==ver> <lib> <old_ver> <new_ver> <shim_file> <python_snippet>
set -u
dep=$1 lib=$2 old=$3 new=$4 shim=$5 snippet=$6
root=$(mktemp -d)
# Resolve the rest of the stack as it was when the new release shipped.
asof=$(curl -s "https://pypi.org/pypi/$lib/$new/json" | python3 -c 'import json,sys; import datetime as d; t=d.datetime.fromisoformat(json.load(sys.stdin)["urls"][0]["upload_time_iso_8601"].replace("Z","+00:00")); print((t+d.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')

run() { # name version [shim]
  env=$root/$1
  uv venv -q --python 3.12 "$env"
  uv pip install -q --python "$env/bin/python" --exclude-newer "$asof" "$dep" "$lib==$2"
  if [ $# -ge 3 ]; then
    cat "$3" >> "$("$env/bin/python" -c "import $lib, sys; sys.stdout.write($lib.__file__)")"
  fi
  if out=$("$env/bin/python" -c "$snippet" 2>&1); then
    echo "$1 ($lib $2): OK"
  else
    echo "$1 ($lib $2): FAIL -> $(printf '%s' "$out" | tail -1)"
  fi
}

echo "as-of: $asof"
run old "$old"
run new "$new"
run new+shim "$new" "$shim"
rm -rf "$root"
