"""Run a Python snippet against one version of a library, contained in Docker.

Installing (network on, no snippet runs) and running (no network, read-only, limited) use separate
containers, so code an agent writes never runs with network access or outside a container.
"""
import hashlib
import json
import subprocess
import uuid

CACHE = "ds-uv-cache"  # docker volume shared by installs


def image(python):
    return f"ghcr.io/astral-sh/uv:python{python}-bookworm-slim"


def docker(*args, input=None, timeout=900):
    return subprocess.run(["docker", *args], capture_output=True, text=True, input=input, timeout=timeout)


def env(case, version, shim=None, fresh=False):
    """Volume holding a venv with the dependent and lib==version (+ shim appended to the lib's __init__.py)."""
    spec = [case["python"], case["asof"], case["dep"], *case.get("pins", []), case["lib"], version, shim or ""]
    key = uuid.uuid4().hex if fresh else hashlib.sha256(json.dumps(spec).encode()).hexdigest()
    vol = "ds-env-" + key[:12]
    if not fresh and docker("volume", "inspect", vol).returncode == 0:
        return vol, None
    script = ('uv venv -q --python /usr/local/bin/python3 /env/v && '
              'uv pip install -q --python /env/v/bin/python --exclude-newer "$ASOF" "$DEP" $PINS "$LIB==$VER"')
    if shim:
        script += ' && cat >> "$(ls /env/v/lib/python*/site-packages/$MOD/__init__.py)"'
    r = docker("run", "--rm", "-i", "-v", f"{CACHE}:/root/.cache/uv", "-v", f"{vol}:/env",
               "-e", f"ASOF={case['asof']}", "-e", f"DEP={case['dep']}", "-e", f"LIB={case['lib']}",
               "-e", f"VER={version}", "-e", f"MOD={case['lib_module']}", "-e", f"PINS={' '.join(case.get('pins', []))}",
               image(case["python"]), "sh", "-c", script, input=shim or "")
    if r.returncode:
        docker("volume", "rm", vol)
        return None, r.stderr[-2000:]
    return vol, None


def run(case, version, code, shim=None, fresh=False, timeout=60):
    """Outcome of `python -I -c code`: pass, fail, timeout or install_error, with output tails."""
    vol, err = env(case, version, shim, fresh)
    if not vol:
        return {"outcome": "install_error", "detail": err}
    try:
        r = docker("run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                   "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
                   "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{vol}:/env:ro",
                   image(case["python"]), "timeout", str(timeout), "/env/v/bin/python", "-I", "-c", code,
                   timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout"}
    finally:
        if fresh:
            docker("volume", "rm", vol)
    outcome = {0: "pass", 124: "timeout"}.get(r.returncode, "fail")
    return {"outcome": outcome, "exit": r.returncode, "stdout": r.stdout[-1500:], "stderr": r.stderr[-12000:]}
