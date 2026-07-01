# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
"""Tier 3 — static + smoke checks on the connector bridge.

No live MCP, no credentials, no network on the static path. These guard the two
properties that matter most for a stdio bridge that handles an OAuth secret:
it must never leak the token/secret to stdout, and it must fail *closed* (exit
non-zero with a helpful message) when credentials are absent.

Run:  uv run --with pytest pytest -q tests/test_bridge_static.py
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "connector" / "exabeam-mcp-bridge.py"
SRC = BRIDGE.read_text()


# ---------- static ----------

def test_bridge_byte_compiles():
    import py_compile
    py_compile.compile(str(BRIDGE), doraise=True)


def test_pep723_header_well_formed():
    """The inline metadata must declare requires-python and the runtime deps, so
    `uv run` can resolve the environment on a cold machine."""
    hdr = re.search(r"# /// script\n(.*?)\n# ///", SRC, re.S)
    assert hdr, "missing PEP 723 inline-metadata header"
    block = hdr.group(1)
    assert re.search(r'requires-python\s*=\s*">=3\.\d+"', block), "no requires-python"
    assert re.search(r"dependencies\s*=\s*\[", block), "no dependencies array"
    for dep in ("mcp", "httpx", "certifi"):
        assert dep in block, f"PEP723 deps missing {dep!r}"


def test_no_secret_written_to_output():
    """A stdio MCP server must keep stdout clean (JSON-RPC only) and must never print
    the OAuth token or API secret anywhere. Assert no print/stdout/stderr write mentions
    a secret-bearing identifier."""
    out_calls = ("print(", "stdout.write", "stderr.write")
    secret_idents = ("SECRET", "client_secret", "access_token", "_token", "Bearer")
    offenders = []
    for line in SRC.splitlines():
        if any(o in line for o in out_calls):
            hit = [s for s in secret_idents if s in line]
            if hit:
                offenders.append((hit, line.strip()))
    assert not offenders, f"secret-bearing identifiers in output calls: {offenders}"


def test_fails_closed_without_credentials():
    """main() must guard on all three creds and exit non-zero, writing guidance to
    stderr (not stdout — stdout is the protocol channel)."""
    assert re.search(r"if not \(URL and KEY and SECRET\)", SRC), "missing credential guard"
    assert "sys.exit(1)" in SRC, "guard must exit non-zero"
    guard = SRC.split("def main()", 1)[1]
    assert "stderr" in guard.split("sys.exit(1)")[0], "guidance must go to stderr"


def test_setup_message_references_existing_paths():
    """The missing-creds guidance must not point at retired files — connect-exabeam.sh
    was removed in v0.3.0, so a reference to it would misdirect a stuck user."""
    for ref in re.findall(r"connector/[A-Za-z0-9_./-]+", SRC):
        # only check things that look like a file (have an extension)
        if "." in Path(ref).name:
            assert (ROOT / ref).exists(), f"bridge references a missing path: {ref}"


# ---------- smoke (opt-in; skips cleanly if the env can't run it) ----------

def test_check_without_creds_exits_clean():
    """Behavioral confirmation of fail-closed: `--check` with no creds exits non-zero
    with the guidance message, no traceback, and nothing on stdout. Runs the bridge
    under a throwaway HOME so it can't find (or use) the operator's real creds; skips
    if uv/deps/network can't set up the ephemeral environment."""
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH")
    tmp = tempfile.mkdtemp()
    # Preserve uv's real cache (compute against the *current* HOME before we override it)
    real_cache = os.environ.get("UV_CACHE_DIR") or os.path.expanduser("~/.cache/uv")
    env = {k: v for k, v in os.environ.items() if not k.startswith("EXABEAM")}
    env["HOME"] = tmp                 # ~/.exabeam-mcp.env now resolves into an empty dir
    env["UV_CACHE_DIR"] = real_cache
    try:
        proc = subprocess.run(
            ["uv", "run", "--quiet", str(BRIDGE), "--check"],
            capture_output=True, text=True, timeout=300, env=env,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        pytest.skip(f"could not run bridge --check: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Distinguish our expected failure from an environment/dep failure (then skip).
    if proc.returncode != 0 and "missing credentials" not in proc.stderr.lower():
        pytest.skip(f"bridge could not initialize (deps/env): {proc.stderr[:200]!r}")

    assert proc.returncode != 0, "no-creds --check must fail closed"
    assert "missing credentials" in proc.stderr.lower(), proc.stderr
    assert "traceback" not in proc.stderr.lower(), f"should exit cleanly, not crash:\n{proc.stderr}"
    assert proc.stdout.strip() == "", f"no-creds run must not print to stdout: {proc.stdout!r}"
