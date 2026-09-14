# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""preflight.sh's credentials check mirrors the bridge's transport rule (#174): https required, plain http
to a loopback host tolerated, anything else is a FAIL that names the value -- before the bridge is started.
Deterministic: the function is sourced and called with a temp credentials file; nothing is connected to."""
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT = ROOT / "plugin" / "preflight.sh"


def _check(tmp_path, url):
    env = tmp_path / "creds.env"
    env.write_text(f"EXABEAM_MCP_URL={url}\nEXABEAM_API_KEY=k\nEXABEAM_API_SECRET=s\n")
    script = textwrap.dedent(f"""
        source '{PREFLIGHT}'
        ok()   {{ echo "OK: $1"; }}
        warn() {{ echo "WARN: $1"; }}
        fail() {{ echo "FAIL: $1"; }}
        ENV_FILE='{env}'
        check_credentials
        echo "CREDS_OK=$CREDS_OK"
    """)
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.mark.parametrize("url", [
    "https://api.us-west.exabeam.cloud/mcp",
    "https://mcp.internal.example:8443/mcp",
    "http://127.0.0.1:8765/mcp",
    "http://localhost:8765/mcp",
    "http://[::1]:8765/mcp",
])
def test_preflight_accepts_https_and_loopback_http(tmp_path, url):
    out = _check(tmp_path, url)
    assert "CREDS_OK=1" in out and "OK: Credentials" in out and "FAIL" not in out, out


@pytest.mark.parametrize("url, expect", [
    ("http://api.us-west.exabeam.cloud/mcp", "in the clear"),
    ("http://127.0.0.1.evil.example/mcp", "in the clear"),
    ("ftp://api.us-west.exabeam.cloud/mcp", "must start with https://"),
    ("api.us-west.exabeam.cloud/mcp", "must start with https://"),
])
def test_preflight_fails_cleartext_before_the_bridge_starts(tmp_path, url, expect):
    out = _check(tmp_path, url)
    assert "CREDS_OK=0" in out and "FAIL: EXABEAM_MCP_URL" in out and expect in out, out
