# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""#139: preflight's 'did someone locally loosen the Codex approval mode on dismiss/close' check must see
every TOML spelling Codex accepts, and must not fire on a config that keeps the gate."""
import subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT = ROOT / "plugin" / "preflight.sh"

CASES = {
    "section header":           "[mcp_servers.exabeam.tools.exabeam_update_alert]\napproval_mode = \"never\"\n",
    "dotted key under server":  "[mcp_servers.exabeam]\ntools.exabeam_update_case.approval_mode = \"never\"\n",
    "fully dotted key":         "mcp_servers.exabeam.tools.exabeam_update_alert.approval_mode = \"never\"\n",
    "inline table":             "[mcp_servers.exabeam]\ntools = { exabeam_update_alert = { approval_mode = \"never\" } }\n",
    "inline, sibling approves": "[mcp_servers.exabeam]\ntools = { exabeam_search_alerts = { approval_mode = \"approve\" }, exabeam_update_case = { approval_mode = \"never\" } }\n",
    "inline, gated sibling approves": "[mcp_servers.exabeam]\ntools = { exabeam_update_alert = { approval_mode = \"approve\" }, exabeam_update_case = { approval_mode = \"never\" } }\n",
    "inline, nested table first": "tools = { exabeam_update_alert = { extra = { a = 1 }, approval_mode = \"never\" } }\n",
    "single-quoted never":       "[mcp_servers.exabeam.tools.exabeam_update_case]\napproval_mode = 'never'\n",
    "quoted key, sibling approves": 'tools = { "exabeam_update_case" = { approval_mode = "never" }, "other" = { approval_mode = "approve" } }\n',
    "quoted key, no spaces":     'tools = {"exabeam_update_case"={approval_mode="never"},"o"={approval_mode="approve"}}\n',
    "quoted key, section header": '[mcp_servers.exabeam.tools."exabeam_update_alert"]\napproval_mode = "never"\n',
    "mode auto":                 "[mcp_servers.exabeam.tools.exabeam_update_alert]\napproval_mode = \"auto\"\n",
}
KEEPS = {
    "section header, approve":  "[mcp_servers.exabeam.tools.exabeam_update_alert]\napproval_mode = \"approve\"\n",
    "dotted, approve":          "mcp_servers.exabeam.tools.exabeam_update_case.approval_mode = \"approve\"\n",
    "other tool loosened":      "[mcp_servers.exabeam.tools.exabeam_search_alerts]\napproval_mode = \"never\"\n",
    "no override at all":       "[mcp_servers.exabeam]\ndefault_tools_approval_mode = \"approve\"\n",
    "comment only":             "# note: exabeam_update_alert approval_mode should stay at approve\n",
    "single-quoted approve":    "[mcp_servers.exabeam.tools.exabeam_update_alert]\napproval_mode = 'approve'\n",
    "both gated tools approve": "tools = { exabeam_update_alert = { approval_mode = \"approve\" }, exabeam_update_case = { approval_mode = 'approve' } }\n",
}

import os, sys, shutil

# Two engines: the TOML parser (python3 with tomllib on PATH -- the pytest interpreter) and the awk
# fallback (PATH restricted to the system's, where a python3 without tomllib or none at all lives).
# Every fixture must give the same answer through both.
def _paths():
    engines = {"awk-fallback": "/usr/bin:/bin"}
    if sys.version_info >= (3, 11):
        engines["tomllib"] = os.path.dirname(sys.executable) + os.pathsep + "/usr/bin:/bin"
    return engines

def _detect(tmp_path, toml, path):
    home = tmp_path / "codex"; home.mkdir(exist_ok=True); (home / "config.toml").write_text(toml)
    r = subprocess.run(["bash", "-c", f"source '{PREFLIGHT}'; codex_write_override"],
                       capture_output=True, text=True, cwd=str(tmp_path),   # never pytest's cwd: ./.codex/config.toml is a search path
                       env={"CODEX_HOME": str(home), "HOME": str(tmp_path), "PATH": path})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def _engine_is_awk(path):
    py = shutil.which("python3", path=path)
    if not py:
        return True
    return subprocess.run([py, "-c", "import tomllib"], capture_output=True).returncode != 0

@pytest.mark.parametrize("engine", list(_paths()))
@pytest.mark.parametrize("label,toml", CASES.items(), ids=list(CASES))
def test_every_loosening_spelling_is_detected(tmp_path, label, toml, engine):
    assert _detect(tmp_path, toml, _paths()[engine]) == "yes", (label, engine)

@pytest.mark.parametrize("engine", list(_paths()))
@pytest.mark.parametrize("label,toml", KEEPS.items(), ids=list(KEEPS))
def test_intact_gates_are_not_flagged(tmp_path, label, toml, engine):
    assert _detect(tmp_path, toml, _paths()[engine]) == "no", (label, engine)

def test_the_parser_engine_is_actually_exercised():
    """The tomllib path must be what the pytest interpreter runs; if this ever skips silently the quoted-key
    class of bug is only covered by the regex fallback."""
    assert "tomllib" in _paths(), "pytest must run on 3.11+ so the parser engine is tested"
    assert not _engine_is_awk(_paths()["tomllib"])

@pytest.mark.parametrize("engine", list(_paths()))
def test_a_file_that_does_not_parse_is_unverifiable_never_on(tmp_path, engine):
    """Review 2026-09-06: the fourth regex bypass in this function. Parsing is the fix; a file the parser
    rejects is reported as 'cannot verify', which preflight shows as a warning, never as gate ON."""
    out = _detect(tmp_path, "[mcp_servers.exabeam\ntools = { exabeam_update_case = { approval_mode = never } }\n", _paths()[engine])
    if engine == "tomllib":
        assert out == "unverifiable"
    else:
        assert out in ("yes", "unverifiable"), "the fallback may not parse, but it must not say the gate holds"
