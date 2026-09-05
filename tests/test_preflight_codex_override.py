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

def _detect(tmp_path, toml):
    home = tmp_path / "codex"; home.mkdir(); (home / "config.toml").write_text(toml)
    r = subprocess.run(["bash", "-c", f"source '{PREFLIGHT}'; codex_write_override"],
                       capture_output=True, text=True, cwd=str(tmp_path),   # never pytest's cwd: ./.codex/config.toml is a search path
                       env={"CODEX_HOME": str(home), "HOME": str(tmp_path), "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

@pytest.mark.parametrize("label,toml", CASES.items(), ids=list(CASES))
def test_every_loosening_spelling_is_detected(tmp_path, label, toml):
    assert _detect(tmp_path, toml) == "yes", label

@pytest.mark.parametrize("label,toml", KEEPS.items(), ids=list(KEEPS))
def test_intact_gates_are_not_flagged(tmp_path, label, toml):
    assert _detect(tmp_path, toml) == "no", label
