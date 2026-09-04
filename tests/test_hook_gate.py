# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The bundled PreToolUse gate (plugin/hooks/gate.py): the one control on Claude Code that is active on
install and survives --dangerously-skip-permissions. Pinned here: its decisions per tier, its fail-safe
posture, that it reads the SAME tiers the permission snippet ships, and that the manifest actually
declares it (a hook that isn't declared is a file, not a gate)."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
HOOK = PLUGIN / "hooks" / "gate.py"
HOOKS_JSON = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
SNIPPET = json.loads((PLUGIN / "skills" / "soc-investigate" / "settings.snippet.json").read_text())["permissions"]


def run_hook(tool_name, stdin=None, env=None):
    e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "SOCXEN_GATE_LOG": "off", **(env or {})}
    r = subprocess.run([sys.executable, str(HOOK)], input=stdin if stdin is not None else json.dumps({"tool_name": tool_name}),
                       capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"]


def bare(t): return t.rsplit("__", 1)[-1]


def test_manifest_declares_the_hook():
    pj = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert pj.get("hooks") == "./hooks/hooks.json"
    assert (PLUGIN / "hooks" / "hooks.json").is_file() and HOOK.is_file()


def test_matcher_covers_every_way_the_server_can_be_named():
    m = re.compile(HOOKS_JSON["hooks"]["PreToolUse"][0]["matcher"])
    for name in ("mcp__plugin_socxen_exabeam__exabeam_update_alert",   # bundled, upstream key
                 "mcp__plugin_soc_exabeam__exabeam_update_alert",      # bundled, a vendor catalog's key
                 "mcp__exabeam__exabeam_update_alert"):                # manually wired (#86)
        assert m.search(name), name
    assert not m.search("mcp__github__create_issue"), "must not gate other servers"
    assert not m.search("Bash"), "must not gate built-in tools"


@pytest.mark.parametrize("prefix", ["mcp__plugin_socxen_exabeam__", "mcp__plugin_soc_exabeam__", "mcp__exabeam__"])
def test_decisions_match_the_shipped_tiers_under_every_prefix(prefix):
    for tier, expected in (("deny", "deny"), ("ask", "ask"), ("allow", "allow")):
        for rule in SNIPPET[tier]:
            out = run_hook(prefix + bare(rule))
            assert out["permissionDecision"] == expected, (tier, rule, out)


def test_dismiss_and_close_ask_and_containment_denies():
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_update_alert")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_update_case")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_isolate_host")["permissionDecision"] == "deny"
    assert run_hook("mcp__plugin_socxen_exabeam__isolate_host")["permissionDecision"] == "deny"


def test_unclassified_tool_asks_instead_of_inheriting_the_session_default():
    """The Codex map's `default_tools_approval_mode: approve` equivalent — a tool the remote MCP grew
    that nobody classified (e.g. exabeam_create_analytics_rule, #143) must not run unattended."""
    out = run_hook("mcp__plugin_socxen_exabeam__exabeam_create_analytics_rule")
    assert out["permissionDecision"] == "ask" and "not classified" in out["permissionDecisionReason"]


def test_never_fails_open():
    assert run_hook("", stdin="not json")["permissionDecision"] == "ask"
    assert run_hook("", stdin="{}")["permissionDecision"] == "ask"
    # tiers unreadable (bogus plugin root) -> ask, never allow
    out = run_hook("mcp__plugin_socxen_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": "/nonexistent"})
    assert out["permissionDecision"] == "ask" and "could not evaluate" in out["permissionDecisionReason"]


def test_decision_log_is_best_effort(tmp_path):
    log = tmp_path / "gate.jsonl"
    run_hook("mcp__plugin_socxen_exabeam__exabeam_update_case", env={"SOCXEN_GATE_LOG": str(log)})
    rec = json.loads(log.read_text().strip().splitlines()[-1])
    assert rec["decision"] == "ask" and rec["tool"].endswith("exabeam_update_case") and "ts" in rec
    # an unwritable log path must not change the decision
    out = run_hook("mcp__plugin_socxen_exabeam__exabeam_update_case", env={"SOCXEN_GATE_LOG": "/proc/no/such/dir/x.jsonl"})
    assert out["permissionDecision"] == "ask"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
