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


import importlib.util
_spec = importlib.util.spec_from_file_location("gate", HOOK)
gate = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(gate)
bare = gate.bare                       # the shipped one, not a copy
NO_DECISION = {"permissionDecision": None}


def run_hook(tool_name, stdin=None, env=None):
    """The end-to-end contract: a subprocess, exactly as Claude Code runs it. Empty stdout is the hook
    asserting nothing (the normal permission flow runs) and is returned as NO_DECISION."""
    e = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "SOCXEN_GATE_LOG": "off", **(env or {})}
    r = subprocess.run([sys.executable, str(HOOK)], input=stdin if stdin is not None else json.dumps({"tool_name": tool_name}),
                       capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else NO_DECISION


def test_manifest_declares_the_hook():
    pj = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert pj.get("hooks") == "./hooks/hooks.json"
    assert (PLUGIN / "hooks" / "hooks.json").is_file() and HOOK.is_file()


def test_matcher_covers_every_way_the_server_can_be_named():
    m = re.compile(HOOKS_JSON["hooks"]["PreToolUse"][0]["matcher"])
    for name in ("mcp__plugin_socxen_exabeam__exabeam_update_alert",   # bundled, upstream key
                 "mcp__plugin_soc_exabeam__exabeam_update_alert",      # bundled, a vendor catalog's key
                 "mcp__exabeam__exabeam_update_alert",                 # manually wired (#86)
                 "mcp__exabeam-prod__exabeam_update_alert",            # wired by hand under another name
                 "mcp__Exabeam__exabeam_update_alert"):
        assert m.search(name), name
        assert gate.is_ours(name), name
    # Not ^mcp__: that would put every MCP server in the session behind this hook's python3 fail-closed.
    assert not m.search("mcp__github__create_issue") and not gate.is_ours("mcp__github__create_issue"), "must not gate other servers"
    assert not m.search("Bash"), "must not gate built-in tools"


def test_another_servers_tool_gets_no_decision_and_no_record(tmp_path):
    log = tmp_path / "gate.jsonl"
    assert run_hook("mcp__github__create_issue", env={"SOCXEN_GATE_LOG": str(log)}) == NO_DECISION
    assert not log.exists()


@pytest.mark.parametrize("prefix", ["mcp__plugin_socxen_exabeam__", "mcp__plugin_soc_exabeam__", "mcp__exabeam__", "mcp__EXABEAM-prod__"])
def test_decisions_match_the_shipped_tiers_under_every_prefix(prefix):
    """Exhaustive, in-process (decide() is a plain function; the subprocess contract is tested beside it):
    deny and ask apply under EVERY Exabeam-named prefix; allow applies to the bundled bridge only
    (Praxen 2026-09-07-003) — elsewhere an allow-tier tool gets no decision."""
    tiers = gate.load_tiers(PLUGIN)
    name = gate.plugin_name(PLUGIN)
    for tier, expected in (("deny", "deny"), ("ask", "ask")):
        for rule in SNIPPET[tier]:
            decision, reason = gate.decide(prefix + bare(rule), tiers, bundled=gate.is_bundled(prefix + bare(rule), name))
            assert decision == expected, (tier, rule, decision, reason)
    for rule in SNIPPET["allow"]:
        tool = prefix + bare(rule)
        decision, _ = gate.decide(tool, tiers, bundled=gate.is_bundled(tool, name))
        assert decision == ("allow" if prefix == "mcp__plugin_socxen_exabeam__" else gate.NO_DECISION), (prefix, rule, decision)


def test_the_allow_tier_is_the_bundled_bridges_alone(tmp_path):
    """Praxen 2026-09-07-003: the prompt-free allow used to apply under any server whose name contained
    'exabeam'. Now it is granted to `plugin_<name>_exabeam` only, with <name> read from identity.json --
    so a vendor-keyed copy (soc@exabeam) recognizes ITS bridge, and a manual or third-party server gets
    the operator's own rules for reads while still getting ask/deny."""
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_search_alerts")["permissionDecision"] == "allow"
    assert run_hook("mcp__exabeam__exabeam_search_alerts") == NO_DECISION            # manual registration: your rules
    assert run_hook("mcp__exabeam-prod__exabeam_get_case_details") == NO_DECISION
    assert run_hook("mcp__exabeam__exabeam_update_alert")["permissionDecision"] == "ask"     # tightening still reaches it
    assert run_hook("mcp__EXABEAM__exabeam_isolate_host")["permissionDecision"] == "deny"    # any case
    # a vendor catalog's copy: same hook, its own identity.json says "soc"
    import shutil
    vendored = tmp_path / "soc"
    shutil.copytree(PLUGIN, vendored, ignore=shutil.ignore_patterns("__pycache__"))
    ident = json.loads((vendored / "identity.json").read_text()); ident["name"] = "soc"
    (vendored / "identity.json").write_text(json.dumps(ident))
    out = run_hook("mcp__plugin_soc_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out["permissionDecision"] == "allow"
    out = run_hook("mcp__plugin_socxen_exabeam__exabeam_search_alerts", env={"CLAUDE_PLUGIN_ROOT": str(vendored)})
    assert out == NO_DECISION, "under the vendored copy, the upstream key is not its bridge"


def test_matcher_and_hook_agree_on_case(tmp_path):
    """Praxen 2026-09-07-004: the matcher was case-sensitive while the hook lowercased, so the two could
    disagree about which calls are ours. Now both are case-insensitive."""
    m = re.compile(HOOKS_JSON["hooks"]["PreToolUse"][0]["matcher"])
    for name in ("mcp__EXABEAM__exabeam_update_alert", "mcp__Exabeam-Prod__exabeam_update_alert", "mcp__plugin_socxen_exabeam__x"):
        assert m.search(name) and gate.is_ours(name), name
    assert not m.search("mcp__github__create_issue") and not gate.is_ours("mcp__github__create_issue")


def test_preflight_warns_about_an_exabeam_server_the_gate_does_not_reach():
    import subprocess
    sample = ("Checking MCP server health…\n\n"
              "exabeam: uv run /x/exabeam-mcp-bridge.py - ✓ Connected\n"
              "siem: uv run /x/exabeam-mcp-bridge.py - ✓ Connected\n"
              "claude.ai Gmail: https://gmailmcp.googleapis.com/mcp/v1 - ✓ Connected\n"
              "prod-mcp: https://api.us-west.exabeam.cloud/mcp - ✓ Connected\n")
    r = subprocess.run(["bash", "-c", f"source '{PLUGIN / 'preflight.sh'}'; gate_reach_warnings"], input=sample, capture_output=True, text=True)
    assert r.stdout.split() == ["siem", "prod-mcp"], r.stdout


def test_safe_operations_are_allowed_so_nothing_prompts_with_nothing_merged():
    """The point of the bundled hook: an install needs no permission merge. Reads and the two escalation
    writes are allowed outright (Codex runs the same tools as `auto`); dismiss/close ask; containment denied."""
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_search_alerts")["permissionDecision"] == "allow"
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_create_case_notes")["permissionDecision"] == "allow"
    codex = json.loads((PLUGIN / ".mcp.codex.json").read_text())["exabeam"]["tools"]
    auto = {t for t, spec in codex.items() if spec.get("approval_mode") == "auto"}
    assert auto == set(gate.load_tiers(PLUGIN)["allow"]), "Claude's allow tier must be exactly Codex's auto set"


def test_dismiss_and_close_ask_and_containment_denies():
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_update_alert")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_update_case")["permissionDecision"] == "ask"
    assert run_hook("mcp__plugin_socxen_exabeam__exabeam_isolate_host")["permissionDecision"] == "deny"
    assert run_hook("mcp__plugin_socxen_exabeam__isolate_host")["permissionDecision"] == "deny"


def test_unclassified_tool_asks_instead_of_inheriting_the_session_default():
    """The Codex map's `default_tools_approval_mode: approve` equivalent — a tool the remote MCP grew
    that nobody classified must not run unattended (exabeam_create_analytics_rule was the live example
    until #143 classified it as deny; the name here is one no release will classify)."""
    out = run_hook("mcp__plugin_socxen_exabeam__exabeam_brand_new_thing")
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



def test_hook_invocation_fails_closed_without_an_interpreter(tmp_path):
    """Praxen PRAX-2026-09-05-001: gate.py never fails open, but a hook whose command errors is
    NON-blocking on the host — so a missing python3 meant no gate. The command now exits 2 (the host's
    blocking code) when the interpreter is missing or the script cannot run."""
    import subprocess, json as _json
    cmd = _json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.endswith("|| exit 2")
    env = {"PATH": str(tmp_path), "CLAUDE_PLUGIN_ROOT": str(PLUGIN)}     # no python3 on PATH
    proc = subprocess.run(["/bin/sh", "-c", cmd], input="{}", capture_output=True, text=True, env=env)
    assert proc.returncode == 2


def test_gate_log_rotates_at_a_ceiling_and_the_off_switch_discloses_itself(tmp_path):
    """Praxen PRAX-2026-09-05-012: the decision log grew without bound and `off` was silent."""
    import subprocess, os
    log = tmp_path / "gate.jsonl"
    log.write_text("x" * 100)
    env = dict(os.environ, SOCXEN_GATE_LOG=str(log), SOCXEN_GATE_LOG_MAX_BYTES="50", CLAUDE_PLUGIN_ROOT=str(PLUGIN))
    subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_update_case"}',
                   capture_output=True, text=True, env=env, check=True)
    assert (tmp_path / "gate.jsonl.1").read_text() == "x" * 100, "the full log was not rotated aside"
    assert log.read_text().count("\n") == 1 and "update_case" in log.read_text()
    env["SOCXEN_GATE_LOG"] = "off"
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_update_case"}',
                          capture_output=True, text=True, env=env, check=True)
    assert "decision log is OFF" in proc.stderr
    assert "permissionDecision" in proc.stdout          # the decision itself is unaffected


def test_the_exact_hook_command_runs_with_python3_present(tmp_path):
    """The command string in hooks.json, run by /bin/sh as the host runs it: exit 0 and one JSON decision."""
    import subprocess, json as _json, os
    cmd = _json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN), SOCXEN_GATE_LOG="off")
    proc = subprocess.run(["/bin/sh", "-c", cmd], input='{"tool_name":"mcp__exabeam__exabeam_update_alert"}', capture_output=True, text=True, env=env)
    assert proc.returncode == 0
    assert _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_gate_never_crashes_on_a_bad_log_path(tmp_path):
    """A bad SOCXEN_GATE_LOG ('~nosuchuser') used to raise outside the guard: no JSON, exit 1, and via
    `|| exit 2` every gated call blocked. Logging must never change the decision."""
    import subprocess, json as _json, os
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN), SOCXEN_GATE_LOG="~nosuchuser_zz/gate.jsonl")
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__plugin_socxen_exabeam__exabeam_search_alerts"}', capture_output=True, text=True, env=env)
    assert proc.returncode == 0 and _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def _fake_claude(tmp_path, install_path):
    """A `claude` on PATH whose `plugin list --json` reports socxen installed at install_path (or nothing)."""
    bin_ = tmp_path / "bin"; bin_.mkdir(exist_ok=True)
    body = json.dumps([{"id": "socxen@open-agent-ai-security", "version": "0.8.6", "scope": "user", "enabled": True,
                        "installPath": str(install_path)}] if install_path else [])
    (bin_ / "claude").write_text("#!/bin/sh\ncase \"$*\" in *'plugin list'*) printf '%s' '" + body + "' ;; *) exit 0 ;; esac\n")
    (bin_ / "claude").chmod(0o755)
    return str(bin_)


def _preflight(tmp_path, install_path):
    import subprocess, os
    settings = tmp_path / "settings.json"; settings.write_text('{"permissions": {}}')
    env = dict(os.environ, SOCXEN_SETTINGS_FILE=str(settings), SOCXEN_PLATFORM="claude", HOME=str(tmp_path),
               PATH=_fake_claude(tmp_path, install_path) + os.pathsep + os.environ.get("PATH", ""))
    return subprocess.run(["bash", str(PLUGIN / "preflight.sh"), "--skip-connectivity"], capture_output=True, text=True, env=env)


def test_preflight_reports_the_hook_when_no_rules_are_merged(tmp_path):
    """Rules not merged (the documented default) must report the hook ON -- attested from the INSTALLED
    plugin (claude plugin list --json), not from the copy the script sits in (review 2026-09-05) -- and
    must not die on an unbound variable (an earlier review: _PF_DIR under set -u)."""
    proc = _preflight(tmp_path, PLUGIN)                       # installed copy == this tree, which has the hook
    assert "unbound variable" not in proc.stderr + proc.stdout
    assert "gate ON via the bundled hook in the INSTALLED plugin" in proc.stdout, proc.stdout


def test_preflight_never_attests_a_hook_the_installed_plugin_lacks(tmp_path):
    """A clone with the hook beside an installed version without it must read OFF, not ON."""
    old = tmp_path / "installed-old"; old.mkdir()              # an installed copy that predates the hook
    proc = _preflight(tmp_path, old)
    assert "gate ON" not in proc.stdout and "predates the bundled hook" in proc.stdout, proc.stdout
    proc = _preflight(tmp_path, None)                          # not installed at all
    assert "gate ON" not in proc.stdout and "not installed or not enabled" in proc.stdout, proc.stdout


def test_decision_log_records_the_safe_target_fields_and_never_free_text(tmp_path):
    """A refused dismiss must read as "tried to dismiss alert X as FP" in the gate log (the near-miss is the
    record a SOC wants), while the free-text fields a payload can ride in never enter it."""
    import subprocess, os, json as _json
    log = tmp_path / "gate.jsonl"
    env = dict(os.environ, SOCXEN_GATE_LOG=str(log), CLAUDE_PLUGIN_ROOT=str(PLUGIN))
    event = {"tool_name": "mcp__plugin_socxen_exabeam__exabeam_update_alert",
             "tool_input": {"arg1": {"alertId": "4471", "alertStatus": "DISMISSED", "closedReason": "FP",
                                     "alertDescription": "SECRET FREE TEXT " * 20, "supportingReason": "planted note",
                                     "nested": {"caseId": "c-9", "note": "more free text"},
                                     "useCases": ["ua", "x" * 200]}}}
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input=_json.dumps(event),
                          capture_output=True, text=True, env=env, check=True)
    assert _json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    rec = _json.loads(log.read_text().splitlines()[-1])
    assert rec["target"]["alertId"] == "4471" and rec["target"]["alertStatus"] == "DISMISSED" and rec["target"]["caseId"] == "c-9"
    assert "alertDescription" not in rec["target"] and "supportingReason" not in rec["target"] and "note" not in rec["target"]
    assert "closedReason" not in rec["target"], "a close reason is free text"
    assert len(rec["target"]["useCases"][1]) == 80, "list values are capped"
    assert "SECRET FREE TEXT" not in log.read_text()
    # a read with no id fields carries no target key at all
    proc = subprocess.run([sys.executable, str(PLUGIN / "hooks" / "gate.py")], input='{"tool_name":"mcp__exabeam__exabeam_search_alerts","tool_input":{"arg0":{"filter":"x"}}}',
                          capture_output=True, text=True, env=env, check=True)
    assert "target" not in _json.loads(log.read_text().splitlines()[-1])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
