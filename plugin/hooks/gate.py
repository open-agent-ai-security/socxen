#!/usr/bin/env python3
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""socxen's human-in-the-loop gate for Claude Code, shipped INSIDE the plugin as a PreToolUse hook.

Why this exists. Claude Code lets a plugin ship code that takes part in permission decisions, but not
permission rules: rules are the operator's to set. Until this hook, socxen's gate on dismiss/close lived
only in `settings.snippet.json`, inert until an operator merged it, and switched off entirely by
`--dangerously-skip-permissions`. A PreToolUse hook is active the moment the plugin is enabled, its
`deny` holds even under `--dangerously-skip-permissions`, and its `ask` forces a human prompt in every
mode and is refused when no human is present — the same posture the Codex package gets from
`default_tools_approval_mode`. Verified live on 2026-09-04 (issue #9's two open questions).

What it decides, keyed on the BARE tool name (the last `__` segment), so it applies equally to the
bundled server under any plugin key (`mcp__plugin_socxen_exabeam__…`, `mcp__plugin_soc_exabeam__…`) and to
the manually wired `mcp__exabeam__…`:

    deny tier  → deny   containment: socxen never executes it, it recommends it
    ask tier   → ask    dismiss / close (and send_email): an explicit human yes, every time
    allow tier → allow  reads and escalation writes (create case, write notes)
    anything else → ask a tool the remote MCP grew that nobody has classified asks rather than
                        inheriting the session default — Codex's `approve` default, on Claude

The tiers come from the file that ships beside this hook — `skills/soc-investigate/permissions.json`
(bare names) when present, else `settings.snippet.json` (prefixed rules, stripped) — so the hook, the
snippet and the Codex map cannot disagree. If the tiers cannot be read at all, every tool asks: the human
decides interactively, and headless the call is refused. The gate never fails open.

Each decision is appended, best-effort, to `~/.socxen/gate.jsonl` (`SOCXEN_GATE_LOG=off` disables;
another path overrides) — a first-party record of what was attempted and what the gate said, including
attempts that never reached the bridge (#87).

Stdlib only. Exit 0 always; the decision is the JSON on stdout.
"""
from __future__ import annotations   # `tuple[str, str]` must not be evaluated on an old system python3

import datetime
import json
import os
import sys
from pathlib import Path

SERVER = "exabeam"


def bare(tool_name: str) -> str:
    return tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name


def load_tiers(plugin_root: Path):
    """{'allow': set, 'ask': set, 'deny': set} of bare tool names, from the shipped tier file."""
    perms = plugin_root / "skills" / "soc-investigate" / "permissions.json"
    if perms.is_file():
        d = json.loads(perms.read_text())
        return {t: set(spec["tools"]) for t, spec in d["tiers"].items()}
    snippet = plugin_root / "skills" / "soc-investigate" / "settings.snippet.json"
    p = json.loads(snippet.read_text())["permissions"]
    return {t: {bare(r) for r in p.get(t, [])} for t in ("allow", "ask", "deny")}


def decide(tool_name: str, tiers) -> tuple[str, str]:
    name = bare(tool_name)
    if name in tiers["deny"]:
        return "deny", f"socxen gate: {name} is a containment action. socxen recommends containment for a human to perform and never executes it."
    if name in tiers["ask"]:
        return "ask", f"socxen gate: {name} dismisses or closes. It needs the analyst's explicit yes — ask, and wait."
    if name in tiers["allow"]:
        return "allow", f"socxen gate: {name} is a read or an escalation write."
    return "ask", f"socxen gate: {name} is not classified in this release's permission tiers, so it asks rather than inheriting the session default."


LOG_MAX_BYTES = 5_000_000   # rotate at ~5 MB, keep 3 backups — bounded like the telemetry log beside it
LOG_BACKUPS = 3


def _rotate(path: Path) -> None:
    """gate.jsonl → gate.jsonl.1 → .2 → .3 (oldest dropped). Best-effort, like the write itself. Two
    concurrent hook invocations can both see the ceiling; the loser's replace() finds the file already
    moved — swallow that, the decision is unaffected and this record still appends below."""
    for i in range(LOG_BACKUPS, 0, -1):
        src = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
        try:
            if src.exists():
                src.replace(path.with_name(f"{path.name}.{i}"))
        except FileNotFoundError:
            pass


def log_decision(record: dict) -> None:
    target = os.environ.get("SOCXEN_GATE_LOG", "").strip()
    if target.lower() == "off":
        # The off switch discloses itself, as the telemetry shim's does — a silent switch is how a
        # forensic record disappears without anyone noticing.
        print("socxen gate: decision log is OFF (SOCXEN_GATE_LOG=off) — this decision is not recorded", file=sys.stderr)
        return
    try:
        # Inside the guard: expanduser() on "~nosuchuser" and Path.home() with no HOME / unknown uid both
        # raise, and a crash here would turn "logging failed" into "every call blocked" via `|| exit 2`.
        path = Path(target).expanduser() if target else Path.home() / ".socxen" / "gate.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            limit = int(os.environ.get("SOCXEN_GATE_LOG_MAX_BYTES", LOG_MAX_BYTES))
        except ValueError:
            limit = LOG_MAX_BYTES
        if path.exists() and path.stat().st_size >= limit:
            _rotate(path)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — logging must never change the decision
        pass


def main() -> int:
    tool = ""
    try:
        event = json.load(sys.stdin)
        tool = str(event.get("tool_name", ""))
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        decision, reason = decide(tool, load_tiers(root))
    except Exception as e:  # noqa: BLE001 — cannot classify → the human decides; headless → refused
        decision, reason = "ask", f"socxen gate could not evaluate this call ({type(e).__name__}); asking rather than allowing."
    log_decision({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  "tool": tool, "decision": decision, "reason": reason})
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
