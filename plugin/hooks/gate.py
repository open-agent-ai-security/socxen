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
    allow tier → allow  reads and the two escalation writes (create case, write notes): safe operations
                        run without a prompt, so an install needs NOTHING merged — the same tools Codex
                        runs as `auto`. This allow removes only the DEFAULT prompt: an operator's own
                        settings rule on one of these tools still wins — a `deny` removes the tool from
                        the model's list before the hook ever runs, and an `ask` still prompts (both
                        verified live in default permission mode, headless, 2026-09-06). Returning no
                        decision here instead would make every read prompt with nothing merged, which is
                        the permission merge back under another name.
    anything else → ask a tool the remote MCP grew that nobody has classified asks rather than
                        inheriting the session default — Codex's `approve` default, on Claude
    a tool of another MCP server → (no decision, not logged): the matcher is broad enough to survive a
                        renamed server, so the hook, not the matcher, decides whether a call is ours.

The tiers come from the file that ships beside this hook — `skills/soc-investigate/permissions.json`
(bare names) when present, else `settings.snippet.json` (prefixed rules, stripped) — so the hook, the
snippet and the Codex map cannot disagree. If the tiers cannot be read at all, every tool asks: the human
decides interactively, and headless the call is refused. The gate never fails open.

Each decision is appended, best-effort, to `~/.socxen/gate.jsonl` with the call's SAFE target fields —
identifiers and dispositions only (alertId, caseId, alertStatus, stage, …), never free text — so a
refused attempt reads as "tried to dismiss alert X as false positive", not just "tried update_alert".
The near-miss is the record that matters in a SOC (`SOCXEN_GATE_LOG=off` disables;
another path overrides) — a first-party record of what was attempted and what the gate said, including
attempts that never reached the bridge (#87).

Stdlib only. Exit 0 always; the decision is the JSON on stdout.
"""
from __future__ import annotations   # `tuple[str, str]` must not be evaluated on an old system python3

import datetime
import json
import os
import re
import sys
from pathlib import Path

SERVER = "exabeam"


def bare(tool_name: str) -> str:
    return tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name


def is_ours(tool_name: str) -> bool:
    """mcp__<server>__<tool> where <server> is the Exabeam MCP: `exabeam`, or a bundled `plugin_<key>_exabeam`,
    or any server an operator named with `exabeam` in it. Anything else belongs to another server."""
    m = re.match(r"^mcp__(.+)__[^_].*$", tool_name)
    return bool(m) and "exabeam" in m.group(1).lower()


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


# The SAFE fields of a call worth recording beside the decision — the same allowlist the bridge's audit
# trail uses (_AUDIT_FIELDS in exabeam-mcp-bridge.py): identifiers and enums, never free text (note,
# description, reason, subject, body). Scalars and short lists only, values capped, first occurrence wins.
AUDIT_FIELDS = {"alertid", "caseid", "alertstatus", "casestatus", "stage",
                "priority", "severity", "queue", "disposition", "usecases", "recipients"}
_CAP = 80


def target_fields(obj, into=None, depth=0):
    """Collect AUDIT_FIELDS from anywhere in the (possibly nested) tool input. Never raises."""
    into = {} if into is None else into
    try:
        if isinstance(obj, dict) and depth < 4:
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in AUDIT_FIELDS and isinstance(v, (str, int, float, bool)):
                    into.setdefault(k, v[:_CAP] if isinstance(v, str) else v)
                elif lk in AUDIT_FIELDS and isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
                    into.setdefault(k, [x[:_CAP] if isinstance(x, str) else x for x in v[:10]])
                elif isinstance(v, dict):
                    target_fields(v, into, depth + 1)
    except Exception:  # noqa: BLE001, S110 — the record is best-effort; the decision never depends on it
        pass
    return into


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
    except Exception:  # noqa: BLE001, S110 — logging must never change the decision, so nothing is raised here
        pass


def main() -> int:
    tool, target = "", {}
    try:
        event = json.load(sys.stdin)
        tool = str(event.get("tool_name", ""))
        if tool and not is_ours(tool):
            return 0                       # another server's tool: no decision, no record (not our business)
        target = target_fields(event.get("tool_input"))
        root = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)
        decision, reason = decide(tool, load_tiers(root))
    except Exception as e:  # noqa: BLE001 — cannot classify → the human decides; headless → refused
        decision, reason = "ask", f"socxen gate could not evaluate this call ({type(e).__name__}); asking rather than allowing."
    record = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool": tool, "decision": decision, "reason": reason}
    if target:
        record["target"] = target          # what was attempted, on which object — never the free text
    log_decision(record)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
