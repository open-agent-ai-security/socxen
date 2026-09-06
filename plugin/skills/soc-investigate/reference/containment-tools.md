<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Containment-class actions — recommend only (defense-in-depth deny-list)

> **The Exabeam MCP does not expose any of these.** Per the official MCP docs, the server's surface is
> Threat Center (cases/alerts/notes/timelines), Search, Attack Surface Insights (entity context),
> Context tables, and Detection rules — all read or triage-workflow. There is **no host isolation,
> account disable, or blocking capability.** So this list isn't gating tools you have; it's
> **defense-in-depth** — a standing `deny` that costs nothing and catches the day a response tool
> *is* added (by Exabeam or another MCP) before it can fire unreviewed.

Because containment isn't an MCP capability, the skill always **recommends** it in the report; the
analyst performs it in their EDR/IAM. The *real* human gate for this MCP is on **dismiss/close**
(`update_alert` / `update_case`) — see `settings.snippet.json` `ask` — because a wrong suppression is
the actual way an AI verdict does harm here.

This list is ported verbatim from Nova's `blast_radius.py` `CONTAINMENT_CLASS_TOOLS` — the immutable
registry that, in the server, could only be weakened by a code change + PR review. Treat it the same
way: additions are fine, silent removals are not.

## The list

**Host isolation**
- `isolate_host`
- `quarantine_host`
- `isolate_device`

**Account actions**
- `disable_account`
- `disable_user`
- `lock_account`
- `revoke_session`
- `force_mfa_reset`
- `revoke_oauth_grant`

**Network / firewall**
- `block_ip`
- `block_url`
- `block_domain`
- `add_firewall_rule`
- `modify_firewall_rule`

**Endpoint actions**
- `kill_process`
- `delete_file`
- `run_script_on_host`

## Also denied: detection-content writes

Not containment, but the same posture — actions socxen **must never perform**, only propose. The live
Exabeam MCP grew `exabeam_create_analytics_rule` (2026-09: builds and creates a detection rule
server-side from one of six canned names) and the proxy defines `exabeam_update_analytics_rule`. The
`rule-tuning` skill's contract is *proposals for detection engineering to act on*, and `SKILL.md`
forbids applying or claiming to have applied a rule change, so both are denied on both hosts, under
both spellings, exactly like the containment verbs. A future rule-write tool under a new name lands on
the hook's unknown-tool rule (ask), which is the safety net until it is classified here.

**Detection content**
- `create_analytics_rule`
- `update_analytics_rule`

## Why these and not `create_case` / `update_alert`

Opening a case or dismissing an alert is **workflow** — it routes and documents, and is easily
reversed. The actions above touch production systems and user access directly: isolating the wrong
host takes a service down; disabling the wrong account locks out a real user; `delete_file` and
`run_script_on_host` are effectively arbitrary endpoint control. That asymmetry is the entire reason
for the human gate, so the line is drawn here.

## Note on exact names

These are Nova's normalized (server-stripped) names. Every tool the Exabeam MCP exposes today follows
the `exabeam_<verb>` convention (see `tool-map.md`), so a containment tool would most likely arrive as
`exabeam_isolate_host`. `settings.snippet.json` therefore denies **both spellings** of every name here
— bare and `exabeam_`-prefixed — in **both namespaces** (the bundled plugin's
`mcp__plugin_socxen_exabeam__` — the prefix derives from `name` in `plugin/identity.json`, from which the snippet is generated — and the manual-wiring `mcp__exabeam__`), and a repo invariant test
(`test_deny_list_matches_containment_doc`) keeps this file and the snippet in sync — that sync is what
makes the gate real. If a live tool list ever shows a containment tool under a *different* name, add
it here and the test will demand the matching deny rules.
