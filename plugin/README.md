<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen
**An agentic SOC analyst, as a Claude Code skill.**

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-v0.7.0-blue)](.claude-plugin/plugin.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

> ⚠️ **Pre-release software — for evaluation purposes only.** socxen is under active development and is
> provided so testers can evaluate it. Expect breaking changes between versions, and do not rely on it
> for production SOC operations or point it at alerts whose disposition matters without a human
> reviewing every action.

socxen investigates and triages **Exabeam New-Scale** alerts and cases end to end — it gathers evidence
through the Exabeam MCP, pivots on entities, weighs competing hypotheses, reaches a threat /
false-positive verdict, and acts. No server, no database, no approval queue: the analyst at the terminal
is the human-in-the-loop, and the consequential action (dismiss/close) is held back by **two locks** —
Claude Code permission rules *and* the skill asking you first — never left to the model alone.

## What it does

- 🔍 **Investigates** on the real Exabeam read surface — `search_events` (data-lake logs),
  `search_alerts`/`search_cases`, threat timelines, rule details, MITRE coverage, context tables.
- ⚖️ **Decides** against a disciplined bar — a false-positive close requires a *positive* benign
  explanation, never merely "I found nothing"; in doubt it escalates rather than silently suppressing.
- ✍️ **Acts** — opens/updates a case, writes case notes, dismisses true false-positives (gated), and
  **recommends** containment for you to perform in EDR/IAM (the Exabeam MCP has none).
- 🔒 **Stops where it should** — dismiss/close sits behind a hard, Claude-Code-enforced permission gate
  you switch on during setup; containment is never executed.
- 🛡️ **Treats telemetry as hostile** — log data is attacker-influenced by construction, so socxen strips
  hidden-character smuggling from what it reads and de-activates dangerous content (formulas, clickable
  links) in what it writes back.
- 🧾 **Logs what it did** — a structured, bounded, privacy-preserving audit record of every action and
  every time a guardrail fired, on by default. ~16 µs/event, non-blocking, local.

## Setup

With the plugin installed, two one-time steps remain — **connect Exabeam** (drop your API key in
`~/.exabeam-mcp.env`) and **turn on the governance safety gate**. The setup guide does the lifting:

### → [Full setup: docs/installation.md](docs/installation.md)

> ⚠️ **The governance permission pack is not optional.** Until you merge it, there is *no* hard gate on
> dismiss/close — only the skill's soft in-prompt ask stands between the model and a suppressed alert.
> Do not point socxen at alerts you care about until it's on. The
> **[setup guide](docs/installation.md#governance--turn-on-the-safety-gate-do-not-skip-this)** walks you
> through merging it by hand, or `install.sh --merge-permissions` will do it for you. Nothing merges by
> default and `-y` does not authorise it — the flag is the consent. The merge is additive-only, backs
> your settings file up first, and refuses if a rule already sits in a different tier.

Then ask it to *"investigate alert &lt;id&gt;"* (or paste an alert/case).

## Documentation

| Guide | What's in it |
|---|---|
| **[Installation & setup](docs/installation.md)** | install, Exabeam credentials, the governance gate (**start here**), updating |
| **[Security guardrails](docs/security-guardrails.md)** | what socxen screens for in untrusted telemetry — and what it deliberately doesn't |
| **[Audit logging](docs/logging.md)** | exactly what's recorded, where the log lives, how to control or route it |
| **[Architecture](https://github.com/open-agent-ai-security/socxen#how-its-built)** | how the layers fit together — methodology, capability, authority, guardrails, evidence — and why they're separate |
| **[Methodology](skills/soc-investigate/SKILL.md)** | how it investigates; `reference/` has the tool map, search cookbook, enrichment playbook, report template, and worked examples (`reference/examples/`). Regression tests live in the repo's [`evals/`](https://github.com/open-agent-ai-security/socxen/tree/main/evals). |

## Layout

```
.claude-plugin/          plugin.json (plugin manifest — installs via open-agent-ai-security/plugins)
.mcp.json                bundled Exabeam MCP — auto-registers on install
skills/soc-investigate/  SKILL.md, settings.snippet.json (governance), reference/
connector/               exabeam-mcp-bridge.py (bridge) · canonicalize/neutralize_output (guardrails) · observra_logging (audit log)
docs/                    installation · security-guardrails · logging
install.sh               convenience installer (idempotent)
```

## How it's tested

Claims about agent safety are worth what the testing behind them is worth, so the testing is public and
every release is gated on it: socxen is **red-teamed** with prompt-injection fixtures run against a live
model — graded on whether the attack *landed*, not on whether the model sounded cautious — and
**behavior-verified** against a declared policy, with no release shipping on an open Critical finding.
Methodology, per-run results and the known residuals:
**[security/](https://github.com/open-agent-ai-security/socxen/tree/main/security)**.

## Status

Pre-release, for evaluation — validated end-to-end against a live Exabeam staging MCP
(install → connect → investigate → gated dismiss), with a grounded search cookbook, enrichment
playbook, and a worked investigation. The version badge above and the
[changelog](https://github.com/open-agent-ai-security/socxen/blob/main/CHANGELOG.md) track the current
release; run `claude plugin list` for your installed version. Sharing with testers; feedback welcome.

## Project sponsor

socxen is sponsored by [Exabeam](https://www.exabeam.com/). Exabeam contributed the initial code and
continues to provide ongoing support and contributions to the project as part of its commitment to
security in an increasingly agentic world.

## License

Apache-2.0 — see `LICENSE` / `NOTICE`.
