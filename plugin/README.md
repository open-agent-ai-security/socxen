<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen
**An agentic SOC skill suite for Exabeam New-Scale — a plugin for Claude Code and OpenAI Codex.**

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![version](https://img.shields.io/badge/version-v0.8.5-blue)](.claude-plugin/plugin.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

> ⚠️ **Pre-release software — for evaluation purposes only.** socxen is under active development and is
> provided so testers can evaluate it. Expect breaking changes between versions, and do not rely on it
> for production SOC operations or point it at alerts whose disposition matters without a human
> reviewing every action.

socxen is an **agentic SOC skill suite** plus the deterministic guardrails and governance that make it
safe to point at a live tenant. Three skills work **Exabeam New-Scale** through the Exabeam MCP — one case, the
whole queue, or the rules behind it — and each is named for the person whose job it does. No server, no
database, no approval queue: the analyst at the terminal is the human-in-the-loop, and the consequential
action (dismiss/close) is held back by **two locks out of the box** — a gate the plugin ships and your
host enforces (a bundled hook on Claude Code, tool-approval policy on Codex) *and* the skill asking you
first — never left to the model alone.
On Codex, the Exabeam tools are annotated destructive, and Codex requires human approval for a
destructive tool in every mode — refusing it when no human is present — so dismiss/close is human-gated
there the same as on Claude, `codex exec` included.

## The three skills

| Skill | Whose work it is | What it does |
|---|---|---|
| **`soc-investigate`** | the analyst | One alert or case, first look to written verdict: gathers evidence, pivots on entities, weighs competing hypotheses, reaches a threat / false-positive verdict, and acts. |
| **`triage-cases`** | the shift lead | The open queue rather than one case: clusters by attack shape, ranks by corroborated signal (risk score is one input, not the answer), returns a "start here" list plus the noise worth tuning. Read-only across the sweep — never closes in bulk. |
| **`rule-tuning`** | the detection engineer | Finds rules that are *noisy*, not merely loud (volume × low precision), and proposes the specific change mapped to real Exabeam mechanics — context table, exclusion rule, filter/scope/maturity. Propose-only: there is no rule-write path. |

Each hands off to the others: a single case to `soc-investigate`, a noise cluster to `rule-tuning`.

## What it does

- 🔍 **Investigates** on the real Exabeam read surface — `search_events` (SIEM logs),
  `search_alerts`/`search_cases`, threat timelines, rule details, MITRE coverage, context tables.
- ⚖️ **Decides** against a disciplined bar — a false-positive close requires a *positive* benign
  explanation, never merely "I found nothing"; in doubt it escalates rather than silently suppressing.
- 🗂️ **Prioritizes at fleet scale** — sweeps the open queue, clusters it by attack shape, and makes the
  urgent cases impossible to miss instead of re-triaging the same noise every shift.
- 🔧 **Tunes the source of the noise** — separates high-volume-low-precision rules from high-volume-
  high-precision ones, so the fix lands on the detection instead of on the analyst.
- ✍️ **Acts** — opens/updates a case, writes case notes, dismisses true false-positives (gated), and
  **recommends** containment for you to perform in EDR/IAM (the Exabeam MCP has none).
- 🔒 **Stops where it should** — dismiss/close sits behind a hard, harness-enforced approval rule;
  containment is never executed. On Claude Code you switch that gate on during setup; on Codex it ships
  with the plugin.
- 🛡️ **Treats telemetry as hostile** — log data is attacker-influenced by construction, so socxen strips
  hidden-character smuggling from what it reads, and on what it writes back it de-activates dangerous
  content (formulas, clickable links) **and masks credentials and structured identifiers** (API keys,
  tokens, private keys, SSNs, card numbers) before they can persist into a case note or export.
- 🧾 **Logs what it did** — a structured, bounded, privacy-preserving audit record of every action and
  every time a guardrail fired, on by default. ~16 µs/event, non-blocking, local.

## Setup

With the plugin installed, two one-time steps remain — **connect Exabeam** (drop your API key in
`~/.exabeam-mcp.env`) and **turn on the governance safety gate**. The setup guide does the lifting:

### → [Full setup: docs/installation.md](docs/installation.md)

> ✅ **The gate ships ON.** On Claude Code a bundled hook asks before dismiss/close and denies containment
> the moment the plugin is enabled; on Codex the same tiers ship as tool-approval policy. The permission
> pack below is **optional** — it makes reads silent and covers a manually wired server. Previously: there was *no* hard gate on
> dismiss/close — only the skill's soft in-prompt ask stands between the model and a suppressed alert.
> Do not point socxen at alerts you care about until it's on. The
> **[setup guide](docs/installation.md#governance--turn-on-the-safety-gate-do-not-skip-this)** walks you
> through merging it by hand, or `install.sh --merge-permissions` will do it for you. Nothing merges by
> default and `-y` does not authorize it — the flag is the consent. The merge is additive-only, backs
> your settings file up first, and refuses if a rule already sits in a different tier.

Then ask it to *"investigate alert &lt;id&gt;"* (or paste an alert/case) — or *"triage the queue"* /
*"find noisy rules"* to reach the other two skills. The host agent routes on what you ask for.

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
.claude-plugin/          plugin.json (Claude Code manifest — installs via open-agent-ai-security/plugins)
.codex-plugin/           plugin.json (Codex manifest — same skills, same catalog)
.mcp.json                bundled Exabeam MCP for Claude Code — auto-registers on install
.mcp.codex.json          the same bridge for Codex, carrying the approval gate (generated)
skills/soc-investigate/  SKILL.md, settings.snippet.json (governance), reference/
skills/triage-cases/     SKILL.md — queue sweep (shift lead)
skills/rule-tuning/      SKILL.md — noisy-rule tuning (detection engineer)
connector/               exabeam-mcp-bridge.py (bridge) · canonicalize/neutralize_output (guardrails) · observra_logging (audit log)
docs/                    installation · security-guardrails · logging
install.sh               convenience installer, Claude Code (idempotent)
preflight.sh             read-only diagnostics, either host agent
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
release; run `claude plugin list` (or `codex plugin list`) for your installed version. Sharing with
testers; feedback welcome.

**Codex support is packaged and red-team gated, not yet field-proven.** The install, the bundled bridge
and the shipped approval gate are verified end to end against `codex-cli` 0.146.0, and the red-team gate
has run on **GPT-5.6 Terra** (the Sonnet-tier analogue) at `model_reasoning_effort = "medium"` — 20
attacks × 5 trials, zero landings in the blocking classes (`security/redteam/HISTORY.md`, 2026-08-27).
Not yet done on an OpenAI model: the routing evals, and the **Sol** release sweep. **Luna** is the
Haiku-tier analogue and is not supported. Treat the Codex path as gated but young.

## Project sponsor

socxen is sponsored by [Exabeam](https://www.exabeam.com/). Exabeam contributed the initial code and
continues to provide ongoing support and contributions to the project as part of its commitment to
security in an increasingly agentic world.

## License

Apache-2.0 — see `LICENSE` / `NOTICE`.
