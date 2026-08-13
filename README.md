<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen

**An agentic SOC analyst for Exabeam New-Scale — built so the actions that matter stop at a
human.** A Claude Code plugin that investigates alerts and cases end to end: gathers evidence,
pivots across users, hosts and IPs, weighs competing hypotheses, and reaches a verdict.

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](plugin/LICENSE)

> ⚠️ **Pre-release software — for evaluation only.** socxen is under active development. Expect
> breaking changes between versions, and do not rely on it for production SOC operations or point it
> at alerts whose disposition matters without a human reviewing every action.

## What it is

Point it at an Exabeam alert or case and it runs the investigation: pulls the underlying events,
pivots on the entities it finds, baselines what is normal for them, tests a benign explanation
against a malicious one, maps activity to MITRE ATT&CK, and writes up a verdict with its evidence.

Then it acts — opens or updates a case, writes case notes, escalates. **Dismissing an alert or
closing a case is held back by two locks**: a Claude Code permission rule that stops the call at the
harness, and the skill asking you first. Containment is *recommended* for you to perform in EDR or
IAM; the plugin never executes it.

There is no server, no database and no approval queue. The analyst at the terminal is the
human-in-the-loop.

## Install

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
```

> 🛑 **Then turn on the governance gate — this is not optional.** The permission pack is the only
> *hard* lock on dismiss/close. Until you merge it, the sole thing standing between a wrong verdict
> and a suppressed alert is the skill's in-prompt ask, which is a soft prompt to the model rather
> than a rule the harness enforces. Do not point socxen at alerts you care about until it is on.
>
> ```bash
> git clone https://github.com/open-agent-ai-security/socxen.git
> cd socxen && ./plugin/install.sh --merge-permissions
> ```
>
> Nothing merges by default and `-y` does not authorise it — the flag is the consent. The merge is
> additive-only, backs your settings file up first, and refuses if a rule already sits in a different
> tier. To do it by hand instead, see
> **[the setup guide](plugin/docs/installation.md#governance--turn-on-the-safety-gate-do-not-skip-this)**.

You also supply Exabeam credentials once (`~/.exabeam-mcp.env`); the MCP connection itself is bundled
and auto-registers, with OAuth refresh handled for you. Full walkthrough:
**[plugin/docs/installation.md](plugin/docs/installation.md)**.

Then ask it to *"investigate alert &lt;id&gt;"*.

## How it's built

socxen is five separable layers, and keeping them separate is the point — a capable model with tool
access is not by itself something you can let near a SOC queue.

| Layer | Where | What it contributes |
|---|---|---|
| **Methodology** | [`plugin/skills/soc-investigate/`](plugin/skills/soc-investigate/) | the investigation *procedure* — entity pivots, baselining, competing hypotheses, an evidence bar, stopping conditions, an action matrix |
| **Capability** | [`plugin/.mcp.json`](plugin/.mcp.json) | the Exabeam New-Scale MCP — data-lake search, alerts and cases, threat timelines, rule and MITRE context |
| **Authority** | [`settings.snippet.json`](plugin/skills/soc-investigate/settings.snippet.json) | which calls run unattended, which stop for a human, which are denied outright — **enforced by Claude Code, not by the model** |
| **Guardrails** | [`plugin/connector/`](plugin/connector/) | a local bridge that treats telemetry as hostile input, and writes an audit trail |
| **Evidence** | [`evals/`](evals/) · [`security/`](security/) | regression harness, red-team program, agent-behavior verification, AI BOM |

**Why the methodology is a file and not a prompt.** It encodes decisions a generic "act like a SOC
analyst" instruction does not make. The one that does the most work:

> A **false positive** needs a *positive* benign explanation (a known automation, a documented change,
> expected admin behavior) — not merely "I found nothing." Absence of evidence is "inconclusive."

Inconclusive escalates. That one rule is the difference between an agent that closes tickets and an
agent that closes them correctly. The rest of the methodology is in
[`SKILL.md`](plugin/skills/soc-investigate/SKILL.md).

**Why telemetry is treated as hostile.** Log data is attacker-influenced by construction: anyone who
can generate an event can plant text in it, including text aimed at the agent reading it. So the
bridge screens what comes *in* for hidden-character and control-character smuggling, and de-activates
dangerous content on the way *out* — spreadsheet formulas and clickable links are defanged before
they can be re-armed in an analyst's notes or an exported report. Details, including what this
deliberately does **not** cover:
**[security-guardrails.md](plugin/docs/security-guardrails.md)**.

**Audit logging is on by default** — a structured, bounded, local record of every tool call, every
gated action and every time a guardrail fired, at `~/.socxen/telemetry.jsonl`, with no network
egress. See **[logging.md](plugin/docs/logging.md)**.

## Evidence

Claims about agent safety are worth what the testing behind them is worth, so the testing is in the
repo and every release is gated on it:

- **Red team** — [`security/redteam/`](security/redteam/). Prompt-injection attack fixtures run
  against a live model, graded on whether the attack *landed*, not on whether the model sounded
  cautious. The gate runs the **weakest supported model** as the conservative floor. The 0.7.0 run
  resisted 50 of 50 trials across 10 attack families; per-run results and the honest residuals are in
  [`HISTORY.md`](security/redteam/HISTORY.md).
- **Agent-behavior verification** — [`security/praxen/`](security/praxen/). An independent scan of the
  agent's own surface; **no release ships with an open Critical finding**. Every finding is tracked as
  a GitHub issue.
- **Regression evals** — [`evals/`](evals/). Worked investigations replayed to catch methodology drift.
- **AI BOM** — [`security/aibom.cdx.json`](security/aibom.cdx.json), CycloneDX, regenerated on every
  version bump and drift-checked in CI.

## Repository layout

The distributable plugin lives in **[`plugin/`](plugin/)** — that subdirectory is the *only* thing
installed on a user's machine (via a `git-subdir` marketplace source). Everything else at the repo
root is build-time only and never ships:

| Path | What it is |
|------|------------|
| [`plugin/`](plugin/) | the shipped plugin — skill, connector bridge, manifests, docs, LICENSE |
| [`plugin/README.md`](plugin/README.md) | **the operator's guide** — day-to-day use once installed |
| `tests/` · `evals/` | test + regression harnesses |
| [`security/`](security/) | AI BOM · red-team program · agent-behavior verification (the two release gates) |
| `scripts/` · `.github/` | release tooling + CI |

## Reuse it elsewhere

The skill is a portable folder of Markdown — any capable coding agent can clone this repo and follow
it against the Exabeam MCP; the packaging and the permission model are the Claude Code-specific
parts. Note what does **not** travel with it: socxen is validated on **Claude Sonnet 4.6+ or Opus**,
and the red-team evidence above is evidence about *those* models. Smaller models are not supported.

## License

[Apache-2.0](plugin/LICENSE). Contributions require a DCO sign-off — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
