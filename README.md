<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen
**agentic SOC analyst for Exabeam New-Scale**

[![Project level: Incubator](https://img.shields.io/badge/project_level-incubator-d29922)](https://open-agent-ai-security.github.io/project-levels/)
[![CI](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml/badge.svg)](https://github.com/open-agent-ai-security/socxen/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](plugin/LICENSE)

> ### It works your alert queue. You keep the verdict.

A Claude Code plugin that takes an Exabeam New-Scale alert or case from first look to written verdict.
Point it at one and it runs the investigation: pulls the underlying events, pivots on the entities it
finds, baselines what is normal for them, tests a benign explanation against a malicious one, and
writes up its reasoning with the evidence behind it. Then it acts — opens or updates a case, writes
notes, escalates.

**Dismissing an alert or closing a case is held back by two locks**: a Claude Code permission rule that
stops the call at the harness, and the skill asking you first. Containment is *recommended* for a human
to perform in EDR or IAM; the plugin never executes it. No server, no database, no approval queue — the
analyst at the terminal is the human-in-the-loop.

> ⚠️ **Pre-release software — for evaluation only.** socxen is under active development. Expect
> breaking changes between versions, and do not rely on it for production SOC operations or point it
> at alerts whose disposition matters without a human reviewing every action.

---

**👀 See what it produces** — a worked investigation, from alert to verdict:
[coordinated credential access](plugin/skills/soc-investigate/reference/examples/coordinated-credential-access.md).

---

## Install

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
```

> 🛑 **Then turn on the governance gate — this is not optional.** The permission pack is the only
> *hard* lock on dismiss/close. Until you merge it, the sole thing standing between a wrong verdict
> and a suppressed alert is the skill's in-prompt ask — a soft prompt to the model, not a rule the
> harness enforces. Don't point socxen at alerts you care about until it's on.
>
> ```bash
> git clone https://github.com/open-agent-ai-security/socxen.git
> cd socxen && ./plugin/install.sh --merge-permissions
> ```
>
> The flag is the consent: nothing merges by default and `-y` doesn't authorise it. To merge by hand
> instead, and to supply your Exabeam credentials (the only other setup step), follow
> **[the setup guide](plugin/docs/installation.md)**.

Then ask it to *"investigate alert &lt;id&gt;"*.

## How it's built

socxen is five separable layers, and keeping them separate is the point — a capable model with tool
access is not, by itself, something you can let near a SOC queue.

| Layer | Where | What it contributes |
|---|---|---|
| **Methodology** | [`skills/soc-investigate/`](plugin/skills/soc-investigate/SKILL.md) | the investigation *procedure* — entity pivots, baselining, competing hypotheses, an evidence bar, stopping conditions, an action matrix |
| **Capability** | [`.mcp.json`](plugin/.mcp.json) | the Exabeam New-Scale MCP — data-lake search, alerts and cases, threat timelines, rule and MITRE context |
| **Authority** | [`settings.snippet.json`](plugin/skills/soc-investigate/settings.snippet.json) | which calls run unattended, which stop for a human, which are denied outright — **enforced by Claude Code, not by the model** |
| **Guardrails** | [`connector/`](plugin/connector/) | a local bridge that treats telemetry as hostile input, and writes an audit trail |
| **Evidence** | [`security/`](security/) · [`evals/`](evals/) | red-team program, agent-behavior verification, AI BOM, regression harness — every release is gated on them |

## Documentation

| Guide | What's in it |
|---|---|
| **[Installation & setup](plugin/docs/installation.md)** | install, Exabeam credentials, the governance gate (**start here**) |
| **[Operator's guide](plugin/README.md)** | day-to-day use once installed |
| **[Methodology](plugin/skills/soc-investigate/SKILL.md)** | how it investigates, and the bar it holds a verdict to |
| **[Security guardrails](plugin/docs/security-guardrails.md)** | why telemetry is treated as hostile — and what this deliberately doesn't cover |
| **[Audit logging](plugin/docs/logging.md)** | what's recorded, where it lives, how to route or disable it |
| **[Assurance](security/)** | how socxen is red-teamed and behavior-verified before each release |

## Repository layout

The distributable plugin lives in **[`plugin/`](plugin/)** — that subdirectory is the *only* thing
installed on a user's machine (via a `git-subdir` marketplace source). Everything else at the repo
root is build-time only and never ships: `tests/` and [`evals/`](evals/) (harnesses),
[`security/`](security/) (the release gates), `scripts/` and `.github/` (release tooling and CI).

---

## Project sponsor

socxen is sponsored by [Exabeam](https://www.exabeam.com/). Exabeam contributed the initial code and
continues to provide ongoing support and contributions to the project as part of its commitment to
security in an increasingly agentic world.

---

## License

[Apache-2.0](plugin/LICENSE). Contributions require a DCO sign-off — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
