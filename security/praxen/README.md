<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# security/praxen/ — Agent Behavior Verification

**Does socxen do its job — and only its job?** This directory holds socxen's
**Worker Remit** (a plain-language policy declaring what the agent is authorized to do)
and the [Praxen](https://github.com/open-agent-ai-security/praxen) reports that check the
implementation against it.

This is the complement to [`../redteam/`](../redteam/METHODOLOGY.md). The red team asks
*"can an attacker who controls the telemetry make socxen misbehave?"* — an adversarial,
runtime question. Praxen asks *"does the shipped code actually enforce what we say our
policy is?"* — a static, whole-system question. Neither subsumes the other: the red team
exercises the paths it has fixtures for; Praxen audits every rule in the remit against the
code, including controls no fixture has ever probed.

## The release gate

> **socxen does not ship a release with an open Praxen Critical finding.**
>
> Before tagging, run a Praxen scan against the release candidate. **Any finding at
> `Critical` severity blocks the release** — it is either fixed, or explicitly waived in
> writing by a maintainer with a rationale recorded in the PR, before the tag.
>
> High / Medium / Low findings do **not** block. They are triaged into issues and carried
> in the normal backlog.

This is a **documented gate, not a CI check** — the same posture as the red-team
[release bar](../redteam/PLAN.md#release-bar). A Praxen scan is an agentic analysis, not a
deterministic test; it belongs in the release checklist a human runs, not in a workflow
that must go green on every push. See [`CONTRIBUTING.md`](../../CONTRIBUTING.md#release-gates).

Why Critical specifically: in Praxen's model a Critical is a control that is *absent or
defeated on the shipped default path* — not a hardening opportunity. For an agent that
reads attacker-influenceable telemetry and writes dispositions into a production SOC
platform, that is the class of defect that must not reach a tag.

## Current status — 0.6.9

| | |
|---|---|
| Scanned | **0.6.9** (`005fa4c`), 2026-08-12 |
| Scanner | Praxen 1.3.0, Claude Opus 5 |
| **Critical findings** | **0 — gate PASSES** |
| Other findings | 5 High · 7 Medium · 1 Low |
| Weighted RAISE posture | **2.45 / 5** (Partial) |
| Remit coverage | 50 rules — 31 verified · 18 partial · 1 gap |
| Independent audit | 13 / 13 findings CONFIRMED · 0 unsupported · 0 remit defects |

RAISE categories: Limit Your Domain 2 · Balance Your Knowledge Base 3 · Implement Zero
Trust 2 · Manage Your Supply Chain 2 · Build an AI Red Team 3 · Monitor Continuously 3.

The two 3s that carry weight: **Build an AI Red Team** is credited on the strength of the
program in [`../redteam/`](../redteam/METHODOLOGY.md) — the a10 find → fix → retest →
regression-fixture arc in [`HISTORY.md`](../redteam/HISTORY.md) is cited as a complete
feedback loop. **Monitor Continuously** is credited for the default-on structured audit
trail at the bridge's single chokepoint.

Open items raised by this scan are tracked as issues: #71 (dependency pinning /
scanning), #76 (red-team runner model alias + gate staleness). #72 (containment deny-list
naming) was found by the previous scan and **fixed in 0.6.9** — the re-scan verifies it.

## Contents

| File | What it is |
|---|---|
| `WORKER_REMIT.md` | **The policy.** What socxen is authorized to do — the standard every scan judges the code against. |
| `SCAN_INSTRUCTIONS.md` | Scan-time scope: *what to scan* for this target. Distinct from the remit, which is *what the agent should do*. |
| `results/<date>-socxen-<version>.html` | The rendered report — findings with `file:line` evidence, remit coverage, RAISE scorecard, OWASP mappings. Self-contained; open it in a browser. |
| `results/<date>-socxen-<version>.json` | The same analysis, machine-readable. |
| `results/<date>-socxen-<version>-audit.md` | Independent audit record — a context-unaware second pass that re-reads every cited line and tries to refute each finding. |

## Reproducing a scan

Praxen installs from the same community marketplace as socxen:

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install praxen@open-agent-ai-security
```

Then, from a clone of socxen at the commit you want to check:

> *"Run a Praxen analysis of this workspace against `security/praxen/WORKER_REMIT.md`,
> using `security/praxen/SCAN_INSTRUCTIONS.md` for scope."*

Add **high thinking mode** to the request when the remit has changed — it adds a
context-unaware audit pass over the findings *and* checks the remit's own rules against
socxen's documentation, at roughly 1.2× tokens and 1.8× wall-clock. That is how the
`-audit.md` record in `results/` is produced.

Scan results vary run to run — synthesis is judgment, not a fixed function. Themes are
the stable signal; treat the weighted score as advisory and the Critical count as the gate.

## Maintaining the remit

**The remit is the standard, so a defect in it is worse than a defect in a report.** An
over-broad or invented rule produces a finding that looks entirely real — correct file,
correct line, an honest violation of the rule *as written* — because the rule is what's
wrong. That cannot be spotted by reading findings; the rules have to be checked.

Two rules of thumb, both learned the hard way while authoring this one:

- **Write rules from documented intent, never from the implementation.** A remit written
  from the code describes what socxen *does*, not what it *should* do — and a scan against
  it finds nothing. This remit was authored blind, from `README.md`, `SECURITY.md` and
  `docs/**` only, with no access to `skills/` or `connector/`.
- **A rule the code does not satisfy is a finding, not a remit bug.** Those are the
  valuable rules. Only narrow a rule when the target's own *documentation* contradicts it.

When the docs settle a question, resolve it in the remit and cite the doc. When they
don't — approver identity, volume limits, whether unattended operation is permitted — it
is a maintainer decision, not something to infer. The remit's **Open Questions** section
records each one with who decided and when.

Praxen's own guidance: [Writing Worker Remits](https://open-agent-ai-security.github.io/praxen/guide/writing-remits.html),
including the *Advanced — hardening a new remit* section that describes the audit-and-review
pass used on this remit.
