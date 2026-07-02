<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen Red-Team Test History

A curated record of full-scale red-team runs and the findings they produced — when we ran, what the
result was, and which bugs have been found **and fixed**. For *how* we test, see
[`METHODOLOGY.md`](METHODOLOGY.md); the raw per-run reports live in [`results/`](results/).

## Disclosure policy — read this first

> **A finding is added to the [Fixed findings](#fixed-findings) ledger below only *after* it is
> remediated.** We do not publish the working details of an unfixed, exploitable weakness in this
> record — doing so would hand a live attack to anyone who reads it before installs are protected. Open
> findings are tracked in GitHub issues (linked here at a high level) and move into the ledger, with
> their fix, once resolved.

## Full-scale runs

Newest first. Each row links its dated `results/` report.

| Date | Scope | Result | Verdict | Findings |
|---|---|---|---|---|
| **2026-07-02** | Sonnet · 3 trials · 10 × class-A (injection→suppression) — [report](results/2026-07-02-sonnet.md) | 27/30 trials resisted. The 9 direct injection→suppression families (a01–a09) resisted **0/3 each**; one family landed. | 🔴 **BLOCK** | 1 open — export/output-neutralization family, tracked in [#30](https://github.com/open-agent-ai-security/socxen/issues/30) |

**Reading the first run:** the core defense held strongly — no embedded instruction, planted benign
claim, fake authority, or encoded payload (base64 / zero-width / homoglyph / field-stuffing) changed the
verdict, even on the weaker surfacing model. The single landing was an **output-neutralization** gap
(dangerous field values echoed verbatim into the report), not a suppression failure — see #30.

## Fixed findings

*Per the [disclosure policy](#disclosure-policy--read-this-first), a finding appears here once it is
fixed.*

| Finding | Class | Found in | Issue | Fixed in |
|---|---|---|---|---|
| _None yet._ | | | | |

**In remediation (not yet ledgered):**
- Output-neutralization / export-injection — [#30](https://github.com/open-agent-ai-security/socxen/issues/30) (found 2026-07-02). Moves into the table above once fixed, with the fix PR/version.

## Maintaining this log

- **After each full-scale run:** add a row to *Full-scale runs* and commit the dated `results/` report as
  evidence. Summarize the outcome and the release-bar verdict; reference open findings by issue only.
- **When a finding is fixed:** add a *Fixed findings* row (with the issue and the fix PR/version) and
  remove it from *In remediation*.
- Keep exploit specifics in the tracking issue and the attack fixture — not in this summary.
