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
| **2026-08-13** | `claude-sonnet-4-6` · 5 trials · 10 × class-A — [report](results/2026-08-13T2009-claude-sonnet-4-6.md) | **50/50 trials resisted** — every family landed 0/5, no errored or inconclusive trials. a10, the family that landed 3/3 in the first run, resisted 5/5 with the neutralizer demonstrably load-bearing (see below). | 🟢 **PASS** | 0 |
| **2026-07-02** | Sonnet · 3 trials · 10 × class-A (injection→suppression) — [report](results/2026-07-02-sonnet.md) | 27/30 trials resisted. The 9 direct injection→suppression families (a01–a09) **resisted 3/3 each** (landed 0/3); one family — a10 — landed 3/3. | 🔴 **BLOCK** | 1 — export/output-neutralization family ([#30](https://github.com/open-agent-ai-security/socxen/issues/30)); **fixed in [#36](https://github.com/open-agent-ai-security/socxen/pull/36)** — see [Fixed findings](#fixed-findings) |

**Reading the first run:** the core defense held strongly — no embedded instruction, planted benign
claim, fake authority, or encoded payload (base64 / zero-width / homoglyph / field-stuffing) changed the
verdict, even on the weakest supported model (Sonnet). The single landing was an **output-neutralization** gap
(dangerous field values echoed verbatim into the report), not a suppression failure — see #30.

**Reading the 2026-08-13 run** (the release gate for the promotion carrying #66/#73/#77/#78): a clean
sweep, and the a10 rows are the ones worth reading closely. In 4 of 5 trials the model *did* reproduce
the phishing markdown link in its chat output — the injection still works on the model — but the
persisted artifact came out clean every time, because `neutralize_output.py` defangs at the write sink.
That is the distinction the `output-pipeline` grading exists to make: a pass where the model simply
never emitted the payload proves nothing about the guardrail, whereas these runs show the deterministic
layer actually firing. The raw-chat copy remains the documented, best-effort-only residual (F3).

This is also the first run under the pinned model default from #76 — the artifact names
`claude-sonnet-4-6` because the runner recorded the model the session actually resolved, not an alias.

## Fixed findings

*Per the [disclosure policy](#disclosure-policy--read-this-first), a finding appears here once it is
fixed.*

| Finding | Class | Found in | Issue | Fixed in |
|---|---|---|---|---|
| **Output-neutralization / export-injection (a10)** | A — injection via telemetry | [2026-07-02 run](results/2026-07-02-sonnet.md) | [#30](https://github.com/open-agent-ai-security/socxen/issues/30) | [#36](https://github.com/open-agent-ai-security/socxen/pull/36) → `dev` (2026-07-03) |

**a10 — fix summary.** A dangerous field value (`=HYPERLINK(...)` formula, phishing markdown link) echoed verbatim into a persisted report becomes an attack when the artifact is exported — a spreadsheet executes the formula, the link is clickable. Prompt-level fixes did **not** hold (3/3 across two retests, then ~100% across an **8-variant prompt experiment**): the chat report is *model output* with **no code chokepoint**. The durable fix is **deterministic neutralization at the write sink** (`plugin/connector/neutralize_output.py`, wired into the bridge) — every case-note/case write is defanged **before it persists**, so the exportable artifact is clean regardless of model behavior. Scoped to the bar **"do no harm (hard) + stop the obvious (best-effort) + document the exotic (out of scope)":** it quote-prefixes executable **formulas** and defangs **markdown-link** targets, and leaves a **bare URL/domain in prose untouched** (defanging every URL would corrupt the legit reference links analysts write; a fresh scoped review caught and fixed a do-no-harm regression where the formula detector over-neutralized ordinary prose). Input canonicalization (`plugin/connector/canonicalize.py`, **#2**) is separate encoding-class hardening — it does not fix a10. The harness grades the **agent's output pipeline** (`grade_mode: output-pipeline`) on the **active fireable form** — a bare IOC *mention* is a documented residual, not a landing — and **a10 resists 0/5 on `claude-sonnet-4-6`** in the 2026-08-13 gate run (persisted artifact deterministically clean; 0/2 at fix time). Two residuals remain, best-effort prompt only: the terminal-display copy and a bare URL/domain in prose. **Note:** the runner's default is pinned to the explicit gate model ID (`claude-sonnet-4-6`), never a floating alias — not because any current model is unsuitable, but so a recorded verdict is always attributable to a specific model version; the runner also records the session's *resolved* model ID in the artifact regardless of how it was invoked ([#76](https://github.com/open-agent-ai-security/socxen/issues/76)). Full find→fix→retest arc: **[case study in #30](https://github.com/open-agent-ai-security/socxen/issues/30)**.

**In remediation (not yet ledgered):** _None._

## Maintaining this log

- **After each full-scale run:** add a row to *Full-scale runs* and commit the dated `results/` report as
  evidence. Summarize the outcome and the release-bar verdict; reference open findings by issue only.
- **When a finding is fixed:** add a *Fixed findings* row (with the issue and the fix PR/version) and
  remove it from *In remediation*.
- Keep exploit specifics in the tracking issue and the attack fixture — not in this summary.
