<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked examples & eval fixtures

Real, end-to-end `soc-investigate` runs against a live Exabeam MCP — kept here as (a) **teaching
material** for the methodology and (b) **eval fixtures** a regression harness can score the skill
against. Every example was actually run; identifiers come from a synthetic staging tenant.

## Files

Each example is a pair:

- **`<id>.md`** — the human-readable worked investigation, in `report-template.md` shape (alert →
  orient → evidence/pivots → timeline → assessment → verdict → actions).
- **`<id>.fixture.json`** — the machine-checkable expectation: the input alert and what a correct run
  must (and must not) do.

| Example | Teaches |
|---|---|
| [`coordinated-credential-access`](coordinated-credential-access.md) | Don't be fooled by a scary aggregate — a CRITICAL/99 alert over ~820 users resolves to one attacker IP; **escalate**, don't dismiss as noise or auto-close. |

## Fixture format

```jsonc
{
  "id": "…",
  "input": { "type": "alert|case", "alertId": "…", "…": "the handed-over signals" },
  "expected": {
    "taxonomy_outcome": "raised | auto_closed | fp_closed",   // see ../triage-taxonomy.md
    "verdict": "…", "confidence": "high|medium|low",
    "primary_pivot": { "type": "ip|user|host", "value": "…" }, // the pivot that decides it
    "must_cite":  ["evidence a correct run has to surface"],
    "mitre":      ["Txxxx", "…"],                              // subset match is fine
    "action":     { "tools": ["…"], "recommend_containment": ["…"] },
    "must_not":   { "outcomes": ["…"], "tools": ["…"], "reasoning": ["…"] }
  },
  "grader_notes": "how to score PASS/FAIL"
}
```

The `must_not` block is the point: the highest-value failures for this skill are **suppressing a real
threat** (a wrong `update_alert`/`update_case` close, `fp_closed`/`auto_closed` when it should escalate)
and **inventing evidence**. A fixture passes only if the run reaches the right outcome *for the right,
cited reason* — not by luck.

## Using them (until a harness lands)

There's no automated runner yet (a scoped follow-up). For now:

1. Point `soc-investigate` at `input.alertId` against a connected MCP, or paste the alert.
2. Run the investigation.
3. Diff the result against `expected` — outcome, cited evidence, MITRE, and especially the `must_not`
   list. A miss on `must_not` is a hard fail regardless of everything else.

A future harness will read each `*.fixture.json`, drive the skill headlessly, and grade per
`grader_notes` — turning these into real regression tests beyond the connector's `--check`.
