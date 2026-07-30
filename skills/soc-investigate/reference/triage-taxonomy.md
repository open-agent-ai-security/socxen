<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Triage taxonomy

The three terminal outcomes (ported from Nova's `triage_outcomes.py`). Use these exact words for the
verdict so results stay countable across investigations.

| Outcome | Meaning | Terminal action |
|---|---|---|
| **raised** | Escalated — a case was opened (or an existing case kept open) for human review. | Alert: `exabeam_create_case`. Case: `exabeam_update_case` (active/escalated) + notes. |
| **auto_closed** | Resolved without escalation — investigated and concluded benign-enough to close, not a clear FP rule. | Alert: close. Case: `exabeam_update_case` (resolved) + notes. |
| **fp_closed** | Suppressed as a false positive — a positive benign explanation was found. | Alert: `exabeam_update_alert` (dismiss). Case: `exabeam_update_case` (closed-FP) + notes. |

Notes:
- **raised** is the right call for a confirmed threat *and* for genuinely inconclusive cases — when in
  doubt, escalate to a human rather than auto-close.
- **fp_closed** requires a *positive* benign explanation (known automation, documented change,
  expected admin behavior). "I found nothing suspicious" without an explanation is **raised**
  (inconclusive), not **fp_closed**.
- These map to the same metrics Nova tracks (close-rate = auto_closed + fp_closed over total), so the
  skill's outcomes stay comparable to the server's if you ever reconcile them.
