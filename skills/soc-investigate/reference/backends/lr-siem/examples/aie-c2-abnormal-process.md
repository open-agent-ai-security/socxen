<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Worked example (LR SIEM) — AIE C2 alarm you can't confirm *or* close

A real end-to-end `soc-investigate` run against a live **LogRhythm SIEM 7.x** instance
(demo/lab data). It shows the LR-specific craft — alarm → AIE drilldown → log pivot —
and the discipline that matters most: an alarm you can neither confirm nor false-positive
**escalates**, it doesn't get force-verdicted.

> Data is from a synthetic lab tenant, but every tool call and value is real and was run
> as shown against the `lrsiem-mcp` server.

---

## The alarm

`list_alarms` surfaced it; `get_alarm(778265)`:

- **Rule:** *AIE: C2: Abnormal Process Activity* (`alarmRuleID` 677, AIE rule 289)
- **alarmId:** 778265 · **status:** New · **RBP (risk-based priority):** **76** (rbpMax = rbpAvg = 76)
- **Classification:** Malware (Security) · **entity:** Global Entity · **eventCount:** 1
- **Fired:** 2026-07-01 00:05 (event) → 00:12 (alarm)
- **MITRE ATT&CK (rule intent):** T1071 (Application Layer Protocol / C2), T1059 (Command and Scripting Interpreter)

**Restated:** a Command-and-Control correlation rule flagged abnormal process activity at
high priority (76). C2 + Malware classification is escalate-first territory — but priority
is the detector's *claim*; pivot before concluding.

## Drill down — the underlying logs (and why they're not here)

Going from an alarm to its underlying log data is the **drill down** (`get_alarm_events`).
It's served from a **cached** copy — and `get_alarm(778265)` shows **`alarmDataCached: "N"`**,
so the drill down wasn't cached for this alarm and `get_alarm_events(778265)` returns null. (When
`alarmDataCached` is `"Y"`, the drill down returns the triggering logs directly.)

With no cached drill down, the next best view is the correlation event via
**`search_aie_events_for_alarm(778265)`**. It returned exactly one event — the AIE correlation
meta-event itself:

- `classificationName` Malware · `commonEventId` 1034846 · `priority` 76
- `logSourceName` **AI Engine** (`logSourceHostName` "AI Engine Server") — i.e. the AI
  Engine's own output, not an endpoint log
- `logMessage` is an AIE summary: `<aie>` blocks with `ProcessSet="9|5"` / `"19|18"`,
  `Login="system"`, `AIERuleID="289"` — the rule fired on **process-activity facts**, but
  the event abstracts them; there is **no concrete host, user, process name, or destination**
  in it (`entityName` / `impactedEntityName` = Global Entity, `direction` Unknown).

## Pivot — is there a real endpoint behind it?

The C2 verdict lives or dies on the underlying process logs. `search_logs_by_common_event(1034846)`
across the alarm window (2026-06-30 → 07-01):

- `FilteredLogsCount` **1** — and it's the **same AIE meta-event**. No endpoint process-create,
  no network connection, no host/user carried through.

So the correlation fired, but the raw activity that would confirm a real C2 process (a
beaconing process, a suspicious parent/child, an external destination) is not retrievable
from this data.

## Timeline

| Time (UTC, 2026-07-01) | Event | Source |
|---|---|---|
| 00:05 | AIE rule 289 correlates abnormal process facts → C2/Malware event, RBP 76 | `search_aie_events_for_alarm` |
| 00:12 | Alarm 778265 raised (status New) | `get_alarm` |
| (pivot) | Common-event search returns only the AIE meta-event — no endpoint corroboration | `search_logs_by_common_event` |

## Assessment

**Malicious hypothesis:** a real process is beaconing / behaving as C2 on a monitored host.
*Supported by:* a Malware-classified C2 correlation at RBP 76. *Missing:* any concrete
process/host/destination — nothing to tie it to a real endpoint.
**Benign hypothesis:** an AIE tuning artifact / baseline noise (the rule fired on aggregate
process facts with `Login=system`, no real actor). *Supported by:* the total absence of a
concrete entity or corroborating endpoint log. *But:* "no corroboration" is not a **positive**
benign explanation — it's absence of evidence, which is inconclusive, not FP.
**Deciding factor:** neither side is provable from the available data — the correlation is
real, the endpoint context is unavailable.

## Verdict & rationale

**Verdict: Inconclusive → escalate. Confidence: Low** (for either direction). A C2/Malware
alarm at RBP 76 must not be **closed as FP** without a positive benign explanation (there is
none), and must not be **confirmed** without positive malicious evidence (there is none). The
honest call is to raise it for a human with endpoint reach to pull the process context.

Taxonomy outcome: **raised**.

## Actions

- **Taken (dry-run — no writes executed):** would `create_case` to escalate and `add_case_note`
  documenting the gap. *(No `update_alarm_status` close — you can't dismiss an unexplained C2.)*
- **For the human, next 10 minutes:** force/refresh the **drill down** (it wasn't cached), then
  identify the host(s) feeding AIE rule 289 in the 00:00–00:10 window and pull process-create logs
  (`search_logs` by host + process classification) for a real parent/child + destination; confirm or clear.
- **Recommended containment (only if confirmed; not an LR-MCP capability):** isolate the host,
  kill/quarantine the process — performed by the analyst in EDR. Not warranted yet (unconfirmed).

## Why this is a good LR teaching case

- **The drill down may not be cached.** `get_alarm_events` (the drill down) is empty when
  `alarmDataCached` is `N`; `search_aie_events_for_alarm` gives the correlation, not the raw logs —
  forcing/refreshing the drill down or pivoting to the underlying logs is the real work.
- **RBP is a claim, not a verdict.** 76 prioritizes; it doesn't conclude.
- **"Can't confirm" ≠ "false positive."** Absence of corroboration is inconclusive → **escalate**,
  never a silent close. The close bar (positive benign explanation) is unmet, so FP is off the table.
