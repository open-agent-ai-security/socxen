<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# LR SIEM backend pack

The **LogRhythm SIEM** backend for the `soc-investigate` skill — the per-backend half
of the multi-backend design (`docs/multi-backend-architecture.md`, PR #16). The
shared methodology (investigation loop, governance dual-lock, triage taxonomy, report
template) lives in the core; everything LogRhythm-specific lives here.

Runs against the [`lrsiem-mcp`](https://github.com/…/lrsiem-mcp) server (LR SIEM 7.x
REST, 77 tools). Connection: `LRSIEM_BASE_URL` + `LRSIEM_API_TOKEN` (pre-minted JWT).

> ⚠️ **Security — connection.** LR auth is a **pre-minted JWT with no refresh**
> (`LRSIEM_API_TOKEN`) — treat it like a password: `chmod 600` the creds file, and rotate it
> in Client Console on any suspected exposure (there's no short-lived-token safety net). And
> **`LRSIEM_VERIFY_TLS=false` is lab-only** — it disables TLS certificate verification, a real
> man-in-the-middle exposure. **Do not set it `false` against a production PM;** install a
> trusted cert and leave verification on.

## Contents & status

| File | Status | Grounded in |
|---|---|---|
| `capability-map.md` | ✅ done | `lrsiem-mcp` source (77 tools) + live tool schemas |
| `tool-map.md` | ✅ done | source, grouped by investigation phase |
| `governance.snippet.json` | ✅ done | read/write classification from source annotations |
| `examples/` worked example + fixture + recorded run | ✅ done | **grounded live run** against LR 7.x — alarm 778265 (AIE C2/Malware) |
| `search-cookbook.md` | ⏳ pending | field catalogue + classifications + `query_filter` structure captured; **live query examples pending** |
| `enrichment.md` | ⏳ pending | lists + topology + UEBA; pending live |

## Grounded run — the merge blocker is cleared

Per `CONTRIBUTING.md`, **a backend is not mergeable without at least one grounded run.**
That's now in: `examples/aie-c2-abnormal-process.{md,fixture.json}` + the recorded run at
`evals/runs/aie-c2-abnormal-process.json`, graded by the (now backend-aware) harness —
`uv run evals/run.py` passes it, HARD safety gates included. The `search-cookbook.md` and
`enrichment.md` remain as follow-ups but don't block the pack.

> **Open guardrail gap (required for safety parity).** v0.6.0 added always-on bridge
> guardrails on the **Exabeam** path — input canonicalization on read results and output
> neutralization (defang formulas/links) on free-text write args (`connector/canonicalize.py`,
> `neutralize_output.py`). The LR path goes through `lrsiem-mcp` (a separate server), so **it is
> not yet guarded** — LR telemetry reaches the agent un-canonicalized and LR case-note/resolution
> writes go out un-neutralized. Closing this needs a per-backend mediation point that reuses the two
> (backend-agnostic) guardrail modules, plus an LR **free-text-write-field** list to neutralize
> (`add_case_note.text`, `update_case.resolution`, evidence notes). Tracked as an architecture item in
> the multi-backend design (#16).

### Live-access note (2026-07)

Grounding was done against a live LR 7.x instance. Observed from a CLI (stdio)
subprocess:
- ✅ **Work live:** `list_alarms` / `get_alarm` / `search_aie_events_for_alarm`, `list_cases` /
  `get_case`, the search API (`search_logs*`), and all static reference tools
  (`describe_search_fields`, `list_classifications`, `lookup_common_events`).
- ⚠️ **Unreliable:** `healthcheck` (returns `ReadTimeout` / `Event loop is closed`) even when
  the data APIs respond — and the alarm API was down for a stretch while the box was being worked
  on. `get_alarm_events` returns null unless the alarm's drill down is cached (`alarmDataCached=Y`).

**Consequence for the skill's LR preflight:** **do not hard-fail on `healthcheck` alone** — use
`list_cases` / `describe_search_fields` as the liveness probe. And when a drill down is uncached,
pivot via `search_aie_events_for_alarm` / `search_logs` rather than treating an empty
`get_alarm_events` as "no evidence."

## Migration note

New-Scale's reference set has not yet moved to `backends/new-scale/` — that's the
Phase 3a refactor (see the design doc). Until then this pack sits alongside the
current New-Scale reference files; it does not change New-Scale behavior.
