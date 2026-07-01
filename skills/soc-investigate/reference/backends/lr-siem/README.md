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

## Contents & status

| File | Status | Grounded in |
|---|---|---|
| `capability-map.md` | ✅ done | `lrsiem-mcp` source (77 tools) + live tool schemas |
| `tool-map.md` | ✅ done | source, grouped by investigation phase |
| `governance.snippet.json` | ✅ done | read/write classification from source annotations |
| `search-cookbook.md` | ⏳ pending | field catalogue + classifications + `query_filter` structure captured; **live query examples pending** |
| `enrichment.md` | ⏳ pending | lists + topology + UEBA; pending live |
| eval fixture + recorded run | ⛔ blocked | **needs a grounded live run** (CONTRIBUTING §Evals) |

## Not yet mergeable

Per `CONTRIBUTING.md`, **a backend is not mergeable without at least one grounded
run.** This pack ships the source-grounded core for review, but the eval fixture +
recorded run are still needed.

### Live-access note (2026-07)

Grounding was done against a live LR 7.x instance. Observed from a CLI (stdio)
subprocess:
- ✅ **Work live:** `list_cases` / `get_case`, the search API (`search_logs*`), and all
  static reference tools (`describe_search_fields`, `list_classifications`,
  `lookup_common_events`).
- ⚠️ **Time out:** `healthcheck` and the **alarm API** (`list_alarms` / `get_alarm`) —
  consistently, even across service restarts, while the LR **web console** responded
  normally. This points at the alarm REST endpoint specifically, not general host health.

**Consequence:** the grounded run should either (a) be built on a **case** work item
(the case API is reliable) rather than an alarm, or (b) wait for stable alarm-API
access. The skill's LR preflight must also **not hard-fail on `healthcheck` alone** —
use `list_cases`/`describe_search_fields` as the liveness probe.

## Migration note

New-Scale's reference set has not yet moved to `backends/new-scale/` — that's the
Phase 3a refactor (see the design doc). Until then this pack sits alongside the
current New-Scale reference files; it does not change New-Scale behavior.
