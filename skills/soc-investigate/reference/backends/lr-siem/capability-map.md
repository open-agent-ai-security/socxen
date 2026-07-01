<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# LR SIEM — capability map

Binds the backend-neutral **capabilities** the methodology calls (to be defined in
`../../capabilities.md` by the Phase 3a refactor) to the real LogRhythm SIEM MCP tools. Grounded in the
`lrsiem-mcp` server source (77 tools) and a live LR 7.x instance. The skill's
investigation loop refers to the left column; this table is what makes it run on LR.

| Capability | LR SIEM tool(s) | Notes / arg shape |
|---|---|---|
| `get_work_item` | `get_alarm(alarm_id)` · `get_case(case_id)` | LR work items are **alarms** and **cases**; `case_id` = case number or GUID. |
| `search_raw_events` | `search_logs` · `search_logs_by_classification` · `search_logs_by_common_event` · `search_aie_events_for_alarm` | See `search-cookbook.md`. LR has **no Lucene/EQL** — `keyword` (Message field) or a grouped `query_filter` tree; scope by `window`/`date_min`/`date_max`, `log_source_ids`. |
| `search_alerts` | `list_alarms` | Filters: `status`, `date_inserted_after/before`, `entity_name`, `alarm_rule_name`, `count`, `offset`. **Divergence:** no risk score in the list payload — `get_alarm` per alarm to rank by RBP. Case queue = `list_cases`. |
| `get_timeline` | `list_case_history` · `list_case_evidence` → `get_case_evidence` (+ `get_case_evidence_user_events`) · `get_alarm_events` | LR's "timeline" is the **case audit trail + evidence set**, not a prebuilt threat timeline. Alarm-side: `get_alarm_events` = **the drill down** (alarm → triggering logs; served from cache — empty when `alarmDataCached=N`, then pivot via `search_aie_events_for_alarm`/`search_logs`). |
| `get_detection_rule` | AIE: `list_aie_rules(engine_id)` · MPE: `list_mpe_rules` / `get_mpe_rule` | **Caveat:** AIE tools register only if the deployment ships `/lr-aie-api/*` (build-dependent; some 7.x boxes 404/timeout). MPE (log parsing) rules are always present. |
| `enrich_entity` | Lists: `list_lists` / `get_list` (membership) · Topology: `list_hosts` / `get_host` / `list_host_summaries`, `list_entities` / `get_entity`, `list_networks` / `get_network` | Host lookup by `host_identifier` (IP / DNSName / WindowsName). **Divergence:** no identity/HR enrichment tool — "users" appear only as an LR `User`-type list, case persons, or UEBA evidence (see enrichment notes). |
| `escalate` (open case) | `create_case(name, …)` | `name` required; `priority`, `summary`, `entity_id`, `external_id` optional. No dedicated "escalate" verb — raise priority/status via the close-family tools below. |
| `document` | `add_case_note(case_id, text)` · `add_case_alarm_evidence` · `add_case_log_evidence` · `add_case_user_events_evidence` | Note = evidence of type note. Attach the alarm and the log-search that made the case. |
| **`close_dismiss` (GATED)** | **`update_alarm_status(alarm_id, status)`** · **`update_case_status(case_id, status)`** · `update_case(case_id, resolution=…)` | The human-gated set. Alarm close codes: **4 Closed, 5 Closed: False Alarm, 6 Closed: Resolved, 7 Closed: Unresolved, 8 Closed: Reported, 9 Closed: Monitor**. Case status: **5 = Resolved** (1 Created, 2 Completed, 3 Incident, 4 Mitigated). `update_case.resolution` writes the FP/close rationale. |
| **containment (ABSENT)** | — none — | **Confirmed: LR SIEM MCP exposes no response/containment** (no host isolation, account disable, block, kill). Verified by grep across the source. Recommend-only, exactly as New-Scale. |

## How LR compares to New-Scale (the "one skill, two backends" test)

The methodology, governance, taxonomy, and report **port unchanged**. What differs is
contained entirely in this pack:

**Ports cleanly ✅**
- **Alarm↔alert / case↔case** — same two-tier work-item model; `get_work_item`, `escalate`, `document`,
  `close_dismiss` all bind naturally.
- **The safety model is identical.** No containment on either MCP; "close" is a gated status write on
  both. The dual-lock (permission `ask` + skill's ask-first) applies to `update_alarm_status` /
  `update_case_status` exactly as it does to `update_alert` / `update_case`.

**Diverges — lives in the pack, not the core ⚠️**
- **Query language:** LR has no EQL/CIM. It's `keyword` (Message only) or a grouped `filterType`-coded
  `query_filter` tree, plus classification/common-event shortcuts. Entirely different cookbook.
- **No risk score in the alarm list** — queue ranking needs a per-alarm `get_alarm` (RBP), unlike
  New-Scale's `riskScore` in `search_alerts`.
- **Thinner entity enrichment** — no identity/HR context tables; enrichment is LR Lists + topology
  (hosts/entities/networks) + UEBA case evidence. A "who is this user" lookup is not first-class.
- **Bigger write surface** — playbooks, collaborators, tags, list/host/log-source/rule administration.
  Most are workflow-additive; a handful are destructive (delete evidence/playbook, retire list, AIE
  enable/disable, restart engine). Governance sorts these into allow/ask/deny (see
  `governance.snippet.json`) rather than the small New-Scale set.
- **`get_timeline`** is assembled from case history + evidence rather than a prebuilt threat timeline.
- **Preflight caveat:** on this class of box the `healthcheck`/alarm APIs can be down while cases + search
  work — the skill's liveness check should not hard-fail on `healthcheck` alone.
