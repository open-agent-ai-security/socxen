<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# LR SIEM MCP — tool surface

The `lrsiem-mcp` server's tools (LogRhythm SIEM 7.x REST), grouped by investigation
phase. Governance tier in the last column: **R** = read (allow), **W** = safe
workflow write (allow), **ASK** = gated close/dismiss, **DENY** = destructive/admin
(see `governance.snippet.json`). Capability bindings: `capability-map.md`.

**Connection:** `LRSIEM_BASE_URL` (Platform Manager API gateway) + `LRSIEM_API_TOKEN`
(pre-minted JWT bearer, no OAuth refresh — regenerate in Client Console on 401),
optional `LRSIEM_VERIFY_TLS`. Pagination travels as HTTP **headers**, not query params.

## Intake — pull the work item
- `list_alarms` (R) — alarm queue; filters `status`, `date_inserted_after/before`, `entity_name`, `alarm_rule_name`, `count`, `offset`. No risk score in payload.
- `get_alarm` (R) — one alarm + RBP · `get_alarm_events` (R) — the logs that triggered it.
- `list_cases` (R) — case queue · `get_case` (R) — one case (number or GUID).

## Evidence — search & correlate (all R)
- `search_logs` — raw-log search: `keyword` (Message field) or grouped `query_filter`; scope by `window`/`date_min`/`date_max`, `log_source_ids`, `match_type` (0 literal / 1 SQL-% / 2 regex).
- `search_logs_by_classification` — by MsgClass id/name (see `list_classifications`).
- `search_logs_by_common_event` — by Common Event id (see `lookup_common_events`).
- `search_aie_events_for_alarm` — AIE events behind an alarm.
- Search reference: `describe_search_fields`, `describe_field`, `list_classifications`, `lookup_common_events`.

## Case timeline & evidence
- `list_case_history` (R) — audit/activity trail · `list_case_evidence` / `get_case_evidence` (R).
- `get_case_evidence_user_events` (R) — UEBA user events · `get_case_evidence_logs_bytes` (R) — raw log bytes · `get_case_evidence_progress` (R).
- Playbooks on a case: `list_case_playbooks`, `get_case_playbook`, `list_case_procedures`, `get_case_procedure` (R).

## Enrichment (R)
- Lists (membership): `list_lists`, `get_list`.
- Topology: `list_hosts` / `list_host_summaries` / `get_host` (by `host_identifier` = IP/DNS/WindowsName), `list_entities` / `get_entity`, `list_networks` / `get_network`.
- People (case actors, not endpoint identities): `list_persons`, `list_owners`, `list_tags`.

## Understand what fired (R)
- AIE (correlation) rules: `list_aie_rules(engine_id)` — **build-dependent** (registers only if `/lr-aie-api/*` is present).
- MPE (log parsing) rules: `list_mpe_rules`, `get_mpe_rule`.
- Log sources: `list_log_sources`, `get_log_source`.

## Act — document & escalate (W = allow)
- `create_case` — escalate/open · `update_case` (metadata + `resolution` text) · `change_case_owner`.
- `add_case_note` — note as evidence · `add_case_alarm_evidence` / `add_case_log_evidence` / `add_case_user_events_evidence` — attach what made the case.
- `add_case_tags`, `add_case_collaborators`, `attach_case_playbook`, `update_case_evidence`, `update_case_procedure`.

## Close / dismiss — GATED (ASK)
- `update_alarm_status(alarm_id, status)` — close/dismiss alarm. Close codes 4–9 (5 = Closed: False Alarm).
- `update_case_status(case_id, status)` — resolve/close case (5 = Resolved).
- Pair the close with `update_case(resolution=…)` for the rationale.

## Denied (defense-in-depth — DENY)
Destructive: `delete_case_evidence`, `remove_case_collaborators/tags/playbook`, `delete_playbook`.
Content/admin: `create/update/set_playbook*`, `clone_playbook`, list mutation (`create_or_update_list`, `add/remove_list_items`, `retire_list`), record-status (`update_host_status`, `update_log_source_status`).
Detection tuning / availability: `update_aie_rule`, `update_aie_rule_statuses`, `restart_aie_engine` (correlation outage). A triage skill doesn't tune or restart detection un-gated.

## Not present — containment
**Confirmed none.** No host isolation, account disable, block, or kill on this MCP — recommend containment in the report; the analyst performs it in EDR/IAM. Same model as New-Scale.
