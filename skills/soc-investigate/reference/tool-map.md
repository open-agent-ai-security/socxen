# Exabeam MCP — real tool surface

The 20 tools exposed by the live MCP (`k8s-mcp-server`, discovered via `list_tools`). Use these exact
names. Grouped by how they serve the investigation loop.

## Calling convention (read this first)

Each tool takes a **single wrapper object**, and the key differs by tool family — getting it wrong is
the most common first-call error:

- **Read / get / search tools → `arg0`.** e.g. `exabeam_get_case_details` → `{"arg0": {"caseId": "…"}}`;
  `exabeam_search_alerts` → `{"arg0": {"filter": "…", "fields": ["*"], "limit": 10, "orderBy": [], "startTime": "…", "endTime": "…"}}`.
- **Write tools → `arg1`** (NOT `arg0`): `exabeam_create_case`, `exabeam_create_case_notes`,
  `exabeam_update_alert`, `exabeam_update_case`.
- **No-arg tools → call with `{}`** (verified via `list_tools`: no `arg0`/`arg1`, empty schema):
  `exabeam_context_table_list`, `exabeam_correlation_rule_list`, `exabeam_analytics_rule_list`,
  `exabeam_get_mitre_coverage`, `exabeam_get_use_case_score`.

Write-tool fields (required in **bold**):

- `exabeam_create_case_notes` → `arg1: {` **`caseId`** `,` **`note`** `}`
- `exabeam_create_case` → `arg1: {` **`alertId`** `,` **`priority`** `, assignee, stage, queue, closedReason, supportingReason }`
- `exabeam_update_alert` → `arg1: {` **`alertId`** `, alertStatus (e.g. "DISMISSED"), alertDescription, alertName, priority, tags }`
- `exabeam_update_case` → `arg1: {` **`caseId`** `, stage, closedReason, supportingReason, assignee, priority, queue, tags, useCases }`

If a call returns a schema/validation error, **swap `arg0`↔`arg1` before anything else** — that's almost
always the cause.

## Intake — pull the work item
- `exabeam_get_alert_details` — full detail for an **alert** ID (use when working an alert)
- `exabeam_get_case_details` — full detail for a **case** ID (use when working a case)
- `exabeam_get_case_notes` — existing notes on a case (read before you add)

## Evidence — gather & correlate (all read-only, run freely)
- `exabeam_search_events` — **raw log/event search** from the data lake by user, host, IP, or time.
  The primary evidence workhorse; pivot on entities here. Its query language (EQL), real CIM field
  names, and copy-paste pivot/baseline recipes are in **`search-cookbook.md`** — read it before writing
  a non-trivial filter.
- `exabeam_search_alerts` — related alerts; takes the same `SearchDetails` shape as search_events.
  Real filter/return fields: `alertId, alertName, caseId, caseNumber, creationTimestamp, mitres,
  priority, product, riskScore, rules, tags, useCases, user, vendor`. `caseId:null` = alerts not yet
  triaged into a case (the queue-sweep entry point); order by `riskScore DESC`.
- `exabeam_search_cases` — related cases by status, priority, assignee, user, or time
- `exabeam_get_alert_threat_timeline` / `exabeam_get_case_threat_timeline` — prebuilt threat timelines
- `exabeam_threat_summary` — summarized threat view
- `exabeam_get_context_table_records` / `exabeam_context_table_list` — context-table enrichment
  (identity/HR, host/asset, SID/UID mapping, watchlists). `context_table_list` takes no args;
  `get_context_table_records` → `arg0: {tableId, limit, offset}`. Which tables tip FP/TP and how to use
  them: `enrichment.md`.

## Understand what fired
- `exabeam_get_correlation_rule_details` — what a correlation rule keys on (fast FP/TP tell)
- `exabeam_correlation_rule_list` / `exabeam_analytics_rule_list` — list correlation / analytics rules
- `exabeam_get_mitre_coverage` — MITRE ATT&CK coverage for the technique
- `exabeam_get_use_case_score` — use-case detection score

## Act (args under `arg1` — see Calling convention)
- `exabeam_create_case` — escalate an alert into a case *(allow — escalation is safe)*
- `exabeam_create_case_notes` — document the investigation *(allow)*
- `exabeam_update_alert` — **dismiss/update an alert** *(ASK — gated; a wrong dismissal hides a threat)*
- `exabeam_update_case` — **update/close a case** *(ASK — gated)*

## Not present (important)
There is **no entity/Attack-Surface lookup tool and no containment tool** on this server. Get entity
context by filtering `search_events`/`search_alerts` on the user/host/IP and via context tables — the
baselining recipes in `search-cookbook.md` show exactly how.
Containment (isolate/disable/block/...) is **recommended in the report only** — performed in EDR/IAM.
