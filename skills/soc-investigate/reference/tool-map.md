# Exabeam MCP — real tool surface

The 20 tools exposed by the live MCP (`k8s-mcp-server`, discovered via `list_tools`). Use these exact
names. Grouped by how they serve the investigation loop.

## Intake — pull the work item
- `exabeam_get_alert_details` — full detail for an **alert** ID (use when working an alert)
- `exabeam_get_case_details` — full detail for a **case** ID (use when working a case)
- `exabeam_get_case_notes` — existing notes on a case (read before you add)

## Evidence — gather & correlate (all read-only, run freely)
- `exabeam_search_events` — **raw log/event search** from the data lake by user, host, IP, or time.
  The primary evidence workhorse; pivot on entities here.
- `exabeam_search_alerts` — related alerts by priority, user, IP, MITRE technique, rule, or time
- `exabeam_search_cases` — related cases by status, priority, assignee, user, or time
- `exabeam_get_alert_threat_timeline` / `exabeam_get_case_threat_timeline` — prebuilt threat timelines
- `exabeam_threat_summary` — summarized threat view
- `exabeam_get_context_table_records` / `exabeam_context_table_list` — context-table enrichment

## Understand what fired
- `exabeam_get_correlation_rule_details` — what a correlation rule keys on (fast FP/TP tell)
- `exabeam_correlation_rule_list` / `exabeam_analytics_rule_list` — list correlation / analytics rules
- `exabeam_get_mitre_coverage` — MITRE ATT&CK coverage for the technique
- `exabeam_get_use_case_score` — use-case detection score

## Act
- `exabeam_create_case` — escalate an alert into a case *(allow — escalation is safe)*
- `exabeam_create_case_notes` — document the investigation *(allow)*
- `exabeam_update_alert` — **dismiss/update an alert** *(ASK — gated; a wrong dismissal hides a threat)*
- `exabeam_update_case` — **update/close a case** *(ASK — gated)*

## Not present (important)
There is **no entity/Attack-Surface lookup tool and no containment tool** on this server. Get entity
context by filtering `search_events`/`search_alerts` on the user/host/IP and via context tables.
Containment (isolate/disable/block/...) is **recommended in the report only** — performed in EDR/IAM.
