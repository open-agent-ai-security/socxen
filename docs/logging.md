<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Logging (structured audit trail) — on by default

**What it is:** a structured, durable, machine-parseable record of what the agent did on every
investigation — which Exabeam tools it called, how long they took, whether they succeeded, **the gated
action it took** (which alert/case, to what disposition), and **when the [security
guardrails](security-guardrails.md) fired**. A good agent keeps an audit trail; socxen keeps one **by
default**, so a production tenant can reconstruct a session or drive anomaly detection instead of relying
on the free-form investigation report alone.

It runs inside the local MCP bridge — the one place that sees every Exabeam call — and is built on
[**observra**](https://open-agent-ai-security.github.io/observra/), an open-source agent-telemetry SDK.
Events are written as newline-delimited JSON (one object per line) in the CIM-normalized observra schema.

## Exactly what is recorded

**One event per tool call**, plus a session marker at each end:

| `event_type` | When | Key fields |
|---|---|---|
| `mcp_session_start` / `mcp_session_end` | bridge process start / exit | `session_id`, host context |
| `tool_start` | a tool call begins | `tool_name` |
| `tool_end` | a tool call succeeds | `tool_name`, `duration_ms`, + the fields below |
| `tool_error` | a tool call raises | `tool_name`, `duration_ms`, `error_class` |

Every event also carries: `framework: "mcp"`, `agent_name: "socxen"`, `skill_name: "soc-investigate"`,
ULID `session_id` / `trace_id` / `span_id` for correlation, a `timestamp`, and host context
(`host`, `user`, `os`, `arch`, `library_version`) for accountability.

On a `tool_end`, three extra kinds of field appear when relevant:

**1. The decision record** — for a gated write (`update_alert`, `update_case`, `create_case`,
`create_case_notes`), the safe identifier/enum fields of the action, namespaced `action.*`:

```json
"action.alertId": "4471", "action.alertStatus": "closed", "action.disposition": "false_positive"
```

Captured fields: `alertId`, `caseId`, `alertStatus`, `caseStatus`, `stage`, `priority`, `severity`,
`queue`, `disposition`, `useCases`. This is *what the agent decided, on which object* — the audit-grade
core of the trail.

**2. Guardrail firings** — proof the [defenses](security-guardrails.md) acted, correlated to the exact
call:

```json
"defang_formula": 1, "defang_link": 1          // output neutralizer defanged a formula / phishing link on a write
"hygiene_stripped": 3, "hygiene_classes": "U+200B,U+202E"   // input canonicalizer stripped smuggling code points on a read
```

## What is deliberately NOT recorded (privacy by construction)

The log stores **metadata about** the agent's actions — never the raw evidence. Specifically **excluded**:

- **Free-text field values** — `note`, `alertDescription`, `alertName`, `supportingReason`,
  `closedReason`, `tags`. The case-note text and alert prose never enter the log.
- **Tool arguments and results** in general — `tool_args` / `tool_result` are always `null`.
- **The neutralized payloads themselves** — a defanged formula or phishing URL is counted, never quoted.

The whole point of the guardrails is to neutralize hostile content; the audit log must not become a second
copy of it. observra additionally applies its own PII redaction over everything above.

> `assignee` is intentionally not in the decision record. Operator identity is already captured once per
> session as host context (`user`/`host`), which is the accountability signal; the per-action assignee is
> omitted to avoid scattering it across every write.

## Where it goes, and how it stays bounded

Default backend is a **local, rotating JSON-lines file** — no network egress:

| Setting | Env var | Default |
|---|---|---|
| Backend | `SOCXEN_OBSERVRA` | `jsonl` (set `off` to disable) |
| File path | `SOCXEN_OBSERVRA_PATH` | `~/.socxen/telemetry.jsonl` |
| Rotate at size | `SOCXEN_OBSERVRA_MAX_BYTES` | `10485760` (10 MB) |
| Backups kept | `SOCXEN_OBSERVRA_BACKUPS` | `5` |

So the log **rotates** (`telemetry.jsonl` → `.1` → … → `.5`, oldest deleted) and is bounded to roughly
**60 MB** by default. It never grows without limit.

Other backends (opt-in via `SOCXEN_OBSERVRA=`): `exabeam` (routes telemetry back into Exabeam using the
bridge's own creds), `otel` / `otel_log` (OpenTelemetry), `webhook`. These make network calls, so `jsonl`
is the default. On first enable, the bridge prints one line to stderr naming the destination and how to
turn it off — disclosed, not silent.

## Finding and reading your log

By default it's at **`~/.socxen/telemetry.jsonl`** (rotated backups are `telemetry.jsonl.1` … `.5`). It's
one JSON object per line — read it with anything that speaks JSON lines:

```bash
tail -f ~/.socxen/telemetry.jsonl                      # watch events live

# the gated actions this session took (which alert, to what disposition):
jq -c 'select(.event_type=="tool_end" and (.data|has("action.disposition")))
       | {tool: .tool_name, alert: .data."action.alertId", disp: .data."action.disposition"}' \
   ~/.socxen/telemetry.jsonl

# every time a guardrail fired:
jq -c 'select(.data.defang_formula or .data.defang_link or .data.hygiene_stripped)
       | {tool: .tool_name, defang_formula: .data.defang_formula, defang_link: .data.defang_link,
          hygiene: .data.hygiene_stripped}' ~/.socxen/telemetry.jsonl
```

Events from one investigation share a `session_id`, so you can reconstruct a run by grouping on it.

## Fail-open

Logging is best-effort and can never break or slow an investigation. If observra is unavailable, a backend
is misconfigured, or an event fails to emit, telemetry **disables itself** (a one-line stderr note) and the
bridge carries on exactly as if logging were off. The security guardrails are independent and keep running.

## Turning it off

```bash
export SOCXEN_OBSERVRA=off
```

Off means *off*: no file, and observra is never imported.

## Known limitation

The trail records the **gated action and its disposition deterministically at the write sink**, and in the
[supported governance posture](installation.md#governance--turn-on-the-safety-gate-do-not-skip-this) an
`update_alert` / `update_case` write only reaches the bridge *after* the human approves it — so the write
event is evidence the approval happened. It does **not** yet capture a distinct *approver-identity* event
(who clicked yes), because that lives in Claude Code's permission layer, which the bridge cannot see. An
explicit approval event would be added via a Claude Code `PostToolUse` hook feeding the same log.
