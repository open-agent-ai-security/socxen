<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design: one skill pack, multiple SIEM backends

**Status:** Draft / for socialization — not yet implemented.
**Goal:** let a single `soc-investigate` skill pack investigate against **either Exabeam New-Scale or
LogRhythm SIEM** (and, later, other SIEMs) depending on what's configured — without forking the skill.

## The idea in one line

socxen's *methodology* is already platform-agnostic; only a thin layer at the bottom is Exabeam-specific.
So we don't fork the skill — we introduce a **capability-abstraction layer** and swap **backend packs**
under it.

## Where the seam falls

| Shared core (written once) | Per-backend pack (swapped) |
|---|---|
| The investigation loop (orient → pull → baseline → evidence → hypotheses → verdict → act → report) | Tool names + argument shapes |
| Governance model — dual-lock (permission deny/ask **+** ask-first before any close) | Query language + field schema |
| Triage taxonomy (raised / auto_closed / fp_closed) | Enrichment sources |
| Report template, hypothesis discipline, confidence calibration | Concrete gated-tool names + governance snippet |
| Eval harness + its two HARD safety gates | Connection / auth |

The methodology **never touches raw query syntax**. It says *"search the raw events for the entity (per
the active backend's search-cookbook)."* The query languages (Exabeam EQL/CIM vs LR log-search/LR fields)
are too different to abstract, so they live **entirely** in per-backend cookbooks. That boundary is the
whole trick.

## The capability model

The methodology refers to **named analytic primitives**; each backend binds them to its real tools. The
bindings below are grounded — New-Scale from the live MCP (20 tools, verified), LR SIEM from the
`lrsiem-mcp` surface (77 tools).

| Capability (what SKILL.md says) | New-Scale binding | LR SIEM binding |
|---|---|---|
| `get_work_item` | `exabeam_get_alert_details` / `get_case_details` | get alarm (`alarm_id`) / get case (`case_id`) |
| `search_raw_events` | `exabeam_search_events` (EQL) | log `search` (LR query) |
| `search_alerts` | `exabeam_search_alerts` | alarms search/list |
| `get_timeline` | `exabeam_get_*_threat_timeline` | case `evidence` / history |
| `get_detection_rule` | `exabeam_get_correlation_rule_details` | `list_aie_rules` / `mpe_rules` |
| `enrich_entity` | context tables (`context_table_list` / `get_context_table_records`) | `lists` + topology (`hosts` / `entities` / `networks`) |
| `escalate` (open case) | `exabeam_create_case` | create case |
| `document` | `exabeam_create_case_notes` | case `note` / `evidence` |
| **`close_dismiss` (GATED)** | `exabeam_update_alert` / `update_case` | case status (`new_status`, `resolved_classification`) / `triage_alarm` |
| **containment (ABSENT)** | none → recommend only | none → recommend only |

**Key observation:** the *last two rows are the same on both platforms.* Neither MCP exposes containment,
and both put "close/dismiss" behind a status-change write. So the safety model — the crown jewel — ports
**unchanged**: dual-lock the close, recommend containment, never execute it. That's the strongest evidence
the core is genuinely shared and belongs in one place.

## Repo structure

```
skills/soc-investigate/
  SKILL.md                     # backend-neutral methodology; refers to CAPABILITIES, not tool names
  reference/
    capabilities.md            # the abstraction: the primitives + how binding/detection works
    triage-taxonomy.md         # shared
    report-template.md         # shared
    backends/
      new-scale/               # capability-map.md, tool-map.md, search-cookbook.md (EQL),
      lr-siem/                 #   enrichment.md, governance.snippet.json   — one set per backend
connector/
  exabeam-mcp-bridge.py        # New-Scale OAuth bridge (exists)
  lrsiem/                      # the lrsiem-mcp server (exists) — registered, not re-bridged
.mcp.json                      # registers whichever backend(s) are configured
evals/
  fixtures + runs tagged by backend
install.sh                     # selects + wires the backend (see below)
```

## Backend selection & connection

Two mechanisms, one authoritative:

1. **Install-time selection (authoritative).** `install.sh` becomes the backend-selection point — this
   is the natural home for the wiring the user asked about. It:
   - prompts (or takes `SOCXEN_BACKEND=new-scale|lr-siem`) for the backend,
   - ensures the matching MCP is registered in `.mcp.json` (Exabeam bridge vs `lrsiem-mcp`),
   - scaffolds the matching **creds template** for that backend's **distinct connection model** (below),
     `chmod 600`,
   - merges that backend's `governance.snippet.json` into `~/.claude/settings.json`,
   - writes an explicit **backend marker** (e.g. `SOCXEN_BACKEND`) the skill's preflight reads first.

   Result: `./install.sh` → pick your SIEM → everything downstream (connection, creds, governance,
   which reference pack) is wired for that backend.

   **The two connection models are genuinely different — the install flow must handle each, not assume a
   shared shape:**

   | | New-Scale | LR SIEM |
   |---|---|---|
   | Creds file | `~/.exabeam-mcp.env` | `~/.lrsiem-mcp.env` (or the `lrsiem-mcp` repo `.env`) |
   | Endpoint | `EXABEAM_MCP_URL` — regional base URL (`https://api.<region>.exabeam.cloud/mcp`) | `LRSIEM_BASE_URL` — **on-prem PM host:port** (e.g. `https://<pm-host>:8501`) |
   | Auth | **OAuth client-credentials:** `EXABEAM_API_KEY` + `EXABEAM_API_SECRET`; the bundled bridge **mints & auto-refreshes** the token | **Pre-minted JWT:** `LRSIEM_API_TOKEN` (from Client Console), **no refresh** — regenerate on 401 |
   | TLS | public CA | `LRSIEM_VERIFY_TLS` (often `false` for self-signed lab PMs) |

   So the New-Scale template collects **base-url/region + key + secret** (OAuth), and the LR template
   collects **host:port + token (+ verify-tls)** (local JWT). `install.sh` writes whichever the selected
   backend needs, and only that one connects.

2. **Runtime detection (fallback / sanity check).** The skill's preflight also detects which tool
   namespace is actually live (`exabeam_*` vs LR tool names). If the marker and the live tools disagree,
   it trusts the live tools and says so. If **both** backends are connected and no marker is set, it asks.

One skill (not two), so there's no activation ambiguity between competing skills for "investigate this
alert." The backend marker + detection decide which reference pack loads.

## Governance across backends

The dual-lock model is identical; only the concrete names change, so each backend ships its own
`governance.snippet.json`:
- `allow`: that backend's read + safe-write tools.
- `ask`: that backend's close/dismiss/status-change tools (the gated set).
- `deny`: the containment-class names as defense-in-depth (absent on both MCPs today, denied anyway).

The skill's own ask-first-before-close backstop is backend-neutral — it asks about the *capability*
(`close_dismiss`), which the active pack has bound to real tool names.

## Evals across backends

The harness generalizes cleanly: a fixture gains a `backend` field; `evals/runs/<backend>/<id>.json`
holds the recorded run. The two HARD gates (no forbidden close/dismiss tool called; no forbidden outcome)
are backend-neutral — they operate on the capability, matched to the pack's tool names by suffix, exactly
as today. `--live` picks the driver/deny-list for the active backend.

## Adding a backend = filling a checklist

Once the abstraction exists, a new SIEM is a well-defined unit of work — no core changes:
1. `capability-map.md` — bind every capability in the table to real tool names + arg shapes.
2. `tool-map.md` — the full tool surface, grouped by investigation phase.
3. `search-cookbook.md` — the query language + field schema + copy-paste pivot recipes (grounded).
4. `enrichment.md` — the enrichment sources that tip FP/TP on that platform.
5. `governance.snippet.json` — allow/ask/deny with that platform's tool names.
6. `install.sh` case + `.mcp.json` entry + creds template.
7. At least one fixture + recorded run.

## Phased rollout

- **3a — Refactor to backend-pluggable, New-Scale as the first pack.** No behavior change: lift the
  existing New-Scale reference set into `backends/new-scale/`, make SKILL.md capability-neutral, add
  `capabilities.md` and the preflight/marker logic. Proves the architecture; ships as its own PR.
- **3b — Add the LR SIEM pack.** Author `capability-map` + `tool-map` + `governance` from the `lrsiem-mcp`
  surface; ground `search-cookbook` + `enrichment` against a live LogRhythm instance (creds to be wired);
  add LR fixtures. Extend `install.sh`.

## Open questions

1. **Backend marker mechanism** — env var vs a small `~/.socxen` config vs a plugin-local file. Which is
   most reliable across Claude Code's headless + interactive paths?
2. **LR query language grounding** — the LR log-search syntax + field schema need the same live grounding
   New-Scale's EQL/CIM got. Depends on a reachable LogRhythm 7.x instance + API token.
3. **"Both connected"** — is auto-ask acceptable, or should the marker always win?
4. **Naming** — keep the skill `soc-investigate` (backend-neutral) and drop "Exabeam New-Scale" from its
   description so it activates for LR too.
5. **LR containment** — confirm the LR MCP truly exposes no response/containment tools (as it appears); if
   any exist, they join the deny-list, not the allow-list.
