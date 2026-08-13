<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design: one skill pack, multiple SIEM backends

**Status:** Draft / for socialization — not yet implemented. **Revised for v0.6.0** — the security bridge
(guardrails + audit) is now the load-bearing adapter, so the seam runs through the bridge, not just the
reference packs (see § The bridge).
**Goal:** let a single `soc-investigate` skill pack investigate against **either Exabeam New-Scale or
LogRhythm SIEM** (and, later, other SIEMs) depending on what's configured — without forking the skill,
and with the v0.6.0 guardrails + audit applied uniformly to every backend.

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
| Eval harness + its two HARD safety gates | The **bridge**: transport + auth + connection |
| **Guardrail + audit *modules*** — input-canonicalization, output-neutralization, on-by-default logging (`canonicalize.py`, `neutralize_output.py`, `observra_logging.py`) | The bridge's **per-backend safety config**: `WRITE_TOOLS`, the free-text `DEFANG_FIELDS` to neutralize, the id/enum `AUDIT_FIELDS` to log |

The methodology **never touches raw query syntax**. It says *"search the raw events for the entity (per
the active backend's search-cookbook)."* The query languages (Exabeam EQL/CIM vs LR log-search/LR fields)
are too different to abstract, so they live **entirely** in per-backend cookbooks. That boundary is the
whole trick.

The last row is the one this design gained after v0.6.0: socxen is no longer just a skill + reference
packs — it's a skill over a **security bridge** (§ The bridge). The bridge is where every cross-cutting
safety control lives, so it, too, splits into a shared core and a per-backend adapter.

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
and both put "close/dismiss" behind a status-change write. So the *governance* half of the safety model —
dual-lock the close, recommend containment, never execute it — ports **unchanged**.

But governance is only half. As of v0.6.0 the safety model also includes **bridge-enforced controls** —
input-canonicalization of everything the agent reads, output-neutralization of everything it writes, and
an on-by-default audit trail. Those are **not** ported by the governance snippet; they live in the bridge.
So "the safety model ports unchanged" is only true if **each backend has a bridge that applies them** — which
is the central consequence of adopting the bridge pattern below. A backend without its own bridge (e.g. LR
today, routed straight at `lrsiem-mcp`) inherits governance but **not** the guardrails or audit — a real
gap, and the reason this design now treats the bridge as a first-class, per-backend component.

## The bridge (the adapter)

v0.6.0 turned socxen from "a skill + a thin OAuth proxy" into "a skill over a **security bridge**." The
bridge sits in the path of *every* MCP call, which makes it the one place to enforce the cross-cutting
controls — so in ports-and-adapters terms **the bridge is the adapter**, and it's where the multi-backend
seam must run for safety, not just for tool names.

What the (Exabeam) bridge composes in its `call_tool`, in order:
1. **Auth / transport** — mint+refresh OAuth, open the authenticated connection to the upstream MCP.
2. **Output neutralization** (write args, **fail-closed**) — defang formulas/phishing links in free-text
   write fields before they persist; a neutralizer error refuses the write.
3. **Proxy** — forward to the upstream MCP.
4. **Input canonicalization** (read results, **fail-open**) — strip invisible-Unicode smuggling before the
   agent reasons over telemetry; a guardrail bug never breaks a read.
5. **Audit** (on by default, fail-open) — record tool name, duration, the gated action's id/enum decision
   record, and *when the guardrails fired* — metadata only, never the free-text values.

**The factoring that makes this multi-backend-safe:** steps 2–5 are **identical logic** across backends —
they must not be re-implemented per bridge (that's precisely the drift the invariant tests exist to catch,
on the highest-consequence code). So the composition lives once in a shared **`bridge_core`**, parameterized
by a small per-backend adapter:

| Shared `bridge_core` (write once) | Per-backend adapter supplies |
|---|---|
| the `call_tool` pipeline (neutralize → proxy → canonicalize → audit) with its fail-open/fail-closed semantics | **transport** — Exabeam: streamable-HTTP to a remote MCP; LR: **stdio-proxy** launching `lrsiem-mcp` as a child |
| `canonicalize.py`, `neutralize_output.py`, `observra_logging.py` (backend-agnostic) | **auth** — Exabeam: OAuth client-credentials (refresh); LR: pre-minted JWT (no refresh) |
| | `WRITE_TOOLS` — which tools mutate (drives neutralize + audit) |
| | `DEFANG_FIELDS` — free-text fields to neutralize (Exabeam: `note, alertDescription, …`; LR: `text, resolution, summary, name`) |
| | `AUDIT_FIELDS` — id/enum decision-record fields (Exabeam: `alertId, alertStatus, disposition, …`; LR: `alarm_id, case_id, status, priority, resolved_classification`) |

So an **LR bridge** (`connector/lrsiem-mcp-bridge.py`) is a *small* adapter: JWT auth + a stdio-proxy transport
+ the three LR constant sets, importing the same `bridge_core` and the same three guardrail/audit modules.
Note the transport difference is real — Exabeam bridges a **remote** MCP; the LR MCP is a **local** stdio
server, so the LR bridge launches and proxies it (the same shape as the smoke-test harness used for grounding).

This also settles two earlier open questions:
- **Bundling / `.mcp.json`** — `.mcp.json` registers the selected **bridge**, and a bridge with no creds
  **no-ops cleanly** (exits without exposing tools) rather than erroring, so bundling both is safe.
- **Guardrail parity** — no longer a per-pack afterthought; it's structural. A backend can't ship without a
  bridge, and the bridge can't be written without the three constant sets, so the guardrails and audit come
  with every backend by construction.

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
  canonicalize.py              # SHARED guardrail — input canonicalization (backend-agnostic)
  neutralize_output.py         # SHARED guardrail — output neutralization (backend-agnostic)
  observra_logging.py          # SHARED audit — on-by-default telemetry (backend-agnostic)
  bridge_core.py               # SHARED — the call_tool composition (canon→neutralize→proxy→audit),
                               #          parameterized by {transport, auth, WRITE_TOOLS, DEFANG_FIELDS, AUDIT_FIELDS}
  exabeam-mcp-bridge.py        # New-Scale ADAPTER: OAuth + streamable-http transport + Exabeam constant sets
  lrsiem-mcp-bridge.py         # LR SIEM ADAPTER (NEW): JWT + stdio-proxy to lrsiem-mcp + LR constant sets
.mcp.json                      # registers the selected backend's BRIDGE (not the raw MCP)
evals/
  fixtures + runs tagged by backend
install.sh                     # selects + wires the backend (see below)
```

> The correction from the pre-v0.6.0 draft: LR is **not** "registered, not re-bridged." Routing the skill
> straight at `lrsiem-mcp` would bypass canonicalization, neutralization, and audit. Every backend gets a
> **socxen-owned bridge** so those controls apply uniformly; the bridge is the adapter, the MCP is upstream.

## Backend selection & connection

Two mechanisms, one authoritative:

1. **Install-time selection (authoritative).** `install.sh` becomes the backend-selection point — this
   is the natural home for the wiring the user asked about. It:
   - prompts (or takes `SOCXEN_BACKEND=new-scale|lr-siem`) for the backend,
   - ensures the matching **bridge** is registered in `.mcp.json` (the Exabeam bridge vs the LR bridge —
     never the raw upstream MCP, so the guardrails + audit are always in the path),
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
6. **The bridge adapter** — transport + auth + the three safety constant sets (`WRITE_TOOLS`,
   `DEFANG_FIELDS`, `AUDIT_FIELDS`) over the shared `bridge_core`. **This is the safety-critical item** —
   without it the backend has no guardrails or audit. A per-backend invariant test asserts the three sets
   are non-empty and the gated writes are covered.
7. `install.sh` case + `.mcp.json` entry (the bridge) + creds template.
8. At least one fixture + recorded run (+ the red-team corpus run against this backend — the injection
   attacks are backend-agnostic).

## Phased rollout

- **3a — Refactor to backend-pluggable, New-Scale as the first pack.** No behavior change: lift the
  existing New-Scale reference set into `backends/new-scale/`, make SKILL.md capability-neutral, add
  `capabilities.md` and the preflight/marker logic. Proves the architecture; ships as its own PR.
  Includes factoring the Exabeam bridge into `bridge_core` + the Exabeam adapter, so 3b's LR bridge is a
  drop-in adapter rather than a fork. Make the New-Scale fixtures + red-team corpus passing identically
  before/after the factoring the *definition* of "no behavior change."
- **3b — Add the LR SIEM pack.** Author `capability-map` + `tool-map` + `governance` from the `lrsiem-mcp`
  surface; ground `search-cookbook` + `enrichment` against a live LogRhythm instance (creds wired); add LR
  fixtures. **Build the `lrsiem-mcp-bridge.py` adapter** (JWT + stdio-proxy + the three LR constant sets) so
  LR gets guardrails + audit at parity with Exabeam. Extend `install.sh`; run the red-team corpus against LR.

## Open questions

1. **`bridge_core` factoring touches the Exabeam bridge** (Steve's v0.6.0 code). 3a must extract the
   shared composition without changing Exabeam behavior — proven by the New-Scale fixtures + red-team
   corpus passing identically before/after. Needs Steve's sign-off on the refactor shape.
2. **Backend marker mechanism** — env var vs a small `~/.socxen` config vs a plugin-local file. Which is
   most reliable across Claude Code's headless + interactive paths? (Leaning `${CLAUDE_PLUGIN_DATA}` /
   an external scope, since the plugin's `.mcp.json` is overwritten on update.)
3. **LR query language grounding** — the LR log-search syntax + field schema need the same live grounding
   New-Scale's EQL/CIM got (search API + reference tools are reachable; alarm/case now too).
4. **"Both connected"** — is auto-ask acceptable, or should the marker always win?
5. **Naming** — keep the skill `soc-investigate` (backend-neutral) and drop "Exabeam New-Scale" from its
   description so it activates for LR too.

**Resolved since the first draft:**
- ~~LR containment~~ — verified from source: `lrsiem-mcp` exposes no response/containment; close is a
  gated status write. The governance posture ports.
- ~~Bundled `.mcp.json` vs multi-backend~~ — registers the selected **bridge**; a creds-less bridge
  no-ops, so bundling both is safe. install.sh sets the marker outside the bundled file.
- ~~Guardrail parity~~ — structural now: every backend ships a bridge (checklist #6), which can't exist
  without the three constant sets, so canonicalization + neutralization + audit come with each backend.
