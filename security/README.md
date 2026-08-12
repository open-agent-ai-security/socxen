<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# security/

Supply-chain and assurance artifacts for socxen. This directory is the home for the
things a security-conscious adopter asks for — a bill of materials, our
**red-team** program, **agent-behavior verification** reports, and (over time) an SBOM.

> **socxen is red-teamed before every release.** It's an agentic SOC analyst that reads
> attacker-influenceable telemetry and takes gated actions, so we adversarially test whether
> an attacker who controls the data can make it suppress a real threat, bypass the human
> gate, or leak. **→ [How we red-team socxen](redteam/METHODOLOGY.md)** ·
> [test history](redteam/HISTORY.md)

> **socxen is behavior-verified against a declared policy.** We publish a **Worker Remit** —
> what socxen is authorized to do — and check the shipped code against every rule in it with
> [Praxen](https://github.com/open-agent-ai-security/praxen). **A release does not ship with an
> open Critical finding.** **→ [Agent Behavior Verification](praxen/README.md)** ·
> [the remit](praxen/WORKER_REMIT.md) · [latest report](praxen/results/)

## Contents

| File | What it is |
|---|---|
| `gen_aibom.py` | Generator — assembles the AI BOM deterministically from the repo's own sources. |
| `aibom.cdx.json` | **AI Bill of Materials** — CycloneDX 1.6 JSON. The machine-readable inventory. |
| `aibom.html` | Human-readable render of the same BOM (self-contained, no external assets). |
| `redteam/METHODOLOGY.md` | **Red-team methodology** — what we test and why (the doc to point people at). |
| `redteam/HISTORY.md` | **Test history** — when full-scale runs happened, results, and the fixed-findings ledger. |
| `redteam/` | The rest of the exercise: `PLAN.md` (operational plan), `attacks/` (corpus), `run.py` (live runner), `results/` (dated reports). |
| `praxen/README.md` | **Agent Behavior Verification** — the release gate, current posture, and how to reproduce a scan. |
| `praxen/WORKER_REMIT.md` | **The Worker Remit** — the declared policy every scan judges the implementation against. |
| `praxen/` | `SCAN_INSTRUCTIONS.md` (scan scope) and `results/` (dated reports, machine-readable findings, and independent audit records). |

Planned neighbors (not yet here): an **SBOM** (dependency bill of materials).

## The AI BOM

socxen is an **AI application / agent**, not a model — it runs on a hosted
foundation model (Claude) it does not ship, and its substance is a prompt/methodology
(`SKILL.md` + `reference/`) plus a small MCP connector. Model-card AI-BOM tools (which
ingest a Hugging Face model id) can't describe that, so we author a CycloneDX AI-BOM
directly. It inventories: the root plugin, **Claude** as an external
machine-learning-model dependency, the **system prompt / methodology** as a `data`
artifact, the connector's Python **dependencies**, the **Exabeam MCP** as a service
with its inbound/outbound **data flows**, and the **governance/guardrails** (permission
tiers, human-in-the-loop, no containment).

### Regenerate

```bash
uv run security/gen_aibom.py          # rewrite aibom.cdx.json + aibom.html
uv run security/gen_aibom.py --check  # CI: fail if the BOM is stale vs the sources
```

The generator is **deterministic** (stable `uuid5` serial; timestamp honors
`SOURCE_DATE_EPOCH`, and `--check` ignores the clock), so re-running on an unchanged
repo produces the same BOM. CI runs `--check` on every PR, so a change to the plugin
version, connector dependencies, MCP, or governance that isn't reflected in the BOM
fails the build. **When you bump the version or change deps, regenerate.**
