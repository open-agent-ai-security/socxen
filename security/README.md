<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# security/

Supply-chain and assurance artifacts for socxen. This directory is the home for the
things a security-conscious adopter asks for — a bill of materials, and (over time)
an SBOM and behavior-assurance reports.

## Contents

| File | What it is |
|---|---|
| `gen_aibom.py` | Generator — assembles the AI BOM deterministically from the repo's own sources. |
| `aibom.cdx.json` | **AI Bill of Materials** — CycloneDX 1.6 JSON. The machine-readable inventory. |
| `aibom.html` | Human-readable render of the same BOM (self-contained, no external assets). |

Planned neighbors (not yet here): an **SBOM** (dependency bill of materials) and
**Praxen** agent-behavior reports.

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
