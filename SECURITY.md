<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

socxen is a security tool that investigates real alerts and can take gated actions
against a SOC platform. We take vulnerabilities in socxen itself seriously. This
document describes how to report one privately, what is in scope, and what to expect.

## Scope

**In scope** — vulnerabilities in socxen itself:

- The `soc-investigate` skill — the methodology, governance rules, and reference
  material in `plugin/skills/soc-investigate/` (`SKILL.md`, `reference/`).
- The **governance surface**: `settings.snippet.json` (the permission tiers) and
  `reference/containment-tools.md` (the deny-list) — anything that could silently
  un-gate a dismiss/close or a containment-class tool.
- The connector bridge `plugin/connector/exabeam-mcp-bridge.py` — especially OAuth
  token/secret handling and the stdio forwarding path.
- The eval harness `evals/` and its HARD safety gates.
- The plugin manifests (`plugin/.claude-plugin/*.json`), the bundled `plugin/.mcp.json`, and
  `plugin/install.sh`.

Examples of in-scope issues: a prompt-injection carried in ingested alert/event
data that flips a verdict or **bypasses the human dismiss/close gate**; a flaw that
lets the bridge log or leak the Exabeam OAuth token or API secret; a governance
drift that lets a close/containment tool run un-gated; a way to make the skill
claim or execute containment, or auto-close a case, without the human approval the
model promises; a tampered install path.

**Out of scope:**

- **Findings socxen produces about *your* alerts.** If socxen investigates an alert
  and reaches a verdict you disagree with, that's tool output (or a tuning issue),
  not a vulnerability. It is also expected that socxen surfaces suspicious activity —
  that's its job.
- **The Exabeam New-Scale platform or its MCP server.** socxen is a client of the
  Exabeam MCP; issues in the platform, its API, or the MCP server belong with
  Exabeam support/security, not here.
- **General LLM behavior** (hallucination, refusals) not tied to a socxen-specific
  defect. socxen's own mitigations — evidence-grounding, the dual-lock gate,
  untrusted-input handling — *are* in scope; a way to defeat them is a vulnerability.

## Reporting a vulnerability

**Do not file a public GitHub issue for a security vulnerability.**

Use GitHub's private security advisory:

1. Go to the **Security** tab on this repository.
2. Click **Report a vulnerability**.
3. Include enough detail to reproduce — the crafted alert/case or event payload, the
   observed behavior (e.g. the gate that was bypassed), and what should have happened.

GitHub creates a private advisory thread between you and the maintainers; we respond
there. If private advisories are unavailable to you, email **developer@exabeam.com**
with the subject **`socxen security report`** and the same level of detail.

Please **do not** include live credentials, real customer data, or unredacted PII in
a report — a synthetic repro against a test tenant is preferred.

## What to expect

- **Initial acknowledgement:** within 3 business days.
- **First substantive reply** (scope, severity, plan): within 10 business days.
- **Fix timeline:** severity-dependent; gate-bypass and credential-leak classes are
  prioritized.
- **Coordinated disclosure:** we prefer to ship the fix, then publish an advisory
  (crediting you unless you ask otherwise) and coordinate public-disclosure timing.

## Supported versions

socxen is pre-`1.0`; security fixes ship in the **latest** release. Upgrade to the
newest version (`claude plugin update socxen@open-agent-ai-security`) before reporting. There is no
back-port or LTS branch while pre-`1.0`.
