<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen documentation

The details behind the [project README](../README.md). Start with installation; the rest you reach for
when you need it.

## Guides

- **[Installation & setup](installation.md)** — **start here.** Install from the community marketplace
  on Claude Code or Codex,
  add your Exabeam credentials, and — optionally — merge the **permission rules** as a second lock
  (the human-in-the-loop gate itself ships ON, on both hosts, and reads already run without a prompt). Also covers updating, fleet auto-update, running
  the skill from any other agent, and uninstalling.

- **[Using the skills](usage.md)** — what to say, what happens, and what socxen asks you before it acts:
  the investigation loop, the two locks on dismiss/close on each host, what it will never do, how to read
  the report and its three outcomes, and how triage and tuning hand off.

- **[Security guardrails](security-guardrails.md)** — the two always-on defenses against hostile content
  planted in your telemetry: screening hidden-character *smuggling* out of what socxen reads, and
  *de-activating* dangerous content (spreadsheet formulas, clickable links) in what it writes. Explains
  why a link in a note may look "broken" (`hxxps://…[.]…`) — that's the safety measure working — and,
  honestly, what these guardrails do **not** cover.

- **[Audit logging](logging.md)** — the structured, on-by-default audit trail: exactly which fields are
  recorded (tool calls, the gated decision, guardrail firings) and which are deliberately **not** (case
  notes, evidence, payloads). Where the log lives (`~/.socxen/telemetry.jsonl`), how to read it, how to
  bound/route/disable it, and its privacy and fail-open guarantees.

## Where the rest lives

Not in this folder, but part of the docs picture:

- **Methodology** — how socxen actually investigates: [`skills/soc-investigate/SKILL.md`](../skills/soc-investigate/SKILL.md).
- **Reference** — tool map, EQL search cookbook, enrichment playbook, triage vocabulary, report
  template, containment list, and worked end-to-end examples: [`skills/soc-investigate/reference/`](../skills/soc-investigate/reference/).
- **Governance snippet** — the permission block you merge during setup:
  [`skills/soc-investigate/settings.snippet.json`](../skills/soc-investigate/settings.snippet.json).
- **Regression harness** — [`evals/`](https://github.com/open-agent-ai-security/socxen/blob/main/evals/).
- **End-to-end testing of real connector code** (maintainers) — [`tests/end-to-end-testing.md`](https://github.com/open-agent-ai-security/socxen/blob/main/tests/end-to-end-testing.md):
  how to test through the *skill* against a live tenant, and why a connector change needs a host-agent restart.
- **Version history** — [`CHANGELOG.md`](https://github.com/open-agent-ai-security/socxen/blob/main/CHANGELOG.md).
- **Contributing / security policy** — [`CONTRIBUTING.md`](https://github.com/open-agent-ai-security/socxen/blob/main/CONTRIBUTING.md),
  [`SECURITY.md`](https://github.com/open-agent-ai-security/socxen/blob/main/SECURITY.md).
