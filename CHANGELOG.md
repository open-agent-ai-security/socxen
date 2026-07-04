<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to socxen. Versions track `.claude-plugin/plugin.json`; releases follow the dev→main
governance model (feature → `dev`, release `dev` → `main`).

## [0.6.0] — Unreleased

The first release to ship socxen's **deterministic security controls** and its **audit trail** — the
shipped **v0.5.0 had neither**. This is a feature release, not a patch, which is why the minor version
moves 0.5 → 0.6.

### Added
- **Untrusted-telemetry guardrails (a10).** The bridge now treats log data as hostile input: an **input
  canonicalizer** strips hidden-character smuggling (zero-width/bidi/etc.) from what socxen reads, and an
  **output neutralizer** defangs export/formula-injection (`=HYPERLINK(…)`) and phishing links in what it
  writes back — quote-prefixed formulas, `hxxps://…[.]…` links. Wired fail-open on reads, fail-closed on
  writes. (#36)
- **Structured audit logging — on by default.** A machine-parseable JSON-lines record of every tool call,
  the **gated-action decision** (which alert/case, to what disposition), and **when the guardrails fired**.
  Local, rotating (~60 MB ceiling), privacy-preserving (metadata + safe IDs only — never note text,
  evidence, or neutralized payloads). Built on [observra](https://open-agent-ai-security.github.io/observra/);
  `SOCXEN_OBSERVRA=off` to disable, or route to Exabeam/OTel/webhook. (#39)
- **Docs.** Restructured README into a front door; added a `docs/` index plus `security-guardrails.md`
  and `logging.md`. Maintainer note `tests/end-to-end-testing.md` covers testing real connector code
  against a live tenant.

### Notes
- Addresses Praxen findings PRAX-2026-07-03-005 (no structured/durable action log) and the a10 red-team
  finding; lifts RAISE "Monitor Continuously" 2 → 3.
- New connector dependencies (`observra`, `typing_extensions`) are inventoried in the AI-BOM.

## [0.5.0] — 2026-07-01

- Baseline `soc-investigate` skill and the bundled Exabeam New-Scale MCP bridge (OAuth token
  auto-refresh); introduced the dev/main governance model and the permission-pack safety gate.
