<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to socxen. Versions track `.claude-plugin/plugin.json`; releases follow the dev→main
governance model (feature → `dev`, release `dev` → `main`).

## [0.6.4] — 2026-07-31

Release-machinery hardening, cut as the repo went public. The plugin payload behavior is unchanged
from 0.6.0.

### Added
- **Branch-drift check** — a daily scheduled workflow asserts the governance invariant that `main`
  is always an ancestor of `dev`, catching a missed post-release fast-forward or an accidental
  squash promotion the day it happens. (#52)
- **Release and rollback playbook** in `CONTRIBUTING.md`: cutting a release, rolling one back with
  forward reverts (never force-push), and repairing already-diverged histories. (#52)
- **Post-release install smoke** — `scripts/release/plugin-smoke.sh` exercises a clean install of
  the current release and an upgrade from the prior one in throwaway `CLAUDE_CONFIG_DIR`s, never
  touching the maintainer's live install. (#52)

## [0.6.3] — 2026-07-30

Public-readiness release — docs, repo hygiene, and metadata from the go-public review. The plugin
payload behavior is unchanged from 0.6.0 (payload files gained only license-header comments).

### Added
- **Pre-release notice** front and center in the README: evaluation purposes only, expect breaking
  changes. (#45)
- **Issue templates** for a public tester audience: a bug-report form (versions, governance-gate
  state, redact-your-tenant-data reminder) and routing of security reports to private advisories
  per `SECURITY.md`. (#47)
- **SPDX/copyright headers on all source** (30 files: connector, skill corpus, tests, evals,
  installer, scripts) plus a repo invariant so coverage can't regress. (#48)
- **CODEOWNERS** — maintainers auto-requested on every PR. (#48)

### Fixed
- **CONTRIBUTING test command** now matches CI's dependency set; the old form failed at collection
  on missing `jsonschema`. (#47)
- **README status line** no longer pins a stale version. (#47)
- **AI BOM** declares verified SPDX license ids for the connector's dependencies. (#48)

## [0.6.2] — 2026-07-30

Installer fix release — the plugin payload (skill, connector, guardrails, permission pack) is
unchanged from 0.6.0.

### Fixed
- **Installer re-runs now actually update.** `claude plugin install` is a silent no-op when the
  plugin is already installed, so re-running `install.sh` left existing installs stale while
  reporting success. The installer now detects an existing install and runs `claude plugin update`
  (with the full `name@marketplace` spec and explicit `--scope`), reports the real version
  transition, and never reports green when the installed state is unverified. Adds `--skip-update`
  to opt out. (#43)

## [0.6.1] — 2026-07-14

Docs and install-experience release — the plugin payload (skill, connector, guardrails, permission
pack) is unchanged from 0.6.0.

### Added
- **Architecture figures.** Two self-contained diagrams with light/dark PNGs: the runtime **guardrail
  bridge** (input canonicalizer / output neutralizer / observra tap) in `docs/security-guardrails.md`,
  and the **red-team harness** (runner → agent under test → grader → release verdict) atop
  `security/redteam/METHODOLOGY.md`. One shared renderer, `scripts/render_diagram.py`. (#41)
- **Installer.** `install.sh` gained a connectivity preflight and skip flags. (#25)

## [0.6.0] — 2026-07-04

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
