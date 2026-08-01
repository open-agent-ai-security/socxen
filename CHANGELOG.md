<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to socxen. Versions track `.claude-plugin/plugin.json`; releases follow the dev→main
governance model (feature → `dev`, release `dev` → `main`).

## [Unreleased]

Post-release review fixes from the 0.6.5 Fable-class adversarial review (PR #58 comment).

### Fixed
- **`install.sh` no longer misclassifies a correct URL-added marketplace.** The community
  marketplace added via a git URL (`…add https://github.com/open-agent-ai-security/plugins`)
  rendered as an `other` source and the installer's failure advice would have removed the user's
  working marketplace. Presence detection now prefers `claude plugin marketplace list --json`
  (resolving the recorded source to `github.com/<repo>` — parsed, so the slug, https and scp
  forms all match while a lookalike host does not), keeping the pretty-print parse only as an
  older-CLI fallback.
- **The installer no longer advises removing a marketplace.** When a marketplace with our name
  points somewhere else, it is now re-pointed in place with `marketplace add` (lossless —
  installed plugins keep working) instead of failing with advice to `marketplace remove`, which
  would have uninstalled the user's praxen.
- **`plugin-smoke.sh` upgrade leg survives pre-cutover prior refs.** Crossing the #58 cutover
  boundary (prior ref tracks `marketplace.json`, target doesn't) aborted the version-flip
  checkout over the fabricated manifest; the flip now uses `checkout -f` and immediately
  re-fabricates.
- Doc/comment truthfulness: CONTRIBUTING release steps and the `bump_version.py` docstring no
  longer reference the retired marketplace edit target; an `install.sh` comment example updated
  to the current plugin id.

## [0.6.5] — 2026-07-31

**Distribution switchover.** socxen now installs exclusively from the Open Agent AI Security
**community marketplace**, [`open-agent-ai-security/plugins`](https://github.com/open-agent-ai-security/plugins)
— one `marketplace add` for every community plugin, socxen's entry pinned to this repo's `main` over
anonymous HTTPS. The plugin payload behavior is unchanged from 0.6.0.

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
```

### Removed
- **The repo-hosted `socxen` marketplace** (`.claude-plugin/marketplace.json`) — a **hard cutover**,
  no deprecation window (no external install base existed). The `socxen@socxen` install key is
  retired; an invariant test asserts no in-repo marketplace reappears (it would resurrect the dead
  key or collide with the community marketplace's registered name). Existing installs migrate with
  the migration recipe in `docs/installation.md`. (#58)

### Changed
- **Install docs and installer** target the community marketplace throughout (README,
  `docs/installation.md` incl. fleet config, CONTRIBUTING, SECURITY, bug-report template). (#58)
- **`install.sh`** judges marketplace presence on the name+source *pair* parsed from
  `claude plugin marketplace list` — the previous whole-output substring match false-detected the
  community marketplace on exactly the machines carrying a legacy repo-hosted one; a same-named
  marketplace pointing elsewhere now fails with explicit migration guidance. (#58)
- **Release machinery decoupled from the deleted manifest** — `bump_version.py` drops its
  marketplace edit target; `gen_aibom.py` pins the supplier and points its distribution reference
  at the marketplace repo; `plugin-smoke.sh`'s clean leg installs from the real community
  marketplace over the network. (#58)
- **Sister-repo alignment with praxen** — promoted under the same model (release by merge commit,
  `dev` fast-forwarded back up), and **`main` becomes the repo's default branch**, so the public
  repo page shows released state and the org's two plugins share one contribution path.

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
