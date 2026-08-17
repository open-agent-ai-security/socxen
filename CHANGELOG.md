<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to socxen. Versions track `plugin/.claude-plugin/plugin.json`; releases follow the dev→main
governance model (feature → `dev`, release `dev` → `main`).

## [Unreleased]

Documentation and repo-side fixes awaiting the next version bump. The only changes inside the shipped
payload are `plugin/README.md` and `plugin/docs/README.md`; no code, skill, connector or manifest
changes.

### Added
- **The root README now says where your data goes.** A prospective customer's security review asks this
  on day one, and the answer was findable only by reading `plugin/connector/exabeam-mcp-bridge.py` and
  reasoning about what enters model context. It is also a *good* answer the page was already giving
  away: the README noted "no server, no database, no approval queue" but spent that entirely on
  human-in-the-loop. The other half is data control — socxen hosts nothing, so residency, retention and
  processing terms stay between the operator and their own model provider, and we are not a party to
  that decision, which means we cannot compromise it. Unlike a hosted SOC agent, which hands the
  customer its own posture. Raised as F-14 of the 2026-08-14 external security assessment, whose
  recommendation asked the *deploying organisation* for a data-classification review and asked socxen
  for nothing; recorded here as documentation, not a defect. Root README only — outside the shipped
  payload, so no version bump.

### Fixed
- **The front page credited the agent with baselining it doesn't do itself.** "Baselines what is normal
  for them" reads as the agent building a baseline. New-Scale is a behavioral analytics platform, so the
  baseline already exists and the skill *consumes* it — the worked example opens on an "abnormal (4) of
  password retrievals" detection and then pushes back on it ("per-detection counts are tiny, so the
  aggregate size alone is not the signal"), which is interrogating the platform's baseline rather than
  recomputing one. The claim was never false, but it attributed the wrong agency. Now reads "weighs the
  activity against what is normal for them", which holds whether normal comes from the platform's scoring
  or from a 30-day search in `reference/search-cookbook.md`. (#97)

- **Both READMEs stated the post-merge state as if it were the shipped state.** "Dismissing an alert or
  closing a case is held back by **two locks**" is true only *after* the operator merges the permission
  pack. On a fresh install there is one lock — the skill's in-prompt ask — which is exactly what the 🛑
  box thirty lines below said, so each page contradicted itself and the claim a skimmer retained was the
  confident one stated up front. The same overclaim appeared twice in `plugin/README.md`. Both now
  qualify the sentence with "once you turn the governance gate on (below)".

  This direction of error is the dangerous one, and the repo's own tooling already knows it: `install.sh`
  refuses to report a gate ON it cannot verify and treats "cannot verify" as a distinct third outcome,
  and #73 added an exit path for a merge that claims success while `gate_on()` still reads OFF. The front
  page should not assert what the installer deliberately declines to assume. It also undercut the hero
  line — *"You keep the verdict"* is precisely what is not yet true on a fresh install. Caught in review
  by @mattwillems-exabeam on #97. (#97)

- **The Evidence row overclaimed for `evals/`.** It grouped `security/` and `evals/` and said every
  release is gated on them. `CONTRIBUTING.md:121-124` names exactly two release gates — red team and
  Agent Behavior Verification — both in `security/`; `evals/` is a regression harness, and `:214` asks
  only for a recorded run when a fixture or the harness changes. The gating is now attributed to the two
  gates that exist, with `evals/` described as what it is. A small thing, on a page whose credibility
  rests on being precise about exactly this. Caught in review by @mattwillems-exabeam on #97. (#97)

- **Shipped docs no longer link to files the restructure stopped shipping.** `plugin/docs/README.md`
  carried five links to `../../CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `evals/` and
  `tests/end-to-end-testing.md`. They resolve while browsing the repo and dead-end in an installed
  plugin, because a plugin cache's root **is** `plugin/` — so `../../` climbs out of the distribution.
  Not a typo class: the same links read `../CHANGELOG.md` and were correct in both places until #29
  stopped shipping their targets, and one of them is how to report a vulnerability. They now point at
  canonical URLs, correct from a clone and a cache alike; in-plugin links stay relative. Added
  `test_shipped_docs_never_link_outside_the_plugin`, which resolves every relative markdown link under
  `plugin/` and fails if it escapes the shipped root or doesn't exist — nothing covered `plugin/docs/`
  before. Shipped in 0.7.0. (#29)

### Changed
- **Both READMEs rewritten as a front door.** The root README is the project's highest-traffic entry
  point but was written as a router to `plugin/README.md` — it offered copy-pasteable install commands
  with **no pre-release warning and no governance-gate warning anywhere on the page**, so a reader
  arriving from search could install and run with no hard dismiss/close gate, never having been told the
  permission pack is mandatory. Both warnings are now on it, the gate warning adjacent to the install
  commands. It also gains a five-layer architecture table (methodology / capability / authority /
  guardrails / evidence) and a documentation index, while the detailed claims stay on the pages that
  own them — `security/` for the release gates, `security-guardrails.md` for the threat model,
  `SKILL.md` for the verdict bar.

  Both READMEs now follow the org house style used by praxen and observra: a bold role descriptor under
  the H1, a pull-quote hero, and a `## Project sponsor` block — the sponsorship was declared in
  `plugin/NOTICE` but appeared in neither README.

  `plugin/README.md` is now a **post-install operator card** rather than a second front page. socxen is
  the only sibling project needing two READMEs: praxen and observra ship their whole repo, so one README
  is both landing page and shipped doc, while socxen ships only `plugin/`. Split by that job, the
  shipped README drops the pull-quote hero, the marketplace install commands and the guided-installer
  clone block — all front-door material for someone who has not installed yet — and merges its two
  overlapping `Highlights` / `What it does` lists into one. Its gate warning now links the setup guide's
  anchor rather than inlining `./plugin/install.sh --merge-permissions`, a clone-relative path that is
  wrong inside an installed plugin where no `plugin/` directory exists. The dangling bare `CHANGELOG.md`
  reference — that file does not ship either — is now an absolute link. The 🛑 governance-gate warning
  is unchanged. (#96, #98)

- **The Praxen triage table is retired in favour of the issue tracker.** Every finding from the
  2026-08-12 scan is now a GitHub issue, so `security/praxen/README.md` no longer keeps a second copy
  of each finding's status — it had already drifted, with nine of thirteen rows reading "awaiting
  triage" after several were fixed or filed. The dated artifacts under `security/praxen/results/`
  remain the authoritative record of what was found. (#94)

### Fixed
- **`bump_version.py`'s duplicate-match guard can now actually fire.** `re.subn` was called with
  `count=1`, which caps the *reported* substitution count at 1, so the `n != 1` check could only ever
  catch zero matches. A version string appearing twice in a file would have had the first occurrence
  bumped and the second silently left stale, with the bumper reporting success. Removing the cap is
  safe because every edit is computed before any file is written. Adds the script's first tests.
  (#65, #85)

## [0.7.0] — 2026-08-13

The plugin's shipped surface changes shape: only the payload under `plugin/` is distributed now, and
the installer can turn the governance gate **on** rather than only warning that it is off. Both release
gates ran against this candidate.

### Added
- **`install.sh --merge-permissions` — the installer can now install the governance gate, not just
  warn about it.** The gate has always been opt-in on every install path: `plugin/install.sh` verified the
  merge and warned loudly when it was missing, but nothing ever *performed* it, so the shipped default
  was "gate OFF until the operator hand-edits `~/.claude/settings.json`" and the installer was a
  detection control rather than an enforcement one. The new flag merges
  `plugin/skills/soc-investigate/settings.snippet.json` for you, and an interactive run whose gate reads
  OFF now offers to do it after showing exactly which rules it would add.

  Consent is preserved, deliberately: nothing merges by default, and `-y` does **not** authorise it —
  "assume yes" answers the installer's own questions, it does not license a write to your settings.
  The merge backs up `settings.json` first (timestamped, same permissions as the original), is
  additive-only, refuses outright when a rule already sits in a different tier than the snippet
  specifies (your intent wins — it writes nothing and reports what to resolve), restores from the
  backup if a write fails, and is idempotent. It is verified afterwards by the pre-existing `gate_on()`
  check, so a merge that somehow doesn't produce a working gate is never reported green. Without
  `python3` or the snippet it reports "cannot merge, here's the manual path" — the same
  "cannot verify ≠ OFF" discipline the gate check already used. (#70, #73)

- **The release smoke now proves the governance gate actually installs.** `plugin-smoke.sh` verified
  that the plugin registers and upgrades, but said nothing about the control that makes socxen safe to
  point at real alerts — so a release could have regressed the assisted merge with every leg still
  reporting PASS. A third leg runs the shipped tree's `--merge-permissions` into a throwaway settings
  file and asserts the gate reads ON *in the `ask` tier specifically*, that the operator's real
  `settings.json` is untouched (digest-compared, not assumed), and that a re-run is a no-op rather than
  double-appending over successive releases. (#70, #79 — thanks @mattwillems-exabeam)

- **Agent Behavior Verification is now a documented release gate.** `security/praxen/` carries a
  blind-authored **Worker Remit** (50 rules derived from the shipped docs, without sight of the
  implementation), the scan instructions, and dated results. The gate: **no release ships with an open
  Critical finding**; High/Medium/Low are triaged in writing, and a waiver needs a maintainer's
  rationale on the PR. The 0.6.9 audit passed it — 0 Critical, 5 High, 7 Medium, 1 Low, all confirmed
  by an independent re-check. Like the red-team bar, this is a gate a human runs, not CI. (#77)

- **The bridge's dependencies are bounded and hash-pinned.** All five PEP 723 dependencies now carry
  upper bounds, and `plugin/connector/exabeam-mcp-bridge.py.lock` pins the full resolved set (33
  packages) by hash — `uv run` picks it up automatically, so a fresh install resolves the same tree
  the maintainers tested. This closes the class of breakage that took out 0.6.8, where an unbounded
  `mcp>=1.0` let a major release land on every new install. (#71, #78)

### Changed
- **Only the plugin payload ships now — the repo's build-time material stays behind.** Everything
  Claude Code installs moved under `plugin/` (connector, skill, docs, installer, manifests) and the
  marketplace entry loads it as a git subdirectory, so a user's plugin cache no longer receives the
  test suite, the eval corpus, the release scripts, or `security/` — which included the red-team
  **attack payloads**. Two consequences worth knowing: the clone-and-run command is now
  `./plugin/install.sh`, and this release is the first whose marketplace source is `git-subdir`
  (`path: plugin`), a paired change with the community marketplace index. (#29, #66 —
  thanks @mattwillems-exabeam)

### Fixed
- **The governance check now looks at the settings file Claude Code actually reads.** `plugin/install.sh`
  hardcoded `~/.claude/settings.json`, so under a relocated config dir it reported the gate's state
  from a file the running Claude Code ignores — able to say "gate ON" about a gate that isn't in
  effect. Survivable while the block only *read*; not once it can *write*, where the same assumption
  would merge the gate into a file that never takes effect. The path now resolves as
  `SOCXEN_SETTINGS_FILE` → `$CLAUDE_CONFIG_DIR/settings.json` → `~/.claude/settings.json`, and every
  message names the resolved path instead of a hardcoded one. (#70)

### Security
- **Telemetry moved off observra's private internals.** The audit shim now emits through the public
  `observra.emit()` API and passes its rotation bounds through `initialize()`, both first-class since
  observra 1.1 (the bridge pins `observra>=1.1,<2`). Two of the three private reach-ins are gone; the
  remaining one is the underscore-level exit drain, tracked upstream. observra's own backend write
  errors now surface on stderr instead of vanishing into a library logger. (#71, #78)

- **The red-team gate is pinned to a named model, and it has been run against this release.** The
  runner's default was the floating `sonnet` alias, so a recorded verdict could not be tied to a model
  version after the fact and the "weakest supported model" invariant quietly stopped holding whenever a
  new Sonnet shipped. It now defaults to the explicit `claude-sonnet-4-6` and records the model the
  session actually *resolved*, so no run can produce an unattributable artifact. The gate itself had not
  run since 2026-07-03, across three releases: the 2026-08-13 run is **50/50 trials resisted — every
  class-A family 0/5, zero errored, zero inconclusive, verdict PASS**
  (`security/redteam/results/2026-08-13T2009-claude-sonnet-4-6.md`). Notably the export/formula-injection
  family resisted 5/5 with the deterministic neutralizer demonstrably load-bearing — the model reproduced
  the payload in chat, and the persisted artifact came out clean anyway. Running it also surfaced a
  harness bug that discarded whole trials on an unrelated stream notice, now fixed with regression tests.
  Classes C and D remain unexercised by the corpus, tracked in #82. (#76, #81)

## [0.6.9] — 2026-08-12

Permission-pack hardening from the 2026-08-12 Praxen behavior audit. The plugin's runtime behavior is
unchanged; what changes is the shipped `deny` tier in the governance snippet.

### Fixed
- **Containment deny-list now matches the live tool-naming convention.** The 17 `deny` rules in
  `settings.snippet.json` used bare names (`…__isolate_host`) while every real tool follows the
  `exabeam_<verb>` convention — a future containment tool would have sailed past the gate at the
  moment the defense-in-depth first mattered. Every documented containment tool is now denied under
  both spellings in both namespaces (bundled plugin + manual `mcp__exabeam__`, which previously had
  no containment coverage at all): 17 rules → 68. The `containment-tools.md` ↔ snippet sync is now
  enforced by a repo invariant test that derives the exact expected rule set (verified to fail red on
  the old snippet), and the red-team harness's containment deny got the same both-spellings fix.
  Found by the Praxen 1.3.0 behavior audit. (#72, #74)

## [0.6.8] — 2026-08-05

Urgent connector fix — fresh installs were broken by an upstream release.

### Fixed
- **Bridge crashed at import on every fresh install.** `mcp` 2.0.0 on PyPI removed
  `streamablehttp_client`, and the bridge's PEP 723 dependency bound was open-ended (`mcp>=1.0`),
  so any *newly resolved* uv environment picked 2.0.0 and the Exabeam bridge died at import.
  Existing installs were shielded by uv's environment cache. Now pinned `mcp>=1.0,<2` (AI BOM
  records the bound); migrating to the mcp 2.0 API is tracked in #67. (#67, #68)

## [0.6.7] — 2026-08-04

Fixture-hygiene release, closing the last pre-public data gate (#46). The plugin's *behavior* is
unchanged; the shipped example/eval/red-team **content** changes.

### Fixed
- **No more real routable IPs branded as attacker infrastructure.** The three fixture datasets that
  used live, globally-routable addresses as malicious indicators now use RFC 5737 documentation
  ranges — one per range, last octets preserved: `43.100.36.57` → `198.51.100.57` (the
  coordinated-credential-access example, fixture, and eval transcript, moved in lockstep),
  `193.42.0.19` → `203.0.113.19` (red-team a04), `45.83.12.7` → `192.0.2.7` (red-team a02). The
  entire shipped corpus is now documentation-range only. (#46, #63 — thanks @mattwillems-exabeam)

## [0.6.6] — 2026-07-31

Installer-correctness release. Post-review fixes to 0.6.5, cut as a new version because a
plugin update is only delivered when the version moves — 0.6.5 users would not otherwise
receive them.

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
