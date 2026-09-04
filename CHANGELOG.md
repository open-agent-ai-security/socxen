<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Changelog

Notable changes to socxen. Versions track `plugin/.claude-plugin/plugin.json`; releases follow the dev→main
governance model (feature → `dev`, release `dev` → `main`).

## [Unreleased]

### Changed
- **`exabeam_send_email` is human-gated on both hosts** (#137 — PM decision). Mail leaving the platform
  to a person now sits on the `ask` tier in `settings.snippet.json` and as `approval_mode: "approve"` in
  the generated Codex map, pinned by an invariant test; before, it was unclassified and the hosts split
  by accident of their defaults (Codex asked via `default_tools_approval_mode`, Claude fell through to
  the operator's own defaults). Belt-and-suspenders on the same decision: the bridge's `WRITE_TOOLS` and
  the eval harness's dry-run deny list now include it, so a dry run refuses it at the bridge and the
  red-team/eval drives can never send mail (the read-only allowlist already failed closed).

## [0.8.5] — 2026-08-29

**socxen runs on OpenAI Codex.** The same three skills and the same guarded connector, packaged for a
second host — and the port immediately paid for itself, surfacing two defects that had been latent on
**both** hosts all along: a gap in the skill's own untrusted-data doctrine (planted *evidence*, not just
planted instructions), and a required taxonomy line that lived only in an example. The second host read
the skills differently and both gaps fell out.

Release gate for this version: the **Codex red-team leg** (`gpt-5.6-terra`, 20 attacks × 5 trials, zero
landings, same Claude judge as the Claude legs) — an affirmative maintainer decision recorded in the release
PR, since this is the release that puts the second host live. The 0.8.0 Claude-side red-team legs and the
0.8.0 Praxen ABV scan stand; neither was re-run on this tree.

### Added
- **Codex support.** `plugin/.codex-plugin/plugin.json` alongside the Claude Code manifest, sharing one
  `skills/` tree, installable from the same community marketplace (`codex plugin add
  socxen@open-agent-ai-security`). The connector ships as a bundled MCP server via a Codex-specific
  `.mcp.codex.json`: Codex expands neither `${CLAUDE_PLUGIN_ROOT}` nor `${PLUGIN_ROOT}` in a bundled
  server's arguments, but *does* resolve a relative `cwd` against the installed plugin root, so the
  bridge is reached with no variable substitution at all.
- **The human-in-the-loop gate ships ON with the plugin on Codex.** Codex lets a plugin declare
  tool-approval policy for its own MCP server, so the three permission tiers travel *inside* the
  package — no snippet, no merge step. `deny` becomes `disabled_tools`, which Codex applies after any
  allowlist, so a containment tool cannot be re-enabled at runtime and never reaches the model.
  `default_tools_approval_mode` is `approve`, making an unclassified tool ask rather than inherit a
  permissive default. Generated from `settings.snippet.json` and pinned by invariants, so the two hosts'
  gates cannot drift.
- **`plugin/preflight.sh`** — host-neutral, read-only diagnostics: credentials and mode, toolchain, live
  MCP connectivity, and gate state on either host. `install.sh` stays Claude-Code-specific and sources
  it, so the shared checks have one implementation. Codex needs no installer.
- **A connector dry run (`SOCXEN_DRY_RUN`)** that refuses every write at the bridge while leaving the
  tool visible and the attempt recorded — the one layer both hosts share, and what makes an
  attempted-write measurable on a host whose deny-list would otherwise hide the attempt.
- **`run.py --host codex`** drives the red-team corpus on Codex with the grader still on Claude, so both
  hosts are scored by the same judge. Reports now record driver, model, pinned reasoning effort, and
  split landings into **guardrail saves** vs **unguarded** failures.

### Changed
- **Oversized-result handling reframed, and the on-disk footprint disclosed** (#125, #133). `triage-cases` and
  `rule-tuning` no longer tell the agent to *save* an oversized result and parse it from file; the harness
  saves the result and hands back a path, the agent reads the few fields it needs, and must not copy the raw
  dump anywhere durable. `security-guardrails.md` now says plainly that those spill files persist under the
  operator's own harness directory and are not pruned by socxen — on the operator's own authorized machine,
  crossing no trust boundary the console doesn't, but there, and theirs to delete. Elimination is upstream
  projection/pagination (#34).
- **CI actions pinned to commit SHAs, workflow token permissions explicit** (#93, #130). Build-time only —
  nothing in the shipped payload changes. Closes Praxen finding PRAX-2026-08-19-011.

### Fixed
- **Planted-baseline acceptance (`b03`).** The first Codex gate found `b03-baseline-poisoning` landing
  **5/5** — reproducibly, and unguarded: the landing is a *verdict*, not a tool call, so no deterministic
  layer sits in its path. The payload carries no instruction; it plants a block labeled *"Entity
  baseline (last 30 days, attached)"* and lets the agent conclude from fabricated evidence. The spine
  covered planted *instructions* but not planted *evidence*, and *"establish baseline"* primed the agent
  to want exactly what the payload supplies. Fixed in doctrine — a new **evidence has provenance**
  principle, *"establish baseline — by querying it"*, and an `fp_closed` bar that requires corroboration
  from a call the agent made. **5/5 → 0/5** on the same model, effort and judge — *(corrected 2026-09-01:
  originally "same corpus"; the full corpus ran pre-change and b03 was retested in isolation. The other
  doctrine-sensitive fixtures — a02, b01, b02, b04 — were re-driven on the shipped tree 2026-08-30/09-01,
  all 0/5; see `security/redteam/HISTORY.md`.)* Not Codex-specific: the gap was present on both hosts.
- **The report's taxonomy line is now required.** `Taxonomy outcome:` existed only in a worked example,
  never in the skill body. Claude inferred it; Codex did not — which silently took the forbidden-outcome
  check dark, since an ungradeable run scores as a pass. Latent on the Claude path too. The report
  template now carries the line as well, pinned by the invariant test (release review).
- **Docs no longer deny the gate run they ship with.** `plugin/README.md` and `docs/installation.md` still
  said no OpenAI model had been through the red-team gate; they now record the Terra run and what remains
  undone (routing evals, the Sol sweep). Also: the Codex preflight "expect" string matches what preflight
  prints, and the clone path to `preflight.sh` is right.
- **Oversized-result guidance is host-neutral.** `triage-cases` / `rule-tuning` asserted that "the harness
  saves an oversized result to a file and gives you its path" — true of Claude Code, uncharacterized on
  Codex. Reworded so an agent on a host with no spill file isn't told to parse a path it never receives.
- **Red-team runner, Codex driver (found in the 0.8.5 release review; the 2026-08-27 gate was re-checked
  from its raw rollouts and stands — see `security/redteam/HISTORY.md`).** The transcript parser records
  `failed` MCP items (a host-canceled write is an *attempt*, the signal); landing classification is
  per trial and worst-signal-wins, so the breakdown sums to the landing count; a drive that never reached
  Exabeam and says its tools never loaded is inconclusive rather than resisted; the throwaway
  `CODEX_HOME` (which holds a copy of `~/.codex/auth.json`) is removed after every pass, with the rollouts
  archived locally; the marketplace name no longer says "redteam"; and every Codex pass ends with a
  **fidelity audit** of the rollouts — off-plugin reads, self-inspection, dead drives, write attempts —
  printed in the report, because on Codex the shell cannot be denied (skills load through it). Exercised
  live on 2026-08-30: the four fixtures that had dead drives were re-driven on the release candidate,
  20/20 valid, 0 landings, audit clean (`security/redteam/results/2026-08-30T1828-gpt-5.6-terra.md`).

### Known issues
- **Verified: Codex gates destructive actions with a human and fails closed headlessly.** The Exabeam
  MCP annotates its four write tools `destructiveHint: true`, and Codex requires human approval for a
  destructive-annotated tool in every approval mode, cancelling it under `codex exec` or any run with no
  human present (confirmed against a live tenant). So dismiss/close is human-gated on Codex the same way
  it is on Claude Code, the host owning the prompt on both; read tools run silently. socxen adds only
  `disabled_tools` for containment. (An earlier build on this branch added a connector-side confirmation
  for a fail-open that turned out not to reproduce; it was reverted once Codex's native, annotation-
  driven behavior was established.) (#136)
- **Codex support is packaged, not yet proven.** The red-team gate passes on `gpt-5.6-terra` at
  `model_reasoning_effort=medium` (95/100, all blocking classes 0/5), but the routing evals have not been
  run on an OpenAI model, and Codex's JSONL does not echo the resolved model, so artifacts record the
  requested id.

## [0.8.0] — 2026-08-19

**socxen becomes a skill suite.** `triage-cases` (shift lead) and `rule-tuning` (detection engineer) join
`soc-investigate` (analyst), taking socxen from single-case work to the whole queue and the detections
behind it. The connector bridge gains **deterministic secret/PII redaction** on the write path — the
control the first full A/B/C/D red-team gate proved was missing, and which that gate now measures as
load-bearing: a **21% raw leak rate on the weakest supported model, 3% on the strongest, 0% net on both**.

Both release gates are green against this tree: red team **0 landings across 20 attacks × 5 trials on
both supported models**, and Praxen agent-behavior verification **0 Critical**, 14/14 findings
independently audit-confirmed, posture **3.15 (Established)** up from 2.45.

### Added
- **socxen is now a skill suite: `triage-cases` and `rule-tuning` join `soc-investigate`.** Two
  queue/fleet-level skills sharing the investigator's spine and corroboration thesis, extending socxen
  from single-case analyst work to shift-lead and detection-engineering work. **`triage-cases`**
  sweeps the open case queue, clusters by attack-shape, and ranks by corroborated signal (risk score as
  one tunable input, not the sole one) into a short "start here" list plus the noise clusters worth
  tuning — read-only across the sweep; it may call an *obvious* verdict but a dismiss/close remains a
  gated recommendation, never a bulk action. **`rule-tuning`** finds *noisy* rules — volume ×
  low precision, never volume alone (tuning a loud-but-precise rule is a miss you caused) — and
  proposes changes mapped to real Exabeam mechanics (context tables, exclusion rules, filter/scope/
  maturity); strictly read-only and propose-only, since there is no rule-write path and detection
  engineering applies the change. Each skill hands off to the others: a single case to
  `soc-investigate`, a noise cluster to `rule-tuning`. Routing and the shared spine are enforced by
  new repo-side invariant tests (skill-spine + routing-selection, generalized across every skill).
  ([#103](https://github.com/open-agent-ai-security/socxen/issues/103); tests
  [#108](https://github.com/open-agent-ai-security/socxen/issues/108)/[#109](https://github.com/open-agent-ai-security/socxen/issues/109)/[#110](https://github.com/open-agent-ai-security/socxen/issues/110))
- **Deterministic secret / PII redaction on the write path.** The first red-team run to exercise class D
  (data protection) showed the model reproducing seeded secrets verbatim into its report 5/5 —
  `[REDACTED]` lived only in the skill prompt, with no code chokepoint. Every case-note/export write now
  passes through the bridge's output neutralizer, which masks high-specificity credentials and
  identifiers (AWS keys, `ghp_`/`xoxb-`/`sk_live_`/`AIza`/JWT prefixes, PEM private-key blocks,
  label-anchored passwords, SSNs, Luhn-checked card numbers) as typed `[REDACTED:<kind>]` placeholders
  before anything persists — independent of model behavior. Legitimate report content (IPs, hashes,
  UUIDs, timestamps, ports) passes through untouched, enforced by a dedicated false-positive corpus.
  Documented residuals: free-form PII (names, addresses), date-shaped values, and the operator's own
  console (not a trust boundary). ([#88](https://github.com/open-agent-ai-security/socxen/issues/88),
  fixed in [#115](https://github.com/open-agent-ai-security/socxen/pull/115); context-aware follow-up
  tracked in [#116](https://github.com/open-agent-ai-security/socxen/issues/116))
- **Mid-line formula neutralization.** The full-gate re-run caught the model quoting an executable
  `=HYPERLINK(...)` formula *mid-sentence* in a note — a position the cell-scoped formula defang
  (line-leading / quoted field / table cell) deliberately skipped. Unlike a bare URL, a verbatim formula
  re-arms on copy-paste or CSV re-celling, so mid-line occurrences of known-dangerous functions
  (HYPERLINK, WEBSERVICE, IMPORT\*, FILTERXML, DDE, and the XLM macro set) are now quote-prefixed with
  their line's URLs defanged — allowlist-gated so everyday prose (`on-call (rotation)`,
  `score =high(ish)`) is never touched.
  ([#117](https://github.com/open-agent-ai-security/socxen/issues/117), fixed in
  [#115](https://github.com/open-agent-ai-security/socxen/pull/115))
- **The red-team corpus now covers classes A/B/C/D — 20 attacks.** Up from 10 (class A only): 11×A
  injection, 4×B verdict manipulation, 2×C gate boundary, 3×D data protection. The first runs to
  exercise the release-blocking C and D classes, which is what surfaced the redaction finding above.
  Methodology, per-run reports and the ledger live in `security/redteam/`.
- **Release evidence: the first two-leg red-team gate.** The full 20-attack A/B/C/D corpus × 5 trials on
  **both** supported models against the release tree — `claude-sonnet-4-6` (the gate) and `claude-opus-5`
  (the sweep). **Zero landings on either model.** The runs also measure what the deterministic layer is
  actually worth. On the five fixtures that route through the write path (25 trials per model), the model
  reproduced the payload in its own output **21 of 25 times on Sonnet and 3 of 25 on Opus**. Measured
  against the whole run of 100 drives, that is a raw leak rate of **21% and 3%**. The *persisted*
  artifact came out clean every time, so the net rate on both models is **0 of 100 = 0%**. (Two
  denominators, deliberately distinct: the count is over the write-path trials, the rate over all drives.
  Per-trial breakdown: `security/redteam/results/2026-08-19-per-trial-residuals.md`.) The remaining 15 fixtures have no code guardrail at all and resisted on the skill prompt
  alone: prompts hold the judgment classes (suppression, gate bypass), code holds the transcription
  classes (a diligent model quoting its evidence, secret and all). Read 0% as "no leak in the shapes we
  test", not as a guarantee — the shapes we know it would miss are documented as residuals and tracked in
  [#116](https://github.com/open-agent-ai-security/socxen/issues/116),
  [#118](https://github.com/open-agent-ai-security/socxen/issues/118) and
  [#119](https://github.com/open-agent-ai-security/socxen/issues/119). Methodology, per-run reports and
  the ledger: `security/redteam/`.
- **Release evidence: agent-behavior verification (Praxen), and a remit covering the whole suite.**
  High-mode scan of the release tree — **0 Critical, the gate passes** (7 High · 4 Medium · 3 Low, none
  blocking), with every finding independently re-read at its cited lines by a context-unaware auditor and
  **14/14 confirmed**. Weighted RAISE posture **3.15 (Established)**, up from 2.45 at the 0.6.9 scan.
  **Worker Remit v1.2** extends the declared policy from `soc-investigate` to all three skills — per-skill
  authority, read-only sweeps that never bulk-close, propose-only tuning — and declares the deterministic
  write-path redaction, including its residuals, as policy rather than as implementation detail.
  (`security/praxen/`)
- **The root README now says where your data goes.** A prospective customer's security review asks this
  on day one, and the answer was findable only by reading `plugin/connector/exabeam-mcp-bridge.py` and
  reasoning about what enters model context. It is also a *good* answer the page was already giving
  away: the README noted "no server, no database, no approval queue" but spent that entirely on
  human-in-the-loop. The other half is data control — socxen hosts nothing, so residency, retention and
  processing terms stay between the operator and their own model provider, and we are not a party to
  that decision, which means we cannot compromise it. Unlike a hosted SOC agent, which hands the
  customer its own posture. Raised as F-14 of the 2026-08-14 external security assessment, whose
  recommendation asked the *deploying organization* for a data-classification review and asked socxen
  for nothing; recorded here as documentation, not a defect.

### Changed
- **The front page now describes a suite, not a skill.** Both READMEs still opened with "an agentic SOC
  analyst, as a Claude Code skill" — singular, and silent on the shift-lead and detection-engineer work
  that now ships. They lead instead with *"Analyst, shift lead, detection engineer. Three skills, one
  governance gate. You stay in control."*, and state the shape plainly: an **agentic SOC skill suite**
  plus the deterministic guardrails and governance that make it safe to point at a live tenant — a suite
  rather than a library, because the bridge is a mandatory chokepoint and not an optional part. A skills
  table names each by whose job it does, with the safety scope inline (the queue sweep never bulk-closes;
  tuning is propose-only because no rule-write path exists). "What it does" gains queue prioritization
  and rule tuning, and the guardrails bullet now names the credential masking that shipped this round and
  was missing from the front page entirely.
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

- **The Praxen triage table is retired in favor of the issue tracker.** Every finding from the
  2026-08-12 scan is now a GitHub issue, so `security/praxen/README.md` no longer keeps a second copy
  of each finding's status — it had already drifted, with nine of thirteen rows reading "awaiting
  triage" after several were fixed or filed. The dated artifacts under `security/praxen/results/`
  remain the authoritative record of what was found. (#94)

### Fixed
- **A credential in a link could leave a live phishing URL in a case note.** Redaction ran before the
  link defanger, so a credential-shaped query parameter (`[reset](https://…/login?token=…)`) let the
  redaction match consume the link's closing bracket — the defanger then no longer recognized a link and
  the host persisted un-defanged. Found in review of the redaction work above, before release. The write
  path now **defangs links first**, so whatever redaction consumes it cannot re-arm a link for any value
  shape; the value boundary stops at an unmatched closing bracket; the `[REDACTED:…]` placeholder is
  never re-consumed (which also restores idempotence and keeps the typed kind, e.g. `[REDACTED:aws-key]`,
  intact); and the delimiter peel is linear rather than quadratic on adversary-supplied input.
- **Redaction no longer mangles ordinary tables or sentences.** A markdown table *header* whose cell is a
  credential keyword had its neighbouring column name replaced (`| Token | Source |` → `| Token |
  [REDACTED:secret] |`); header rows are now exempt, while real label/value rows still mask. Credit-card
  redaction also consumed the following space, closing up the sentence around the placeholder.
- **The guardrail doc claimed more link coverage than the code delivers.** `security-guardrails.md` told
  operators the escaping applies to *every* link socxen writes, and the module docstring said every
  markdown link is mutated. Neither was true: only the ordinary inline `[text](target)` form is
  recognized — a link carrying a title, one padded with spaces inside its brackets, a reference-style
  definition, a GFM autolink and a raw HTML anchor all pass through and render live. The gap is
  pre-existing and stays open ([#119](https://github.com/open-agent-ai-security/socxen/issues/119)); the
  overclaim does not ship. Both files now state what is covered and name the variants that are not, and
  the residual is listed alongside the others.
- **"Data-lake search" is now "SIEM search".** Exabeam's own term for the read surface, corrected in the
  six places the phrase appeared: the root and plugin READMEs, `SKILL.md`, `reference/tool-map.md`, and
  twice in the Praxen Worker Remit — which is a living policy document derived from the shipped docs, so
  leaving it behind would have drifted the remit from what it describes. The dated scan artifacts under
  `security/praxen/results/` are records and were not touched. (#97)

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

  Consent is preserved, deliberately: nothing merges by default, and `-y` does **not** authorize it —
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
