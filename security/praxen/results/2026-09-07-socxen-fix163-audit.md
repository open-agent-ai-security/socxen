# socxen findings adjudication — 2026-09-07 20:55:29Z

Source findings: `reports/socxen-findings-2026-09-07.json` (schema 3.0, praxen 2.0.0-beta.1, remit 1.5)
Workspace audited (read-only): `/Users/steve.wilson/Documents/github/deckard/local/socxen-fix163-2026-09-07T2053/src`

## Audit verdicts

### PRAX-2026-09-07-001 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:639-647` (the `_DIRECTIVE_RE` comment and pattern),
`:487-493` (the wildcard-search workaround comment), `:715-743` (`_screen_tools`), and `:376-386`
(`tools()`, which caches the screened list). Both citations are exact at the cited lines: the comment at
643 reads "Surfaced (startup line + tools_list event), never altered, never blocked", and `_screen_tools`
only appends the matching tool's *name* to `acc["directive_tools"]` — the description and schema text are
passed through `_screen_text`/`_screen_schema`, which canonicalize code points only and leave the language
intact, so the directive text reaches the model verbatim. The 1,840-of-1,840 measurement is the project's
own, quoted at 489-490, and the only deterministic counter is the wildcard-argument substitution keyed to
three search tools (`_SEARCH_COLUMNS`, 494-497), exactly as the finding states. R-02 holds as cited.

### PRAX-2026-09-07-002 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:706-712` (`_definition_sha`, whose own docstring says "The
list is fetched once per process, so within a session there is nothing to compare against"),
`:415-418` (the single `telemetry.tools_list(...)` call site passing `surface_sha`/`tool_shas`), and
`plugin/connector/observra_logging.py:225-234` (`tools_list`, which only `_emit`s them). A tree-wide search
for `surface_sha` / `tool_shas` returns only the emitter, the docs (`plugin/docs/logging.md:34`, which tells
the operator to "compare across sessions"), a test, and the CHANGELOG — nothing in the shipped payload reads a
prior session's hashes back, and no signature or version pin exists. The `observra_logging.py:227` citation is
inside the `tools_list` function (def at 225), so it resolves. No `policy_rule_ids`; nothing to re-status.

### PRAX-2026-09-07-003 — CONFIRMED

Read `plugin/docs/installation.md:365-371` (the "Any other agent" section — the quoted sentence is verbatim
and the section carries no gate caveat of any kind), `:170-190` and `:250-260` (the two places the gate and the
"keep permissions on" warning *are* prominent, both scoped to Claude Code and Codex),
`plugin/skills/soc-investigate/SKILL.md:128-130` (the quoted "can be switched off … your explicit ask is the
lock that always holds" is verbatim) and `:137-143`, and `plugin/hooks/gate.py:1-30` (whose header states the
`deny` holds under `--dangerously-skip-permissions` and the `ask` fires in every mode). Both halves of the claim
check out: the third install path has neither host enforcement layer nor a missing-gate warning, and the skill
text both understates the bundled hook and elevates the in-prompt ask above the harness gate — which R-58
prohibits in terms and R-37's "active on a fresh install" requirement does not reach on that path.

### PRAX-2026-09-07-004 — CONFIRMED

Read `plugin/skills/soc-investigate/SKILL.md:33-35`, `plugin/skills/triage-cases/SKILL.md:37-38`, and
`plugin/skills/rule-tuning/SKILL.md:37-38`. All three carry the instruction at or within a line of the cited
locations, verbatim ("run `claude mcp list` (Codex: `codex mcp get exabeam`)"). Attempted refutation via the
remit's own carve-outs: the Tools section (WORKER_REMIT.md:202-204) says host built-in tools follow the host's
defaults but names exactly one host tool socxen relies on (the spill-file read), and R-24's carve-out sentence
covers only that read — so instructing the model into the host's shell tool at preflight is a second host
capability outside the declared inventory, as claimed. The finding does not over-claim: it states the command
is fixed, read-only and argument-free.

### PRAX-2026-09-07-005 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:1013-1026` — `texts = [t for t, _ in (_block_text(b) for b in
content) if t]` then `raise _UpstreamToolError(_safe_text(" ".join(texts) …))`, and the handler emits
`telemetry.tool_error(..., error_message=str(e) + suffix)` — plus `_safe_text` at `:920-927` (canonicalize +
`cap=300`), confirming "capped at 300 characters and canonicalized but otherwise verbatim" precisely. Read
`plugin/docs/logging.md:90-97` — line 96 reads "**Tool arguments and results** in general — `tool_args` /
`tool_result` are always `null`" verbatim — and `:38`, whose `error_message` column is scoped "for a remote
failure", while the code emits it on the `upstream_tool` stage as well. R-33 holds as cited.

### PRAX-2026-09-07-006 — CONFIRMED (with a line-reference note)

Read `plugin/skills/soc-investigate/permissions.json` in full (the only copy in the tree) and
`plugin/skills/soc-investigate/reference/tool-map.md:56`. The tool-map quotation is verbatim at line 56. The
permissions.json line numbers in the evidence are drifted — `exabeam_parser_list` / `exabeam_get_parser_details`
are at lines 26-27, not 29-30, and `exabeam_get_use_case_score` is at line 17, not 21 — but all three names are
in the `allow` tier of the cited file, and the remit's Allowed Tools baseline (WORKER_REMIT.md:191-197)
enumerates neither parser reads nor a use-case score, so the substance is unrefuted; the drift is a citation
defect, not a wrong reading. The hook's prompt-free allow over that tier is confirmed at
`plugin/hooks/gate.py:17-30`.

### PRAX-2026-09-07-007 — CONFIRMED

Read `plugin/docs/installation.md:182` ("its *allow* on the 16 read tools and the two escalation writes" —
verbatim), counted the tier file (`allow` = 21 entries, of which `exabeam_create_case` and
`exabeam_create_case_notes` are writes, so 19 reads), read
`plugin/skills/soc-investigate/reference/tool-map.md:8` ("The 23 tools exposed by the live MCP") against
`plugin/skills/soc-investigate/SKILL.md:274` ("the **real 21 tools** this MCP exposes"; the same "all 21 tools"
figure recurs at SKILL.md:172). Both miscounts are exactly as stated, and the CI drift gates named in the
positives cover generated artifacts only. R-28 holds as cited.

### PRAX-2026-09-07-008 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:86-96` (`p = urlparse(URL)` then a POST of `client_id` /
`client_secret` to `f"{p.scheme}://{p.netloc}/auth/v1/token"`) and `:1099-1106` (`main()` exits only on
`not (URL and KEY and SECRET)`). A tree-wide grep for scheme validation over `EXABEAM_MCP_URL` finds none in
the bridge, `plugin/install.sh`, or `plugin/preflight.sh` — https appears only in example values. The secondary
claim also holds: `ALLOWED_LINK_HOSTS = tenant_hosts_from_url(URL)` (`:399`) and
`plugin/connector/neutralize_output.py:301-314` take the hostname irrespective of scheme. No `policy_rule_ids`;
nothing to re-status.

## Remit feedback

### R-20 — "Allowed Tools (Known Good Baseline)"

- **Defect class:** under-inclusive allow-list closure — the list omits a read the target's own documentation
  describes as routine operation, so documented operation violates the closure.
- **Doc citation:** `plugin/skills/soc-investigate/SKILL.md:173-176` puts `exabeam_threat_summary` inside the
  standard "Gather evidence (read-only, run freely)" step, and
  `plugin/skills/soc-investigate/reference/examples/coordinated-credential-access.md:38-42` works it into a
  shipped example; `plugin/skills/soc-investigate/reference/tool-map.md:66-67` lists it as a tool distinct from
  `exabeam_get_alert_threat_timeline` / `exabeam_get_case_threat_timeline`. The remit's baseline
  (WORKER_REMIT.md:191-193) enumerates "threat timelines" but no threat summary, so socxen's own documented
  evidence-gathering step calls a tool the baseline does not name. (The heading-as-rule extraction itself is
  correct — the heading sits over a real allowlist with a closure clause at R-21 — so only the list content is
  at issue.)
- **Findings it drives:** PRAX-2026-09-07-006 (verdict unchanged: CONFIRMED). The tools that finding names are
  not covered by this defect — the parser reads are documented as "classified allow ahead of the MCP exposing
  it" (`tool-map.md:56`), i.e. not routine operation at all, and `exabeam_get_use_case_score` appears in the
  tool map but in no documented workflow step.
- **Narrower obligation the docs support:** enumerate the baseline against the read tools the shipped tool map
  documents as in use (adding the threat summary), and keep the closure aimed at what it is actually for —
  a tool the MCP does not yet expose, or that no skill uses, must not sit in the prompt-free allow tier.

No other cited rule (R-02, R-24, R-28, R-33, R-37, R-58) failed the four-question check: each demands a
mechanism the code or docs already implement (`gate.py` for R-37, the CI `--check` steps for R-28,
`plugin/docs/logging.md:90-97` for R-33), none prohibits a behavior the docs present as an intended feature
that could not be delivered another way — R-24's shell prohibition is satisfiable by the tool-visibility check
the finding itself proposes — and none bundles a sound prohibition with a routine-operation extension.

## Audit summary

- CONFIRMED: 8
- UNSUPPORTED: 0
- REMIT-DEFECT: 0
- Remit-feedback entries: 1 (R-20)

Every finding survived refutation. All eight rest on evidence that reads as cited in the pinned workspace, and
in each case the load-bearing quotation is verbatim: the `_DIRECTIVE_RE` comment's "never altered, never
blocked", `_definition_sha`'s own "nothing to compare against", the "Any other agent" section's silence on the
gate, the three identical preflight shell instructions, the `_UpstreamToolError` branch's `error_message`, the
allow tier's parser entries, the "16 read tools" miscount against a 19-read tier, and the unvalidated URL scheme
on the token POST. One citation defect is worth correcting in the report rather than against the finding:
PRAX-2026-09-07-006's `permissions.json` line numbers are drifted by three to four lines, though the names are
in the cited tier of the cited file. The single rule-level issue is R-20's baseline list, which omits
`exabeam_threat_summary` even though the skill's own evidence-gathering step calls it; fixing that list makes
finding 006's real complaint — a tool pre-classified allow before the platform exposes it — stand on its own
rather than sharing a closure that documented routine operation already breaches.

## Cleanup record

**No cleanup was required.** All eight findings returned CONFIRMED; there were no UNSUPPORTED and no
REMIT-DEFECT verdicts, so no finding block was removed, no `related_findings` entry was stripped, no remit
rule was re-statused, and no RAISE category score was re-derived. The Phase-1 artifacts are the final
deliverable **unchanged** — they are not renamed `-raw`, because no audited replacement was produced:

- Report:   `reports/socxen-analysis-2026-09-07-205529.html`
- Findings: `reports/socxen-findings-2026-09-07.json`
- Summary:  `reports/socxen-analysis-2026-09-07-205529.txt`
- Draft manifest: `reports/socxen-draft-2026-09-07-205529.md`
- Evidence checkpoint: `reports/socxen-evidence-2026-09-07-205529.txt`

Weighted overall stands at **3.55 / 5.0 (Established)** on the Phase-1 category scores (Limit Your Domain 3,
Balance Your Knowledge Base 3, Implement Zero Trust 4, Manage Your Supply Chain 4, Build an AI Red Team 4,
Monitor Continuously 3), since no removed finding could have been load-bearing in any rationale.

**Orchestrator spot-check:** the high-mode rule requires opening the auditor's cited contradicting evidence
for each UNSUPPORTED verdict before acting on it. There were none, so no spot-check was owed and none was
performed.

**Carried forward, not actioned here:**

1. *Remit feedback (R-20)* — the auditor's `## Remit feedback` section is the **remit owner's fix list, not
   the agent's risk list**. A thinking mode never edits the Worker Remit, so R-20's under-inclusive
   Known-Good-Baseline closure (omitting `exabeam_threat_summary`, which the shipped `soc-investigate` skill
   calls in its routine evidence-gathering step) stays as written in the coverage table and is handed to the
   remit owner.
2. *Citation drift, PRAX-2026-09-07-006* — the auditor found the `plugin/permissions.json` line references
   drifted by three to four lines (parser tools at 26-27; `exabeam_get_use_case_score` at 17). The named tools
   are in the `allow` tier of the cited file, so the finding is unaffected; the drift is recorded here rather
   than corrected, because high-mode cleanup edits the manifest only to remove killed findings.

**Provenance:** Praxen high thinking mode — Phase 1 standard scan (fresh-context subagent), Phase 2
context-unaware findings audit (fresh-context subagent, on-disk inputs only), Phase 3 orchestrator cleanup.
Subject pinned at commit `8eb6c2433de99c03e89d882042c892ae437ca661`.
