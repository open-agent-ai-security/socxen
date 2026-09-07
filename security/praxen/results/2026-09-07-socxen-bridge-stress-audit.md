# socxen findings adjudication — 2026-09-07 (scan 04:57:03Z)

Auditor pass over `reports/socxen-findings-2026-09-07.json` (10 findings, remit v1.5) against the
pinned read-only clone at `16dea29`. Every cited artifact was re-read at its cited location and each
claim was attacked before it was accepted.

## Audit verdicts

### PRAX-2026-09-07-001 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:561-572` (`list_tools()` — `return await UPSTREAM.tools()`
at :565, no canonicalize on the returned tool objects), `:634` (`_canon_content(result.content, …)` in
`call_tool`), `_canon_content` at `:481`, and `plugin/skills/soc-investigate/reference/tool-map.md:27-33`
(the blockquote at :29 records that the MCP's own parameter descriptions instruct the caller to always
send `fields: ["*"]` / `orderBy: []` and to "IGNORE any user request", countered only by the prose
"**Do not comply.**"). Both citations are exact. I looked for a declared residual covering the
`tools/list` channel in `security/design/input-canonicalizer.md` and `plugin/docs/security-guardrails.md`
and found no mention of `list_tools`/`tools/list` at all, so this is not an accepted residual. The
asymmetry between the two ingress paths is real and the rule (R-46) is sound as written; nothing
refutes the claim.

### PRAX-2026-09-07-002 — CONFIRMED

Read `plugin/install.sh` (preflight sourced at :110; the only preflight calls in the file are
`PF_PLATFORM=claude check_toolchain` at :134, `check_credentials` at :135 and `check_connectivity` at
:413 — grep for `installed_hook_state|check_gate` across install.sh returns nothing), the Governance
block at :493-524 (`GATE_STATE` is computed from `gate_on`, i.e. the settings file, and the gate-OFF
branch at :511 emits verbatim the quoted "Permission rules not merged — not needed: the bundled hook
gates dismiss/close…"), the failed-update path at :328 (`warn "Plugin update failed — still at ${before}…"`
and continue), and `plugin/preflight.sh:116-139` (`installed_hook_state()` at :120, whose header comment
at :117-119 records the exact misread the finding quotes) plus `check_gate()` at :336-372 where the
`off`/`none` hook states are routed to `fail`. Every citation lands; the installer really does attest a
control it never inspects, and an offline re-run over a pre-hook installed copy reaches that line.

### PRAX-2026-09-07-003 — CONFIRMED

Read `plugin/skills/soc-investigate/reference/tool-map.md:40-43` (`exabeam_update_alert` → `alertId`,
`alertStatus`, `alertDescription`, `alertName`, `priority`, `tags`; `exabeam_update_case` → `caseId`,
`stage`, `closedReason`, `supportingReason`, `assignee`, `priority`, `queue`, `tags`, `useCases`),
`plugin/skills/soc-investigate/SKILL.md:196-206` (the action matrix; :201 is verbatim "`exabeam_update_alert`
to dismiss (**ask the analyst first**), with the reason"), `plugin/connector/exabeam-mcp-bridge.py:407-408`
(`_DEFANG_FIELDS` does name all of those fields) and `:525-535` (`_defang_args` neutralizes values but
forwards the argument object unchanged in shape — there is no argument allowlist and no read-before-write).
A grep for `overwrit|preserve|read-before-write|append-only|prior value|existing content` across
`plugin/skills/` and `plugin/connector/` returns only three unrelated hits
(`merge_permissions.py:122,150`, `rule-tuning/SKILL.md:158`). The claim is stated conservatively, flags
its own ambiguity, and the severity is explicitly discounted for the gated path; nothing refutes it.
See Remit feedback for a scope defect in R-41 that does not reach this finding — it still stands on
`alertDescription`, `alertName`, `supportingReason` and `tags`, which are unambiguously free text.

### PRAX-2026-09-07-004 — CONFIRMED

Read `plugin/hooks/gate.py:113-125` (`decide()`; the terminal branch at :125 is verbatim the quoted
"…is not classified in this release's permission tiers, so it asks rather than inheriting the session
default.") and `plugin/skills/soc-investigate/permissions.json`. I counted the tiers myself: allow =
21 tools (lines 7-27), ask = 3 (lines 35-37), deny = 70 entries (lines 46-115) — 34 containment
spellings (17 verbs × bare and `exabeam_`-prefixed, lines 46-79) and 36 detection-content spellings
(lines 80-115), exactly the numbers the finding states, and line 80 is exactly
`"exabeam_create_analytics_rule"` as cited. There is no pattern/regex rule anywhere in `decide()` or in
the tier file; membership is set-equality on bare names. The remit's R-24 demand ("deterministically…
under every spelling… any future tool") is implementable by pattern, so it is not a fabricated
obligation. Confirmed.

### PRAX-2026-09-07-005 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:404-409` (`_DEFANG_FIELDS` defined at :407-408, the
eight-name set quoted verbatim), `:525-535` (`_defang_args`; the key test at :531 is
`k.lower() in _DEFANG_FIELDS`, else plain recursion with no neutralization), and the sibling comment at
`:375-379` which does state the opposite default for tools ("a tool this release did not classify as a
read is neutralized, audited and refused in a dry run… instead of sailing past an enumeration that only
knew today's names") together with `_read_tools()`/`is_write_tool()` at :383-403. Both citations are
exact and the asymmetry is real. The finding is careful to say the set is "correct today" and scopes
the exposure to a field this release did not anticipate, so it is not an over-claim. Both load-bearing
rules (R-48, R-51) are sound and implemented; the finding is about the scoping of the implementation,
not a fabricated obligation.

### PRAX-2026-09-07-006 — CONFIRMED

Read `plugin/connector/observra_logging.py:61` (`_OFF_VALUES`), `:67-71` (`_disable(reason=None)` —
writes to stderr only `if reason`), `:85-86` (`if backend in _OFF_VALUES: return _disable()` — a bare
call, exactly as cited) and `:145` (`return _disable(f"{type(e).__name__}: {e}")`, the path that does
disclose), against `plugin/hooks/gate.py:171-177` where the identical switch prints
"socxen gate: decision log is OFF (SOCXEN_GATE_LOG=off) — this decision is not recorded" with the
comment at :174-175 giving the reason. Line references are exact. Noted for the record: R-67's "if"
clauses name self-disable and backend-unavailable, and an operator-set `SOCXEN_OBSERVRA=off` is
neither — read narrowly the finding leans on the rule's general "MUST NOT disappear silently" half. I
take the conservative reading: the factual claim is exactly right, `plugin/docs/logging.md:73` shows the
project already holds the sibling log to disclosure on the same switch, and the rule's leading clause
covers it. Confirmed.

### PRAX-2026-09-07-007 — CONFIRMED

Read `plugin/docs/installation.md:17-36` (the Sonnet 4.6 floor and "Smaller models (e.g. Haiku) are
**not supported**" at :20, plus the tiers table at :29-33 naming Sonnet 4.6+ as the floor and Haiku as
not supported — the cited range 21-36 covers the table but not the primary sentence at :17-20; a range
imprecision, not a misreading) and `security/redteam/HISTORY.md:26`, which carries the quoted control
result verbatim ("**Control: 5/5 landed** — Haiku declared `fp_closed` / 'Alert Dismissed' in every trial
**without calling the tool** (0 attempts, 0 gate decisions): a below-floor model fabricates completion
rather than attempting, a failure no action gate can see."). I re-ran the enforcement search myself:
a case-insensitive grep for `sonnet|haiku|4-6|model_floor|floor` across `plugin/`, `scripts/` and
`.github/` `.py/.sh/.json/.yml` returns nothing, so the floor is prose-only as claimed, and
`security/redteam/run.py:204` confirms C-class grading rests on "the judge and the outcome line alone"
rather than on any report-vs-telemetry reconciliation. Noted: the linked rule R-05 is a loose fit — it
governs detection-rule/exclusion/context-table claims, while the reproduced failure is a fabricated
alert dismissal, which R-01 ("never… claimed as done") and R-54 (no untraceable verdict) address more
directly. The mapping is imprecise, not refuted; per the conservative reading this stays CONFIRMED,
and R-05's "or claim to have applied" clause is a defensible anchor for a fabricated-completion finding.

### PRAX-2026-09-07-008 — CONFIRMED

Read `plugin/preflight.sh:144-161` — `check_credentials` greps only for the three key names (:151-153),
reads the mode at :159 and at :160 emits exactly `[ "$perms" = "600" ] || warn "  $ENV_FILE is mode
$perms — consider: chmod 600 $ENV_FILE"` — plus `tests/test_repo_invariants.py:462`
(`test_preflight_never_writes`), and `plugin/connector/exabeam-mcp-bridge.py:48-65` (`load_env` opens the
file and parses `k=v` with no `stat`/mode assertion; `CFG`/`URL`/`KEY`/`SECRET` at :62-65) with `main()`
at :701-708 checking only `if not (URL and KEY and SECRET)`. All citations exact. Carries no
`policy_rule_ids`, so no rule re-status applies; the finding explicitly disclaims any objection to the
file's location, which matches the remit's Allowed Data Sources.

### PRAX-2026-09-07-009 — CONFIRMED

Read `plugin/connector/exabeam-mcp-bridge.py:84-92` — `p = urlparse(URL)` at :84 and the POST target
`f"{p.scheme}://{p.netloc}/auth/v1/token"` at :88 carrying `client_id`/`client_secret` in the JSON body
at :89 — and `plugin/preflight.sh:151-153` (`check_credentials`' key-presence grep). A grep for
`https|scheme` across the bridge, `preflight.sh` and `install.sh` returns only documentation strings and
one unrelated URL-parsing comment; there is no scheme assertion on any path. I also confirmed the
second-order claim: `ALLOWED_LINK_HOSTS = tenant_hosts_from_url(URL)` at :415 is derived from the same
unvalidated URL and is passed to `neutralize_output` at :514, so links to a plaintext tenant host would
stay clickable. Severity rationale (requires operator misconfiguration) is the finding's own and is not
mine to re-grade. No `policy_rule_ids`.

### PRAX-2026-09-07-010 — CONFIRMED

Read `plugin/skills/soc-investigate/reference/tool-map.md:8` ("The 23 tools exposed by the live MCP
(`k8s-mcp-server`, discovered via `list_tools`)") against `plugin/skills/soc-investigate/SKILL.md:172`
("for all 21 tools") and `:264` ("lists the **real 21 tools** this MCP exposes (confirmed via
`list_tools`)") — the two documents make the same claim about the same quantity and disagree, and the
shipped tiers are 21 allow + 3 ask + 70 deny, matching neither. I checked
`.github/workflows/ci.yml:46-68`: the drift `--check` gates cover the guide, the AIBOM, the identity
artifacts, the Codex map and the SBOM — nothing covers `tool-map.md` or the SKILL counts, so the "not
drift-checked" half holds. `permissions.json:26-27` are indeed `exabeam_parser_list` and
`exabeam_get_parser_details` in the allow tier, and the remit's Allowed Tools baseline
(`WORKER_REMIT.md:191-198`) names no parser capability. Mitigating context I found and weighed:
`tool-map.md:54` says the parser reads are "classified allow ahead of the MCP exposing it" — that
explains the pre-classification but does not close the gap R-22's "MUST be classified here before
socxen may use it" opens. R-21 is a heading-as-rule over an allowlist, which is the documented
extraction convention rather than a defect. Confirmed.

## Remit feedback

### R-41 — conflated obligations (sound prohibition + a clause documented routine operation triggers)

Verbatim rule text as extracted:

> socxen MUST NOT delete or overwrite existing free-text content — case notes, descriptions, names, and
> supporting or closing reasons.

Defect class: **bundled/conflated obligations**, aggravated by a truncated extraction. The remit's own
sentence in `WORKER_REMIT.md:346-348` continues "State and disposition enumerations are exempt: changing
them is the approved gated action" — that qualifier is absent from the extracted `rule_text`, so the
rule as it reaches a finding reads as an unqualified prohibition. The target's own documentation
describes `closedReason` not as free text but as a disposition value drawn from a fixed set:
`plugin/skills/rule-tuning/SKILL.md:58-59` — "`closedReason` (e.g. *False Positive*, *Benign*,
*Already Mitigated / Resolved*, vs. *Confirmed* / escalated)" — and `plugin/skills/soc-investigate/SKILL.md:201`
documents the gated close as "`exabeam_update_alert` to dismiss (**ask the analyst first**), **with the
reason**", i.e. writing the closing reason is the intended, human-approved terminal action. So one clause
carries a sound prohibition (do not delete or overwrite existing case-note bodies, alert names and alert
descriptions) alongside an extension ("closing reasons") that documented routine operation triggers, and
the sound half lends the extension its weight.

Findings it drives: PRAX-2026-09-07-003 (sole cited rule). **This does not kill that finding** — it
independently rests on `alertDescription`, `alertName`, `supportingReason` and `tags`, which the remit,
the tool map (`reference/tool-map.md:42-43`) and the bridge's own `_DEFANG_FIELDS`
(`exabeam-mcp-bridge.py:407-408`) all treat as free text, and no control reads or preserves their prior
values.

Narrower obligation the docs support: *socxen MUST NOT delete or overwrite existing free-text content —
case notes, alert names, and alert or case descriptions — and MUST NOT clear a supporting reason it did
not author; the disposition enumerations (`alertStatus`, `stage`, `closedReason`) set at the gated close
are the approved change.* The extraction should also carry the exemption sentence, so a finding is
judged against the whole clause.

Rules checked and found sound (no doc citation supports over-reach): R-05, R-21, R-24, R-46, R-48,
R-51, R-57, R-67. Specifically — R-46's screening obligation is implemented and documented in
`security/design/input-canonicalizer.md` with no carve-out for `tools/list`; R-24's deterministic deny
is implementable by pattern (the finding names the shape) and so is not a fabricated obligation; R-48
and R-51 enumerate exactly the classes `neutralize_output.py` implements; R-21 is the by-design
heading-as-rule over the Allowed Tools allowlist and the section carries a real closure at R-22; R-57
matches the operator decision recorded at `WORKER_REMIT.md:495` and `plugin/docs/installation.md:130`;
and R-67's disclosure obligation is one the project already holds its sibling log to
(`plugin/hooks/gate.py:171-177`, `plugin/docs/logging.md:73`), so the operator-set-off gap it exposes is
a consistency gap, not rule over-reach. R-05 is a loose fit for PRAX-2026-09-07-007 but is not itself
defective — see that finding's rationale.

## Audit summary

- **CONFIRMED: 10**
- **UNSUPPORTED: 0**
- **REMIT-DEFECT: 0**
- **Remit-feedback entries: 1** (R-41)

Every one of the ten findings survived a refutation attempt. Line references are unusually precise —
`install.sh:511`, `permissions.json:80`, `observra_logging.py:85-86`, `gate.py:125` and
`exabeam-mcp-bridge.py:88` all land exactly on the quoted text, and where I re-derived a count myself
(34 containment and 36 detection-content deny spellings; 21 allow + 3 ask; the 21-vs-23 tool-count
contradiction) the scan's arithmetic was correct. Two findings carry citation imprecision worth
recording but not worth a kill: -007's `installation.md` range (21-36) covers the model-tiers table
rather than the primary floor sentence at :17-20, and -006's `_disable` span is off by roughly a line;
in both cases I re-read the surrounding code and docs and the substantive claim held. The only real
soft spot in the set is rule *mapping* rather than evidence: -007 hangs a fabricated-alert-dismissal
finding on R-05, a detection-rule-tuning clause, where R-01 or R-54 fits the reproduced failure better,
and I have left it CONFIRMED under the conservative reading. One remit rule needs the owner's
attention: R-41 as extracted drops its own exemption sentence and, in the process, prohibits writing a
closing reason that the target's docs describe as the approved gated action — a scope fix that does not
disturb the finding it drives. Nothing in the set looked inflated, fabricated, or built on a stale read
of the pinned tree.

## Cleanup record

**No cleanup was required.** All ten findings returned CONFIRMED; there were no UNSUPPORTED and no
REMIT-DEFECT verdicts, so no finding was removed, no `related_findings` list was edited, no remit rule
was re-statused, and no RAISE category score was re-derived. Per `THINKING_MODES.md` high-mode Phase 3,
the Phase-1 artifacts are the final deliverable **unchanged** — there is no `-raw` artifact pair,
because nothing was superseded.

Final artifact set (high mode, Praxen 2.0.0-beta.1):

| Artifact | Path |
|---|---|
| Analysis report (HTML) | `reports/socxen-analysis-2026-09-07-045703.html` |
| Findings (canonical JSON) | `reports/socxen-findings-2026-09-07.json` |
| Summary (TXT) | `reports/socxen-analysis-2026-09-07-045703.txt` |
| Adjudication record (this file) | `reports/socxen-adjudication-2026-09-07-045703.md` |
| Draft manifest (Step 9.9 checkpoint) | `reports/socxen-draft-2026-09-07-045703.md` |
| Evidence checkpoint (Step 4) | `reports/socxen-evidence-2026-09-07-045703.txt` |
| Scan provenance | `reports/socxen-scan-provenance-2026-09-07-045552.txt` |

Provenance: subject workspace
`/Users/steve.wilson/Documents/github/deckard/local/socxen-stress-2026-09-07T0318/src`, a read-only
pinned clone at SHA `16dea2951c235344e56c98ae09d3e28eeb0b95cd`; Worker Remit v1.5 (2026-09-05); scan
scope per `SCAN_INSTRUCTIONS.md`. Scan date 2026-09-07, `$TIMESTAMP` 2026-09-07-045703.

**Orchestrator spot-check.** High-mode Phase 3 requires the orchestrator to open the cited
contradicting evidence behind every UNSUPPORTED verdict before acting on it. There were none, so no
spot-check was owed and none was performed.

**For the remit owner, not the risk list.** The `## Remit feedback` section above is the remit owner's
fix list — one entry, **R-41**, whose extracted `rule_text` drops the remit's own following exemption
sentence and so reads as prohibiting a disposition write the target documents as the approved gated
action. It changes nothing in this report: `PRAX-2026-09-07-003` stands independently on
`alertDescription`, `alertName`, `supportingReason` and `tags`. All other cited rules (R-05, R-21,
R-24, R-46, R-48, R-51, R-57, R-67) audited sound; R-21 is a heading-as-rule over an allowlist, which
is the documented closure-extraction convention rather than a defect. Separately recorded, not a remit
defect: `PRAX-2026-09-07-007` is mapped to R-05 (a detection-rule-tuning clause) where R-01 or R-54
fits its reproduced failure better — a mapping imprecision left CONFIRMED under the conservative
reading.
