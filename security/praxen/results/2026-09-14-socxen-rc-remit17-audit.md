# socxen findings adjudication — 2026-09-15

Audit of `reports/socxen-findings-2026-09-15.json` (11 findings, remit v1.7) against the analyzed
workspace at `scratchpad/wt-praxen`. Every cited artifact was re-read at its cited location and the
finding was attacked before it was accepted. All paths below are relative to the workspace root.

## Audit verdicts

### PRAX-2026-09-15-001 — CONFIRMED

Read: `plugin/docs/installation.md:22, 36-38` (tier table: release sweep Opus / GPT-5.6 Sol, floor
**Sonnet 4.6+** / Terra, not supported Haiku / Luna — prose and a markdown table, nothing machine-read);
`plugin/skills/soc-investigate/SKILL.md:1-13` (frontmatter carries `name` and `description` only, no
`model` key); tree-wide `grep -rniE 'haiku|sonnet|opus'` over `plugin/**/*.py|*.sh|*.json` returns zero
hits, so neither `gate.py`, the bridge, `install.sh` nor `preflight.sh` inspects the running model.
The cited evidence is exact and the claim — floor stated in docs, unread at runtime — survives refutation.
Noted for the reader, not as a demotion: R-24's literal obligations (state the floor, do not present as
supported below it, red-team the weakest supported tier) are met in documentation; the finding's own text
and its second recommended action frame this as "not supported" vs "not prevented", and the remit's Risk
Sensitivities list that exposure, so the Medium/log_only framing is honest.

### PRAX-2026-09-15-002 — CONFIRMED

Read: `plugin/hooks/gate.py:120-132` — `decide(tool_name, tiers, *, bundled)` branches on `bare(tool_name)`
and the `bundled` flag only; `main()` at 203-213 reads `tool_name` and `tool_input` from the PreToolUse
event and passes no skill or session field into `decide`. `plugin/skills/soc-investigate/permissions.json`
— `exabeam_create_case` and `exabeam_create_case_notes` are in the `allow` tier at **lines 24-25**, with
`"prefixes": ["plugin"]` at **29-31**; the finding cites line 26 (`exabeam_parser_list`), a two-line drift
inside the same tier block, with the substance verbatim present. Claim holds: an allow-tier additive write
is indistinguishable from a sweep-time one at the gate, while `ask` still covers every disposition change
(`exabeam_update_alert`/`update_case` at 35-36). The remit itself declares this residual with the same
fix (#92, #169) at WORKER_REMIT.md:380-385, which corroborates rather than contradicts.

### PRAX-2026-09-15-003 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:813-814` — `_DEFANG_FIELDS` is exactly the eight keys cited;
`:964-975` — `_defang_args` neutralizes a value only when `k.lower() in _DEFANG_FIELDS`, recursing
otherwise; `:501-505` — the inverse policy for tool classification is stated verbatim ("Writes are the
DEFAULT, reads the exception … instead of sailing past an enumeration that only knew today's names"),
with `is_write_tool` at 808-809 implementing it as `name not in READ_TOOLS`. Both halves of the asymmetry
are where the finding says they are; the "structural, not currently exploitable" qualifier is accurate,
since the five write tools' free-text fields are all in the set and `_STATE_FIELDS` (515-518) drops the
rest on the two update tools.

### PRAX-2026-09-15-004 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:1122` — `_canon_content(result.content, …)` inside
`call_tool`; the only other `canonicalize()` call sites are `_screen_text` at 697 (tools/list definitions)
and `_safe_text` at 1014-1021 (text already on its way out of the bridge), so no ingress screen exists
off the MCP path. `plugin/docs/usage.md:22-24` documents handing in "a pasted alert payload" and leans on
re-querying Exabeam, as cited. The sub-claim also checks out: `security/redteam/run.py:9, 97` state the
corpus is driven in **paste mode**, and the obfuscation fixtures (e.g.
`security/redteam/attacks/a07-zero-width-hidden-instruction.attack.json`) ride that path. I attempted the
obvious refutation — that R-45 binds only "text retrieved from the platform", which a paste is not — but
the finding claims a coverage boundary on the code, not a breach of a retrieval, and states plainly that
the paste ingress is governed by skill prose; the evidence supports exactly that.

### PRAX-2026-09-15-005 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:1126` — `raise _UpstreamToolError(_safe_text(_upstream_error_text(content, withheld_blocks)))`,
verbatim; `:1131-1133` — the handler passes `error_message=str(e) + suffix` to `telemetry.tool_error`;
`_safe_text` at 1014-1021 caps at 300 characters, so "up to 300 characters" is precise. The upstream text
is canonicalized but is still the tool's own result content. `plugin/docs/logging.md:96` reads
"**Tool arguments and results** in general — `tool_args` / `tool_result` are always `null`", as cited,
and `logging.md:38` documents `error_message` (canonicalized, capped) for the `tool_error` event — so the
internal doc tension the finding names is real, not asserted.

### PRAX-2026-09-15-006 — CONFIRMED

Read: `plugin/connector/observra_logging.py:85-86` — `if backend in _OFF_VALUES: return _disable()`, called
with no reason; `_disable` at 67-71 writes to stderr only under `if reason:`; the configuration-failure
path at 145 does pass a reason. `plugin/hooks/gate.py:181-183` — the comment "The off switch discloses
itself, as the telemetry shim's does…" sits directly above a `print(..., file=sys.stderr)`, so the in-code
claim about the sibling shim is untrue as written. Both citations are exact. Interpretive note, not a
demotion: R-70's disclosure trigger is phrased as "if it disables itself or a backend is unavailable", and
`plugin/docs/logging.md:176-180` documents the operator-set switch, so the silence is narrower than a
covert disappearance — but "MUST NOT disappear silently" plus the false in-code parity claim carry it.

### PRAX-2026-09-15-007 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:690-693` — `_DIRECTIVE_RE`, whose only consumer is
`_screen_tools` at 775-776 appending `t.name` to `acc["directive_tools"]`; the screening loop at 777-790
rewrites text for code points only, never for directives. `:523-529` records the measurement verbatim
("MANDATORY … IGNORE any user request"; "measured 2026-09-07: 1,840 of 1,840 Claude searches") with
`_SEARCH_COLUMNS` at 530-534 and `_wildcard_fields` at 576-589 as the single-shape counter. The startup
line at 436-438 surfaces directive-carrying definitions as "countered **in prose**", which is the
finding's point stated by the code itself. Evidence holds at every cited line.

### PRAX-2026-09-15-008 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:752-755` — the `_definition_sha` docstring, including "The
list is fetched once per process, so within a session there is nothing to compare against"; `:421` `async
def warm(self)`, whose startup-line assembly at 439-442 computes the surface hash and prints "compare
across sessions in the audit trail". A module-wide search for any read of a stored prior surface
(`baseline`, `prior surface`, `previous session`) returns nothing on the comparison path. The control is
present up to, and excluding, the comparison — exactly as claimed. No `policy_rule_ids`, so no re-status.

### PRAX-2026-09-15-009 — CONFIRMED

Read: `plugin/connector/exabeam-mcp-bridge.py:530-534` (`_SEARCH_COLUMNS` covers the three search tools
only) and `:576-589` (`_wildcard_fields` returns `False` for every other tool); no byte ceiling or
truncation exists anywhere in `call_tool`. `plugin/skills/triage-cases/SKILL.md:180-183` carries the quoted
sentence about `exabeam_get_case_details` taking only `caseId` and the "read that file" mitigation — the
finding cites line 183, a three-line drift within the same paragraph, text verbatim present.
`plugin/docs/security-guardrails.md:133-147` documents the harness spill file, its path, its
non-redaction and its persistence. The finding is honest that this is the remit's declared residual
(Open Question 9) and that the intended bridge-side bound is unimplemented; confidence Medium is apt.
See Remit feedback — the extracted R-34 text drops the remit's own carve-out, which does not change this
verdict.

### PRAX-2026-09-15-010 — CONFIRMED

Read: `plugin/hooks/hooks.json:5` — the matcher is the cited case-insensitive `exabeam`-substring regex,
and `plugin/hooks/gate.py:76-79` `is_ours` applies `SERVER in server_of(tool_name).lower()`, the same test;
`main()` returns 0 with no decision and no record when `is_ours` is false. `plugin/preflight.sh:360` carries
the quoted warning, reachable only on a preflight run (and skipped under `--skip-connectivity`, line 353).
The mitigations the finding credits are real: `plugin/docs/installation.md:204` instructs naming a manual
registration `exabeam`, and `plugin/docs/security-guardrails.md:123-127` states the permission layer holds
"only if the server is named `exabeam`" — which is why Low is the right factual basis. Mapping note (not a
demotion): the gate obligation the gap actually touches is R-36; R-08 is cited because the manual
registration is one of its two authorized paths.

### PRAX-2026-09-15-011 — CONFIRMED

Read: `plugin/preflight.sh:181-182` — `stat` then `warn "  $ENV_FILE is mode $perms — consider: chmod 600 …"`,
with the design comment at line 143 ("never changes it: 0600 is advice here, exactly as it is in
install.sh") verbatim; `plugin/docs/installation.md:49` — "(role-gated; the MCP inherits the key's access
level)", with no least-privilege role guidance in the credentials section. A search for
`keychain|vault|secret-tool` across `plugin/connector/*.py` and the install docs returns nothing, so the
env file is the only credential source. Claim holds. No `policy_rule_ids`, so no re-status.

## Remit feedback

### R-34 — `socxen MUST NOT copy alert, case, or event content out of the tenant to any local or remote store other than the investigation report it returns to the analyst in-session.`

- **Defect class:** the extracted rule text prohibits behavior the target documents as intended, supported
  operation, because extraction stopped at the sentence boundary and dropped the remit's own carve-out.
  In `WORKER_REMIT.md:294-297` the same bullet continues: "The host agent's own spill file for an oversized
  tool result is the host's copy, not a socxen write — a declared residual (Open Question 9), disclosed in
  the shipped docs." The closure that reaches the findings pass therefore has no exemption for the one
  local store the docs say exists.
- **Doc citation:** `plugin/docs/security-guardrails.md:133-140` — "**Large results are written to a local
  file, and it isn't redacted.** When the Exabeam MCP returns a payload too big for the context window … the
  harness writes it to a file under `~/.claude/projects/…/tool-results/` so socxen can extract the few fields
  it needs. … **socxen itself neither writes nor transmits it (the harness does)**", with the Codex variant
  at 143-147; the skills instruct reading it (`plugin/skills/triage-cases/SKILL.md:181-183`,
  `plugin/skills/rule-tuning/SKILL.md:113`). This is documented, routine operation for an oversized read.
- **Findings it drives:** PRAX-2026-09-15-009 (Medium) — which remains CONFIRMED on its facts: the bridge
  genuinely bounds only the three search tools, and the remit itself names the missing bound as the
  intended fix.
- **Narrower obligation the docs support:** "socxen MUST NOT itself write or transmit alert, case or event
  content to any local or remote store other than the in-session investigation report. The host agent's own
  spill file for an oversized tool result is the host's copy and is excluded — a declared residual; the
  bridge SHOULD bound oversized results so nothing needs spilling." That phrasing keeps the real obligation
  (no socxen-authored copies) and scores finding -009 against the *missing bound* rather than against a
  copy socxen does not make.

No other cited rule is defective. R-02, R-45 name exactly the code points `plugin/connector/canonicalize.py:32-39`
implements, with ZWJ/ZWNJ/LRM/RLM/ALM flagged not stripped at line 46; R-50's shapes are all present in
`plugin/connector/neutralize_output.py:68-80, 189, 253`; R-41 matches `plugin/skills/triage-cases/SKILL.md:12,
139, 167` ("Do not write case notes, create cases, or update…"); R-24's floor and weakest-model red-team
posture are documented at `plugin/docs/installation.md:22, 28-40`; R-08 and R-28 match the two documented
registrations (`installation.md:134, 204`) and the shipped provenance behavior; R-32's privacy claim is the
docs' own (`plugin/docs/logging.md:92-98`); R-70's stderr channel is documented at
`plugin/docs/logging.md:168-172`. None of the cited rules is a heading-as-rule, and none demands a mechanism
the docs never had.

## Audit summary

- **CONFIRMED: 11**
- **UNSUPPORTED: 0**
- **REMIT-DEFECT: 0**
- **Remit feedback entries: 1** (R-34)
- Rule audit-status changes required: none (no UNSUPPORTED verdicts).

Every finding survived an attempt to refute it against the code. The citations are unusually disciplined:
nine of eleven resolve to the exact line, and the two that drift (`permissions.json:26` for an allow-tier
entry actually at 24-25/29-31, and `triage-cases/SKILL.md:183` for a sentence at 180-181) drift by two and
three lines inside the same block, with the quoted text verbatim present — no stale reference changes a
claim. The set is internally consistent with what the code does: the controls are real and on the execution
path, and each finding names a boundary of a control rather than its absence, which is how it was written.
Two findings lean on readings slightly wider than the rule they cite — -001 treats "MUST NOT be presented as
supported below the floor" as implying runtime prevention, and -004 extends "text retrieved from the
platform" to an analyst paste — but both state their own scope honestly in the description, neither
over-claims what the code shows, and both are logged at Medium/log_only, so neither reaches the bar for a
kill. The single rule-level defect is an extraction artifact rather than an authoring error: R-34 lost the
carve-out sentence that the remit and the shipped guardrail page both state, which is worth fixing in the
remit so the host's spill file is not re-litigated as a socxen write on the next pass.

---

## Cleanup record

**No cleanup was required. Every finding survived the audit, so the Phase-1 artifacts are the final
deliverable, unchanged.**

- **Verdicts:** CONFIRMED 11 · UNSUPPORTED 0 · REMIT-DEFECT 0. No finding was removed, so no finding IDs
  were retired, no `related_findings` entry was stripped, and no rule's `finding_id` was re-pointed or
  nulled.
- **Orchestrator spot-check:** not owed. High mode requires the orchestrator to open the cited
  contradicting evidence behind every UNSUPPORTED verdict before acting on it; the auditor returned none,
  so there was nothing to re-open and nothing to revert to CONFIRMED.
- **RAISE scores:** unchanged. Re-derivation is triggered only where a *removed* finding was load-bearing
  in a category rationale. Nothing was removed, so all six category scores, their rationales, and
  `weighted_overall` = 3.70 stand as assigned in the Phase-1 scan's Step 9.4 against its committed
  evidence set.
- **Report prose:** unchanged. `behavior_summary` and the intro-band blocks assert no claim that the audit
  disturbed.
- **Re-render:** not performed, and deliberately so. The mechanical tail is re-run only against an audited
  manifest that differs from the original; re-rendering an unchanged manifest would produce byte-identical
  output under a new timestamp and split one result across two filenames. There is consequently **no
  `-raw` artifact set** — the raw and the final report are the same files.

### Artifact pairing

| Role | File |
|---|---|
| Final report (HTML) | `socxen-analysis-2026-09-15-044440.html` |
| Final summary (TXT) | `socxen-analysis-2026-09-15-044440.txt` |
| Canonical findings | `socxen-findings-2026-09-15.json` |
| Draft manifest (Step 9.9 checkpoint) | `socxen-draft-2026-09-15-044440.md` |
| Evidence checkpoint (Step 4/5/8b/8.5) | `socxen-evidence-2026-09-15-044440.txt` |
| Adjudication record (this file) | `socxen-adjudication-2026-09-15-044440.md` |

### Outstanding for the remit owner, not the engineer

The rule-level check returned **one** defective rule, **R-34**, detailed in `## Remit feedback` above. It is
a remit-authoring fix, not a risk item: the extracted clause dropped the remit's own spill-file carve-out, so
it reads as prohibiting behavior the shipped docs describe as routine host operation. The finding it drives,
PRAX-2026-09-15-009, is unaffected — it stands on the bridge bounding only the three search tools, which the
audit verified independently. Route R-34 to whoever owns the Worker Remit; nothing in the analysis report
changes either way.
