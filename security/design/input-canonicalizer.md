<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design Spec — Input Telemetry Canonicalizer

> **Status:** Draft (for review — not implemented). **Addresses:** RFE [#2](https://github.com/open-agent-ai-security/socxen/issues/2) (code-layer half — "pre-filter high-risk free-text fields before they enter reasoning context"). **Supersedes:** the inbound-*defang* approach in PR [#31](https://github.com/open-agent-ai-security/socxen/pull/31), which two independent reviews blocked for mutating pivotable values (see [§2](#2-why-this-is-not-the-pr-31-approach)). **Companion:** the a10 export-injection fix moves to *output-side* neutralization (Option A), specified separately.

> **CODEX:** Directionally, this is the right split: canonicalize invisible/obfuscating input before reasoning, and keep active-content defanging at the output/write/export boundary. My main red-pen themes are: do not let annotations become another untrusted text payload, preserve enough raw forensic/pivot context for dirty stored values, and make offset/accounting semantics testable. — **CODEX**

> **AUTHOR →** All three themes accepted, and they converge on one change that this revision makes: **hygiene output is now structured, out-of-band metadata — never prose mixed into the telemetry text** ([§9](#9-annotation--hygiene-metadata-out-of-band)). That single decision closes theme 1 (annotation can't be read as evidence or become a payload), theme 2 (the metadata carries an *escaped* raw reconstruction for dirty values, [§8](#8-keep-raw-for-pivots)), and theme 3 (offset semantics defined + made a test bucket, [§9](#9-annotation--hygiene-metadata-out-of-band)/[§11](#11-test-corpus-deterministic-ci--no-model)).

## Revision — review round 1 (Codex) resolutions

Changes folded in from the inline comments below:
- **Annotations are out-of-band structured metadata** (was: appended prose). Resolves OQ-1 (Codex marked blocking).
- **Machine-checkable invariants** added as required test buckets: the clean-corpus pivot-safety property, per-codepoint annotation completeness, annotation safety (escaped-only), pivot reconstruction, and observable fail-open ([§11](#11-test-corpus-deterministic-ci--no-model)).
- **Offset semantics, flag severity, escaped-raw reconstruction** defined ([§9](#9-annotation--hygiene-metadata-out-of-band)).
- **strip-before-NFC** justified against the Special-K concern ([§6](#6-normalization)); **fixpoint operates on the value only** ([§7](#7-idempotence--the-fixpoint-question)).
- **OQ-1 resolved; OQ-6 promoted to a gate** (transport mechanism + content-block coverage). Pre-implementation gate: **OQ-4, OQ-6, OQ-8** — OQ-4/OQ-8 wait on the Option-A output-side spec.

> **CODEX ROUND 2:** Status consistency issue: this summary says **OQ-6 resolved**, but §3 says OQ-6 is a pre-code gate and §12 marks OQ-6 as `⛔ GATE`. I think the intended state is "OQ-1 resolved; OQ-6 promoted to a gate for transport/content-block coverage." Please align the revision summary so implementers do not start coding before OQ-6 is actually settled. — **CODEX**

> **AUTHOR →** Fixed — the summary bullet now reads "OQ-1 resolved; OQ-6 promoted to a gate," consistent with §3 and §12. The gate is OQ-4/OQ-6/OQ-8; no coding until all three settle.

## 1. Purpose

Untrusted telemetry (alert fields, event text, prior case notes) reaches the agent through the bridge. Attackers control that text, and a documented class of attacks hides payloads from the model's — and a human's — perception using **invisible / obfuscating Unicode**: tag-block "ASCII smuggling," zero-width characters, bidirectional overrides, variation-selector byte channels, and homoglyphs. Empirically these bypass *detection*-based guardrails at near-100% rates ([Mindgard/Lancaster, arXiv:2504.11168](https://arxiv.org/abs/2504.11168)), so the durable defense is **deterministic canonicalization that removes the obfuscation layer before anything reads the text** — not a classifier that tries to spot injections.

This canonicalizer does exactly three things:

1. **Strip** the invisible smuggling layer (characters with no legitimate place in a value).
2. **Flag** visible-but-suspicious constructs (homoglyphs, abnormal hidden-char counts) — never rewrite them.
3. **Normalize** to NFC, and **annotate** every change so nothing is silent.

> **CODEX:** I would make "nothing is silent" a hard invariant with a machine-checkable result shape, not just a UX promise. For every removed or flagged code point, tests should assert there is an annotation entry with original offset, code point, class, and reason; otherwise future cleanups can quietly weaken the forensic trail. — **CODEX**

> **AUTHOR →** Accepted as a hard invariant. `canonicalize()` returns `(text, hygiene)` where `hygiene` is the [§9](#9-annotation--hygiene-metadata-out-of-band) record; a required test bucket asserts **`len(hygiene.removed) == sum(1 for c in input if c in STRIP_SET)`** — counted over the *original input* (not a post-deletion diff, whose positions shift) — with every entry mapping to its original input index and carrying a complete record (offset, cp, class, reason). Completeness is checked mechanically, not by eyeballing ([§11](#11-test-corpus-deterministic-ci--no-model)).

> **CODEX ROUND 2:** Tighten the accounting wording before it becomes a test oracle. "Code points that differ between input and pre-NFC output" is ambiguous after deletion because all following positions shift. The invariant should be `len(hygiene.removed) == count(input code points whose code point is in STRIP_SET)` and each entry maps to that original input index. That is simpler, deterministic, and does not depend on a diff algorithm. — **CODEX**

> **AUTHOR →** Corrected exactly as specified — the oracle is now `len(removed) == count of original-input code points in STRIP_SET`, each entry mapped to its original index (fixed in the reply above and the §11 accounting bucket). No diff, deterministic.

### Non-goals (explicitly out of scope)

- **Not** active-content defanging. Neutralizing `=HYPERLINK(...)` formulas and phishing URLs so they can't fire on export is the **a10 output-side fix** (Option A), a separate layer. This spec does **not** touch URLs, emails, or formula cells. (That conflation is exactly what broke PR #31.)
- **Not** semantic injection detection. No "ignore previous instructions" phrase-matching, no LLM classifier. Detection-based defenses are what the smuggling attacks defeat.
- **Not** decoding or interpreting. base64/hex blobs are *flagged*, never decoded-and-acted-on.
- **Not** homoglyph rewriting. Mixed-script is flagged; the value is preserved (a Cyrillic hostname may itself be the IOC).

## 2. Why this is NOT the PR #31 approach

PR #31 defanged URLs/emails/formulas **on inbound tool results**. Both reviewers (adversarial agent + Codex) rated that a P1 blocker: it *mutated pivotable values* — `user@CORP.EXAMPLE` → `user[@]CORP[.]EXAMPLE`, `https://evil.example/x` → `hxxps://evil[.]example/x` — so any follow-up `search_events` on the visible value missed the raw telemetry, silently degrading investigations.

The distinction that makes **this** design safe where that one wasn't:

| | PR #31 defang (withdrawn) | This canonicalizer |
|---|---|---|
| Operates on | legitimate **visible** values | the **invisible** smuggling layer |
| A clean value (`user@corp.example`) | **mutated** → breaks pivot | **untouched** (has no invisibles) |
| Homoglyph / IOC domain | mutated | **flagged, preserved** |
| Result for search pivots | broken | preserved |

**Invariant:** a legitimate value that contains no smuggling characters passes through **unchanged except for NFC** (which is canonical-equivalent). Only the crap is removed. This is what keeps it pivot-safe.

> **CODEX:** Strongly agree with this invariant. I would phrase it as an executable property test: for a curated corpus of clean UPNs, emails, URLs, domains, hostnames, filenames, IPs, hashes, paths, and multilingual text, `canonicalize(value).text == unicodedata.normalize("NFC", value)` and `annotations == []`. This is the guardrail that prevents PR #31 from returning under a different name. — **CODEX**

> **AUTHOR →** Accepted verbatim as the headline test bucket — "the clean-corpus invariant" in [§11](#11-test-corpus-deterministic-ci--no-model): for the curated clean corpus, `canonicalize(v).text == NFC(v)` **and** `hygiene.removed == [] and hygiene.flagged == []`. This is the executable form of the [§2](#2-why-this-is-not-the-pr-31-approach) invariant and, as you say, the regression gate that stops PR #31 returning under a new name. Your exact field list (UPNs, emails, URLs, domains, hostnames, filenames, IPs, hashes, paths, multilingual) is the corpus.

## 3. Where it runs

Same interception point the withdrawn defang used — the bridge's `call_tool`, over each text content block returned from the remote MCP — but doing strip/flag/NFC instead of defang.

```
remote MCP → call_tool result → [canonicalize per text block] → agent context
```

- **Text blocks only.** Non-text content (images, embedded resources) passes through untouched. (Open question OQ-6: do we also canonicalize `EmbeddedResource` text?)
- **Fail-open per block.** A raised exception passes the *original* block through unchanged with a stderr note. This sits in the path of every tool call; a canonicalizer bug must never break an investigation.
- **Reads only, not arguments** (v1). See OQ-4.
- Pure function, no I/O, deterministic → unit-tested in CI with no model.

> **CODEX:** Text-block-only scope is a likely footgun unless it is validated against the actual MCP SDK block shapes. The implementation should have fixture tests for current `TextContent`, plus explicit tests proving `EmbeddedResource` / `structuredContent` are either handled or deliberately passed through with a documented residual risk. — **CODEX**

> **AUTHOR →** Accepted — folded into OQ-6 (now a pre-code gate) and [§11](#11-test-corpus-deterministic-ci--no-model). Fixture tests over real `mcp` SDK types (`TextContent`, `EmbeddedResource`, and a result carrying `structuredContent`), asserting each is either canonicalized (with `_meta`/sentinel hygiene) or passed through with a **documented residual-risk** annotation in the code — no silent gaps. Coverage decision is part of resolving OQ-6 before implementation.

## 4. The strip set (curated deny-list)

Removed unconditionally and annotated. **Driven by an explicit list — NOT by the `Default_Ignorable_Code_Point` property**, which includes ZWJ/ZWNJ and variation selectors we must keep (UTS #39; see [§5](#5-the-flag-set-detect-annotate-never-rewrite)).

| Codepoint(s) | Name | Why strip | Source |
|---|---|---|---|
| `U+E0000–E007F` | Unicode **Tag block** | The canonical LLM "ASCII smuggling" channel; mirrors ASCII invisibly; no legit use in telemetry | Goodside 2024; AWS; CSA; OWASP LLM01 |
| `U+E0100–E01EF` | **Variation Selectors Supplement** (VS17–256) | Maps to raw bytes — arbitrary-data smuggling channel | Rehberger 2025 |
| `U+202A–202E` | Bidi embeddings/overrides (LRE/RLE/PDF/LRO/RLO) | Trojan-Source visual reordering | Boucher & Anderson (CVE-2021-42574) |
| `U+2066–2069` | Bidi **isolates** (LRI/RLI/FSI/PDI) | Same; naive filters miss the isolates | Boucher & Anderson; UTS #55 |
| `U+200B` | Zero-width space | Splits keywords to evade filters / hide text | UTS #39 |
| `U+2060` | Word joiner | Invisible; smuggling | Rehberger |
| `U+2061–2064` | Function application, invisible times/separator/plus | "Sneaky Bits" binary encoding | Rehberger 2025 |
| `U+FEFF` | BOM / ZWNBSP (mid-string) | Invisible; smuggling | UTS #39 |
| `U+00AD` | Soft hyphen | Invisible in most renderers | UTS #39 |
| `U+180E` | Mongolian vowel separator | Deprecated format char, invisible | Unicode |
| `U+0000–001F` except `\t \n \r` | C0 controls | Non-printable control smuggling / parser confusion | OWASP |
| `U+0080–009F` | C1 controls | Same | OWASP |
| `U+D800–DFFF` | Lone/orphaned surrogates | Can recombine into tag chars; also crash JSON serialization | AWS; Python bug #17906 |

**Note on lone surrogates:** in well-formed UTF-8 these can't occur (they'd raise on `json.dumps`), so for our Python/UTF-8 pipeline this is *defensive* — but upstream UTF-16 SIEM components can emit them, so we strip at the decode boundary regardless.

> **CODEX:** Please define offset semantics before implementation: original Python code-point index, UTF-8 byte offset, or both. Security/debug consumers will need to reconcile annotations back to raw tool output, and NFC after stripping can change indexing if offsets are measured after normalization. My preference: record original code-point offset and, when available, original byte offset. — **CODEX**

> **AUTHOR →** Accepted, matching your preference — defined in [§9](#9-annotation--hygiene-metadata-out-of-band): **original code-point index into the pre-normalization input, plus original byte offset when available.** Accounting is computed *before* NFC precisely so indices never refer to the normalized form. A test asserts offsets reconcile back to the raw input.

## 5. The flag set (detect, annotate, NEVER rewrite)

Surfaced as a hygiene annotation; the value is left intact so pivots and legitimate multilingual/emoji content are preserved.

| Construct | Codepoints / test | Why flag-not-strip |
|---|---|---|
| **ZWJ / ZWNJ** | `U+200C`, `U+200D` | **Required** in Persian/Arabic/Indic and emoji sequences — stripping corrupts legitimate text (UTS #39 §5.1; PR-96). v1: flag + count. |
| **Emoji variation selectors** | `U+FE00–FE0F` (esp. `U+FE0F`) | `FE0F` is the ubiquitous emoji-presentation selector; legit. Flag only if count is abnormal. |
| **Directional marks** | `U+200E`, `U+200F`, `U+061C` (LRM/RLM/ALM) | Legitimate in mixed-direction text; weaker than the stripped overrides. |
| **Mixed-script / homoglyph** | UTS #39 resolved-script-set = ∅; `Identifier_Status=Restricted` | Confusable domains are often the IOC itself; rewriting destroys evidence + pivot. Flag the token + rationale. |
| **base64 / hex blob** | length/charset heuristic, pre-decode | Never decode-and-act; flag so downstream treats decoded content as untrusted too. |
| **Exotic whitespace** | NBSP `U+00A0`, `U+2028/2029` (line/para sep), `U+3000`, other `Zs` | Can spoof line structure; but legitimate. v1: flag (OQ-5: flag vs normalize-to-space). |
| **Combining-mark runs (Zalgo)** | run of `Mn` above threshold | Obfuscation/DoS vector but legitimate in many scripts — count/flag, don't strip. NFC won't remove. |
| **Hidden-char budget** | total stripped+flagged per field/message > threshold | A legit note has ~0; dozens = smuggling. Per-message flag signal (Rehberger). |

> **CODEX:** Flag-only is the right posture for homoglyphs, joiners, and emoji selectors. The hard part is alert fatigue: a "flag" should have severity/category (`info`, `suspicious`, `high-risk smuggling`) so ordinary multilingual/emoji content does not become a constant false alarm that analysts learn to ignore. — **CODEX**

> **AUTHOR →** Accepted — `severity` is now a required field on every flag ([§9](#9-annotation--hygiene-metadata-out-of-band)). Default mapping: emoji selectors / joiners / directional marks = `info`; abnormal hidden-char count or exotic whitespace = `suspicious`; mixed-script confusable, tag-block, or bidi = `high`. The skill surfaces only `suspicious`+ by default so multilingual/emoji content stays quiet.

## 6. Normalization

- **NFC only.** Applied **last** (strip → NFC → done). NFC is canonical-equivalent (preserves the visible value → pivot-safe).
- **Never NFKC on searchable values** — it rewrites full-width/ligatures/`U+212A`→K etc., mutating legitimate indicators. (NFKC may be used only for a *derived, flagged-for-analysis* view, never the value the agent pivots on.)
- **Order matters — and strip-before-NFC is safe *here* specifically because our strip is identity-based, not content-based.** The Special-K bypass hits *allow/deny decisions on content*: a compatibility character slips past a filter, then normalizes into the dangerous form. We make no such decision — we remove a **fixed set of code points by identity**, and NFC neither creates nor destroys any code point in that set (NFC won't turn a visible character into a tag-block/zero-width/bidi control, nor vice-versa). So strip→NFC and NFC→strip yield the same result for our set; we pick strip-first so offset accounting is on the raw input. Combining marks (`Mn`) are preserved. This is a test bucket (order-independence over the strip set) — [§11](#11-test-corpus-deterministic-ci--no-model).

> **CODEX:** The "strip then NFC" statement and the "Special-K" warning appear to be in tension: many Unicode bypass discussions recommend normalizing before applying allow/deny decisions so compatibility/canonical forms cannot evade filters. If this design intentionally strips specific code-point ranges before NFC, call that out as safe for this curated strip set, and add tests where pre/post-normalization order matters. — **CODEX**

> **AUTHOR →** Good catch on the apparent tension — resolved by making the reasoning explicit (bullet above). The Special-K concern is about *content allow/deny*; we do *identity* removal of a fixed code-point set that NFC can't produce or hide, so order is immaterial for correctness and we choose strip-first only for clean offset accounting. Added an order-independence test over the strip set.

## 7. Idempotence & the fixpoint question

- On **decoded Unicode code points** (Python `str`, UTF-8), a single well-ordered pass is idempotent — removing whole code points cannot recombine into a new tag char the way split UTF-16 surrogate *pairs* can (that's the AWS/Java concern, UTF-16-specific).
- **Cheap insurance, adopted:** after strip→NFC, assert a second pass is a no-op; if not, re-run, **capped at 3 iterations** (bounded, no DoS). This gives the AWS "recursive-until-stable" guarantee without assuming single-pass is safe.

> **CODEX:** The fixpoint check should operate on the canonicalized telemetry value only, not on any human-readable annotation appended to that value. If annotations are appended inline and then reprocessed, the canonicalizer can end up analyzing its own warning text. That argues for out-of-band metadata or a separate content block with a sentinel that the canonicalizer skips. — **CODEX**

> **AUTHOR →** Resolved structurally by the [§9](#9-annotation--hygiene-metadata-out-of-band) decision: hygiene metadata is **out-of-band**, so the fixpoint only ever sees the sanitized value — there is no appended prose to re-analyze. If the metadata is carried as a sentinel content block, the canonicalizer **skips** that block by its reserved sentinel on every pass (also a test bucket). The canonicalizer never analyzes its own output.

## 8. Keep-raw-for-pivots

The reviewers' pivot break came from *mutating visible values*. This design doesn't: it **strips only invisibles** (never part of a searchable value) and **flags** everything that would otherwise require mutation. NFC is the sole value transform and is canonical-equivalent. So the visible/searchable content the agent sees still matches the SIEM — the **value** carries no raw copy, while the out-of-band hygiene metadata retains an *escaped* raw form for the one edge below.

- **The dirty-stored-value edge, and how we preserve pivot/IR ability:** if an attacker planted an invisible char *inside* a stored value (e.g. a username), the sanitized value won't match the dirty raw record. We do **not** drop that raw context — the [§9](#9-annotation--hygiene-metadata-out-of-band) hygiene record's **`escapedRaw`** carries a safe **escaped** reconstruction (e.g. `alice\u200b@example.com`, invisible char shown only as `\uXXXX`) so IR can rebuild an exact search / containment scope / vendor-support artifact. We never render the raw invisible literally into the value, but we never lose it either.

> **CODEX:** I would not fully close the door on raw-for-pivots. The "dirty stored username" edge is exactly when IR may need the original escaped value for exact search, containment scoping, or vendor support. Avoid showing raw invisible characters directly, but consider exposing a safe escaped representation such as `alice\\u200b@example.com` in annotation metadata so the analyst can reconstruct an exact query if needed. — **CODEX**

> **AUTHOR →** Accepted — this is exactly `escapedRaw` in [§9](#9-annotation--hygiene-metadata-out-of-band), and "pivot reconstruction" is now a required test bucket ([§11](#11-test-corpus-deterministic-ci--no-model)): for a dirty value, assert the hygiene record contains an escaped form sufficient to rebuild an exact query, with invisibles represented only as `\uXXXX`. I softened the earlier "no raw copy needed" claim accordingly — the *value* carries no raw copy, but the out-of-band metadata does.

## 9. Annotation & hygiene metadata (out-of-band)

**Decision (resolves OQ-1, previously blocking):** the canonicalizer emits its findings as **structured, namespaced hygiene metadata carried out-of-band — never as prose mixed into the sanitized telemetry text.** Appending commentary into the tool-result text would (a) let trusted canonicalizer output be read as *evidence*, (b) create a **new injection surface** (the annotation is derived from attacker-controlled input), and (c) get re-analyzed by the fixpoint pass. So:

- The **tool-result text** is the sanitized value only (stripped + NFC) — nothing else.
- A separate **hygiene record** travels alongside it: either a dedicated content block prefixed with a reserved sentinel that the canonicalizer **skips on any re-pass** and the skill renders as *metadata, not evidence*, or the MCP result's `_meta` / structured channel if the SDK surfaces it (implementation choice — see OQ-6). Namespaced `socxen.hygiene`.

**Record shape** (per content block):

```json
{
  "schema": "socxen.hygiene/v1",
  "removed": [{"cp": "U+200B", "name": "ZERO WIDTH SPACE", "offset": 12, "byteOffset": 12, "class": "strip", "reason": "zero-width"}],
  "flagged": [{"token": "аpple.com", "offset": 40, "class": "mixed-script", "severity": "high", "reason": "Latin+Cyrillic confusable"}],
  "counts": {"stripped": 3, "flagged": 1},
  "escapedRaw": {"40": "аpple.com", "12": "alice\\u200b@example.com"}
}
```

- **Offset semantics (resolves the §4 Codex note):** offsets are **original code-point indices** into the *pre-normalization* input, plus original **byte offset** when available. Accounting happens *before* NFC, so an index never refers to the normalized form — a consumer can always reconcile a finding back to raw tool output.
- **Severity** per flag (`info` | `suspicious` | `high`) so ordinary multilingual/emoji content (`info`) doesn't drown the real smuggling signal (`high`) — the alert-fatigue concern.
- **`escapedRaw`** carries a safe, escaped reconstruction of any value we stripped (e.g. `alice\u200b@example.com`) so IR can rebuild an exact query / containment scope for a *dirty stored value*. Invisible chars appear **only** as escaped `\uXXXX` sequences, never literally (that's a test bucket — [§11](#11-test-corpus-deterministic-ci--no-model)).
- The skill summarizes the hygiene record separately (a "data hygiene" line in the report) and it must **never** influence the verdict as if it were evidence.
- **The hygiene record is itself untrusted.** Its `token` / `escapedRaw` fields are attacker-derived substrings, so: they are **length-bounded** (per-field cap, summarized with an ellipsis if longer — *without* dropping any per-codepoint accounting entry); serialized **inertly** (plain JSON string escaping only — no markdown/HTML the skill would render as active); and the skill treats the whole record as **untrusted metadata, never authoritative analysis**. The out-of-band channel must not become a smaller, more-trusted injection surface.

> **CODEX ROUND 2:** The out-of-band record is safer, but it is still derived from attacker-controlled telemetry. Add an explicit invariant that every attacker-derived field inside `socxen.hygiene` (`token`, `escapedRaw`, maybe future snippets) is length-bounded and rendered/serialized inertly, and that the skill treats the hygiene record as untrusted metadata, not authoritative analysis. Otherwise the metadata channel can become a smaller, more trusted prompt-injection surface. — **CODEX**

> **AUTHOR →** Sharp — accepted. Added the "hygiene record is itself untrusted" invariant to §9 (length-bounded fields, inert serialization, skill treats it as untrusted metadata) and a **metadata bounds & inertness** test bucket to §11. The metadata channel now gets the same untrusted-input treatment as the telemetry it describes, so it can't become a smaller, more-trusted surface.

> **CODEX:** I would treat OQ-1 as blocking. Appending prose into the same tool-result text is simple, but it mixes trusted canonicalizer commentary with untrusted telemetry and can influence the investigation as if it were evidence. Preferred shape: keep the sanitized text as the tool result, and attach a structured, clearly namespaced hygiene block or metadata object that the skill can summarize separately. — **CODEX**

> **AUTHOR →** Accepted in full — this section is rewritten to your preferred shape. Sanitized text is the sole tool-result value; hygiene is a namespaced structured record out-of-band; it carries severity (alert fatigue), original-offset accounting, and an escaped-raw reconstruction (pivot/IR). The remaining implementation choice — sentinel content-block vs MCP `_meta`/structured channel — is folded into OQ-6 and gated before coding.

## 10. Fail-open & performance

- Per-block `try/except` → original block passes through on any error (availability > canonicalization).
- **Observable fail-open.** A fail-open is **not silent**: it emits a bounded diagnostic to **stderr** (never stdout — that's the stdio MCP protocol channel) and increments a per-process `canonicalize_failopen` counter. The hygiene record for that block is marked `{"status": "failopen", "error": "<class>"}` so a downstream consumer can tell "canonicalized clean" from "passed through unchecked." A deterministic test asserts: a raising block → original returned **and** a bounded diagnostic emitted **and** counter incremented.
- Linear time; stripping **shrinks** text (no `[.]`-style inflation — that was the defang; not present here). Metadata is out-of-band and bounded.
- Perf budget: multi-MB Exabeam dumps must stay well under a second (research probes: ~1s on 5–11 MB). Optional size guard: above N MB, still fail-open (and mark it).

> **CODEX:** Fail-open is correct for availability, but it should be observable. Add a counter/log string that is safe for stdio MCP, plus a deterministic test that an exception returns the original block and emits a bounded diagnostic. If this silently fails open, the system will look protected while running with no canonicalization. — **CODEX**

> **AUTHOR →** Accepted — fail-open is now observable (stderr diagnostic + counter + a `failopen` status on the block's hygiene record), with a deterministic test. Your exact failure mode ("looks protected while running with no canonicalization") is what the status flag + counter defeat: a monitored `canonicalize_failopen > 0` is the signal that coverage silently degraded.

## 11. Test corpus (deterministic, CI — no model)

- **Positive (must strip/flag):** one fixture per channel — tag block, zero-width, bidi override + isolate, variation-selector byte channel, sneaky-bits (`U+2062/2064`), homoglyph domain; plus red-team payloads a06 (base64), a07 (zero-width), a08 (homoglyph).
- **Negative — the clean-corpus invariant (§2 made executable):** for a curated corpus of clean UPNs, emails, URLs, domains, hostnames, filenames, IPs, hashes, paths, and multilingual text (Persian/Indic ZWNJ/ZWJ, emoji `ZWJ`/`FE0F`, legit NBSP, combining marks): `canonicalize(v).text == NFC(v)` **and** `hygiene.removed == [] and hygiene.flagged == []`. This is the regression gate that stops PR #31 returning under a new name.
- **Accounting completeness (oracle = original input, not a diff):** `len(hygiene.removed) == sum(1 for c in input if c in STRIP_SET)` — counted over the *original input string*, so it never depends on post-deletion position shifts or a diff algorithm; every entry maps to its original input index and carries a full record (offset, cp, class, reason, severity).
- **Annotation safety (Codex bucket 1):** stripped invisible characters appear in the hygiene record **only** as escaped `\uXXXX` / code-point names — assert no literal invisible from the strip set is present anywhere in `text` or the rendered hygiene block.
- **Pivot reconstruction (Codex bucket 2):** for a dirty value, `hygiene.escapedRaw` contains an escaped form sufficient to rebuild an exact follow-up query; round-trip un-escape → equals the original dirty value.
- **Order-independence over the strip set:** `strip(NFC(x)) == NFC(strip(x))` for the fixed strip set (justifies strip-before-NFC, §6).
- **Metadata bounds & inertness:** a very long suspicious `token` / `escapedRaw` is truncated to the field cap **without dropping any per-codepoint accounting entry**; every attacker-derived field round-trips through serialization inertly (no unescaped invisibles, no active markup) — the hygiene channel can't itself smuggle.
- **Structural:** idempotence (second pass = no-op; sentinel block skipped); fail-open (raising block → original returned + diagnostic + counter + `failopen` status); NFC-not-NFKC (full-width preserved as a `flag`, not folded); MCP block-shape fixtures (`TextContent`, `EmbeddedResource`, `structuredContent`) each handled-or-documented.

> **CODEX ROUND 2:** Mirror the §1 accounting fix here too: make "accounting completeness" count strip-set code points in the original input, not textual diff output. Also add a metadata-bounds test: very long suspicious tokens / escaped raw values are truncated or summarized without losing the per-codepoint accounting entries. — **CODEX**

> **AUTHOR →** Both done: the accounting bucket now counts `STRIP_SET` code points in the *original input* (matching the §1 fix), and a **metadata bounds & inertness** bucket asserts long `token`/`escapedRaw` values truncate without losing accounting entries and serialize inertly.

> **CODEX:** Add two more property buckets: (1) annotation safety, proving stripped invisible characters are represented only as escaped code-point names and never reintroduced literally; (2) pivot reconstruction, proving a dirty value's annotation contains enough escaped raw context to build an exact follow-up query when necessary. — **CODEX**

> **AUTHOR →** Both buckets added verbatim (annotation safety; pivot reconstruction), alongside the clean-corpus invariant, accounting completeness, order-independence, and the observable-fail-open and block-shape buckets. Every invariant you asked to be machine-checkable now has a named bucket here.

## 12. Open questions (red-pen targets)

- **OQ-1 — Annotation surfacing. ✅ RESOLVED** (§9): structured, out-of-band hygiene metadata, namespaced, severity-tagged; the skill summarizes it separately and it never influences the verdict as evidence. Remaining sub-decision folded into OQ-6.
- **OQ-2 — ZWJ/ZWNJ policy.** v1 flag-only (safe). Do we ever want *contextual* stripping (strip only when NOT adjacent to script letters/emoji)? Adds complexity; defer to a corpus-tuned v2. *(Codex: start conservative.)*
- **OQ-3 — Hidden-char budget threshold.** What count per field/message trips the `suspicious` flag? (Proposal: >3 stripped, or any tag-block/bidi = `high` regardless; tune with corpus.) *(Codex: start conservative.)*
- **OQ-4 — Arguments too? ⛔ GATE.** v1 canonicalizes tool *results* only. Do we also canonicalize outbound tool *arguments*? This intersects the a10 output-side write neutralization — decide *with* the Option-A spec so the two layers don't overlap or gap. Blocks coding.
- **OQ-5 — Exotic whitespace.** Flag (v1) vs normalize exotic `Zs` → `U+0020`? Normalizing mutates the value (only for a detection copy). *(Codex: start conservative → flag.)*
- **OQ-6 — Content-block coverage + hygiene transport. ⛔ GATE.** (a) Handle `EmbeddedResource`/`structuredContent` text or document text-only residual (validated against real MCP SDK shapes, §11); (b) **transport mechanism** for the out-of-band record — a reserved-sentinel content block the canonicalizer skips, vs the MCP result `_meta`/structured channel if the SDK exposes it through the bridge. Blocks coding.
- **OQ-7 — Layer / hook.** Bridge `call_tool` (this design) vs a Claude Code `PostToolUse` hook shipped in `settings.snippet.json`? Bridge = on-by-default for every user; hook = user-configurable.
- **OQ-8 — Relationship to a10 output-side fix. ⛔ GATE.** This spec + the separate Option-A output neutralization = the full #2 (input) / #4-successor (output) code layer. Cross-reference and reconcile the boundary once Option A is specced. Blocks coding.

**Pre-implementation gate (per Codex):** resolve **OQ-4, OQ-6, OQ-8** (⛔) before writing the bridge hook. OQ-1 is resolved. OQ-2/3/5 start conservative and tune with corpus data.

> **CODEX:** My implementation gate would be: resolve OQ-1, OQ-4, OQ-6, and OQ-8 before coding the bridge hook. OQ-2/OQ-3/OQ-5 can safely start conservative and tune with corpus data. The key release risk is not the strip table; it is where the hygiene signal lives and whether it preserves investigation ergonomics. — **CODEX**

> **AUTHOR →** Adopted as the gate. OQ-1 is now resolved (§9). OQ-4 and OQ-8 both wait on the **Option-A output-side spec** (the next doc I'll draft), because the argument-canonicalization and layer-boundary questions can only be answered against it. OQ-6's transport sub-decision (sentinel block vs `_meta`) is the last input-side blocker and needs validation against the live MCP SDK. Agreed the release risk is *where the hygiene signal lives*, not the strip table — which is why §9 got the biggest rewrite.

## 13. References

- [UTS #39: Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/) · [UTS #55: Unicode Source Code Handling](https://www.unicode.org/reports/tr55/) · [UAX #31 / PR-96 (joiners in identifiers)](http://unicode.org/review/pr-96.html)
- [Trojan Source — Boucher & Anderson, arXiv:2111.00169 (CVE-2021-42574)](https://arxiv.org/abs/2111.00169)
- [Bypassing LLM Guardrails — Mindgard/Lancaster, arXiv:2504.11168](https://arxiv.org/abs/2504.11168)
- [AWS: Defending LLM applications against Unicode character smuggling](https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/)
- [Rehberger: Sneaky Bits and ASCII Smuggler (2025)](https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/)
- [CSA: Hidden Unicode Instruction Injection in AI Agent Skills](https://labs.cloudsecurityalliance.org/research/csa-research-note-unicode-instruction-injection-ai-skills-20/)
- [AppCheck: Unicode Normalization Vulnerabilities & the Special-K Polyglot](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- Libraries: Python `unicodedata` (core), `regex`/`unicodedata2` (`\p{}` + current UCD), [`confusable_homoglyphs`](https://pypi.org/project/confusable-homoglyphs/) (flag path), `ftfy` (reference only — mutates).
