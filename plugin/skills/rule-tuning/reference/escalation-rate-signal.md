<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Precision signal — escalation-to-case rate (the searchable first pass)

A supplement to the precision signals in `rule-tuning`'s noise model. The disposition sample
(`closedReason`) is the most decisive precision signal, but — as the skill notes — `closedReason`
is **read-only per case, not searchable**, so it can only be *sampled*, one `get_case_details` at a
time. That makes it expensive: you cannot afford to sample every rule, so you need a cheap signal to
decide **which** rules earn the expensive sampling.

**Escalation-to-case rate is that cheap signal.** For a detection rule, it is:

> escalation rate = (alerts from this rule that became a case) ÷ (all alerts from this rule)

Unlike `closedReason`, this is **searchable rather than per-case** — an alert either is linked to a
case or it isn't, and `caseId` is a real filter/return field on `exabeam_search_alerts`
(`soc-investigate/reference/tool-map.md`, where `caseId:null` = alerts not yet in a case). So the rate
can be computed without a single `get_case_details` call.

> **It is not a one-pass aggregate through this skill.** Server-side aggregation is *not* available
> via the MCP tool — `groupBy` and `distinct` are silently dropped (see the tested-reality note in
> `soc-investigate/reference/search-cookbook.md`, verified against a live tenant). So do not expect one
> grouped search to return the rate for every rule. Compute it per candidate rule instead, either way:
>
> - **two counted searches** — the rule's alerts with `caseId:null` (not escalated) and without it
>   (escalated); the rate is the ratio; or
> - **one search returning `caseId` in `fields`** for that rule's alerts, tallied client-side.
>
> That makes it *cheaper than disposition sampling*, not free — which is still the argument for using
> it as the first pass.

## Where it sits in the noise model

It is a **coarse precision proxy**, weaker than a disposition sample but far cheaper and complete:

- **High volume + near-zero escalation = the strongest cheap noise signal.** A rule that fires
  constantly and almost never produces a case an analyst opened is spending attention and returning
  nothing. This is the fast analog of "sampled mostly-FP" — available for *all* rules, not just the
  ones you had budget to sample.
- **High escalation = deprioritize for sampling, not proof of precision.** If a rule's alerts
  frequently become cases, it is at least earning an analyst's attention, so it is a poor use of a
  limited sampling budget — but "an analyst opened a case" is not "the alert was real." Those cases
  can still close as false-positive, so a high rate does not by itself clear a rule (see the caveats).

## How to use it — a two-stage precision estimate

1. **First pass (cheap):** rank candidate rules by `volume × (1 − escalation_rate)`, computing the
   rate per rule with the two counted searches (or client-side `caseId` tally) described above — not
   one grouped search, since the MCP tool drops aggregation. This produces the *candidate* noisy list
   without a single `get_case_details` call.
2. **Confirm (expensive, targeted):** for the top candidates only, run the existing decisive signals —
   **sample** `closedReason` disposition, compute corroboration, read the noise-prone config
   (`scopeValue: 'org'`, maturity gates off, `actOnCondition: "true"`). Escalation rate tells you
   *where* to spend the sampling budget; disposition + config tell you *whether to tune and how*.

## Caveats (do no harm — same discipline as the rest of the model)

- **Escalation is coarser than disposition.** A low escalation rate can also mean the SOC is not
  *working* the queue, not that the rule is noisy. Confirm with a disposition sample before proposing a
  change — never tune on escalation rate alone. (This is the SOC-health cross-check: an unworked
  backlog depresses escalation across *every* rule uniformly; a genuinely noisy rule stands out against
  that baseline.)
- **Escalation rate is a proxy for precision, not precision itself.** It counts "did a human open a
  case," not "was it a true positive." Corroboration and disposition still decide truth.
- **The caveat cuts both ways.** A *low* rate can mean an unworked queue rather than a noisy rule; a
  *high* rate can sit on a genuinely noisy rule whose cases mostly close as false-positive. Both
  directions are resolved the same way — by the disposition sample, not by this signal. Treat
  escalation-to-case as a **first-pass prioritizer** that decides *what is worth sampling*, and let
  `closedReason` do the confirmed-vs-dismissed split.
- Same first principle as the rest of the skill: **precision before proposals.** Escalation rate
  promotes a rule to *candidate*; it never by itself justifies a tuning change.

---

*Provenance:* this signal is the New-Scale-native reframing of the legacy Advanced Analytics tuning
metric `NotableReductionOnDeletion` (which ranked rules by how many *notables* their removal would
retire). NSA has no notables; alerts→cases is the analog, and escalation-to-case rate is its
searchable, aggregate form.
