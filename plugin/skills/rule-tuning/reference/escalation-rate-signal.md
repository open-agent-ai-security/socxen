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

Unlike `closedReason`, this is **aggregate and fully searchable** — an alert either is linked to a
case or it isn't (in New-Scale the alert carries the case linkage; where a `caseId`-style field is
exposed on the alert, a single grouped alert search yields the rate for *every* rule in one pass). So
you can compute it across the whole rule inventory up front, with no per-case fetch.

## Where it sits in the noise model

It is a **coarse precision proxy**, weaker than a disposition sample but far cheaper and complete:

- **High volume + near-zero escalation = the strongest cheap noise signal.** A rule that fires
  constantly and almost never produces a case an analyst opened is spending attention and returning
  nothing. This is the fast analog of "sampled mostly-FP" — available for *all* rules, not just the
  ones you had budget to sample.
- **High escalation = loud-but-precise, leave it.** If a rule's alerts frequently become cases, it is
  earning its volume; do not tune it on volume alone (the skill's core guardrail).

## How to use it — a two-stage precision estimate

1. **First pass (cheap, complete):** rank the whole inventory by `volume × (1 − escalation_rate)`.
   One grouped alert search gives volume and escalation rate per rule. This produces the *candidate*
   noisy list without a single `get_case_details` call.
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
- Same first principle as the rest of the skill: **precision before proposals.** Escalation rate
  promotes a rule to *candidate*; it never by itself justifies a tuning change.

---

*Provenance:* this signal is the New-Scale-native reframing of the legacy Advanced Analytics tuning
metric `NotableReductionOnDeletion` (which ranked rules by how many *notables* their removal would
retire). NSA has no notables; alerts→cases is the analog, and escalation-to-case rate is its
searchable, aggregate form.
