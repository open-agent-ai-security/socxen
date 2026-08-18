<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Security guardrails

**Why this exists:** your log data is not trusted input. Anyone who can get an event into your telemetry
— a phishing sender, a malware sample, a probing attacker — can *plant something in it on purpose*,
knowing an analyst (or an AI agent) will later read it. Think of these as **booby traps left in the log
data**: a hidden instruction smuggled in invisible characters, or a payload that only does damage when a
report is opened or exported. socxen assumes that hostile content is present and screens for it, purely as
a **safety measure** — so a bomb someone planted in an alert can't go off in your hands.

To do that, socxen runs two automatic checks on every Exabeam call. They're always on and need no
configuration.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="diagram/guardrails-dark.png">
    <img alt="socxen guardrail bridge: Claude Code talks to a local bridge MCP that proxies to the remote Exabeam MCP. On writes, neutralize_output defangs formulas and links and redacts secrets/structured identifiers in free-text fields (fail-closed); on reads, canonicalize strips invisible smuggling before the agent reasons (fail-open); observra records a metadata-only audit trail of every call." src="diagram/guardrails-light.png" width="900">
  </picture>
</p>

<p align="center"><sub>The bridge hooks input and output on the path to the real Exabeam MCP — source &amp; regeneration in <a href="diagram/README.md"><code>diagram/</code></a>.</sub></p>

This is a safety net, not a replacement for judgment. Your **[governance permission gate](installation.md#governance--turn-on-the-safety-gate-do-not-skip-this)**
and your own review before you act remain the primary controls.

## 1. Screening what socxen reads (hidden-character smuggling)

Text can carry **invisible characters** — zero-width spaces, direction-reversing marks, and other hidden
control codes. Attackers use them to *smuggle* instructions past a reader: a line that looks harmless on
screen can hide extra text, or read one way to a human and another way to software.

Before socxen reasons over any alert or case, it strips out the obvious smuggling characters and cleans
up hidden line breaks. What the agent analyzes is the plain, visible text — not a version with hidden
payloads spliced in. Legitimate text (names in any language, file paths, emoji) is left untouched.

## 2. Filtering what socxen writes (de-activating dangerous content)

When socxen writes its findings back to Exabeam — a case note, an alert update — it makes sure it never
*re-arms* a payload that was sitting in the original alert. Two kinds of content are neutralized:

- **Spreadsheet formulas.** A value like `=HYPERLINK(...)` looks like data, but if a report is exported
  to a spreadsheet it can *run* when the file is opened. socxen prefixes these so they're treated as
  plain text and never execute.
- **Clickable links.** Any link written into a note is **escaped** so it can't be clicked or auto-opened
  — you'll see it rendered as `hxxps://example[.]com` instead of a live link.
- **Secrets and personal identifiers.** If a credential (an API key, token, private key, or a labelled
  password) or a structured identifier (a Social Security number, a payment-card number) is sitting in
  the alert data, socxen **masks it before writing** — you'll see `[REDACTED:aws-key]` or `[REDACTED:ssn]`
  in the note instead of the value. The finding is still recorded ("a credential was exposed here"); the
  secret itself doesn't get copied into a case note or export where a wider audience — or an attacker who
  can read case notes — could retrieve it. This is deterministic: it doesn't depend on the model
  remembering to redact.

### Why your links look "broken" — this is intentional

If you see a URL in a socxen note written as `hxxps://sso-reset[.]evil[.]example` rather than a normal
clickable link, **that is the safety measure working, not a bug.** socxen defangs the links it writes so
that a phishing or malware URL buried in an alert can't be clicked by accident — or fire automatically
when someone opens or exports the report later. The address is still fully readable; you can copy it into
a sandbox or threat-intel tool if you need to investigate it. It just can't hurt anyone with a stray
click.

This applies to **every** link socxen writes, including harmless internal ones. socxen can't reliably
tell a legitimate link from a disguised malicious one, so it treats them all the same way — the tiny
inconvenience of copy-pasting a good link is worth never handing an analyst a live malicious one.

## What these guardrails do *not* do

Keep expectations honest:

- They protect the **records socxen writes** and the **text socxen analyzes**. They do not sanitize
  content you open directly in the Exabeam console or elsewhere — treat raw alert data with normal care.
  In particular, the redaction above protects what socxen **persists** (case notes, exports) — the
  durable, wider-audience copy. A secret shown on **your own screen** during an investigation is *not*
  redacted, and that's deliberate: you're already authorised to read the underlying log, so it crosses
  no trust boundary the console itself doesn't.
- Redaction covers **structured** secrets and identifiers (keys, tokens, SSNs, card numbers) — the shapes
  a deterministic pass can catch without mangling legitimate reports. It does **not** chase free-form
  personal data such as **names or home addresses**, or **dates of birth** (a date is indistinguishable
  from the timestamps in every log line). Handle those with the same care you'd give any sensitive case.
- A suspicious link typed as ordinary prose in an alert may be left as written; the link-escaping applies
  to links socxen itself writes into notes. Always verify a URL out-of-band before you trust it.
- They reduce the blast radius of hostile content. They do **not** replace the permission gate, your SOC
  procedures, or your judgment on the verdict itself.
