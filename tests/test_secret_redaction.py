# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic secret / structured-PII redaction (#88 / assessment F-04).

Prompt-only redaction was measured leaking 100% (red-team d01/d03). neutralize_output now redacts
credentials + structured identifiers on the WRITE path. Two things must hold, and the second matters
as much as the first: real secrets get masked, AND legitimate report content does NOT (false positives
mangle analyst writeups — the whole risk of a redactor). No creds, no network; CI-safe.
"""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("neut", ROOT / "plugin" / "connector" / "neutralize_output.py")
neut = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(neut)
redact = neut.redact_secrets
neutralize = neut.neutralize_output


# --- the exact strings the live gate (2026-08-18T1711) reproduced verbatim; each MUST now be masked ---
LEAKED = [
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Wq7$vault-prod-2026-BUILD",
    "456-78-9012",
]

@pytest.mark.parametrize("secret", LEAKED)
def test_gate_leaked_secrets_are_now_redacted(secret):
    ctx = f"process command line: aws s3 sync s3://x . --secret-key {secret} password= {secret}"
    # embed in the plausible field form so labeled/prefixed anchors fire as they would in a real note
    seeded = {
        "AKIAIOSFODNN7EXAMPLE": "aws --access-key AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "--secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Wq7$vault-prod-2026-BUILD": "password= Wq7$vault-prod-2026-BUILD",
        "456-78-9012": "SSN 456-78-9012",
    }[secret]
    out = redact(seeded)
    assert secret not in out, f"{secret!r} survived redaction: {out!r}"
    # and it must survive the FULL pipeline too (this is what output-pipeline grading routes through)
    assert secret not in neutralize(seeded)[0]


# --- structured credential coverage ---
# Secret literals are ASSEMBLED at runtime (prefix + body), never written whole, so GitHub secret
# scanning doesn't fire on this file — a secrets test that trips the secrets scanner is its own bug.
# AWS's documented example keys (AKIA…EXAMPLE) are scanner-allowlisted, so they may stay literal.
def _s(*parts):
    return "".join(parts)

@pytest.mark.parametrize("secret,kind", [
    ("AKIAIOSFODNN7EXAMPLE", "aws-key"),                                  # AWS docs example (allowlisted)
    (_s("ASIA", "Z2XYABCDEFGH1234"), "aws-key"),
    (_s("ghp", "_", "0123456789abcdefABCDEF0123456789abcd"), "token"),
    (_s("xoxb", "-", "123456789012-abcdefGHIJKL"), "token"),
    (_s("sk", "_live_", "0123456789abcdefABCDEF"), "token"),
    (_s("AIza", "abcdefghijklmnopqrstuvwxyz012345678"), "token"),
])
def test_structured_credentials_redacted(secret, kind):
    out = redact(f"found {secret} in the log")
    assert secret not in out
    assert f"[REDACTED:{kind}]" in out

def test_private_key_block_redacted():
    blob = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z\n-----END RSA PRIVATE KEY-----"
    out = redact(f"key material:\n{blob}\nend")
    assert "MIIEpAIBAAKCAQEA0Z" not in out and "[REDACTED:private-key]" in out

def test_labeled_password_redacts_value_not_label():
    out = redact("password=Hunter2-prod-9x")
    assert "Hunter2-prod-9x" not in out and "password" in out.lower() and "[REDACTED:secret]" in out

def test_luhn_credit_card_redacted_but_random_digits_not():
    assert "[REDACTED:credit-card]" in redact("card 4111 1111 1111 1111 on file")   # valid Luhn
    passed = redact("order 4111 1111 1111 1112 shipped")                            # fails Luhn
    assert "[REDACTED:credit-card]" not in passed and "4111 1111 1111 1112" in passed


# --- FALSE-POSITIVE CORPUS: legitimate report content must pass through UNTOUCHED ---
FP_SAFE = [
    "host WKSTN-4471 signed in from 198.51.100.23 at 03:12 UTC",   # IP + hostname + time
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # hash
    "session 550e8400-e29b-41d4-a716-446655440000 expired",       # UUID
    "MITRE T1078, T1003; risk_score 99; case_id 4cc3c489-4c77",    # ids/tags
    "the user logged in 27 of the last 30 days from 10.4.2.9",     # baseline prose
    "rule First-seen process for user fired at 2026-08-18T03:41Z", # ISO timestamp (NOT a DOB)
    "archive ledger_exports.7z (2.3 GB) to mega.nz over 443",      # sizes/ports
    "employee count 214500 in the finance OU",                     # bare number, not a card
    # Prose CARRYING credential keywords -- what a SOC writeup is made of. The word after a line
    # break / table pipe following "token"/"credential" is usually a recommendation verb, not a
    # secret; these must survive verbatim (found in review of #115).
    "Recommended containment: rotate the API token\nDisable the service account.",
    "The exposed refresh token\nRotation is required immediately.",
    "Evidence: token | source: pastebin capture",
    "Next steps:\n- credential\n- Rotate all affected keys",
    "password rotation is scheduled for Friday",
    "the secret was rotated and the incident closed",
]

@pytest.mark.parametrize("text", FP_SAFE)
def test_legitimate_report_content_is_not_redacted(text):
    assert redact(text) == text, f"false positive: {text!r} -> {redact(text)!r}"


# --- residuals: free-form PII and dates are deliberately NOT redacted ---
def test_documented_residuals_pass_through():
    assert redact("home 4127 Larkspur Ln") == "home 4127 Larkspur Ln"   # free-form address
    assert redact("DOB 1987-03-14") == "DOB 1987-03-14"                  # date-shaped


# --- the redactor must not re-leak into the audit note ---
def test_redaction_note_never_contains_the_secret():
    notes = []
    redact("--secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", notes)
    assert notes and all("wJalrXUtnFEMI" not in str(n) for n in notes), notes


# --- formula/link neutralization still works alongside redaction ---
def test_defang_and_redaction_compose():
    out, notes = neutralize('note: [reset](https://sso-reset.evil.example) key AKIAIOSFODNN7EXAMPLE')
    assert "AKIAIOSFODNN7EXAMPLE" not in out          # redacted
    assert "hxxps" in out or "[.]" in out              # link still defanged


def test_credential_query_param_link_gets_both_controls():
    """Regression (#115 review blocker): a markdown link whose URL carries a credential-ish query
    parameter. The labeled-secret value must stop BEFORE the closing paren -- if it swallows it,
    _MD_LINK_RE no longer matches and a live phishing link persists un-defanged. An attacker reaches
    this by simply appending ?token=... to their URL, so both controls must fire together."""
    out, _ = neutralize('Suspicious link: [reset](https://sso-reset.evil.example/login?token=a1b2c3d4e5f6)')
    assert "a1b2c3d4e5f6" not in out                                  # credential redacted
    assert "https://sso-reset.evil.example" not in out                # link not left live
    assert "hxxps://sso-reset[.]evil[.]example" in out                # ...but actually defanged
    assert out.rstrip().endswith(")")                                 # link structure intact


def test_credential_query_param_in_code_span_keeps_backtick():
    out, _ = neutralize('See `https://evil.example/x?api_key=abcdef123456` for the capture')
    assert "abcdef123456" not in out
    assert out == 'See `https://evil.example/x?api_key=[REDACTED:secret]` for the capture'

# --- natural-language label forms the LIVE model actually used (2026-08-18 gate gap) ---
@pytest.mark.parametrize("text,secret", [
    ("AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("Exposed credentials:\n- password: Wq7$vault-prod-2026-BUILD", "Wq7$vault-prod-2026-BUILD"),
    ("the password was Hunter2-prod-9x in the log", "Hunter2-prod-9x"),
    ("| Password | Wq7$vault-prod-2026-BUILD |", "Wq7$vault-prod-2026-BUILD"),
    ("client secret = abcdef-ghijkl-mnopqr", "abcdef-ghijkl-mnopqr"),
])
def test_natural_label_forms_are_redacted(text, secret):
    out = neutralize(text)[0]
    assert secret not in out, f"escaped: {out!r}"


# --- AWS secret-by-proximity: caught WITH an access key present, untouched WITHOUT ---
def test_aws_secret_redacted_when_access_key_present():
    body = "creds: AKIAIOSFODNN7EXAMPLE and wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    out = redact(body)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out

def test_bare_40char_hash_untouched_without_access_key():
    # a lone 40-char blob (e.g. a SHA-1) with NO AWS access key nearby must NOT be redacted
    h = "a".join(["", "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233"])  # assembled, 40 chars, no AKIA nearby
    body = f"git commit {h} verified"
    assert redact(body) == body, f"false positive on bare hash: {redact(body)!r}"



# --- delimiter-wrapped values: the formats SKILL.md itself asks the model to use ------------------
# Review of #115 round 2: excluding wrapping delimiters from the value class blinded the redactor to
# backtick- and quote-wrapped secrets -- and SKILL.md actively instructs "wrap it in backticks so it
# stays inert" / "render them inert: a code span". The redactor must see the format we ask for, so
# delimiters are peeled at substitution time and handed back around the placeholder.

@pytest.mark.parametrize("text", [
    "Observed password: `%s`",
    'password: "%s"',
    "password: '%s'",
    "| Password | `%s` |",
    "| Password | %s |",
    "| user | host | Password | %s |",
])
def test_delimiter_wrapped_secret_is_masked(text):
    secret = _s("Wq7$", "vault-prod-", "2026-BUILD")
    out = redact(text % secret)
    assert secret not in out
    assert "[REDACTED:secret]" in out


def test_wrapping_delimiters_survive_redaction():
    """The delimiters belong to the surrounding structure, not the value -- downstream passes (the link
    defanger, the formula quoter) still need them, and a mangled code span corrupts the note."""
    assert redact("Observed password: `%s`" % _s("Wq7$", "vault-prod-2026")) == "Observed password: `[REDACTED:secret]`"
    assert redact("| Password | %s |" % _s("Wq7$", "vault-prod-2026")) == "| Password | [REDACTED:secret] |"


def test_alphabetic_passphrase_in_table_row_is_masked():
    """A table row whose cell is exactly a credential keyword is a structural label/value pair, so no
    digit-shape guard applies -- an all-alphabetic passphrase there is still a secret."""
    out = redact("| Password | correcthorsebatterystaple |")
    assert out == "| Password | [REDACTED:secret] |"


@pytest.mark.parametrize("row", [
    "| Finding | token rotation recommended |",   # keyword mid-cell, not the whole cell
    "| Status | Secret rotated by IR |",
    "| Step | rotate the API token |",
])
def test_table_rows_of_prose_are_not_redacted(row):
    """The table rule requires the keyword to BE the cell (a label), not merely appear inside it."""
    assert redact(row) == row


def test_punctuation_only_value_is_not_a_secret():
    """_trim_delims peels delimiters, then enforces the minimum on what's LEFT -- so a run of brackets
    after a label never counts as a secret."""
    assert redact("password: ((((((") == "password: (((((("


def test_alphabetic_value_after_bare_newline_is_a_documented_residual():
    """DOCUMENTED RESIDUAL (see module docstring + security-guardrails.md): after a bare line break, an
    all-alphabetic value is indistinguishable from prose ('credential\\nRotation is required'), so the
    shape guard spares it. Labeled, quoted, and table forms ARE caught. Asserted so the residual is a
    recorded decision rather than an accident."""
    text = "Recovered credential\ncorrecthorsebatterystaple"
    assert redact(text) == text


# --- ordering: link defang must run BEFORE redaction ----------------------------------------------
# Round-3 review: with redaction first, a credential-shaped query parameter let the value match consume
# the link's closing ")", so _MD_LINK_RE no longer saw a link and a LIVE clickable phishing URL
# persisted -- strictly worse than having no redactor (dev defangs these correctly). Defanging first
# makes that impossible for EVERY value shape, not just the shapes a fixture happens to cover.

@pytest.mark.parametrize("trailer", ["", ".", "!", ",", "**now**", ", then rotate", ")"])
def test_credential_link_is_defanged_whatever_follows_it(trailer):
    """The trailing character after a link is what defeated the previous fix -- a sentence-ending period
    is the single most natural way a model writes this. No trailer may leave the host live."""
    out, _ = neutralize("See [reset](https://sso-reset.evil.example/login?token=a1b2c3d4e5f6)" + trailer)
    assert "https://sso-reset.evil.example" not in out       # never a live host
    assert "hxxps://sso-reset[.]evil[.]example" in out       # actually defanged
    assert "a1b2c3d4e5f6" not in out                         # and the credential still masked


@pytest.mark.parametrize("raw,kept", [
    ("See [r](https://e.evil.example/l?token=a1b2c3d4e5f6).", ")."),
    ("See [r](https://e.evil.example/l?token=a1b2c3d4e5f6)**now**", ")**now**"),
    ("See [r](https://e.evil.example/l?token=a1b2c3d4e5f6), then rotate", "), then rotate"),
])
def test_structure_after_the_link_is_not_swallowed(raw, kept):
    """An unmatched closing bracket ends the value -- so the ")" and everything after it survive rather
    than being eaten into the redaction span."""
    assert neutralize(raw)[0].endswith(kept)


# --- the placeholder is never re-consumed ---------------------------------------------------------

@pytest.mark.parametrize("text,kind", [
    ("password: AKIAIOSFODNN7EXAMPLE", "aws-key"),
    ("credential: 123-45-6789", "ssn"),
    ("api key: %s" % _s("ghp_", "abcdefghij", "klmnopqrst", "uvwxyz0123"), "token"),
])
def test_typed_kind_survives_a_second_matching_rule(text, kind):
    """An intrinsic pattern fires first and a label rule then matches the SAME span. Without a guard the
    placeholder is re-wrapped and its type is destroyed ([[REDACTED:secret]]), losing the analyst-facing
    fact of WHAT leaked."""
    out = redact(text)
    assert out.endswith("[REDACTED:%s]" % kind), out
    assert "[[" not in out


def test_redaction_is_idempotent():
    """The bridge could apply the pipeline twice (retry, re-edit of an existing note). Re-application
    must be a no-op, not accrete brackets and spurious audit notes."""
    once = neutralize("password: hunter2xyz and key AKIAIOSFODNN7EXAMPLE")[0]
    twice, notes = neutralize(once)
    assert twice == once
    assert notes == []


def test_trailing_punctuation_in_a_value_is_not_disclosed():
    """A password may genuinely end in punctuation. Peeling it out of the redacted span would leak that
    character, so bare trailing punctuation (no structural delimiter with it) stays inside the value."""
    assert redact("password: Hunter2!") == "password: [REDACTED:secret]"
    assert redact("password: abc123.") == "password: [REDACTED:secret]"


@pytest.mark.parametrize("raw", [
    "[token: abcdef123456](https://sso-reset.evil.example/x)",
    "[password: hunter2xyz](https://sso-reset.evil.example/x)",
])
def test_credential_label_in_link_TEXT_still_defangs_the_target(raw):
    """The case that makes the ordering load-bearing rather than belt-and-braces: a credential label in
    the link's TEXT (not its target) lets the redaction match run through the "](" and swallow the whole
    link, so with redaction first the target is never defanged and a live host persists. Defanging first
    means the URL is already inert whatever redaction later consumes."""
    out, _ = neutralize(raw)
    assert "https://sso-reset.evil.example" not in out
    assert "hxxps://sso-reset[.]evil[.]example" in out


def test_delimiter_peel_is_linear_not_quadratic():
    """The peel runs on attacker-controlled telemetry; a per-character slice loop was ~1.4s on a 320k
    delimiter run. Bounded generously so the test is about complexity class, not machine speed."""
    import time
    payload = "password: " + "(" * 200_000 + ")" * 200_000
    start = time.monotonic()
    neutralize(payload)
    assert time.monotonic() - start < 1.0


def test_card_redaction_does_not_swallow_the_following_space():
    """Do no harm: the candidate match must not consume the separator after the final digit, or the
    sentence closes up around the placeholder in a legitimate report."""
    assert redact("Card number 4111 1111 1111 1111 was charged") == "Card number [REDACTED:credit-card] was charged"
    assert redact("card 4111-1111-1111-1111 seen") == "card [REDACTED:credit-card] seen"


@pytest.mark.parametrize("template", ['password: "%s"', "password: '%s'", "api_key = \"%s\""])
def test_quote_wrapped_values_are_masked(template):
    """Pinning behavior that arrived UNINTENDED: dropping quotes from the value class (a fix aimed at
    backticks and link parens) made quote-wrapped values redactable as a side effect. It is the behavior
    we want, but nothing asserted it, and per #120 the suite would not notice it regressing. NOTE the
    JSON-shaped form ({"password": "..."}) is still a MISS -- the closing quote sits between keyword and
    separator, so `[:=]` is not adjacent. Tracked in #118 with a d04 fixture."""
    secret = _s("Wq7$", "vault-prod-", "2026-BUILD")
    out = redact(template % secret)
    assert secret not in out
    assert "[REDACTED:secret]" in out


@pytest.mark.parametrize("table", [
    "| Token | Source | First seen |\n|---|---|---|\n| abc | pastebin | 03:12 |",
    "| Credential | Status |\n| :--- | ---: |\n| svc-backup | rotated |",
    "| Secret | Location |\n|---|---|",
])
def test_table_header_rows_are_not_redacted(table):
    """Do no harm: a GFM header row's cells are COLUMN NAMES, not values. A findings table with a Token
    or Credential column had its neighbouring header cell replaced. A header is always followed by a
    delimiter row (|---|---|), which is what distinguishes it from a real label/value row."""
    assert redact(table) == table


@pytest.mark.parametrize("row", [
    "| Password | correcthorsebatterystaple |",
    "| user | host | Password | Wq7$vault-2026 |",
    "| Password | `Wq7$vault-2026` |",
])
def test_table_label_value_rows_still_masked(row):
    """The header exemption must not disarm the rule it guards -- a real label/value row still masks."""
    assert "[REDACTED:secret]" in redact(row)
