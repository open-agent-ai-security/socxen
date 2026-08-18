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
@pytest.mark.parametrize("secret,kind", [
    ("AKIAIOSFODNN7EXAMPLE", "aws-key"),
    ("ASIAZ2XYABCDEFGH1234", "aws-key"),
    ("ghp_0123456789abcdefABCDEF0123456789abcd", "token"),
    ("xoxb-123456789012-abcdefGHIJKL", "token"),
    ("sk_live_0123456789abcdefABCDEF", "token"),
    ("AIzaabcdefghijklmnopqrstuvwxyz012345678", "token"),
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
