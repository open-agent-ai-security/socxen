# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
"""Deterministic tests for the input canonicalizer core (connector/canonicalize.py).

Structured as the §11 test buckets from security/design/input-canonicalizer.md. No model, CI-safe.
Test data uses \\uXXXX escapes so this source file contains no literal smuggling characters.

Run:  uv run --with pytest pytest -q tests/test_canonicalize.py
"""
import importlib.util
import json
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("canonicalize", ROOT / "connector" / "canonicalize.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

TAG_A = "\U000E0041"        # tag-block 'A'
ZWSP = "​"
ZWJ = "‍"
ZWNJ = "‌"
BOM = "﻿"
RLO = "‮"              # bidi override
FSI = "⁨"              # bidi isolate
VS_SUP = "\U000E0101"       # variation selector supplement (byte channel)
INV_TIMES = "⁢"       # sneaky-bits '0'
INV_PLUS = "⁤"        # sneaky-bits '1'
FE0F = "️"            # emoji presentation selector (legit)


# ---- 1. Positive: each smuggling channel must be stripped / flagged ----

@pytest.mark.parametrize("payload,needle", [
    (f"SOC{TAG_A}note", TAG_A),
    (f"dis{ZWSP}miss", ZWSP),
    (f"{RLO}txet", RLO),
    (f"a{FSI}b", FSI),
    (f"x{VS_SUP}y", VS_SUP),
    (f"a{INV_TIMES}b{INV_PLUS}c", INV_TIMES),
    (f"lead{BOM}ing", BOM),
])
def test_smuggling_chars_are_stripped(payload, needle):
    clean, hy = C.canonicalize(payload)
    assert needle not in clean, f"{needle!r} survived into clean text"
    assert any(needle == chr(int(r["cp"][2:], 16)) for r in hy.removed), "strip not recorded"


def test_homoglyph_is_flagged_not_stripped():
    # Cyrillic 'а' (U+0430) in an otherwise-Latin domain
    clean, hy = C.canonicalize("login at аpple.com now")
    assert "аpple.com" in clean, "homoglyph must be preserved (it may be the IOC), not stripped"
    assert any(f["class"] == "mixed-script" and f["severity"] == "high" for f in hy.flagged)


# ---- 2. The clean-corpus invariant (§2 made executable): the anti-PR-#31 guardrail ----

CLEAN = [
    "user@CORP.EXAMPLE",                       # UPN
    "svc-backup/web01.corp.local@CORP.EXAMPLE",# SPN
    "alice.mensah@example.com",                # email
    "https://portal.example.com/a/b?q=1&x=2",  # URL
    "sub.domain.co.uk", "host-01.corp.local",  # hostnames
    "C:\\Windows\\System32\\cmd.exe", "/usr/bin/python3", "config.json",  # paths/files
    "10.0.0.4", "2001:db8::1", "192.168.1.0/24",  # IPs/CIDR
    "d41d8cd98f00b204e9800998ecf8427e",        # MD5 hash (must NOT be flagged)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
    "-5", "+1.5", "-1,200", "3.2e4",           # signed numbers
    "@finance_team", "=comparison used", "-verbose", "@LEEF:1.0|Vendor|Prod",  # leading-symbol non-formulas
    "کاربر‌نام",                          # Persian with a legitimate ZWNJ
    "family \U0001F468‍\U0001F469‍\U0001F467 emoji",  # ZWJ emoji sequence
    f"rainbow \U0001F3F3{FE0F} flag",          # emoji + FE0F variation selector
    "couple \U0001F469‍❤️‍\U0001F48B‍\U0001F468 emoji",  # 3×ZWJ+2×FE0F must NOT flag (self-sweep regression)
    "price 5 USD",                        # legit NBSP
    "Ω ω café naïve Москва",                    # multilingual (single-script tokens)
]


@pytest.mark.parametrize("v", CLEAN)
def test_clean_corpus_invariant(v):
    clean, hy = C.canonicalize(v)
    assert clean == unicodedata.normalize("NFC", v), f"clean value was mutated: {v!r} -> {clean!r}"
    assert hy.is_empty(), f"clean value produced hygiene noise: removed={hy.removed} flagged={hy.flagged}"


# ---- 3. Accounting oracle (Codex R2): count STRIP_SET code points in the ORIGINAL input ----

@pytest.mark.parametrize("v", [
    f"a{ZWSP}b{TAG_A}c{RLO}d", f"{BOM}{BOM}plain", "nothing here", f"{VS_SUP}{VS_SUP}{VS_SUP}x",
])
def test_accounting_oracle(v):
    _, hy = C.canonicalize(v)
    expected = sum(1 for ch in v if ord(ch) in C.STRIP_SET)
    assert len(hy.removed) == expected
    for r in hy.removed:                       # every entry maps to its original index
        assert ord(v[r["offset"]]) in C.STRIP_SET


# ---- 4. Annotation safety (Codex bucket 1): no literal strip-set invisible anywhere in output ----

def test_no_literal_invisible_in_output_or_record():
    payload = f"user{ZWSP}@аpple.com{TAG_A}"
    clean, hy = C.canonicalize(payload)
    blob = clean + json.dumps(hy.__dict__, ensure_ascii=True)
    for cp in C.STRIP_SET:
        assert chr(cp) not in blob, f"literal U+{cp:04X} leaked into output/record"


# ---- 5. Pivot reconstruction (Codex bucket 2): dirty value rebuildable from escapedRaw ----

def test_pivot_reconstruction_roundtrip():
    dirty = f"alice{ZWSP}@example.com"
    _, hy = C.canonicalize(f"user {dirty} logged in")
    assert hy.escapedRaw, "no escapedRaw for a dirty value"
    esc = next(iter(hy.escapedRaw.values()))
    assert "\\u200b" in esc                     # invisible shown escaped, not literal
    assert esc.encode().decode("unicode_escape") == dirty  # un-escape rebuilds the exact dirty token


# ---- 6. Order-independence over the strip set (justifies strip-before-NFC, §6) ----

@pytest.mark.parametrize("v", [f"a{ZWSP}Å{TAG_A}", "café", f"{RLO}ＡＢ"])  # incl. decomposables
def test_strip_nfc_order_independence(v):
    strip = lambda s: "".join(c for c in s if ord(c) not in C.STRIP_SET)
    nfc = lambda s: unicodedata.normalize("NFC", s)
    assert strip(nfc(v)) == nfc(strip(v))


# ---- 7. Structural: idempotence, NFC-not-NFKC ----

@pytest.mark.parametrize("v", CLEAN + [f"a{ZWSP}{TAG_A}аpple.com{RLO}"])
def test_idempotent(v):
    once, _ = C.canonicalize(v)
    twice, hy2 = C.canonicalize(once)
    # Idempotence is a property of the TEXT: strip+NFC reach a fixpoint, and nothing is left to strip on
    # a second pass. Flags are a pure function of the (stable) text, so a *preserved* construct — e.g. a
    # homoglyph we deliberately keep — correctly re-flags every pass; that is not a violation.
    assert twice == once, "second pass changed the text (strip/NFC not idempotent)"
    assert hy2.counts["stripped"] == 0, "second pass still found strippable code points"
    thrice, hy3 = C.canonicalize(twice)
    assert thrice == twice and hy3.flagged == hy2.flagged, "flagging is not stable across passes"


def test_nfc_not_nfkc():
    # full-width 'A' (U+FF21): NFC leaves it; NFKC would fold to ASCII 'A' (a value mutation)
    clean, hy = C.canonicalize("ＡＢＣ")
    assert clean == "ＡＢＣ", "must not NFKC-fold full-width (would mutate the value)"
    assert clean != "ABC"


# ---- 8. Metadata bounds & inertness (Codex R2) ----

def test_many_invisibles_linear_and_offsets_correct():
    import time
    payload = ("a" + ZWSP) * 20000              # 20k stripped chars — would be O(n²) with slice-encode
    t = time.time(); clean, hy = C.canonicalize(payload); dt = time.time() - t
    assert dt < 1.0, f"stripping is not linear: {dt:.2f}s for 20k invisibles"
    assert clean == "a" * 20000 and len(hy.removed) == 20000
    boffs = [r["byteOffset"] for r in hy.removed]
    assert boffs == sorted(boffs) and boffs[0] == 1  # ZWSP after one ASCII byte


def test_metadata_fields_are_bounded():
    long_tok = "а" + "a" * 500 + "pple.com"   # long mixed-script token
    _, hy = C.canonicalize(long_tok)
    for f in hy.flagged:
        assert len(f["token"]) <= C._FIELD_CAP + 1  # + ellipsis
    # accounting entries are never dropped by field truncation
    dirty = ("x" * 500) + ZWSP
    _, hy2 = C.canonicalize(dirty)
    assert len(hy2.removed) == 1
    assert all(len(v) <= C._FIELD_CAP + 1 for v in hy2.escapedRaw.values())
