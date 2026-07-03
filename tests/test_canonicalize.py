# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "regex>=2024.0"]
# ///
"""Deterministic tests for the input canonicalizer core (connector/canonicalize.py). No model, CI-safe.

Every invisible character in this file comes from a \\uXXXX / \\U escape or a named constant — the source
contains NO literal invisible characters (a repo that tests smuggling must not itself carry hidden ones;
visible non-ASCII like Cyrillic/accents/emoji bases are fine). Buckets follow design §11.

Run:  uv run --with pytest --with regex pytest -q tests/test_canonicalize.py
"""
import importlib.util
import json
import time
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("canonicalize", ROOT / "connector" / "canonicalize.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

# Invisible chars — all escaped. CGJ / Hangul filler / VS-supplement are the ones the old hand-list
# MISSED; pinning them proves the \p{DI}-property fix (the P1 both reviews found).
TAG_A = chr(0xE0041)          # tag-block 'A'
ZWSP = chr(0x200B)
BOM = chr(0xFEFF)
RLO = chr(0x202E)             # bidi override
FSI = chr(0x2068)             # bidi isolate
CGJ = chr(0x034F)             # combining grapheme joiner (Mn - p{Cf} misses it)
HANGUL_FILLER = chr(0x115F)   # (Lo - p{Cf} misses it)
VS_SUPP = chr(0xE0100)        # variation selector supplement (Mn)
INV_TIMES = chr(0x2062)       # sneaky-bits
ACUTE = chr(0x0301)           # combining acute accent
# Carve-outs (kept):
ZWJ = chr(0x200D)
ZWNJ = chr(0x200C)
FE0F = chr(0xFE0F)
RLM = chr(0x200F)
# Cf format controls NOT in Default_Ignorable (the gap Reviewer A found — proves \p{Cf} is needed):
ARABIC_NS = chr(0x0600)       # Arabic number sign
INTERLINEAR = chr(0xFFF9)     # interlinear annotation anchor
SYRIAC = chr(0x070F)          # Syriac abbreviation mark
BRAILLE_BLANK = chr(0x2800)   # visually blank, NOT stripped -> flagged only in ASCII context

FAMILY = chr(0x1F468) + ZWJ + chr(0x1F469) + ZWJ + chr(0x1F467)       # ZWJ emoji sequence
COUPLE = chr(0x1F469) + ZWJ + chr(0x2764) + FE0F + ZWJ + chr(0x1F468)  # ZWJ + FE0F emoji
PERSIAN = ''.join(map(chr, (0x6a9,0x627,0x631,0x628,0x631))) + ZWNJ + ''.join(map(chr,(0x646,0x627,0x645)))  # legit ZWNJ


@pytest.mark.parametrize("ch", [TAG_A, ZWSP, BOM, RLO, FSI, CGJ, HANGUL_FILLER, VS_SUPP, INV_TIMES,
                                ARABIC_NS, INTERLINEAR, SYRIAC])
def test_smuggling_chars_stripped(ch):
    clean, hy = C.canonicalize("A" + ch + "B")
    assert clean == "AB", f"{ch!r} survived into clean text"
    assert len(hy.removed) == 1 and hy.removed[0]["cp"] == f"U+{ord(ch):04X}"


@pytest.mark.parametrize("ch", [ZWJ, ZWNJ, FE0F, RLM])
def test_carveout_chars_not_stripped(ch):
    # Carve-outs are KEPT (not stripped) so legit Persian/Indic/emoji survive. In an ASCII context they
    # are separately FLAGGED as obfuscated-ascii (see below) — but never removed from the text.
    clean, _ = C.canonicalize("A" + ch + "B")
    assert ch in clean, f"carve-out {ch!r} was stripped (should be kept)"


@pytest.mark.parametrize("payload", ["ignore" + ZWJ + "previous", "drop" + FE0F + "table",
                                     "a" + BRAILLE_BLANK + "b", "A" + RLM + "B"])
def test_obfuscated_ascii_flagged(payload):
    # An ASCII word with a kept invisible/blank spliced in must NOT read as clean (Codex P1/P2).
    _, hy = C.canonicalize(payload)
    assert any(f["class"] == "obfuscated-ascii" for f in hy.flagged), f"{payload!r} not flagged"


# ---- the clean-corpus invariant (§2 executable): the anti-PR-#31 guardrail ----
CLEAN = [
    "user@CORP.EXAMPLE", "svc-backup/web01.corp.local@CORP.EXAMPLE",
    "alice.mensah@example.com", "https://portal.example.com/a/b?q=1&x=2",
    "sub.domain.co.uk", "host-01.corp.local",
    "C:\\Windows\\System32\\cmd.exe", "/usr/bin/python3", "config.json",
    "10.0.0.4", "2001:db8::1", "192.168.1.0/24",
    "d41d8cd98f00b204e9800998ecf8427e",                                   # MD5
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   # SHA-256
    "-5", "+1.5", "-1,200", "3.2e4",
    "@finance_team", "=comparison used", "-verbose", "@LEEF:1.0|Vendor|Prod",
    PERSIAN, f"family {FAMILY} emoji", f"couple {COUPLE} emoji",
    "Царь Москва",       # legit single-script Cyrillic
    "café naïve Ångström",                            # accented Latin (NFC)
]


@pytest.mark.parametrize("v", CLEAN, ids=range(len(CLEAN)))
def test_clean_corpus_invariant(v):
    clean, hy = C.canonicalize(v)
    assert clean == unicodedata.normalize("NFC", v), f"clean value mutated: {v!r} -> {clean!r}"
    assert hy.is_empty(), f"clean value produced hygiene noise: removed={hy.removed} flagged={hy.flagged}"


# ---- accounting oracle (Codex R2): count strippable code points in the ORIGINAL input ----
@pytest.mark.parametrize("v", [
    f"a{ZWSP}b{TAG_A}c{RLO}d", f"{BOM}{BOM}plain", "nothing here",
    f"{VS_SUPP}{CGJ}{HANGUL_FILLER}x",
])
def test_accounting_oracle(v):
    _, hy = C.canonicalize(v)
    assert len(hy.removed) == sum(1 for ch in v if C.is_strippable(ch))


def test_no_literal_invisible_in_output_or_record():
    payload = f"user{ZWSP}@аpple.com{TAG_A}"
    clean, hy = C.canonicalize(payload)
    blob = clean + json.dumps(hy.__dict__, ensure_ascii=True)
    for ch in (ZWSP, TAG_A, BOM, RLO, CGJ, HANGUL_FILLER, VS_SUPP):
        assert ch not in blob, f"literal {ch!r} leaked into output/record"


def test_nfc_not_nfkc():
    clean, _ = C.canonicalize("ＡＢＣ")   # fullwidth ABC
    assert clean == "ＡＢＣ" and clean != "ABC", "must not NFKC-fold (would mutate the value)"


@pytest.mark.parametrize("v", CLEAN + [f"a{ZWSP}{TAG_A}аpple.com{RLO}"], ids=range(len(CLEAN) + 1))
def test_idempotent(v):
    once, _ = C.canonicalize(v)
    twice, hy2 = C.canonicalize(once)
    assert twice == once, "strip/NFC not a text fixpoint"
    assert hy2.counts["stripped"] == 0, "second pass still found strippable code points"


def test_strip_then_nfc_recomposes_across_removed_char():
    # a + ZWSP + combining-acute: stripping the ZWSP lets NFC compose á (documents the defined behavior).
    clean, hy = C.canonicalize("a" + ZWSP + ACUTE)
    assert clean == "á" and len(hy.removed) == 1


def test_perf_is_not_quadratic():
    # Generous wall-clock bounds — NOT a tight benchmark (avoids CI-runner flake); they only need to
    # catch a quadratic blow-up (the pre-fix O(n^2) took ~200s on the dense case).
    big = "host.sub.example.com " * 250_000          # ~5 MB, URL/dot heavy
    t = time.time(); C.canonicalize(big); assert time.time() - t < 20.0
    dense = ("a" + ZWSP) * 20_000                     # 20k stripped chars
    t = time.time(); clean, hy = C.canonicalize(dense)
    assert time.time() - t < 10.0 and clean == "a" * 20_000 and len(hy.removed) == 20_000


def test_counts_match_lists():
    _, hy = C.canonicalize(f"user{ZWSP}{TAG_A} ig{ZWJ}nore")
    assert hy.counts == {"stripped": len(hy.removed), "flagged": len(hy.flagged)}
    assert hy.counts["stripped"] == 2 and hy.counts["flagged"] == 1  # ZWSP+TAG stripped; ig<ZWJ>nore flagged


def test_empty_is_safe():
    clean, hy = C.canonicalize("")
    assert clean == "" and hy.is_empty()
