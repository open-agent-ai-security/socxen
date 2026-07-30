# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic tests for the input canonicalizer (connector/canonicalize.py). No model, CI-safe.

One bar, honestly: DO NO HARM (legit values pass through unchanged) and STOP THE OBVIOUS (unambiguous
smuggling code points are stripped). The exotic tail (kept-invisible ASCII splices, variation-selector
byte channels, NBSP-splitting, NFC compatibility folds) is a documented residual in the module and is
intentionally NOT tested here -- we do not test what we have decided not to solve.

All invisible characters come from chr(); the source carries no literal invisibles.

Run:  uv run --with pytest pytest -q tests/test_canonicalize.py
"""
import importlib.util
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("canonicalize", ROOT / "connector" / "canonicalize.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

ZWJ, ZWNJ, FE0F = chr(0x200D), chr(0x200C), chr(0xFE0F)

# ---- DO NO HARM: legit values pass through unchanged (only NFC-normalized) ----
LEGIT = [
    "user@corp.example", "svc/web01.corp.local@CORP.EXAMPLE", "portal.example.com/a/b?q=1",
    "10.0.0.4", "2001:db8::1", "C:\\Windows\\System32\\cmd.exe", "/usr/bin/python3",
    "report.md", "logo.png", "v1.2.3", "d41d8cd98f00b204e9800998ecf8427e",
    "cafe naive value", "Cyrillic Москва", "accented cafe\u0301",
    "mi" + ZWNJ + "rud (persian zwnj)",
    chr(0x1F468) + ZWJ + chr(0x1F469) + ZWJ + chr(0x1F467),   # family emoji (ZWJ sequence)
    chr(0x2764) + FE0F,                                       # heart + emoji variation selector
    "hangul " + chr(0x1160),                                  # Hangul filler (legit, kept)
    "khmer " + chr(0x17B4),                                   # Khmer inherent vowel (legit, kept)
    "co" + chr(0x00AD) + "operate",                           # soft hyphen (legit, kept)
    "arabic " + chr(0x0645) + chr(0x034F) + chr(0x0631),      # CGJ in Arabic (legit, kept)
]


@pytest.mark.parametrize("v", LEGIT, ids=range(len(LEGIT)))
def test_do_no_harm(v):
    clean, hy = C.canonicalize(v)
    assert clean == unicodedata.normalize("NFC", v), f"legit value mutated: {v!r} -> {clean!r}"
    assert hy.is_empty(), f"legit value had chars stripped: {hy.removed}"


# ---- STOP THE OBVIOUS: unambiguous smuggling code points are stripped ----
OBVIOUS = [0x200B, 0x2060, 0x2062, 0xFEFF, 0x202E, 0x2068, 0x206F, 0xFFF9, 0xE0041, 0xE0100, 0x0007, 0x009F]


@pytest.mark.parametrize("cp", OBVIOUS, ids=[f"U+{c:04X}" for c in OBVIOUS])
def test_obvious_smuggling_stripped(cp):
    clean, hy = C.canonicalize("A" + chr(cp) + "B")
    assert clean == "AB", f"U+{cp:04X} survived into clean text"
    assert len(hy.removed) == 1 and hy.removed[0]["cp"] == f"U+{cp:04X}"


# ---- invisible line/paragraph separators become a VISIBLE newline (no token fusion) ----
@pytest.mark.parametrize("cp", [0x2028, 0x2029])
def test_line_separators_become_newline(cp):
    clean, hy = C.canonicalize("12" + chr(cp) + "34")
    assert clean == "12\n34", f"expected newline, not fusion/deletion: {clean!r}"
    assert hy.removed and hy.removed[0]["cp"] == f"U+{cp:04X}"


# ---- basic invariants ----
def test_empty_is_safe():
    clean, hy = C.canonicalize("")
    assert clean == "" and hy.is_empty()


def test_idempotent():
    for v in LEGIT + ["A" + chr(0x200B) + "B", "12" + chr(0x2028) + "34"]:
        once, _ = C.canonicalize(v)
        twice, hy2 = C.canonicalize(once)
        assert twice == once and hy2.is_empty(), f"not idempotent: {v!r} -> {once!r} -> {twice!r}"


def test_no_stripped_char_survives_in_output():
    clean, _ = C.canonicalize("mix" + chr(0x200B) + chr(0xFEFF) + "ed")
    assert clean == "mixed" and all(ord(c) not in C._STRIP for c in clean)


def test_counts_match_removed():
    _, hy = C.canonicalize("a" + chr(0x200B) + chr(0xFEFF) + "b")
    assert hy.counts == {"stripped": 2} and len(hy.removed) == 2
