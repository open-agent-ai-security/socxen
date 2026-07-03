# /// script
# requires-python = ">=3.11"
# dependencies = ["regex>=2024.0", "confusable-homoglyphs>=3.3"]
# ///
"""Input telemetry canonicalizer — pure, deterministic core.

Design: security/design/input-canonicalizer.md. Given untrusted text read from a SIEM, this:
  1. **strips** the invisible Unicode "smuggling" layer,
  2. **NFC-normalizes**, and
  3. **flags** (never rewrites) obfuscated-ASCII tokens (a kept invisible/blank spliced into an ASCII
     word) and homoglyph / mixed-script tokens,
returning `(clean_text, Hygiene)`.

It leans on maintained libraries for the two *solved* primitives, rather than hand-rolling them:
  - **strip set** = Unicode `\p{Cf}` ∪ `\p{Default_Ignorable_Code_Point}` ∪ `\p{Cc}` ∪ `\p{Cs}` via the
    `regex` module (minus the whitespace + joiners we carve out). BOTH Cf and DI are needed — DI omits the
    invisible Cf format controls (Arabic U+0600–0605/06DD, interlinear U+FFF9–FFFB, Syriac U+070F, …) and
    Cf omits the DI Mn/Lo invisibles (variation selectors, CGJ, Hangul fillers). The properties (not an
    enumerated list) keep it complete + zero-maintenance as the UCD evolves.
  - **confusable detection** = `confusable_homoglyphs` (UTS #39), detection-only. KNOWN v1 FP: a legit
    non-Latin word with attached ASCII in one token (localized filename/hostname) flags — restrict-vs-defer
    under review.
So this module is only the thin wrapper that adds socxen's pivot-safety guarantee and hygiene record.

Runtime deps (`regex`, `confusable_homoglyphs`) are declared in this module's PEP-723 header for
standalone/test use. WIRING TODO: when the bridge imports this module, move the deps into the bridge's
own PEP-723 header (its `uv run` env doesn't read this file's) and regenerate the AI BOM.

Pivot-safety invariant (§2): a value with no invisible smuggling code points returns `NFC(value)` with an
empty hygiene record — nothing legitimate (Cyrillic/Persian/emoji *visible* content) is mutated, so
downstream exact-match search still works.

Scope: STRIP + NFC + FLAG only. The richer forensic record (per-offset escaped-raw reconstruction, byte
offsets, severity) is deferred to the bridge-wiring phase (gated: OQ-4/6/8) — intentionally not built here.
"""
import unicodedata
from dataclasses import dataclass, field

import regex
from confusable_homoglyphs import confusables

__all__ = ["canonicalize", "Hygiene", "is_strippable"]

# §4 strip set: Default_Ignorable ∪ controls ∪ surrogates, MINUS the whitespace we keep and the
# legitimate joiners/marks we carve out (carve-out "A"). `[[...]--[...]]` is regex set subtraction.
#   kept: \t \n \r · ZWNJ/ZWJ (U+200C/D — required in Persian/Indic & emoji) · LRM/RLM/ALM
#         (U+200E/F, U+061C) · emoji variation selectors (U+FE00–FE0F).
# NOTE: \p{Cf} is REQUIRED and SEPARATE from \p{DI} — DI does NOT include invisible format controls
# U+0600-0605/06DD/08E2 (Arabic), U+070F (Syriac), U+FFF9-FFFB (interlinear), Kaithi/Egyptian format.
# \p{Cf} u \p{DI} together are the complete invisible/format set; properties keep it zero-maintenance.
_STRIP_RE = regex.compile(
    r"[[\p{Cf}\p{Default_Ignorable_Code_Point}\p{Cc}\p{Cs}]"
    r"--[\t\n\r\u200c\u200d\u200e\u200f\u061c\uFE00-\uFE0F]]",
    flags=regex.VERSION1,
)

_FIELD_CAP = 80  # bound the (visible-only) token echoed in a flag

# Invisible/blank chars we do NOT strip but WILL flag when they appear inside an otherwise-ASCII token
# (the carve-outs kept for legit Persian/Indic/emoji, plus U+2800 BRAILLE BLANK which is visually blank
# but not in Cf/DI). See the obfuscated-ASCII flag below.
_KEEP_INVIS = {0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x2800} | set(range(0xFE00, 0xFE10))


def is_strippable(ch):
    """True if `ch` is in the strip set — exposed so tests can compute the accounting oracle."""
    return bool(_STRIP_RE.fullmatch(ch))


@dataclass
class Hygiene:
    removed: list = field(default_factory=list)   # [{"cp": "U+200B", "name": "ZERO WIDTH SPACE"}]
    flagged: list = field(default_factory=list)   # [{"class": "mixed-script", "token": "аpple.com"}]
    counts: dict = field(default_factory=dict)

    def is_empty(self):
        return not self.removed and not self.flagged


def canonicalize(text):
    """Strip invisibles → NFC → flag confusables. Pure and deterministic. See design §2–§11."""
    if not text:
        return text, Hygiene(counts={"stripped": 0, "flagged": 0})

    hy = Hygiene()

    # ---- strip: the complete Cf ∪ DI ∪ Cc ∪ Cs set (regex), recording each removed code point ----
    def _record(m):
        ch = m.group()
        hy.removed.append({"cp": f"U+{ord(ch):04X}", "name": unicodedata.name(ch, "")})
        return ""
    stripped = _STRIP_RE.sub(_record, text)

    # ---- normalize LAST: NFC is canonical-equivalent, so visible values are preserved (pivot-safe) ----
    clean = unicodedata.normalize("NFC", stripped)

    # ---- flag (never rewrite), per token ----
    for m in regex.finditer(r"\S+", clean):
        tok = m.group()
        if tok.isascii():
            continue
        # (a) obfuscated-ASCII: an ASCII word with a KEPT invisible/blank char spliced in — a keyword-
        # splitting smuggle (a ZWJ inside "ignore", an FE0F inside "table", a Braille-blank in an ASCII
        # token). Legit Persian/Indic/emoji have real non-ASCII LETTERS around the char, so removing the
        # kept invisibles/blanks leaves a still-non-ASCII token and does NOT flag. (Closes the carve-out
        # and U+2800 channels that would otherwise pass as clean.)
        bare = "".join(c for c in tok if ord(c) not in _KEEP_INVIS)
        if bare != tok and bare.isascii() and any(c.isalnum() for c in bare):
            hy.flagged.append({"class": "obfuscated-ascii", "token": tok[:_FIELD_CAP]})
            continue
        # (b) mixed-script (confusable). Check LETTERS only — the kept format chars aren't script-bearing
        # and otherwise read as a script boundary (false-flag on Persian/emoji).
        # KNOWN v1 FP (Reviewer A): a legit non-Latin word + attached ASCII in ONE token (localized
        # filenames/hostnames like "процесс.exe", "北京-server01") flags. Restrict-vs-defer under review.
        letters = "".join(c for c in tok if c.isalpha())
        if letters and not letters.isascii() and confusables.is_mixed_script(letters):
            hy.flagged.append({"class": "mixed-script", "token": tok[:_FIELD_CAP]})

    hy.counts = {"stripped": len(hy.removed), "flagged": len(hy.flagged)}
    return clean, hy
