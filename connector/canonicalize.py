# /// script
# requires-python = ">=3.11"
# dependencies = ["regex>=2024.0", "confusable-homoglyphs>=3.3"]
# ///
"""Input telemetry canonicalizer — pure, deterministic core.

Design: security/design/input-canonicalizer.md. Given untrusted text read from a SIEM, this:
  1. **strips** the invisible Unicode "smuggling" layer,
  2. **NFC-normalizes**, and
  3. **flags** (never rewrites) homoglyph / mixed-script tokens,
returning `(clean_text, Hygiene)`.

It leans on maintained libraries for the two *solved* primitives, rather than hand-rolling them:
  - **strip set** = the Unicode **Default_Ignorable_Code_Point** property via the `regex` module — the
    authoritative "invisible" set, tracking the UCD (this replaced a hand-list that two reviews found had
    ~50 gaps: variation selectors, CGJ, Hangul fillers, interlinear/musical/Arabic format controls);
  - **confusable detection** = `confusable_homoglyphs` (UTS #39), detection-only.
So this module is only the thin wrapper that adds socxen's pivot-safety guarantee and hygiene record.

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
# Using the DI *property* (not an enumerated list) is what makes this complete + zero-maintenance.
_STRIP_RE = regex.compile(
    r"[[\p{Default_Ignorable_Code_Point}\p{Cc}\p{Cs}]"
    r"--[\t\n\r\u200c\u200d\u200e\u200f\u061c\uFE00-\uFE0F]]",
    flags=regex.VERSION1,
)

_FIELD_CAP = 80  # bound the (visible-only) token echoed in a flag


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

    # ---- strip: authoritative Default-Ignorable set (regex), recording each removed code point ----
    def _record(m):
        ch = m.group()
        hy.removed.append({"cp": f"U+{ord(ch):04X}", "name": unicodedata.name(ch, "")})
        return ""
    stripped = _STRIP_RE.sub(_record, text)

    # ---- normalize LAST: NFC is canonical-equivalent, so visible values are preserved (pivot-safe) ----
    clean = unicodedata.normalize("NFC", stripped)

    # ---- flag (never rewrite) mixed-script tokens. Per token + ASCII fast-path so legit single-script
    # text (Russian, Persian, CJK) and plain ASCII never flag — only a token that MIXES scripts (the
    # homoglyph-domain attack, e.g. Cyrillic-а + Latin "pple.com"). Whole-script confusables and
    # script+digit mixes are NOT caught (UTS #39 treats digits as Common) — a documented v1 limit.
    for m in regex.finditer(r"\S+", clean):
        tok = m.group()
        if tok.isascii():
            continue
        # Check LETTERS only: the carve-out format chars we keep (ZWJ/ZWNJ/FE0F) aren't script-bearing,
        # and confusable_homoglyphs otherwise reads them as a script boundary -> false mixed-script on
        # legit Persian / ZWJ-emoji. Digits/punct are Common (excluded from mixed-script) anyway.
        letters = "".join(c for c in tok if c.isalpha())
        if letters and not letters.isascii() and confusables.is_mixed_script(letters):
            hy.flagged.append({"class": "mixed-script", "token": tok[:_FIELD_CAP]})

    hy.counts = {"stripped": len(hy.removed), "flagged": len(hy.flagged)}
    return clean, hy
