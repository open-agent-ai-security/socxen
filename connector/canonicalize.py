# /// script
# requires-python = ">=3.11"
# ///
"""Input telemetry canonicalizer -- pure, deterministic core.

"DO NO HARM" first. Strip only the OBVIOUS, unambiguous smuggling code points (no legitimate use inside a
value), normalize invisible line/paragraph separators to a visible newline, and NFC-normalize. Anything
with real linguistic use is LEFT ALONE -- corrupting a legit value (and breaking an exact-match pivot) is
worse than missing an exotic smuggle.

  canonicalize(text) -> (clean_text, Hygiene)      # Hygiene.removed = the stripped code points

KEPT (legit use, so stripping them would do harm): ZWNJ/ZWJ, LRM/RLM/ALM, emoji variation selectors
(U+FE00-FE0F), soft hyphen, Mongolian/Khmer/Hangul-filler format, NBSP & other spaces.

Accepted residuals (out of scope by design -- we do not chase perfection on an adversarially-infinite
domain, nor corrupt legit data to try): a kept-invisible spliced into an ASCII word, emoji
variation-selector byte channels, NBSP keyword-splitting, and NFC folding of compatibility singletons
(U+212A KELVIN -> "K") / NFD recomposition (a rare, bounded exact-match-pivot miss).
"""
import unicodedata
from dataclasses import dataclass, field

__all__ = ["canonicalize", "Hygiene", "is_strippable"]

# Curated "obvious smuggling" set -- code points with no legitimate use inside a telemetry value.
# Each (first, last) range is inclusive. C0/C1 controls keep \t \n \r.
_SMUGGLE_RANGES = [
    (0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F), (0x7F, 0x9F),   # C0 / C1 controls
    (0x200B, 0x200B),                                         # ZERO WIDTH SPACE
    (0x2060, 0x2064),                                         # WORD JOINER + invisible math operators
    (0x206A, 0x206F),                                         # deprecated format controls
    (0x202A, 0x202E), (0x2066, 0x2069),                       # bidi embeddings / overrides / isolates
    (0xFEFF, 0xFEFF),                                         # ZERO WIDTH NO-BREAK SPACE / BOM
    (0xFFF9, 0xFFFB),                                         # interlinear annotation
    (0xE0000, 0xE007F),                                       # tag characters
    (0xE0100, 0xE01EF),                                       # variation selectors SUPPLEMENT (FE00-FE0F kept)
]
_STRIP = frozenset(cp for lo, hi in _SMUGGLE_RANGES for cp in range(lo, hi + 1))
_LINE_SEP = frozenset({0x2028, 0x2029})   # invisible logical newlines -> normalized to "\n" (not deleted)


def is_strippable(ch):
    """True if `ch` is in the strip set -- exposed so tests can compute the accounting oracle."""
    return ord(ch) in _STRIP


@dataclass
class Hygiene:
    removed: list = field(default_factory=list)   # [{"cp": "U+200B", "name": "ZERO WIDTH SPACE"}]
    counts: dict = field(default_factory=dict)

    def is_empty(self):
        return not self.removed


def canonicalize(text):
    """Strip obvious smuggling -> normalize LS/PS to newline -> NFC. Pure and deterministic."""
    if not text:
        return text, Hygiene(counts={"stripped": 0})

    hy = Hygiene()
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in _LINE_SEP:
            hy.removed.append({"cp": f"U+{cp:04X}", "name": unicodedata.name(ch, "") + " -> newline"})
            out.append("\n")
        elif cp in _STRIP:
            hy.removed.append({"cp": f"U+{cp:04X}", "name": unicodedata.name(ch, "")})
        else:
            out.append(ch)

    clean = unicodedata.normalize("NFC", "".join(out))
    hy.counts = {"stripped": len(hy.removed)}
    return clean, hy
