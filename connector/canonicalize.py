# /// script
# requires-python = ">=3.11"
# dependencies = ["regex>=2024.0"]
# ///
r"""Input telemetry canonicalizer — pure, deterministic core.

Design: security/design/input-canonicalizer.md. Given untrusted text read from a SIEM, this:
  1. **strips** the invisible Unicode "smuggling" layer,
  2. **NFC-normalizes**, and
  3. **flags — and neutralizes —** confirmed obfuscation (a kept invisible/blank spliced into an ASCII
     word, or a variation-selector covert channel): the offending invisibles are stripped from the value,
returning `(clean_text, Hygiene)`.

The strip set uses the `regex` module's Unicode properties rather than a hand-list:
`\p{Cf}` ∪ `\p{Default_Ignorable_Code_Point}` ∪ `\p{Cc}` ∪ `\p{Cs}` (minus the whitespace + joiners we
carve out). BOTH Cf and DI are needed — DI omits the invisible Cf format controls (Arabic U+0600–0605/
06DD, interlinear U+FFF9–FFFB, Syriac U+070F, …) and Cf omits the DI Mn/Lo invisibles (variation
selectors, CGJ, Hangul fillers). The properties (not an enumerated list) keep it complete +
zero-maintenance as the UCD evolves. Everything else is plain stdlib.

The single `regex` runtime dep is declared in this module's PEP-723 header for standalone/test use.
WIRING TODO: when the bridge imports this module, add `regex` to the bridge's own PEP-723 header (its
`uv run` env doesn't read this file's) and regenerate the AI BOM.

Pivot-safety (§2): a value with no invisible smuggling code points returns `NFC(value)` with an empty
hygiene record — visible Cyrillic/Persian/emoji content is preserved. CAVEAT (review #8, OPEN design
question): NFC is not identity on all code points — it recomposes NFD-stored values (macOS filenames)
and folds canonical singletons (U+212A KELVIN → ASCII "K"), so an exact-match pivot on a backend that
stored the raw form can miss. Whether to canonicalize search-pivot values at all — vs. only display/
reasoning text, preserving a raw copy for pivots — is a deferred design decision, not settled here.

Scope: STRIP + NFC + FLAG only. The richer forensic record (per-offset escaped-raw reconstruction, byte
offsets, severity) is deferred to the bridge-wiring phase (gated: OQ-4/6/8) — intentionally not built here.
"""
import unicodedata
from dataclasses import dataclass, field

import regex

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

# U+2028 LINE / U+2029 PARAGRAPH SEPARATOR (Zl/Zp \u2014 not in Cf/DI/Cc/Cs) are invisible line breaks an LLM
# tokenizes as logical newlines, letting an attacker smuggle a "new instruction" out of a single quoted
# field. We NORMALIZE them to a visible "\n" rather than DELETE them: deleting fuses the tokens on either
# side (corrupting values / pivots), and \n\r\t are already kept \u2014 this makes the hidden break visible.
_LINE_SEP_RE = regex.compile(r"[\u2028\u2029]")

_FIELD_CAP = 80  # bound the (visible-only) token echoed in a flag

# Invisible/blank chars we do NOT strip but WILL flag when they appear inside an otherwise-ASCII token
# (the carve-outs kept for legit Persian/Indic/emoji, plus U+2800 BRAILLE BLANK which is visually blank
# but not in Cf/DI). See the obfuscated-ASCII flag below.
_KEEP_INVIS = {0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x2800} | set(range(0xFE00, 0xFE10))
# Joiners/marks that legitimately sit BETWEEN characters — they don't count as "base" characters when
# deciding whether a token carries more variation selectors than it has bases to attach to.
_JOINERS = frozenset({0x200C, 0x200D, 0x200E, 0x200F, 0x061C})


def _escape(tok):
    """Render a (potentially invisible-bearing) flagged token as printable \\uXXXX escapes, so a hygiene
    record / log line never carries raw invisible bytes back into text the agent or a human reads."""
    out = "".join(c if (c.isprintable() and ord(c) not in _KEEP_INVIS) else f"\\u{ord(c):04X}" for c in tok)
    return out[:_FIELD_CAP]


def is_strippable(ch):
    """True if `ch` is in the strip set — exposed so tests can compute the accounting oracle."""
    return bool(_STRIP_RE.fullmatch(ch))


@dataclass
class Hygiene:
    removed: list = field(default_factory=list)   # [{"cp": "U+200B", "name": "ZERO WIDTH SPACE"}]
    flagged: list = field(default_factory=list)   # [{"class": "obfuscated-ascii", "token": "..."}]
    counts: dict = field(default_factory=dict)

    def is_empty(self):
        return not self.removed and not self.flagged


def canonicalize(text):
    """Strip invisibles → NFC → flag+neutralize confirmed obfuscation. Pure, deterministic. See design §2–§11."""
    if not text:
        return text, Hygiene(counts={"stripped": 0, "flagged": 0})

    hy = Hygiene()

    # ---- normalize invisible line/paragraph separators to a VISIBLE newline. Deleting them (like the
    #      strip set) would FUSE the tokens on either side and corrupt the value; \n\r\t are already kept,
    #      and U+2028/2029 are their invisible cousins — make the hidden break visible instead. ----
    def _sep(m):
        ch = m.group()
        hy.removed.append({"cp": f"U+{ord(ch):04X}", "name": unicodedata.name(ch, "") + " → newline"})
        return "\n"
    text = _LINE_SEP_RE.sub(_sep, text)

    # ---- strip: the complete Cf ∪ DI ∪ Cc ∪ Cs set (regex), recording each removed code point ----
    def _record(m):
        ch = m.group()
        hy.removed.append({"cp": f"U+{ord(ch):04X}", "name": unicodedata.name(ch, "")})
        return ""
    stripped = _STRIP_RE.sub(_record, text)

    # ---- normalize LAST: NFC is canonical-equivalent, so visible values are preserved (pivot-safe) ----
    clean = unicodedata.normalize("NFC", stripped)

    # ---- flag AND neutralize confirmed obfuscation riding the KEPT carve-out invisibles:
    #  (a) obfuscated-ASCII — an ASCII word with a spliced kept invisible/blank (ZWJ in "ignore", Braille
    #      blank). Legit Persian/Indic/emoji have non-ASCII LETTERS, so removing the kept invisibles leaves
    #      a still-non-ASCII token and does NOT flag.
    #  (b) variation-selector smuggle — more FE00-FE0F selectors than base chars to attach to (a legit
    #      emoji uses <=1 per base; joiners aren't bases, so `FE0F ZWJ FE0F` interleaving can't evade it).
    #  A flagged token is confirmed obfuscation (not legit script), so we STRIP the offending invisibles
    #  from `clean` (protection in the VALUE, not a spoofable annotation) and record the token ESCAPED.
    #  (Homoglyph / mixed-script detection is intentionally NOT here — advisory, FP-prone; a later feature.)
    def _flag(m):
        tok = m.group()
        out = tok
        if not tok.isascii():
            bare = "".join(c for c in tok if ord(c) not in _KEEP_INVIS)
            if bare != tok and bare.isascii() and any(c.isalnum() for c in bare):
                hy.flagged.append({"class": "obfuscated-ascii", "token": _escape(tok)})
                out = bare
        vs = sum(1 for c in out if 0xFE00 <= ord(c) <= 0xFE0F)
        if vs:
            bases = sum(1 for c in out if not (0xFE00 <= ord(c) <= 0xFE0F) and ord(c) not in _JOINERS)
            if vs > bases:
                hy.flagged.append({"class": "variation-selector-run", "token": _escape(tok)})
                out = "".join(c for c in out if not (0xFE00 <= ord(c) <= 0xFE0F))
        return out
    clean = regex.sub(r"\S+", _flag, clean)


    hy.counts = {"stripped": len(hy.removed), "flagged": len(hy.flagged)}
    return clean, hy
