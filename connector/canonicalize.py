# /// script
# requires-python = ">=3.11"
# ///
"""Input telemetry canonicalizer — the pure, deterministic core.

Design: security/design/input-canonicalizer.md. This module is the un-gated core (strip / flag / NFC /
structured hygiene record). Bridge integration — hygiene transport (OQ-6), argument handling (OQ-4),
and the boundary with the output-side a10 fix (OQ-8) — is deliberately NOT here; it waits on those gates.

Contract:  canonicalize(text) -> (clean_text, Hygiene)
  - STRIP a curated set of invisible/smuggling code points (identity-based; §4).
  - FLAG (never rewrite) homoglyph/mixed-script, base64/hex blobs, combining-mark runs, and abnormal
    hidden-char density (§5).
  - Normalize to NFC last (§6).
  - Emit a structured, out-of-band Hygiene record (§9) — offsets into the ORIGINAL input, per-flag
    severity, and an escaped-raw reconstruction for dirty values. The record is itself untrusted:
    attacker-derived fields are escaped and length-bounded (§9 R2 invariant).

Pivot-safety invariant (§2): a value with no smuggling code points returns `NFC(value)` with an empty
hygiene record — nothing legitimate is mutated.
"""
import re
import unicodedata
from dataclasses import dataclass, field

__all__ = ["canonicalize", "Hygiene", "STRIP_SET"]

# ---- §4 strip set (curated deny-list; identity-based) ----------------------------------------------

def _build_strip_set():
    cps = set()
    cps |= set(range(0xE0000, 0xE0080))                 # Unicode Tag block
    cps |= set(range(0xE0100, 0xE01F0))                 # Variation Selectors Supplement (VS17–256)
    cps |= set(range(0x202A, 0x202F))                   # bidi embeddings/overrides (202A–202E)
    cps |= set(range(0x2066, 0x206A))                   # bidi isolates (2066–2069)
    cps |= {0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064}  # ZWSP, word joiner, invisible math ops
    cps |= {0xFEFF, 0x00AD, 0x180E}                     # BOM/ZWNBSP, soft hyphen, Mongolian vowel sep
    cps |= (set(range(0x00, 0x20)) - {0x09, 0x0A, 0x0D})  # C0 controls except \t \n \r
    cps |= set(range(0x80, 0xA0))                       # C1 controls
    cps |= set(range(0xD800, 0xE000))                   # lone/orphaned surrogates
    return frozenset(cps)

STRIP_SET = _build_strip_set()

# ---- §5 flag-only sets (never stripped) ------------------------------------------------------------

_JOINERS = {0x200C, 0x200D}                             # ZWNJ/ZWJ — legit in scripts/emoji
_EMOJI_VS = set(range(0xFE00, 0xFE10))                  # variation selectors 1–16 (incl FE0F)
_DIR_MARKS = {0x200E, 0x200F, 0x061C}                   # LRM/RLM/ALM — legit in mixed-direction text
_CONFUSABLE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "COPTIC", "CHEROKEE"}  # Latin look-alikes

# Tuning (start conservative; §12 OQ-3):
_HIDDEN_BUDGET = 3          # > this many stripped chars in one blob -> high "excessive hidden chars"
_COMBINING_RUN = 5          # run of >= this many combining marks (Mn) -> suspicious (Zalgo)
_FIELD_CAP = 80             # §9 R2: length-bound attacker-derived metadata fields

# NOTE — no "invisible-density" flag over ZWJ / emoji variation-selectors (FE00–FE0F). Those are
# legitimate emoji glue (a couple-kiss emoji has 5), so counting them false-positives on ordinary
# emoji. The real byte-smuggling channels — VS-supplement E0100–E01EF, sneaky-bits math ops, the tag
# block — are already in STRIP_SET (and drive the hidden-char budget), so density over the legit ones
# adds no detection, only noise. Surfaced by an adversarial self-sweep, not the original tests.


@dataclass
class Hygiene:
    schema: str = "socxen.hygiene/v1"
    removed: list = field(default_factory=list)
    flagged: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    escapedRaw: dict = field(default_factory=dict)
    status: str = "ok"

    def is_empty(self):
        return not self.removed and not self.flagged


def _script(ch):
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return None


def _escape(s, cap=_FIELD_CAP):
    """Render a value display-safe: invisibles/controls -> \\uXXXX, visible letters (incl. Cyrillic, so
    a homoglyph reads as `аpple.com`) kept literal. Length-bounded so a metadata field can't smuggle."""
    out = []
    total = 0
    for ch in s:
        o = ord(ch)
        cat = unicodedata.category(ch)
        piece = f"\\u{o:04x}" if (o in STRIP_SET or cat in ("Cc", "Cf", "Cs", "Zl", "Zp")
                                  or o in _JOINERS or o in _EMOJI_VS or o in _DIR_MARKS) else ch
        out.append(piece)
        total += len(piece)
        if total > cap:                 # §9 R2: bound the work — never scan a huge token past the cap
            return "".join(out)[:cap] + "…"
    return "".join(out)


def _mixed_script(token):
    if token.isascii():                 # mixed-script needs a non-ASCII confusable; skip per-char work
        return False
    scripts = set()
    for ch in token:
        if ch.isalpha():
            s = _script(ch)
            if s == "LATIN" or s in _CONFUSABLE_SCRIPTS:
                scripts.add("LATIN" if s == "LATIN" else s)
    return "LATIN" in scripts and bool(scripts - {"LATIN"})


# NOTE — base64/hex "encoded-blob" flagging (design §5) is intentionally DEFERRED from v1. Writing the
# clean-corpus test surfaced that a naive blob regex flags every MD5/SHA hash and long ID/token — exactly
# the legitimate values the pivot-safety invariant says must stay unflagged. A useful version must be
# FP-safe (e.g. flag only when a decode yields strip-set/control chars — but decode-to-inspect needs its
# own review). Tracked as a follow-up so hashes/IDs don't become constant false alarms.


def canonicalize(text):
    """Return (clean_text, Hygiene). Pure and deterministic. See module docstring / design §2–§11."""
    if not text:
        return text, Hygiene(counts={"stripped": 0, "flagged": 0})

    hy = Hygiene()
    kept = []
    bpos = 0  # running byte offset into the ORIGINAL input (O(n) total; avoids per-hit re-encoding)

    # ---- strip pass: identity removal over ORIGINAL code points; offsets are original indices (§9) ----
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in STRIP_SET:
            hy.removed.append({
                "cp": f"U+{cp:04X}",
                "name": unicodedata.name(ch, ""),
                "offset": i,
                "byteOffset": bpos,
                "class": "strip",
                "reason": _strip_reason(cp),
            })
        else:
            kept.append(ch)
        bpos += len(ch.encode("utf-8", "surrogatepass"))
    stripped_text = "".join(kept)

    # ---- flag pass: ONE O(n) sweep over tokens of the ORIGINAL text (never mutates) ----
    for m in re.finditer(r"\S+", text):
        token, start = m.group(), m.start()
        if _mixed_script(token):
            _flag(hy, token, start, "mixed-script", "high", "Latin mixed with a confusable script")
        if _max_combining_run(token) >= _COMBINING_RUN:   # Zalgo
            _flag(hy, token, start, "combining-run", "suspicious", "long combining-mark run")
        # escapedRaw: if this token held any stripped char, record its escaped form so IR can rebuild an
        # exact query (§8). Computed ONCE per token, keyed by token start; `any` short-circuits at the
        # first stripped char (was an O(removed × token_len) loop — a DoS on a single invisible-dense token).
        if any(ord(c) in STRIP_SET for c in token):
            hy.escapedRaw[str(start)] = _escape(token)

    # hidden-char budget: many stripped code points in one blob is itself a signal (§5)
    if len(hy.removed) > _HIDDEN_BUDGET:
        hy.flagged.append({"class": "excessive-hidden-chars", "severity": "high",
                           "reason": f"{len(hy.removed)} stripped invisible code points"})

    # ---- §6 normalize LAST (identity strip commutes with NFC; strip-first for clean offsets) ----
    clean = unicodedata.normalize("NFC", stripped_text)

    hy.counts = {"stripped": len(hy.removed), "flagged": len(hy.flagged)}
    return clean, hy


def _strip_reason(o):
    if 0xE0000 <= o <= 0xE007F:
        return "tag-block"
    if 0xE0100 <= o <= 0xE01EF:
        return "variation-selector-supplement"
    if 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069:
        return "bidi-control"
    if 0xD800 <= o <= 0xDFFF:
        return "lone-surrogate"
    if o < 0x20 or 0x80 <= o <= 0x9F:
        return "control"
    return "zero-width"


def _flag(hy, token, offset, cls, severity, reason):
    hy.flagged.append({"token": _escape(token), "offset": offset, "class": cls,
                       "severity": severity, "reason": reason})


def _max_combining_run(s):
    if s.isascii():                     # ASCII has no combining marks; skip per-char category lookup
        return 0
    best = cur = 0
    for ch in s:
        if unicodedata.category(ch) == "Mn":
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best
