# /// script
# requires-python = ">=3.11"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Output-side active-content neutralizer -- the a10 (export / formula injection) fix.

Applied to content socxen WRITES back through the bridge (case notes, alert/case updates) so a payload
planted in telemetry cannot fire when that persisted artifact is later exported. Scope is deliberately
narrow -- "do no harm; stop the obvious; document the exotic" -- to two ACTIVE-content forms:

  1. FORMULA cells (=HYPERLINK(...), @SUM(...), =cmd|'..'!A0): quote-prefixed inert, and any URL on the
     formula's line is defanged. Stops CSV / formula injection on spreadsheet export.
  2. MARKDOWN LINKS [text](target): the target is defanged (host -> [.], scheme -> hxxp, javascript: ->
     [:]). Stops a clickable phishing link. EVERY markdown link is mutated -- the accepted compromise,
     since a deterministic pass cannot tell a legit link from a malicious one.
  3. SECRETS / STRUCTURED PII (the class-D redaction fix, #88 / assessment F-04): a credential or
     structured government identifier planted in telemetry must not survive verbatim into a persisted
     case note / export -- a durable, broader-audience artifact. Prompt-only redaction was measured
     leaking 100% (red-team d01/d03), so this is deterministic. Each match is replaced with a typed
     placeholder [REDACTED:<kind>] so the report still says "a credential was here" without the value.

  neutralize_output(text) -> (clean_text, notes)     # notes: list of {"type","original"} that changed

DOCUMENTED RESIDUALS (out of scope, by decision):
  - a BARE URL typed in prose (not a markdown link, not on a formula line) is left UNTOUCHED -- defanging
    every URL would mangle the legit reference links analysts write in notes (do harm).
  - FREE-FORM PII (names, home addresses) and DATE-shaped values (DOB) are NOT redacted: a home address
    is not reliably regex-detectable, and a date is indistinguishable from the timestamp on every log
    line (redacting it would gut legitimate reports). These stay a best-effort SKILL-prompt ask.
  - the operator's own on-screen chat is not a sink here: they are authorized to read the raw telemetry,
    so display crosses no trust boundary. This gates the WRITE path (what gets persisted), not the console.

Redaction is HIGH-SPECIFICITY only -- format/prefix/checksum/label-anchored, never blind entropy -- so a
hash, UUID, IP, or hostname in a legitimate report passes through untouched (see the FP corpus in tests).
"""
import re

__all__ = ["neutralize_output", "redact_secrets"]

# --- secret / structured-PII redaction (#88) ----------------------------------------------------------
# Each entry: (kind, compiled regex). Order matters only for overlapping matches (private-key blocks
# before generic tokens). Every pattern is anchored on a structural signal a legitimate value would not
# carry, to keep false positives near zero:
#   - AWS keys: the AKIA/ASIA prefix + fixed length
#   - vendor tokens: distinctive, registered prefixes (ghp_, xoxb-, sk-, AIza, JWT eyJ...)
#   - private keys: the PEM armor
#   - labeled secrets: a credential KEYWORD immediately preceding the value (password=, --secret-key X)
#   - SSN: the exact \d{3}-\d{2}-\d{4} shape (rare in logs); credit cards are Luhn-verified below
_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.S)),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("token", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("token", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
]
# Labeled secret: a credential keyword, a separator, then the value up to whitespace/quote/comma.
# Redacts only the VALUE, and only because a label vouches for it -- so a bare 40-char string with no
# credential context is left alone (that is where blind entropy would create false positives).
_LABELED_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret[\s_-]?key|secret|api[\s_-]?key|access[\s_-]?key|auth[\s_-]?token|token|client[\s_-]?secret|bearer)\b"
    r"(\s*[:=]\s*|\s+)"
    r"(?P<val>[^\s,;\"'<>]{6,})")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact_secrets(text, notes=None):
    """Replace credentials and structured government identifiers with typed [REDACTED:<kind>] markers.
    High-specificity only -- see module docstring for what is deliberately NOT redacted. Pure; appends a
    {"type":"redact:<kind>", "original": <masked-preview>} note per hit when `notes` is given. Never
    records the secret itself in the note (a redactor must not re-leak into the audit trail)."""
    if not text:
        return text
    ns = notes if notes is not None else []

    def _note(kind):
        ns.append({"type": f"redact:{kind}", "original": f"<{kind} redacted>"})

    for kind, rx in _SECRET_PATTERNS:
        def _sub(m, _k=kind):
            _note(_k)
            return f"[REDACTED:{_k}]"
        text = rx.sub(_sub, text)

    def _labeled(m):
        _note("secret")
        return m.group(1) + m.group(2) + "[REDACTED:secret]"
    text = _LABELED_SECRET_RE.sub(_labeled, text)

    def _cc(m):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            _note("credit-card")
            return "[REDACTED:credit-card]"
        return m.group(0)
    text = _CC_CANDIDATE_RE.sub(_cc, text)

    return text

_FORMULA_CALL_RE = re.compile(r"^[=+\-@][\w.$]*\(")                 # sign + name + "(" : =HYPERLINK(, @SUM(
_DDE_RE = re.compile(r"\|\S[^|!]*!")                                # DDE channel ref: cmd|'/C calc'!A0
_QUOTED_FORMULA_RE = re.compile(r'"(\s*)([=+\-@][^"]*)')            # a quoted field value: "=HYPERLINK(...)"
_MD_CELL_RE = re.compile(r"(\|[ \t]*)([^|\n]*)")                    # a markdown-table cell
_MD_LINK_RE = re.compile(r"(\[[^\]]*\]\()([^)\s]+)(\))")            # a markdown link: [text](target)
_URL_RE = re.compile(r"(?P<scheme>(?:https?|ftps?)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)", re.IGNORECASE)
_DANGER_SCHEME_RE = re.compile(
    r"(?i)(?<![a-z0-9])(javascript|vbscript|data|file)(?:\s|&#?\w+;)*(?::|&#0*58;|&#x0*3a;|&colon;)")
_HOST_RE = re.compile(r"^(//)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(.*)$", re.S)


def _defang_url(m):
    scheme, rest = m.group("scheme"), m.group("rest")
    host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
    scheme = re.sub(r"(?i)http", "hxxp", scheme)
    scheme = re.sub(r"(?i)ftp", "fxp", scheme)
    scheme = re.sub(r"(?i)www\.", "www[.]", scheme)
    return scheme + host.replace(".", "[.]") + tail


def _defang(s):
    """Defang dangerous schemes + scheme/www URLs in a string. Applied ONLY to markdown-link targets and
    formula-carrying lines -- never to bare prose (the documented residual)."""
    s = _DANGER_SCHEME_RE.sub(lambda m: m.group(1) + "[:]", s)
    return _URL_RE.sub(_defang_url, s)


def _defang_target(t):
    """Defang a markdown-link target: a scheme URL / dangerous scheme, or a scheme-less dotted host (which
    a renderer linkifies). A relative path / anchor with no dotted host is left alone."""
    d = _defang(t)
    if d != t:
        return d
    m = _HOST_RE.match(t)
    if m:
        slashes, host, tail = m.groups()
        return (slashes or "") + host.replace(".", "[.]") + tail
    return t


def _is_formula(cell):
    """True only if a spreadsheet would EXECUTE this cell: it opens with =/@/+/- AND the danger signal is
    STRUCTURALLY ATTACHED -- a function call right after the sign (=HYPERLINK(, @SUM(, +WEBSERVICE() or a
    DDE channel reference (cmd|'..'!A0). A bare (, !, or | merely appearing SOMEWHERE in the text does NOT
    count -- so an analyst line like '- pending (review)', '- fixed! ok', '-5 (approx)', '@channel (all
    hands)', or '=summary: 3 accounts (contained)' opens with one of those chars but is plain prose and is
    left ALONE (do no harm)."""
    s = cell.strip()
    if len(s) < 2 or s[0] not in "=@+-":
        return False
    return bool(_FORMULA_CALL_RE.match(s) or _DDE_RE.search(s))


def _neutralize_formulas(text, notes):
    out = []
    for line in text.splitlines(keepends=True):
        core, nl = (line[:-1], line[-1:]) if line.endswith("\n") else (line, "")
        found = False

        if "|" in core:                                     # markdown-table cells
            def _md(m):
                nonlocal found
                pad, cell = m.group(1), m.group(2)
                if not _is_formula(cell):
                    return m.group(0)
                found = True
                notes.append({"type": "formula", "original": cell.strip()[:60]})
                return pad + "'" + cell.lstrip()
            core = _MD_CELL_RE.sub(_md, core)

        fields = core.split("\t")                           # line start + tab-separated fields
        for i, field in enumerate(fields):
            stripped = field.lstrip()
            if _is_formula(stripped):
                found = True
                notes.append({"type": "formula", "original": stripped[:60]})
                fields[i] = field[: len(field) - len(stripped)] + "'" + stripped
        core = "\t".join(fields)

        def _q(m):                                          # quoted field values
            nonlocal found
            val = m.group(2)
            if not _is_formula(val):
                return m.group(0)
            found = True
            notes.append({"type": "formula", "original": val[:60]})
            return '"' + m.group(1) + "'" + val
        core = _QUOTED_FORMULA_RE.sub(_q, core)

        if found:                                           # this line carries a formula -> defang its URL(s)
            core = _defang(core)
        out.append(core + nl)
    return "".join(out)


def neutralize_output(text):
    """Redact secrets/structured-PII, quote-prefix executable formulas (+ defang URLs on those lines),
    and defang markdown-link targets. Bare URLs and free-form PII in prose are out of scope (documented
    residuals). Pure and deterministic. Redaction runs FIRST, so a secret is masked before any structural
    transform can split or requote it."""
    if not text:
        return text, []
    notes = []

    text = redact_secrets(text, notes)

    def _link(m):
        target = m.group(2)
        d = _defang_target(target)
        if d != target:
            notes.append({"type": "link", "original": target[:60]})
        return m.group(1) + d + m.group(3)
    text = _MD_LINK_RE.sub(_link, text)

    text = _neutralize_formulas(text, notes)
    return text, notes
