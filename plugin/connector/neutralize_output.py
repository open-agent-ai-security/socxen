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
  - an ALL-ALPHABETIC value after a BARE LINE BREAK ("Recovered credential\ncorrecthorsebatterystaple")
    is not caught: after a line break, a word with no digit and no delimiter is indistinguishable from
    recommendation prose ("credential\nRotation is required immediately"), and redacting it would eat
    real analyst text. Labelled (`password: X`), wrapped (`X` / "X"), and markdown-TABLE forms are all
    caught regardless of shape -- this residual is only the bare-newline-plus-dictionary-word case.
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
# Labeled secret: a credential keyword, a separator, then the value. Redacts only the VALUE, and only
# because a label vouches for it -- so a bare high-entropy string with no credential context is left
# alone (that is where blind entropy would create false positives). The keyword set and separator are
# broad on purpose: the live red-team (2026-08-18) showed the MODEL phrases labels its own way --
# "Secret Access Key: <v>", a value on the next line under a heading, a markdown-table cell -- so a
# rigid `key=value` anchor missed real leaks a unit test (which used the exact form) did not.
_KEYWORD = (
    r"passwo?r?d|passwd|pwd|pass[\s_-]?phrase|"
    r"secret[\s_-]?(?:access[\s_-]?)?key|access[\s_-]?key(?:[\s_-]?id)?|"
    r"api[\s_-]?(?:key|token|secret)|auth(?:orization)?[\s_-]?token|client[\s_-]?secret|"
    r"secret|token|bearer|credential|passcode")
# Delimiters that WRAP a value rather than belong to it. Matching excludes them from the value class
# would be wrong in both directions: exclude them and a backtick- or quote-wrapped secret is never seen
# (SKILL.md actively tells the model to wrap dangerous values in a code span, so that is the FORMAT WE
# ASK FOR); include them and the match swallows a markdown link's closing paren, disarming the link
# defanger downstream. So match permissively and hand the delimiters back at substitution time.
_OPEN_DELIMS, _CLOSE_DELIMS = "([{`\"'", ")]}`\"'"


# Sentence punctuation that can trail a structural delimiter ("...(see [x](url).", "...`secret`!").
# Peeled ONLY when a real closing delimiter is peeled with it -- otherwise a password that genuinely ends
# in punctuation ("Hunter2!") would have that character stripped out of the redacted span and disclosed.
_TRAIL_PUNCT = ".!?"


def _trim_delims(val, minlen):
    """Split a matched value into (lead, core, tail) by peeling wrapping delimiters. Returns None when the
    value must not be redacted: it is already a placeholder, or the core is shorter than minlen (so a run
    of punctuation never counts as a secret). O(len(val)) -- a per-character slice loop here is quadratic
    on an adversary-supplied delimiter run, and this input is attacker-controlled telemetry."""
    if "[REDACTED:" in val:              # never re-consume our own output: keeps the typed <kind> intact
        return None                      # (password: AKIA... -> [REDACTED:aws-key], not [[REDACTED:secret]])
    core = val.lstrip(_OPEN_DELIMS)
    lead = val[:len(val) - len(core)]
    # An UNMATCHED closing bracket ends the value: it belongs to the structure around it, and everything
    # after it does too. This is what keeps "…?token=abc123)." and "…?token=abc123)**now**" from having
    # their ")" (and trailing text) eaten -- peeling only from the end cannot see a delimiter with junk
    # behind it. Depth-tracked so a value with balanced brackets is not cut short.
    depth = {")": 0, "]": 0, "}": 0}
    pairs = {"(": ")", "[": "]", "{": "}"}
    cut = len(core)
    for i, ch in enumerate(core):
        if ch in pairs:
            depth[pairs[ch]] += 1
        elif ch in depth:
            if depth[ch] == 0:
                cut = i
                break
            depth[ch] -= 1
    stripped, tail = core[:cut], core[cut:]
    # Then peel any quote/backtick wrapper, plus sentence punctuation riding on a real closing delimiter.
    inner = stripped.rstrip(_CLOSE_DELIMS + _TRAIL_PUNCT)
    peeled = stripped[len(inner):]
    if peeled and any(c in _CLOSE_DELIMS for c in peeled):
        stripped, tail = inner, peeled + tail   # e.g. `secret`  ->  core=secret, tail=`
    return (lead, stripped, tail) if len(stripped) >= minlen else None


# STRONG separator: an explicit label assignment (`password: X`, `token=X`). The label vouches for the
# value, so any 6+ core is a secret -- you don't write "password: rotated".
_LABELED_SECRET_RE = re.compile(
    r"(?i)\b(" + _KEYWORD + r")\b"
    r"(\s*[:=]\s*)"
    r"(?P<val>[^\s,;<>|]{6,})")
# STRONG separator, table form: a markdown table ROW whose cell is exactly a credential keyword labels
# the cell beside it -- structurally a label/value pair, so no shape guard is needed. Anchored to ^| so
# an INLINE pipe in prose ("Evidence: token | source: pastebin") stays with the weak rule below.
# A GFM table delimiter row: |---|:---:|---| . Its presence marks the line ABOVE as a header row.
_TABLE_DELIM_RE = re.compile(r"^\s*\|?[\s:|-]*-[\s:|-]*\|[\s:|-]*$")
_TABLE_ROW_SECRET_RE = re.compile(
    r"(?im)^(\|[^\n]*?\b(?:" + _KEYWORD + r")\b)(\s*\|\s*)"
    r"(?P<val>[^\s,;<>|]{6,})")
# WEAK separators -- a copula ("secret was rotated") or a bare line break ("API token\nAKIA...") -- are
# AMBIGUOUS: what follows is usually recommendation prose ("rotated", "Rotate", "Disable"), not the
# secret. These require a secret-SHAPED core: 12+ chars with a digit AND a letter, the same heuristic
# _SPACE_SECRET_RE uses for the identical ambiguity. Documented consequence: a purely ALPHABETIC
# passphrase after a bare line break ("Recovered credential\ncorrecthorsebatterystaple") is NOT caught --
# a line break genuinely cannot be told from prose. Labelled, quoted, and table forms all are.
_WEAK_SEP_SECRET_RE = re.compile(
    r"(?i)\b(" + _KEYWORD + r")\b"
    r"(\s+(?:is|was)\s+|\s*[\r\n|]+\s*[-*|]?\s*)"
    r"(?P<val>(?=[^\s]*\d)(?=[^\s]*[A-Za-z])[^\s,;<>|]{12,})")
# Plain-space separator (a CLI flag like `--secret-key <v>`) is ambiguous — "password protection" would
# false-positive. So a space-separated value is redacted ONLY if it LOOKS secret-like: 12+ chars with at
# least one digit AND one letter (a dictionary word like "protection" has no digit and is spared).
_SPACE_SECRET_RE = re.compile(
    r"(?i)\b(" + _KEYWORD + r")\b\s+"
    r"(?P<val>(?=[^\s]*\d)(?=[^\s]*[A-Za-z])[A-Za-z0-9+/=_$.\-]{12,})")
# The final digit must not carry a separator, or the match eats the space after the number and the
# sentence closes up ("[REDACTED:credit-card]was charged") -- a do-no-harm defect on legitimate text.
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
# AWS secret access keys are exactly 40 base64 chars with no intrinsic prefix -- bare, they are
# indistinguishable from a hash (redacting all 40-char b64 => heavy false positives). But an AWS leak
# almost always carries the paired ACCESS key (AKIA/ASIA...), which IS intrinsically detectable. So:
# only when an access key is present in the text, redact 40-char base64 secrets. Proximity to the
# intrinsic marker is what makes this low-FP.
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_B64_40_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])")


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
    # Snapshot the AWS-access-key signal BEFORE any redaction — the intrinsic pass below rewrites AKIA to
    # a placeholder, which would blind the proximity rule that keys off it.
    had_aws_key = bool(_AWS_ACCESS_KEY_RE.search(text))

    def _note(kind):
        ns.append({"type": f"redact:{kind}", "original": f"<{kind} redacted>"})

    for kind, rx in _SECRET_PATTERNS:
        def _sub(m, _k=kind):
            _note(_k)
            return f"[REDACTED:{_k}]"
        text = rx.sub(_sub, text)

    def _labeled_min(minlen):
        def _sub(m):
            trimmed = _trim_delims(m.group("val"), minlen)
            if trimmed is None:                      # punctuation only -- not a secret
                return m.group(0)
            lead, _core, tail = trimmed
            _note("secret")
            # Hand the wrapping delimiters back: the link keeps its ")", the code span its backticks,
            # so the downstream link defanger / formula passes still see the structure they need.
            return m.group(1) + m.group(2) + lead + "[REDACTED:secret]" + tail
        return _sub
    text = _LABELED_SECRET_RE.sub(_labeled_min(6), text)
    # A GFM HEADER row is always followed by a delimiter row (|---|---|), and its cells are column
    # names, not values -- redacting there mangles an ordinary findings table ("| Token | Source |
    # First seen |"). Skip those rows; apply the label/value rule to the rest.
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if i + 1 < len(lines) and _TABLE_DELIM_RE.match(lines[i + 1]):
            continue
        lines[i] = _TABLE_ROW_SECRET_RE.sub(_labeled_min(6), line)
    text = "\n".join(lines)
    text = _WEAK_SEP_SECRET_RE.sub(_labeled_min(12), text)

    def _space_labeled(m):
        _note("secret")
        return m.group(1) + " [REDACTED:secret]"
    text = _SPACE_SECRET_RE.sub(_space_labeled, text)

    def _cc(m):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            _note("credit-card")
            return "[REDACTED:credit-card]"
        return m.group(0)
    text = _CC_CANDIDATE_RE.sub(_cc, text)

    # AWS secret-by-proximity: only if an AWS access key is present (the leak signature), redact bare
    # 40-char base64 blobs -- the paired secret. Skips our own placeholder. Off entirely without the
    # access-key signal, so a lone hash elsewhere is never touched.
    if had_aws_key:
        def _awssec(m):
            _note("aws-secret")
            return "[REDACTED:aws-secret]"
        text = _B64_40_RE.sub(_awssec, text)

    return text

_FORMULA_CALL_RE = re.compile(r"^[=+\-@][\w.$]*\(")                 # sign + name + "(" : =HYPERLINK(, @SUM(
# Mid-line (prose-position) formulas. A formula the model QUOTES in running text -- after a label colon
# ("username field: =HYPERLINK(..."), inside backticks, in a bullet -- is not cell-leading, but the
# verbatim string re-arms the moment it is copy-pasted into a sheet or re-celled by a CSV export, so it
# is not a safe "mention" the way a bare URL is. Cell positions keep the generic sign+name+( detector;
# mid-line detection requires a KNOWN dangerous function name (high specificity, same philosophy as
# redaction) so prose like "score =high(ish)" or "@channel (all hands)" is never touched. (?<!') skips
# occurrences already quote-prefixed by the cell-position passes.
# (?<![\w']) blocks occurrences already quote-prefixed AND hyphenated prose ("on-call (rotation)",
# "auto-exec (enabled)" -- the sign glued to a preceding word is prose, not a formula). Function names
# that are also English words (EXEC, CALL, REGISTER, RTD) additionally require the "(" with no space.
_MID_LINE_FORMULA_RE = re.compile(
    r"(?<![\w'])[=+\-@](?:(?:HYPERLINK|WEBSERVICE|FILTERXML|IMPORT(?:XML|DATA|HTML|FEED|RANGE)|"
    r"DDE(?:AUTO)?)\s*\(|(?:EXEC|CALL|REGISTER|RTD)\()",
    re.IGNORECASE)
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

        def _mid(m):                                        # known-dangerous formula quoted mid-prose
            nonlocal found
            found = True
            notes.append({"type": "formula", "original": m.group(0)[:60]})
            return "'" + m.group(0)
        core = _MID_LINE_FORMULA_RE.sub(_mid, core)

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

    # ORDER MATTERS. Link defang runs BEFORE redaction, not after. A credential-shaped query parameter
    # (`[reset](https://evil/login?token=abc123).`) puts both controls on one span, and whichever runs
    # first wins: with redaction first, its value match consumed the link's closing ")" and _MD_LINK_RE
    # could no longer see a link -- leaving a LIVE clickable phishing URL in a persisted note (worse than
    # no redactor at all). Defanging first makes that impossible for EVERY value shape rather than for the
    # shapes a fixture happens to cover: by the time the redactor runs, the host is already inert, so
    # whatever it consumes it cannot re-arm a link. Redaction still sees the query value verbatim (defang
    # rewrites the scheme and host, never the query string), so nothing is lost.
    def _link(m):
        target = m.group(2)
        d = _defang_target(target)
        if d != target:
            notes.append({"type": "link", "original": target[:60]})
        return m.group(1) + d + m.group(3)
    text = _MD_LINK_RE.sub(_link, text)

    text = redact_secrets(text, notes)

    text = _neutralize_formulas(text, notes)
    return text, notes
