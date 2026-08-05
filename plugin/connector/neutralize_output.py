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

  neutralize_output(text) -> (clean_text, notes)     # notes: list of {"type","original"} that changed

DOCUMENTED RESIDUAL (out of scope, by decision): a BARE URL typed in prose (not a markdown link, not on a
formula line) is left UNTOUCHED -- defanging every URL would mangle the legit reference links analysts
write in notes (do harm). A bare phishing domain in prose is best-effort (SKILL prompt), not deterministic.
"""
import re

__all__ = ["neutralize_output"]

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
    """Quote-prefix executable formulas (+ defang URLs on those lines) and defang markdown-link targets.
    Bare URLs in prose are out of scope (documented residual). Pure and deterministic."""
    if not text:
        return text, []
    notes = []

    def _link(m):
        target = m.group(2)
        d = _defang_target(target)
        if d != target:
            notes.append({"type": "link", "original": target[:60]})
        return m.group(1) + d + m.group(3)
    text = _MD_LINK_RE.sub(_link, text)

    text = _neutralize_formulas(text, notes)
    return text, notes
