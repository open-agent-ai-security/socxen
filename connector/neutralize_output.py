# /// script
# requires-python = ">=3.11"
# ///
"""Output-side active-content neutralizer — the a10 (export / formula injection) fix.

Applied to content socxen WRITES back through the bridge (case notes, alert/case updates) so a payload
planted in telemetry can't fire when that persisted artifact is later exported to a spreadsheet / ticket /
email. It DEFANGS visible values — which, UNLIKE the input canonicalizer, is safe here: these are
human-read output artifacts, not search-pivot values (defanging IOCs in a writeup is SOC-standard).

  neutralize_output(text) -> (clean_text, notes)     # notes: list of {"type", "original"} that changed

Neutralizations:
  1. **Active URLs** -> inert (`http`->`hxxp`, host dots -> `[.]`), incl. scheme-less markdown link
     targets (renderers linkify them) so a phishing link isn't clickable or reconstructable.
  2. **Dangerous schemes** (`javascript:`/`vbscript:`/`data:`/`file:`) -> `[:]`, so they don't execute
     or load when a note is exported into an HTML ticket / email.
  3. **Spreadsheet-formula cells** -> prefixed with `'` so Excel/Sheets treats them as text, not a formula
     (CSV/DDE injection). A formula-lead char (`=`/`@`, or `+`/`-` unless a number or `"- "` bullet) is
     neutralized at the start of *any* delimiter-bounded field — line start, a tab-separated field
     (paste-into-Excel), or a markdown-table cell — not only the first column.

Scope ("control what we control"): the sinks socxen owns — the case-note / alert-update WRITE tools,
gated on their (free-text) arguments at the bridge. The chat report (LLM free-text) has no code gate and
is covered by the SKILL.md defang rule (best-effort); what a human does to an artifact after it leaves
socxen is out of scope — but what socxen PERSISTS is already clean, so an export of it is safe.
"""
import re

__all__ = ["neutralize_output"]

# Active URL with an explicit scheme or leading www.
_URL_RE = re.compile(r"(?P<scheme>(?:https?|ftps?)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)", re.IGNORECASE)
# Non-navigational schemes that execute / load when a note is rendered as HTML (ticket / email).
_DANGER_SCHEME_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(javascript|vbscript|data|file)(:)")
# A markdown link target: [text](TARGET). Renderers linkify TARGET even with no scheme -> defang its host.
_MD_TARGET_RE = re.compile(r"(?<=\]\()([^)\s]+)")
# A scheme-less host[.tld][/path]. Only applied inside a link target, to avoid mangling prose / filenames.
_HOST_RE = re.compile(r"^(//)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(.*)$", re.S)
# A whole cell that is just a signed/plain number (thousands, decimal, scientific, percent) — not a formula.
_NUMBER_RE = re.compile(r"[+-]?[\d,]+(?:\.\d+)?(?:[eE][+-]?\d+)?%?$")
# A quoted field value opening with a formula-active char (e.g.  username: "=HYPERLINK(...)").
_QUOTED_FORMULA_RE = re.compile(r'"(\s*)([=+\-@][^"]*)')
# Delimiters a spreadsheet / markdown-table renderer treats as cell boundaries. Paste-into-Excel splits
# on TAB (and newline); a markdown table splits on `|`. A formula-lead char at the start of ANY such
# field — not just the line — evaluates on export. (Comma/semicolon CSV is intentionally NOT split here:
# free prose is comma-dense, so it would over-quote; the realistic note-export paths are paste and table.)
_CELL_DELIM_RE = re.compile(r"([\t|])")


def _defang_dots(host):
    return host.replace(".", "[.]")


def _defang_url(m):
    scheme, rest = m.group("scheme"), m.group("rest")
    host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
    scheme = re.sub(r"(?i)http", "hxxp", scheme)
    scheme = re.sub(r"(?i)ftp", "fxp", scheme)
    scheme = re.sub(r"(?i)www\.", "www[.]", scheme)
    return scheme + _defang_dots(host) + tail


def _defang_target(t):
    """Defang a scheme-less markdown link target. Already-schemed or already-defanged targets (which have
    no bare `host.tld` prefix once `_URL_RE`/`_DANGER_SCHEME_RE` have run) don't match `_HOST_RE`."""
    m = _HOST_RE.match(t)
    if not m:
        return t
    slashes, host, tail = m.groups()
    return (slashes or "") + _defang_dots(host) + tail


def _is_formula(cell):
    """True if a spreadsheet would evaluate this cell as a formula. `=`/`@` always. `+`/`-` unless it's a
    plain number (`-5`, `-1,200`) or a `"- "` list item — so `-cmd|'…'!A0`, `+HYPERLINK(x)`, `-2+3+cmd`
    are caught while numbers and markdown bullets are left alone."""
    s = cell.strip()
    if not s:
        return False
    if s[0] in ("=", "@"):
        return True
    if s[0] in ("+", "-"):
        if _NUMBER_RE.match(s):
            return False
        return len(s) > 1 and s[1] != " "
    return False


def _neutralize_formulas(text, notes):
    out = []
    for line in text.splitlines(keepends=True):
        core, nl = (line[:-1], line[-1:]) if line.endswith("\n") else (line, "")
        # Every delimiter-bounded field is a potential spreadsheet cell — quote-prefix each formula field,
        # not just the first. _CELL_DELIM_RE.split keeps delimiters at odd indices; content is at even.
        parts = _CELL_DELIM_RE.split(core)
        for i in range(0, len(parts), 2):
            field = parts[i]
            stripped = field.lstrip()
            if _is_formula(stripped):
                lead = field[: len(field) - len(stripped)]
                notes.append({"type": "formula", "original": stripped[:60]})
                parts[i] = f"{lead}'{stripped}"
        core = "".join(parts)

        def _q(m):                                                  # cell = quoted field value
            val = m.group(2)
            if not _is_formula(val):
                return m.group(0)
            notes.append({"type": "formula", "original": val[:60]})
            return f'"{m.group(1)}\'{val}'
        core = _QUOTED_FORMULA_RE.sub(_q, core)
        out.append(core + nl)
    return "".join(out)


def neutralize_output(text):
    """Neutralize active content in text socxen is about to WRITE. Pure and deterministic."""
    if not text:
        return text, []
    notes = []

    def _url(m):
        notes.append({"type": "url", "original": m.group()})
        return _defang_url(m)
    text = _URL_RE.sub(_url, text)

    def _sch(m):
        notes.append({"type": "scheme", "original": m.group()})
        return m.group(1) + "[:]"
    text = _DANGER_SCHEME_RE.sub(_sch, text)

    def _mdt(m):
        t = m.group(0)
        d = _defang_target(t)
        if d != t:
            notes.append({"type": "url", "original": t})
        return d
    text = _MD_TARGET_RE.sub(_mdt, text)

    text = _neutralize_formulas(text, notes)
    return text, notes
