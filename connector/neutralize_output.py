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

Known residuals (deliberately narrowed, not silent): (1) a **bare host in prose** with no scheme and no
markdown-link syntax (`beacon to evil.example/x`) is NOT defanged — defanging every `word.word/word` in
free text over-mangles legit references; scheme/`www.`/markdown-link forms ARE defanged. (2) A scheme
NAME split internally by whitespace/entities (`java\tscript:`) is not caught (matching it would false-fire
on prose). (3) Comma/semicolon CSV cells are not quoted (prose is comma-dense). These need the payload in
a specific unusual shape; the common export-injection forms are covered.
"""
import re

__all__ = ["neutralize_output"]

# Active URL with an explicit scheme or leading www.
_URL_RE = re.compile(r"(?P<scheme>(?:https?|ftps?)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)", re.IGNORECASE)
# Non-navigational schemes that execute / load when a note is rendered as HTML (ticket / email). The
# colon may be HTML-entity or whitespace encoded (`javascript&#58;`, `javascript&#09;:`) — an HTML sink
# decodes it — so allow an optional run of entities/whitespace before a literal-or-entity colon. The
# trailing colon-terminator is REQUIRED, so a plain word like "database" (data + "base") does not match.
_DANGER_SCHEME_RE = re.compile(
    r"(?i)(?<![a-z0-9])(javascript|vbscript|data|file)(?:\s|&#?\w+;)*(?::|&#0*58;|&#x0*3a;|&colon;)")
# A markdown link target: [text](TARGET). Renderers linkify TARGET even with no scheme -> defang its host.
_MD_TARGET_RE = re.compile(r"(?<=\]\()([^)\s]+)")
# A scheme-less host[.tld]/path. Only defanged (inside a link target) when it has a PATH or `//` — a bare
# dotted filename / relative link (`report.md`, `logo.png`, `v1.2`) has no path and is left alone.
_HOST_RE = re.compile(r"^(//)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(.*)$", re.S)
# A whole cell that is just a signed/plain number (thousands, decimal, scientific, percent) — not a formula.
_NUMBER_RE = re.compile(r"[+-]?[\d,]+(?:\.\d+)?(?:[eE][+-]?\d+)?%?$")
# A markdown table separator / thematic break (`---`, `:---:`, `- - -`) — never a formula.
_MD_SEP_RE = re.compile(r"[:\- ]+")
# Function-call / DDE syntax — what makes a `+`/`-`-led cell actually execute (`+HYPERLINK(x)`, `-cmd|'…'!A0`).
_DDE_SIGNAL_RE = re.compile(r"[(|!]")
# A quoted field value opening with a formula-active char (e.g.  username: "=HYPERLINK(...)").
_QUOTED_FORMULA_RE = re.compile(r'"(\s*)([=+\-@][^"]*)')
# A markdown-table cell: `|` + optional padding + content up to the next `|` (a raw `|` can't appear in a
# cell without breaking the table). Used to quote a formula lead inside a table cell. Paste-into-Excel
# (TAB-delimited) is handled by splitting fields on TAB only, so a DDE's own `|` stays in its field.
# (Comma/semicolon CSV is intentionally NOT handled: free prose is comma-dense — it would over-quote.)
_MD_CELL_RE = re.compile(r"(\|[ \t]*)([^|\n]*)")


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
    """Defang a scheme-less markdown link target that looks like a live host WITH A PATH (`host.tld/…`) —
    which renderers linkify. A bare dotted filename / relative link (`report.md`, `logo.png`, `v1.2`) has
    no path and is left ALONE. Already-schemed/defanged targets don't match `_HOST_RE`."""
    m = _HOST_RE.match(t)
    if not m:
        return t
    slashes, host, tail = m.groups()
    if not (slashes or tail.startswith("/")):        # no path and no `//` -> a filename/relative link, not a host
        return t
    return (slashes or "") + _defang_dots(host) + tail


def _is_formula(cell):
    """True if a spreadsheet would EXECUTE this cell as a formula. `=`/`@` always. A `+`/`-` lead executes
    only with function/DDE syntax (`+HYPERLINK(x)`, `-cmd|'…'!A0`) — a plain number (`-5`, `-1,200`), a
    `"- "` bullet, a markdown separator (`---`), or a bare measurement/word (`-5 ms`, `-verbose`) is inert
    and left alone (avoids over-quoting benign prose / tables)."""
    s = cell.strip()
    if not s:
        return False
    if s[0] in ("=", "@"):
        return True
    if s[0] in ("+", "-"):
        if _NUMBER_RE.match(s):                 # -5, -1,200, +1.5
            return False
        if s[1:2] == " ":                       # "- " list item
            return False
        if _MD_SEP_RE.fullmatch(s):             # ---, :---:, - - -
            return False
        # executes as a formula if the lead is followed by a function name (`+cmd`, `+HYPERLINK`) or it
        # carries DDE/function syntax (`( | !`). A bare number-lead measurement (`-5 ms`) is inert.
        return s[1:2].isalpha() or bool(_DDE_SIGNAL_RE.search(s))
    return False


def _quote(lead, cell, notes):
    notes.append({"type": "formula", "original": cell.strip()[:60]})
    return f"{lead}'{cell.lstrip()}"


def _neutralize_formulas(text, notes):
    out = []
    for line in text.splitlines(keepends=True):
        core, nl = (line[:-1], line[-1:]) if line.endswith("\n") else (line, "")

        # (1) markdown-table cells: quote a formula lead right after a `|`. Cell content has no `|` (a raw
        #     pipe would break the table), so this can't swallow a DDE's own `|`.
        if "|" in core:
            def _md(m):
                pad, cell = m.group(1), m.group(2)
                return f"{pad}{_quote('', cell, notes)}" if _is_formula(cell) else m.group(0)
            core = _MD_CELL_RE.sub(_md, core)

        # (2) line start + tab-separated fields (paste-into-Excel). Split on TAB ONLY — a field KEEPS its
        #     `|`, so a DDE payload (`+cmd|'x'!A0`) is detected whole, not cut at the pipe.
        fields = core.split("\t")
        for i, field in enumerate(fields):
            stripped = field.lstrip()
            if _is_formula(stripped):
                fields[i] = _quote(field[: len(field) - len(stripped)], field, notes)
        core = "\t".join(fields)

        # (3) quoted field values (username: "=HYPERLINK(...)")
        def _q(m):
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
