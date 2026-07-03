# /// script
# requires-python = ">=3.11"
# ///
"""Output-side active-content neutralizer — the a10 (export / formula injection) fix.

Applied to content socxen WRITES back through the bridge (case notes, alert/case updates) so a payload
planted in telemetry can't fire when that persisted artifact is later exported to a spreadsheet / ticket /
email. It DEFANGS visible values — which, UNLIKE the input canonicalizer, is safe here: these are
human-read output artifacts, not search-pivot values (defanging IOCs in a writeup is SOC-standard).

  neutralize_output(text) -> (clean_text, notes)     # notes: list of {"type", "original"} that changed

Two neutralizations:
  1. **Active URLs** -> inert (`hxxps://` -> `hxxps://`, host dots -> `[.]`), so a phishing link isn't
     clickable and can't be reconstructed by a renderer.
  2. **Spreadsheet-formula cells** -> prefixed with `'` so Excel/Sheets treats them as text, not a formula
     (CSV/DDE injection). `=`/`@` always; `+`/`-` unless the cell is a plain number or a `"- "` list item.

Scope ("control what we control"): the sinks socxen owns — the case-note / alert-update WRITE tools, gated
on their arguments at the bridge (wiring is the gated next step). The chat report (LLM free-text) has no
code gate and is covered by the SKILL.md defang rule (best-effort); what a human does to an artifact after
it leaves socxen is out of scope — but what socxen PERSISTS is already clean, so an export of it is safe.
"""
import re

__all__ = ["neutralize_output"]

# Active URL with an explicit scheme or leading www. (case-note IOCs — defanging them is safe + standard).
_URL_RE = re.compile(r"(?P<scheme>(?:https?|ftps?)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)", re.IGNORECASE)
# A whole cell that is just a signed/plain number (thousands, decimal, scientific, percent) — not a formula.
_NUMBER_RE = re.compile(r"[+-]?[\d,]+(?:\.\d+)?(?:[eE][+-]?\d+)?%?$")
# A quoted field value opening with a formula-active char (e.g.  username: "=HYPERLINK(...)").
_QUOTED_FORMULA_RE = re.compile(r'"(\s*)([=+\-@][^"]*)')


def _defang_url(m):
    scheme, rest = m.group("scheme"), m.group("rest")
    host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
    host = host.replace(".", "[.]")
    scheme = re.sub(r"(?i)http", "hxxp", scheme)
    scheme = re.sub(r"(?i)ftp", "fxp", scheme)
    scheme = re.sub(r"(?i)www\.", "www[.]", scheme)
    return scheme + host + tail


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
        stripped = core.lstrip()
        if _is_formula(stripped):                                   # cell = whole line
            lead = core[: len(core) - len(stripped)]
            notes.append({"type": "formula", "original": stripped[:60]})
            core = f"{lead}'{stripped}"

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
    text = _neutralize_formulas(text, notes)
    return text, notes
