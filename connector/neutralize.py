# /// script
# requires-python = ">=3.11"
# ///
"""Inbound neutralization of untrusted telemetry — the code-layer half of RFE #2.

The bridge proxies every read result from the remote Exabeam MCP into the agent's context. That
content is attacker-influenceable (alert fields, event text, prior case notes), so before it reaches
the model we neutralize the two constructs that are dangerous *downstream of the agent* — i.e. that
survive into the report / case note / exported artifact and fire there:

  1. **Active URLs / emails** -> defanged (`hxxps://`, `evil[.]example`, `user[@]host`). A defanged IOC
     is still readable and analyzable, but it is not a clickable phishing link, and it no longer matches
     its live form — so an agent that echoes it verbatim can't reproduce the live domain in the report.
  2. **Spreadsheet-formula-active cells** (`=`, `@`, and `+`/`-` followed by a non-digit) -> prefixed
     with a single quote so Excel/Sheets treats them as text, not a formula (CSV/formula injection).

This is deliberately conservative about false positives: usernames with dots (`p.mensah`), filenames
(`config.json`), bare IPs, and signed numbers (`-5`, `+1.5`) are NOT touched — only scheme/`www.` URLs,
`local@domain.tld` emails, and genuine formula leads. Because it's a pure function, it is unit-tested
without the model, and the confirmed a10 export-injection payload becomes a deterministic regression
guardrail (PLAN.md: "confirmed attacks become permanent regression fixtures").

Scope note: this covers the **fetch path** (agent reads telemetry through the bridge) — socxen's real
ingestion path. It does not cover a human *pasting* raw telemetry into the chat; nothing runs in that
path but the prompt. Encoding canonicalization (zero-width / homoglyph / base64 — a06-a08) is the other
half of #2 and is intentionally left to a follow-up; those already resist at the prompt layer.
"""
import re
import sys

__all__ = ["neutralize", "neutralize_content"]

# A URL with an explicit scheme or a leading www. — conservative on purpose: a bare `p.mensah` or
# `config.json` has no scheme, so it is never matched and never mangled.
_URL_RE = re.compile(
    r"(?P<scheme>(?:https?|ftps?|file)://|www\.)(?P<rest>[^\s<>\"'\)\]}]+)",
    re.IGNORECASE,
)

# local@domain.tld — requires a dotted TLD so a lone `@SUM(...)` formula lead is not read as an email.
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})\b")

# A field value opening with a formula-active char, e.g.  username: "=HYPERLINK(...)"  or  "@SUM(...)".
# Restricted to `=`/`@` inside quotes so a legitimate quoted "-5" is left alone.
_QUOTED_FORMULA_RE = re.compile(r'(")(\s*)([=@])')

# A whole cell that is just a signed/plain number (incl. thousands commas, decimals, scientific, percent).
# A `+`/`-`-led cell matching this is a NUMBER, not a formula, and must be left alone.
_NUMBER_RE = re.compile(r"[+-]?[\d,]+(?:\.\d+)?(?:[eE][+-]?\d+)?%?$")


def _defang_url(m):
    scheme, rest = m.group("scheme"), m.group("rest")
    host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
    host = host.replace(".", "[.]")
    scheme = re.sub(r"(?i)http", "hxxp", scheme)
    scheme = re.sub(r"(?i)ftp", "fxp", scheme)
    scheme = scheme.replace("www.", "www[.]").replace("WWW.", "www[.]")
    return scheme + host + tail


def _defang_email(m):
    return f"{m.group(1)}[@]{m.group(2).replace('.', '[.]')}"


def _looks_like_formula(cell):
    """True if a spreadsheet would evaluate this cell as a dangerous formula. `=X`/`@X` always. A `+`/`-`
    lead is the ambiguous case: a signed *number* (`-5`, `+1.5`, `-1,200`, `-3.2e4`) is left alone, but a
    sign-led cell carrying formula machinery — letters, `(`, `|`, `!` (e.g. `-2+3+cmd|'…'`, `+HYPERLINK(x)`)
    — is neutralized. A lone `-` / arithmetic-only `-2+3` is neither number nor payload, so left alone."""
    s = cell.strip()
    if not s:
        return False
    if s[0] in ("=", "@"):
        return True
    if s[0] in ("+", "-"):
        if _NUMBER_RE.match(s):
            return False
        return bool(re.search(r"[A-Za-z(|!]", s))
    return False


def _neutralize_formulas(text):
    out = []
    for line in text.splitlines(keepends=True):
        core, nl = (line[:-1], "\n") if line.endswith("\n") else (line, "")
        stripped = core.lstrip()
        if _looks_like_formula(stripped):
            lead = core[: len(core) - len(stripped)]
            core = f"{lead}'{stripped}"
        core = _QUOTED_FORMULA_RE.sub(r"\1\2'\3", core)  # "=..  ->  "'=..
        out.append(core + nl)
    return "".join(out)


def neutralize(text):
    """Neutralize one untrusted text blob. Pure and idempotent-safe on already-defanged input
    (defanged forms no longer match the live patterns)."""
    if not text:
        return text
    text = _URL_RE.sub(_defang_url, text)
    text = _EMAIL_RE.sub(_defang_email, text)
    text = _neutralize_formulas(text)
    return text


def neutralize_content(content):
    """Map neutralize() over the text of MCP content blocks returned by a tool call. Leaves non-text
    blocks (images, embedded resources) untouched. Returns a new list; rebuilds text blocks via
    model_copy when available so we never depend on the block being mutable.

    FAIL-OPEN, per block: this sits in the path of *every* tool call, so a bug in neutralization must
    never break an investigation. If any block raises, we log to stderr and pass that block through
    UNCHANGED rather than dropping it or aborting the call. The cost of fail-open is that a
    neutralizer bug degrades to "no defense-in-depth on that block" (the prompt-layer rule still
    applies) — never to "the agent can't read its evidence"."""
    out = []
    for block in content:
        try:
            if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str):
                cleaned = neutralize(block.text)
                copy = getattr(block, "model_copy", None)
                if callable(copy):
                    block = copy(update={"text": cleaned})
                else:  # pragma: no cover - fallback for non-pydantic block
                    block.text = cleaned
        except Exception as e:  # noqa: BLE001 - availability over neutralization; see docstring
            sys.stderr.write(f"neutralize: passing block through unchanged after error: {e!r}\n")
        out.append(block)
    return out
