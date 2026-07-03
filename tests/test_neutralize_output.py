# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
"""Deterministic tests for the output-side neutralizer (connector/neutralize_output.py). No model, CI-safe.

This is the a10 (export/formula injection) fix. The a10 red-team payload becomes a deterministic
regression guardrail here (PLAN.md: confirmed attacks become permanent fixtures).

Run:  uv run --with pytest pytest -q tests/test_neutralize_output.py
"""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("neutralize_output", ROOT / "connector" / "neutralize_output.py")
N = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(N)

A10 = json.loads((ROOT / "security/redteam/attacks/a10-export-formula-injection.attack.json").read_text())
A10_PAYLOAD = A10["input"]["payload"]
A10_MARKERS = A10["expected"]["must_not"]["leak"]   # raw domains a correct defang breaks


def test_a10_payload_is_neutralized():
    clean, notes = N.neutralize_output(A10_PAYLOAD)
    for marker in A10_MARKERS:                        # evil.example/x, sso-reset.evil.example
        assert marker not in clean, f"a10 leak marker {marker!r} survived"
    assert "evil[.]example" in clean and "hxxps://" in clean, "domains not defanged"
    assert "'=HYPERLINK" in clean, "the =HYPERLINK formula was not neutralized"
    assert notes, "no neutralization notes recorded"


# ---- MARKDOWN-LINK targets are defanged (every link -- the accepted compromise) ----
@pytest.mark.parametrize("raw,gone,present", [
    ("[click](https://sso-reset.evil.example)", "sso-reset.evil.example", "hxxps://sso-reset[.]evil[.]example"),
    ("[c2](evil-c2.example/beacon)", "evil-c2.example/beacon", "evil-c2[.]example/beacon"),
    ("[x](javascript:alert(1))", "javascript:", "[:]"),
    ("[x](javascript&#58;alert(1))", "javascript:", "[:]"),        # entity-encoded colon
    ("[runbook](https://docs.exabeam.com)", "docs.exabeam.com", "docs[.]exabeam[.]com"),  # legit link also mutated
])
def test_markdown_link_targets_defanged(raw, gone, present):
    clean, _ = N.neutralize_output(raw)
    assert gone not in clean.lower() and present in clean


# ---- DO NO HARM: a BARE URL / scheme in prose (no link, no formula) is a documented residual: untouched ----
@pytest.mark.parametrize("prose", [
    "See https://docs.exabeam.com/runbook for the procedure.",
    "console at https://portal.corp.local/dashboard",
    "visit www.exabeam.com now",
    "the IOC api.evil-c2.example/beacon was seen",
    "open file:///etc/hosts to check",
    "run vbscript:msgbox(1) manually",
])
def test_bare_urls_in_prose_untouched(prose):
    assert N.neutralize_output(prose)[0] == prose


# ---- formula cells neutralized (line-lead and quoted) ----
@pytest.mark.parametrize("cell", [
    "=HYPERLINK(\"http://x\")", "@SUM(A1)", "-cmd|' /c calc'!A0", "+WEBSERVICE(\"x\")", "-2+3+cmd|'x'!A0",
])
def test_formula_leads_prefixed(cell):
    clean, _ = N.neutralize_output(cell)
    assert clean.startswith("'"), f"formula {cell!r} not neutralized: {clean!r}"


def test_quoted_formula_neutralized():
    clean, _ = N.neutralize_output('username: "=HYPERLINK(\\"x\\")"')
    assert "\"'=HYPERLINK" in clean


# ---- FALSE-POSITIVE guards: benign output must NOT be corrupted ----
@pytest.mark.parametrize("benign", [
    "-5", "+1.5", "-1,200", "3.2e4",          # signed numbers
    "- first bullet", "- second item",         # markdown list items ("- " with a space)
    "risk dropped by 12 points",               # plain prose
    "user p.mensah logged in from 10.0.0.4",   # username + IP (no scheme -> untouched)
    "SELECT * FROM t WHERE score=5",           # inline = mid-line, not a cell lead
])
def test_benign_output_unchanged(benign):
    clean, notes = N.neutralize_output(benign)
    assert clean == benign and notes == [], f"benign output mangled: {benign!r} -> {clean!r}"


def test_idempotent():
    once, _ = N.neutralize_output(A10_PAYLOAD)
    twice, notes2 = N.neutralize_output(once)
    assert twice == once and notes2 == [], "second pass changed already-neutralized text"


def test_empty_is_safe():
    assert N.neutralize_output("") == ("", [])


# ---- adversarial-review regressions (PR #36) ----

@pytest.mark.parametrize("raw", [
    "host\t=cmd|'/C calc'!A0",                       # tab-separated DDE (paste-into-Excel column split)
    '| username | =HYPERLINK("http://evil.example/x") |',  # function in a markdown cell, not at column 0
    "a\t@SUM(1+1)*cmd",                              # @-function after a tab
    "col1\t+cmd|calc",                              # +-lead DDE after a tab (keeps its pipe)
])
def test_formula_neutralized_past_first_column(raw):
    """Finding #1 (Critical): a formula-lead char at the start of ANY tab/pipe field, not just column 0,
    must be quote-prefixed — otherwise it fires on paste/export."""
    clean, notes = N.neutralize_output(raw)
    assert "'=" in clean or "'@" in clean or "'+" in clean, f"formula field not quoted: {clean!r}"
    assert notes


@pytest.mark.parametrize("raw,gone", [
    ("[x](javascript:alert(document.cookie))", "javascript:"),
    ("[o](file:///etc/passwd)", "file:"),
    ("[r](data:text/html;base64,PHN2Zz4=)", "data:"),
    ("[v](vbscript:msgbox(1))", "vbscript:"),
])
def test_dangerous_schemes_in_links_defanged(raw, gone):
    """Finding #2 (High): a non-navigational scheme USED AS A LINK TARGET is rendered inert (`[:]`).
    (Bare in prose it is a documented residual -- see test_bare_urls_in_prose_untouched.)"""
    clean, _ = N.neutralize_output(raw)
    assert gone not in clean and "[:]" in clean, f"dangerous scheme survived: {clean!r}"


@pytest.mark.parametrize("raw,gone,present", [
    ("[reset](sso-reset.evil.example/x)", "sso-reset.evil.example", "sso-reset[.]evil[.]example"),
    ("[c2](evil-c2.example/path)", "evil-c2.example/path", "evil-c2[.]example"),
])
def test_schemeless_markdown_link_targets_defanged(raw, gone, present):
    """Finding #3/M1 (Med): a scheme-less host used as a markdown link target is linkified by renderers,
    so its host must be defanged."""
    clean, _ = N.neutralize_output(raw)
    assert gone not in clean and present in clean, f"scheme-less link target not defanged: {clean!r}"


@pytest.mark.parametrize("benign", [
    "The user logged in, then 3 - 2 failures, - see the note below",   # commas/dashes in prose
    "| Time | Event | Source |",                                       # markdown table header row
    "path is C:\\Users\\a\\report.pdf and v1.2.3 shipped",             # dotted filename/version
])
def test_review_benign_not_over_mangled(benign):
    """The hardening must not quote/defang ordinary prose, table headers, filenames, or versions."""
    clean, notes = N.neutralize_output(benign)
    assert clean == benign and notes == [], f"benign mangled: {benign!r} -> {clean!r}"


@pytest.mark.parametrize("raw", [
    "host\t=cmd|'/C calc'!A0",
    "[x](javascript:alert(1))",
    "[reset](sso-reset.evil.example/x)",
])
def test_hardening_is_idempotent(raw):
    once, _ = N.neutralize_output(raw)
    twice, notes2 = N.neutralize_output(once)
    assert twice == once and notes2 == [], f"second pass changed neutralized text: {once!r} -> {twice!r}"


# ---- second-review regressions (PR #36 round 2) ----

@pytest.mark.parametrize("raw", [
    "[x](javascript&#58;alert(1))",       # entity-encoded colon
    "[x](javascript&#09;:alert(1))",      # entity-tab before colon
    "[x](JavaScript:alert(1))",           # case
    "[v](vbscript&#58;msgbox(1))",        # entity-encoded colon, in a link
])
def test_scheme_entity_bypass_in_links_defanged(raw):
    """Finding #5: the dangerous-scheme colon may be entity/whitespace encoded — an HTML sink decodes it.
    Inside a link target the scheme must still be neutralized."""
    clean, _ = N.neutralize_output(raw)
    assert "[:]" in clean and "javascript:" not in clean.lower() and "vbscript:" not in clean.lower()


@pytest.mark.parametrize("word", ["the database is fine", "metadata: none", "profile info"])
def test_scheme_name_inside_a_word_not_mangled(word):
    """The scheme match requires a colon terminator, so 'database' (data+base) is untouched."""
    assert N.neutralize_output(word)[0] == word


@pytest.mark.parametrize("prose", ["see report.md", "attached logo.png", "shipped v1.2.3", "notes.txt saved"])
def test_bare_filenames_in_prose_not_mangled(prose):
    """DO NO HARM: a dotted filename / version typed in PROSE (not a link target) is left alone."""
    assert N.neutralize_output(prose)[0] == prose


@pytest.mark.parametrize("link,present", [
    ("[r](report.md)", "report[.]md"), ("![l](logo.png)", "logo[.]png"),
    ("[p](page.html)", "page[.]html"), ("[a](notes.txt)", "notes[.]txt"),
])
def test_relative_markdown_links_are_defanged(link, present):
    """Accepted compromise (a10 re-scope): a deterministic pass can't tell a legit relative link from a
    disguised phishing target, so EVERY markdown-link target is defanged -- including benign ones."""
    assert present in N.neutralize_output(link)[0]


def test_schemeless_host_with_path_is_defanged():
    """A scheme-less target WITH a path is an auto-linkable host — defang it."""
    clean, _ = N.neutralize_output("[c2](evil-c2.example/path)")
    assert "evil-c2.example/path" not in clean and "evil-c2[.]example" in clean


@pytest.mark.parametrize("benign", ["| --- | --- |", "---", ":---:", "latency\t-5 ms",
                                    "-3 dB drop", "| Time | Event | Source |"])
def test_markdown_separators_and_measurements_not_quoted(benign):
    """Finding #8: markdown separators and negative measurements are inert — the delimiter-split must not
    quote them as formulas."""
    assert N.neutralize_output(benign)[0] == benign


@pytest.mark.parametrize("dde", ["-2+3+cmd|'x'!A0", "host\t+cmd|'/C calc'!A0"])
def test_dde_with_pipe_still_caught(dde):
    """The tab-only field split keeps a DDE's own `|`, so a numeric- or +/-lead DDE is still neutralized."""
    clean, _ = N.neutralize_output(dde)
    assert "'=" in clean or "'+" in clean or "'-" in clean


@pytest.mark.parametrize("prose", [
    "@channel please review this",      # @-mention at line start
    "=baseline drift observed",         # =word prose
    "-verbose logging was enabled",     # -word prose
    "+notes attached to the case",      # +word prose
    "=1+1 evaluates to two",            # arithmetic, no function/DDE syntax
])
def test_formula_lead_prose_not_quoted(prose):
    """Harm reduction: a cell that merely OPENS with =/@/+/- but carries no function/DDE syntax (( | !)
    is inert prose -- it must NOT be quote-prefixed."""
    assert N.neutralize_output(prose)[0] == prose
