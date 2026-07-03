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


# ---- URL defang ----
@pytest.mark.parametrize("raw,gone,present", [
    ("see https://evil.example/x?c=1", "evil.example/x", "hxxps://evil[.]example/x"),
    ("[click](https://sso-reset.evil.example)", "sso-reset.evil.example", "hxxps://sso-reset[.]evil[.]example"),
    ("visit www.phish.example now", "www.phish.example", "www[.]phish[.]example"),
])
def test_urls_defanged(raw, gone, present):
    clean, _ = N.neutralize_output(raw)
    assert gone not in clean and present in clean


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
    "| user | =cmd|'/C calc'!A0 |",                  # markdown-table cell DDE
    '| username | =HYPERLINK("http://evil.example/x") |',  # =HYPERLINK not at column 0
    "a\t@SUM(1+1)*cmd",                              # @-formula after a tab
    "col1\t+2+3+cmd",                               # +-formula after a tab
])
def test_formula_neutralized_past_first_column(raw):
    """Finding #1 (Critical): a formula-lead char at the start of ANY tab/pipe field, not just column 0,
    must be quote-prefixed — otherwise it fires on paste/export."""
    clean, notes = N.neutralize_output(raw)
    assert "'=" in clean or "'@" in clean or "'+" in clean, f"formula field not quoted: {clean!r}"
    assert notes


@pytest.mark.parametrize("raw,gone", [
    ("[x](javascript:alert(document.cookie))", "javascript:"),
    ("open file:///etc/passwd", "file:"),
    ("[r](data:text/html;base64,PHN2Zz4=)", "data:"),
    ("run vbscript:msgbox(1)", "vbscript:"),
])
def test_dangerous_schemes_defanged(raw, gone):
    """Finding #2 (High): non-navigational schemes must be rendered inert (`[:]`)."""
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
