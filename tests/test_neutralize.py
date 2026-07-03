# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
"""Deterministic tests for the inbound telemetry neutralizer (connector/neutralize.py).

This is the code-layer half of RFE #2 and the durable fix for red-team finding a10 (downstream export /
formula injection). Because neutralize() is a pure function, the confirmed a10 payload becomes a
DETERMINISTIC regression guardrail here — no model, runs in CI — exactly as PLAN.md requires ("confirmed
attacks become permanent regression fixtures"). The live LLM retest (security/redteam) is the
complementary perspective; this file is the one that gates every PR.

Run:  uv run --with pytest pytest -q tests/test_neutralize.py
"""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("neutralize", ROOT / "connector" / "neutralize.py")
N = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(N)

A10 = json.loads((ROOT / "security/redteam/attacks/a10-export-formula-injection.attack.json").read_text())
A10_PAYLOAD = A10["input"]["payload"]
A10_MARKERS = A10["expected"]["must_not"]["leak"]  # the raw domains a correct defang breaks


# ---- the a10 fix: the live leak markers must not survive neutralization ----

def test_a10_leak_markers_are_broken():
    out = N.neutralize(A10_PAYLOAD)
    for marker in A10_MARKERS:
        assert marker not in out, f"a10 leak marker {marker!r} survived neutralization"


def test_a10_domains_are_defanged_not_deleted():
    """Defanged, not dropped — the analyst still sees the IOC, just inert."""
    out = N.neutralize(A10_PAYLOAD)
    assert "evil[.]example" in out and "sso-reset[.]evil[.]example" in out
    assert "hxxps://" in out


def test_a10_formula_is_neutralized():
    """The =HYPERLINK cell must be rendered inert (quote-prefixed) so it can't execute on export."""
    out = N.neutralize(A10_PAYLOAD)
    assert "\"'=HYPERLINK" in out, "the quoted =HYPERLINK field was not prefixed"
    assert '"=HYPERLINK' not in out, "a live (unprefixed) =HYPERLINK field survived"


# ---- URL / email defanging ----

@pytest.mark.parametrize("raw,expected_absent,expected_present", [
    ("visit https://evil.example/x?c=1", "evil.example/x", "hxxps://evil[.]example/x"),
    ("link http://a.b.co/p", "a.b.co/p", "hxxp://a[.]b[.]co/p"),
    ("mail to attacker@evil.example now", "attacker@evil.example", "attacker[@]evil[.]example"),
    ("go to www.evil.example please", "www.evil.example", "www[.]evil[.]example"),
])
def test_urls_and_emails_defanged(raw, expected_absent, expected_present):
    out = N.neutralize(raw)
    assert expected_absent not in out
    assert expected_present in out


# ---- formula neutralization at line start ----

@pytest.mark.parametrize("cell", ["=1+1", "=cmd|' /c calc'!A0", "@SUM(1)", "-2+3+cmd|' /c calc'", "+HYPERLINK(x)"])
def test_formula_leads_are_prefixed(cell):
    out = N.neutralize(cell)
    assert out.startswith("'"), f"formula-active cell {cell!r} was not prefixed: {out!r}"


# ---- FALSE-POSITIVE GUARDS: benign data must pass through untouched ----
# These are the safety tests. The neutralizer sits in the path of EVERY tool call, so over-neutralizing
# would silently corrupt legitimate telemetry the analyst depends on.

@pytest.mark.parametrize("benign", [
    "finance user p.mensah signed in",            # dotted username != URL
    "see config.json and app.py for details",     # filenames
    "risk delta was -5 this window",              # negative number
    "adjustments: +1.5 and -1,200 recorded",      # signed numbers
    "source host 10.0.0.4 reached 172.16.0.9",    # bare IPs (no scheme)
    "query: SELECT * FROM t WHERE score=-3",       # inline = mid-string, not a cell lead
    "the alert title says LOW / benign",          # plain prose
    "",                                            # empty
])
def test_benign_input_is_unchanged(benign):
    assert N.neutralize(benign) == benign, "false positive: benign telemetry was mangled"


# ---- structural / robustness ----

def test_idempotent_on_already_defanged():
    once = N.neutralize(A10_PAYLOAD)
    assert N.neutralize(once) == once, "neutralize is not idempotent (double-mangles defanged text)"


def test_neutralize_content_preserves_non_text_and_fails_open():
    class Text:
        type = "text"
        def __init__(self, t): self.text = t
        def model_copy(self, update): n = Text(update["text"]); return n

    class Image:
        type = "image"

    class Boom:
        type = "text"
        @property
        def text(self): raise RuntimeError("boom")

    img = Image()
    out = N.neutralize_content([Text("go https://evil.example/x"), img, Boom()])
    assert len(out) == 3
    assert "evil.example/x" not in out[0].text     # text block neutralized
    assert out[1] is img                            # non-text passed through by identity
    # Boom block raised inside neutralize_content but was passed through, not fatal
    assert out[2].type == "text"
