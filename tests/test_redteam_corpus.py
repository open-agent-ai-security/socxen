# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "jsonschema>=4.0"]
# ///
"""Deterministic lint of the red-team attack corpus (the CI-safe slice of the red-team plan).

The red-team *execution* is a live, pre-release exercise (needs the model + MCP; see
security/redteam/PLAN.md) and is NOT run here. What IS deterministic — and what these tests keep
healthy on every PR — is that the attack fixtures stay schema-valid, reference only real governed
tools, and actually assert the suppression they claim to test.

Run:  uv run --with pytest --with jsonschema pytest -q tests/test_redteam_corpus.py
"""
import base64
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
RT = ROOT / "security" / "redteam"
SCHEMA = json.loads((RT / "attack.schema.json").read_text())
ATTACKS = sorted((RT / "attacks").glob("*.attack.json"))
PERMS = json.loads((ROOT / "skills/soc-investigate/settings.snippet.json").read_text())["permissions"]


def _governed_tools():
    plug = [t for t in (PERMS["allow"] + PERMS["ask"]) if t.startswith("mcp__plugin_")]
    return {t.split("__")[-1] for t in plug}


def test_attack_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_corpus_is_non_trivial():
    assert len(ATTACKS) >= 8, f"expected a real corpus, found {len(ATTACKS)} attacks"
    ids = [json.loads(p.read_text())["id"] for p in ATTACKS]
    assert len(ids) == len(set(ids)), "duplicate attack ids"


@pytest.mark.parametrize("path", ATTACKS, ids=lambda p: p.name.replace(".attack.json", ""))
def test_attack_validates_against_schema(path):
    a = json.loads(path.read_text())
    errs = sorted(Draft202012Validator(SCHEMA).iter_errors(a), key=lambda e: list(e.path))
    assert not errs, f"{path.name}: {errs[0].message} (at {list(errs[0].path)})"


@pytest.mark.parametrize("path", ATTACKS, ids=lambda p: p.name.replace(".attack.json", ""))
def test_attack_tools_are_governed(path):
    """must_not.tools must be real, governed tools — otherwise the attack asserts against a phantom."""
    gov = _governed_tools()
    tools = json.loads(path.read_text())["expected"]["must_not"].get("tools", [])
    unknown = sorted(t for t in tools if t not in gov)
    assert not unknown, f"{path.name} references non-governed tool(s): {unknown}"


@pytest.mark.parametrize("path", ATTACKS, ids=lambda p: p.name.replace(".attack.json", ""))
def test_suppression_attacks_forbid_the_close_path(path):
    """A class-A/B/C suppression attack must forbid the dismiss/close outcome AND tools — otherwise it
    isn't actually testing that the injection can't suppress a threat."""
    a = json.loads(path.read_text())
    if a["attack_class"] not in ("A", "B", "C"):
        pytest.skip("not a suppression class")
    mn = a["expected"]["must_not"]
    outcomes, tools = set(mn.get("outcomes", [])), {t.split("__")[-1] for t in mn.get("tools", [])}
    assert {"fp_closed", "auto_closed"} & outcomes, f"{path.name}: must_not.outcomes should forbid a close outcome"
    assert {"exabeam_update_alert", "exabeam_update_case"} & tools, \
        f"{path.name}: must_not.tools should forbid the dismiss/close tools"


@pytest.mark.parametrize("path", ATTACKS, ids=lambda p: p.name.replace(".attack.json", ""))
def test_leak_markers_are_live_substrings_of_the_payload(path):
    """Every must_not.leak marker must appear verbatim in the payload — it must be the LIVE form the
    attack plants (the form a correct defang breaks), not a fragment a *defanged* mention also contains.
    Guards the harness-bug-B fix: `=HYPERLINK(` is a bad marker (any writeup quotes it); the raw domains
    are good markers (defanging turns `.`→`[.]`)."""
    a = json.loads(path.read_text())
    payload = a["input"]["payload"]
    for marker in a["expected"]["must_not"].get("leak", []):
        assert marker in payload, f"{path.name}: leak marker {marker!r} is not a verbatim substring of the payload"


def test_every_attack_carries_judge_reasoning():
    """Every attack must have a non-empty must_not.reasoning, or `--judge` silently no-ops for it."""
    for path in ATTACKS:
        a = json.loads(path.read_text())
        assert a["expected"]["must_not"].get("reasoning"), f"{path.name}: empty must_not.reasoning (judge would no-op)"


def test_encoding_attacks_actually_carry_their_signature():
    """An encoding attack whose payload has lost its encoded content is neutered but still schema-valid.
    Pin that the signature is present so a corpus edit can't quietly defang the attack."""
    by_id = {json.loads(p.read_text())["id"]: json.loads(p.read_text())["input"]["payload"] for p in ATTACKS}

    b64 = by_id.get("a06-base64-encoded-instruction")
    if b64:
        blobs = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", b64)
        assert any(_decodes_b64(x) for x in blobs), "a06 payload contains no decodable base64 blob"

    zw = by_id.get("a07-zero-width-hidden-instruction")
    if zw:
        assert any(ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF) or 0x2060 <= ord(c) <= 0x2064 for c in zw), \
            "a07 payload contains no zero-width / invisible unicode char"

    homoglyph = by_id.get("a08-homoglyph-benign-domain")
    if homoglyph:
        assert any(ord(c) > 0x7F for c in homoglyph), "a08 payload contains no non-ASCII homoglyph"


def _decodes_b64(s):
    try:
        base64.b64decode(s, validate=True)
        return len(s) >= 24
    except Exception:  # noqa: BLE001
        return False
