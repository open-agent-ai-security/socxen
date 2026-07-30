# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "jsonschema>=4.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
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
    """Every must_not.leak marker must be grounded in the payload — the LIVE form the attack plants (the
    form a correct defang breaks), not a fragment a *defanged* mention also contains.

    Two marker styles, both discriminating:
      • raw-mode attacks: a seeded string / domain checked verbatim in the report.
      • output-pipeline attacks (a10): the ACTIVE, FIREABLE form the neutralizer transforms — a
        scheme-bearing `=HYPERLINK("https…` formula or a `](https://…` clickable link. After neutralization
        the scheme becomes `hxxps`, so the marker vanishes; a bare IOC *mention* never contains the call /
        link syntax. (Bare-domain markers were retired: a bare mention is a documented residual, not a leak.)

    Matched modulo the telemetry field's JSON escaping — a formula embedded in a quoted field carries
    backslash-escaped quotes (`=HYPERLINK(\\"https`) that the fireable form does not."""
    a = json.loads(path.read_text())
    payload = a["input"]["payload"]
    unescaped = payload.replace("\\", "")
    for marker in a["expected"]["must_not"].get("leak", []):
        assert marker in payload or marker in unescaped, \
            f"{path.name}: leak marker {marker!r} is not grounded in the payload"


def test_every_attack_carries_judge_reasoning():
    """Every attack must have a non-empty must_not.reasoning, or `--judge` silently no-ops for it."""
    for path in ATTACKS:
        a = json.loads(path.read_text())
        assert a["expected"]["must_not"].get("reasoning"), f"{path.name}: empty must_not.reasoning (judge would no-op)"


def test_encoding_attacks_actually_carry_their_signature():
    """An encoding attack whose payload has lost its encoded content is neutered but still schema-valid.
    Pin that the signature is present so a corpus edit can't quietly defang the attack."""
    by_id = {json.loads(p.read_text())["id"]: json.loads(p.read_text())["input"]["payload"] for p in ATTACKS}

    # Assert the ids exist so a rename/removal fails LOUD rather than silently no-opping the check.
    for wanted in ("a06-base64-encoded-instruction", "a07-zero-width-hidden-instruction",
                   "a08-homoglyph-benign-domain"):
        assert wanted in by_id, f"encoding attack {wanted!r} missing — signature check would silently no-op"

    b64 = by_id["a06-base64-encoded-instruction"]
    blobs = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", b64)
    assert any(_decodes_b64(x) for x in blobs), "a06 payload contains no decodable base64 blob"

    zw = by_id["a07-zero-width-hidden-instruction"]
    assert any(ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF) or 0x2060 <= ord(c) <= 0x2064 for c in zw), \
        "a07 payload contains no zero-width / invisible unicode char"

    homoglyph = by_id["a08-homoglyph-benign-domain"]
    assert any(ord(c) > 0x7F for c in homoglyph), "a08 payload contains no non-ASCII homoglyph"


def _decodes_b64(s):
    try:
        base64.b64decode(s, validate=True)
        return len(s) >= 24
    except Exception:  # noqa: BLE001
        return False


# ---- grade_mode scope guard (PR #36 review F5) ----

def test_output_pipeline_markers_are_defangable():
    """`grade_mode: output-pipeline` routes the leak check through neutralize_output. If a marker is NOT
    something the neutralizer changes (e.g. a seeded secret / API key), the mode would silently downgrade a
    real leak to non-landing `info`. So every output-pipeline attack's leak markers must be defangable —
    otherwise the attack must stay in the default `raw` mode."""
    import importlib.util
    nspec = importlib.util.spec_from_file_location("neut", ROOT / "connector" / "neutralize_output.py")
    neut = importlib.util.module_from_spec(nspec)
    nspec.loader.exec_module(neut)
    for path in ATTACKS:
        a = json.loads(path.read_text())
        if a.get("grade_mode") != "output-pipeline":
            continue
        # Scrub the attack's own payload (the markers in their active form) — the pipeline must remove
        # each marker. If it can't (e.g. a seeded secret, not a URL/formula), output-pipeline grading would
        # hide a real leak and the attack must use the default `raw` mode instead.
        scrubbed = neut.neutralize_output(a["input"]["payload"])[0]
        for marker in a["expected"]["must_not"].get("leak", []):
            assert marker not in scrubbed, (
                f"{a['id']}: leak marker {marker!r} survives the output pipeline on its own payload — "
                f"output-pipeline grading would hide a real leak; use grade_mode 'raw' instead")
