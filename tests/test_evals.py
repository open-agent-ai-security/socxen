# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "jsonschema>=4.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tier 4 — eval fixtures/runs are valid and reference only real, governed tools.

Deterministic, no-inference checks that the eval assets stay well-formed and can't
drift from the governed tool surface (a fixture that names a tool the skill can't
call, or a run with no link to a fixture, is caught here rather than at grade time).

Run:  uv run --with pytest --with jsonschema pytest -q tests/test_evals.py
"""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"
FIXTURE_DIR = ROOT / "skills" / "soc-investigate" / "reference" / "examples"
RUNS_DIR = EVALS / "runs"
SCHEMA = json.loads((EVALS / "schema.json").read_text())
PERMS = json.loads((ROOT / "skills/soc-investigate/settings.snippet.json").read_text())["permissions"]

FIXTURES = sorted(FIXTURE_DIR.glob("*.fixture.json"))


def _governed_tools():
    """The Exabeam tool surface the skill is actually permitted to call = plugin-namespaced
    allow + ask, server-stripped."""
    plug = [t for t in (PERMS["allow"] + PERMS["ask"]) if t.startswith("mcp__plugin_")]
    return {t.split("__")[-1] for t in plug}


def test_at_least_one_fixture_exists():
    assert FIXTURES, "no *.fixture.json found under reference/examples/"


def test_schema_is_itself_valid():
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("fx_path", FIXTURES, ids=lambda p: p.name.replace(".fixture.json", ""))
def test_fixture_validates_against_schema(fx_path):
    fx = json.loads(fx_path.read_text())
    errs = sorted(Draft202012Validator(SCHEMA).iter_errors(fx), key=lambda e: list(e.path))
    assert not errs, f"{fx_path.name}: {errs[0].message} (at {list(errs[0].path)})"


@pytest.mark.parametrize("fx_path", FIXTURES, ids=lambda p: p.name.replace(".fixture.json", ""))
def test_fixture_names_only_governed_tools(fx_path):
    """Tool names in must_not.tools / action.tools must be tools the skill can actually
    call — otherwise the fixture is asserting against a phantom."""
    fx = json.loads(fx_path.read_text())
    gov = _governed_tools()
    exp = fx["expected"]
    named = list(exp.get("must_not", {}).get("tools", [])) \
        + list((exp.get("action") or {}).get("tools", []))
    unknown = sorted(t for t in named if t not in gov)
    assert not unknown, f"{fx_path.name} references non-governed tool(s): {unknown}"


@pytest.mark.parametrize("fx_path", FIXTURES, ids=lambda p: p.name.replace(".fixture.json", ""))
def test_fixture_forbids_the_close_tools(fx_path):
    """Sanity on the safety contract itself: every fixture's must_not must forbid the
    dismiss/close writes (a fixture that permits them isn't testing the gate)."""
    fx = json.loads(fx_path.read_text())
    forbidden = {t.split("__")[-1] for t in fx["expected"].get("must_not", {}).get("tools", [])}
    for close_tool in ("exabeam_update_alert", "exabeam_update_case"):
        assert close_tool in forbidden, f"{fx_path.name} must_not.tools should forbid {close_tool}"


def test_recorded_runs_parse_and_link_to_a_fixture():
    fixture_ids = {json.loads(p.read_text())["id"] for p in FIXTURES}
    runs = sorted(RUNS_DIR.glob("*.json"))
    assert runs, "no recorded runs under evals/runs/"
    for r in runs:
        run = json.loads(r.read_text())
        assert run.get("fixture") in fixture_ids, \
            f"{r.name}: fixture {run.get('fixture')!r} not among {sorted(fixture_ids)}"
        for key in ("toolCalls", "report"):
            assert key in run, f"{r.name}: recorded run missing {key!r}"
