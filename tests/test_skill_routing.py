# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Skill-selection routing tests (#110).

With multiple skills, routing moved to the description layer — Claude Code picks a skill by
matching the user's ask against frontmatter descriptions. That layer is a routing API with,
until now, no tests. These guard it deterministically (no model, no tenant):

  * no two skills advertise a colliding trigger phrase — the #103 Finding A collision, where
    bare "triage" was owned by BOTH soc-investigate and triage-cases, so an analyst typing
    "triage" got a coin-flip between skills that state different verdict policies;
  * every ask in evals/routing-corpus.json routes to exactly its expected skill.

Routing here is a deterministic *proxy* for the model's selection — a substring match on the
quoted trigger phrases each description advertises — chosen so the corpus grades in CI without
a live model. It cannot prove the model routes identically, but it fails the moment two
descriptions overlap, which is the class of bug this exists to catch.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "plugin" / "skills"
CORPUS = json.loads((ROOT / "evals" / "routing-corpus.json").read_text())


def _description(skill_md: Path) -> str:
    """The frontmatter `description:` block, joined to one line."""
    fm = re.search(r"^---\n(.*?)\n---", skill_md.read_text(), re.S)
    block = fm.group(1) if fm else ""
    d = re.search(r"description:\s*>-\n(.*?)\Z", block, re.S)
    return " ".join(line.strip() for line in (d.group(1) if d else "").splitlines())


def _trigger_phrases(desc: str) -> set[str]:
    """The quoted phrases a description advertises — its routing triggers."""
    return {p.strip().lower() for p in re.findall(r'"([^"]+)"', desc) if p.strip()}


def _skills() -> dict[str, set[str]]:
    return {d.name: _trigger_phrases(_description(d / "SKILL.md"))
            for d in sorted(SKILLS.iterdir()) if (d / "SKILL.md").exists()}


def _route(ask: str, skills: dict[str, set[str]]) -> set[str]:
    a = ask.lower()
    return {name for name, phrases in skills.items() if any(p in a for p in phrases)}


def test_skills_advertise_trigger_phrases():
    """Every skill's description must advertise at least one quoted trigger phrase — that
    is the routing contract this suite grades."""
    for name, phrases in _skills().items():
        assert phrases, f"{name}/SKILL.md description advertises no quoted trigger phrase"


def test_no_trigger_phrase_collides_across_skills():
    """No skill's advertised trigger phrase may be a substring of another skill's — exactly
    the #103 Finding A collision (bare "triage" nested in "triage the queue"), where the ask
    routes to the wrong skill and thus the wrong governance."""
    skills = _skills()
    for a, pa in skills.items():
        for b, pb in skills.items():
            if a >= b:
                continue
            for x in pa:
                for y in pb:
                    assert x not in y and y not in x, (
                        f"trigger-phrase collision: {a} advertises {x!r} and {b} advertises "
                        f"{y!r} — one contains the other; disambiguate the descriptions")


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["ask"])
def test_corpus_routes_to_expected_skill(case):
    skills = _skills()
    assert case["expect"] in skills, f"corpus names unknown skill {case['expect']!r}"
    hit = _route(case["ask"], skills)
    assert hit == {case["expect"]}, (
        f"ask {case['ask']!r} routed to {sorted(hit) or 'nothing'}, "
        f"expected exactly {{{case['expect']}}}")
