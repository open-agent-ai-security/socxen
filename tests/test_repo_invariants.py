# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, no-inference invariant tests for the socxen plugin.

The skill's safety model lives in structured, cross-referenced files — the plugin
manifests, the permissions snippet, the containment list, and the tool-map. Almost
every regression this repo has shipped was a *drift* between two of those files, so
these tests encode the invariants that keep them in sync. No creds, no network, no
LLM — runs in ~1s and is suitable as a CI gate.

Run:  uv run --with pytest pytest -q tests/
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "plugin" / "skills" / "soc-investigate"


# ---------- loaders ----------

def _load(path):
    return json.loads((ROOT / path).read_text())

PLUGIN = _load("plugin/.claude-plugin/plugin.json")
MCP = _load("plugin/.mcp.json")
SETTINGS = _load("plugin/skills/soc-investigate/settings.snippet.json")
PERMS = SETTINGS["permissions"]
ALLOW, ASK, DENY = PERMS["allow"], PERMS["ask"], PERMS["deny"]

CONTAINMENT_MD = (SKILL_DIR / "reference" / "containment-tools.md").read_text()
TOOL_MAP_MD = (SKILL_DIR / "reference" / "tool-map.md").read_text()

WRITE_TOOLS = ["exabeam_create_case", "exabeam_create_case_notes",
               "exabeam_update_alert", "exabeam_update_case"]
GATED_WRITES = ["exabeam_update_alert", "exabeam_update_case"]        # dismiss/close — must be gated
SAFE_WRITES = ["exabeam_create_case", "exabeam_create_case_notes"]   # escalate/document — stay allowed


# ---------- helpers ----------

def bare(tool):
    """Server-stripped tool name: the segment after the last '__'."""
    return tool.split("__")[-1]

def tier_has(tier, verb):
    return any(bare(t) == verb for t in tier)


# =====================================================================
# TIER 1 — invariant tests (each encodes a bug this repo actually shipped)
# =====================================================================

# --- #1: plugin-prefix derivation (the v0.3.1 "bundling broke the gate" bug) ---

def test_plugin_prefix_is_derived_not_drifted():
    """Every plugin-namespaced permission rule must use the prefix DERIVED from
    plugin.json's name + .mcp.json's server key. Bundling the MCP silently changed
    tool identity to mcp__plugin_<plugin>_<server>__* once; the ask/deny rules stopped
    matching and the gate went inert. This fails red if that ever recurs."""
    plugin_name = PLUGIN["name"]                       # "socxen"
    servers = list(MCP["mcpServers"].keys())
    assert len(servers) == 1, f"expected exactly one bundled MCP server, got {servers}"
    server = servers[0]                                # "exabeam"
    expected = f"mcp__plugin_{plugin_name}_{server}__"

    plugin_rules = [t for r in (ALLOW, ASK, DENY) for t in r if t.startswith("mcp__plugin_")]
    assert plugin_rules, "no plugin-namespaced rules found — snippet may be mis-prefixed"
    bad = [t for t in plugin_rules if not t.startswith(expected)]
    assert not bad, f"rules not using derived prefix {expected!r}: {bad}"


# --- #2: governance tier invariants (the safety gate can't silently regress) ---

def test_dismiss_close_are_gated_never_auto_allowed():
    """update_alert / update_case (dismiss + close) are where a wrong AI verdict does
    real harm. They must sit in `ask`, and must never leak into `allow`."""
    for verb in GATED_WRITES:
        assert tier_has(ASK, verb), f"{verb} must be in the `ask` tier (the human gate)"
        assert not tier_has(ALLOW, verb), f"{verb} must NOT be in `allow` — that removes the gate"

def test_safe_writes_stay_allowed():
    """Escalating (create_case) and documenting (create_case_notes) must stay
    frictionless — in `allow`, not accidentally gated."""
    for verb in SAFE_WRITES:
        assert tier_has(ALLOW, verb), f"{verb} should be in `allow` (escalation is always safe)"
        assert not tier_has(ASK, verb), f"{verb} should not be gated behind `ask`"

def test_no_containment_tool_is_allowed_or_asked():
    """Containment lives only in `deny`. It must never appear in allow/ask —
    under either spelling (bare or exabeam_-prefixed)."""
    containment = _containment_doc_tools()
    for name in containment:
        for verb in (name, f"exabeam_{name}"):
            assert not tier_has(ALLOW, verb), f"containment tool {verb} must not be in `allow`"
            assert not tier_has(ASK, verb), f"containment tool {verb} must not be in `ask`"


# --- #109: the safety spine must live in every skill body, not just a shared file ---

def _skill_dirs():
    """Every skill under plugin/skills/ (the #108 glob) — dirs carrying a SKILL.md."""
    base = ROOT / "plugin" / "skills"
    return sorted(d for d in base.iterdir() if (d / "SKILL.md").exists())

# Load-bearing safety markers every SKILL.md body must carry. Distinctive phrases,
# matched case-insensitively and tolerant of the wording around them — the point is
# "this lock exists in this body", not freezing prose. The write-gating marker set is
# a union across tiers (investigate: explicit-human-yes; sweep: no writes across the
# sweep; propose: propose-only) so skills nobody has written yet still have to carry one.
# Known limit (honest): because it is a union, it asserts *some* recognized write-gating
# phrase exists, not that *this skill's tier's* gate does — a future investigate-tier skill
# could satisfy it with propose-only prose while lacking a human-ask gate. Bind the marker
# subset to the tier once skills carry a `tier:` frontmatter key.
SPINE_MARKERS = {
    "untrusted-data principle": ["untrusted data, never instructions"],
    "evidence over assertion": ["evidence over assertion"],
    "write-gating rule for its tier": [
        "ask the analyst", "explicit yes", "explicit human yes",
        "never auto-write", "present-only", "propose-only",
        "no rule-write", "no write path", "gated egress",
    ],
}

def test_every_skill_body_carries_the_safety_spine():
    """Reference files load lazily, so a guardrail that lives only in a shared file is
    one the model may never read — an unloaded guardrail is no guardrail. The safety
    spine is therefore duplicated into every skill body on purpose; the cost of that
    doctrine is drift (#105 shipped because two copies of one governance claim diverged).
    This proves every plugin/skills/*/SKILL.md still carries its locks — the untrusted-
    data principle, evidence-over-assertion, and a write-gating rule for its tier — so
    coherence holds by construction, including for skills not yet written. (#109)"""
    skills = _skill_dirs()
    assert skills, "no skills found under plugin/skills/"
    for d in skills:
        body = (d / "SKILL.md").read_text().lower()
        for marker, phrases in SPINE_MARKERS.items():
            assert any(p.lower() in body for p in phrases), (
                f"{d.name}/SKILL.md is missing the {marker!r} spine marker "
                f"(expected one of: {phrases})")


# --- #3: containment deny-list <-> containment-tools.md sync ---

def _containment_doc_tools():
    return set(re.findall(r"^- `([a-z_]+)`", CONTAINMENT_MD, re.M))

def test_deny_list_matches_containment_doc():
    """containment-tools.md says: 'keeping the two in sync is what makes the gate real,'
    and warns that *silent removals* from the deny-list are the failure mode. Enforce it:
    every documented containment tool must be denied under BOTH spellings — bare and
    exabeam_-prefixed (the convention every real tool follows, see tool-map.md) — in BOTH
    namespaces (bundled plugin and manual `claude mcp add`), and `deny` must contain
    nothing else. Encodes shipped bug #72: bare-only, plugin-namespace-only rules that an
    exabeam_-prefixed containment tool would have sailed past."""
    doc_tools = _containment_doc_tools()
    assert doc_tools, "no containment tools parsed from containment-tools.md"
    server = list(MCP["mcpServers"].keys())[0]
    namespaces = (f"mcp__plugin_{PLUGIN['name']}_{server}__", f"mcp__{server}__")
    expected = {f"{ns}{spelling}{name}"
                for name in doc_tools for ns in namespaces for spelling in ("exabeam_", "")}
    missing = expected - set(DENY)
    extra = set(DENY) - expected
    assert not missing, f"deny rules absent for documented containment tools: {sorted(missing)}"
    assert not extra, f"`deny` rules not derived from containment-tools.md: {sorted(extra)}"


# --- supporting Tier-1 invariants ---

def _canonical_tools():
    """The governed Exabeam tool surface = plugin-namespaced allow + ask, stripped."""
    plug = [t for t in (ALLOW + ASK) if t.startswith("mcp__plugin_")]
    return {bare(t) for t in plug}

def test_governed_tools_are_all_documented_in_tool_map():
    """No governed tool may be undocumented, and no drift between the snippet and the
    tool-map. Every plugin-namespaced allow/ask tool must appear in tool-map.md."""
    canonical = _canonical_tools()
    assert len(canonical) == 20, f"expected 20 governed Exabeam tools, got {len(canonical)}: {sorted(canonical)}"
    undocumented = sorted(t for t in canonical if t not in TOOL_MAP_MD)
    assert not undocumented, f"governed tools missing from tool-map.md: {undocumented}"

def test_write_tools_are_exactly_the_arg1_family():
    """The four write tools named by the tool-map's arg1 convention must be exactly
    the create/update family, split correctly across allow (create) and ask (update)."""
    for verb in SAFE_WRITES:
        assert tier_has(ALLOW, verb)
    for verb in GATED_WRITES:
        assert tier_has(ASK, verb)
    # all four are documented as writes in the tool-map
    for verb in WRITE_TOOLS:
        assert verb in TOOL_MAP_MD, f"{verb} not documented in tool-map.md"


def test_readme_version_badge_matches_plugin():
    """The README's static version pill must track plugin.json so it can't go stale."""
    readme = (ROOT / "plugin" / "README.md").read_text()
    m = re.search(r"img\.shields\.io/badge/(?:version|release)-v([0-9]+\.[0-9]+\.[0-9]+)-", readme)
    if not m:  # no version pill present — nothing to keep in sync
        pytest.skip("no version badge in README")
    assert m.group(1) == PLUGIN["version"], (
        f"README version badge v{m.group(1)} != plugin.json v{PLUGIN['version']}")


# --- #6: marketplace identity (the name-collision guard) ---

def test_no_in_repo_marketplace():
    """socxen is published via the community marketplace
    (open-agent-ai-security/plugins, marketplace name 'open-agent-ai-security');
    the repo-hosted 'socxen' marketplace was retired in a hard cutover (#58).
    Reintroducing a marketplace.json here would either resurrect the dead
    socxen@socxen install path or collide with the community marketplace's
    name (a duplicate name silently REPLACES another marketplace — this
    overwrote praxen once). The plugin manifest itself must stay."""
    assert not (ROOT / "plugin/.claude-plugin/marketplace.json").exists(), (
        "unexpected plugin/.claude-plugin/marketplace.json — socxen installs via "
        "open-agent-ai-security/plugins; see plugin/docs/installation.md")
    assert PLUGIN["name"] == "socxen"


# =====================================================================
# TIER 2 — structural / install-breakers
# =====================================================================

def test_all_json_files_parse():
    """A malformed manifest breaks `claude plugin install`. Every JSON in the repo
    (outside .git) must parse."""
    bad = []
    for p in ROOT.rglob("*.json"):
        if ".git" in p.parts:
            continue
        try:
            json.loads(p.read_text())
        except json.JSONDecodeError as e:
            bad.append(f"{p.relative_to(ROOT)}: {e}")
    assert not bad, "unparseable JSON:\n" + "\n".join(bad)


def test_no_dangling_reference_links():
    """Every `reference/*.md` (and settings.snippet.json) a skill points at must exist.
    Iterates ALL skills (#108) — a `reference/...` mention resolves against the citing
    skill's own dir first, then soc-investigate's `reference/` (SKILL_DIR — the shared
    library the fleet skills cite in prose), so cross-skill references don't false-positive."""
    missing = []
    for d in _skill_dirs():
        own_ref = d / "reference"
        scanned = [d / "SKILL.md", *(own_ref.glob("*.md") if own_ref.is_dir() else [])]
        for doc in scanned:
            text = doc.read_text()
            for rel in set(re.findall(r"`?(reference/[A-Za-z0-9_./-]+\.md)`?", text)):
                if not ((d / rel).exists() or (SKILL_DIR / rel).exists()):
                    missing.append(f"{d.name}/{doc.name} -> {rel}")
            if "settings.snippet.json" in text and not (d / "settings.snippet.json").exists() \
                    and not (SKILL_DIR / "settings.snippet.json").exists():
                missing.append(f"{d.name}/{doc.name} -> settings.snippet.json")
    assert not missing, "dangling references:\n" + "\n".join(sorted(missing))


def test_skill_frontmatter_is_valid():
    """Every plugin/skills/*/SKILL.md must have YAML frontmatter whose `name` matches its
    OWN directory and a non-empty `description` within Claude Code's 1024-char cap — else
    the skill won't register. Iterates all skills (#108), not just soc-investigate: anything
    matching plugin/skills/*/SKILL.md registers with Claude Code, so all of it must be valid."""
    for d in _skill_dirs():
        text = (d / "SKILL.md").read_text()
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
        assert m, f"{d.name}/SKILL.md is missing --- frontmatter ---"
        fm = m.group(1)

        name_m = re.search(r"^name:\s*(\S+)\s*$", fm, re.M)
        assert name_m, f"{d.name}/SKILL.md frontmatter has no `name:`"
        assert name_m.group(1) == d.name, (
            f"{d.name}/SKILL.md frontmatter name {name_m.group(1)!r} != skill dir {d.name!r}")

        desc_m = re.search(r"^description:\s*>?-?\s*\n((?:[ \t]+.*\n?)+)", fm, re.M) \
            or re.search(r"^description:\s*(.+)$", fm, re.M)
        assert desc_m, f"{d.name}/SKILL.md frontmatter has no `description:`"
        desc = " ".join(line.strip() for line in desc_m.group(1).splitlines()).strip()
        assert desc, f"{d.name}/SKILL.md frontmatter description is empty"
        assert len(desc) <= 1024, f"{d.name}/SKILL.md description is {len(desc)} chars (>1024 cap)"


def test_source_files_carry_spdx_headers():
    """Every source/doc file (.py/.sh/.md) must open with the Apache-2.0 copyright + SPDX
    header, so license coverage can't regress as files are added. security/redteam/results/
    and security/praxen/results/ (committed run records, generated) are exempt."""
    SKIP_DIRS = {".git", ".claude", "local", "__pycache__", ".pytest_cache", "node_modules"}
    missing = []
    for pattern in ("*.py", "*.sh", "*.md"):
        for p in ROOT.rglob(pattern):
            rel = p.relative_to(ROOT)
            if SKIP_DIRS & set(rel.parts):
                continue
            if rel.parts[:3] in {("security", "redteam", "results"),
                                 ("security", "praxen", "results")}:
                continue
            head = "\n".join(p.read_text().splitlines()[:15])
            if "SPDX-License-Identifier: Apache-2.0" not in head:
                missing.append(str(rel))
    assert not missing, "files missing the SPDX header:\n" + "\n".join(sorted(missing))


def test_shipped_docs_never_link_outside_the_plugin():
    """Everything under plugin/ is copied into a user's plugin cache, and that cache's root IS
    plugin/ — so a relative link climbing above it (`../../CHANGELOG.md`) resolves fine while you
    browse the repo and dead-ends for every installed user. That is not a typo class: #29 moved
    tests/, evals/, security/ and the root docs out of the distribution ON PURPOSE, so any shipped
    link to them is pointing at something deliberately absent. Link those absolutely, or not at all.

    Caught five such links in plugin/docs/README.md, introduced by mechanically deepening `../` to
    `../../` during the restructure — correct for the repo, dead in the cache."""
    PLUGIN = ROOT / "plugin"
    bad = []
    for doc in PLUGIN.rglob("*.md"):
        if "__pycache__" in doc.parts:
            continue
        for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            t = target.strip().split("#")[0].strip()
            if not t or t.startswith(("http://", "https://", "mailto:", "#")):
                continue
            resolved = (doc.parent / t).resolve()
            rel = doc.relative_to(ROOT)
            if PLUGIN.resolve() not in resolved.parents and resolved != PLUGIN.resolve():
                bad.append(f"{rel} -> {t} (escapes the shipped plugin root)")
            elif not resolved.exists():
                bad.append(f"{rel} -> {t} (target does not exist)")
    assert not bad, "shipped docs link outside the distributed plugin:\n" + "\n".join(sorted(bad))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
