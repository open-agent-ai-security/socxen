# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
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
SKILL_DIR = ROOT / "skills" / "soc-investigate"
SKILL_NAME = "soc-investigate"


# ---------- loaders ----------

def _load(path):
    return json.loads((ROOT / path).read_text())

MARKETPLACE = _load(".claude-plugin/marketplace.json")
PLUGIN = _load(".claude-plugin/plugin.json")
MCP = _load(".mcp.json")
SETTINGS = _load("skills/soc-investigate/settings.snippet.json")
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
    """Containment lives only in `deny`. It must never appear in allow/ask."""
    containment = _containment_doc_tools()
    for verb in containment:
        assert not tier_has(ALLOW, verb), f"containment tool {verb} must not be in `allow`"
        assert not tier_has(ASK, verb), f"containment tool {verb} must not be in `ask`"


# --- #3: containment deny-list <-> containment-tools.md sync ---

def _containment_doc_tools():
    return set(re.findall(r"^- `([a-z_]+)`", CONTAINMENT_MD, re.M))

def test_deny_list_matches_containment_doc():
    """containment-tools.md says: 'keeping the two in sync is what makes the gate real,'
    and warns that *silent removals* from the deny-list are the failure mode. Enforce it:
    the `deny` tier (server-stripped) must equal the documented containment set exactly."""
    deny_stripped = {bare(t) for t in DENY}
    doc_tools = _containment_doc_tools()
    assert doc_tools, "no containment tools parsed from containment-tools.md"
    missing_from_deny = doc_tools - deny_stripped
    extra_in_deny = deny_stripped - doc_tools
    assert not missing_from_deny, f"documented containment tools absent from `deny`: {missing_from_deny}"
    assert not extra_in_deny, f"`deny` tools not documented in containment-tools.md: {extra_in_deny}"


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


# --- #5: version sync across the two manifests ---

def test_plugin_version_matches_marketplace_entry():
    """plugin.json.version must equal the marketplace's plugin entry version.
    NOTE: marketplace.json ALSO has metadata.version (the catalog's own version) —
    that one is intentionally independent and is not compared here."""
    entry = MARKETPLACE["plugins"][0]
    assert PLUGIN["version"] == entry["version"], (
        f"version drift: plugin.json={PLUGIN['version']} vs "
        f"marketplace plugin entry={entry['version']}")

def test_readme_version_badge_matches_plugin():
    """The README's static version pill must track plugin.json so it can't go stale."""
    readme = (ROOT / "README.md").read_text()
    m = re.search(r"img\.shields\.io/badge/(?:version|release)-v([0-9]+\.[0-9]+\.[0-9]+)-", readme)
    if not m:  # no version pill present — nothing to keep in sync
        pytest.skip("no version badge in README")
    assert m.group(1) == PLUGIN["version"], (
        f"README version badge v{m.group(1)} != plugin.json v{PLUGIN['version']}")


# --- #6: marketplace identity (the name-collision guard) ---

def test_marketplace_identity_prevents_collision():
    """The marketplace `name` is the unique key `claude plugin marketplace add` uses;
    a duplicate name silently REPLACES another marketplace (this overwrote praxen once).
    Lock the identity so that class of bug can't reappear."""
    assert MARKETPLACE["name"] == "socxen"
    entry = MARKETPLACE["plugins"][0]
    assert entry["name"] == "socxen"
    assert entry["source"] == "./"
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
    """SKILL.md and the reference docs point at reference/*.md and settings.snippet.json;
    every such local target must exist on disk (catches 'points to a file that isn't there')."""
    scanned = [SKILL_DIR / "SKILL.md", *(SKILL_DIR / "reference").glob("*.md")]
    missing = []
    for doc in scanned:
        text = doc.read_text()
        for rel in set(re.findall(r"`?(reference/[A-Za-z0-9_./-]+\.md)`?", text)):
            if not (SKILL_DIR / rel).exists():
                missing.append(f"{doc.name} -> {rel}")
        if "settings.snippet.json" in text and not (SKILL_DIR / "settings.snippet.json").exists():
            missing.append(f"{doc.name} -> settings.snippet.json")
    assert not missing, "dangling references:\n" + "\n".join(sorted(missing))


def test_skill_frontmatter_is_valid():
    """SKILL.md must have YAML frontmatter whose `name` matches the skill directory and
    a non-empty `description` within Claude Code's length cap — else the skill won't register."""
    text = (SKILL_DIR / "SKILL.md").read_text()
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    assert m, "SKILL.md is missing --- frontmatter ---"
    fm = m.group(1)

    name_m = re.search(r"^name:\s*(\S+)\s*$", fm, re.M)
    assert name_m, "frontmatter has no `name:`"
    assert name_m.group(1) == SKILL_NAME, (
        f"frontmatter name {name_m.group(1)!r} != skill dir {SKILL_NAME!r}")

    desc_m = re.search(r"^description:\s*>?-?\s*\n((?:[ \t]+.*\n?)+)", fm, re.M) \
        or re.search(r"^description:\s*(.+)$", fm, re.M)
    assert desc_m, "frontmatter has no `description:`"
    desc = " ".join(line.strip() for line in desc_m.group(1).splitlines()).strip()
    assert desc, "frontmatter description is empty"
    assert len(desc) <= 1024, f"description is {len(desc)} chars (>1024 cap)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
