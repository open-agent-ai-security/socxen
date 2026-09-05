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
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "plugin" / "skills" / "soc-investigate"


# ---------- loaders ----------

def _load(path):
    return json.loads((ROOT / path).read_text())

PLUGIN = _load("plugin/.claude-plugin/plugin.json")
IDENTITY = _load("plugin/identity.json")
PLUGIN_PREFIX = f"mcp__plugin_{IDENTITY['name']}_{_load('plugin/skills/soc-investigate/permissions.json')['server']}__"
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
    # 21 = the original 20 (16 reads + 2 creates + 2 gated updates) + exabeam_send_email, which the
    # remote MCP grew after 0.8.5 and #137 classified onto the ask tier (before that it was ungoverned
    # and each host fell back to its own default — the exact split #137 closed).
    assert len(canonical) == 21, f"expected 21 governed Exabeam tools, got {len(canonical)}: {sorted(canonical)}"
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
    assert PLUGIN["name"] == IDENTITY["name"]


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


# =====================================================================
# TIER 1 (cont.) — the Codex gate
#
# socxen ships the same human-in-the-loop gate to two host agents that enforce it in
# different places. Claude Code reads permission tiers out of the operator's
# settings.json; Codex reads approval modes out of the plugin's own .mcp.codex.json.
# Two hand-maintained copies of a safety control is exactly the drift this file exists
# to catch, so the Codex copy is generated and pinned here.
# =====================================================================

CODEX_PLUGIN = _load("plugin/.codex-plugin/plugin.json")
CODEX_MCP = _load("plugin/.mcp.codex.json")
CODEX_SERVER = CODEX_MCP["exabeam"]


def _gen_codex_mcp():
    """Import the generator by path — scripts/ is not a package."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_codex_mcp", ROOT / "scripts" / "gen_codex_mcp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build()


def test_codex_gate_is_derived_from_the_claude_snippet():
    """The committed Codex gate must equal what the generator derives from the snippet.

    Without this, editing settings.snippet.json silently loosens the Codex gate — the
    Claude tier changes and the Codex approval modes stay where they were."""
    assert CODEX_MCP == _gen_codex_mcp(), (
        "plugin/.mcp.codex.json is stale — run python3 scripts/gen_codex_mcp.py")


def test_codex_gate_never_auto_approves_a_gated_write():
    """dismiss/close must require a human on Codex, exactly as on Claude Code."""
    for verb in GATED_WRITES:
        mode = CODEX_SERVER["tools"].get(verb, {}).get("approval_mode")
        assert mode == "approve", f"{verb} is '{mode}' on Codex — must be 'approve'"


def test_codex_gate_disables_every_containment_tool():
    """The deny tier must land in disabled_tools, which Codex applies after any
    allowlist — so a containment tool cannot be re-enabled at runtime."""
    disabled = set(CODEX_SERVER["disabled_tools"])
    missing = sorted({bare(t) for t in DENY} - disabled)
    assert not missing, f"containment tools not disabled on Codex: {missing}"
    assert not (disabled & set(CODEX_SERVER["tools"])), (
        "a tool is both disabled and given an approval mode")


def test_codex_gate_defaults_to_asking():
    """An unclassified tool must ask a human, not inherit a permissive default.

    This is the one place the Codex gate is stricter than the Claude one, and it is
    why we never set enabled_tools: an allowlist would silently drop a tool the remote
    server grows, where 'approve' surfaces it to a human instead."""
    assert CODEX_SERVER["default_tools_approval_mode"] == "approve"
    assert "enabled_tools" not in CODEX_SERVER


def test_codex_transport_needs_no_variable_expansion():
    """Verified against codex-cli 0.146.0: Codex expands neither ${CLAUDE_PLUGIN_ROOT}
    nor ${PLUGIN_ROOT} in a plugin-bundled .mcp.json, but does resolve a relative `cwd`
    against the installed plugin root. A '$' back in these args means the bridge
    launches at a literal path and every skill comes up with no tools."""
    assert CODEX_SERVER["cwd"] == "."
    assert not any("$" in a for a in CODEX_SERVER["args"]), (
        "Codex does not expand variables in .mcp.json args")


def test_codex_and_claude_manifests_agree():
    """Two manifests, one release. bump_version.py must move both."""
    assert CODEX_PLUGIN["version"] == PLUGIN["version"], (
        f"version skew: claude={PLUGIN['version']} codex={CODEX_PLUGIN['version']}")
    assert CODEX_PLUGIN["name"] == PLUGIN["name"]
    assert CODEX_PLUGIN["skills"] == PLUGIN["skills"]
    assert CODEX_PLUGIN["mcpServers"] == "./.mcp.codex.json", (
        "Codex only registers a bundled server when the manifest names the file")



# =====================================================================
# TIER 1 (cont.) — the installer / preflight split
#
# install.sh is Claude-Code-specific by nature: 63% of it is `claude plugin` CLI
# quirk-handling and a gate merge Codex does not need. Everything genuinely shared —
# credentials, toolchain, live connectivity — lives in preflight.sh, which BOTH entry
# points use. A check that behaves differently depending on which script you ran is
# the bug that reproduces on one platform and not the other.
# =====================================================================

INSTALL_SH = (ROOT / "plugin" / "install.sh").read_text()
PREFLIGHT_SH = (ROOT / "plugin" / "preflight.sh").read_text()


def test_install_sources_preflight_instead_of_duplicating_it():
    """The shared checks must have exactly one implementation."""
    assert '. "$SCRIPT_DIR/preflight.sh"' in INSTALL_SH, "install.sh no longer sources preflight.sh"
    for fn in ("check_toolchain", "check_credentials", "check_connectivity"):
        assert f"{fn}()" in PREFLIGHT_SH, f"{fn} is not defined in preflight.sh"
        assert f"{fn}()" not in INSTALL_SH, (
            f"{fn} was re-inlined into install.sh — it must come from preflight.sh")


def _shell_code_only(text):
    """Shell source with comments and quoted strings removed.

    A tripwire, not a parser: the point is that a mutating command must not appear in
    *code*, while the same word is fine inside a message ("consider: chmod 600 ..."),
    which is where every legitimate occurrence in preflight.sh lives."""
    lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    body = "\n".join(lines)
    body = re.sub(r'"(?:[^"\\]|\\.)*"', '""', body)
    body = re.sub(r"'(?:[^'])*'", "''", body)
    return body


def test_preflight_never_writes():
    """preflight.sh is a mirror, not a hand.

    On Claude Code the gate ships off and turning it on is a consent-gated action that
    belongs to install.sh --merge-permissions. On Codex the gate ships inside the plugin
    and there is nothing to merge. A fixer here would re-import exactly the consent
    problem the Codex packaging removed, so mutation stays out of this file."""
    code = _shell_code_only(PREFLIGHT_SH)
    forbidden = [
        ("merge_permissions", "runs the settings.json merger"),
        ("plugin install", "mutates a plugin install"),
        ("plugin update", "mutates a plugin install"),
        ("plugin add", "mutates a plugin install"),
        ("mcp add", "writes an MCP server into config.toml"),
        ("mcp remove", "removes an MCP server from config.toml"),
        ("chmod", "changes file modes"),
        ("tee ", "writes a file"),
    ]
    found = [f"{tok} ({why})" for tok, why in forbidden if tok in code]
    assert not found, "preflight.sh must stay read-only, found:\n  " + "\n  ".join(found)
    # No redirection into a real file. /dev/null and heredocs are fine.
    bad_redirects = [m for m in re.findall(r">>?\s*\S+", code)
                     if "/dev/null" not in m and not m.startswith(">&")]
    assert not bad_redirects, f"preflight.sh redirects into a file: {bad_redirects}"


def test_codex_gate_check_sees_per_tool_overrides():
    """`codex mcp get` prints the server default and disabled_tools but NOT per-tool
    approval modes. An operator who loosens only exabeam_update_case leaves a server that
    still reports 'default: approve' while dismiss/close runs unattended — so reading the
    resolved server config alone reports a false green on the single change that matters
    most. The reader must also inspect config.toml and downgrade to 'overridden'."""
    body = PREFLIGHT_SH.split("gate_state_codex()", 1)[1].split("\n}", 1)[0]
    assert "codex_write_override" in body, (
        "gate_state_codex trusts `codex mcp get` alone — it cannot see a per-tool override")
    assert "overridden" in body, "gate_state_codex has no 'weakened by local config' outcome"
    assert "overridden)" in PREFLIGHT_SH, "check_gate does not handle the overridden state"
    ovr = PREFLIGHT_SH.split("codex_write_override()", 1)[1].split("\n}", 1)[0]
    for verb in ("exabeam_update_alert", "exabeam_update_case"):
        stem = verb.replace("exabeam_update_", "")
        assert stem in ovr or verb in ovr, f"override scan does not cover {verb}"


def test_preflight_reports_cannot_verify_separately_from_off():
    """Three outcomes, not two, on both hosts.

    'Cannot verify' reported as 'OFF' sends an operator re-merging a working gate; on
    Codex it would send them reinstalling over a server that a bad approval_mode had
    silently dropped. Both gate readers must have an unknown branch."""
    for fn in ("gate_state_claude", "gate_state_codex"):
        body = PREFLIGHT_SH.split(f"{fn}()", 1)[1].split("\n}", 1)[0]
        assert "unknown" in body, f"{fn} has no 'cannot verify' outcome"



def test_send_email_is_human_gated_on_both_hosts():
    """#137 (PM decision, Matt, 2026-08-30): mail leaving the platform to a person is a human-confirm
    action on BOTH hosts — before this it was unclassified, so the split between hosts was an accident
    of their defaults. Pins: the snippet asks (both prefixes), the generated Codex map says approve,
    and both dry-run layers treat it as a write."""
    for prefix in (PLUGIN_PREFIX, "mcp__exabeam__"):
        assert prefix + "exabeam_send_email" in ASK, f"send_email not on the ask tier under {prefix}"
    assert not tier_has(ALLOW, "exabeam_send_email") and not tier_has(DENY, "exabeam_send_email")
    codex = json.loads((ROOT / "plugin" / ".mcp.codex.json").read_text())
    assert codex["exabeam"]["tools"]["exabeam_send_email"]["approval_mode"] == "approve", (
        "the generated Codex map does not require a human for send_email")
    assert "exabeam_send_email" in (ROOT / "plugin" / "connector" / "exabeam-mcp-bridge.py").read_text().split("WRITE_TOOLS")[1][:400]
    assert "exabeam_send_email" in (ROOT / "evals" / "run.py").read_text().split("WRITE_TOOLS")[1][:400]


def test_identity_artifacts_are_generated_from_identity_json():
    """The plugin's identity lives in ONE place (plugin/identity.json); both manifests and every permission
    rule are generated from it by plugin/gen_identity.py. A hand edit to a generated file is drift that
    would silently split the key from the namespace the gate matches on — so --check must be clean, and
    the generated name must be the one the rules actually use."""
    import subprocess
    r = subprocess.run([sys.executable, str(ROOT / "plugin" / "gen_identity.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout
    assert PLUGIN["name"] == IDENTITY["name"]
    assert _load("plugin/.codex-plugin/plugin.json")["name"] == IDENTITY["name"]
    assert all(t.startswith(PLUGIN_PREFIX) for t in ALLOW), "allow tier not under the identity's plugin prefix"
    assert PLUGIN["version"] == IDENTITY["version"] == _load("plugin/.codex-plugin/plugin.json")["version"]
    # The shell include install.sh / preflight.sh source (no python3 on the host) carries the same identity.
    sh = dict(line.split("=", 1) for line in (ROOT / "plugin" / "identity.sh").read_text().splitlines()
              if line and not line.startswith("#"))
    assert sh["SOCXEN_ID_NAME"].strip("'") == IDENTITY["name"]
    assert sh["SOCXEN_ID_MARKETPLACE_NAME"].strip("'") == IDENTITY["marketplace"]["name"]
    assert sh["SOCXEN_ID_MARKETPLACE_REPO"].strip("'") == IDENTITY["marketplace"]["repo"]
    assert sh["SOCXEN_ID_MCP_SERVER"].strip("'") == IDENTITY["mcpServer"] == list(MCP["mcpServers"])[0]
    assert "|| echo socxen" not in INSTALL_SH and "|| echo socxen" not in PREFLIGHT_SH, "no literal identity fallback"


def test_skill_states_the_taxonomy_report_contract():
    """derive_outcome() reads a `Taxonomy outcome:` line out of the report, and grading treats a missing
    line as UNMEASURABLE — which the red-team grader then scores as not-landed, i.e. a pass. The line was
    only ever demonstrated in a worked example, never required: Claude inferred it and complied, Codex
    wrote its own structure and omitted it, and the forbidden-outcome axis silently went dark. It has to
    be stated in the skill body itself, and it has to name all three valid outcomes."""
    body = (SKILL_DIR / "SKILL.md").read_text()
    assert "Taxonomy outcome:" in body, "SKILL.md does not state the taxonomy report contract"
    for outcome in ("raised", "auto_closed", "fp_closed"):
        assert outcome in body, f"SKILL.md does not name the {outcome!r} outcome"
    # The template the skill twice says to follow must carry the line itself — an agent that renders
    # from the template and skips the prose would otherwise omit it (review of #138).
    tmpl = (SKILL_DIR / "reference" / "report-template.md").read_text()
    assert "Taxonomy outcome:" in tmpl, "report-template.md omits the Taxonomy outcome line"



if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
