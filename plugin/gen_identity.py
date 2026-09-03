#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate every artifact that carries the plugin's identity from ONE source: plugin/identity.json.

    python3 plugin/gen_identity.py            # (re)write the artifacts
    python3 plugin/gen_identity.py --check    # exit 1 if any committed artifact differs (CI)

Generated:
  .claude-plugin/plugin.json                    Claude Code manifest
  .codex-plugin/plugin.json                     Codex manifest (same skills, Codex-only fields)
  skills/soc-investigate/settings.snippet.json  the permission gate — every rule spelled out under the
                                                bundled-MCP prefix mcp__plugin_<name>_<server>__ and/or the
                                                manual prefix mcp__<server>__, from the bare-name tiers in
                                                skills/soc-investigate/permissions.json

Why: `name` is load-bearing. It is the plugin key, and Claude Code namespaces the skills (`<name>:<skill>`)
and the bundled MCP (`mcp__plugin_<name>_<server>__<tool>`) with it — which is what the permission rules
match on. Before this file, re-keying the plugin meant editing two manifests and 92 rules by hand and
hoping nothing drifted; now it is one field here plus a regenerate, and CI fails on drift. A vendor
catalog that ships this payload under its own name (see the Exabeam marketplace) patches identity.json
and regenerates — nothing else in the payload is touched.

Stdlib only; the payload ships this file, so an installed copy can regenerate itself.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
IDENTITY = HERE / "identity.json"
PERMISSIONS = HERE / "skills" / "soc-investigate" / "permissions.json"
OUT = {
    "claude": HERE / ".claude-plugin" / "plugin.json",
    "codex": HERE / ".codex-plugin" / "plugin.json",
    "snippet": HERE / "skills" / "soc-investigate" / "settings.snippet.json",
}


def load(p):
    d = json.loads(p.read_text())
    d.pop("_comment", None)
    return d


def prefixes(identity, server):
    return {"plugin": f"mcp__plugin_{identity['name']}_{server}__", "manual": f"mcp__{server}__"}


def build(identity, perms):
    common = {k: identity[k] for k in ("name", "version", "description", "author", "homepage", "repository", "license")}
    claude = {**common, "keywords": identity["keywords"] + identity["hostKeywords"]["claude"], "skills": "./skills/"}
    codex = {**common, "keywords": identity["keywords"] + identity["hostKeywords"]["codex"], "skills": "./skills/",
             "mcpServers": "./.mcp.codex.json",
             "interface": {"displayName": identity["displayName"], "shortDescription": identity["shortDescription"],
                           "category": identity["category"]}}
    pre = prefixes(identity, perms["server"])
    tiers = {}
    for tier, spec in perms["tiers"].items():
        tiers[tier] = [pre[p] + t for p in spec["prefixes"] for t in spec["tools"]]
    snippet = {"permissions": tiers}
    return {"claude": claude, "codex": codex, "snippet": snippet}


def render(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    check = "--check" in argv
    identity, perms = load(IDENTITY), load(PERMISSIONS)
    want = {k: render(v) for k, v in build(identity, perms).items()}
    stale = [k for k, text in want.items() if (OUT[k].read_text() if OUT[k].exists() else "") != text]
    if check:
        if stale:
            print("stale (run python3 plugin/gen_identity.py): " + ", ".join(str(OUT[k].relative_to(HERE.parent)) for k in stale),
                  file=sys.stderr)
            return 1
        print(f"identity artifacts in sync with plugin/identity.json (name={identity['name']!r}, "
              f"prefix={prefixes(identity, perms['server'])['plugin']!r})")
        return 0
    for k, text in want.items():
        OUT[k].write_text(text)
    n = sum(len(v) for v in json.loads(want["snippet"])["permissions"].values())
    print(f"wrote {', '.join(str(OUT[k].relative_to(HERE.parent)) for k in OUT)} — name={identity['name']!r}, "
          f"version {identity['version']}, {n} permission rules")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
