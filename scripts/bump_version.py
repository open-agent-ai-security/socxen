#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Bump socxen's version everywhere it lives, in one shot.

Version lives in four coupled places; the invariant tests + CI fail if they drift, so bumping by hand
is error-prone. This edits all of them and regenerates the AI BOM:

  - `.claude-plugin/plugin.json`               → `version`
  - `.claude-plugin/marketplace.json`          → the *plugin entry* version (NOT `metadata.version`)
  - `README.md`                                → the `version-vX.Y.Z` pill
  - `security/aibom.cdx.json` / `aibom.html`   → regenerated (stamps the new version)

Then it verifies all agree — the same consistency `tests/test_repo_invariants.py` enforces — so CI
stays green. It does NOT commit; review the diff and open a PR yourself.

Usage:
    uv run scripts/bump_version.py 0.6.0
    uv run scripts/bump_version.py 0.6.0 --dry-run
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / ".claude-plugin/plugin.json"
MARKET = ROOT / ".claude-plugin/marketplace.json"
README = ROOT / "README.md"
GEN_AIBOM = ROOT / "security/gen_aibom.py"

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def fail(msg):
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _sub_once(text, pattern, repl, what):
    new, n = re.subn(pattern, repl, text, count=1)
    if n != 1:
        fail(f"{what}: expected exactly 1 match, found {n} — file layout may have changed")
    return new


def main(argv):
    positional = [a for a in argv if not a.startswith("-")]
    dry = "--dry-run" in argv or "-n" in argv
    if len(positional) != 1 or not SEMVER.match(positional[0]):
        fail("usage: bump_version.py X.Y.Z[-prerelease] [--dry-run]")
    new = positional[0]
    old = json.loads(PLUGIN.read_text())["version"]
    if old == new:
        fail(f"version is already {new}")
    print(f"bump {old} -> {new}" + ("  (dry run — no files written)" if dry else ""))

    edits = [
        (PLUGIN, _sub_once(PLUGIN.read_text(),
                           r'("version"\s*:\s*")' + re.escape(old) + r'(")',
                           r"\g<1>" + new + r"\g<2>", "plugin.json version")),
        # the FIRST "version" after "plugins" is the plugin entry; metadata.version (before it) is left alone
        (MARKET, _sub_once(MARKET.read_text(),
                           r'("plugins"[\s\S]*?"version"\s*:\s*")' + re.escape(old) + r'(")',
                           r"\g<1>" + new + r"\g<2>", "marketplace plugin-entry version")),
        (README, _sub_once(README.read_text(),
                           r"(badge/version-v)" + re.escape(old) + r"(-)",
                           r"\g<1>" + new + r"\g<2>", "README version pill")),
    ]

    if dry:
        for path, _ in edits:
            print(f"  would edit {path.relative_to(ROOT)}")
        print("  would regenerate security/aibom.cdx.json + security/aibom.html")
        return 0

    for path, content in edits:
        path.write_text(content)
        print(f"  edited {path.relative_to(ROOT)}")

    if GEN_AIBOM.exists():
        subprocess.run([sys.executable, str(GEN_AIBOM)], check=True, cwd=str(ROOT))
    else:
        print("  note: security/gen_aibom.py not present — skipped AI BOM regen", file=sys.stderr)

    # verify consistency (what the invariant tests enforce), and that metadata.version was NOT touched
    market = json.loads(MARKET.read_text())
    got = {
        "plugin.json": json.loads(PLUGIN.read_text())["version"],
        "marketplace plugin entry": market["plugins"][0]["version"],
        "README pill": (re.search(r"badge/version-v([0-9][0-9A-Za-z.\-]*)-", README.read_text()) or [None, None])[1],
    }
    mismatch = {k: v for k, v in got.items() if v != new}
    if mismatch:
        fail(f"post-bump mismatch (expected {new}): {mismatch}")
    print(f"\n✓ plugin.json / marketplace entry / README pill all at {new} "
          f"(marketplace metadata.version left at {market['metadata']['version']})")
    print("  AI BOM regenerated.")
    print("\nnext: review the diff, commit the bump + regenerated BOM, and open a PR to dev.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
