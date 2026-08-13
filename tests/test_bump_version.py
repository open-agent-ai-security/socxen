# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the release version bumper's edit guard (scripts/bump_version.py).

The bumper rewrites the version in two files that must agree with each other, and a repo invariant
plus CI's AI-BOM drift check fail the build when they don't. The guard that matters here is
`_sub_once`: an edit it can't make *exactly once* must abort the release rather than half-apply.

Run:  uv run --with pytest pytest -q tests/test_bump_version.py
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bump_version", ROOT / "scripts" / "bump_version.py")
BV = importlib.util.module_from_spec(_spec)
sys.modules["bump_version"] = BV
_spec.loader.exec_module(BV)


def test_single_match_is_substituted():
    out = BV._sub_once('"version": "0.6.9"', r'("version"\s*:\s*")0\.6\.9(")',
                       r"\g<1>0.7.0\g<2>", "plugin.json version")
    assert out == '"version": "0.7.0"'


def test_zero_matches_aborts():
    # The file layout moved out from under the pattern — never silently produce an unbumped release.
    with pytest.raises(SystemExit):
        BV._sub_once("nothing to match here", r"(badge/version-v)0\.6\.9(-)",
                     r"\g<1>0.7.0\g<2>", "README version pill")


def test_duplicate_match_aborts(capsys):
    """The #65 regression. `_sub_once` used to pass count=1 to re.subn, which caps the REPORTED
    count at 1 — so the `n != 1` guard could only ever catch zero matches, and a second occurrence
    (a version quoted twice in the README, say) would survive un-edited into a release. With no cap
    the guard sees n=2 and aborts; nothing is written, because every edit is computed before any
    file is touched."""
    text = 'badge/version-v0.6.9-blue ... and again badge/version-v0.6.9-blue'
    with pytest.raises(SystemExit):
        BV._sub_once(text, r"(badge/version-v)0\.6\.9(-)", r"\g<1>0.7.0\g<2>", "README version pill")
    assert "found 2" in capsys.readouterr().err
