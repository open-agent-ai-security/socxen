# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "observra", "typing_extensions"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic tests for the structured agent-telemetry shim (plugin/connector/observra_logging.py).

Four things matter and all are tested without a network:
  * DEFAULT ON — logging runs unless explicitly SOCXEN_OBSERVRA=off. A production agent keeps an audit trail.
  * FAIL-OPEN — a missing/misconfigured backend disables logging silently; no recording call ever raises.
    Telemetry must never break an investigation.
  * PRIVACY BY CONSTRUCTION — events carry the gated action's IDs/enums + guardrail COUNTS/CLASSES, never
    the raw free-text note / value / payload the guardrails neutralize.
  * BOUNDED — the jsonl backend rotates, so the audit log never grows without limit.

The real-emit tests importorskip observra; the enable/disable-logic tests run with or without it.

Run:  uv run --with pytest --with observra --with typing_extensions pytest -q tests/test_observra_logging.py
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugin" / "connector"))


def _fresh(monkeypatch, env):
    """Import a pristine copy of the shim under a controlled environment (its on/off decision is cached
    per-module, so each scenario needs its own module instance)."""
    for key in ("SOCXEN_OBSERVRA", "SOCXEN_OBSERVRA_PATH", "SOCXEN_OBSERVRA_MAX_BYTES", "SOCXEN_OBSERVRA_BACKUPS"):
        monkeypatch.delenv(key, raising=False)
    for key, val in env.items():
        monkeypatch.setenv(key, val)
    spec = importlib.util.spec_from_file_location(
        f"obslog_{abs(hash(frozenset(env.items())))}", ROOT / "plugin" / "connector" / "observra_logging.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- default-on / off-switch / fail-open ------------------------------------------------------------

def test_enabled_by_default(monkeypatch, tmp_path):
    # No SOCXEN_OBSERVRA set at all -> logging is ON (jsonl). Assurance is the default posture.
    pytest.importorskip("observra")
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA_PATH": str(tmp_path / "t.jsonl")})
    assert t.enabled() is True


@pytest.mark.parametrize("val", ["off", "0", "false", "none", "disabled"])
def test_explicit_off_disables(monkeypatch, val):
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": val})
    assert t.enabled() is False


def test_unknown_backend_fails_open(monkeypatch):
    # A bad backend name must disable telemetry, not crash the bridge.
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": "definitely-not-a-backend"})
    assert t.enabled() is False


def test_missing_observra_fails_open_even_on_default(monkeypatch):
    # Default-on, but observra not importable (sys.modules[...]=None makes `import observra` raise) ->
    # the shim disables silently rather than propagate. No file is written.
    t = _fresh(monkeypatch, {})
    monkeypatch.setitem(sys.modules, "observra", None)
    assert t.enabled() is False


def test_recording_calls_never_raise_when_disabled(monkeypatch):
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": "off"})
    t.session_start()
    t.tool_start("exabeam_search_alerts")
    t.tool_end("exabeam_update_alert", 12.3, defang_notes=[{"type": "formula"}],
               hygiene_removed=[{"cp": "U+200B"}], action_fields={"alertId": "a-1", "alertStatus": "closed"})
    t.tool_error("exabeam_update_case", 4.0, ValueError("boom"))
    t.session_end()


# ---- real emit + audit record + privacy (needs observra) --------------------------------------------

def _read_events(monkeypatch, tmp_path):
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": "jsonl", "SOCXEN_OBSERVRA_PATH": str(out)})
    assert t.enabled() is True

    t.session_start()
    t.tool_start("exabeam_search_events")
    # a read that carried smuggled invisibles -> input canonicalizer stripped them
    t.tool_end("exabeam_search_events", 1804.2,
               hygiene_removed=[{"cp": "U+200B", "name": "ZERO WIDTH SPACE"},
                                {"cp": "U+200B", "name": "ZERO WIDTH SPACE"},
                                {"cp": "U+202E", "name": "RIGHT-TO-LEFT OVERRIDE"}])
    # the gated suppression: update_alert closing alert 4471 as false-positive, whose note field carried
    # a formula + phishing link the output neutralizer defanged. The DECISION (id + disposition) is logged;
    # the raw note is NOT.
    t.tool_start("exabeam_update_alert")
    t.tool_end("exabeam_update_alert", 143.2,
               defang_notes=[{"type": "formula", "original": '=HYPERLINK("https://evil.example/x")'},
                             {"type": "link", "original": "https://sso-reset.evil.example"}],
               action_fields={"alertId": "4471", "alertStatus": "closed", "disposition": "false_positive"})
    t.tool_error("exabeam_get_mitre_coverage", 7.0, TimeoutError("upstream"))
    t.session_end()

    t._state["observra"]._worker._shutdown()   # drain the background worker to the file
    return out.read_text(), [json.loads(l) for l in out.read_text().splitlines() if l.strip()]


def test_emits_expected_mcp_events(monkeypatch, tmp_path):
    _raw, events = _read_events(monkeypatch, tmp_path)
    by_type = {e["event_type"]: e for e in events}
    for et in ("mcp_session_start", "tool_start", "tool_end", "tool_error", "mcp_session_end"):
        assert et in by_type, f"missing {et}; saw {sorted(by_type)}"
    end = by_type["tool_end"]
    assert end["framework"] == "mcp" and end["skill_name"] == "soc-investigate"


def test_gated_action_decision_is_recorded(monkeypatch, tmp_path):
    # The audit-grade part: the write's IDs + disposition are captured as the decision record.
    _raw, events = _read_events(monkeypatch, tmp_path)
    write = next(e for e in events if e.get("tool_name") == "exabeam_update_alert"
                 and e["event_type"] == "tool_end")
    data = write["data"]
    assert data["action.alertId"] == "4471"
    assert data["action.alertStatus"] == "closed"
    assert data["action.disposition"] == "false_positive"
    # guardrail firing on that same write is recorded too
    assert data["defang_formula"] == 1 and data["defang_link"] == 1


def test_guardrail_metadata_is_counts_and_classes(monkeypatch, tmp_path):
    _raw, events = _read_events(monkeypatch, tmp_path)
    read = next(e for e in events if e.get("tool_name") == "exabeam_search_events"
                and e["event_type"] == "tool_end")["data"]
    assert read["hygiene_stripped"] == 3
    assert read["hygiene_classes"] == "U+200B,U+202E"     # distinct code-point IDs, order-stable


def test_privacy_no_raw_payload_in_log(monkeypatch, tmp_path):
    # THE invariant: the neutralized free-text content never appears -- only metadata + safe IDs/enums.
    raw, _events = _read_events(monkeypatch, tmp_path)
    assert "evil.example" not in raw
    assert "HYPERLINK" not in raw
    assert "sso-reset" not in raw
    assert "4471" in raw                                  # ...but the decision record IS present


def test_jsonl_rotation_is_bounded(monkeypatch, tmp_path):
    # A tiny max_bytes forces rotation; a backup file must appear, proving the log is bounded.
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": "jsonl", "SOCXEN_OBSERVRA_PATH": str(out),
                             "SOCXEN_OBSERVRA_MAX_BYTES": "2048", "SOCXEN_OBSERVRA_BACKUPS": "3"})
    assert t.enabled() is True
    for i in range(200):
        t.tool_end("exabeam_search_events", float(i))
    t._state["observra"]._worker._shutdown()
    rotated = list(tmp_path.glob("telemetry.jsonl.*"))
    assert rotated, "expected at least one rotated backup file under the tiny size cap"
    assert len(rotated) <= 3, f"backup_count not honored: {sorted(p.name for p in rotated)}"


def test_single_emit_failure_does_not_disable_the_whole_trail(monkeypatch, tmp_path):
    """A transient per-event emit fault (queue burst, one bad value) must drop THAT event only — never
    switch off the mandatory audit log for the rest of the session (code-review PR #39, round 2, #1)."""
    pytest.importorskip("observra")
    out = tmp_path / "telemetry.jsonl"
    t = _fresh(monkeypatch, {"SOCXEN_OBSERVRA": "jsonl", "SOCXEN_OBSERVRA_PATH": str(out)})
    assert t.enabled() is True

    real_emit = t._state["emit"]
    calls = {"n": 0}

    def flaky_emit(event_type, **kw):       # raises on the first call, delegates after
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient emit fault")
        real_emit(event_type, **kw)

    t._state["emit"] = flaky_emit
    t.tool_start("exabeam_search_alerts")   # this emit fails...
    assert t.enabled() is True              # ...but logging is NOT disabled
    t.tool_end("exabeam_search_alerts", 5.0)  # a later emit still lands
    t._state["observra"]._worker._shutdown()

    events = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert any(e["event_type"] == "tool_end" for e in events), "later event lost — trail was disabled"
