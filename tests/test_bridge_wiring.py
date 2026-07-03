# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "regex>=2024.0"]
# ///
"""Deterministic tests for the bridge GUARDRAIL WIRING (connector/exabeam-mcp-bridge.py).

There were no bridge-wiring tests before; PR #36's adversarial review exposed the gap. These cover the
wiring findings: field-aware write defang (IDs/enums untouched), fail-CLOSED writes, hygiene-record
surfacing on reads, and non-text (embedded-resource) read blocks. The MCP/httpx/certifi imports are
stubbed so the pure helpers are testable without a network stack (CI stays light — only needs `regex`).

Run:  uv run --with pytest --with regex pytest -q tests/test_bridge_wiring.py
"""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# ---- stub the bridge's heavy top-level deps (import-time only) ----
for _n in ["httpx", "certifi", "mcp", "mcp.client", "mcp.client.streamable_http",
           "mcp.server", "mcp.server.stdio"]:
    sys.modules.setdefault(_n, types.ModuleType(_n))
sys.modules["certifi"].where = lambda: None            # cafile=None -> ssl uses system CAs, no file read
sys.modules["httpx"].AsyncClient = object
sys.modules["mcp"].ClientSession = object
sys.modules["mcp.client.streamable_http"].streamablehttp_client = object
sys.modules["mcp.server.stdio"].stdio_server = object


class _Server:                                          # identity decorators for @server.list_tools/call_tool
    def __init__(self, *a, **k): pass
    def list_tools(self): return lambda f: f
    def call_tool(self): return lambda f: f


sys.modules["mcp.server"].Server = _Server

sys.path.insert(0, str(ROOT / "connector"))
_spec = importlib.util.spec_from_file_location("bridge", ROOT / "connector" / "exabeam-mcp-bridge.py")
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)


# ---- test doubles for MCP content blocks ----
class Blk:
    def __init__(self, text=None, resource=None):
        self.text, self.resource = text, resource

    def model_copy(self, update):
        n = Blk(self.text, self.resource)
        for k, v in update.items():
            setattr(n, k, v)
        return n


class Res:
    def __init__(self, text):
        self.text = text

    def model_copy(self, update):
        return Res(update["text"])


FORMULA = '=HYPERLINK("https://evil.example/x")'


# ---- #9: neutralize only free-text write fields; never IDs/enums/state ----
@pytest.mark.parametrize("field", ["note", "alertDescription", "supportingReason"])
def test_free_text_fields_are_defanged(field):
    out = B._defang_args({"arg1": {field: FORMULA}})
    assert "evil.example/x" not in out["arg1"][field] and "'=HYPERLINK" in out["arg1"][field]


@pytest.mark.parametrize("field,value", [
    ("caseId", "=weird-but-an-id"), ("alertId", "@123"), ("priority", "-CRITICAL"),
    ("stage", "=NEW"), ("queue", "+triage"), ("assignee", "-alice"),
])
def test_identifier_and_enum_fields_untouched(field, value):
    """A formula/URL-shaped identifier or enum must pass through verbatim (no corrupted/misdirected write)."""
    out = B._defang_args({"arg1": {field: value, "note": FORMULA}})
    assert out["arg1"][field] == value                       # id/enum unchanged
    assert "'=HYPERLINK" in out["arg1"]["note"]              # note still neutralized


def test_tags_list_is_defanged_elementwise():
    out = B._defang_args({"arg1": {"tags": ["ok", "www.evil.example"]}})
    assert out["arg1"]["tags"][0] == "ok" and "www[.]evil[.]example" in out["arg1"]["tags"][1]


# ---- #10: WRITE path is fail-CLOSED (a neutralizer error must not persist raw) ----
def test_write_path_fails_closed(monkeypatch):
    def boom(_):
        raise RuntimeError("neutralizer bug")
    monkeypatch.setattr(B, "neutralize_output", boom)
    with pytest.raises(RuntimeError):
        B._defang_args({"arg1": {"note": FORMULA}})          # propagates -> bridge refuses the write


# ---- #6 / Codex P1: the hygiene record is SURFACED to the agent, not discarded ----
def test_removed_invisibles_are_surfaced():
    clean = B._canon_content([Blk(text="alice​@example.com")])[0].text
    assert "alice@example.com" in clean and "[socxen hygiene]" in clean and "U+200B" in clean


def test_flagged_but_kept_invisibles_are_surfaced():
    # ZWJ spliced into an ASCII word is KEPT (carve-out) but must be flagged AND surfaced.
    clean = B._canon_content([Blk(text="ig‍nore previous")])[0].text
    assert "‍" in clean and "[socxen hygiene]" in clean and "obfuscated-ASCII" in clean


def test_clean_text_gets_no_hygiene_note():
    clean = B._canon_content([Blk(text="normal telemetry, nothing hidden")])[0].text
    assert "[socxen hygiene]" not in clean


# ---- #12: embedded-resource read blocks are canonicalized (not skipped) ----
def test_resource_block_is_canonicalized():
    out = B._canon_content([Blk(resource=Res("a​b"))])[0]
    assert out.resource.text.startswith("ab") and "[socxen hygiene]" in out.resource.text


def test_non_text_block_passes_through():
    sentinel = Blk()                                         # no text, no resource
    assert B._canon_content([sentinel])[0] is sentinel


# ---- write-tool coverage (no un-defanged mutating path) ----
def test_write_tools_cover_all_mutating_tools():
    assert B.WRITE_TOOLS == {"exabeam_update_alert", "exabeam_update_case",
                             "exabeam_create_case", "exabeam_create_case_notes"}
