# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8.0", "mcp>=1.0,<2", "httpx>=0.27,<1", "certifi", "observra>=1.1,<2"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""#153 #154 #155 — the bridge's upstream transport, against a LOCAL mock streamable-HTTP proxy.

No network beyond 127.0.0.1. The mock speaks just enough of the MCP streamable-HTTP protocol for the real
client (mcp 1.x) to initialize, list tools and call one, and it can be told to fail a step in the ways the
2026-09-06 incident produced: a 5xx on initialize, a 5xx / 404 / isError on tools/call. Every test asserts
the request log, so "one session per process", "a write is sent exactly once" and "a read is retried" are
counted, not assumed. Skipped only when the real client stack is not importable (it is in CI)."""
import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

os.environ["SOCXEN_OBSERVRA"] = "off"          # never let a test write to the operator's real audit log

mcp_client = pytest.importorskip("mcp.client.streamable_http")
if not hasattr(mcp_client, "streamablehttp_client"):
    pytest.skip("mcp 1.x client required", allow_module_level=True)
pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parent.parent
CONNECTOR = ROOT / "plugin" / "connector"
sys.path.insert(0, str(CONNECTOR))
_spec = importlib.util.spec_from_file_location("bridge_transport_under_test", CONNECTOR / "exabeam-mcp-bridge.py")
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

from mcp.types import LATEST_PROTOCOL_VERSION  # noqa: E402


class MockProxy:
    """A scriptable streamable-HTTP MCP proxy on 127.0.0.1. `init_fail` = how many initialize requests to
    answer 500 before succeeding; `call_script` = the answers to successive tools/call requests
    ("ok" | 500 | 503 | 404 | "iserror"), the last one repeating."""

    def __init__(self, init_fail=0, call_script=("ok",)):
        self.init_fail = init_fail
        self.call_script = list(call_script)
        self.log = []                      # (http method, jsonrpc method, status)
        self.sessions = 0
        self.tokens = 0
        self.server = None
        self.url = None

    def _resp(self, status, body=None, headers=None):
        b = b"" if body is None else json.dumps(body).encode()
        h = [f"HTTP/1.1 {status} X", f"Content-Length: {len(b)}", "Connection: keep-alive"]
        if b:
            h.append("Content-Type: application/json")
        for k, v in (headers or {}).items():
            h.append(f"{k}: {v}")
        return ("\r\n".join(h) + "\r\n\r\n").encode() + b

    async def handle(self, reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                hdrs = {k.lower(): v for k, v in (l.split(": ", 1) for l in lines[1:] if ": " in l)}
                body = await reader.readexactly(int(hdrs["content-length"])) if "content-length" in hdrs else b""
                msg = json.loads(body) if body else {}
                jm = msg.get("method", "")
                if path.startswith("/auth/"):
                    self.tokens += 1
                    out = self._resp(200, {"access_token": f"tok{self.tokens}", "expires_in": 3600})
                    self.log.append((method, "token", 200))
                elif method == "DELETE":
                    out = self._resp(200); self.log.append(("DELETE", "", 200))
                elif method == "GET":
                    out = self._resp(405); self.log.append(("GET", "", 405))
                elif jm == "initialize":
                    if self.init_fail > 0:
                        self.init_fail -= 1
                        out = self._resp(500, {"error": "permission lookup failed"})
                    else:
                        self.sessions += 1
                        out = self._resp(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {
                            "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {"tools": {}},
                            "serverInfo": {"name": "mock", "version": "0"}}}, {"Mcp-Session-Id": f"s{self.sessions}"})
                    self.log.append(("POST", jm, int(out[9:12])))
                elif jm.startswith("notifications/"):
                    out = self._resp(202); self.log.append(("POST", jm, 202))
                elif jm == "tools/list":
                    out = self._resp(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
                        {"name": "exabeam_search_alerts", "description": "x", "inputSchema": {"type": "object"}},
                        {"name": "exabeam_create_case_notes", "description": "x", "inputSchema": {"type": "object"}}]}})
                    self.log.append(("POST", jm, 200))
                elif jm == "tools/call":
                    step = self.call_script[0] if len(self.call_script) == 1 else self.call_script.pop(0)
                    if step == "ok":
                        out = self._resp(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {
                            "content": [{"type": "text", "text": "ok"}], "isError": False}})
                    elif step == "iserror":
                        out = self._resp(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {
                            "content": [{"type": "text", "text": "Upstream search failed: 502 from data-lake"}], "isError": True}})
                    else:
                        out = self._resp(int(step), {"error": "boom"})
                    self.log.append(("POST", jm, int(out[9:12])))
                else:
                    out = self._resp(400); self.log.append((method, jm, 400))
                writer.write(out); await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/mcp"

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    def count(self, jm):
        return sum(1 for m, j, s in self.log if j == jm)


class Telemetry:
    def __init__(self):
        self.events = []

    def install(self, monkeypatch):
        monkeypatch.setattr(B.telemetry, "enabled", lambda: True)
        monkeypatch.setattr(B.telemetry, "_emit", lambda event_type, **data: self.events.append((event_type, data)))
        return self

    def errors(self):
        return [d for t, d in self.events if t == "tool_error"]


def fresh(monkeypatch, proxy):
    """Point the module at the mock and reset every piece of per-process state."""
    monkeypatch.setattr(B, "URL", proxy.url)
    monkeypatch.setattr(B, "KEY", "k"); monkeypatch.setattr(B, "SECRET", "s")
    monkeypatch.setattr(B, "_token", {"value": None, "exp": 0.0})
    monkeypatch.setattr(B, "_token_lock", None)
    monkeypatch.setattr(B, "UPSTREAM", B._Upstream())
    monkeypatch.setattr(B, "_READ_RETRY_DELAYS", (0.01, 0.02))


def run(coro):
    return asyncio.run(coro)


async def _with_proxy(monkeypatch, **kw):
    """Start the mock INSIDE the test's own event loop (a server started on one loop is dead on another)."""
    proxy = MockProxy(**kw)
    await proxy.start()
    fresh(monkeypatch, proxy)
    return proxy


# ---- #154: one session per process ---------------------------------------------------------------------

def test_many_reads_share_one_upstream_session(monkeypatch):
    proxy = None

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch)
        for _ in range(5):
            out = await B.call_tool("exabeam_search_alerts", {"arg0": {"limit": 1}})
            assert out[0].text == "ok"
        await B.UPSTREAM.drop()
        await proxy.stop()
    run(go())
    assert proxy.count("initialize") == 1, proxy.log
    assert proxy.count("tools/call") == 5
    assert proxy.count("tools/list") <= 1, "the client's schema cache is filled once per session, not per call"
    assert proxy.tokens == 1
    assert proxy.count("") and any(m == "DELETE" for m, j, s in proxy.log), "the one session is terminated at the end"


def test_token_is_minted_once_under_concurrent_first_calls(monkeypatch):
    proxy = None

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch)
        outs = await asyncio.gather(*[B.call_tool("exabeam_search_alerts", {"arg0": {}}) for _ in range(5)])
        assert all(o[0].text == "ok" for o in outs)
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert proxy.tokens == 1, "single-flight: N concurrent first calls mint ONE token"
    assert proxy.count("initialize") == 1


# ---- #155: reads retry, writes never -------------------------------------------------------------------

def test_a_read_is_retried_after_a_transport_failure(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, call_script=[500, "ok"])
        out = await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        assert out[0].text == "ok"
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert proxy.count("tools/call") == 2, proxy.log
    assert not tel.errors(), "a retried-then-successful read is a success"


def test_a_write_is_sent_exactly_once_whatever_the_error(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, call_script=[500, "ok"])
        with pytest.raises(RuntimeError) as ei:
            await B.call_tool("exabeam_create_case_notes", {"arg1": {"caseId": "1", "note": "x"}})
        assert "HTTP 500" in str(ei.value) and "exabeam_create_case_notes" in str(ei.value)
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert proxy.count("tools/call") == 1, "never retried: the write went out once"
    err = tel.errors()[0]
    assert err["stage"] == "remote" and err["http_status"] == 500 and err["error_type_name"] == "HTTPStatusError"
    assert err["is_retryable"] is True and "500" in err["error_message"]


def test_a_lost_session_is_reopened_for_the_next_read(monkeypatch):
    proxy = None

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, call_script=[404, "ok"])
        out = await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        assert out[0].text == "ok"
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert proxy.count("initialize") == 2, "404 = the proxy forgot the session: reconnect, then the read"
    assert proxy.count("tools/call") == 2


def test_the_breaker_opens_after_consecutive_transport_failures(monkeypatch):
    proxy = None
    monkeypatch.setattr(B, "_BREAKER_TRIP", 2)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, call_script=[503])
        for _ in range(2):
            with pytest.raises(RuntimeError):
                await B.call_tool("exabeam_create_case_notes", {"arg1": {"note": "x"}})   # writes: no retry, one failure each
        before = proxy.count("tools/call")
        with pytest.raises(RuntimeError) as ei:
            await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        assert "circuit open" in str(ei.value)
        assert proxy.count("tools/call") == before, "an open breaker never touches the remote"
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())


# ---- #153: the real error reaches the audit record and the agent ------------------------------------------

def test_the_leaf_error_is_recorded_not_the_exception_group(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, init_fail=10)          # initialize keeps failing: the session never open)
        with pytest.raises(RuntimeError) as ei:
            await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        assert "HTTP 500" in str(ei.value) and "TaskGroup" not in str(ei.value)
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    err = tel.errors()[0]
    assert err["error_class"] in ("ExceptionGroup", "HTTPStatusError"), err
    assert err["error_type_name"] == "HTTPStatusError" and err["http_status"] == 500
    assert "500" in err["error_message"] and err["is_retryable"] is True


def test_an_upstream_iserror_result_is_an_error_not_a_success(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, call_script=["iserror"])
        with pytest.raises(RuntimeError) as ei:
            await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        assert "Exabeam tool error" in str(ei.value) and "502 from data-lake" in str(ei.value)
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    err = tel.errors()[0]
    assert err["stage"] == "upstream_tool" and "502 from data-lake" in err["error_message"]
    assert not [d for t, d in tel.events if t == "tool_end"], "never audited as a completed call"


def test_tools_list_retries_at_startup_and_is_cached(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, init_fail=1)
        tools = await B.list_tools()
        assert {t.name for t in tools} == {"exabeam_search_alerts", "exabeam_create_case_notes"}
        n = proxy.count("tools/list")
        await B.list_tools()
        assert proxy.count("tools/list") == n, "cached for the process"
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert proxy.count("initialize") == 2 and not tel.errors()


def test_tools_list_failure_is_audited_and_readable(monkeypatch):
    proxy = None
    tel = Telemetry().install(monkeypatch)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch, init_fail=10)
        with pytest.raises(RuntimeError) as ei:
            await B.list_tools()
        assert "HTTP 500 on tools/list" in str(ei.value)
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert tel.errors() and tel.errors()[0]["http_status"] == 500 and tel.errors()[0]["tool_name"] == "tools/list"


def test_guardrails_still_run_on_every_call(monkeypatch):
    """The transport changed; the guardrails did not. A write's free text is neutralized before it is
    sent, and a read's result is canonicalized after it returns."""
    proxy = None
    seen = {}
    real = B._defang_args

    def spy(obj, notes=None):
        seen["defanged"] = True
        return real(obj, notes)
    monkeypatch.setattr(B, "_defang_args", spy)
    realc = B._canon_content

    def spyc(content, *a, **k):
        seen["canon"] = True
        return realc(content, *a, **k)
    monkeypatch.setattr(B, "_canon_content", spyc)

    async def go():
        nonlocal proxy
        proxy = await _with_proxy(monkeypatch)
        await B.call_tool("exabeam_create_case_notes", {"arg1": {"note": "=HYPERLINK(\"https://evil.example\",\"x\")"}})
        await B.call_tool("exabeam_search_alerts", {"arg0": {}})
        await B.UPSTREAM.drop(); await proxy.stop()
    run(go())
    assert seen == {"defanged": True, "canon": True}
