# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "httpx>=0.27", "certifi", "observra>=1.0.6,<2", "typing_extensions"]
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exabeam MCP bridge.

A tiny local (stdio) MCP server that Claude Code launches and talks to, which forwards
every request to the *remote* Exabeam New-Scale MCP — minting and refreshing the OAuth
token automatically so the human never deals with expiring tokens.

Connect once:
    claude mcp add exabeam -- uv run /path/to/exabeam-mcp-bridge.py

Reads creds from ~/.exabeam-mcp.env:
    EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
    EXABEAM_API_KEY=...
    EXABEAM_API_SECRET=...

Run with --check to validate the connection (and warm the dependency cache) without
starting the server.
"""
import asyncio
import os
import re
import ssl
import sys
import time
from urllib.parse import urlparse

import certifi
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

_VERIFY = ssl.create_default_context(cafile=certifi.where())
_token = {"value": None, "exp": 0.0}


def load_env(path="~/.exabeam-mcp.env"):
    cfg = {}
    p = os.path.expanduser(path)
    if not os.path.exists(p):
        return cfg
    for line in open(p):
        s = line.rstrip("\n")
        if not s.strip() or s.lstrip().startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        cfg[k.strip()] = re.sub(r"\s+#.*$", "", v).strip()
    return cfg


CFG = load_env()
URL = CFG.get("EXABEAM_MCP_URL", "")
KEY = CFG.get("EXABEAM_API_KEY", "")
SECRET = CFG.get("EXABEAM_API_SECRET", "")


async def get_token():
    """Mint/refresh the OAuth client-credentials token; cached until ~1 min before expiry."""
    if _token["value"] and time.time() < _token["exp"] - 60:
        return _token["value"]
    p = urlparse(URL)
    async with httpx.AsyncClient(verify=_VERIFY) as c:
        r = await c.post(
            f"{p.scheme}://{p.netloc}/auth/v1/token",
            json={"grant_type": "client_credentials", "client_id": KEY, "client_secret": SECRET},
            headers={"Content-Type": "application/json"},
            timeout=20,
        )
        r.raise_for_status()
        d = r.json()
    _token["value"] = d["access_token"]
    _token["exp"] = time.time() + int(d.get("expires_in", 3600))
    return _token["value"]


async def remote(op):
    """Open a fresh authenticated connection to the remote Exabeam MCP and run op(session)."""
    tok = await get_token()
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {tok}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            return await op(session)


server = Server("exabeam")

# ---- code-layer telemetry handling (RFE #2 / a10) --------------------------------------------------
# The bridge sits in the path of every MCP call, so it's where the two deterministic guardrails live:
#   • INPUT canonicalization on read RESULTS — strip the invisible Unicode smuggling layer before the
#     agent reasons over telemetry (connector/canonicalize.py).
#   • OUTPUT neutralization on WRITE ARGUMENTS — defang active content (formulas/phishing links) in what
#     socxen persists to Exabeam, so an export of that stored artifact can't fire (connector/
#     neutralize_output.py — the a10 fix). Only the write tools; reads are never argument-mutated.
# Both are FAIL-OPEN: a guardrail bug must never break an investigation.
from canonicalize import canonicalize
from neutralize_output import neutralize_output
# On-by-default, fail-open agent audit logging (SOCXEN_OBSERVRA=off to disable). observra is a hard
# dependency BY DESIGN (see the PEP-723 header): an autonomous agent that takes gated actions must keep an
# audit trail, so logging ships on out of the box — which requires the lib to be resolvable at launch.
# This is a requirement, not an optional add-on. The shim itself stays fail-open at runtime, so a
# telemetry fault never affects an investigation.
import observra_logging as telemetry

WRITE_TOOLS = {"exabeam_update_alert", "exabeam_update_case",
               "exabeam_create_case", "exabeam_create_case_notes"}
# Free-text write fields a payload can ride in — the ONLY fields we neutralize. IDs / enums / state
# fields (caseId, alertId, priority, stage, queue, assignee, alertStatus, useCases) are left untouched so
# a formula/URL-shaped identifier can't be silently corrupted into a failed or misdirected write.
_DEFANG_FIELDS = {"note", "alertdescription", "alertname", "supportingreason", "closedreason", "tags"}

# Safe (non-free-text) fields of a gated write to record in the audit log: identifiers, state and
# disposition enums. These are the deterministic decision record — WHAT the agent did, on WHICH object,
# to WHAT disposition. They are explicitly NOT free text (never PII / evidence), so logging them cannot
# leak a planted payload. `assignee` is deliberately excluded (operator identity is captured out of band).
_AUDIT_FIELDS = {"alertid", "caseid", "alertstatus", "casestatus", "stage",
                 "priority", "severity", "queue", "disposition", "usecases"}


def _log_hygiene(hy):
    """Log what canonicalize() stripped OUT-OF-BAND (stderr) — never appended to the read text (that would
    be forgeable, could re-embed invisibles, and corrupts structured payloads). The protection lives in
    `clean` itself: the smuggling code points are stripped from the value."""
    if hy.removed:
        cps = ", ".join(dict.fromkeys(r["cp"] for r in hy.removed))
        sys.stderr.write(f"bridge: hygiene - stripped [{cps}]\n")


def _block_text(block):
    """Text of a content block regardless of shape: TextContent(`.text`) or EmbeddedResource
    (`.resource.text`). Returns (text, kind); (None, None) for a block that carries no text."""
    t = getattr(block, "text", None)
    if isinstance(t, str):
        return t, "text"
    rt = getattr(getattr(block, "resource", None), "text", None)
    if isinstance(rt, str):
        return rt, "resource"
    return None, None


def _rewrite_block(block, kind, clean):
    copy = getattr(block, "model_copy", None)
    if not callable(copy):
        return block
    if kind == "text":
        return copy(update={"text": clean})
    rcopy = getattr(block.resource, "model_copy", None)          # kind == "resource"
    return copy(update={"resource": rcopy(update={"text": clean})}) if callable(rcopy) else block


def _canon_content(content, removed=None):
    """READ-side (#2): strip the invisible smuggling layer from tool results. Confirmed-obfuscation
    invisibles are neutralized IN the value by canonicalize(); the hygiene record is logged out-of-band,
    never appended to the content. Covers text and embedded-resource blocks. FAIL-OPEN — read wins.
    `removed` is an optional accumulator for telemetry (default None — behavior is unchanged)."""
    out = []
    for block in content:
        try:
            text, kind = _block_text(block)
            if text is not None:
                clean, hy = canonicalize(text)
                _log_hygiene(hy)
                if removed is not None and hy.removed:
                    removed.extend(hy.removed)
                block = _rewrite_block(block, kind, clean)
        except Exception as e:  # noqa: BLE001 — availability over canonicalization
            sys.stderr.write(f"bridge: canonicalize passthrough after error: {e!r}\n")
        out.append(block)
    return out


def _defang_value(v, notes=None):
    """Neutralize a free-text value; when `notes` is provided, accumulate the neutralizer's change
    records into it (for telemetry only — the security behavior is identical whether or not it is)."""
    if isinstance(v, str):
        clean, ns = neutralize_output(v)
        if notes is not None:
            notes.extend(ns)
        return clean
    if isinstance(v, list):
        return [_defang_value(x, notes) for x in v]
    if isinstance(v, dict):
        return {k: _defang_value(x, notes) for k, x in v.items()}
    return v


def _defang_args(obj, notes=None):
    """WRITE-side (a10): neutralize active content in FREE-TEXT write fields only, recursing to reach
    nested fields (e.g. `arg1.note`). FAIL-CLOSED — a neutralizer error is NOT swallowed; it propagates
    so the bridge refuses the write rather than persist a raw payload. `notes` is an optional telemetry
    accumulator (default None — byte-identical to the un-instrumented path)."""
    if isinstance(obj, dict):
        return {k: (_defang_value(v, notes) if k.lower() in _DEFANG_FIELDS else _defang_args(v, notes))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_defang_args(v, notes) for v in obj]
    return obj


def _audit_fields(obj, into=None):
    """Collect the SAFE identifier/enum fields of a write (see `_AUDIT_FIELDS`) from anywhere in the
    (possibly nested) arguments — the decision record for the audit log. Scalars and lists of scalars
    only; free text and nested objects are never captured. First occurrence of a key wins."""
    into = {} if into is None else into
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _AUDIT_FIELDS and isinstance(v, (str, int, float, bool)):
                into.setdefault(k, v[:80] if isinstance(v, str) else v)
            elif (k.lower() in _AUDIT_FIELDS and isinstance(v, list)
                  and all(isinstance(x, (str, int, float, bool)) for x in v)):
                # cap list length AND each string item, same 80-char bound as scalars, so a long value
                # smuggled into a list field can't land verbatim in the log (keeps it bounded/metadata-only)
                into.setdefault(k, [x[:80] if isinstance(x, str) else x for x in v[:10]])
            else:
                _audit_fields(v, into)
    elif isinstance(obj, list):
        for v in obj:
            _audit_fields(v, into)
    return into


@server.list_tools()
async def list_tools():
    return (await remote(lambda s: s.list_tools())).tools


@server.call_tool()
async def call_tool(name, arguments):
    t0 = time.perf_counter()
    log_on = telemetry.enabled()                                     # decide once; when off, do zero extra work
    if log_on:
        telemetry.tool_start(name)
    # Accumulators only when logging is on. When off they stay None -> the guardrail helpers take their
    # byte-identical, un-instrumented path (no allocation, no per-value extend).
    defang_notes = [] if log_on else None
    hygiene_removed = [] if log_on else None
    is_write = name in WRITE_TOOLS and bool(arguments)
    try:
        if is_write:
            arguments = _defang_args(arguments, defang_notes)        # output-side (a10) — fail-closed
        content = (await remote(lambda s: s.call_tool(name, arguments or {}))).content
        content = _canon_content(content, hygiene_removed)           # input-side (#2) — fail-open
    except Exception as e:
        if log_on:
            telemetry.tool_error(name, (time.perf_counter() - t0) * 1000, e)
        raise
    # Telemetry tail — FULLY GUARDED. The remote call has already committed; nothing here (not even
    # _audit_fields on pathological arguments) may raise into the return path and discard a successful write.
    try:
        if log_on:
            telemetry.tool_end(name, (time.perf_counter() - t0) * 1000,
                               defang_notes=defang_notes, hygiene_removed=hygiene_removed,
                               action_fields=_audit_fields(arguments) if is_write else None)
    except Exception as e:  # noqa: BLE001 — telemetry must never break a completed call
        sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
    return content


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    print(f"OK — connected to {URL}; {len(tools)} Exabeam tools available.")


async def _serve():
    telemetry.session_start()   # best-effort; a no-op unless SOCXEN_OBSERVRA names a backend
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main():
    if not (URL and KEY and SECRET):
        sys.stderr.write(
            "exabeam-mcp-bridge: missing credentials. Create ~/.exabeam-mcp.env with "
            "EXABEAM_MCP_URL, EXABEAM_API_KEY, EXABEAM_API_SECRET "
            "(see docs/installation.md, section Credentials).\n"
        )
        sys.exit(1)
    asyncio.run(_check() if "--check" in sys.argv else _serve())


if __name__ == "__main__":
    main()
