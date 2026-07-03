# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0", "httpx>=0.27", "certifi", "regex>=2024.0"]
# ///
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

WRITE_TOOLS = {"exabeam_update_alert", "exabeam_update_case",
               "exabeam_create_case", "exabeam_create_case_notes"}


def _canon_content(content):
    out = []
    for block in content:
        try:
            if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str):
                clean, _ = canonicalize(block.text)
                copy = getattr(block, "model_copy", None)
                block = copy(update={"text": clean}) if callable(copy) else block
        except Exception as e:  # noqa: BLE001 — availability over canonicalization
            sys.stderr.write(f"bridge: canonicalize passthrough after error: {e!r}\n")
        out.append(block)
    return out


def _defang_args(obj):
    try:
        if isinstance(obj, str):
            return neutralize_output(obj)[0]
        if isinstance(obj, dict):
            return {k: _defang_args(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_defang_args(v) for v in obj]
    except Exception as e:  # noqa: BLE001 — availability over neutralization
        sys.stderr.write(f"bridge: neutralize_output passthrough after error: {e!r}\n")
    return obj


@server.list_tools()
async def list_tools():
    return (await remote(lambda s: s.list_tools())).tools


@server.call_tool()
async def call_tool(name, arguments):
    if name in WRITE_TOOLS and arguments:
        arguments = _defang_args(arguments)                                   # output-side (a10)
    content = (await remote(lambda s: s.call_tool(name, arguments or {}))).content
    return _canon_content(content)                                            # input-side (#2)


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    print(f"OK — connected to {URL}; {len(tools)} Exabeam tools available.")


async def _serve():
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
