# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0", "httpx>=0.27", "certifi"]
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

from neutralize import neutralize_content

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


@server.list_tools()
async def list_tools():
    return (await remote(lambda s: s.list_tools())).tools


@server.call_tool()
async def call_tool(name, arguments):
    content = (await remote(lambda s: s.call_tool(name, arguments or {}))).content
    return neutralize_content(content)  # inbound defang of untrusted telemetry (RFE #2); fail-open per block


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
