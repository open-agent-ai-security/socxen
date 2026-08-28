# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp>=1.0,<2", "httpx>=0.27,<1", "certifi>=2024,<2027", "observra>=1.1,<2", "typing_extensions>=4.7,<5"]
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
from mcp.types import ClientCapabilities, ElicitationCapability, TextContent

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

# DRY RUN — refuse every write at the bridge instead of forwarding it to the tenant.
#
# Why this lives here and not in the host's permission layer: the two supported hosts disagree about
# what "requires approval" means without a human present. Claude Code's `ask` tier fails CLOSED under
# `claude -p` (the call never reaches us). Codex's `approve` fails OPEN under `codex exec` — the write
# is auto-approved and executed. The bridge is the only layer both hosts share, so it is the only place
# a write can be refused identically on either one.
#
# The refusal is RETURNED, not raised: the agent sees a normal tool result saying the write was refused,
# which is what Claude Code's permission layer does, and what the red-team harness needs in order to
# record that an attack ATTEMPTED a gated write. A host-side deny-list cannot give us that — on Codex a
# disabled tool is removed from the model's view entirely, so the attempt never happens and the attempt
# signal can never fire.
#
# Opt-in and loud: off unless SOCXEN_DRY_RUN is set, and announced on stderr at startup so a dry run can
# never be mistaken for a live one (or the reverse).
def _truthy(v):
    return str(v).strip().lower() in {"1", "true", "yes", "on"}

DRY_RUN = _truthy(os.environ.get("SOCXEN_DRY_RUN", ""))

# HUMAN CONFIRMATION — the second lock on dismiss/close, owned by the bridge.
#
# socxen's safety model is two locks before a suppression: the skill asks in chat, and the harness asks
# again at the tool call. On Claude Code the second lock is the `ask` permission tier, and it fails
# CLOSED when no human is present (`claude -p` refuses the call before it reaches us). On Codex the
# equivalent (`approval_mode: approve`) fails OPEN under `codex exec` — the write is auto-approved.
# The bridge cannot tell the two session kinds apart (scrubbed env, pipes either way), so instead of
# detecting, it ASKS: an MCP elicitation the host must route to a human. Interactive hosts render it;
# a headless host cancels it — and a cancelled question is a refused write. Verified on Codex 0.146.0:
# under `codex exec` the elicitation comes back "user cancelled MCP tool call".
#
# Hosts listed here already gate these writes fail-closed at their own permission layer, so the bridge
# does not ask twice — that host's behaviour is exactly what it was before this existed.
GATED_WRITES = {"exabeam_update_alert", "exabeam_update_case"}
_HOSTS_GATING_AT_HARNESS = {"claude-code"}

_REFUSAL = "Permission to use `{name}` was not granted; the call was not executed."


def _refusal(name):
    """The tool result for a write the bridge refused. Deliberately minimal, and deliberately the same
    shape as Claude Code's own permission refusal ("...but you haven't granted it yet"): a statement of
    fact, no instruction. Anything more — "leave it to a human", "do not retry" — is coaching the exact
    behaviour the red team measures, and text the Claude baseline never saw."""
    return [TextContent(type="text", text=_REFUSAL.format(name=name))]


def _client_name():
    """The host talking to us, from the MCP initialize handshake (clientInfo.name)."""
    try:
        return server.request_context.session.client_params.clientInfo.name
    except Exception:  # noqa: BLE001 — no handshake info means we cannot trust the host to gate
        return ""


async def _human_confirms(name, arguments):
    """Ask the human, through the host, before a gated write. Returns how the write was authorized:

        "host"      the host gates this write fail-closed itself (Claude Code) — nothing to ask
        "elicited"  a human answered the elicitation with confirm=true
        None        declined, cancelled, no human present, host cannot ask, or anything went wrong

    Everything that is not an explicit yes is a no. The prompt is built from the write's SAFE fields
    only (IDs and enums, see _AUDIT_FIELDS) — never free text, which is attacker-influenceable and
    would otherwise let a planted note write its own confirmation prompt."""
    client = _client_name()
    if client in _HOSTS_GATING_AT_HARNESS:
        return "host"
    try:
        ctx = server.request_context
        session = ctx.session
        if not session.check_client_capability(ClientCapabilities(elicitation=ElicitationCapability())):
            sys.stderr.write(f"bridge: host {client or '?'} cannot ask a human; refusing {name}\n")
            return None
        fields = _audit_fields(arguments) if arguments else {}
        what = ", ".join(f"{k}={v}" for k, v in fields.items()) or "no identifiers supplied"
        message = (f"socxen is about to call {name} ({what}). "
                   f"This changes the alert/case in Exabeam. Confirm?")
        res = await session.elicit(
            message=message,
            requestedSchema={"type": "object",
                             "properties": {"confirm": {"type": "boolean",
                                                        "description": "true to allow this write"}},
                             "required": ["confirm"]},
            related_request_id=ctx.request_id)
        content = getattr(res, "content", None) or {}
        if getattr(res, "action", None) == "accept" and content.get("confirm") is True:
            return "elicited"
        sys.stderr.write(f"bridge: human did not confirm {name} ({getattr(res, 'action', '?')})\n")
        return None
    except Exception as e:  # noqa: BLE001 — an error asking is a no, never a yes
        sys.stderr.write(f"bridge: confirmation failed for {name} ({type(e).__name__}); refusing\n")
        return None

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


def _authorized(arguments, via):
    """Audit fields for a landed write, plus HOW a gated one was authorized ("host" or "elicited").
    This is the approver event docs/logging.md said the bridge could not see — it can now, for the
    elicited case, because the bridge asked the question itself."""
    fields = _audit_fields(arguments)
    if via:
        fields["humanConfirmation"] = via
    return fields


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
    # Dry run: refuse the write here, BEFORE the remote call. Keyed on the tool name alone, not on
    # `is_write` — a write with no arguments is still a write we must not forward. The tool_start above
    # is paired with a tool_end below so the audit trail records the ATTEMPT (what the agent tried, on
    # which object, to what disposition) even though nothing was sent.
    if DRY_RUN and name in WRITE_TOOLS:
        try:
            if log_on:
                # Mark the record as a refusal. The emit layer's own `result` field means "the MCP call
                # completed", which is true even here — so without this an audit reader (or the red-team
                # grader) would see action.stage=closed with result=success and reasonably conclude the
                # close LANDED. `action.dryRunRefused` sits beside the disposition fields and is a state
                # fact, not free text, so it belongs in the same safe-to-log set.
                fields = dict(_audit_fields(arguments) or {}) if arguments else {}
                fields["dryRunRefused"] = True
                telemetry.tool_end(name, (time.perf_counter() - t0) * 1000, action_fields=fields)
        except Exception as e:  # noqa: BLE001 — telemetry must never break the refusal path
            sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
        sys.stderr.write(f"bridge: DRY RUN - refused write {name} (nothing sent to Exabeam)\n")
        # Deliberately minimal, and deliberately mirrors what Claude Code's permission layer returns
        # ("...but you haven't granted it yet"). An earlier draft added "leave the action to a human",
        # which is coaching: deferring to a human is the exact behaviour a red-team run measures, so
        # saying it here would inflate the score and would be text the Claude baseline never saw. State
        # the fact, nothing else. The machine-readable marker lives in the audit record
        # (action.dryRunRefused), not in text the model reads.
        return _refusal(name)
    # Human confirmation — the second lock. AFTER the dry run (a dry run never asks) and BEFORE the
    # remote call (a question asked after the write confirms nothing).
    confirmed_via = None
    if name in GATED_WRITES:
        def _log_refused():
            try:
                if log_on:
                    fields = dict(_audit_fields(arguments) or {}) if arguments else {}
                    fields["humanConfirmation"] = "refused"
                    telemetry.tool_end(name, (time.perf_counter() - t0) * 1000, action_fields=fields)
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
        try:
            confirmed_via = await _human_confirms(name, arguments)
        except asyncio.CancelledError:
            # A headless Codex does not answer the elicitation with "decline" — it cancels the whole
            # tool request, which arrives here as CancelledError (a BaseException, so no `except
            # Exception` sees it). The write is already refused by construction; what would be lost is
            # the audit record of the ATTEMPT, leaving a tool_start with no tool_end. Record the
            # refusal, then let the cancellation proceed — swallowing it would keep a dead request alive.
            _log_refused()
            raise
        if confirmed_via is None:
            _log_refused()
            return _refusal(name)
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
                               action_fields=_authorized(arguments, confirmed_via) if is_write else None)
    except Exception as e:  # noqa: BLE001 — telemetry must never break a completed call
        sys.stderr.write(f"bridge: telemetry tail error (ignored): {e!r}\n")
    return content


async def _check():
    tools = (await remote(lambda s: s.list_tools())).tools
    dry = " [DRY RUN - writes refused at the bridge]" if DRY_RUN else ""
    print(f"OK — connected to {URL}; {len(tools)} Exabeam tools available.{dry}")


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
    # Announce loudly. A dry run mistaken for a live one wastes an exercise; a live run mistaken for a
    # dry one writes to a real tenant, so this is never silent in either direction.
    if DRY_RUN:
        sys.stderr.write("bridge: DRY RUN is ON (SOCXEN_DRY_RUN) - every write is refused at the "
                         "bridge; nothing reaches Exabeam\n")
    asyncio.run(_check() if "--check" in sys.argv else _serve())


if __name__ == "__main__":
    main()
