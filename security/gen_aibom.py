# /// script
# requires-python = ">=3.9"
# ///
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate socxen's AI Bill of Materials (CycloneDX 1.6) from the repo's own sources.

socxen is an AI *agent/application*, not a model: a Claude Code skill (prompt + methodology) plus a
small MCP connector, running on a hosted foundation model (Claude) and calling the Exabeam New-Scale
MCP. Model-card AI-BOM tools (which ingest a Hugging Face model id) can't describe that, so we assemble
a CycloneDX AI-BOM directly from what socxen actually ships:

  - the root component (this plugin) from .claude-plugin/plugin.json + marketplace.json,
  - the foundation model (Claude) as an external machine-learning-model component,
  - the system prompt / methodology (SKILL.md + reference corpus) as a `data` component,
  - the connector's Python dependencies (PEP 723) as `library` components,
  - the Exabeam MCP as a `service` with its inbound/outbound data flows,
  - governance/guardrails (permission tiers, human-in-the-loop) as metadata properties.

Deterministic: same repo state -> byte-identical output (stable uuid5 serial; timestamp from
SOURCE_DATE_EPOCH if set, else current UTC — `--check` ignores the timestamp so CI can verify freshness).

Usage:
    uv run security/gen_aibom.py            # (re)write security/aibom.cdx.json + security/aibom.html
    uv run security/gen_aibom.py --check    # non-zero exit if the on-disk BOM is stale vs. the sources
"""
import datetime
import json
import os
import re
import sys
import uuid
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEC = ROOT / "security"
JSON_OUT = SEC / "aibom.cdx.json"
HTML_OUT = SEC / "aibom.html"


# ---------- read the sources ----------

def _json(rel):
    return json.loads((ROOT / rel).read_text())

def _pep723(pyfile):
    txt = (ROOT / pyfile).read_text()
    block = re.search(r"# /// script\n(.*?)\n# ///", txt, re.S).group(1)
    dm = re.search(r"dependencies\s*=\s*\[(.*?)\]", block, re.S)
    deps = re.findall(r'"([^"]+)"', dm.group(1)) if dm else []
    py = re.search(r'requires-python\s*=\s*"([^"]+)"', block)
    return deps, (py.group(1) if py else None)

def _split_dep(spec):
    m = re.match(r"([A-Za-z0-9_.\-]+)\s*(.*)", spec)
    return m.group(1), (m.group(2).strip() or None)

# SPDX ids for the connector's PyPI deps, verified against PyPI/upstream 2026-07-30.
# A dep added to the bridge without an entry here ships with no license claim rather
# than a guessed one.
DEP_LICENSES = {
    "mcp": "MIT",
    "httpx": "BSD-3-Clause",
    "certifi": "MPL-2.0",
    "observra": "Apache-2.0",
    "typing_extensions": "PSF-2.0",
}


# ---------- build the BOM ----------

def build_bom(timestamp):
    plugin = _json(".claude-plugin/plugin.json")
    market = _json(".claude-plugin/marketplace.json")
    mcp = _json(".mcp.json")
    perms = _json("skills/soc-investigate/settings.snippet.json")["permissions"]
    deps, requires_python = _pep723("connector/exabeam-mcp-bridge.py")
    toolmap = (ROOT / "skills/soc-investigate/reference/tool-map.md").read_text()
    tool_count = len(set(re.findall(r"\bexabeam_[a-z_]+", toolmap)))
    mcp_server = next(iter(mcp["mcpServers"]))  # "exabeam"

    name, version = plugin["name"], plugin["version"]
    repo = plugin["repository"]
    serial = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{repo}@{version}"))
    lic = [{"license": {"id": plugin["license"]}}]

    root = {
        "bom-ref": f"{name}@{version}",
        "type": "application",
        "name": name,
        "version": version,
        "description": plugin["description"],
        "licenses": lic,
        "supplier": {"name": market["owner"]["name"], "url": [market["owner"]["url"]]},
        "publisher": plugin["author"]["name"],
        "externalReferences": [
            {"type": "vcs", "url": repo},
            {"type": "website", "url": plugin["homepage"]},
            {"type": "distribution", "url": repo, "comment": "Claude Code plugin marketplace: socxen@open-agent-ai-security (via open-agent-ai-security/plugins)"},
        ],
        "properties": [
            {"name": "ai:systemType", "value": "agent"},
            {"name": "ai:platform", "value": "Claude Code plugin (skill)"},
            {"name": "ai:skillName", "value": "soc-investigate"},
        ],
    }

    components = [
        {
            "bom-ref": "model:anthropic-claude",
            "type": "machine-learning-model",
            "name": "Claude (Anthropic)",
            "description": ("Foundation model the skill runs on. Hosted API — weights are not distributed "
                            "with socxen. The specific member (e.g. Opus / Sonnet) is selected at runtime "
                            "by Claude Code, not pinned by socxen."),
            "supplier": {"name": "Anthropic", "url": ["https://www.anthropic.com"]},
            "externalReferences": [{"type": "website", "url": "https://www.anthropic.com/claude"}],
            "properties": [
                {"name": "ai:hosting", "value": "external-hosted-api"},
                {"name": "ai:weightsDistributed", "value": "false"},
                {"name": "ai:pinnedByThisProject", "value": "false"},
            ],
        },
        {
            "bom-ref": "artifact:soc-investigate-methodology",
            "type": "data",
            "name": "soc-investigate methodology (system prompt + reference corpus)",
            "description": ("The agent's instructions: SKILL.md (investigation methodology, governance, "
                            "output discipline) plus reference/ (tool map, EQL search cookbook, enrichment "
                            "playbook, report template, triage taxonomy, containment list, worked examples). "
                            "This prompt corpus — not a model — is the primary AI artifact socxen ships."),
            "licenses": lic,
            "properties": [
                {"name": "ai:artifactKind", "value": "system-prompt/methodology"},
                {"name": "ai:untrustedInputHandling",
                 "value": "treats tool output (alerts/events/case notes) as data, never instructions"},
            ],
        },
        {
            "bom-ref": "component:exabeam-mcp-bridge",
            "type": "application",
            "name": "exabeam-mcp-bridge",
            "description": ("Bundled local stdio MCP connector (connector/exabeam-mcp-bridge.py). Forwards "
                            "to the remote Exabeam New-Scale MCP and auto-refreshes the OAuth token. "
                            "Read-through; handles the API key/secret."),
            "licenses": lic,
            "properties": [
                {"name": "runtime", "value": "python"},
                {"name": "requires-python", "value": requires_python or "unspecified"},
                {"name": "pep723", "value": "true"},
            ],
        },
    ]

    for spec in deps:
        dep_name, constraint = _split_dep(spec)
        comp = {
            "bom-ref": f"pkg:pypi/{dep_name}",
            "type": "library",
            "name": dep_name,
            "version": constraint or "unspecified",
            "purl": f"pkg:pypi/{dep_name}",
            "description": f"Connector dependency ({spec}), resolved by uv at runtime (PEP 723).",
        }
        if dep_name in DEP_LICENSES:
            comp["licenses"] = [{"license": {"id": DEP_LICENSES[dep_name]}}]
        components.append(comp)

    service = {
        "bom-ref": f"service:{mcp_server}-mcp",
        "name": "Exabeam New-Scale MCP",
        "description": (f"External tool surface reached through the bundled connector: {tool_count} tools "
                        "(Threat Center, Search, detection rules, context tables) and NO containment "
                        "capability. Registered via .mcp.json as a bundled MCP server."),
        "endpoint": "https://api.<region>.exabeam.cloud/mcp",
        "authenticated": True,
        "x-trust-boundary": True,
        "data": [
            {"flow": "inbound", "classification": "security-telemetry (alerts, events, cases — attacker-influenceable)"},
            {"flow": "outbound", "classification": "case-management actions (create/notes: free; dismiss/close: human-gated)"},
        ],
        "externalReferences": [
            {"type": "documentation",
             "url": "https://docs.exabeam.com/en/new-scale-soc-platform/all/administration-guide/get-started-with-the-new-scale-security-operations-platform/connect-to-exabeam-mcp-server.html"}
        ],
        "properties": [
            {"name": "mcp:toolCount", "value": str(tool_count)},
            {"name": "mcp:containmentCapability", "value": "none"},
            {"name": "mcp:transport", "value": "stdio bridge -> streamable-http"},
        ],
    }

    metadata = {
        "component": root,
        "supplier": {"name": market["owner"]["name"], "url": [market["owner"]["url"]]},
        "authors": [{"name": plugin["author"]["name"]}],
        "properties": [
            {"name": "ai:foundationModel", "value": "Claude (Anthropic), external hosted API"},
            {"name": "ai:humanInTheLoop", "value": "required for dismiss/close (update_alert/update_case)"},
            {"name": "ai:autonomousActions", "value": "read/search + create_case/case_notes (escalation)"},
            {"name": "ai:containmentCapability", "value": "none — recommend-only, performed by a human in EDR/IAM"},
            {"name": "ai:guardrails",
             "value": f"permission tiers {len(perms['allow'])} allow / {len(perms['ask'])} ask / {len(perms['deny'])} deny "
                      "(settings.snippet.json) + in-prompt ask-before-close backstop"},
            {"name": "ai:secretsHandling", "value": "Exabeam OAuth key/secret from ~/.exabeam-mcp.env; never logged"},
            {"name": "aibom:generator", "value": "security/gen_aibom.py (deterministic, from repo sources)"},
        ],
    }
    if timestamp:
        metadata["timestamp"] = timestamp

    dependencies = [
        {"ref": root["bom-ref"],
         "dependsOn": ["model:anthropic-claude", "artifact:soc-investigate-methodology",
                       "component:exabeam-mcp-bridge", f"service:{mcp_server}-mcp"]},
        {"ref": "component:exabeam-mcp-bridge",
         "dependsOn": [f"pkg:pypi/{_split_dep(s)[0]}" for s in deps]},
        {"ref": "artifact:soc-investigate-methodology", "dependsOn": ["model:anthropic-claude"]},
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "services": [service],
        "dependencies": dependencies,
    }


# ---------- render HTML ----------

_CATEGORY = {
    "machine-learning-model": "Foundation model",
    "data": "AI artifact (prompt / methodology)",
    "application": "Connector",
    "library": "Software dependency",
}
_CSS = """
:root{--ink:#0f1e2e;--sub:#4a5b6b;--line:#e2e8f0;--accent:#0aa5a5;--bg:#f7f9fb;--chip:#eef4f7}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:960px;margin:0 auto;padding:0 24px 64px}
header{background:var(--ink);color:#fff;padding:34px 0;margin-bottom:28px}
header .wrap{padding-bottom:0}
h1{margin:0 0 4px;font-size:26px}h1 .sc{color:var(--accent)}
.tag{color:#b9c6d2;font-size:14px;margin:0}
.badges{margin-top:14px}.badge{display:inline-block;background:#183041;color:#cfe;border:1px solid #2a4a5f;border-radius:20px;padding:3px 11px;font-size:12px;margin:0 6px 6px 0}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--sub);border-bottom:1px solid var(--line);padding-bottom:6px;margin:34px 0 14px}
.lead{color:var(--sub)}
table{width:100%;border-collapse:collapse;margin:8px 0 4px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line);font-size:14px}
th{color:var(--sub);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.k{white-space:nowrap;font-weight:600}
.cat{font-size:12px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.05em;padding-top:16px}
code{background:var(--chip);padding:1px 5px;border-radius:4px;font-size:13px}
.flow{display:inline-block;font-size:12px;font-weight:700;border-radius:4px;padding:1px 7px;margin-right:6px}
.in{background:#e6f6f0;color:#0a7a55}.out{background:#fdeee6;color:#b5561e}
.meta{font-size:13px;color:var(--sub)}
.prop{font-size:14px;padding:7px 0;border-bottom:1px solid var(--line)}.prop b{color:var(--ink)}
footer{margin-top:40px;color:var(--sub);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
a{color:#0a7d99}
"""

def render_html(bom):
    m = bom["metadata"]; root = m["component"]
    def props_of(x): return {p["name"]: p["value"] for p in x.get("properties", [])}

    def esc(s): return escape(str(s))

    badges = "".join(f'<span class="badge">{esc(t)}</span>' for t in (
        f'v{root["version"]}', f'CycloneDX {bom["specVersion"]}', root["licenses"][0]["license"]["id"],
        f'serial {bom["serialNumber"].split(":")[-1][:8]}…'))

    # components grouped by category, in a stable, sensible order
    order = ["machine-learning-model", "data", "application", "library"]
    rows = []
    for cat_type in order:
        first = True
        for c in bom["components"]:
            if c["type"] != cat_type:
                continue
            if first:
                rows.append(f'<tr><td class="cat" colspan="2">{esc(_CATEGORY[cat_type])}</td></tr>')
                first = False
            ver = f' <code>{esc(c["version"])}</code>' if c.get("version") else ""
            purl = f'<div class="meta"><code>{esc(c["purl"])}</code></div>' if c.get("purl") else ""
            extra = ""
            pr = props_of(c)
            if pr:
                extra = '<div class="meta">' + " · ".join(f'{esc(k)}: {esc(v)}' for k, v in pr.items()) + "</div>"
            rows.append(f'<tr><td class="k">{esc(c["name"])}{ver}</td>'
                        f'<td>{esc(c.get("description",""))}{purl}{extra}</td></tr>')
    comp_rows = "\n".join(rows)

    svc_rows = []
    for s in bom["services"]:
        flows = "".join(
            f'<span class="flow {"in" if d["flow"]=="inbound" else "out"}">{esc(d["flow"])}</span>{esc(d["classification"])}<br>'
            for d in s.get("data", []))
        sp = props_of(s)
        spx = '<div class="meta">' + " · ".join(f'{esc(k)}: {esc(v)}' for k, v in sp.items()) + "</div>" if sp else ""
        svc_rows.append(f'<tr><td class="k">{esc(s["name"])}<div class="meta"><code>{esc(s.get("endpoint",""))}</code>'
                        f'{" · authenticated" if s.get("authenticated") else ""}</div></td>'
                        f'<td>{esc(s.get("description",""))}<div style="margin-top:6px">{flows}</div>{spx}</td></tr>')
    svc_html = "\n".join(svc_rows)

    gov = "".join(f'<div class="prop"><b>{esc(p["name"].split(":")[-1])}</b> — {esc(p["value"])}</div>'
                  for p in m.get("properties", []) if p["name"].startswith("ai:"))

    refs = "".join(f'<li><a href="{esc(r["url"])}">{esc(r["type"])}</a> — {esc(r["url"])}</li>'
                   for r in root.get("externalReferences", []))
    ts = m.get("timestamp", "(reproducible build — timestamp omitted)")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Copyright 2026 Exabeam, Inc. SPDX-License-Identifier: Apache-2.0 -->
<title>socxen — AI Bill of Materials</title><style>{_CSS}</style></head>
<body>
<header><div class="wrap">
  <h1><span class="sc">socxen</span> — AI Bill of Materials</h1>
  <p class="tag">{esc(root["description"])}</p>
  <div class="badges">{badges}</div>
</div></header>
<div class="wrap">
  <p class="lead">This is an <b>AI application / agent</b> BOM, not a model card. socxen runs on a
  hosted foundation model (Claude) it does not ship, and its substance is a <b>prompt/methodology</b>
  plus a small <b>MCP connector</b>. The inventory below is generated deterministically from the repo's
  own sources by <code>security/gen_aibom.py</code>.</p>
  <p class="meta">Supplier: {esc(m["supplier"]["name"])} · Generated: {esc(ts)} · Serial: <code>{esc(bom["serialNumber"])}</code></p>

  <h2>Components</h2>
  <table><tbody>{comp_rows}</tbody></table>

  <h2>Services &amp; data flows</h2>
  <table><tbody>{svc_html}</tbody></table>

  <h2>Governance &amp; guardrails</h2>
  {gov}

  <h2>Provenance</h2>
  <ul>{refs}</ul>

  <footer>CycloneDX {esc(bom["specVersion"])} · {esc(bom["serialNumber"])}<br>
  Regenerate with <code>uv run security/gen_aibom.py</code>. Raw BOM: <code>security/aibom.cdx.json</code>.</footer>
</div></body></html>
"""


# ---------- main ----------

def _timestamp():
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    dt = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
          else datetime.datetime.now(datetime.timezone.utc))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _dumps(bom):
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"

def main(argv):
    check = "--check" in argv
    bom = build_bom(_timestamp())

    if check:
        if not JSON_OUT.exists():
            print("aibom.cdx.json missing — run: uv run security/gen_aibom.py", file=sys.stderr)
            return 1
        cur = json.loads(JSON_OUT.read_text())
        fresh = json.loads(_dumps(bom))
        cur.get("metadata", {}).pop("timestamp", None)      # ignore the clock
        fresh.get("metadata", {}).pop("timestamp", None)
        if cur != fresh:
            print("security/aibom.cdx.json is STALE vs the repo sources — regenerate with "
                  "`uv run security/gen_aibom.py`.", file=sys.stderr)
            return 1
        print("AI BOM is current.")
        return 0

    SEC.mkdir(exist_ok=True)
    JSON_OUT.write_text(_dumps(bom))
    HTML_OUT.write_text(render_html(bom))
    print(f"wrote {JSON_OUT.relative_to(ROOT)} and {HTML_OUT.relative_to(ROOT)} "
          f"({len(bom['components'])} components, {len(bom['services'])} service)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
