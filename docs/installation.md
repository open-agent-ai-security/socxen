<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation

socxen ships as a portable **agent skill** (`skills/soc-investigate`) for **Claude Code**, running
against the **Exabeam New-Scale MCP**. It investigates and triages alerts/cases end to end and produces
a structured report. It takes no destructive action: containment is *recommended* for a human, and
dismiss/close are *gated* by permission rules.

## Prerequisites

- **Claude Code** (the `claude` CLI) — tool use and multi-step instruction following.
- **The Exabeam New-Scale MCP**, configured in Claude Code, with an **API key + secret** (OAuth
  client-credentials) for your region. Generate the key in the New-Scale platform — this is role-gated,
  and the MCP inherits the key's access level. The skill uses read tools to gather evidence and
  case/alert workflow tools to act.
- **Network access** for your agent's LLM provider during analysis.

That's the entire dependency surface — no Python, nothing to `pip install`.

## Claude Code

Install from the plugin marketplace. From your terminal:

```bash
claude plugin marketplace add open-agent-ai-security/socxen
claude plugin install socxen@socxen
claude plugin list      # confirm: socxen@socxen, enabled, v0.1.0+
```

> The marketplace registers under the name `socxen` (from `.claude-plugin/marketplace.json`), so the
> install target is `socxen@socxen` — the part after `@` is the marketplace name, not the repo owner.
> This name is deliberately distinct from praxen's marketplace (`open-agent-ai-security`), so you can
> have both org marketplaces added at the same time with no conflict.

The skill registers as `soc-investigate`. The in-session equivalents — `/plugin marketplace add …`,
`/plugin install …`, `/plugin list` — do the same thing; if you install from within a session, run
`/reload-plugins` (or restart) to activate the skill. Prefer the terminal `claude plugin …` form when
scripting — it's argument-driven and runs the same way on every interface.

Or run the bundled convenience script after cloning: `./install.sh` (idempotent).

## Connect the Exabeam MCP

The skill talks to Exabeam through an MCP connection. The bundled connector installs a small local
bridge that **refreshes the OAuth token automatically** — Exabeam uses client-credentials tokens that
expire every few hours, and the bridge handles that so you never see it — then registers it in Claude
Code as `exabeam`:

```bash
git clone https://github.com/open-agent-ai-security/socxen
cd socxen && ./connector/connect-exabeam.sh
```

You paste your API key + secret once (stored owner-only in `~/.exabeam-mcp.env`); the bridge installs to
`~/.socxen/` and registers at user scope. Requires [`uv`](https://docs.astral.sh/uv/). Restart Claude
Code afterward. Regions: `us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`.

<details><summary>Advanced — wire it manually (no auto-refresh)</summary>

You can register the remote MCP directly, but the bearer token expires in ~4h and you'll have to re-add
it each time:

```bash
TOK=$(curl -s https://api.<region>.exabeam.cloud/auth/v1/token -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"<KEY>","client_secret":"<SECRET>"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
claude mcp add --transport http exabeam https://api.<region>.exabeam.cloud/mcp \
  --header "Authorization: Bearer $TOK"
```
</details>

Keep the server named `exabeam` so the governance rules (`mcp__exabeam__…`) match.

## Governance (recommended)

Merge the `permissions` block from `skills/soc-investigate/settings.snippet.json` into your
`~/.claude/settings.json`. It allows read + escalation tools, **gates `update_alert` / `update_case`**
(dismiss/close — where a wrong verdict does the most harm), and denies containment as defense-in-depth
(the MCP exposes none). If your MCP server isn't named `exabeam`, update the `mcp__exabeam__*` prefixes.

> ⚠️ **Do not run socxen with `--dangerously-skip-permissions`**, bypass-permissions, or auto-accept
> modes. They disable every permission prompt — including the dismiss/close gate — and socxen will then
> close alerts with no human in the loop. (The skill asks before any close as a backstop, but the full
> safety model depends on permissions being on.)

## Updating

```bash
claude plugin marketplace update socxen     # refresh the catalog
claude plugin update socxen@socxen          # install the latest
```

Both steps matter: without the first, `plugin update` only sees your local (possibly stale) catalog
cache. Restart or `/reload-plugins` to apply.

### Auto-update / fleet config (Claude Code)

Auto-update is per-marketplace and off by default for third-party marketplaces. Enable it
interactively: `/plugin` → **Marketplaces** → `socxen` → **enable auto-update**. Or fleet-wide in
managed `settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "socxen": {
      "source": { "source": "github", "repo": "open-agent-ai-security/socxen" },
      "autoUpdate": true
    }
  }
}
```

## Any other agent

socxen is just a skill folder in the repo — any capable coding agent can fetch and run it:

> Clone `https://github.com/open-agent-ai-security/socxen` and follow its `soc-investigate` skill to
> investigate Exabeam alert &lt;id&gt;, using the Exabeam New-Scale MCP.

## Uninstalling

```bash
claude plugin uninstall socxen@socxen
claude plugin marketplace remove socxen
```

The marketplace is removed by its registered name (`socxen`, from `.claude-plugin/marketplace.json`).
