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

## Configure the Exabeam MCP

```bash
claude mcp add --transport http exabeam https://api.<region>.exabeam.cloud/mcp
claude mcp list      # confirm 'exabeam' is configured
```

Supply your API key/secret per your environment (OAuth client-credentials → bearer token). Regions:
`us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`. If you register the server under a name
other than `exabeam`, note it for the governance step below.

## Governance (recommended)

Merge the `permissions` block from `skills/soc-investigate/settings.snippet.json` into your
`~/.claude/settings.json`. It allows read + escalation tools, **gates `update_alert` / `update_case`**
(dismiss/close — where a wrong verdict does the most harm), and denies containment as defense-in-depth
(the MCP exposes none). If your MCP server isn't named `exabeam`, update the `mcp__exabeam__*` prefixes.

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
