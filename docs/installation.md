<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation

socxen ships as a portable **agent skill** (`skills/soc-investigate`) for **Claude Code**, running
against the **Exabeam New-Scale MCP**. It investigates and triages alerts/cases end to end and produces
a structured report. It takes no destructive action: containment is *recommended* for a human, and
dismiss/close are *gated* — by permission rules **and** an explicit confirmation the skill asks for.

## Prerequisites

- **Claude Code** (the `claude` CLI) — tool use and multi-step instruction following.
- **A supported model.** socxen is validated on **Claude Sonnet 4.6+ or Opus**. Sonnet is the *floor* —
  our pre-release red-team gates on the weakest supported model as the conservative default (it's the most
  injection-susceptible and cheapest to run), and a release run additionally sweeps Opus. Smaller models
  (e.g. Haiku) are **not supported** for this skill.
- **An Exabeam New-Scale API key + secret** (OAuth client-credentials), from the New-Scale platform
  (role-gated; the MCP inherits the key's access level). You wire it up in *Connect the Exabeam MCP*
  below — the skill uses read tools to gather evidence and case/alert tools to act.
- **[`uv`](https://docs.astral.sh/uv/)** — runs the connector's bridge; it auto-installs its own Python
  dependencies, so there's nothing for you to `pip install`.
- **Network access** for your agent's LLM provider during analysis.

## Claude Code

Install from the plugin marketplace. From your terminal:

```bash
claude plugin marketplace add open-agent-ai-security/socxen
claude plugin install socxen@socxen
claude plugin list      # confirm: socxen@socxen, enabled
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

## Credentials (the only manual step)

socxen **bundles** the Exabeam connection: installing the plugin auto-registers a server named
`exabeam` — a small local bridge that **refreshes the OAuth token automatically**, so you never deal
with expiring tokens. No `claude mcp add`, no clone. The only thing you supply is your key + secret,
in `~/.exabeam-mcp.env`:

```bash
cat > ~/.exabeam-mcp.env <<'EOF'
EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
EXABEAM_API_KEY=your-key
EXABEAM_API_SECRET=your-secret
EOF
chmod 600 ~/.exabeam-mcp.env
```

Requires [`uv`](https://docs.astral.sh/uv/) (it runs the bundled bridge). Restart Claude Code (or
`/reload-plugins`); confirm with `claude mcp list` → `exabeam ✔ Connected`. Regions: `us-west`,
`us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`.

<details><summary>Advanced — wire it manually (no auto-refresh)</summary>

If you'd rather not use the bundled bridge, register the remote MCP directly — but the bearer token
expires in ~4h and you'll have to re-add it each time:

```bash
TOK=$(curl -s https://api.<region>.exabeam.cloud/auth/v1/token -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"<KEY>","client_secret":"<SECRET>"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
claude mcp add --transport http exabeam https://api.<region>.exabeam.cloud/mcp \
  --header "Authorization: Bearer $TOK"
```
</details>

The bundled server registers as `exabeam`; the governance rules match its plugin-namespaced tools
(`mcp__plugin_socxen_exabeam__…` — see Governance below).

## Governance (strongly recommended) — turn on the safety gate

This is the control that makes socxen safe to point at real alerts. Merge the `permissions` block from
`skills/soc-investigate/settings.snippet.json` into your `~/.claude/settings.json`:

- **allow** the read + escalation tools,
- **`ask`** on `update_alert` / `update_case` (dismiss/close — where a wrong verdict does the most harm),
- **`deny`** the 17 containment tools (defense-in-depth; the MCP exposes none today).

Merged, this is a **hard, harness-enforced gate**: Claude Code prompts you before a dismiss/close runs
and will not execute it without your approval, and deterministically hard-blocks the containment tools.
**Until it's merged there is no permission-layer gate** — only the skill's in-prompt ask (softer). The
rules use the **bundled** MCP's tool names (`mcp__plugin_socxen_exabeam__…`); for the advanced manual
`claude mcp add exabeam` path instead, use `mcp__exabeam__…`.

> ⚠️ **Do not run socxen with `--dangerously-skip-permissions`**, bypass-permissions, or auto-accept
> modes — they turn the hard gate off (every prompt, including dismiss/close), leaving only the skill's
> soft ask. Keep permissions on.

Beyond this gate, socxen also runs two automatic checks on every Exabeam call — screening the telemetry
it reads for hidden-character smuggling, and de-activating dangerous content (like clickable links) in
what it writes back. See **[Security guardrails](security-guardrails.md)** for what to expect.

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
