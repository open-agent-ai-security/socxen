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
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
claude plugin list      # confirm: socxen@open-agent-ai-security, enabled
```

> socxen is published through the community marketplace
> ([open-agent-ai-security/plugins](https://github.com/open-agent-ai-security/plugins)), which
> registers under the name `open-agent-ai-security` — so the install target is
> `socxen@open-agent-ai-security` (the part after `@` is the marketplace name). The same
> marketplace serves every community plugin (praxen is `praxen@open-agent-ai-security`); one
> `marketplace add` covers them all.

**Upgrading from the pre-marketplace install (`socxen@socxen`)?** The plugin was briefly
distributed from a marketplace hosted in this repo. Migrate with:

```bash
claude plugin marketplace remove socxen                        # also uninstalls socxen@socxen
claude plugin marketplace add open-agent-ai-security/plugins   # re-points in place if already present
claude plugin install socxen@open-agent-ai-security
```

> **Remove the old marketplace first — don't just add the new one.** The two marketplaces have
> *different* names (`socxen` vs `open-agent-ai-security`), so adding the new one leaves the old
> one in place and you end up with **two enabled copies of socxen** — the current release and the
> retired one — both registering the `soc-investigate` skill. Removing a marketplace uninstalls
> the plugins that came from it, which is what you want here, so a separate
> `claude plugin uninstall socxen@socxen` is unnecessary.
>
> Already have a marketplace named `open-agent-ai-security` from praxen? Leave it — the add above
> re-points it to the catalog in place, without disturbing your installed praxen.

The skill registers as `soc-investigate`. The in-session equivalents — `/plugin marketplace add …`,
`/plugin install …`, `/plugin list` — do the same thing; if you install from within a session, run
`/reload-plugins` (or restart) to activate the skill. Prefer the terminal `claude plugin …` form when
scripting — it's argument-driven and runs the same way on every interface.

Or use the guided installer — it wraps the same commands with preflight checks (CLI, `uv`,
credentials), a live MCP connectivity test, and a governance-gate check. Idempotent; safe to re-run
(re-running also picks up updates):

```bash
git clone https://github.com/open-agent-ai-security/socxen.git
cd socxen && ./plugin/install.sh
```

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

## Governance — turn on the safety gate (do not skip this)

> 🛑 **This is the most important step on the page. Install the permissions pack before you point socxen
> at anything real.** It is the *only* hard, harness-enforced lock on dismiss/close. Skip it and a wrong
> AI verdict can suppress a genuine threat with nothing but a soft prompt in the way. Treat it as
> mandatory, not "recommended."

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

### Let the installer merge it for you

From a clone, `install.sh` can perform the merge instead of you hand-editing JSON:

```bash
./install.sh --merge-permissions        # merge, then verify the gate reads ON
```

It is **opt-in and never silent**. Installing without the flag still only *warns* that the gate is
off — and `-y` does not stand in for consent here, because installation alone must never rewrite your
settings. Run interactively without the flag and, if the gate is off, the installer shows you exactly
which rules it would add and asks a plain `y/N` first.

What it guarantees:

- **Backs up first** — a timestamped copy of `settings.json` beside the original, before any write.
- **Additive only** — your existing rules are never removed, reordered, or retiered; ours are appended.
- **Stops on a tier conflict** — if one of these tools already sits in a *different* tier than the
  snippet specifies, that's your decision (or a mis-merge worth a look), so it writes **nothing** and
  tells you which entries to resolve.
- **Idempotent** — re-running is safe; already-merged rules are left alone. Worth re-running even when
  the gate reads ON: a hand-merge of just the two `ask` lines leaves the containment `deny` list missing.
- **Fails honestly** — no `python3`, or a snippet it can't find, means "cannot merge, here's the manual
  path," never a false green. A failed write is restored from the backup.

The merge itself is `skills/soc-investigate/merge_permissions.py`, which you can also run directly —
add `--dry-run` to see the exact changes without writing anything.

> ⚠️ **Do not run socxen with `--dangerously-skip-permissions`**, bypass-permissions, or auto-accept
> modes — they turn the hard gate off (every prompt, including dismiss/close), leaving only the skill's
> soft ask. Keep permissions on.

Beyond this gate, socxen also runs two automatic checks on every Exabeam call — screening the telemetry
it reads for hidden-character smuggling, and de-activating dangerous content (like clickable links) in
what it writes back. See **[Security guardrails](security-guardrails.md)** for what to expect.

## Audit logging (on by default)

socxen keeps a **structured audit log out of the box** — a machine-parseable record of every tool call,
the gated action taken (which alert/case, to what disposition), and when the guardrails fired. It needs
**no setup**: it writes newline-delimited JSON to a local, rotating file at **`~/.socxen/telemetry.jsonl`**
(bounded to ~60 MB), with no network egress.

When you're ready to do more with it, you can point it elsewhere or turn it off — route events to
Exabeam, an OpenTelemetry collector, or a webhook, tune the rotation size, or disable it entirely with
`SOCXEN_OBSERVRA=off`. See **[Logging](logging.md)** for exactly what is (and isn't) recorded, where to
find and read the file, and every control knob.

## Updating

```bash
claude plugin marketplace update open-agent-ai-security     # refresh the catalog
claude plugin update socxen@open-agent-ai-security          # install the latest
```

Both steps matter: without the first, `plugin update` only sees your local (possibly stale) catalog
cache. Restart or `/reload-plugins` to apply.

### Auto-update / fleet config (Claude Code)

Auto-update is per-marketplace and off by default for third-party marketplaces. Enable it
interactively: `/plugin` → **Marketplaces** → `open-agent-ai-security` → **enable auto-update**.
Or fleet-wide in managed `settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "open-agent-ai-security": {
      "source": { "source": "github", "repo": "open-agent-ai-security/plugins" },
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
claude plugin uninstall socxen@open-agent-ai-security
claude plugin marketplace remove open-agent-ai-security   # optional — see note
```

The marketplace is removed by its registered name (`open-agent-ai-security`). Skip that step if
you use other community plugins from it (e.g. praxen) — removing a marketplace also uninstalls
every plugin that was installed from it.
