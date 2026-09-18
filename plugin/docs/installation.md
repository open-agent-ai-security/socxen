<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation & setup

socxen is a plugin for **Claude Code** and **OpenAI Codex** that works your **Exabeam New-Scale** tenant
through the Exabeam MCP. Setup is the same shape on both hosts: install the plugin, add one credentials
file, check, and run your first investigation. Five minutes.

The safety gate is on from the moment the plugin is installed: dismissing an alert or closing a case
always asks you first, and containment is never executed. Nothing to configure for that. On Claude Code
the gate is a hook inside the plugin, and it holds even if you run with permissions skipped or auto-accept
on: its deny on containment and its ask on dismiss and close still fire in those modes, and with nobody
there to answer, an ask is refused.

## Before you start

- **A host agent:** the `claude` CLI (Claude Code) or the `codex` CLI (Codex), signed in.
- **A supported model.** On Claude Code, Sonnet 4.6 or newer, or Opus; on Codex, GPT-5.6 Terra or Sol.
  Smaller models (Haiku, Luna) are not supported. See [Security](security-guardrails.md#how-it-is-tested)
  for how the supported models are validated.
- **[`uv`](https://docs.astral.sh/uv/)** on your `PATH`. It runs the bundled Exabeam connector and
  installs the connector's own Python dependencies; there is nothing to `pip install`.
- **An Exabeam New-Scale API key and secret**, created in your New-Scale console. The connector inherits
  the key's role, so the key needs a role that can read alerts, cases and events and open cases and
  write case notes. A read-only key works for investigating but not for the case actions.
- **Your New-Scale region** — one of `us-west`, `us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`.
  It is the region your tenant is hosted in; your Exabeam administrator or your console address tells
  you which.
- **Windows:** socxen is not supported natively on Windows; use **WSL**. The diagnostics and the safety
  gate are shell scripts and Python, and the credentials file below is protected by Unix file
  permissions, which Git Bash on NTFS does not enforce — so Git Bash can run the scripts but leaves your
  key and secret unprotected. There is no PowerShell path.
- **Exabeam customers:** the supported build is delivered through the Exabeam Plug-in Forge, with its
  own install command; your Exabeam representative can point you at it. These instructions cover the
  community release; see [Support](support.md).

## Quick start — Claude Code

**1. Install the plugin.**

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
claude plugin list      # expect: socxen@open-agent-ai-security  <version>  enabled, no errors
```

**2. Add your credentials.** One file, in your home directory:

```bash
cat > ~/.exabeam-mcp.env <<'ENV'
EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
EXABEAM_API_KEY=your-key
EXABEAM_API_SECRET=your-secret
ENV
chmod 600 ~/.exabeam-mcp.env
```

Replace `<region>` with your region. The URL must be `https://`. Then restart Claude Code, or run
`/reload-plugins` inside it.

**3. Check the setup.** The plugin ships a read-only diagnostic that tells you what, if anything, is
missing. It lives in the installed plugin directory: take the version `claude plugin list` shows and
run

```bash
bash ~/.claude/plugins/cache/open-agent-ai-security/socxen/<version>/preflight.sh
```

Use the exact version, not a wildcard — the cache keeps earlier versions after an update, and a
wildcard would run the oldest one.

Expect every line to start with `✓`, including **`Exabeam MCP reachable`** and **`Human-in-the-loop
gate ON`**. A `✗` line names the step to fix.

**4. Run your first investigation.** Start Claude Code and hand it an alert:

> investigate alert `<alert id>`

You can find an alert ID in the New-Scale console under **Threat Center → Alerts**; or ask socxen
*"triage the queue"* first and pick one from the list it returns. socxen loads the `soc-investigate`
skill, queries Exabeam for the evidence (you will see the tool calls go by), and ends with a written
report: the timeline, the evidence with its source, a MITRE mapping, a verdict, and a last line of
`Taxonomy outcome: raised`, `auto_closed` or `fp_closed`. If it concludes the alert is a false
positive, it **asks you** — *"Dismiss alert X as a false positive? (yes / no)"* — and waits. Nothing is
dismissed or closed until you say yes.

That is the whole setup. [Using the skills](usage.md) covers what else you can ask.

## Quick start — Codex

**1. Install the plugin.**

```bash
codex plugin marketplace add open-agent-ai-security/plugins
codex plugin add socxen@open-agent-ai-security
codex plugin list      # expect: socxen@open-agent-ai-security  installed, enabled  <version>
```

**2. Add your credentials** — the same file as for Claude Code, above (`~/.exabeam-mcp.env`, `https://`,
`chmod 600`). Then start a new Codex session.

**3. Check the setup.** From the installed plugin directory (`codex plugin list` prints its path):

```bash
./preflight.sh --platform codex
```

Expect `✓` on every line, including **`Exabeam MCP reachable`** and **`Human-in-the-loop gate ON`**.

**4. Run your first investigation.** In a Codex session:

> investigate alert `<alert id>`

Same report, same last line, same question before any dismissal. One difference on Codex: it also asks
you before socxen *opens* a case or writes a note, because Exabeam marks those tools as writes and Codex
asks before every write. Noisier, not less safe. And if you script socxen with `codex exec`, where
nobody is at the keyboard, Codex cancels any write that needs an approval rather than letting it
through — the gate does not evaporate when the human does.

## Updating

```bash
# Claude Code
claude plugin marketplace update open-agent-ai-security
claude plugin update socxen@open-agent-ai-security

# Codex
codex plugin marketplace upgrade open-agent-ai-security
codex plugin add socxen@open-agent-ai-security
```

Both commands matter on Claude Code: the first refreshes the catalog, the second installs from it.
Restart or `/reload-plugins` to apply. Auto-update on Claude Code is per marketplace and off by default
for community marketplaces; turn it on under `/plugin` → **Marketplaces** → `open-agent-ai-security`,
or fleet-wide in a managed `settings.json`:

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

## Troubleshooting

Run `preflight.sh` first (step 3 above); it checks the CLI, `uv`, the credentials file, the connection
to your tenant, and the safety gate, and names the failing step.

- **`Exabeam MCP reachable` fails.** Check the region in `EXABEAM_MCP_URL`, that the URL starts with
  `https://`, and that the key and secret are the ones your console shows. The connector refuses to
  start over `http://`, on purpose.
- **The skill says the Exabeam MCP is not connected.** The credentials file is missing or was added
  after the host started; add it and restart the host.
- **`claude plugin list` shows an error beside socxen.** The plugin installed but did not load; run
  `claude plugin update socxen@open-agent-ai-security` to get the current release, then restart.
- **Two copies of socxen.** If you installed an early build from the retired `socxen@socxen`
  marketplace, remove it first: `claude plugin marketplace remove socxen`, then install as in step 1.
- **On Codex, no `exabeam` server appears.** Codex drops a bundled server silently if any part of its
  configuration is invalid; run `codex plugin add socxen@open-agent-ai-security` again and re-check.

## For organizations: the same tiers as host policy

The safety gate that ships in the plugin is a hook the host enforces; you do not need anything else.
Organizations that manage Claude Code through policy can apply the same allow, ask and deny tiers as
host permission rules: the plugin publishes them, generated from its tier file, as
`skills/soc-investigate/settings.snippet.json` inside the installed plugin. Push that block through
your managed settings; the two layers agree on every tool because both come from one source.

## Advanced: wiring the Exabeam MCP by hand (not recommended)

You can register the remote Exabeam MCP in your host directly (`claude mcp add … exabeam …`) with a
bearer token you mint yourself. Two things to know: the token expires in about four hours, and, more
importantly, socxen's guardrails — the screening of what it reads, the neutralizing and masking of what
it writes, and the audit trail — live in the bundled connector, so
none of them run when Claude Code talks to the remote MCP directly. Only the dismiss/close gate
survives, and only if the server is named `exabeam`. Use this for a connectivity check, not for investigations you rely on.

## Uninstalling

```bash
# Claude Code
claude plugin uninstall socxen@open-agent-ai-security
claude plugin marketplace remove open-agent-ai-security   # optional; also removes other plugins from this catalog

# Codex
codex plugin remove socxen@open-agent-ai-security
codex plugin marketplace remove open-agent-ai-security   # optional; same caveat
```

Removing the plugin removes the gate it shipped. Neither command touches `~/.exabeam-mcp.env`; delete
that yourself when you are done with the credentials.
