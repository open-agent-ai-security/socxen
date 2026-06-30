# socxen

**An agentic SOC analyst, as a Claude Code skill.**

socxen investigates and triages **Exabeam New-Scale** alerts and cases end to end — it gathers evidence
through the Exabeam MCP, pivots on entities, weighs competing hypotheses, reaches a threat /
false-positive verdict, and acts. No server, no database, no approval queue: the analyst at the terminal
is the human-in-the-loop, and the consequential action (dismiss/close) is held back by **two locks** —
Claude Code permission rules *and* the skill asking you first — never left to the model alone.

## Install (Claude Code plugin marketplace)

From your terminal:

```bash
claude plugin marketplace add open-agent-ai-security/socxen
claude plugin install socxen@socxen
claude plugin list      # confirm: socxen@socxen, enabled
```

Or run `./install.sh` (idempotent — does both and prints next steps). Full guide:
[docs/installation.md](docs/installation.md). The skill registers as `soc-investigate`.

That installs the skill. Two one-time steps remain below — **connect Exabeam** and (recommended)
**governance** — after which you ask it to *"investigate alert &lt;id&gt;"* (or paste an alert/case).

## Add your Exabeam credentials (one time)

socxen **bundles** the Exabeam connection — installing the plugin **auto-registers** it (no
`claude mcp add`, no clone, no expiring tokens to manage). The one thing it can't do for you is supply
your secret, so create `~/.exabeam-mcp.env`:

```bash
cat > ~/.exabeam-mcp.env <<'EOF'
EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
EXABEAM_API_KEY=your-key
EXABEAM_API_SECRET=your-secret
EOF
chmod 600 ~/.exabeam-mcp.env
```

(Get a key + secret from the New-Scale platform → Settings → API Keys; role-gated. The bundled bridge
runs via [`uv`](https://docs.astral.sh/uv/getting-started/installation/) and refreshes the OAuth token
for you.) Restart Claude Code, and you're set.

## Governance (recommended)

Merge `skills/soc-investigate/settings.snippet.json` into your `.claude/settings.json` `permissions`.
It allows read + escalation tools, **gates `update_alert` / `update_case`** (dismiss/close — where a
wrong AI verdict does harm), and denies containment as defense-in-depth. Keep the MCP named `exabeam`
so the `mcp__exabeam__…` rules match.

> ⚠️ **Don't run with `--dangerously-skip-permissions`** (or bypass-permissions / auto-accept modes).
> They disable *every* permission prompt — including the dismiss/close gate — so socxen would close
> alerts with no human in the loop. The skill also asks before any close as a backstop, but the safety
> model only fully holds with permissions **on**.

## What it does

- **Investigates** with the real Exabeam read surface — `search_events` (data-lake logs),
  `search_alerts`/`search_cases`, threat timelines, rule details, MITRE coverage, context tables.
- **Decides** with a disciplined bar: a false-positive close requires a *positive* benign explanation;
  when in doubt, it escalates rather than silently suppressing a real threat.
- **Acts** — opens/updates a case, writes case notes, dismisses true false-positives (gated), and
  **recommends** containment for the analyst to perform in EDR/IAM (the Exabeam MCP has no containment).

See `skills/soc-investigate/SKILL.md` for the methodology and `reference/` for the tool map, triage
vocabulary, report template, and the containment list.

## Layout

```
.claude-plugin/          marketplace.json + plugin.json (marketplace install)
.mcp.json                bundled Exabeam MCP — auto-registers on install
skills/soc-investigate/  SKILL.md, settings.snippet.json (governance), reference/
connector/               exabeam-mcp-bridge.py (the bridge — auto token refresh)
install.sh               convenience installer · docs/installation.md  full guide
```

## Status

Early (v0.2.x) — validated end-to-end against a live Exabeam staging MCP
(install → connect → investigate → gated dismiss). Run `claude plugin list` for your installed version.
Sharing with testers; feedback welcome.

## License

Apache-2.0 — see `LICENSE` / `NOTICE`.
