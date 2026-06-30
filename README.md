# socxen

**An agentic SOC analyst, as a Claude Code skill.**

socxen investigates and triages **Exabeam New-Scale** alerts and cases end to end — it gathers evidence
through the Exabeam MCP, pivots on entities, weighs competing hypotheses, reaches a threat /
false-positive verdict, and acts. No server, no database, no approval queue: the analyst at the terminal
is the human-in-the-loop, and the unsafe actions are held back by **Claude Code permission rules**, not
by trusting the model.

## Install (Claude Code plugin marketplace)

```
/plugin marketplace add open-agent-ai-security/socxen
/plugin install socxen@socxen
```

Then just ask: **"investigate alert &lt;id&gt;"** or paste an alert/case.

## Prerequisites

1. **Claude Code.**
2. **The Exabeam New-Scale MCP**, configured in Claude Code with your region URL + an API key/secret
   (OAuth client-credentials — generate one in the New-Scale platform; role-gated):
   ```
   claude mcp add --transport http exabeam https://api.<region>.exabeam.cloud/mcp
   ```
   (Auth/token wiring per your environment — the MCP inherits the key's access level.)
3. **Governance (recommended):** merge `skills/soc-investigate/settings.snippet.json` into your
   `.claude/settings.json` `permissions`. It allows read + escalation tools, **gates `update_alert`
   / `update_case`** (dismiss/close — where a wrong AI verdict does harm), and denies containment as
   defense-in-depth. If you registered the MCP under a name other than `exabeam`, update the
   `mcp__exabeam__…` prefixes to match.

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
.claude-plugin/        marketplace.json + plugin.json (marketplace install)
skills/soc-investigate/  SKILL.md, settings.snippet.json (governance), reference/
```

## Status

`v0.1.0` — early. Validated against a live Exabeam staging MCP. Sharing with testers; feedback welcome.

## License

Apache-2.0 — see `LICENSE` / `NOTICE`.
