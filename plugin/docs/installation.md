<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation

socxen ships as a portable **agent skill suite** (`skills/`) for **Claude Code** and **OpenAI Codex**,
running against the **Exabeam New-Scale MCP**. Both hosts load the same skills and the same guarded
connector; only the packaging and where the safety gate lives differ. It investigates and triages alerts/cases end to end and produces
a structured report. It takes no destructive action: containment is *recommended* for a human, and
dismiss/close are *gated* — by permission rules **and** an explicit confirmation the skill asks for.

## Prerequisites

- **A host agent** — **Claude Code** (the `claude` CLI) or **OpenAI Codex** (the `codex` CLI). Both need
  tool use and multi-step instruction following.
- **A supported model.** On **Claude Code**, socxen is validated on **Claude Sonnet 4.6+ or Opus**. Sonnet
  is the *floor* — our pre-release red-team gates on the weakest supported model as the conservative
  default (it's the most injection-susceptible and cheapest to run), and a release run additionally sweeps
  Opus. Smaller models (e.g. Haiku) are **not supported** for this skill.

  On **Codex**, the red-team gate has run on **GPT-5.6 Terra** at `model_reasoning_effort = "medium"`
  (2026-08-27: zero landings in the blocking classes — see `security/redteam/HISTORY.md`). The routing
  evals have not yet been run against an OpenAI model, and the Sol sweep has not been run.

  The intended tiers mirror the Claude Code discipline — gate on the weakest supported tier, sweep the
  strongest at release — and map by capability, not by name:

  | role | Claude Code | Codex |
  |---|---|---|
  | release sweep | Opus | GPT-5.6 **Sol** |
  | **floor — the red-team gate** | **Sonnet 4.6+** | GPT-5.6 **Terra** |
  | not supported | Haiku | GPT-5.6 **Luna** |

  Luna is the Haiku-tier analogue, so it is out for the same reason Haiku is. Reasoning effort is pinned
  at `model_reasoning_effort = "medium"` — Codex's own default — and the red-team result will be stated
  at that level. Codex accepts `minimal | low | medium | high | xhigh`; there is no `auto`. A run at a
  different effort is a different result, so quote the effort alongside the number.

  Until that run lands, treat the Codex path as *packaged, not proven* — the same conservative reading
  you would give any un-gated release.
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

## OpenAI Codex

Codex reads the **same community marketplace** as the Claude Code path — the catalog manifest and its
`main`-branch pin are shared, so the plugin key is the same shape. From your terminal:

```bash
codex plugin marketplace add open-agent-ai-security/plugins
codex plugin add socxen@open-agent-ai-security
codex plugin list      # confirm: socxen@open-agent-ai-security, installed, enabled
```

That's the whole install. **There is no installer script and no permissions merge on Codex** — Codex
requires human approval for its destructive-annotated write tools and refuses them when nobody is present, so the gate
needs nothing merged. See Governance below.

The bundled connector registers as `exabeam` and the three skills are available to every Codex session.
To check credentials and reach the tenant, run the diagnostics from a clone, or from the installed plugin
directory — `codex plugin list` prints its path:

```bash
./plugin/preflight.sh   # from a clone (from the installed plugin directory: ./preflight.sh); read-only, nothing is written
```

> **Two host agents on one machine?** `preflight.sh` detects which one it is checking, or takes
> `--platform claude|codex`. Installing on both is supported, but each host keeps its own plugin copy
> and its own gate — verify them separately.

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

Requires [`uv`](https://docs.astral.sh/uv/) (it runs the bundled bridge). Restart your host agent (on
Claude Code, `/reload-plugins`); confirm with `claude mcp list` → `exabeam ✔ Connected`, or on Codex
`codex mcp get exabeam`. Regions: `us-west`,
`us-east`, `ca`, `eu`, `sa`, `sg`, `ch`, `jp`, `au`.

<details><summary>Advanced — wire it manually (no auto-refresh)</summary>

If you'd rather not use the bundled bridge, register the remote MCP directly. Two things to know
first. The bearer token expires in ~4h and you'll have to re-add it each time. More importantly,
**all three of socxen's deterministic controls live in the bundled bridge** — input screening of
telemetry, the write-side neutralizer that masks secrets and de-fangs links in what socxen writes, and
the audit trail — and **none of them run when Claude Code talks to the remote MCP directly.** The
dismiss/close gate still applies if you name the server `exabeam` (the hook matches it); nothing else
does. Use this path for a connectivity check, not for investigations you rely on:

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

## Governance — the safety gate

> ✅ **The gate ships ON, on both hosts.** On **Claude Code** it is a `PreToolUse` hook bundled in the
> plugin (`hooks/gate.py`) that is active the moment the plugin is enabled: it **asks** you before
> `exabeam_update_alert` / `exabeam_update_case` / `exabeam_send_email`, **denies** every containment
> tool outright, and **asks** on any tool this release hasn't classified. Its decisions hold even under
> `--dangerously-skip-permissions`, and when no human is present (`claude -p`, CI) an *ask* is refused.
> On **Codex** the same tiers ship inside the package as tool-approval policy, and Codex cancels a
> destructive tool when nobody is there to approve it. Nothing to merge on either host.
>
> The hook also grants the reads: its *allow* on the 16 read tools and the two escalation writes
> bypasses the prompt, so with nothing merged a safe operation runs silently and a dangerous one asks —
> the same split Codex applies from the same tier file (verified headless in default permission mode,
> 2026-09-06). Your own rules still win: a `deny` on one of these tools removes it from the model's tool
> list before the hook runs, and an `ask` still prompts — the hook's *allow* only removes the default
> prompt (both verified live the same day). The hook
> fires for the bundled server under any plugin key and for any manually wired server whose name
> contains `exabeam` (`claude mcp add exabeam …`); the permission rules below recognize only the bundled
> key and a server named exactly `exabeam`, so if you wire by hand, **name it `exabeam`**. The hook runs as a shell command, so the Claude Code host needs a POSIX shell (or Git Bash on
> Windows) and `python3` 3.7+ on `PATH`; without `python3` every gated call is refused, not allowed.

### Claude Code — the optional permission rules

You do not need these. They are a second lock on dismiss/close that does not depend on the hook (the
same tiers, enforced by Claude Code's own permission system), and nothing more. Merge the `permissions` block from
`skills/soc-investigate/settings.snippet.json` — inside the installed plugin, or
`plugin/skills/soc-investigate/settings.snippet.json` from a clone — into the settings file Claude Code
reads (usually `~/.claude/settings.json` — see [Which settings file?](#which-settings-file) below):

- **allow** the read + escalation tools,
- **`ask`** on `update_alert` / `update_case` (dismiss/close — where a wrong verdict does the most harm),
- **`deny`** the 17 containment tools (defense-in-depth; the MCP exposes none today).

Merged, the rules and the bundled hook agree on every tool — they are generated from the same tier
file, and a test pins that — so a dismiss/close prompts once, not twice. The rules use the **bundled**
MCP's tool names (`mcp__plugin_socxen_exabeam__…`); for the advanced manual
`claude mcp add exabeam` path instead, use `mcp__exabeam__…`.

### Let the installer merge it for you

From a clone, `plugin/install.sh` can perform the merge instead of you hand-editing JSON:

```bash
./plugin/install.sh --merge-permissions   # merge, then verify the gate reads ON
```

`--checks-only` outranks it: diagnostics promise to change nothing, so the two together skip the merge
and say so.

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

The merge itself is `skills/soc-investigate/merge_permissions.py` (`plugin/skills/…` from a clone),
which you can also run directly —
add `--dry-run` to see the exact changes without writing anything.

### Which settings file?

The one Claude Code will actually read: `SOCXEN_SETTINGS_FILE` if you set it,
otherwise `$CLAUDE_CONFIG_DIR/settings.json` if your config dir is relocated, otherwise
`~/.claude/settings.json`. Every message names the resolved path, so you can always see which file was
checked or written.

> ⚠️ **Keep permissions on.** `--dangerously-skip-permissions`, bypass-permissions and auto-accept modes
> turn the *permission rules* off — but **not the bundled hook**: its *deny* on containment and its *ask*
> on dismiss/close still fire in those modes, and with nobody there to answer, an *ask* is refused
> (verified live, 2026-09-04). What you lose in those modes is the second lock — the rules, if you
> merged them. Do not rely on that.

Beyond this gate, socxen also runs two automatic checks on every Exabeam call — screening the telemetry
it reads for hidden-character smuggling, and de-activating dangerous content (like clickable links) in
what it writes back. See **[Security guardrails](security-guardrails.md)** for what to expect.

### Verifying the gate on Codex

Codex lets a plugin declare tool-approval policy for its own bundled MCP server, so socxen ships the gate
rather than asking you to merge it. There is no snippet and no merge step: in an **interactive** Codex
session the gate is on from the moment you install.

**Codex requires a human before any destructive action, and refuses it when there is no human.** The
Exabeam MCP annotates its four write tools — `update_alert`, `update_case`, `create_case`,
`create_case_notes` — with `destructiveHint: true`, and Codex requires approval for a destructive-
annotated tool in *every* approval mode (read-only tools run silently). Under `codex exec`, or any run
with nobody at the keyboard, there is no one to approve, so Codex cancels the call: verified against
`codex-cli` 0.146.0, a headless `exabeam_update_case` returns `user cancelled MCP tool call` and never
reaches the tenant. An action that needs a human, run without one, fails — the correct default.

So on Codex the host owns the approval prompt, exactly as Claude Code's permission layer does. socxen
adds one thing on top: the containment tools ship in `disabled_tools`, removed from the model's view
entirely. One difference from Claude worth knowing: because Exabeam marks *all four* write tools
destructive, Codex also prompts for escalation (`create_case`, `create_case_notes`) where Claude runs
those silently. Noisier, not less safe — and it is Exabeam's annotation, not a socxen setting, so it
cannot be quieted from config.

The same three tiers, expressed as Codex approval modes in `.mcp.codex.json`:

- **`approval_mode: "auto"`** on the read + escalation tools,
- **`approval_mode: "approve"`** on `update_alert` / `update_case` (dismiss/close),
- **`disabled_tools`** for the containment tools — Codex applies this *after* any allowlist, so they
  cannot be re-enabled at runtime and never reach the model at all.

`default_tools_approval_mode` is `approve`, which makes the Codex gate slightly stricter than the Claude
one in one deliberate place: a tool the Exabeam MCP grows that socxen has not classified asks you rather
than inheriting a permissive default.

Verify it:

```bash
./preflight.sh --platform codex
```

Expect **`Human-in-the-loop gate ON — containment disabled by the plugin; Codex requires approval for the
destructive write tools and refuses them with no human present`**. Or
read the config directly:

```bash
codex mcp get exabeam    # expect default_tools_approval_mode: approve, and a disabled_tools list
```

> **If no `exabeam` server resolves**, that is not the same as the gate being off — Codex drops a bundled
> server entirely if any part of its config is invalid, and `codex plugin add` still reports success.
> Reinstall with `codex plugin add socxen@open-agent-ai-security` and check again.

You can tighten socxen's defaults further in `~/.codex/config.toml` under
`[plugins."socxen@open-agent-ai-security".mcp_servers.exabeam]` — for example moving more tools to
`approve`. Overrides there win over what the plugin ships.

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

### OpenAI Codex

```bash
codex plugin marketplace upgrade open-agent-ai-security
codex plugin add socxen@open-agent-ai-security
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

On **Codex**:

```bash
codex plugin remove socxen@open-agent-ai-security
codex plugin marketplace remove open-agent-ai-security   # optional — same caveat as above
```

Removing the plugin also removes the gate it shipped, since the two are the same artifact. Neither
command touches `~/.exabeam-mcp.env` — delete that yourself if you are done with the credentials.
