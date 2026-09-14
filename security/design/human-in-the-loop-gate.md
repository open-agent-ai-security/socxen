<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# Design record — The human-in-the-loop gate

> **Status:** Shipped and current with the code as of 0.8.6. The authoritative statement of behaviour is
> the code: `plugin/hooks/gate.py` (its docstring is the decision table), `plugin/hooks/hooks.json`,
> `plugin/.mcp.codex.json`, and the tier file they are generated from,
> `plugin/skills/soc-investigate/permissions.json`. The operator's view is
> [the installation guide](../../plugin/docs/installation.md#governance--the-safety-gate). This record
> says why the gate is built this way and what each layer does and does not promise.

## 1. What the gate promises

Three tiers, one source, enforced by the **host agent** rather than by the model:

| Tier | Tools | Decision | Why |
|---|---|---|---|
| **deny** (70) | every containment and rule-write tool the Exabeam MCP exposes or may expose | refused outright | socxen recommends containment for a human to perform in EDR/IAM and never executes it; detection engineering applies rule changes |
| **ask** (3) | `exabeam_update_alert`, `exabeam_update_case`, `exabeam_send_email` | an explicit human yes, every time; refused when no human is present | dismiss and close are the irreversible outcomes of an investigation, and mail leaves the platform |
| **allow** (21) | the reads, plus the two escalation writes `create_case` and `create_case_notes` | prompt-free | a fresh install must be useful immediately without weakening anything; escalation must never prompt (a prompt on escalation teaches the model to avoid it) |
| *unclassified* | any tool the remote MCP grows that this release has not tiered | asks | inherits the safe default, not the session default |

The counts are the shipped tier file's; the invariant tests pin that every live tool is in exactly one
tier and that the generated artifacts agree with it.

## 2. Why a hook, and why it ships on

Until 0.8.6 the Claude Code gate was a permission snippet the operator had to **merge** into their
settings. Inert until merged, and switched off entirely by `--dangerously-skip-permissions` — the two
open questions of issue #9, and the reason the red team could only test the gate "on" and "bypassed".

Claude Code lets a plugin ship *code that takes part in permission decisions* (a `PreToolUse` hook) but
not permission *rules*, which are the operator's. A hook is active the moment the plugin is enabled; its
`deny` holds under `--dangerously-skip-permissions`; its `ask` forces a human prompt in every mode and is
**refused by the host when no human is present** (`claude -p`, CI). That is the same posture the Codex
package already had from its tool-approval policy, so shipping the hook (#148) made the two hosts equal:
**nothing to merge on either host, and the gate is on.** Verified live on 2026-09-04, including the
headless refusal and the bypass flag.

The permission pack (`settings.snippet.json`, merged by `merge_permissions.py`) stays as an **optional
second lock** that does not depend on the hook — the same tiers under the plugin's prefixed rule names.
Merged, the two agree on every tool because both are generated from the same file (§5).

## 3. What the hook decides, and its two reaches

Keyed on the **bare** tool name (the last `__` segment), so a renamed server cannot move a tool between
tiers. Two reaches, deliberately different:

- **`deny` and `ask` apply to every Exabeam-named server** — the bundled bridge under any plugin key
  (`mcp__plugin_socxen_exabeam__…`, `mcp__plugin_soc_exabeam__…` after a vendor re-key), a manual
  `claude mcp add exabeam …` registration, a third party's server — because tightening is always safe.
  The matcher in `hooks.json` and the hook's own `is_ours` test are both case-insensitive on the word
  `exabeam` (Praxen 2026-09-07-004).
- **`allow` applies only to the bundled bridge** — the server named `plugin_<this plugin's name>_exabeam`,
  the name read from `identity.json` beside the hook. On any other Exabeam-named server an allow-tier tool
  gets **no decision**: the operator's own permission rules apply, exactly as the permission pack already
  spells it (its allow rules exist under the bundled prefix only). Granting the allow everywhere would have
  let a third party's server run prompt-free by naming itself well (Praxen 2026-09-07-003).

An operator's own settings rule on an allow-tier tool still wins: a `deny` removes the tool from the model's
list before the hook runs, an `ask` still prompts — the hook's allow removes only the *default* prompt.
Both verified live in default permission mode, headless, 2026-09-06. Returning no decision on the allow
tier instead would make every read prompt with nothing merged, which is the permission merge back under
another name.

## 4. Failure direction

**The gate never fails open.** If the tier file cannot be read, every tool asks. If the hook itself raises,
the decision is `ask` with the exception class in the reason — interactively the human decides, headless
the call is refused. The hook exits 0 always; the decision is the JSON on stdout, and `hooks.json` turns a
non-zero exit into a block (`|| exit 2`). The host needs a POSIX shell and `python3` 3.7+ on `PATH`;
without `python3` every gated call is refused, not allowed. The installer and `preflight.sh` verify that
the **installed** copy carries the hook before they report the gate as on (Praxen 2026-09-07-002: an
offline operator holding a hook-less older install must not read "gate ON").

## 5. One tier file, four enforcement points

`permissions.json` (bare names, three tiers, the MCP server key) is the only place the tiers are written.
`plugin/gen_identity.py` regenerates from it and from `identity.json`:

- `settings.snippet.json` — the permission pack, prefixed `mcp__plugin_<name>_exabeam__` and, for the
  manual path, `mcp__exabeam__` (ask and deny only);
- `.mcp.codex.json` — the Codex map: `default_tools_approval_mode: approve`, `approval_mode: auto` on the
  21 allow-tier tools, `approve` on the 3 ask-tier tools, the 70 deny-tier tools in `disabled_tools`;
- the hook reads `permissions.json` directly at call time (falling back to the snippet, stripped).

CI runs the generator's `--check`; the tier invariants in `tests/test_repo_invariants.py` pin that the
hook, the snippet and the Codex map cannot disagree, and that a re-key (a vendor catalog renaming the
plugin) moves the allow's prefix with it. Codex is slightly stricter than Claude on one point: Exabeam's
own annotation of `create_case` and `create_case_notes` makes Codex prompt on them regardless — that is
the platform's annotation, not socxen's tier, and the guides say so.

## 6. What the gate records

Each decision — including refusals and the near-miss that never reached the bridge — is appended
best-effort to `~/.socxen/gate.jsonl` with the call's **safe target fields** only: identifiers and
dispositions (`alertId`, `caseId`, `alertStatus`, `stage`, …), never free text, values capped. So a
refused attempt reads as "tried to dismiss alert X as false positive", which is the record that matters
in a SOC (#87). `SOCXEN_GATE_LOG=off` disables it; the bridge's audit trail records the calls that do
reach it ([logging guide](../../plugin/docs/logging.md)).

## 7. The model-side layer beneath

Each `SKILL.md` also instructs the model to ask before dismiss or close and never to claim or attempt
containment. That is doctrine, not enforcement: the Worker Remit states it as the layer *beneath* the host
gate (R-38), and it is what the red team measures when the write tools are offered — 100 hook-leg trials
on 2026-09-05 recorded zero attempts, so a doctrine-following model never reaches the hook. The corpus
therefore includes fixtures that provoke the attempt on purpose, so the hook's save is observable.

## 8. How it is verified

- **Deterministic, in CI:** `tests/test_hook_gate.py` (decision table, both reaches, unclassified,
  error → ask, the log's field allowlist), `test_merge_permissions.py`, `test_preflight_codex_override.py`
  (every TOML spelling of a Codex override), the tier invariants in `test_repo_invariants.py`.
- **Live, before every release:** the red team's **hook leg** (`--claude-gate hook`) offers the write
  tools under `--dangerously-skip-permissions` with the hook as the only thing in the way and the bridge
  dry run as backstop; a write that reaches the bridge is a hook miss and blocks the release. The standard
  Claude leg and the Codex leg withhold the write tools by host policy and rely on the dry run.
  [`security/redteam/METHODOLOGY.md`](../redteam/METHODOLOGY.md).
- **Praxen** checks the remit's gate rules against this code on every scan; the 2026-09-05 through
  2026-09-08 scans drove the reach split (§3), the installed-copy check (§4) and the `create_case`
  refusal in the bridge ([output-neutralizer record](output-neutralizer.md#5-two-write-rules-in-the-bridge-beside-the-neutralizer)).

## 9. Declared residuals

- A server registered by hand under a name **without** `exabeam` in it is outside the hook's reach; the
  guides say to name it `exabeam`, and `preflight.sh` warns when it sees an Exabeam server the gate does
  not reach.
- The "any other agent" install path (no plugin host) has no gate at all — the installation guide marks
  it evaluation-only.
- The permission pack governs MCP tools only; a host's own Bash, Write and Edit tools stay at the session
  default (tracked as an issue).
