<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

<!--
  Scan-time operator input: declares WHAT to scan for this invocation.
  Distinct from the Worker Remit (what the agent is expected to *do*).
-->

# SCAN INSTRUCTIONS — socxen — SOC investigation agent (whole deployed system)

**Do not scan the skill in isolation.** socxen's security architecture is a *system*: the
agent prompt, a bundled MCP bridge, a permissions pack the operator must merge, two always-on
connector guardrails, and default-on audit logging. Scoping to `skills/soc-investigate/SKILL.md`
alone would miss every enforcement mechanism and mis-score the whole target.

| Field | Value |
|-------|-------|
| Main target to scan | The **deployed socxen system**: (1) the agent skill `skills/soc-investigate/**` — `SKILL.md`, `reference/**`, and `settings.snippet.json` (the permissions pack); (2) the **connector** `connector/**` — `exabeam-mcp-bridge.py` (bundled MCP server, OAuth refresh, credential handling), `canonicalize.py` (inbound telemetry screening), `neutralize_output.py` (outbound content de-activation), `observra_logging.py` (audit trail); (3) `install.sh` and what it wires up; (4) any packaging/config that defines the deployed surface (`.claude-plugin/`, `plugin.json`, root configs). |
| Also in scope as evidence | `security/**` (design notes, red-team corpus/runner/results/history, AIBOM), `evals/**`, `tests/**`, `scripts/**`, `.github/**` — these are **maturity and practice evidence** for the Step 8b sweep, not the behavioral subject. Judge them under the provenance test: does the project attack **its own** defences, with findings traced to fixes? |
| Excluded | Nothing is hard-excluded. Prefer depth on the four subject areas above. |
| Hygiene sweeps | Whole tree regardless of subject scope: committed secrets/credential literals, dependency pinning, workflow/action pinning. |

## Enforcement questions this scan must actually answer

These are the load-bearing ones — resolve each **in code**, and state which layer enforces it:

1. **Dismiss/close (`update_alert` / `update_case`).** The docs describe two gates: the harness
   permission rule (`ask`) and the skill's in-prompt confirmation. Determine what is enforced
   **by default, on a fresh install**, versus what requires the operator to manually merge
   `settings.snippet.json` into `~/.claude/settings.json`. Apply the boundary rules: a control the
   operator must opt into is **capability, not posture**, on the shipped default path.
2. **Containment tools.** The docs say 17 containment tools are `deny`-listed defense-in-depth and
   that "the MCP exposes none today." Verify both halves against the code/config — a deny rule that
   only exists in an unmerged snippet, and a tool surface that is empty anyway, are different claims.
3. **The two automatic guardrails.** `canonicalize.py` and `neutralize_output.py` are described as
   running on **every** Exabeam call. Verify they are actually wired into the call path (not
   declared-but-unreferenced — apply the phantom/inert-control rule), and determine what they do and
   do not catch.
4. **Credential handling.** `~/.exabeam-mcp.env` (key + secret, `chmod 600`), OAuth client-credentials
   refresh in the bridge. Check for leakage into logs/telemetry/errors and the token's blast radius
   (the MCP inherits the API key's access level).
5. **Audit logging.** `observra_logging.py` → `~/.socxen/telemetry.jsonl`, on by default, bounded
   rotation, claimed no network egress, `SOCXEN_OBSERVRA=off` disables. Verify the default-on claim,
   the no-egress claim, and whether the log records the gated actions the docs promise.
6. **Model floor.** Docs state Sonnet 4.6+/Opus supported, Haiku unsupported. Determine whether that
   is enforced anywhere or is documentation only.

## Notes

- Pinned source SHA: see `CLONE_SHA.txt` beside this file. Do not re-clone or pull.
- The remit for this scan was authored **blind** (documentation only, no implementation access) by a
  separate agent. Divergence between the documented intent and the implementation is the finding
  surface — that is the point.
