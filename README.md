<!--
  Copyright 2026 Exabeam, Inc.
  SPDX-License-Identifier: Apache-2.0
-->

# socxen

**Agentic SOC analyst for Exabeam New-Scale** — a Claude Code plugin that triages
alerts and cases end to end through the Exabeam MCP: gathers evidence, correlates
activity, reaches a threat/false-positive verdict, and acts — with containment
recommended for human approval and dismiss/close gated by permission rules.

## Install

```bash
claude plugin marketplace add open-agent-ai-security/plugins
claude plugin install socxen@open-agent-ai-security
```

## Repository layout

The distributable plugin lives in **[`plugin/`](plugin/)** — that subdirectory is
the *only* thing installed on a user's machine (via a `git-subdir` marketplace
source). Everything else at the repo root is build-time only and never ships:

| Path | What it is |
|------|------------|
| [`plugin/`](plugin/) | the shipped plugin — skill, connector bridge, manifests, docs, LICENSE |
| [`plugin/README.md`](plugin/README.md) | **full documentation** — what socxen does, how it investigates, governance |
| `tests/` · `evals/` | test + regression harnesses |
| `security/` | AI BOM generator + red-team corpus |
| `scripts/` · `.github/` | release tooling + CI |

See **[`plugin/README.md`](plugin/README.md)** for the complete overview, and
[`plugin/docs/`](plugin/docs/) for installation, logging, and security-guardrails detail.

## License

[Apache-2.0](plugin/LICENSE). Contributions require a DCO sign-off — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
