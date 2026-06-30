#!/usr/bin/env bash
#
# socxen installer — adds the marketplace and installs the soc-investigate skill
# into Claude Code via the `claude` CLI. Idempotent; safe to re-run to update.
#
# Requires: the `claude` CLI on PATH, and (git/gh) access to the repo.
# Usage:    ./install.sh           # install at user scope
#           SOCXEN_SCOPE=project ./install.sh
#
set -euo pipefail

MARKETPLACE_REPO="${SOCXEN_REPO:-open-agent-ai-security/socxen}"
MARKETPLACE_NAME="${SOCXEN_MARKETPLACE:-socxen}"
PLUGIN="${SOCXEN_PLUGIN:-socxen}"
SCOPE="${SOCXEN_SCOPE:-user}"

say()  { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }

command -v claude >/dev/null 2>&1 || {
  echo "claude CLI not found on PATH — install Claude Code first: https://claude.com/claude-code" >&2
  exit 1
}
say "Using $(claude --version 2>/dev/null | head -1)"

# 1) Add (or refresh) the marketplace — idempotent.
if claude plugin marketplace list 2>/dev/null | grep -qiE "(^|[^a-z])${MARKETPLACE_NAME}([^a-z]|$)|${MARKETPLACE_REPO}"; then
  say "Marketplace '${MARKETPLACE_NAME}' already configured — updating"
  claude plugin marketplace update "${MARKETPLACE_NAME}"
else
  say "Adding marketplace: ${MARKETPLACE_REPO}"
  claude plugin marketplace add "${MARKETPLACE_REPO}"
fi

# 2) Install (or update) the plugin.
say "Installing ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
if ! claude plugin install "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}"; then
  warn "install reported an issue (already installed?) — trying update"
  claude plugin update "${PLUGIN}"
fi

# 3) Confirm.
say "Installed plugins:"
claude plugin list 2>/dev/null | grep -i "${PLUGIN}" || claude plugin list 2>/dev/null || true

cat <<'NEXT'

✓ socxen installed. Two steps remain (per-environment):

  1. Connect Exabeam — from a clone of this repo, run:
       ./connector/connect-exabeam.sh
     Paste your API key + secret once; it installs a small bridge that handles the
     OAuth token automatically and registers the `exabeam` MCP.

  2. (Recommended) Merge the governance permissions into ~/.claude/settings.json:
       the "permissions" block from skills/soc-investigate/settings.snippet.json
       — gates update_alert / update_case, denies containment as defense-in-depth.
     ⚠️ Don't run with --dangerously-skip-permissions; it disables that gate.

Then restart Claude Code and ask:  "investigate alert <id>"
NEXT
