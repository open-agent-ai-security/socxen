#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Post-release plugin install smoke — run after promoting dev -> main.
#
# Exercises both real Claude Code journeys in throwaway scratch config dirs,
# never touching your live install:
#   Leg 1 (clean):   add the COMMUNITY marketplace (open-agent-ai-security/plugins,
#                    whose socxen entry pins this repo's main) + plugin install.
#                    This is the documented install path, end to end over the network.
#   Leg 2 (upgrade): install the PRIOR release, then marketplace update +
#                    plugin update to the current one — the exact re-run path
#                    that silently went stale before the #43 fix. Since the
#                    in-repo marketplace was retired (#58 hard cutover), this
#                    leg fabricates a minimal same-named marketplace manifest
#                    inside a throwaway worktree to make the version rewind
#                    locally controllable.
#
# socxen has no tags, so "releases" are resolved from git history:
#   current = origin/main@HEAD
#   prior   = the commit just before the last change to plugin.json on main
#             (i.e. the previous version), overridable as $1.
#
# Usage: scripts/release/plugin-smoke.sh [prior-ref]
# Run from anywhere inside the repo. Requires: git, python3, claude.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
PLUGIN="socxen"
MARKETPLACE="open-agent-ai-security"
MARKETPLACE_REPO="open-agent-ai-security/plugins"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/socxen-smoke.XXXXXX")"
WT_CURRENT="${SCRATCH}/wt-current"
WT_UPGRADE="${SCRATCH}/wt-upgrade"

cleanup() {
  git -C "${REPO_ROOT}" worktree remove --force "${WT_CURRENT}" 2>/dev/null || true
  git -C "${REPO_ROOT}" worktree remove --force "${WT_UPGRADE}" 2>/dev/null || true
  rm -rf "${SCRATCH}"
}
trap cleanup EXIT

version_at() {  # version_at <dir>
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' \
    "$1/.claude-plugin/plugin.json"
}

installed_version() {  # installed_version <config-dir>
  CLAUDE_CONFIG_DIR="$1" claude plugin list --json 2>/dev/null | python3 -c '
import json, sys
plugins = json.load(sys.stdin)
print(next((p.get("version") or "" for p in plugins
            if p.get("id") == "'"${PLUGIN}@${MARKETPLACE}"'"), ""))'
}

assert_version() {  # assert_version <leg> <config-dir> <expected>
  local got
  got="$(installed_version "$2")"
  if [ "${got}" = "$3" ]; then
    echo "  ok: ${1} — installed version ${got}"
  else
    echo "  FAIL: ${1} — expected version ${3}, got '${got:-<not installed>}'" >&2
    exit 1
  fi
}

git -C "${REPO_ROOT}" fetch origin --quiet
CURRENT_SHA="$(git -C "${REPO_ROOT}" rev-parse origin/main)"
LAST_BUMP="$(git -C "${REPO_ROOT}" log -1 --format=%H origin/main -- .claude-plugin/plugin.json)"
PRIOR_REF="${1:-${LAST_BUMP}^}"
PRIOR_SHA="$(git -C "${REPO_ROOT}" rev-parse "${PRIOR_REF}")"

git -C "${REPO_ROOT}" worktree add --detach --quiet "${WT_CURRENT}" "${CURRENT_SHA}"
git -C "${REPO_ROOT}" worktree add --detach --quiet "${WT_UPGRADE}" "${PRIOR_SHA}"

CURRENT_VER="$(version_at "${WT_CURRENT}")"
PRIOR_VER="$(version_at "${WT_UPGRADE}")"
echo "smoke: current ${CURRENT_VER} (origin/main ${CURRENT_SHA:0:7}), prior ${PRIOR_VER} (${PRIOR_SHA:0:7})"
if [ "${CURRENT_VER}" = "${PRIOR_VER}" ]; then
  echo "  FAIL: current and prior resolve to the same version (${CURRENT_VER}) — pass a prior-ref explicitly" >&2
  exit 1
fi

# Write a minimal marketplace manifest into a worktree so it can be added as a
# local marketplace under the community marketplace's name. Needed for the
# upgrade leg (rewindable source) and for worktrees at refs after the in-repo
# marketplace.json was retired (#58). Untracked, so a later `git checkout
# --detach` in the worktree leaves it in place.
fabricate_marketplace() {  # fabricate_marketplace <worktree>
  mkdir -p "$1/.claude-plugin"
  python3 - "$1" <<'PY'
import json, sys
json.dump({"name": "open-agent-ai-security",
           "owner": {"name": "Open Agent AI Security",
                     "url": "https://github.com/open-agent-ai-security"},
           "plugins": [{"name": "socxen", "source": "./"}]},
          open(sys.argv[1] + "/.claude-plugin/marketplace.json", "w"))
PY
}

echo "leg 1: clean install of ${CURRENT_VER} from the community marketplace (${MARKETPLACE_REPO})"
CFG1="${SCRATCH}/config-clean"; mkdir -p "${CFG1}"
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "clean install" "${CFG1}" "${CURRENT_VER}"

echo "leg 2: upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
CFG2="${SCRATCH}/config-upgrade"; mkdir -p "${CFG2}"
git -C "${WT_UPGRADE}" rm -q --cached .claude-plugin/marketplace.json 2>/dev/null || true  # pre-#58 refs track it; make ours the only copy
fabricate_marketplace "${WT_UPGRADE}"
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace add "${WT_UPGRADE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "prior install" "${CFG2}" "${PRIOR_VER}"
git -C "${WT_UPGRADE}" checkout --detach --quiet "${CURRENT_SHA}"   # marketplace dir now serves the new release
fabricate_marketplace "${WT_UPGRADE}"                               # re-assert ours over whatever the ref carries
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace update "${MARKETPLACE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin update "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "upgrade" "${CFG2}" "${CURRENT_VER}"

echo "smoke: PASS — clean ${CURRENT_VER}, upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
