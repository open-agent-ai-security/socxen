#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Post-release plugin install smoke — run after promoting dev -> main.
#
# Exercises both real Claude Code journeys in throwaway scratch config dirs,
# never touching your live install:
#   Leg 1 (clean):   marketplace add + plugin install of the current release
#   Leg 2 (upgrade): install the PRIOR release, then marketplace update +
#                    plugin update to the current one — the exact re-run path
#                    that silently went stale before the #43 fix.
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
MARKETPLACE="socxen"
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

echo "leg 1: clean install of ${CURRENT_VER}"
CFG1="${SCRATCH}/config-clean"; mkdir -p "${CFG1}"
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin marketplace add "${WT_CURRENT}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG1}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "clean install" "${CFG1}" "${CURRENT_VER}"

echo "leg 2: upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
CFG2="${SCRATCH}/config-upgrade"; mkdir -p "${CFG2}"
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace add "${WT_UPGRADE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin install "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "prior install" "${CFG2}" "${PRIOR_VER}"
git -C "${WT_UPGRADE}" checkout --detach --quiet "${CURRENT_SHA}"   # marketplace dir now serves the new release
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace update "${MARKETPLACE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin update "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "upgrade" "${CFG2}" "${CURRENT_VER}"

echo "smoke: PASS — clean ${CURRENT_VER}, upgrade ${PRIOR_VER} -> ${CURRENT_VER}"
