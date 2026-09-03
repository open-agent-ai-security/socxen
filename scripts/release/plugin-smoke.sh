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
PLUGIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$(git rev-parse --show-toplevel)/plugin/identity.json" 2>/dev/null || echo socxen)"
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

# Read a worktree's plugin version, from whichever layout that ref carries. The PRIOR ref is
# routinely pre-#29 — on the first run after this restructure promotes, prior IS the last
# root-layout release — and hardcoding the plugin/ path made that a FileNotFoundError that killed
# the whole smoke run under set -e. Probe, don't assume. A genuinely missing manifest must still be
# a hard error (python raises, set -e stops us), never an empty version: that would sail through the
# current-vs-prior equality check below and silently smoke-test nothing.
version_at() {  # version_at <dir>
  local manifest="$1/plugin/.claude-plugin/plugin.json"
  if [ ! -f "$manifest" ]; then manifest="$1/.claude-plugin/plugin.json"; fi
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$manifest"
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
LAST_BUMP="$(git -C "${REPO_ROOT}" log -1 --follow --format=%H origin/main -- plugin/.claude-plugin/plugin.json)"
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
# marketplace.json was retired (#58). Re-fabricated after every checkout: when
# a checkout crosses the cutover boundary (prior ref tracks the path, target
# ref doesn't), git wants to delete the tracked copy and refuses over our
# untracked one — hence `checkout -f` at the version flip, which discards
# whatever is in the way before we immediately re-assert our manifest.
fabricate_marketplace() {  # fabricate_marketplace <worktree>
  # Point at the subdirectory THIS ref actually ships from: post-#29 refs serve ./plugin, older
  # ones serve the worktree root. Resolved per call, not once — the upgrade leg fabricates twice
  # against the same worktree, straddling the checkout that crosses the restructure boundary.
  local src="./"
  if [ -d "$1/plugin" ]; then src="./plugin"; fi
  mkdir -p "$1/.claude-plugin"
  python3 - "$1" "$src" <<'PY'
import json, sys
json.dump({"name": "open-agent-ai-security",
           "owner": {"name": "Open Agent AI Security",
                     "url": "https://github.com/open-agent-ai-security"},
           "plugins": [{"name": "socxen", "source": sys.argv[2]}]},
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
git -C "${WT_UPGRADE}" checkout -f --detach --quiet "${CURRENT_SHA}"   # marketplace dir now serves the new release (-f: see fabricate_marketplace)
fabricate_marketplace "${WT_UPGRADE}"                                  # re-assert ours over whatever the ref carries
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin marketplace update "${MARKETPLACE}" >/dev/null
CLAUDE_CONFIG_DIR="${CFG2}" claude plugin update "${PLUGIN}@${MARKETPLACE}" >/dev/null
assert_version "upgrade" "${CFG2}" "${CURRENT_VER}"

echo "leg 3: governance merge (--merge-permissions) into a throwaway settings.json"
# The gate is the control that makes socxen safe to point at real alerts, and the installer can now
# install it (#70) — so the release smoke has to prove the assisted path still works on the shipped
# tree, not just that the plugin registers.
#
# SOCXEN_SETTINGS_FILE is what makes this safe to run at all: install.sh would otherwise write the
# REAL ~/.claude/settings.json, and a release smoke that edits the maintainer's live governance
# config on every run is worse than no smoke. The containment is asserted, not assumed — the real
# file's digest is compared before and after, and a "PASS" that quietly rewrote it fails here.
#
# Deliberately NOT the version_at() probe pattern: falling back to a root install.sh would run a
# PRE-#70 installer that has no --merge-permissions at all, so the leg would "pass" having tested
# nothing. A release whose current ref predates the plugin/ layout can't run this leg, and must say
# so plainly rather than surfacing a file-not-found as an installer regression.
if [ ! -x "${WT_CURRENT}/plugin/install.sh" ]; then
  echo "  FAIL: current release (origin/main) predates the plugin/ layout — leg 3 needs a main at >=0.7.0; run after the promotion" >&2
  exit 1
fi
SMOKE_SETTINGS="${SCRATCH}/settings.json"
CFG3="${SCRATCH}/config-governance"; mkdir -p "${CFG3}"
REAL_SETTINGS="${HOME}/.claude/settings.json"
digest() { [ -f "$1" ] && (shasum "$1" 2>/dev/null || md5 -q "$1") | awk '{print $1}' || echo "<absent>"; }
REAL_BEFORE="$(digest "${REAL_SETTINGS}")"

SOCXEN_SETTINGS_FILE="${SMOKE_SETTINGS}" CLAUDE_CONFIG_DIR="${CFG3}" \
  "${WT_CURRENT}/plugin/install.sh" --skip-connectivity --skip-update --merge-permissions --no-color \
  >"${SCRATCH}/governance.log" 2>&1 || { echo "  FAIL: governance leg — installer exited non-zero" >&2; tail -20 "${SCRATCH}/governance.log" >&2; exit 1; }

# Gate ON = the dismiss/close pair sits specifically in `ask` — the same check install.sh's gate_on()
# makes. Merely mentioning the tools anywhere in the file must not read as installed.
if ! python3 - "${SMOKE_SETTINGS}" <<'PY'
import json, sys
try:
    ask = json.load(open(sys.argv[1])).get("permissions", {}).get("ask", [])
except Exception:
    sys.exit(1)
sys.exit(0 if {"exabeam_update_alert", "exabeam_update_case"} <= {t.split("__")[-1] for t in ask} else 1)
PY
then
  echo "  FAIL: governance merge — dismiss/close is not in the ask tier of ${SMOKE_SETTINGS}" >&2
  tail -20 "${SCRATCH}/governance.log" >&2; exit 1
fi
echo "  ok: governance merge — gate reads ON in the throwaway settings"

if [ "$(digest "${REAL_SETTINGS}")" != "${REAL_BEFORE}" ]; then
  echo "  FAIL: the smoke modified your real ${REAL_SETTINGS} — SOCXEN_SETTINGS_FILE is not being honored" >&2
  exit 1
fi
echo "  ok: real ~/.claude/settings.json untouched"

# Re-run must be a no-op: the installer is documented idempotent, and an assisted merge that
# double-appended on every release run would corrupt the operator's file over time.
SOCXEN_SETTINGS_FILE="${SMOKE_SETTINGS}" CLAUDE_CONFIG_DIR="${CFG3}" \
  "${WT_CURRENT}/plugin/install.sh" --skip-connectivity --skip-update --merge-permissions --no-color \
  >"${SCRATCH}/governance2.log" 2>&1 || { echo "  FAIL: governance re-run exited non-zero" >&2; exit 1; }
if ! grep -q "already merged" "${SCRATCH}/governance2.log"; then
  echo "  FAIL: governance re-run was not a no-op — expected 'already merged'" >&2
  tail -20 "${SCRATCH}/governance2.log" >&2; exit 1
fi
echo "  ok: governance merge is idempotent on re-run"

echo "smoke: PASS — clean ${CURRENT_VER}, upgrade ${PRIOR_VER} -> ${CURRENT_VER}, governance gate installs"
