#!/usr/bin/env bash
#
# socxen installer — adds the marketplace, installs the soc-investigate skill into
# Claude Code, and runs a connectivity preflight. Idempotent; safe to re-run.
#
# Usage:
#   ./install.sh                     install at user scope, then check connectivity
#   ./install.sh --checks-only       run diagnostics only (no install/changes)
#   ./install.sh --skip-connectivity install but skip the live MCP check
#   ./install.sh --skip-update       keep an existing install as-is (e.g. offline re-runs)
#   ./install.sh -y                  non-interactive (assume yes)
#   ./install.sh --no-color          plain output
#   ./install.sh -h | --help
#
# Env (all overridable):
#   SOCXEN_SCOPE=user|project   SOCXEN_REPO   SOCXEN_MARKETPLACE   SOCXEN_PLUGIN
set -euo pipefail

MARKETPLACE_REPO="${SOCXEN_REPO:-open-agent-ai-security/socxen}"
MARKETPLACE_NAME="${SOCXEN_MARKETPLACE:-socxen}"
PLUGIN="${SOCXEN_PLUGIN:-socxen}"
SCOPE="${SOCXEN_SCOPE:-user}"
ENV_FILE="${EXABEAM_ENV_FILE:-$HOME/.exabeam-mcp.env}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRIDGE="$SCRIPT_DIR/connector/exabeam-mcp-bridge.py"

# ---- flags ----
ASSUME_YES=0; CHECKS_ONLY=0; SKIP_CONN=0; SKIP_UPDATE=0; USE_COLOR=1
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --checks-only) CHECKS_ONLY=1 ;;
    --skip-connectivity) SKIP_CONN=1 ;;
    --skip-update) SKIP_UPDATE=1 ;;
    --no-color) USE_COLOR=0 ;;
    -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done
[ -t 1 ] || USE_COLOR=0

# ---- palette ----
if [ "$USE_COLOR" = 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
  CYAN=$'\033[1;36m'; GRN=$'\033[1;32m'; YLW=$'\033[1;33m'; RED=$'\033[1;31m'; GRY=$'\033[0;90m'; MAG=$'\033[1;35m'
else
  BOLD=""; DIM=""; RST=""; CYAN=""; GRN=""; YLW=""; RED=""; GRY=""; MAG=""
fi

# ---- ui ----
PASS=0; WARN_N=0; FAIL=0; SUMMARY=()
banner() {
  printf '%s' "$MAG"
  cat <<'ART'
   ███████╗ ██████╗  ██████╗██╗  ██╗███████╗███╗   ██╗
   ██╔════╝██╔═══██╗██╔════╝╚██╗██╔╝██╔════╝████╗  ██║
   ███████╗██║   ██║██║      ╚███╔╝ █████╗  ██╔██╗ ██║
   ╚════██║██║   ██║██║      ██╔██╗ ██╔══╝  ██║╚██╗██║
   ███████║╚██████╔╝╚██████╗██╔╝ ██╗███████╗██║ ╚████║
   ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
ART
  printf '%s        agentic SOC analyst · Claude Code skill%s\n\n' "$DIM" "$RST"
}
hr()   { printf '%s   ────────────────────────────────────────────────────%s\n' "$GRY" "$RST"; }
head2(){ printf '\n%s   %s%s\n' "$BOLD" "$1" "$RST"; }
ok()   { printf '   %s✓%s %s\n'  "$GRN" "$RST" "$1"; PASS=$((PASS+1)); SUMMARY+=("${GRN}✓${RST} $1"); }
warn() { printf '   %s!%s %s\n'  "$YLW" "$RST" "$1"; WARN_N=$((WARN_N+1)); SUMMARY+=("${YLW}!${RST} $1"); }
fail() { printf '   %s✗%s %s\n'  "$RED" "$RST" "$1"; FAIL=$((FAIL+1)); SUMMARY+=("${RED}✗${RST} $1"); }
skip() { printf '   %s↷ %s%s\n'  "$GRY" "$1" "$RST"; SUMMARY+=("${GRY}↷ $1${RST}"); }
step() { printf '   %s▸%s %s\n'  "$CYAN" "$RST" "$1"; }

banner

# ---- preflight checks ----
head2 "Preflight"

# claude CLI (required)
if command -v claude >/dev/null 2>&1; then
  ok "Claude Code CLI — $(claude --version 2>/dev/null | head -1)"
else
  fail "Claude Code CLI not found — install it first: https://claude.com/claude-code"
  echo; printf '   %sCannot continue without the claude CLI.%s\n' "$RED" "$RST"; exit 1
fi

# uv (needed by the bundled bridge)
if command -v uv >/dev/null 2>&1; then
  ok "uv present — $(uv --version 2>/dev/null)"
else
  warn "uv not found — the bundled Exabeam bridge needs it: https://docs.astral.sh/uv/"
fi

# python3 (used to read installed-plugin state and verify the governance gate)
if command -v python3 >/dev/null 2>&1; then
  ok "python3 present"
else
  warn "python3 not found — plugin-state detection and the governance-gate check will be degraded"
fi

# credentials file
CREDS_OK=0
if [ -f "$ENV_FILE" ]; then
  missing=""
  for k in EXABEAM_MCP_URL EXABEAM_API_KEY EXABEAM_API_SECRET; do
    grep -q "^${k}=" "$ENV_FILE" 2>/dev/null || missing="$missing $k"
  done
  if [ -z "$missing" ]; then
    CREDS_OK=1; ok "Credentials — $ENV_FILE (all keys present)"
    perms="$(stat -f '%A' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')"
    [ "$perms" = "600" ] || warn "  $ENV_FILE is mode $perms — consider: chmod 600 $ENV_FILE"
  else
    warn "Credentials file present but missing:$missing"
  fi
else
  warn "No credentials yet — create $ENV_FILE (see the Next steps below)"
fi

# Version of ${PLUGIN}@${MARKETPLACE_NAME} installed at scope $1 (any scope if omitted); prints
# empty if absent. Returns 1 when the state CANNOT be determined (no python3, an older claude CLI
# without 'plugin list --json') — callers must treat that as unknown, not as absent, or a present
# plugin would be "installed" over (a 0-exit no-op) and silently left stale. JSON + exact id/scope
# match: grepping `claude plugin list` would match substrings, other scopes, and can die of
# SIGPIPE under pipefail when grep -q exits early.
installed_version() {
  local json
  json="$(claude plugin list --json 2>/dev/null)" || return 1
  printf '%s' "$json" | python3 -c '
import json, sys
spec = sys.argv[1]
scope = sys.argv[2] if len(sys.argv) > 2 else None
try:
    plugins = json.load(sys.stdin)
except Exception:
    sys.exit(1)
print(next((p.get("version", "") for p in plugins
            if p.get("id") == spec and (scope is None or p.get("scope") == scope)), ""))
' "${PLUGIN}@${MARKETPLACE_NAME}" ${1:+"$1"} 2>/dev/null || return 1
}

# ---- install (unless --checks-only) ----
if [ "$CHECKS_ONLY" = 0 ]; then
  head2 "Install"
  # capture-then-grep (not a live pipeline): grep -q exiting early + pipefail can SIGPIPE the CLI
  mkts="$(claude plugin marketplace list 2>/dev/null || true)"
  if grep -qiE "(^|[^a-z])${MARKETPLACE_NAME}([^a-z]|$)|${MARKETPLACE_REPO}" <<<"$mkts"; then
    step "Marketplace '${MARKETPLACE_NAME}' present — updating"
    claude plugin marketplace update "${MARKETPLACE_NAME}" >/dev/null 2>&1 && ok "Marketplace updated" || warn "Marketplace update reported an issue"
  else
    step "Adding marketplace ${MARKETPLACE_REPO}"
    claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null 2>&1 && ok "Marketplace added" || fail "Marketplace add failed"
  fi
  # `claude plugin install` exits 0 without updating when the plugin is already installed at this
  # scope, and `claude plugin update` requires the full name@marketplace spec plus --scope (bare
  # name is rejected; scope defaults to user) — so pick the verb by what's installed at ${SCOPE},
  # and report the outcome by comparing versions, not by parsing the CLI's message wording.
  # PLUGIN_OUTCOME feeds the presence line below: a version string / "installed" / "updated" on
  # success, empty on failure.
  PLUGIN_OUTCOME=""
  if before="$(installed_version "${SCOPE}")"; then
    if [ -n "$before" ]; then
      if [ "$SKIP_UPDATE" = 1 ]; then
        skip "Update skipped (--skip-update) — plugin stays at ${before}"
        PLUGIN_OUTCOME="$before"
      else
        step "Plugin present at ${SCOPE} scope (${before}) — updating ${PLUGIN}@${MARKETPLACE_NAME}"
        if claude plugin update "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}" >/dev/null 2>&1; then
          after="$(installed_version "${SCOPE}")" || after=""
          if [ -n "$after" ] && [ "$after" != "$before" ]; then
            ok "Plugin updated ${before} → ${after} — restart Claude Code to apply"
            PLUGIN_OUTCOME="$after"
          elif [ "$after" = "$before" ]; then
            ok "Plugin already at the latest version (${before})"
            PLUGIN_OUTCOME="$before"
          else
            # update succeeded but the re-read failed — assume it applied; never report
            # "already at the latest version" for an update we couldn't verify.
            ok "Plugin update completed — restart Claude Code to apply"
            PLUGIN_OUTCOME="updated"
          fi
        else
          # A real failure the operator must see (exit 1) — the plugin keeps working at the old
          # version meanwhile. For deliberate offline re-runs, --skip-update avoids the attempt.
          fail "Plugin update failed (still at ${before}) — run 'claude plugin update ${PLUGIN}@${MARKETPLACE_NAME}' to see the error, or use --skip-update"
          PLUGIN_OUTCOME="$before"
        fi
      fi
    else
      step "Installing ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
      if claude plugin install "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}" >/dev/null 2>&1; then
        ok "Plugin installed (scope: ${SCOPE})"
        PLUGIN_OUTCOME="installed"
      else
        fail "Plugin install failed — run 'claude plugin install ${PLUGIN}@${MARKETPLACE_NAME}' to see the error"
      fi
    fi
  else
    # Installed state unknown (no python3 / older CLI without --json). Update-then-install keeps
    # an existing install fresh and a missing one installed without knowing which case this is:
    # update fails when absent (then install runs); install alone would 0-exit-no-op when present.
    warn "Cannot read installed-plugin state (needs python3 and a claude CLI with 'plugin list --json')"
    step "Trying update, then install — ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
    if [ "$SKIP_UPDATE" = 0 ] && claude plugin update "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}" >/dev/null 2>&1; then
      ok "Plugin updated to the latest version — restart Claude Code to apply"
      PLUGIN_OUTCOME="updated"
    elif claude plugin install "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}" >/dev/null 2>&1; then
      ok "Plugin installed (scope: ${SCOPE})"
      PLUGIN_OUTCOME="installed"
    else
      fail "Plugin install/update failed — run 'claude plugin install ${PLUGIN}@${MARKETPLACE_NAME}' to see the error"
    fi
  fi
else
  head2 "Install"; skip "skipped (--checks-only)"
fi

# plugin presence (info). Checks-only queries live (any scope — an install at another scope is
# still a working install); otherwise the install block above already knows the outcome, so don't
# spend another CLI round-trip re-deriving it.
if [ "$CHECKS_ONLY" = 1 ]; then
  if anyv="$(installed_version)"; then
    if [ -n "$anyv" ]; then
      ok "Plugin registered with Claude Code (${anyv})"
    else
      skip "Plugin not installed (run without --checks-only)"
    fi
  else
    skip "Plugin state unknown — needs python3 and a claude CLI with 'plugin list --json'"
  fi
elif [ -n "$PLUGIN_OUTCOME" ]; then
  ok "Plugin registered with Claude Code"
else
  warn "Plugin not registered — see the install failure above"
fi

# ---- connectivity ----
head2 "Connectivity"
if [ "$SKIP_CONN" = 1 ]; then
  skip "MCP connectivity check skipped (--skip-connectivity)"
elif [ "$CREDS_OK" = 0 ]; then
  skip "MCP connectivity check skipped — add credentials first"
elif ! command -v uv >/dev/null 2>&1; then
  skip "MCP connectivity check skipped — uv not installed"
elif [ ! -f "$BRIDGE" ]; then
  skip "MCP connectivity check skipped — bridge not found (run from a cloned repo)"
else
  step "Connecting to Exabeam MCP via the bundled bridge…"
  if out="$(uv run --quiet "$BRIDGE" --check 2>&1)"; then
    ok "Exabeam MCP reachable — ${out##*OK — }"
  else
    warn "Could not reach the Exabeam MCP: $(printf '%s' "$out" | tail -1)"
  fi
fi

# ---- governance reminder (info) ----
# A false "gate is ON" is the dangerous direction, so verify the close tools are specifically in the
# `ask` tier — not merely that settings.json mentions them (a mis-merge into allow/deny must read as OFF).
head2 "Governance"
SETTINGS="$HOME/.claude/settings.json"
gate_on() {
  [ -f "$SETTINGS" ] || return 1
  python3 - "$SETTINGS" <<'PY' 2>/dev/null
import json, sys
try:
    ask = json.load(open(sys.argv[1])).get("permissions", {}).get("ask", [])
except Exception:
    sys.exit(1)
bare = {t.split("__")[-1] for t in ask}
sys.exit(0 if {"exabeam_update_alert", "exabeam_update_case"} <= bare else 1)
PY
}
if gate_on; then
  ok "Governance gate ON — dismiss/close (update_alert/update_case) is in the ask tier"
else
  warn "Governance not merged — the dismiss/close hard-gate is OFF until you merge settings.snippet.json"
fi

# ---- summary ----
hr
printf '\n%s   Summary%s   %s%d ok%s · %s%d warn%s · %s%d fail%s\n\n' \
  "$BOLD" "$RST" "$GRN" "$PASS" "$RST" "$YLW" "$WARN_N" "$RST" "$RED" "$FAIL" "$RST"
for line in "${SUMMARY[@]}"; do printf '     %b\n' "$line"; done

if [ "$CREDS_OK" = 0 ]; then
  cat <<NEXT

${BOLD}   Next steps${RST}
   1. Add your Exabeam credentials — create ${ENV_FILE} (then chmod 600):
        EXABEAM_MCP_URL=https://api.<region>.exabeam.cloud/mcp
        EXABEAM_API_KEY=<your key>
        EXABEAM_API_SECRET=<your secret>
   2. Merge the ${BOLD}permissions${RST} block from
      skills/soc-investigate/settings.snippet.json into ~/.claude/settings.json
      ${YLW}⚠ don't run with --dangerously-skip-permissions (it disables the gate).${RST}
   3. Restart Claude Code, then:  ${CYAN}"investigate alert <id>"${RST}
NEXT
else
  printf '\n%s   Ready.%s Restart Claude Code, then:  %s"investigate alert <id>"%s\n' "$GRN" "$RST" "$CYAN" "$RST"
fi

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
