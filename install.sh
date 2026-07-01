#!/usr/bin/env bash
#
# socxen installer — adds the marketplace, installs the soc-investigate skill into
# Claude Code, and runs a connectivity preflight. Idempotent; safe to re-run.
#
# Usage:
#   ./install.sh                     install at user scope, then check connectivity
#   ./install.sh --checks-only       run diagnostics only (no install/changes)
#   ./install.sh --skip-connectivity install but skip the live MCP check
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
ASSUME_YES=0; CHECKS_ONLY=0; SKIP_CONN=0; USE_COLOR=1
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --checks-only) CHECKS_ONLY=1 ;;
    --skip-connectivity) SKIP_CONN=1 ;;
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

# ---- install (unless --checks-only) ----
if [ "$CHECKS_ONLY" = 0 ]; then
  head2 "Install"
  if claude plugin marketplace list 2>/dev/null | grep -qiE "(^|[^a-z])${MARKETPLACE_NAME}([^a-z]|$)|${MARKETPLACE_REPO}"; then
    step "Marketplace '${MARKETPLACE_NAME}' present — updating"
    claude plugin marketplace update "${MARKETPLACE_NAME}" >/dev/null 2>&1 && ok "Marketplace updated" || warn "Marketplace update reported an issue"
  else
    step "Adding marketplace ${MARKETPLACE_REPO}"
    claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null 2>&1 && ok "Marketplace added" || fail "Marketplace add failed"
  fi
  step "Installing ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
  if claude plugin install "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}" >/dev/null 2>&1; then
    ok "Plugin installed"
  elif claude plugin update "${PLUGIN}" >/dev/null 2>&1; then
    ok "Plugin already present — updated"
  else
    fail "Plugin install/update failed — run 'claude plugin install ${PLUGIN}@${MARKETPLACE_NAME}' to see the error"
  fi
else
  head2 "Install"; skip "skipped (--checks-only)"
fi

# plugin presence (info)
if claude plugin list 2>/dev/null | grep -qi "${PLUGIN}"; then
  ok "Plugin registered with Claude Code"
else
  [ "$CHECKS_ONLY" = 1 ] && skip "Plugin not installed (run without --checks-only)" || warn "Plugin not visible in 'claude plugin list' — restart Claude Code"
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
head2 "Governance"
SETTINGS="$HOME/.claude/settings.json"
if [ -f "$SETTINGS" ] && grep -q "update_alert" "$SETTINGS" 2>/dev/null; then
  ok "Governance gate detected in settings.json (dismiss/close is gated)"
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
