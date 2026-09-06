#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# socxen preflight — read-only diagnostics, on any host agent.
#
# Everything socxen needs to actually work is the same on Claude Code and on Codex:
# credentials, a toolchain, and a bridge that can reach the tenant. Only the
# human-in-the-loop gate is stored differently, so only the gate check branches.
#
# This script NEVER writes. Not to settings.json, not to config.toml, not to the
# credentials file. On both hosts the gate ships inside the plugin (a PreToolUse hook on Claude
# Code, approval policy on Codex). The Claude permission rules are an optional second lock that
# `install.sh --merge-permissions` writes with consent; a fixer here would re-import that consent
# problem, so this stays a mirror, not a hand.
#
# Usage:
#   preflight.sh                       detect the host agent and check everything
#   preflight.sh --platform codex      force a host (claude | codex | none)
#   preflight.sh --skip-connectivity   skip the live MCP call
#   preflight.sh --no-color
#
# Exit: 0 when nothing failed, 1 when something did. Warnings do not fail.
#
# install.sh sources this file for the shared checks; sourcing defines functions and reads the
# identity include — it runs no checks. The UI helpers are only defined if the caller has not
# already defined them.

# Identity from identity.sh (GENERATED from identity.json by gen_identity.py; no python3 needed). The same
# SOCXEN_PLUGIN / SOCXEN_MARKETPLACE overrides install.sh honors apply here, so a remediation message
# names the key the operator actually installed. Both halves come from the same source or neither does:
# a key stitched from one real half and one guessed half is one no marketplace serves.
_PF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_PF_DIR/identity.sh" ]; then . "$_PF_DIR/identity.sh"; fi
PLUGIN_NAME="${SOCXEN_PLUGIN:-${SOCXEN_ID_NAME:-}}"
_PF_MKT="${SOCXEN_MARKETPLACE:-${SOCXEN_ID_MARKETPLACE_NAME:-}}"
if [ -n "$PLUGIN_NAME" ] && [ -n "$_PF_MKT" ]; then
  PLUGIN_KEY="${PLUGIN_NAME}@${_PF_MKT}"
else
  PLUGIN_NAME="${PLUGIN_NAME:-plugin}"
  PLUGIN_KEY="<plugin>@<marketplace>  (identity.sh missing — regenerate with python3 $_PF_DIR/gen_identity.py)"
fi


# ---- ui (only if the sourcing script has not already provided these) ----
# Palette as a function, not a one-shot assignment: --no-color is parsed inside preflight_main,
# which runs AFTER this file loads, so assigning here only would make the documented flag a no-op
# on a TTY (it silently "worked" whenever stdout was already a pipe). preflight_main re-derives.
_palette() {
  if [ "${USE_COLOR:-1}" = 1 ] && [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
    CYAN=$'\033[1;36m'; GRN=$'\033[1;32m'; YLW=$'\033[1;33m'; RED=$'\033[1;31m'; GRY=$'\033[0;90m'
  else
    BOLD=""; DIM=""; RST=""; CYAN=""; GRN=""; YLW=""; RED=""; GRY=""
  fi
}

if ! declare -F ok >/dev/null 2>&1; then
  _palette
  PASS=0; WARN_N=0; FAIL=0; SUMMARY=()
  ok()   { printf '   %s✓%s %s\n'  "$GRN" "$RST" "$1"; PASS=$((PASS+1)); SUMMARY+=("${GRN}✓${RST} $1"); }
  warn() { printf '   %s!%s %s\n'  "$YLW" "$RST" "$1"; WARN_N=$((WARN_N+1)); SUMMARY+=("${YLW}!${RST} $1"); }
  fail() { printf '   %s✗%s %s\n'  "$RED" "$RST" "$1"; FAIL=$((FAIL+1)); SUMMARY+=("${RED}✗${RST} $1"); }
  skip() { printf '   %s↷ %s%s\n'  "$GRY" "$1" "$RST"; SUMMARY+=("${GRY}↷ $1${RST}"); }
  step() { printf '   %s▸%s %s\n'  "$CYAN" "$RST" "$1"; }
  head2(){ printf '\n%s   %s%s\n' "$BOLD" "$1" "$RST"; }
  hr()   { printf '%s   ────────────────────────────────────────────────────%s\n' "$GRY" "$RST"; }
fi

: "${ENV_FILE:=${EXABEAM_ENV_FILE:-$HOME/.exabeam-mcp.env}}"
: "${CREDS_OK:=0}"

# ---- host detection ----
# Which agent is this install for? Both CLIs can be present on one machine, so an explicit
# --platform always wins; otherwise prefer the one whose plugin cache actually holds socxen,
# and fall back to whichever CLI exists.
detect_platform() {
  if [ -n "${SOCXEN_PLATFORM:-}" ]; then printf '%s' "$SOCXEN_PLATFORM"; return; fi
  local has_claude=0 has_codex=0
  command -v claude >/dev/null 2>&1 && has_claude=1
  command -v codex  >/dev/null 2>&1 && has_codex=1
  if [ "$has_claude" = 1 ] && [ "$has_codex" = 1 ]; then
    # Both installed — let an actual socxen install break the tie.
    if codex mcp get exabeam >/dev/null 2>&1; then printf 'codex'; else printf 'claude'; fi
  elif [ "$has_codex" = 1 ]; then printf 'codex'
  elif [ "$has_claude" = 1 ]; then printf 'claude'
  else printf 'none'; fi
}

# ---- shared checks (identical on every host) ----

check_toolchain() {
  if command -v uv >/dev/null 2>&1; then
    ok "uv present — $(uv --version 2>/dev/null)"
  else
    warn "uv not found — the bundled Exabeam bridge needs it: https://docs.astral.sh/uv/"
  fi
  if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
      ok "python3 present ($(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null))"
    else
      fail "python3 is older than 3.7 — the bundled dismiss/close gate (hooks/gate.py) cannot run on it, and the hook fails closed (every gated call refused). Install a current python3."
    fi
  else
    # A failure only where the gate needs it: on Claude Code the bundled hook is python3. On Codex the gate
    # is approval policy and the bridge runs under uv's own interpreter, so a python3-less Codex host is a
    # healthy install and "warnings do not fail" holds (review, 2026-09-05).
    if [ "${PF_PLATFORM:-}" = claude ]; then
      fail "python3 not found — the bundled dismiss/close gate (hooks/gate.py) cannot execute. The hook is wired to fail closed (every gated call is refused until python3 is on PATH), so install python3: https://www.python.org/downloads/"
    else
      warn "python3 not found — fine on this host (the gate is approval policy here); on a Claude Code host the bundled hook would need it"
    fi
  fi
}

# The bundled hook, as INSTALLED: the copy Claude Code actually loads (claude plugin list --json), enabled,
# with hooks/hooks.json in it. The plugin copy this script sits in proves nothing about the install --
# a clone with the hook beside an older installed version read "gate ON" (review, 2026-09-05).
# Prints: "on <version> <path>" | "off <version> <path>" (installed copy has no hook) | "none" | "unknown".
installed_hook_state() {
  local json key="${PLUGIN_KEY:-socxen@open-agent-ai-security}"
  command -v claude >/dev/null 2>&1 || { printf 'unknown'; return; }
  command -v python3 >/dev/null 2>&1 || { printf 'unknown'; return; }
  json="$(claude plugin list --json 2>/dev/null)" || { printf 'unknown'; return; }
  printf '%s' "$json" | python3 -c '
import json, os, sys
key = sys.argv[1]
try:
    plugins = json.load(sys.stdin)
except Exception:
    print("unknown"); sys.exit(0)
hits = [p for p in plugins if p.get("id") == key and p.get("enabled", True)]
if not hits:
    print("none"); sys.exit(0)
p = hits[0]
path = p.get("installPath") or ""
state = "on" if path and os.path.isfile(os.path.join(path, "hooks", "hooks.json")) else "off"
print(state, p.get("version") or "unknown", path)
' "$key" 2>/dev/null || printf 'unknown'
}

# Sets CREDS_OK=1 when the file exists and carries all three keys. Reports the file mode but
# never changes it: 0600 is advice here, exactly as it is in install.sh.
check_credentials() {
  CREDS_OK=0
  if [ ! -f "$ENV_FILE" ]; then
    warn "No credentials yet — create $ENV_FILE (see Next steps)"
    return
  fi
  local missing="" k perms
  for k in EXABEAM_MCP_URL EXABEAM_API_KEY EXABEAM_API_SECRET; do
    grep -q "^${k}=" "$ENV_FILE" 2>/dev/null || missing="$missing $k"
  done
  if [ -n "$missing" ]; then
    warn "Credentials file present but missing:$missing"
    return
  fi
  CREDS_OK=1; ok "Credentials — $ENV_FILE (all keys present)"
  perms="$(stat -f '%A' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE" 2>/dev/null || echo '?')"
  [ "$perms" = "600" ] || warn "  $ENV_FILE is mode $perms — consider: chmod 600 $ENV_FILE"
}

# The one check that proves the whole path works: same bridge, same --check, on both hosts.
check_connectivity() {
  local bridge="${BRIDGE:-$SCRIPT_DIR/connector/exabeam-mcp-bridge.py}" out
  if [ "${SKIP_CONN:-0}" = 1 ]; then
    skip "MCP connectivity check skipped (--skip-connectivity)"
  elif [ "$CREDS_OK" = 0 ]; then
    skip "MCP connectivity check skipped — add credentials first"
  elif ! command -v uv >/dev/null 2>&1; then
    skip "MCP connectivity check skipped — uv not installed"
  elif [ ! -f "$bridge" ]; then
    skip "MCP connectivity check skipped — bridge not found (run from a cloned repo)"
  else
    step "Connecting to Exabeam MCP via the bundled bridge…"
    if out="$(uv run --quiet "$bridge" --check 2>&1)"; then
      ok "Exabeam MCP reachable — ${out##*OK — }"
    else
      warn "Could not reach the Exabeam MCP: $(printf '%s' "$out" | tail -1)"
    fi
  fi
}

# ---- gate check (the only part that differs by host) ----

# Claude Code: this reads the OPTIONAL permission rules in the operator's settings.json; the gate
# itself is the bundled hook (checked in check_gate). Three outcomes, not two — without python3 the
# check CANNOT run, and "cannot verify" must never be reported as "OFF".
gate_state_claude() {
  local settings="${SOCXEN_SETTINGS_FILE:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json}"
  command -v python3 >/dev/null 2>&1 || { printf 'unknown'; return; }
  [ -f "$settings" ] || { printf 'off'; return; }
  if python3 - "$settings" <<'PY' 2>/dev/null
import json, sys
try:
    ask = json.load(open(sys.argv[1])).get("permissions", {}).get("ask", [])
except Exception:
    sys.exit(1)
bare = {t.split("__")[-1] for t in ask}
sys.exit(0 if {"exabeam_update_alert", "exabeam_update_case"} <= bare else 1)
PY
  then printf 'on'; else printf 'off'; fi
}

# Codex: the gate ships inside the plugin, so this reads the resolved server config. ON means Codex
# resolved both halves — the approve default and the containment deny-list. Codex itself prompts for
# approval for the Exabeam write tools (annotated destructive) in every mode and refuses them when no
# human is present, so the dismiss/close gate needs nothing merged. A missing server reads as "unknown".
# Does any config.toml loosen a per-tool approval mode on a gated write?
#
# `codex mcp get` prints the server's default mode and disabled_tools, but NOT per-tool
# overrides — so an operator who sets ONLY exabeam_update_case to "auto" leaves a server
# that still reports 'default: approve' while dismiss/close runs unattended. Reading the
# resolved server config alone therefore produces a false green on precisely the change
# that matters most, which is the dangerous direction.
#
# This does not resolve TOML — it detects that an override exists and refuses to claim
# green, which is the conservative half of the job and the only half worth doing here. An
# override that TIGHTENS the gate reads as "overridden" too; safe direction, and rare.
codex_write_override() {
  local f
  for f in "${CODEX_HOME:-$HOME/.codex}/config.toml" "./.codex/config.toml"; do
    [ -f "$f" ] || continue
    awk '
      /^[[:space:]]*\[/ {
        ingate = ($0 ~ /tools\.exabeam_update_(alert|case)\]/) ? 1 : 0
        next
      }
      ingate && /approval_mode/ {
        if ($0 !~ /"approve"/) { print "loose"; exit }
      }
    ' "$f" | grep -q loose && { printf 'yes'; return; }
  done
  printf 'no'
}

gate_state_codex() {
  local out
  command -v codex >/dev/null 2>&1 || { printf 'unknown'; return; }
  out="$(codex mcp get exabeam 2>/dev/null)" || { printf 'unknown'; return; }
  [ -n "$out" ] || { printf 'unknown'; return; }
  if printf '%s' "$out" | grep -q 'default_tools_approval_mode: *approve' \
     && printf '%s' "$out" | grep -q 'disabled_tools:'; then
    [ "$(codex_write_override)" = "yes" ] && { printf 'overridden'; return; }
    printf 'on'
  else
    printf 'off'
  fi
}

check_gate() {
  local platform="$1" state
  case "$platform" in
    codex)
      state="$(gate_state_codex)"
      case "$state" in
        on)  ok "Human-in-the-loop gate ON — containment disabled by the plugin; Codex requires approval for the destructive write tools and refuses them with no human present" ;;
        overridden)
             fail "Gate WEAKENED by local config — a config.toml sets a per-tool approval_mode on update_alert/update_case; dismiss/close may run unattended" ;;
        off) fail "Gate is not active on the resolved Exabeam server — reinstall: codex plugin add ${PLUGIN_KEY}" ;;
        *)   warn "Cannot verify the gate — no 'exabeam' server resolved (is the plugin installed and enabled?)" ;;
      esac ;;
    claude)
      state="$(gate_state_claude)"
      case "$state" in
        on)  ok "Human-in-the-loop gate ON — the bundled hook asks on dismiss/close and denies containment, and the permission rules are merged too" ;;
        off) local hook hstate hver hpath
             hook="$(installed_hook_state)"; hstate="${hook%% *}"; hver="$(printf '%s' "$hook" | awk '{print $2}')"; hpath="$(printf '%s' "$hook" | awk '{print $3}')"
             case "$hstate" in
               on)  ok "Human-in-the-loop gate ON via the bundled hook in the INSTALLED plugin (${hver} at ${hpath}) — asks on dismiss/close, denies containment, holds even under --dangerously-skip-permissions"
                    ok "Permission rules not merged — not needed: the hook gates dismiss/close, denies containment and allows the reads. Merging adds a second lock that does not depend on the hook: install.sh --merge-permissions" ;;
               off) fail "Gate is OFF — the installed plugin (${hver} at ${hpath}) predates the bundled hook and no permission rules are merged; update the plugin (install.sh), or merge with: install.sh --merge-permissions" ;;
               none) fail "Gate is OFF — the plugin is not installed or not enabled for Claude Code (${PLUGIN_KEY:-socxen@open-agent-ai-security}) and no permission rules are merged; install it (install.sh)" ;;
               *)   if [ -f "${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/hooks/hooks.json" ]; then
                      warn "Cannot verify the installed plugin (needs the claude CLI with 'plugin list --json' and python3). This plugin copy carries the bundled hook, but only the INSTALLED copy gates — check 'claude plugin list'"
                    else
                      fail "Gate is OFF — no bundled hook in this plugin copy, the install cannot be verified, and no permission rules merged; reinstall, or merge with: install.sh --merge-permissions"
                    fi ;;
             esac ;;
        *)   warn "Cannot verify the permission rules (needs python3) — not the same as OFF. Note the bundled hook also needs python3: without it every gated call is refused (fail-closed), not allowed" ;;
      esac ;;
    *)
      skip "Gate check skipped — no host agent detected" ;;
  esac
}

# ---- standalone entry point ----

preflight_main() {
  local platform=""
  # A while/shift loop, not `for arg in "$@"`: `--platform codex` needs to consume its value,
  # and a `shift` inside a for-loop does not advance the loop variable — the value came back
  # round as an unknown option.
  while [ $# -gt 0 ]; do
    case "$1" in
      --platform=*) platform="${1#*=}" ;;
      --platform)   shift; platform="${1:-}"
                    [ -n "$platform" ] || { printf '--platform needs a value (claude|codex|none)\n' >&2; return 2; } ;;
      --skip-connectivity) SKIP_CONN=1 ;;
      --no-color) USE_COLOR=0 ;;
      -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; return 0 ;;
      *) printf 'unknown option: %s (try --help)\n' "$1" >&2; return 2 ;;
    esac
    shift
  done
  case "${platform:-auto}" in
    claude|codex|none|auto) ;;
    *) printf 'unknown platform: %s (want claude|codex|none)\n' "$platform" >&2; return 2 ;;
  esac
  [ "$platform" = "auto" ] && platform=""
  [ -n "$platform" ] || platform="$(detect_platform)"
  PF_PLATFORM="$platform"
  _palette          # re-derive now that --no-color has actually been parsed

  printf '\n%s   %s preflight%s  %s(read-only — nothing is written)%s\n' "$BOLD" "$PLUGIN_NAME" "$RST" "$DIM" "$RST"

  head2 "Host agent"
  case "$platform" in
    claude) ok "Claude Code — $(claude --version 2>/dev/null | head -1)" ;;
    codex)  ok "OpenAI Codex — $(codex --version 2>/dev/null | head -1)" ;;
    *)      warn "No host agent CLI found (looked for 'claude' and 'codex')" ;;
  esac

  head2 "Toolchain";    check_toolchain
  head2 "Credentials";  check_credentials
  head2 "Connectivity"; check_connectivity
  head2 "Governance";   check_gate "$platform"

  hr
  printf '\n%s   Summary%s   %s%d ok%s · %s%d warn%s · %s%d fail%s\n\n' \
    "$BOLD" "$RST" "$GRN" "$PASS" "$RST" "$YLW" "$WARN_N" "$RST" "$RED" "$FAIL" "$RST"
  local line; for line in "${SUMMARY[@]}"; do printf '     %b\n' "$line"; done
  printf '\n'
  [ "$FAIL" -gt 0 ] && return 1 || return 0
}

# Run only when executed directly; sourcing defines the checks and runs nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -euo pipefail
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  preflight_main "$@"
fi
