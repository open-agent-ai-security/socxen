#!/usr/bin/env bash
# Copyright 2026 Exabeam, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# socxen installer — adds the marketplace, installs the soc-investigate skill into
# Claude Code, and runs a connectivity preflight. Idempotent; safe to re-run.
#
# Claude Code only, deliberately. Most of this script is `claude plugin` CLI handling plus
# the governance-gate merge, and Codex needs neither: its gate ships inside the plugin, so
# installing there is just `codex plugin marketplace add` + `codex plugin add`. The checks
# that ARE shared — credentials, toolchain, live connectivity — live in preflight.sh, which
# this script sources and Codex users run directly:
#
#   ./preflight.sh                 read-only diagnostics on either host agent
#
# Usage — run it as ./plugin/install.sh from a clone of the repo, or ./install.sh from inside the
# installed plugin directory (the payload ships under plugin/, so the two differ):
#   install.sh                     install at user scope, then check connectivity
#   install.sh --checks-only       run diagnostics only (no install/changes)
#   install.sh --merge-permissions merge the governance gate into the resolved settings file
#                                  (SOCXEN_SETTINGS_FILE below), NOT always ~/.claude/settings.json
#   install.sh --skip-connectivity install but skip the live MCP check
#   install.sh --skip-update       keep an existing install as-is (e.g. offline re-runs)
#   install.sh -y                  non-interactive (assume yes; never merges on its own)
#   install.sh --no-color          plain output
#   install.sh -h | --help
#
# Env (all overridable):
#   SOCXEN_SCOPE=user|project   SOCXEN_REPO   SOCXEN_MARKETPLACE   SOCXEN_PLUGIN
#   SOCXEN_SETTINGS_FILE        the settings.json the governance gate is checked/merged in
set -euo pipefail

MARKETPLACE_REPO="${SOCXEN_REPO:-open-agent-ai-security/plugins}"
MARKETPLACE_NAME="${SOCXEN_MARKETPLACE:-open-agent-ai-security}"
PLUGIN="${SOCXEN_PLUGIN:-socxen}"
SCOPE="${SOCXEN_SCOPE:-user}"
ENV_FILE="${EXABEAM_ENV_FILE:-$HOME/.exabeam-mcp.env}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRIDGE="$SCRIPT_DIR/connector/exabeam-mcp-bridge.py"

# ---- flags ----
ASSUME_YES=0; CHECKS_ONLY=0; SKIP_CONN=0; SKIP_UPDATE=0; USE_COLOR=1; MERGE_PERMS=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --checks-only) CHECKS_ONLY=1 ;;
    --merge-permissions) MERGE_PERMS=1 ;;
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
# Sourced, not exec'd: preflight.sh defines its checks and runs nothing when sourced, and its UI
# helpers defer to the ones defined above so counters and summary stay shared.
# shellcheck source=./preflight.sh
. "$SCRIPT_DIR/preflight.sh"

head2 "Preflight"

# claude CLI (required)
if command -v claude >/dev/null 2>&1; then
  ok "Claude Code CLI — $(claude --version 2>/dev/null | head -1)"
else
  fail "Claude Code CLI not found — install it first: https://claude.com/claude-code"
  echo; printf '   %sCannot continue without the claude CLI.%s\n' "$RED" "$RST"
  if command -v codex >/dev/null 2>&1; then
    printf '\n   %sOn Codex?%s This installer is Claude-Code-only, and Codex does not need one —\n' "$BOLD" "$RST"
    printf '   the gate ships inside the plugin, so there is nothing to merge:\n\n'
    printf '     %scodex plugin marketplace add %s%s\n' "$CYAN" "$MARKETPLACE_REPO" "$RST"
    printf '     %scodex plugin add %s@%s%s\n' "$CYAN" "$PLUGIN" "$MARKETPLACE_NAME" "$RST"
    printf '     %s%s/preflight.sh%s   %s(checks credentials and connectivity)%s\n\n' \
      "$CYAN" "$SCRIPT_DIR" "$RST" "$DIM" "$RST"
  fi
  exit 1
fi

# Host-neutral checks live in preflight.sh so the two entry points cannot drift: a credentials
# or connectivity check that behaves differently depending on which script you ran is exactly the
# bug that reproduces on one platform and not the other.
check_toolchain
check_credentials

# Version of ${PLUGIN}@${MARKETPLACE_NAME} installed at scope $1 (any scope if omitted). Prints
# empty ONLY when the plugin is genuinely absent; a present entry with no version field prints
# "unknown" so it still routes to the update path. Returns 1 when the state CANNOT be determined
# at all (no python3, an older claude CLI without 'plugin list --json') — callers must treat that
# as unknown, not as absent, or a present plugin would be "installed" over (a 0-exit no-op) and
# silently left stale. JSON + exact id/scope match: grepping `claude plugin list` would match
# substrings, other scopes, and can die of SIGPIPE under pipefail when grep -q exits early.
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
print(next(((p.get("version") or "unknown") for p in plugins
            if p.get("id") == spec and (scope is None or p.get("scope") == scope)), ""))
' "${PLUGIN}@${MARKETPLACE_NAME}" ${1:+"$1"} 2>/dev/null || return 1
}

# No redirection in the helpers — one call site captures stderr for diagnostics.
plugin_install_cmd() { claude plugin install "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}"; }
plugin_update_cmd()  { claude plugin update  "${PLUGIN}@${MARKETPLACE_NAME}" --scope "${SCOPE}"; }

# Escape a user-overridable name (SOCXEN_REPO etc.) for interpolation into an ERE, so the
# patterns below can stay boundary-anchored (a bare -F substring match would let
# 'acme/socxensuite' pass for 'socxen') without regex metacharacters breaking grep.
esc_ere() { printf '%s' "$1" | sed 's/[][\.|$(){}?+*^]/\\&/g'; }

# Does this 'claude plugin list' (plain) output contain ${PLUGIN}@${MARKETPLACE_NAME} as a
# standalone id? Boundary excludes [alnum]_- continuation so 'socxen@open-agent-ai-security-dev' never matches.
plugin_listed() {
  grep -Eqi "(^|[^[:alnum:]_-])$(esc_ere "${PLUGIN}@${MARKETPLACE_NAME}")([^[:alnum:]_-]|$)" <<<"$1"
}

# ---- install (unless --checks-only) ----
if [ "$CHECKS_ONLY" = 0 ]; then
  head2 "Install"
  # Presence must be judged on the NAME+SOURCE pair, not a substring of the whole listing:
  # every legacy repo-hosted marketplace's source contains 'open-agent-ai-security', and a
  # marketplace with OUR name but a different source (the old praxen repo-hosted one) must
  # be re-pointed, not silently updated as if it were the right catalog. Prefer the structured
  # `--json` listing (same rationale as the plugin_listed --json path below); the pretty-print
  # awk scrape survives only as the older-CLI fallback. "ours" means the recorded source
  # RESOLVES to github.com/<repo> — parsed, not string-matched, so that neither the scp form
  # (`git@github.com:owner/repo.git`, colon not slash) nor a lookalike host
  # (`https://evil.example/x/github.com/owner/repo.git`) is misjudged.
  # MKT_FRESH qualifies "already/updated to the latest version" below — a version compare against
  # stale marketplace metadata can't rule out a newer upstream release.
  MKT_FRESH=1
  # Live pipeline is safe here (unlike the text path below): json.load() drains stdin to EOF
  # before this can exit, so the CLI is never SIGPIPEd. Exit 3 on any shape we don't recognise
  # -> the `||` fallback runs; "cannot determine" must never render as "absent".
  mkt_state="$(claude plugin marketplace list --json 2>/dev/null | python3 -c '
import json, re, sys
from urllib.parse import urlsplit
name, repo = sys.argv[1], sys.argv[2]
try:
    mkts = json.load(sys.stdin)
except Exception:
    sys.exit(3)  # no/invalid --json (older CLI) -> caller falls back to the text parse
if not isinstance(mkts, list):
    sys.exit(3)  # unrecognised shape -> unknown, not absent

def resolves_to(target):
    """True when target is a github.com URL/slug for exactly <repo>."""
    t = str(target or "").strip()
    if not t:
        return False
    m = re.match(r"^(?:[^@/]+@)?([^/:]+):(?!//)(.+)$", t)   # scp-like: [user@]host:path
    if m:
        host, path = m.group(1), m.group(2)
    elif "://" in t:
        u = urlsplit(t)
        host, path = u.netloc.rsplit("@", 1)[-1], u.path     # drop any userinfo
    else:
        host, path = "github.com", t                          # bare owner/repo slug
    host = host.split(":")[0].lower()                         # drop any port
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return host == "github.com" and path == repo

for m in mkts:
    if not isinstance(m, dict) or m.get("name") != name:
        continue
    src = str(m.get("source") or "")
    target = m.get("repo") if src == "github" else (m.get("url") or m.get("repo"))
    print("ours" if resolves_to(target) else "other")
    break
' "${MARKETPLACE_NAME}" "${MARKETPLACE_REPO}" 2>/dev/null )" || {
    # capture-then-parse (not a live pipeline): an early-exiting consumer + pipefail can
    # SIGPIPE the CLI. Name lines carry no ':' ("❯ <name>") while detail lines do
    # ("Source: GitHub (owner/repo)" / "Source: Git (https://github.com/owner/repo.git)") —
    # that, not the marker glyph, is the parse. The source must match to END of line in one of
    # the three known forms, so a lookalike host embedding our slug doesn't read as ours.
    mkts="$(claude plugin marketplace list 2>/dev/null || true)"
    mkt_state="$(awk -v name="${MARKETPLACE_NAME}" -v repo="$(esc_ere "${MARKETPLACE_REPO}")" '
      !/:/ && NF { cur = $NF; next }
      /Source:/ && cur == name {
        ok = ($0 ~ "\\(" repo "\\)[[:space:]]*$") \
          || ($0 ~ "\\(https://github\\.com/" repo "(\\.git)?/?\\)[[:space:]]*$") \
          || ($0 ~ "\\(git@github\\.com:" repo "(\\.git)?\\)[[:space:]]*$")
        print (ok ? "ours" : "other"); exit
      }
    ' <<<"$mkts")"
  }
  if [ "$mkt_state" = "ours" ]; then
    step "Marketplace '${MARKETPLACE_NAME}' present — updating"
    if claude plugin marketplace update "${MARKETPLACE_NAME}" >/dev/null 2>&1; then
      ok "Marketplace updated"
    else
      warn "Marketplace update reported an issue — plugin versions may lag upstream"
      MKT_FRESH=0
    fi
  elif [ "$mkt_state" = "other" ]; then
    # Re-point in place. `marketplace add` under an existing name replaces its source
    # losslessly — installed plugins keep working — so never advise `marketplace remove`
    # here: that WOULD uninstall them (e.g. a praxen install from the legacy path).
    step "Marketplace '${MARKETPLACE_NAME}' points elsewhere — re-pointing to ${MARKETPLACE_REPO}"
    if claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null 2>&1; then
      ok "Marketplace re-pointed to ${MARKETPLACE_REPO} (existing plugins unaffected)"
    else
      fail "Could not re-point marketplace '${MARKETPLACE_NAME}' — run 'claude plugin marketplace add ${MARKETPLACE_REPO}' to see the error"
      MKT_FRESH=0
    fi
  else
    step "Adding marketplace ${MARKETPLACE_REPO}"
    if claude plugin marketplace add "${MARKETPLACE_REPO}" >/dev/null 2>&1; then
      ok "Marketplace added"
    else
      fail "Marketplace add failed"
      MKT_FRESH=0
    fi
  fi
  # `claude plugin install` exits 0 without updating when the plugin is already installed at this
  # scope, and `claude plugin update` requires the full name@marketplace spec plus --scope (bare
  # name is rejected; scope defaults to user) — so pick the verb by what's installed at ${SCOPE},
  # and report the outcome by comparing versions, not by parsing the CLI's message wording.
  # PLUGIN_OUTCOME = what this block established is present at ${SCOPE} after it ran: a version
  # string, "installed", "updated", or "present". It is deliberately non-empty after a FAILED
  # update too (the old version remains installed and working). Empty = no install is known to
  # exist at ${SCOPE}; the presence line below then checks other scopes before warning.
  PLUGIN_OUTCOME=""
  if before="$(installed_version "${SCOPE}")"; then
    if [ -n "$before" ]; then
      if [ "$SKIP_UPDATE" = 1 ]; then
        skip "Update skipped (--skip-update) — plugin stays at ${before}"
        PLUGIN_OUTCOME="$before"
      else
        step "Plugin present at ${SCOPE} scope (${before}) — updating ${PLUGIN}@${MARKETPLACE_NAME}"
        if uerr="$(plugin_update_cmd 2>&1)"; then
          # Verified live (claude CLI 2.1.210): 'plugin list --json' reflects the new version
          # immediately after 'plugin update' returns — the restart only applies it to running
          # sessions — so an unchanged version here really does mean "no newer version".
          if after="$(installed_version "${SCOPE}")"; then
            if [ -n "$after" ] && [ "$after" != "$before" ]; then
              ok "Plugin updated ${before} → ${after} — restart Claude Code to apply"
              PLUGIN_OUTCOME="$after"
            elif [ "$after" = "$before" ]; then
              if [ "$MKT_FRESH" = 1 ]; then
                ok "Plugin already at the latest version (${before})"
              else
                ok "Plugin at the latest locally-known version (${before}) — the marketplace refresh failed, so upstream may be newer"
              fi
              PLUGIN_OUTCOME="$before"
            else
              # the re-read worked and the plugin is GONE at this scope — not a read failure
              warn "Update succeeded but the plugin is no longer listed at ${SCOPE} scope — check 'claude plugin list'"
            fi
          else
            # update succeeded but the re-read failed — assume it applied; never report
            # "already at the latest version" for an update we couldn't verify.
            ok "Plugin update completed — restart Claude Code to apply"
            PLUGIN_OUTCOME="updated"
          fi
        else
          # Deliberate trade (do not "fix" one way without the other): the header promises
          # "Idempotent; safe to re-run" and the installed plugin keeps working at ${before},
          # so a failed update check (offline, GitHub blip, revoked repo) is a WARNING with the
          # CLI's error surfaced — not an exit 1 that turns a re-run on a healthy machine into
          # a provisioning failure. Persistent breakage stays visible: every run repeats the
          # warning with the underlying error. --skip-update skips the attempt entirely.
          # tr strips backslashes/control chars: the summary renderer prints entries with %b,
          # which would otherwise expand escape sequences inside the CLI's error text.
          uline="$(printf '%s' "$uerr" | tail -1 | tr -d '\\' | tr -cd '[:print:]')"
          warn "Plugin update failed — still at ${before} (${uline}); re-run when online, or use --skip-update"
          PLUGIN_OUTCOME="$before"
        fi
      fi
    else
      step "Installing ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
      if plugin_install_cmd >/dev/null 2>&1; then
        ok "Plugin installed (scope: ${SCOPE})"
        PLUGIN_OUTCOME="installed"
      else
        fail "Plugin install failed — run 'claude plugin install ${PLUGIN}@${MARKETPLACE_NAME}' to see the error"
      fi
    fi
  else
    # Installed state unknown (no python3 / older CLI without --json). Update-then-install:
    # update succeeds only when the plugin is present (and freshens it); when update fails,
    # install covers the absent case. But a 0-exit install can ALSO be a no-op on a present,
    # stale plugin — with update having just failed, we cannot tell those apart, so that
    # branch reports a warning ("possibly stale"), never a green "installed". The presence
    # re-check below independently verifies whatever these commands claim.
    warn "Cannot read installed-plugin state (needs python3 and a claude CLI with 'plugin list --json')"
    if [ "$SKIP_UPDATE" = 1 ]; then
      # honor the flag's offline purpose: attempt nothing network-touching on unknown state
      skip "Plugin state unknown and --skip-update set — leaving everything as-is"
      PLUGIN_OUTCOME="skipped"
    else
      step "Trying update, then install — ${PLUGIN}@${MARKETPLACE_NAME} (scope: ${SCOPE})"
      if plugin_update_cmd >/dev/null 2>&1; then
        if [ "$MKT_FRESH" = 1 ]; then
          ok "Plugin updated to the latest version — restart Claude Code to apply"
        else
          ok "Plugin updated to the latest locally-known version — the marketplace refresh failed, so upstream may be newer; restart Claude Code to apply"
        fi
        PLUGIN_OUTCOME="updated"
      elif plugin_install_cmd >/dev/null 2>&1; then
        warn "Plugin present — freshly installed, or already there and possibly stale; run 'claude plugin update ${PLUGIN}@${MARKETPLACE_NAME} --scope ${SCOPE}' when online to be sure"
        PLUGIN_OUTCOME="present"
      else
        fail "Plugin install/update failed — run 'claude plugin install ${PLUGIN}@${MARKETPLACE_NAME}' to see the error"
      fi
    fi
  fi
else
  head2 "Install"; skip "skipped (--checks-only)"
fi

# plugin presence (info). Checks-only queries live (any scope — an install at another scope is
# still a working install), with a python-free plain-list fallback so the diagnostic mode never
# answers "unknown" when 'claude plugin list' can answer. After an install/update, this is an
# INDEPENDENT live re-check (one plain 'plugin list'): a 0-exit install/update whose registration
# didn't actually land must not be reported green on the strength of its exit code alone.
if [ "$CHECKS_ONLY" = 1 ]; then
  if anyv="$(installed_version)"; then
    if [ -n "$anyv" ]; then
      ok "Plugin registered with Claude Code (${anyv})"
    else
      skip "Plugin not installed (run without --checks-only)"
    fi
  else
    plist="$(claude plugin list 2>/dev/null || true)"
    if plugin_listed "$plist"; then
      ok "Plugin registered with Claude Code (version unknown — older CLI or no python3)"
    else
      skip "Plugin not installed (run without --checks-only)"
    fi
  fi
else
  plist="$(claude plugin list 2>/dev/null || true)"
  if plugin_listed "$plist"; then
    if [ -n "$PLUGIN_OUTCOME" ]; then
      ok "Plugin registered with Claude Code"
    elif anyv="$(installed_version)" && [ -n "$anyv" ]; then
      warn "Not installed at ${SCOPE} scope (see the failure above), but a ${anyv} install exists at another scope and still works"
    else
      warn "Install at ${SCOPE} scope failed (see above), but a socxen install is visible in 'claude plugin list'"
    fi
  else
    case "$PLUGIN_OUTCOME" in
      skipped) skip "Plugin not installed (skipped by --skip-update)" ;;
      "")      warn "Plugin not registered — see the install failure above" ;;
      *)       warn "Install/update reported success, but the plugin is not visible in 'claude plugin list' — restart Claude Code and re-run with --checks-only" ;;
    esac
  fi
fi

# ---- connectivity ----
head2 "Connectivity"
check_connectivity

# ---- governance ----
# A false "gate is ON" is the dangerous direction, so verify the close tools are specifically in the
# `ask` tier — not merely that settings.json mentions them (a mis-merge into allow/deny must read as OFF).
# Three outcomes, not two: without python3 the check CANNOT run, which must read as "cannot verify",
# never as "gate is OFF" (that would send users re-merging a working gate).
head2 "Governance"
# Check and merge the settings file Claude Code will actually READ. Hardcoding
# ~/.claude/settings.json was survivable while this block only reported the gate's state (it could
# read a file the running Claude Code ignores, and mis-report ON — the dangerous direction); once we
# can WRITE it, the same assumption would merge the gate into a file that never takes effect, i.e.
# a green "gate ON" protecting nothing. CLAUDE_CONFIG_DIR relocates Claude's config dir (the release
# smoke script isolates whole installs with it), and SOCXEN_SETTINGS_FILE is the explicit override —
# same escape hatch EXABEAM_ENV_FILE gives the credentials path, and what lets an automated test
# exercise the merge without writing the operator's real settings.
SETTINGS="${SOCXEN_SETTINGS_FILE:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json}"
SNIPPET="$SCRIPT_DIR/skills/soc-investigate/settings.snippet.json"
MERGER="$SCRIPT_DIR/skills/soc-investigate/merge_permissions.py"
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

# Why the merge can't run, or "" when it can. The snippet and the merger ship beside each other in
# the skill directory, so normally they are both present or both absent (marketplace-only installs
# have neither — install.sh is a clone-path tool) — but report which one is missing so a partial
# checkout doesn't masquerade as an unsupported install path.
merge_blocker() {
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 not found'
  elif [ ! -f "$SNIPPET" ]; then
    printf 'settings.snippet.json not found (run from a cloned repo)'
  elif [ ! -f "$MERGER" ]; then
    printf 'merge_permissions.py not found (run from a cloned repo)'
  fi
}

# Run the merger and report. Mirrors its four exit codes; every path that ends with the gate not ON
# is reported as such. Verification is the pre-existing gate_on() re-read, NOT the merger's own exit
# code: the same "a 0-exit doesn't prove it landed" discipline the install block uses above.
run_merge() {
  local out rc
  out="$(python3 "$MERGER" --snippet "$SNIPPET" --settings "$SETTINGS" 2>&1)" && rc=0 || rc=$?
  case "$rc" in
    0|10)
      if ! gate_on; then
        # merger reported success but the gate still doesn't read ON — never call that green
        fail "Merge reported success but the gate still reads OFF — inspect $SETTINGS"
      elif [ "$rc" = 10 ]; then
        ok "Governance gate ON — permissions were already merged, nothing to change"
      else
        ok "Governance gate ON — merged into $SETTINGS; restart Claude Code to apply"
      fi
      ;;
    20) fail "Governance merge stopped — a rule already sits in a different tier (nothing was written)" ;;
    *)  fail "Governance merge failed — nothing was written; merge $SNIPPET into $SETTINGS by hand" ;;
  esac
  [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/     /' || true
}

# --checks-only promises "no install/changes" — that promise outranks a merge request.
if [ "$CHECKS_ONLY" = 1 ] && [ "$MERGE_PERMS" = 1 ]; then
  skip "--merge-permissions ignored under --checks-only (diagnostics change nothing) — re-run without it"
  MERGE_PERMS=0
fi

BLOCKER="$(merge_blocker)"
if ! command -v python3 >/dev/null 2>&1; then GATE_STATE=unknown
elif gate_on; then GATE_STATE=on
else GATE_STATE=off
fi

if [ "$MERGE_PERMS" = 1 ] && [ -n "$BLOCKER" ]; then
  # Same "cannot do it ≠ pretend it's done" discipline as the gate check: say why, give the manual path.
  warn "Cannot merge permissions ($BLOCKER) — merge the permissions block from settings.snippet.json into $SETTINGS by hand"
elif [ "$MERGE_PERMS" = 1 ]; then
  # Explicitly requested: the flag IS the consent, so no second confirmation. The merger is additive,
  # backs up first, and refuses on tier conflicts, so re-running is safe even when the gate reads ON
  # (a hand-merge of just the two ask lines leaves the whole containment deny list missing).
  step "Merging governance permissions into $SETTINGS"
  run_merge
elif [ "$GATE_STATE" = unknown ]; then
  warn "Cannot verify the governance gate (python3 not found) — check that settings.snippet.json is merged into $SETTINGS"
elif [ "$GATE_STATE" = on ]; then
  ok "Governance gate ON — dismiss/close (update_alert/update_case) is in the ask tier"
elif [ -n "$BLOCKER" ] || [ "$ASSUME_YES" = 1 ] || [ ! -t 0 ]; then
  # Gate is OFF and we can't ask (no tty, or -y). Note that -y does NOT stand in for consent here:
  # "assume yes" answers the installer's own questions, it does not authorise writing to the
  # operator's settings.json. Installation alone must never change that file (#70 non-goal).
  warn "Governance not merged — the dismiss/close hard-gate is OFF until you merge settings.snippet.json (or re-run with --merge-permissions)"
else
  # Gate is OFF, we're interactive, and we can do something about it — offer, showing exactly what
  # would change first. Declining leaves the original warning, unchanged from previous releases.
  printf '\n   %sThe dismiss/close hard-gate is OFF.%s I can merge it for you — additive only,\n' "$YLW" "$RST"
  printf '   nothing of yours removed or reordered, and %s is backed up first:\n\n' "$SETTINGS"
  python3 "$MERGER" --snippet "$SNIPPET" --settings "$SETTINGS" --dry-run 2>&1 | sed 's/^/     /' || true
  printf '\n   Merge it now? [y/N] '
  read -r reply || reply=""
  case "$reply" in
    [yY]|[yY][eE][sS]) run_merge ;;
    *) warn "Governance not merged (declined) — the dismiss/close hard-gate stays OFF until you merge settings.snippet.json" ;;
  esac
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
        ${SNIPPET}
      into ${SETTINGS}
      — or let the installer do it: ${CYAN}${SCRIPT_DIR}/install.sh --merge-permissions${RST}
      ${YLW}⚠ don't run with --dangerously-skip-permissions (it disables the gate).${RST}
   3. Restart Claude Code, then:  ${CYAN}"investigate alert <id>"${RST}
NEXT
else
  printf '\n%s   Ready.%s Restart Claude Code, then:  %s"investigate alert <id>"%s\n' "$GRN" "$RST" "$CYAN" "$RST"
fi

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
