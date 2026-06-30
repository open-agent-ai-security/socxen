#!/usr/bin/env bash
#
# Connect socxen to Exabeam — one-time setup.
#
# Installs a tiny local bridge that talks to the Exabeam New-Scale MCP and refreshes
# the OAuth token automatically (no expiring tokens to manage), then registers it in
# Claude Code as the `exabeam` MCP. Run from the socxen repo:
#
#   ./connector/connect-exabeam.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/exabeam-mcp-bridge.py"
DEST_DIR="$HOME/.socxen"
DEST="$DEST_DIR/exabeam-mcp-bridge.py"
ENV="$HOME/.exabeam-mcp.env"

say() { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }

command -v uv     >/dev/null 2>&1 || { echo "Please install uv first: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
command -v claude >/dev/null 2>&1 || { echo "Please install Claude Code first: https://claude.com/claude-code"; exit 1; }

# 1) Credentials — paste once, stored owner-only.
if [ ! -f "$ENV" ] || ! grep -q '^EXABEAM_API_KEY=' "$ENV"; then
  say "Let's connect Exabeam. You'll need an API key + secret from the New-Scale platform"
  echo "  (Settings → API Keys; ask an admin if you can't create one)."
  read -rp "  Exabeam MCP URL [https://api.us-west.exabeam.cloud/mcp]: " U
  read -rp "  API key: " K
  read -rsp "  API secret: " S; echo
  ( umask 177; cat > "$ENV" <<EOF
EXABEAM_MCP_URL=${U:-https://api.us-west.exabeam.cloud/mcp}
EXABEAM_API_KEY=$K
EXABEAM_API_SECRET=$S
EOF
  )
  say "Saved credentials to $ENV (owner-only)."
else
  say "Using existing credentials at $ENV."
fi

# 2) Install the bridge to a stable location (survives if you move or delete the clone).
mkdir -p "$DEST_DIR"
cp "$SRC" "$DEST"

# 3) Verify the connection (also warms uv's dependency cache so first launch is fast).
say "Testing the connection…"
uv run --quiet "$DEST" --check

# 4) Register it in Claude Code as `exabeam` (the name the governance rules expect).
claude mcp remove exabeam --scope user >/dev/null 2>&1 || true
claude mcp add exabeam --scope user -- uv run --quiet "$DEST"

echo
say "Connected. Restart Claude Code (or run /reload-plugins), then ask: \"investigate alert <id>\""
