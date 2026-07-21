#!/usr/bin/env bash
# Launch the ask_peer MCP server for THIS agent (spawned by claude at session start via
# ~/.claude.json mcpServers). ALL domain-specific config comes from a 600 `.env` beside this
# script (gitignored) or the process env — this reference launcher bakes in NO addresses,
# realms, or peer names. Secrets never touch ~/.claude.json.
#
# Required in .env/env: AGENT_NAME, GATEWAY_URL, and auth (either the KC_* trio or
# GW_BEARER_TOKEN). Optional: KC_TOKEN_URL, KC_CLIENT_ID, KOINE_PEERS (peer directory —
# inline JSON or @path; see ask_peer_server.py). A domain whose secrets live in a vault may
# fetch them in .env (see the wilkin-lab overlay for the pattern) rather than storing them here.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -f "$HERE/.env" ] && { set -a; . "$HERE/.env"; set +a; }

: "${AGENT_NAME:?set AGENT_NAME in askpeer/.env}"
: "${GATEWAY_URL:?set GATEWAY_URL in askpeer/.env}"
if [ -z "${KC_CLIENT_SECRET:-}" ] && [ -z "${GW_BEARER_TOKEN:-}" ]; then
  echo "ask_peer: need KC_CLIENT_SECRET (+KC_TOKEN_URL/KC_CLIENT_ID) or GW_BEARER_TOKEN in .env" >&2
  exit 1
fi

exec python3 "$HERE/ask_peer_server.py"
