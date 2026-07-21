#!/usr/bin/env bash
# Launch the ask_peer MCP server for THIS agent. Spawned by claude at session start
# (configured in ~/.claude.json mcpServers). Injects creds from Vault (agent-host/Atlas) or,
# on peer-host/Genie, from a 600 EnvironmentFile that pre-sets KC_CLIENT_SECRET + GW_BEARER_TOKEN
# (Genie's Vault token can't read secret/<mount>/agent-gateway). Secrets never touch ~/.claude.json.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VAULT="https://192.0.2.10:8200"

# peer-host/Genie: a 600 .env beside this script pre-sets AGENT_NAME=genie + KC creds
# (Genie has no Vault access to secret/<mount>/agent-gateway). agent-host/Atlas has no .env -> Vault path.
[ -f "$HERE/.env" ] && { set -a; . "$HERE/.env"; set +a; }

export AGENT_NAME="${AGENT_NAME:-atlas}"
export GATEWAY_URL="${GATEWAY_URL:-http://192.0.2.10:8095}"
export KC_TOKEN_URL="${KC_TOKEN_URL:-https://192.0.2.10:8443/realms/workloads/protocol/openid-connect/token}"
export KC_CLIENT_ID="${KC_CLIENT_ID:-agent-atlas}"

# If creds aren't already in the env (peer-host EnvironmentFile path), pull them from Vault (agent-host).
if [ -z "${KC_CLIENT_SECRET:-}" ] && [ -f "$HOME/.vault-token" ]; then
  sec() { curl -sk -H "X-Vault-Token: $(cat "$HOME/.vault-token")" "$VAULT/v1/secret/data/lab/$1" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['data']['$2'])"; }
  export KC_CLIENT_SECRET="$(sec agent-gateway agent_atlas_client_secret)"
  export GW_BEARER_TOKEN="${GW_BEARER_TOKEN:-$(sec agent-gateway gw_bearer_token)}"
fi

exec python3 "$HERE/ask_peer_server.py"
