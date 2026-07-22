#!/usr/bin/env bash
# Launcher for the agent answer-endpoint: pulls the bearer token from Vault into the
# process environment, then exec's the daemon. The secret is NEVER written to disk or
# baked into the systemd unit — it lives only in this process's env.
#
# Non-secret config (AGENT_NAME, WORKDIR, MODEL, ENDPOINT_BIND, ...) comes from the
# systemd unit's Environment= lines. On hosts without a vault token you can instead
# export AUTH_TOKEN before starting (see README) and this Vault read is skipped.
set -euo pipefail

VAULT="${VAULT_ADDR:-}"   # your vault address; set in env/.env
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-$HOME/.vault-token}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${AUTH_TOKEN:-}" ]]; then
  AUTH_TOKEN="$(curl -sk -H "X-Vault-Token: $(cat "$VAULT_TOKEN_FILE")" \
    "$VAULT/v1/secret/data/lab/agent-endpoint" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['data']['token'])")"
  export AUTH_TOKEN
fi

exec python3 "$HERE/endpoint.py"
