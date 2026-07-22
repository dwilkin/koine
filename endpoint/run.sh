#!/usr/bin/env bash
# Launcher for the agent answer-endpoint: pulls the bearer token from Vault into the
# process environment, then exec's the daemon. The secret is NEVER written to disk or
# baked into the systemd unit — it lives only in this process's env.
#
# Non-secret config (AGENT_NAME, WORKDIR, MODEL, ENDPOINT_BIND, ...) comes from the
# systemd unit's Environment= lines. On hosts without a vault token you can instead
# export AUTH_TOKEN before starting (see README) and this Vault read is skipped.
# VAULT_SECRET_PATH selects the KV-v2 data path holding the `token` (+ optional
# `ops_token`) fields; the default is the reference deployment's path — set your own.
set -euo pipefail

VAULT="${VAULT_ADDR:-}"   # your vault address; set in env/.env
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-$HOME/.vault-token}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/data/lab/agent-endpoint}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${AUTH_TOKEN:-}" ]]; then
  AUTH_TOKEN="$(curl -sk -H "X-Vault-Token: $(cat "$VAULT_TOKEN_FILE")" \
    "$VAULT/v1/$VAULT_SECRET_PATH" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['data']['token'])")"
  export AUTH_TOKEN
fi
# Optional ops-channel bearer (monitoring wake-ups); absent field -> ops stays disabled.
if [[ -z "${OPS_TOKEN:-}" ]]; then
  OPS_TOKEN="$(curl -sk -H "X-Vault-Token: $(cat "$VAULT_TOKEN_FILE")" \
    "$VAULT/v1/$VAULT_SECRET_PATH" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['data'].get('ops_token',''))" \
    2>/dev/null || true)"
  export OPS_TOKEN
fi

exec python3 "$HERE/endpoint.py"
