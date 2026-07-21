# agent-gateway — central A2A hub (Phase 2)

The routing + safety layer between the initiating agent's `ask_peer` MCP tool and the
recipient agent's always-on answer-endpoint (`agent-endpoint/`, `:8090 /ask`). Runs as a
Docker stack on **infra-host** (`http://192.0.2.10:8095`). Plan:
`~/.claude/plans/crystalline-growing-quail.md`.

## Flow
```
initiator agent (live turn)
  └─ ask_peer(to, body, type)  → POST /message (Bearer: Keycloak JWT or gateway token)
       gateway: authn · identity-bind · caps (thread-depth/rate/cooldown) · AUDIT (SQLite)
                · notify (Telegram on action_request/escalation) · route → peer /ask
       ← synchronous reply  ← peer answer-endpoint spawns `claude -p` (full context + guard hooks)
```

## Endpoints
- `POST /message` — relay an A2A message `{from,to,type,body,thread_id?,id?}`. Authn required.
- `GET  /health`  — status, known agents, whether OIDC is on, kill-switch state.
- `GET  /agents`  — the agent-card directory (`agents.json`).
- `GET  /audit?limit=N` — recent audit rows (gateway bearer required). Darian-readable log.

## AuthN
- **Preferred:** Keycloak (infra-host `workloads` realm) JWT — dedicated confidential clients
  `agent-atlas` / `agent-genie` (client_credentials). `azp` claim → agent identity, and the
  message `from` must match it (no peer-spoofing).
- **Bootstrap/fallback:** a shared `GW_BEARER_TOKEN` (Vault `secret/<mount>/agent-gateway`). With
  the bearer, identity is taken from the body's `from` (trusted caller). Set `OIDC_JWKS_URL`
  to enable JWT mode; keep the bearer for `GET /audit` (Darian's ops read).

## Safety
- **Audit:** every request/reply/refusal persisted to SQLite (`/data/audit.db`, named volume).
- **Loop cap:** `MAX_THREAD_DEPTH` requests per `thread_id`. Answerers don't get `ask_peer`
  (endpoint `--disallowedTools`) so they can't recurse; the depth cap is defense-in-depth.
- **Rate cap:** `MAX_MSGS_PER_HOUR` per initiator + optional `COOLDOWN_SECONDS`.
- **Notify:** `action_request` / `escalation` → Telegram to the recipient's human (best-effort).
- **Kill switch:** `touch /data/DISABLED` (or `docker stop agent-gateway`) severs all traffic.

## Deploy / operate
```bash
~/lab/stacks/agent-gateway/deploy.sh            # from agent-host: Vault→.env, sync, up --build, health
ssh claude@192.0.2.10 'docker logs --tail 40 agent-gateway'
curl -s http://192.0.2.10:8095/health | python3 -m json.tool
# kill switch:
ssh claude@192.0.2.10 'docker exec agent-gateway touch /data/DISABLED'   # re-enable: rm it
```

## Secrets (Vault)
- `secret/<mount>/agent-gateway` — `gw_bearer_token` (+ later `oidc_jwks_url`/`oidc_issuer`/`oidc_audience`).
- `secret/<mount>/agent-endpoint` — `token` (bearer the gateway uses to call the peers' `/ask`).
- `secret/<mount>/telegram` — `bot_token`, `chat_darian`, `chat_marie` (Phase 4; notify off until set).
