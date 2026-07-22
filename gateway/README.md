# gateway — a Koine domain's policy enforcement point

The routing + safety layer between an initiating agent's `ask_peer` MCP tool and a recipient
agent's answerer (`endpoint/`, `/ask`). One gateway per **trust domain** (SPEC.md §2). Runs as a
container; stdlib + `PyJWT[crypto]` (OIDC) + optional `cryptography` (E2E).

## Flow
```
initiator agent (live turn)
  └─ ask_peer(to, body, type)  → POST /message   (Bearer: OIDC JWT or gateway token)
       gateway: authn · identity-bind · grant/caps (types·rate·thread-depth) · AUDIT
                · notify (human on action_request) · route → peer /ask (or its mailbox)
       ← synchronous reply  ← the peer's answerer produces it
```

## Endpoints
- `POST /message` — relay an envelope `{from,to,type,body,thread_id?,id?}` (SPEC §3). Authn required.
- `GET  /health`  — status, known agents, OIDC on/off, kill-switch state.
- `GET  /agents`  — the agent-card directory (`agents.json`).
- `GET  /audit?limit=N` — recent audit rows (gateway bearer). The operator's log.

## AuthN
- **Preferred:** per-agent OIDC confidential clients (client_credentials → RS256 JWT). The `azp`
  claim maps to the agent, and the message `from` MUST match it — no peer-spoofing (SPEC §8).
- **Bootstrap/fallback:** a shared `GW_BEARER_TOKEN`; with it, identity is the body's `from`
  (trusted caller). Set `OIDC_JWKS_URL` to enable JWT mode.

## Safety (SPEC §5)
- **Audit:** every request/reply/refusal persisted to SQLite (`$STATE_DIR/audit.db`).
- **Grants + caps:** per-edge types/rate; `MAX_THREAD_DEPTH` per `thread_id`; `MAX_MSGS_PER_HOUR`
  + optional `COOLDOWN_SECONDS`. Answerers don't get `ask_peer`, so they can't recurse.
- **E2E (KN1/§8a):** set `MY_PRIVKEY`; a peer card's `pubkey` opts that edge into encryption —
  the body is sealed before it leaves this domain and the reply is opened on return.
- **Notify:** `action_request`/`escalation` → the recipient's human (best-effort, configurable).
- **Kill switch:** `touch $STATE_DIR/DISABLED` severs all traffic.

## Config (environment)
`GW_BIND` · `GW_BEARER_TOKEN` · `OIDC_JWKS_URL`/`OIDC_ISSUER`/`OIDC_AUDIENCE` · `AGENTS_JSON`
(cards+grants) · `ENDPOINT_TOKEN` (bearer for peers' `/ask`) · `MAX_THREAD_DEPTH` · `MAX_MSGS_PER_HOUR`
· `COOLDOWN_SECONDS` · `ROUTE_TIMEOUT` · `DOMAIN` (observability label) · `MY_PRIVKEY` (E2E) ·
`BRIDGE_NOTE_URL` (optional chat-bridge history) · `STATE_DIR`. `agents.json`, certs, and all
secrets are **domain data** — the operating domain overlays them at deploy (see the domain's own
ops repo). This repo ships none.
