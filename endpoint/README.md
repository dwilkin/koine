# agent-endpoint — Atlas ↔ Genie answer-endpoint (A2A messaging, Phase 1)

The **linchpin** of the A2A-service messaging model (full plan:
`~/.claude/plans/crystalline-growing-quail.md`, memory `agent-messaging-plan`). A small,
dependency-free HTTP daemon that runs **on the host where the agent's `claude` + context live**
and answers a *peer agent's* message by spawning `claude -p`. The reply comes back
**synchronously** as the HTTP response, so an agent is reachable 24/7 regardless of whether its
interactive session is active — and because it's a real `claude -p`, any action a peer asks for
still hits the same **guard hooks** (action-gating for free).

```
peer (live turn) --POST /ask--> [agent-endpoint] --spawn--> claude -p (full context + hooks)
                 <---answer----                   <--result--
```

## Layout
- `endpoint.py` — the daemon (stdlib `ThreadingHTTPServer`; no pip deps).
- `run.sh` — launcher: reads the bearer token from Vault into the env, then exec's the daemon.
- `agent-endpoint.service` — `systemd --user` unit (agent-host/Atlas values; peer-host overrides noted inline).
- This README.

## Security model (Phase 1)
- **Auth:** every `POST /ask` needs `Authorization: Bearer <token>`; token in Vault
  `secret/<mount>/agent-endpoint`, injected by `run.sh` (never on disk / in the unit). Constant-time compare.
- **Answerer posture:** *full-capability + hook-gating* (Darian's call 2026-07-02). The spawned
  `claude -p` inherits the host agent's full tool permissions; destructive/outbound actions are
  stopped by the existing **PreToolUse guard hooks**, not by tool restriction. Because of that,
  the compensating controls below are load-bearing.
- **Untrusted-input framing:** the peer's text is handed to the answerer as UNTRUSTED DATA between
  fences, explicitly *not* as instructions that can override CLAUDE.md / guard rails.
- **No recursion:** the answerer is spawned with `--disallowedTools mcp__ask-peer__ask_peer`
  (the future Phase-3 tool), so it can't call back out and start a loop.
- **Caps:** `MAX_CONCURRENCY` semaphore (429 when busy), `ANSWER_TIMEOUT`, `MAX_BODY_BYTES`.
- **Kill switch:** `touch $STATE_DIR/DISABLED` → `/ask` returns 503 with no restart
  (`rm` it to re-enable). Or just `systemctl --user stop agent-endpoint`.
- **Audit:** append-only `$STATE_DIR/audit.jsonl` (default `~/.local/share/agent-endpoint/`) —
  every ask/answer/auth-reject/busy event, Darian-readable. (Phase 2 adds the central gateway's
  SQLite audit; this local log stays as a per-host record. Register it in BACKUP_PLAN.md in Phase 4.)

> Phase 1 is directly callable (bearer auth). Phase 2 puts the **central A2A gateway** (infra-host) in
> front for Keycloak authn, rate/loop caps, policy routing, and the agent-card directory.

## Message schema (A2A-inspired)
`POST /ask` body — JSON object:
```json
{ "id": "uuid", "thread_id": "uuid", "from": "genie", "type": "question", "body": "…", "ts": "…" }
```
`type ∈ {question, answer, notification, action_request, escalation}`. Response mirrors it with
`from`=this agent, `type`="answer", `body`=the reply, plus a `meta` block (elapsed, cost_usd,
num_turns, session_id).

`GET /health` → `{"status":"ok","agent":"atlas","disabled":false}`.

## Deploy (agent-host / Atlas)
```bash
# repo is source of truth; the unit runs the code straight from ~/lab/agent-endpoint
cp ~/lab/agent-endpoint/agent-endpoint.service ~/.config/systemd/user/
chmod +x ~/lab/agent-endpoint/run.sh
systemctl --user daemon-reload
systemctl --user enable --now agent-endpoint
systemctl --user status agent-endpoint --no-pager
curl -s http://127.0.0.1:8090/health
```

## Deploy (peer-host / Genie) — as-built 2026-07-02
Same `endpoint.py`, deployed as user `genie` to `/home/genie/agent-endpoint/`. `genie` has **no
Vault token**, so instead of `run.sh` the token is delivered by an **EnvironmentFile** that Atlas
provisions from Vault (Darian's choice 2026-07-02): keeps Genie lean (one bearer token, no Vault
reach). `genie` already has linger enabled.

```bash
# from agent-host (Atlas has Vault): write the token to a 600 env file on peer-host (token via stdin)
TOK=$(curl -sk -H "X-Vault-Token: $(cat ~/.vault-token)" \
  https://192.0.2.10:8200/v1/secret/data/lab/agent-endpoint \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['data']['token'])")
printf 'AUTH_TOKEN=%s\n' "$TOK" | ssh root@192.0.2.10 \
  'umask 077; cat > /home/genie/.config/agent-endpoint.env \
   && chown genie:genie /home/genie/.config/agent-endpoint.env'
unset TOK
```
Genie's unit differs from agent-host's only in: `AGENT_NAME=genie`, `WORKDIR=/home/genie`,
`CLAUDE_BIN=/home/genie/.local/bin/claude`, `EnvironmentFile=/home/genie/.config/agent-endpoint.env`,
and `ExecStart=/usr/bin/python3 /home/genie/agent-endpoint/endpoint.py` (no `run.sh`). Enable it as
`genie` from a root shell on peer-host (no `sudo` there):
```bash
GUID=$(id -u genie)
runuser -u genie -- env XDG_RUNTIME_DIR=/run/user/$GUID \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$GUID/bus \
  systemctl --user enable --now agent-endpoint
```
To rotate the token: rewrite the env file (above) + update Vault, then `systemctl --user restart
agent-endpoint` for genie and `systemctl --user restart agent-endpoint` on agent-host.

## Config (env — set in the unit)
| Var | Default | Meaning |
|-----|---------|---------|
| `AGENT_NAME` | *(required)* | this agent's identity |
| `AUTH_TOKEN` | *(from Vault)* | bearer token; injected by run.sh |
| `ENDPOINT_BIND` | `0.0.0.0:8090` | listen host:port |
| `CLAUDE_BIN` | `~/.local/bin/claude` | absolute path to claude |
| `WORKDIR` | cwd | project dir (must hold CLAUDE.md) |
| `MODEL` | `sonnet` | pinned answer model (cost control) |
| `ANSWER_TIMEOUT` | `180` | seconds per answer |
| `MAX_CONCURRENCY` | `2` | concurrent answerers |
| `MAX_BODY_BYTES` | `65536` | request body cap |
| `DISALLOWED_TOOLS` | `mcp__ask-peer__ask_peer` | `--disallowedTools` (no recursion) |
| `STATE_DIR` | `~/.local/share/agent-endpoint` | audit + kill switch |

## Cost note
Each answer is a cold `claude -p` (~$0.13 on agent-host's context, ~3.6–7s). `MODEL=sonnet` keeps it
down; watch `meta.cost_usd` in the audit log.
