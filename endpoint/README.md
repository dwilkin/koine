# endpoint — the Koine answer-endpoint (answerer daemon)

The **linchpin** of Koine's agent-as-a-service model (SPEC.md §6). A small, dependency-free
HTTP daemon that runs **on the host where the agent's `claude` + context live** and answers an
inbound message by spawning `claude -p`. The reply comes back **synchronously** as the HTTP
response, so an agent is reachable 24/7 regardless of whether its interactive session is active —
and because it's a real `claude -p`, any action a caller asks for still hits the same **guard
hooks** (action-gating for free).

```
caller (gateway/bridge) --POST /ask--> [answer-endpoint] --spawn--> claude -p (full context + hooks)
                        <---answer----                    <--result--
```

## Layout
- `endpoint.py` — the daemon (stdlib `ThreadingHTTPServer`; no pip deps).
- `run.sh` — launcher: reads the bearer token(s) from your secret store into the env, then
  exec's the daemon.
- `agent-endpoint.service` — `systemd --user` reference unit for the full-context daemon
  (human/ops channels).
- `agent-peer-endpoint.service` — system reference unit for the **sandboxed, unprivileged**
  peer-facing daemon (SPEC §6.2).
- `pending_actions.py` — the durable pending-actions ledger (propose in one spawn, approve +
  execute in a later one).
- `redaction.py` — peer-path output redaction + inbound secret-seeking tripwire.
- `empty-mcp.json` — empty MCP config used by `STRICT_MCP`.
- `test_machine_lane.py`, `test_escalation.py` — unit tests (fake `claude`, no model calls).

## Security model
- **Auth:** every `POST /ask` needs `Authorization: Bearer <token>`; the token lives in your
  secret store and is injected into the process env by `run.sh` (never on disk / in the unit).
  Constant-time compare. A separate `OPS_TOKEN` may authenticate the ops channel only.
- **Answerer posture — SANDBOXED IS THE DEFAULT.** Run the PEER-facing daemon as a separate
  **unprivileged, sandboxed user** (the `agent-peer-endpoint.service` pattern: dedicated
  system user, `ProtectHome`/`ProtectSystem=strict`, a curated WORKDIR with **no credentials
  reachable**, its own scoped API key, `REFUSE_HUMAN_CHANNEL=1`). This is the recommended
  path for **every** peer answerer — self-hosters and new agents should start here, and the
  human/ops channels stay on a separate full-context daemon. The single privileged
  full-context daemon serving peers directly is a **fallback only**, and only acceptable
  when that daemon's user cannot reach real secrets: guard hooks are Bash-only, so the
  spawned answerer can still `Read` anything its user can — on the fallback path the
  compensating controls below (tool disallow list, redaction, tripwire) are load-bearing
  backstops, not walls.
- **Phase C note:** an agent whose peer answers need live scoped data (e.g. a calendar)
  should be given a **narrow capability inside the sandbox** (a read-only proxy/gateway for
  exactly that data source), not the privileged fallback path — "needs one credential" never
  justifies full-context peer answering.
- **Untrusted-input framing:** a peer's text is handed to the answerer as UNTRUSTED DATA between
  fences, explicitly *not* as instructions that can override CLAUDE.md / guard rails.
- **No recursion:** peer spawns are launched with `--disallowedTools` including the `ask_peer`
  tool (`askpeer/` in this repo), so an answerer can't call back out and start a loop.
- **Peer-path hardening:** `Edit,Write,WebFetch,WebSearch` are also disallowed by default on the
  peer path; replies are scrubbed for secret-shaped strings and inbound secret-seeking asks trip
  an alert (`redaction.py` + `ALERT_CMD`). The structural fix is running the peer daemon as an
  unprivileged sandboxed user — see `agent-peer-endpoint.service` and SPEC §6.2.
- **Caps:** `MAX_CONCURRENCY` semaphore (429 when busy), `ANSWER_TIMEOUT`, `MAX_BODY_BYTES`.
- **Kill switch:** `touch $STATE_DIR/DISABLED` → `/ask` returns 503 with no restart
  (`rm` it to re-enable). Or just `systemctl --user stop agent-endpoint`.
- **Audit:** append-only `$STATE_DIR/audit.jsonl` (default `~/.local/share/agent-endpoint/`) —
  every ask/answer/auth-reject/busy event. The domain gateway keeps its own SQLite audit; this
  local log is the per-host record (include it in your domain's backup set).

> The endpoint is directly callable (bearer auth), but a domain normally puts its **gateway**
> (`gateway/`) in front for OIDC authn, rate/loop caps, grant enforcement, and routing.

## Channels
- *(none / default)* — **peer**: untrusted-data framing, restricted tools, redaction + tripwires.
- `"human"` — the agent's own human via an authenticated bridge (e.g. Telegram): control-channel
  framing; with `PERMISSION_MODE_HUMAN=bypassPermissions` it's a real control channel (guard hooks
  stay the hard floor).
- `"ops"` — **monitoring wakes the agent to troubleshoot.** Authenticated by a
  separate `OPS_TOKEN` valid for this channel ONLY (the monitoring stack never holds the human
  bearer; the main bearer also works). Ops spawns keep the human-channel **model/timeout** (the
  wake must be able to diagnose) but run the **restricted tool profile** (KO-M2): never
  `bypassPermissions`, the peer disallowed set, and `--allowedTools` = the pending-actions
  ledger — the wake investigates and RECORDS a proposed fix for the human to approve rather
  than auto-executing privileged mutations. The framing is honest: a MACHINE alert carrying no
  human authority, with verify-first, confirm-gated-actions-stay-gated, and a loop guard (a
  re-fired alert after a prior fix attempt escalates to the human instead of repeating
  mutations). **Fire-and-forget:**
  `/ask` acks `202 {"queued": true}` immediately and spawns in the background — alert webhooks
  time out in seconds, and a synchronous reply would read as failure and re-fire every probe
  cycle (spawn storm). The outcome lands in the audit log + the agent's proactive notify. A 429
  (busy) is safe: the sender retries next cycle. Example caller: a Gatus `alerting.custom`
  provider POSTing `{"from":"gatus","channel":"ops","type":"question","body":"GATUS ALERT …"}`.
- A **machine lane** (peer channel only, `MACHINE_LANE=1` default) answers `caldera/v1` read-only
  questions and acks informational notifications deterministically from published JSON — no LLM
  spawn, zero cost. State-changing kinds always take the LLM + ledger path.

## Message schema (Koine envelope — SPEC §3)
`POST /ask` body — JSON object:
```json
{ "id": "uuid", "thread_id": "uuid", "from": "<peer>", "type": "question", "body": "…", "ts": "…" }
```
`type ∈ {question, answer, notification, action_request, escalation}`. Response mirrors it with
`from`=this agent, `type`="answer", `body`=the reply, plus a `meta` block (elapsed, cost_usd,
num_turns, session_id).

`GET /health` → `{"status":"ok","agent":"<name>","disabled":false}`.

## Deploy
The daemon runs the same everywhere; only per-domain config differs. Install the systemd `--user`
unit (`agent-endpoint.service`), set `AGENT_NAME`/`WORKDIR`/`CLAUDE_BIN` + the bearer, and start it:
```bash
cp agent-endpoint.service ~/.config/systemd/user/ && systemctl --user daemon-reload
systemctl --user enable --now agent-endpoint && curl -s http://127.0.0.1:8090/health
```
The bearer (`AUTH_TOKEN`) comes from `run.sh` (fetches it from your secret store) OR a 0600
`EnvironmentFile` if the host has no secret-store reach — never on disk in the unit. A domain with
multiple agents deploys one unit per agent (distinct `AGENT_NAME`/`WORKDIR`). Domain-specific
deploy steps, secret paths, and host wiring live in that domain's own ops repo, not here.

**Default deploy = two daemons:** the peer-facing daemon runs SANDBOXED (unprivileged user,
no state-changing tools, no secrets reachable — `agent-peer-endpoint.service`, SPEC §6.2) and
the human/ops control channels stay on the separate full-context `agent-endpoint.service`. A
single privileged daemon that also serves peers is the fallback for hosts that can't split
yet — use it only where the daemon's user can't reach real secrets, and plan the split.

## Config (env — set in the unit)
| Var | Default | Meaning |
|-----|---------|---------|
| `AGENT_NAME` | *(required)* | this agent's identity |
| `AUTH_TOKEN` | *(required)* | main bearer token; injected by run.sh or an EnvironmentFile |
| `OPS_TOKEN` | *(unset)* | separate bearer valid for `channel:"ops"` ONLY (monitoring wake-ups); unset = ops reachable only via the main bearer |
| `ENDPOINT_BIND` | `0.0.0.0:8090` | listen host:port |
| `CLAUDE_BIN` | `~/.local/bin/claude` | absolute path to claude |
| `WORKDIR` | cwd | project dir (must hold CLAUDE.md) |
| `MODEL` | `sonnet` | pinned answer model (cost control) |
| `MODEL_HUMAN` | `MODEL` | model for `channel:"human"` asks (e.g. a smarter model for chat) |
| `MODEL_ESCALATION` | *(unset)* | retry-once model when a spawn fails (non-zero exit / is_error; never on timeout); empty = no escalation |
| `ANSWER_TIMEOUT` | `180` | seconds per answer |
| `ANSWER_TIMEOUT_HUMAN` | `ANSWER_TIMEOUT` | seconds per human-channel answer (raise with a slower `MODEL_HUMAN`; the bridge's timeout must exceed it) |
| `MAX_CONCURRENCY` | `2` | concurrent answerers |
| `MAX_BODY_BYTES` | `65536` | request body cap |
| `DISALLOWED_TOOLS` | `mcp__ask-peer__ask_peer,Edit,Write,WebFetch,WebSearch` | peer-path `--disallowedTools` (no recursion, no write/outbound) |
| `DISALLOWED_TOOLS_HUMAN` | *(empty)* | same, for `channel:"human"` (empty = the human channel may use ask_peer) |
| `PERMISSION_MODE_HUMAN` | *(empty)* | `--permission-mode` for human-channel spawns; set `bypassPermissions` to make chat a real control channel (guard hooks stay the floor) |
| `ALLOWED_TOOLS_PEER` | `Bash(python3 <pending_actions.py>:*)` | `--allowedTools` for peer spawns — just the ledger, so an action_request can be RECORDED without granting general shell; empty string disables |
| `REFUSE_HUMAN_CHANNEL` | *(off)* | set `1` on the sandboxed peer daemon so it structurally 403s the human/ops channels |
| `ALERT_CMD` | *(empty)* | executable invoked with the alert text on redaction/tripwire hits (your domain's notify helper); empty = audit-only |
| `STRICT_MCP` | *(off)* | peer path: spawn with `--strict-mcp-config` + an empty `--mcp-config` (`MCP_CONFIG`, default `empty-mcp.json`) so no inherited MCP server is reachable |
| `MACHINE_LANE` | `1` | deterministic caldera/v1 read-only answers + acks (peer channel); `CALDERA_CTX` (default `WORKDIR/caldera`) holds the published JSON |
| `STATE_DIR` | `~/.local/share/agent-endpoint` | audit + kill switch + ledger fallback |

## Cost note
Each answer is a cold `claude -p`. `MODEL=sonnet` keeps it down; the machine lane answers
caldera/v1 reads at $0; watch `meta.cost_usd` in the audit log.
