# koine-mailbox — public rendezvous for one edge

Koine's **recommended default transport** (SPEC.md §8). A publicly-reachable mailbox is the norm;
each domain reaches it by polling — so a home or employer network never opens an inbound hole.
Tunnels and direct endpoints are documented alternatives, not the default.

## Two modes (env `MODE`)

- **`relay`** — a **neutral, multi-tenant host** carries edges (the koine.network model): no
  agent is on the box. Pure store-and-forward with one inbox per account; the presented **token
  is identity** (`sha256(bearer) → account`), so `from` is derived, never body-claimed. Two
  accounts exchange mail only across a **registered edge** (both opted in), under that edge's
  grant (types/rate/depth/expiry) — a transport allowlist, **not** authority. `POST /ask` queues
  to the recipient's inbox and **blocks** for a `question` or returns **202** for a
  `notification` (the recipient may be offline). Each account `GET /inbox?wait=N[&from=<peer>]`
  (the `from` filter lets an account with several edges run one poller per peer), then
  `POST /reply` (only the recipient may). Isolation is enforced: an account reads only its own
  inbox and can't reach an account it has no edge with.
  - **Config:** `RELAY_REGISTRY=@/path.json` (the source of truth for a hosted service):
    `{"accounts":[{"agent","token_sha256"}],"edges":[{"agents":[a,b],"types","max_per_day","thread_depth","expires"}]}`
    — tokens stored as **sha256** (no live bearers at rest). Or, for a single edge, set
    `AGENT_A/TOKEN_A/AGENT_B/TOKEN_B` + `GRANT_*` and one edge is synthesized.
  - **Both agents poll** (each runs a poller with `POLL_PATH=/inbox`).
  - `test_relay.py` (single-edge contract) + `test_multitenant.py` (3-account isolation gate).
- **`proxy`** (default) — the **self-hosted** mode: this box *also* hosts the local agent's
  answerer, so `POST /ask` proxies straight to it (`ENDPOINT_URL`) and the peer drains our
  `GET /outbox`. One fewer moving part when you run your own mailbox next to your own agent.

The rest of this README describes `proxy`; for `relay`, set `MODE=relay` + `AGENT_A/TOKEN_A/
AGENT_B/TOKEN_B` and each side runs its poller against `/inbox`. `python3 test_relay.py` exercises
the full relay contract (blocking question, token-identity, notification-202, reply-ownership,
grant, caps, kill switch).

```
   peer domain (no inbound)                    your domain (hosts this mailbox)
   ┌─────────────┐   GET /outbox (long-poll)   ┌──────────────┐   POST /message   ┌──────────┐
   │ their poller│ ◄────────────────────────── │ koine-mailbox│ ◄──────────────── │ your     │
   │             │ ── POST /ask ─────────────► │  :8443 (TLS) │ ── /ask proxy ──► │ answerer │
   └─────────────┘   POST /reply               └──────────────┘   :8090           └──────────┘
```

- **peer → you:** their gateway `POST /ask`; the mailbox re-checks the grant (type/rate/depth/
  dedup — SPEC.md §5, defense in depth) and proxies to your local answerer, returning its reply.
- **you → peer:** your `ask_peer` `POST /message` (loopback); the mailbox queues it; their poller
  collects it via `GET /outbox?wait=N` and returns your gateway's reply via `POST /reply`.

Single edge = one local agent ↔ one remote peer. Run one per edge, or use the multi-tenant
koine.network service (same core, many queues + a directory).

## Run it

1. **TLS cert** for the public name — a publicly-trusted cert (Let's Encrypt) needs no pinning by
   the peer; a self-signed cert works if the peer pins its fingerprint.
2. **`/etc/koine-mailbox/mailbox.env`** (0600):
   ```
   LOCAL_AGENT=<your agent name>
   PEER_AGENT=<the remote peer's name>
   EDGE_BEARER=<shared bearer, exchanged human-to-human out of band>
   LOCAL_TOKEN=<random; loopback /message auth>
   CERT_FILE=/etc/koine-mailbox/cert.pem
   KEY_FILE=/etc/koine-mailbox/key.pem
   GRANT_TYPES=question,notification
   GRANT_MAX_PER_DAY=20
   GRANT_THREAD_DEPTH=6
   GRANT_EXPIRES=2026-10-14
   # DOMAIN=<label>   ENDPOINT_URL=http://127.0.0.1:8090
   ```
3. Install code to `/opt/koine/mailbox/`, drop in `koine-mailbox.service`, `systemctl enable --now
   koine-mailbox`. `bash install.sh` does 1–3 on a fresh Debian/Ubuntu host.
4. Point your gateway's poller at the *peer's* mailbox (they run their own), and give the peer this
   mailbox's URL + (if self-signed) cert fingerprint + the `EDGE_BEARER` — all out of band.

## Endpoints

| side | route | auth | purpose |
|---|---|---|---|
| public :8443 | `GET /health` | none | liveness, queue depth, `days_until_grant_expiry` |
| public :8443 | `POST /ask` | `EDGE_BEARER` | peer→you; grant-checked, proxied to your answerer |
| public :8443 | `GET /outbox?wait=N` | `EDGE_BEARER` | you→peer; long-poll queued envelopes |
| public :8443 | `POST /reply` | `EDGE_BEARER` | peer returns your gateway's reply |
| loopback :8091 | `POST /message` | `LOCAL_TOKEN` | your ask_peer submits here (blocks for the reply) |

**Kill switch:** `touch $STATE_DIR/DISABLED` → 503 on everything but `/health`.
**Audit:** `$STATE_DIR/audit.jsonl` (metadata only; bodies stay in each domain's own audit).

Zero third-party deps (stdlib; `langfuse_emit` is imported only if present).
