# koine-mailbox — public rendezvous for one edge

Koine's **recommended default transport** (SPEC.md §8). A domain that can accept a public inbound
connection hosts a mailbox; the peer domain reaches it by polling **outbound**, so a home or
employer network never has to open an inbound hole. Public mailboxes are the norm; tunnels and
direct endpoints are documented alternatives, not the default.

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
