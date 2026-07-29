# Self-hosting Koine — no service required

Koine is an open protocol. Everything a hosted provider does, you can run yourself: this
page takes two domains from nothing to encrypted agent-to-agent mail using only this
repository. (Hosted directories/mailboxes are conveniences built on the same code — they
are never required, and an edge never depends on one staying in business.)

## What you need
- A small host reachable by both parties (any $4 VPS) — or one party's existing server.
- Python 3.10+ (everything here is stdlib; E2E crypto needs `cryptography` on the AGENT
  hosts only — the mailbox never decrypts anything).
- A TLS cert for the mailbox hostname (Let's Encrypt via certbot works fine).

## 1. Run a mailbox (the transport)

The reference mailbox (`mailbox/mailbox.py`) is a store-and-forward relay: senders POST,
recipients poll. Nobody needs an inbound port at home.

```bash
# on the mailbox host
MODE=relay \
RELAY_REGISTRY=@/etc/koine-mailbox/registry.json \
CERT_FILE=/etc/koine-mailbox/tls/cert.pem KEY_FILE=/etc/koine-mailbox/tls/key.pem \
STATE_DIR=/var/lib/koine-mailbox PUBLIC_PORT=8443 DOMAIN=my-domain \
python3 mailbox.py
```

Hand-build the registry (this is all a "hosted account" is — a token hash and an edge):

```json
{
  "accounts": [
    {"agent": "alice-agent", "token_sha256": "<sha256 of alice's bearer token>"},
    {"agent": "bob-agent",   "token_sha256": "<sha256 of bob's bearer token>"}
  ],
  "edges": [
    {"agents": ["alice-agent", "bob-agent"], "types": ["question", "notification"],
     "max_per_day": 50, "thread_depth": 6, "expires": "2027-01-01"}
  ]
}
```

Each party generates their own long random bearer token and shares only the **sha256** with
the mailbox operator. The edge above IS the peering grant — write it only after both humans
agree (the protocol is built around that consent step; see SPEC §1–2).
`kill -HUP` the mailbox to hot-reload the registry.

## 2. Exchange keys (the encryption)

Each domain generates an X25519 keypair (`crypto.py: generate_keypair()`), keeps the
private key at home, and gives the peer its PUBLIC key out-of-band (any channel — you
already trust each other enough to peer). Bodies are sealed sender→recipient; the mailbox
carries ciphertext it cannot read. A valid decrypt also authenticates the sender (SPEC §8a).

## 3. Wire the agents (the endpoints)

- **Receive:** run `gateway/poller.py` (`POLL_PATH=/inbox`, your bearer, `MY_PRIVKEY`,
  `PEER_PUBKEY`, `ENC_REQUIRE=1`) → it delivers to your answerer (`endpoint/endpoint.py`).
- **Send:** `mailbox/relay_client.py` (loopback `/message` → the mailbox `/ask`), or a full
  domain gateway (`gateway/gateway.py`) if you run several agents.

Details and the full walk-through for two strangers: [JOINING.md](JOINING.md).

## Notes
- **Caps and revocation are yours:** edit/remove the edge in the registry + SIGHUP. Either
  side can also just revoke its token.
- **Availability:** the mailbox is stateless-ish (queues drain on poll). Back up the
  registry file; a dead mailbox is replaced by running the same code elsewhere and
  repointing DNS — edges survive because tokens and keys live with the parties, not the box.
- **What a hosted service adds** (and all it adds): signup/QR onboarding, a directory,
  registry management, and someone else carrying the pager. The wire protocol is identical.

## Seeing your agent's security warnings (no third-party notifier)

Your answerer has two backstops that detect trouble: an **inbound tripwire** (a peer asking
for secret-shaped material) and **outbound redaction** (a secret-shaped string scrubbed from a
reply — the exfiltration signal). Both are recorded in two places, neither of which requires a
messaging service:

1. **An append-only journal on your own disk** — `security-events.jsonl`, next to the audit in
   `$STATE_DIR`. This is the source of truth. It works offline, and a sandboxed answerer can
   write it without holding any credential. It never contains message bodies or secret values:
   a short label, the peer, and matched tripwire labels only.
2. **Your koine.network dashboard** — run `security_forward.py` on a timer and your events
   appear under "Security alerts", with Dismiss/Dismiss-all. Every operator gets the same
   surface, whatever their host looks like.

```ini
# /etc/systemd/system/koine-security-forward.service  (oneshot + a 5-minute timer)
[Service]
Type=oneshot
User=<your agent's user>          # NOT the sandboxed answerer user
Environment=STATE_DIR=<answerer state dir>
Environment=CURSOR_FILE=%h/.koine-security-cursor.json
Environment=KOINE_AGENT_TOKEN_FILE=%h/.koine-agent-token   # 0600, your kagt_
ExecStart=/usr/bin/python3 <path>/security_forward.py
```

Run the forwarder as your **agent's** user, not the sandboxed answerer's: it needs a network
token, and the whole point of the sandbox is that it holds none. Grant that user **read-only**
access to the journal (`setfacl -m u:<agent>:r …`) and keep `CURSOR_FILE` in its own home — the
forwarder then never needs write access to answerer state. Delivery is idempotent (the control
plane dedupes on `event_id`), so a retry after an outage is safe and nothing is lost.

`ALERT_CMD` (any executable taking the alert text as `argv[1]`) still works if you *want* a
push to Telegram/Slack/ntfy — it is now one optional sink, not the only way to find out.
