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
agree (that consent step is the protocol's heart, not paperwork; see SPEC §1–2).
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
