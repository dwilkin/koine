#!/usr/bin/env python3
"""a2a-poller — collects ONE peer's queued A2A envelopes from its mailbox and runs them through
OUR gateway (SPEC.md §8 asymmetric transport: a domain that accepts no inbound, so this side
dials out and polls). One poller instance per federated peer (PEER_AGENT), each pointed at that
peer's mailbox.

Loop: GET {MAILBOX}{POLL_PATH}?wait=25 (bearer; pinned cert if self-signed) -> for each envelope,
force from=PEER_AGENT (structural identity — NEVER trust the remote box's claimed `from`; this is
what prevents a peer from impersonating another agent), refuse any target but LOCAL_AGENT (the
only granted edge), POST to the gateway /message (bootstrap bearer), then POST the gateway's full
reply back to {MAILBOX}/reply.

POLL_PATH selects the topology, the job is identical ("collect messages addressed to me"):
  /outbox (default) — the peer SELF-HOSTS its mailbox (proxy mode); we drain its outbound queue.
  /inbox            — a NEUTRAL relay hosts the edge (relay mode); we drain our own inbox there,
                      authenticated by OUR per-agent token.

The gateway still enforces the grant (types/rate/expiry) — this poller is transport, not policy.
Env: MAILBOX_URL, MAILBOX_TOKEN, GATEWAY_URL, GW_BEARER_TOKEN, GATEWAY_PATH (default /message),
     PEER_AGENT (required — the edge's remote peer), LOCAL_AGENT (this domain's receiving
     agent — SET IT EXPLICITLY; the "atlas" default exists only for back-compat with
     deployments that predate the extraction), POLL_PATH (default "/outbox"),
     MAILBOX_CA (optional — omit for a publicly-trusted cert).
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.request

MAILBOX_URL = os.environ["MAILBOX_URL"].rstrip("/")
MAILBOX_TOKEN = os.environ["MAILBOX_TOKEN"].strip()
MAILBOX_CA = os.environ.get("MAILBOX_CA", "").strip()
POLL_PATH = os.environ.get("POLL_PATH", "/outbox").strip()

# E2E body encryption (KN1) — opt-in: set MY_PRIVKEY + PEER_PUBKEY to decrypt inbound asks and
# encrypt outbound replies, so the relay only ever carries ciphertext. No keys set -> plaintext
# passthrough (unchanged). KO-M1 (2026-07-23): on an ENCRYPTED edge (keys present) an unsealed
# inbound is now ALWAYS refused — fail-closed against a relay downgrading/substituting a
# plaintext body. ENC_REQUIRE is retained for back-compat but is implied on every encrypted
# edge; edges without keys are unaffected.
MY_PRIVKEY = os.environ.get("MY_PRIVKEY", "").strip()
PEER_PUBKEY = os.environ.get("PEER_PUBKEY", "").strip()
ENC = bool(MY_PRIVKEY and PEER_PUBKEY)
ENC_REQUIRE = os.environ.get("ENC_REQUIRE", "").strip() in ("1", "true", "yes")  # implied on enc edges
if ENC:
    import crypto
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://koine-gateway:8095").rstrip("/")
# A domain WITHOUT a gateway (single agent) points the poller straight at its answerer:
# GATEWAY_URL=http://127.0.0.1:8090 GATEWAY_PATH=/ask (the answerer's {ok,body,meta} response
# is posted back as the reply — shape-compatible with the gateway reply for the sender's client).
GATEWAY_PATH = os.environ.get("GATEWAY_PATH", "/message").strip()
GW_BEARER_TOKEN = os.environ["GW_BEARER_TOKEN"].strip()
LOCAL_AGENT = os.environ.get("LOCAL_AGENT", "atlas").strip()

# MULTI-PEER mode (a hub-account draining mail from MANY peers on one relay account — e.g. an
# agent that auto-accepts connections): set PEERS_FILE=@/path.json = {"<agent>":{"pubkey":"…"}}.
# Then this poller drains the WHOLE inbox (no from-filter) and routes each message by its REAL
# sender: sender must be a KNOWN peer, and on an encrypted edge the body must DECRYPT with that
# peer's pubkey — a valid decrypt authenticates `from` (a wrong sender can't be forged, X25519
# static-static). The gateway re-checks the grant. Single-peer mode (PEER_AGENT set) is unchanged.
PEERS_FILE = os.environ.get("PEERS_FILE", "").strip()
MULTI = bool(PEERS_FILE)
PEER_AGENT = os.environ.get("PEER_AGENT", "").strip()   # single mode: the forced `from`
if MULTI and MY_PRIVKEY:
    import crypto                                        # multi mode needs per-peer crypto
_PEERS = {}


def _load_peers():
    global _PEERS
    if not PEERS_FILE:
        return
    path = PEERS_FILE[1:] if PEERS_FILE.startswith("@") else PEERS_FILE
    try:
        _PEERS = json.load(open(path))
    except Exception as e:
        print(f"peers file unreadable ({path}): {e}", flush=True)


CTX = ssl.create_default_context(cafile=MAILBOX_CA) if MAILBOX_CA \
    else ssl.create_default_context()


def _sealed(env):
    """Structural sealed-check (mirrors crypto.is_sealed; no `cryptography` import needed)."""
    return isinstance(env, dict) and isinstance(env.get("enc"), dict)


def _inbound_seal_error(env, enc_edge):
    """KO-M1 (fail-closed on downgrade): on an E2E edge (this side holds keys for the peer),
    an inbound envelope MUST arrive sealed — otherwise a neutral/malicious relay could
    substitute a plaintext body and have it processed. Returns refusal text, or None."""
    if enc_edge and not _sealed(env):
        return ("unencrypted message refused on an encrypted edge "
                "(E2E sealing required; possible downgrade by the transport)")
    return None


def _req(url, body=None, bearer="", ctx=None, timeout=35):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {bearer}"},
        method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read())


def handle(env):
    # Resolve the sender + that edge's pubkey. SINGLE mode forces from=PEER_AGENT (this poller only
    # ever speaks for its peer). MULTI mode takes the relay-stamped `from`, requires it to be a
    # KNOWN peer, and authenticates it by decrypt (below).
    if MULTI:
        sender = str(env.get("from", "")).strip()
        peer = _PEERS.get(sender)
        if peer is None:
            _reply_err(env, f"unknown sender '{sender}' (no synced edge)")
            return
        peer_pub = peer.get("pubkey", "")
        enc_edge = bool(MY_PRIVKEY and peer_pub)
    else:
        sender = PEER_AGENT
        env["from"] = sender          # structural identity for the single edge
        peer_pub = PEER_PUBKEY
        enc_edge = ENC

    reply = None
    seal_err = _inbound_seal_error(env, enc_edge)
    if seal_err:                      # KO-M1: never process a plaintext body on an E2E edge
        reply = {"ok": False, "body": seal_err}
        print(f"REFUSED unsealed inbound on E2E edge from={sender} id={env.get('id')}", flush=True)
    elif enc_edge:
        try:                          # a valid decrypt with the sender's pubkey AUTHENTICATES `from`
            env = crypto.open_body(env, MY_PRIVKEY, peer_pub)
        except Exception as e:
            reply = {"ok": False, "body": f"decrypt/auth failed: {e}"}
    if reply is None:
        if str(env.get("to", "")).strip() != LOCAL_AGENT:
            reply = {"ok": False, "body": f"refused: not addressed to {LOCAL_AGENT}"}
        else:
            env["from"] = sender      # authenticated sender handed to the gateway
            try:
                reply = _req(GATEWAY_URL + GATEWAY_PATH, env, GW_BEARER_TOKEN, timeout=230)
            except urllib.error.HTTPError as e:
                try:
                    reply = json.loads(e.read())
                except Exception:
                    reply = {"ok": False, "body": f"gateway HTTP {e.code}"}
                reply.setdefault("ok", False)
            except Exception as e:
                reply = {"ok": False, "body": f"gateway unreachable: {e}"}
    if enc_edge:                      # encrypt the reply body back to the sender
        reply.setdefault("id", env.get("id", ""))
        reply.setdefault("thread_id", env.get("thread_id", env.get("id", "")))
        try:
            reply = crypto.seal_body(reply, MY_PRIVKEY, peer_pub)
        except Exception as e:
            reply = {"ok": False, "body": f"reply encrypt failed: {e}", "id": env.get("id", "")}
    _req(MAILBOX_URL + "/reply", {"reply_to": env.get("id", ""), "reply": reply},
         MAILBOX_TOKEN, CTX, timeout=15)
    print(f"relayed from={sender} id={env.get('id')} type={env.get('type')} enc={enc_edge}", flush=True)


def _reply_err(env, msg):
    """Post a plaintext error reply for an envelope we refuse before decrypt (unknown sender)."""
    try:
        _req(MAILBOX_URL + "/reply", {"reply_to": env.get("id", ""),
             "reply": {"ok": False, "body": msg}}, MAILBOX_TOKEN, CTX, timeout=15)
    except Exception:
        pass
    print(f"refused from={env.get('from')} id={env.get('id')}: {msg}", flush=True)


def main():
    _load_peers()
    if MULTI:                          # hot-reload the peer set (edge-sync adds peers) on SIGHUP
        import signal
        signal.signal(signal.SIGHUP, lambda *_: (_load_peers(),
                      print(f"koine-poller: peers reloaded — {len(_PEERS)} peer(s)", flush=True)))
        print(f"koine-poller: MULTI {MAILBOX_URL}{POLL_PATH} -> {GATEWAY_URL} "
              f"({len(_PEERS)} peers)", flush=True)
    else:
        print(f"koine-poller: {MAILBOX_URL}{POLL_PATH} -> {GATEWAY_URL}", flush=True)
    backoff = 1
    while True:
        try:
            out = _req(MAILBOX_URL + POLL_PATH + "?wait=25", bearer=MAILBOX_TOKEN, ctx=CTX, timeout=40)
            backoff = 1
            for env in out.get("envelopes", []):
                try:
                    handle(env)
                except Exception as e:
                    print(f"ERROR handling envelope: {e}", flush=True)
        except Exception as e:
            print(f"poll error: {e} (retry in {backoff}s)", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    main()
