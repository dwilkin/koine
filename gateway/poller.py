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
     PEER_AGENT (required — the edge's remote peer), LOCAL_AGENT (default "atlas"),
     POLL_PATH (default "/outbox"), MAILBOX_CA (optional — omit for a publicly-trusted cert).
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
# encrypt outbound replies, so the relay only ever carries ciphertext. ENC_REQUIRE=1 refuses a
# plaintext inbound on an encrypted edge. No keys set -> plaintext passthrough (unchanged).
MY_PRIVKEY = os.environ.get("MY_PRIVKEY", "").strip()
PEER_PUBKEY = os.environ.get("PEER_PUBKEY", "").strip()
ENC = bool(MY_PRIVKEY and PEER_PUBKEY)
ENC_REQUIRE = os.environ.get("ENC_REQUIRE", "").strip() in ("1", "true", "yes")
if ENC:
    import crypto
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://agent-gateway:8095").rstrip("/")
# A domain WITHOUT a gateway (single agent) points the poller straight at its answerer:
# GATEWAY_URL=http://127.0.0.1:8090 GATEWAY_PATH=/ask (the answerer's {ok,body,meta} response
# is posted back as the reply — shape-compatible with the gateway reply for the sender's client).
GATEWAY_PATH = os.environ.get("GATEWAY_PATH", "/message").strip()
GW_BEARER_TOKEN = os.environ["GW_BEARER_TOKEN"].strip()
PEER_AGENT = os.environ["PEER_AGENT"].strip()          # whose mailbox this is — the forced `from`
LOCAL_AGENT = os.environ.get("LOCAL_AGENT", "atlas").strip()

CTX = ssl.create_default_context(cafile=MAILBOX_CA) if MAILBOX_CA \
    else ssl.create_default_context()


def _req(url, body=None, bearer="", ctx=None, timeout=35):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {bearer}"},
        method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read())


def handle(env):
    env["from"] = PEER_AGENT          # structural identity: this poller only ever speaks for its peer
    reply = None
    if ENC:
        if ENC_REQUIRE and not crypto.is_sealed(env):
            reply = {"ok": False, "body": "unencrypted message refused on an encrypted edge"}
        else:
            try:                      # decrypt the inbound body before it reaches the answerer
                env = crypto.open_body(env, MY_PRIVKEY, PEER_PUBKEY)
            except Exception as e:
                reply = {"ok": False, "body": f"decrypt failed: {e}"}
    if reply is not None:
        pass
    elif str(env.get("to", "")).strip() != LOCAL_AGENT:
        reply = {"ok": False,
                 "body": f"refused: {PEER_AGENT}<->{LOCAL_AGENT} is the only granted edge"}
    else:
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
    if ENC:                           # encrypt the reply body back to the sender
        reply.setdefault("id", env.get("id", ""))
        reply.setdefault("thread_id", env.get("thread_id", env.get("id", "")))
        try:
            reply = crypto.seal_body(reply, MY_PRIVKEY, PEER_PUBKEY)
        except Exception as e:
            reply = {"ok": False, "body": f"reply encrypt failed: {e}",
                     "id": env.get("id", "")}
    _req(MAILBOX_URL + "/reply", {"reply_to": env.get("id", ""), "reply": reply},
         MAILBOX_TOKEN, CTX, timeout=15)
    print(f"relayed id={env.get('id')} type={env.get('type')} enc={ENC}", flush=True)


def main():
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
