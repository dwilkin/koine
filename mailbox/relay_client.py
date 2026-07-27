#!/usr/bin/env python3
"""koine-relay-client — the SEND side of relay mode for a domain without a gateway.

Serves the same loopback contract the proxy-mode mailbox's local side served
(POST /message, bearer LOCAL_TOKEN), so an existing ask_peer needs zero changes —
but instead of queueing locally, it submits to the neutral relay's POST /ask with
this agent's per-agent RELAY_TOKEN and returns the relay's response:
  question      -> blocks until the recipient replies through the relay
  notification  -> the relay 202-queues; returns immediately

(The RECEIVE side of relay mode is the standard poller with POLL_PATH=/inbox.)

MULTI-PEER (default for any agent with more than one edge): set PEERS_FILE=@/path.json =
{"<agent>":{"pubkey":"…"}} — the SAME file the receive-side poller uses, and the same file
koine's edge-sync already writes. Then this client will send to ANY peer in that map, sealing
per-peer with that peer's key. SIGHUP hot-reloads it, so a newly-approved edge becomes sendable
without a restart. Single-peer mode (PEER_AGENT, no PEERS_FILE) is unchanged for back-compat.

Peering is many-to-many by design (SPEC §5): an agent accumulates edges over time, so the send
side must not be pinned to one peer. It used to be, which meant an agent could RECEIVE from
many peers (the poller has had MULTI for a while) but only ever SEND to one — fixed 2026-07-27.

Env:
  LOCAL_AGENT    this agent (informational; the relay derives identity from RELAY_TOKEN)
  PEER_AGENT     single-peer mode: the edge's remote peer — the only accepted `to`
                 (optional when PEERS_FILE is set)
  RELAY_URL      e.g. https://mailbox.koine.network:8443
  RELAY_TOKEN    this agent's per-agent bearer at the relay
  LOCAL_TOKEN    bearer required on the loopback /message side
Optional:
  PEERS_FILE (multi-peer routing; see above), LOCAL_PORT (default 8091),
  REPLY_TIMEOUT (default 210), DOMAIN (observability label),
  RELAY_CA (pin a self-signed relay cert; omit for a publicly-trusted one)
"""
import json
import os
import ssl
import hmac
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # observability optional — runs fine without it
    import langfuse_emit as _lf
except Exception:  # pragma: no cover
    class _lf:  # type: ignore
        @staticmethod
        def log_exchange(**_):
            return None

LOCAL_AGENT = os.environ["LOCAL_AGENT"].strip()
PEERS_FILE = os.environ.get("PEERS_FILE", "").strip()
MULTI = bool(PEERS_FILE)
# single-peer mode still REQUIRES PEER_AGENT; multi mode makes it optional (and uses it only as
# the default `to` when a caller omits one, preserving old one-peer call sites verbatim).
PEER_AGENT = (os.environ.get("PEER_AGENT", "") if MULTI
              else os.environ["PEER_AGENT"]).strip()
RELAY_URL = os.environ["RELAY_URL"].rstrip("/")
RELAY_TOKEN = os.environ["RELAY_TOKEN"].strip()
LOCAL_TOKEN = os.environ["LOCAL_TOKEN"].strip()
LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "8091"))
REPLY_TIMEOUT = int(os.environ.get("REPLY_TIMEOUT", "210"))
DOMAIN = os.environ.get("DOMAIN", "").strip()
RELAY_CA = os.environ.get("RELAY_CA", "").strip()

# E2E body encryption (KN1) — opt-in: MY_PRIVKEY + PEER_PUBKEY encrypt the outbound body and
# decrypt the reply, so the relay only carries ciphertext. Unset -> plaintext (unchanged).
MY_PRIVKEY = os.environ.get("MY_PRIVKEY", "").strip()
PEER_PUBKEY = os.environ.get("PEER_PUBKEY", "").strip()
ENC = bool(MY_PRIVKEY and PEER_PUBKEY)
if ENC or (MULTI and MY_PRIVKEY):
    import crypto

_PEERS = {}


def _load_peers():
    """{'<agent>': {'pubkey': '…'}} — same shape the poller and edge-sync use."""
    global _PEERS
    if not PEERS_FILE:
        return
    path = PEERS_FILE[1:] if PEERS_FILE.startswith("@") else PEERS_FILE
    try:
        _PEERS = json.load(open(path))
    except Exception as e:
        print(f"peers file unreadable ({path}): {e}", flush=True)


def _resolve(to: str):
    """(target_agent, peer_pubkey_or_'', error_or_None) for an outbound `to`."""
    if MULTI:
        target = to or PEER_AGENT
        if not target:
            return None, "", "`to` is required (this client serves multiple peers)"
        rec = _PEERS.get(target)
        if rec is None:
            known = sorted(_PEERS)
            return None, "", (f"no edge to '{target}' — known peers: {known or 'none yet'}. "
                              "A newly approved edge appears after the next edge-sync + SIGHUP.")
        return target, str((rec or {}).get("pubkey", "")), None
    if to != PEER_AGENT:
        return None, "", f"this edge only reaches '{PEER_AGENT}'"
    return PEER_AGENT, PEER_PUBKEY, None

CTX = ssl.create_default_context(cafile=RELAY_CA) if RELAY_CA else ssl.create_default_context()


def _now():
    return datetime.now(timezone.utc).isoformat()


class Handler(BaseHTTPRequestHandler):
    server_version = "koine-relay-client/1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        payload = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "side": "relay-client",
                                    "relay": RELAY_URL, "agent": LOCAL_AGENT})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/message":
            return self._send(404, {"error": "not found"})
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        if not (tok and hmac.compare_digest(tok, LOCAL_TOKEN)):
            return self._send(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            msg = json.loads(self.rfile.read(n)) if 0 < n <= 65536 else None
        except (ValueError, json.JSONDecodeError):
            msg = None
        if not isinstance(msg, dict):
            return self._send(400, {"error": "bad body"})
        target, peer_pub, err = _resolve(str(msg.get("to", "")).strip())
        if err:
            return self._send(403, {"error": err})
        msg["from"] = LOCAL_AGENT   # informational; the relay re-derives from RELAY_TOKEN
        msg["to"] = target
        msg.setdefault("id", os.urandom(6).hex())
        msg.setdefault("thread_id", msg["id"])
        msg.setdefault("ts", _now())
        msg.setdefault("type", "question")
        # Seal per-peer: in MULTI the key comes from the peers file, so each edge gets its own
        # ciphertext. A peer with no pubkey on file goes plaintext (bootstrap case) rather than
        # failing shut — the relay still enforces the edge grant either way.
        enc = bool(MY_PRIVKEY and peer_pub)
        wire = crypto.seal_body(msg, MY_PRIVKEY, peer_pub) if enc else msg
        req = urllib.request.Request(
            RELAY_URL + "/ask", data=json.dumps(wire).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {RELAY_TOKEN}"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=REPLY_TIMEOUT + 15, context=CTX) as r:
                reply = json.loads(r.read())
                status = r.status
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read())
            except Exception:
                reply = {"ok": False, "body": f"relay HTTP {e.code}"}
            reply.setdefault("ok", False)
            status = e.code
        except Exception as e:
            return self._send(502, {"ok": False, "body": f"relay unreachable: {e}"})
        if enc and crypto.is_sealed(reply):   # decrypt the reply body for our own agent
            try:
                reply = crypto.open_body(reply, MY_PRIVKEY, peer_pub)
            except Exception as e:
                reply = {"ok": False, "body": f"reply decrypt failed: {e}"}
        _lf.log_exchange(
            trace_id=msg.get("thread_id") or msg["id"],
            name=f"{LOCAL_AGENT}->{target}:{msg.get('type', 'question')}",
            sender=LOCAL_AGENT, target=target,
            mtype=str(msg.get("type", "question")),
            body=msg.get("body", ""), reply=str(reply.get("body", "")),
            ok=bool(reply.get("ok")), domain=DOMAIN)
        return self._send(status if status in (200, 202) else 502, reply)


def main():
    _load_peers()
    if MULTI:      # hot-reload the peer set (edge-sync adds peers) on SIGHUP — same as the poller
        import signal
        signal.signal(signal.SIGHUP, lambda *_: (_load_peers(),
                      print(f"koine-relay-client: peers reloaded — {len(_PEERS)} peer(s)",
                            flush=True)))
    srv = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), Handler)
    where = (f"MULTI {sorted(_PEERS) or 'no peers yet'}" if MULTI else f"{LOCAL_AGENT} -> {PEER_AGENT}")
    print(f"koine-relay-client: 127.0.0.1:{LOCAL_PORT}/message -> {RELAY_URL}/ask [{where}]",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
