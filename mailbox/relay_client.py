#!/usr/bin/env python3
"""koine-relay-client — the SEND side of relay mode for a domain without a gateway.

Serves the same loopback contract the proxy-mode mailbox's local side served
(POST /message, bearer LOCAL_TOKEN), so an existing ask_peer needs zero changes —
but instead of queueing locally, it submits to the neutral relay's POST /ask with
this agent's per-agent RELAY_TOKEN and returns the relay's response:
  question      -> blocks until the recipient replies through the relay
  notification  -> the relay 202-queues; returns immediately

(The RECEIVE side of relay mode is the standard poller with POLL_PATH=/inbox.)

Env:
  LOCAL_AGENT    this agent (informational; the relay derives identity from RELAY_TOKEN)
  PEER_AGENT     the edge's remote peer — the only accepted `to`
  RELAY_URL      e.g. https://mailbox.koine.network:8443
  RELAY_TOKEN    this agent's per-agent bearer at the relay
  LOCAL_TOKEN    bearer required on the loopback /message side
Optional:
  LOCAL_PORT (default 8091), REPLY_TIMEOUT (default 210), DOMAIN (observability label),
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
PEER_AGENT = os.environ["PEER_AGENT"].strip()
RELAY_URL = os.environ["RELAY_URL"].rstrip("/")
RELAY_TOKEN = os.environ["RELAY_TOKEN"].strip()
LOCAL_TOKEN = os.environ["LOCAL_TOKEN"].strip()
LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "8091"))
REPLY_TIMEOUT = int(os.environ.get("REPLY_TIMEOUT", "210"))
DOMAIN = os.environ.get("DOMAIN", "").strip()
RELAY_CA = os.environ.get("RELAY_CA", "").strip()

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
        if str(msg.get("to", "")).strip() != PEER_AGENT:
            return self._send(403, {"error": f"this edge only reaches '{PEER_AGENT}'"})
        msg["from"] = LOCAL_AGENT   # informational; the relay re-derives from RELAY_TOKEN
        msg.setdefault("id", os.urandom(6).hex())
        msg.setdefault("thread_id", msg["id"])
        msg.setdefault("ts", _now())
        req = urllib.request.Request(
            RELAY_URL + "/ask", data=json.dumps(msg).encode(),
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
        _lf.log_exchange(
            trace_id=msg.get("thread_id") or msg["id"],
            name=f"{LOCAL_AGENT}->{PEER_AGENT}:{msg.get('type', 'question')}",
            sender=LOCAL_AGENT, target=PEER_AGENT,
            mtype=str(msg.get("type", "question")),
            body=msg.get("body", ""), reply=str(reply.get("body", "")),
            ok=bool(reply.get("ok")), domain=DOMAIN)
        return self._send(status if status in (200, 202) else 502, reply)


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), Handler)
    print(f"koine-relay-client: 127.0.0.1:{LOCAL_PORT}/message -> {RELAY_URL}/ask "
          f"[{LOCAL_AGENT} -> {PEER_AGENT}]", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
