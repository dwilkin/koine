#!/usr/bin/env python3
"""koine-mailbox — a store-and-forward rendezvous for one Koine edge.

Koine's recommended default transport (SPEC.md §8): a domain that can accept a public inbound
connection hosts a mailbox; a domain that cannot (home network, employer network) reaches it by
polling OUTBOUND — so neither side needs to open a hole it doesn't want to. A publicly-reachable
mailbox is the norm; tunnels are the exception.

This is the SINGLE-EDGE reference server (one local agent <-> one remote peer). A multi-tenant
service (koine.network) wraps this same core with accounts, many queues, and a directory — but the
per-edge contract below is identical, so anything proven here is proven there.

Public TLS side (:8443, bearer EDGE_BEARER — a publicly-trusted cert needs no pinning):
  POST /ask            remote gateway -> proxied to the LOCAL answer-endpoint  (peer -> us)
  GET  /outbox?wait=N  long-poll queued envelopes                             (us -> peer)
  POST /reply          the peer's poller returns our gateway's reply object
  GET  /health         open (no auth; leaks only liveness + queue depth + grant-expiry)
Local side (127.0.0.1:8091, bearer LOCAL_TOKEN):
  POST /message        our own ask_peer submits here (gateway /message contract); blocks
                       until the reply arrives via POST /reply (or times out).

Defense in depth: the RECEIVING edge (/ask) re-enforces the grant HERE (type allow-list, daily
cap, thread-depth, dedup) — not only on the peer's gateway. Keep GRANT_* in lockstep with the
grant recorded in your gateway's agents.json.

Kill switch: $STATE_DIR/DISABLED -> 503 on everything but /health.
Audit: $STATE_DIR/audit.jsonl (metadata only — bodies live in each domain's own audit).

Required env:
  LOCAL_AGENT   this domain's agent identity (the `from` stamped on our outbound asks)
  PEER_AGENT    the remote peer allowed on this edge (the only `from` accepted on /ask)
  EDGE_BEARER   shared bearer for the public edge (exchanged human-to-human, out of band)
  LOCAL_TOKEN   bearer for the loopback /message side (intra-box only)
  CERT_FILE, KEY_FILE   TLS cert/key for :8443
Optional env:
  STATE_DIR (default /var/lib/koine-mailbox), ENDPOINT_URL (default http://127.0.0.1:8090),
  REPLY_TIMEOUT (default 210), DOMAIN (observability label), PUBLIC_PORT (default 8443),
  LOCAL_PORT (default 8091), GRANT_TYPES (default question,notification), GRANT_MAX_PER_DAY
  (default 20), GRANT_THREAD_DEPTH (default 6), GRANT_EXPIRES (YYYY-MM-DD), SEEN_TTL (default 900).
"""
import hmac
import json
import os
import pathlib
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # observability is optional — the mailbox runs fine without it
    import langfuse_emit as _lf
except Exception:  # pragma: no cover
    class _lf:  # type: ignore
        @staticmethod
        def log_exchange(**_):
            return None

LOCAL_AGENT = os.environ["LOCAL_AGENT"].strip()
PEER_AGENT = os.environ["PEER_AGENT"].strip()
EDGE_BEARER = os.environ["EDGE_BEARER"].strip()
LOCAL_TOKEN = os.environ["LOCAL_TOKEN"].strip()
CERT_FILE = os.environ.get("CERT_FILE", "/etc/koine-mailbox/mailbox-cert.pem")
KEY_FILE = os.environ.get("KEY_FILE", "/etc/koine-mailbox/mailbox-key.pem")
STATE_DIR = pathlib.Path(os.environ.get("STATE_DIR", "/var/lib/koine-mailbox"))
ENDPOINT_URL = os.environ.get("ENDPOINT_URL", "http://127.0.0.1:8090").rstrip("/")
REPLY_TIMEOUT = int(os.environ.get("REPLY_TIMEOUT", "210"))
DOMAIN = os.environ.get("DOMAIN", "").strip()
PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "8443"))
LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "8091"))
MAX_QUEUE = 50

GRANT_TYPES = {t.strip() for t in
               os.environ.get("GRANT_TYPES", "question,notification").split(",") if t.strip()}
GRANT_MAX_PER_DAY = int(os.environ.get("GRANT_MAX_PER_DAY", "20"))
GRANT_THREAD_DEPTH = int(os.environ.get("GRANT_THREAD_DEPTH", "6"))
GRANT_EXPIRES = os.environ.get("GRANT_EXPIRES", "").strip()   # "YYYY-MM-DD"
SEEN_TTL = int(os.environ.get("SEEN_TTL", "900"))
SERVICE_NAME = "koine-mailbox"

DB_PATH = STATE_DIR / "edge.db"
_db_lock = threading.Lock()
STATE_DIR.mkdir(parents=True, exist_ok=True)
KILL = STATE_DIR / "DISABLED"
AUDIT = STATE_DIR / "audit.jsonl"
_audit_lock = threading.Lock()

OUTBOX = deque()                 # queued envelopes awaiting pickup
RESULTS = {}                     # id -> reply object
EVENTS = {}                      # id -> threading.Event
_lock = threading.Lock()
_outbox_event = threading.Event()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _audit_write(kind, **meta):
    rec = {"ts": _now(), "kind": kind, **meta}
    with _audit_lock, open(AUDIT, "a") as f:
        f.write(json.dumps(rec) + "\n")


def _db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init_db():
    with _db_lock, _db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS asks "
                  "(id TEXT PRIMARY KEY, thread_id TEXT, ts REAL, day TEXT)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_thread ON asks(thread_id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_day ON asks(day)")


def _grant_gate(msg):
    """Independent receiving-edge grant enforcement + /ask idempotency. Only cross-domain /ask
    reaches here, so per-thread counting == cross-domain hops only (SPEC.md §5)."""
    mtype = str(msg.get("type", "question"))
    if mtype not in GRANT_TYPES:
        return 403, f"type '{mtype}' not permitted by the local grant ({sorted(GRANT_TYPES)})"
    mid = str(msg.get("id", "")).strip()
    tid = str(msg.get("thread_id", "") or mid).strip()
    now = time.time()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _db_lock, _db() as c:
        if mid:
            row = c.execute("SELECT ts FROM asks WHERE id=?", (mid,)).fetchone()
            if row and now - row["ts"] < SEEN_TTL:
                return 409, "duplicate message id (replay/retry) — already handled"
        n_day = c.execute("SELECT COUNT(*) n FROM asks WHERE day=?", (day,)).fetchone()["n"]
        if n_day >= GRANT_MAX_PER_DAY:
            return 429, f"local grant daily cap reached ({GRANT_MAX_PER_DAY}/day)"
        n_thr = c.execute("SELECT COUNT(*) n FROM asks WHERE thread_id=?", (tid,)).fetchone()["n"]
        if n_thr >= GRANT_THREAD_DEPTH:
            return 429, f"local grant thread-depth cap reached ({GRANT_THREAD_DEPTH})"
        c.execute("INSERT OR REPLACE INTO asks (id, thread_id, ts, day) VALUES (?,?,?,?)",
                  (mid or os.urandom(6).hex(), tid, now, day))
    return None


def _days_to_expiry():
    if not GRANT_EXPIRES:
        return None
    try:
        exp = datetime.strptime(GRANT_EXPIRES, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return (exp - datetime.now(timezone.utc)).days
    except ValueError:
        return None


class BaseH(BaseHTTPRequestHandler):
    server_version = SERVICE_NAME + "/1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        payload = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self, cap=65536):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n <= 0 or n > cap:
            return None
        try:
            obj = json.loads(self.rfile.read(n))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    def _authed(self, token):
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        return bool(tok) and hmac.compare_digest(tok, token)


class PublicHandler(BaseH):
    """TLS :PUBLIC_PORT — the remote peer's side (they POST /ask, GET /outbox, POST /reply)."""

    def do_GET(self):
        if self.path == "/health":
            body = {"status": "ok", "service": SERVICE_NAME,
                    "disabled": KILL.exists(), "outbox": len(OUTBOX)}
            d = _days_to_expiry()
            if d is not None:
                body["days_until_grant_expiry"] = d
            return self._send(200, body)
        if KILL.exists():
            return self._send(503, {"error": "mailbox disabled (kill switch)"})
        if not self._authed(EDGE_BEARER):
            return self._send(401, {"error": "unauthorized"})
        if self.path.startswith("/outbox"):
            wait = 0
            if "wait=" in self.path:
                try:
                    wait = max(0, min(60, int(self.path.split("wait=")[1].split("&")[0])))
                except ValueError:
                    pass
            deadline = time.time() + wait
            while True:
                with _lock:
                    if OUTBOX:
                        env = OUTBOX.popleft()
                        _audit_write("pickup", id=env.get("id"), to=env.get("to"),
                                     type=env.get("type"))
                        return self._send(200, {"envelopes": [env]})
                    _outbox_event.clear()
                remaining = deadline - time.time()
                if remaining <= 0:
                    return self._send(200, {"envelopes": []})
                _outbox_event.wait(min(remaining, 5))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if KILL.exists():
            return self._send(503, {"error": "mailbox disabled (kill switch)"})
        if not self._authed(EDGE_BEARER):
            return self._send(401, {"error": "unauthorized"})
        msg = self._body()
        if msg is None:
            return self._send(400, {"error": "bad body"})
        if self.path == "/reply":
            rid = str(msg.get("reply_to", "")).strip()
            if not rid:
                return self._send(400, {"error": "reply_to required"})
            with _lock:
                RESULTS[rid] = msg.get("reply", {})
                ev = EVENTS.get(rid)
            if ev:
                ev.set()
            _audit_write("reply", id=rid, ok=msg.get("reply", {}).get("ok"))
            return self._send(200, {"ok": True})
        if self.path == "/ask":
            # peer -> us: only the granted peer, then independent grant enforcement + dedup.
            if str(msg.get("from", "")).strip() != PEER_AGENT:
                return self._send(403, {"error": f"only '{PEER_AGENT}' may ask on this edge"})
            gate = _grant_gate(msg)
            if gate:
                code, reason = gate
                _audit_write("ask_refused", id=msg.get("id"), frm=msg.get("from"),
                             type=msg.get("type"), code=code, reason=reason)
                return self._send(code, {"ok": False, "body": reason})
            _audit_write("inbound_ask", id=msg.get("id"), frm=msg.get("from"),
                         type=msg.get("type"))
            req = urllib.request.Request(
                ENDPOINT_URL + "/ask", data=json.dumps(msg).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {LOCAL_TOKEN}"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=REPLY_TIMEOUT) as r:
                    data = json.loads(r.read())
                pm = (data.get("meta") or {}) if isinstance(data, dict) else {}
                _lf.log_exchange(
                    trace_id=msg.get("thread_id") or msg.get("id"),
                    name=f"{msg.get('from','?')}->{LOCAL_AGENT}:{msg.get('type','question')}",
                    sender=str(msg.get("from", "?")), target=LOCAL_AGENT,
                    mtype=str(msg.get("type", "question")),
                    body=msg.get("body", ""), reply=str(data.get("body", "")),
                    ok=bool(data.get("ok", True)), domain=DOMAIN,
                    latency_ms=int(pm["elapsed"] * 1000) if pm.get("elapsed") else None,
                    cost_usd=pm.get("cost_usd"))
                return self._send(r.status, data)
            except urllib.error.HTTPError as e:
                return self._send(e.code, {"ok": False,
                                           "body": e.read().decode(errors="replace")[:300]})
            except Exception as e:
                return self._send(502, {"ok": False, "body": f"endpoint unreachable: {e}"})
        return self._send(404, {"error": "not found"})


class LocalHandler(BaseH):
    """127.0.0.1:LOCAL_PORT — our own ask_peer submits here (gateway /message contract)."""

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "side": "local",
                                    "disabled": KILL.exists()})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/message":
            return self._send(404, {"error": "not found"})
        if KILL.exists():
            return self._send(503, {"error": "mailbox disabled (kill switch)"})
        if not self._authed(LOCAL_TOKEN):
            return self._send(401, {"error": "unauthorized"})
        msg = self._body()
        if msg is None:
            return self._send(400, {"error": "bad body"})
        msg["from"] = LOCAL_AGENT          # identity is structural, not caller-asserted
        msg.setdefault("id", os.urandom(6).hex())
        msg.setdefault("thread_id", msg["id"])
        msg.setdefault("ts", _now())
        if str(msg.get("to", "")).strip() != PEER_AGENT:
            return self._send(403, {"error": f"this edge only reaches '{PEER_AGENT}'"})
        with _lock:
            if len(OUTBOX) >= MAX_QUEUE:
                return self._send(429, {"error": "outbox full"})
            ev = EVENTS[msg["id"]] = threading.Event()
            OUTBOX.append(msg)
        _outbox_event.set()
        _audit_write("queued", id=msg["id"], to=msg["to"], type=msg.get("type"))
        ok = ev.wait(REPLY_TIMEOUT)
        with _lock:
            EVENTS.pop(msg["id"], None)
            reply = RESULTS.pop(msg["id"], None)
        if not ok or reply is None:
            return self._send(504, {"error": f"no reply from the '{PEER_AGENT}' gateway "
                                             f"within {REPLY_TIMEOUT}s (poller down?)"})
        rm = (reply.get("meta") or {}) if isinstance(reply, dict) else {}
        _lf.log_exchange(
            trace_id=msg.get("thread_id") or msg.get("id"),
            name=f"{LOCAL_AGENT}->{msg.get('to')}:{msg.get('type','question')}",
            sender=LOCAL_AGENT, target=str(msg.get("to", PEER_AGENT)),
            mtype=str(msg.get("type", "question")),
            body=msg.get("body", ""), reply=str(reply.get("body", "")),
            ok=bool(reply.get("ok")), domain=DOMAIN,
            latency_ms=int(rm["elapsed"] * 1000) if rm.get("elapsed") else None)
        return self._send(200 if reply.get("ok") else 502, reply)


def main():
    _init_db()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    pub = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), PublicHandler)
    pub.socket = ctx.wrap_socket(pub.socket, server_side=True)
    loc = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), LocalHandler)
    threading.Thread(target=pub.serve_forever, daemon=True).start()
    print(f"{SERVICE_NAME}: public :{PUBLIC_PORT} (TLS) + local 127.0.0.1:{LOCAL_PORT} "
          f"[{LOCAL_AGENT} <-> {PEER_AGENT}]", flush=True)
    loc.serve_forever()


if __name__ == "__main__":
    main()
