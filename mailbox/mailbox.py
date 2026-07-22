#!/usr/bin/env python3
"""koine-mailbox — a store-and-forward rendezvous for one Koine edge.

Koine's recommended default transport (SPEC.md §8): a domain that can accept a public inbound
connection hosts a mailbox; a domain that cannot (home network, employer network) reaches it by
polling OUTBOUND — so neither side needs to open a hole it doesn't want to. A publicly-reachable
mailbox is the norm; tunnels are the exception.

This is the SINGLE-EDGE reference server (exactly two parties). Two modes (env MODE):

MODE=proxy (default) — the co-located mode: this box also hosts the LOCAL agent's answerer.
  Public TLS side (:8443, bearer EDGE_BEARER — a publicly-trusted cert needs no pinning):
    POST /ask            remote gateway -> proxied to the LOCAL answer-endpoint  (peer -> us)
    GET  /outbox?wait=N  long-poll queued envelopes                             (us -> peer)
    POST /reply          the peer's poller returns our gateway's reply object
    GET  /health         open (no auth; leaks only liveness + queue depth + grant-expiry)
  Local side (127.0.0.1:8091, bearer LOCAL_TOKEN):
    POST /message        our own ask_peer submits here (gateway /message contract); blocks
                         until the reply arrives via POST /reply (or times out).

MODE=relay — a NEUTRAL host (the koine.network model): neither agent is on the box; the mailbox
  is a pure two-queue store-and-forward. Per-agent tokens (TOKEN_A/TOKEN_B) are structural
  identity — `from` is derived from which token authenticated, never from the body.
  Public TLS side only:
    POST /ask            sender submits; grant-checked; queued to the OTHER agent's inbox.
                         `question` BLOCKS until the recipient replies (sender sees an ordinary
                         synchronous call); `notification` returns 202 immediately (recipient
                         may be offline — that asymmetry is the point of a mailbox).
    GET  /inbox?wait=N   recipient long-polls messages addressed to IT (its own token)
    POST /reply          recipient returns its reply for a message id (only the recipient may)
    GET  /health         open (mode, per-agent inbox depths, grant expiry)
  A multi-tenant service (koine.network) wraps THIS mode with accounts + many queues + a
  directory; the per-edge contract is identical, so anything proven here is proven there.

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

# MODE:
#   proxy (default) — the original co-located mode: this box also hosts the LOCAL agent's
#     answerer; /ask proxies to it, /outbox holds our outbound. For self-hosters.
#   relay — a NEUTRAL host (koine.network): neither agent is on the box. Two queues, two
#     per-agent tokens (structural identity — `from` is derived from which token authenticated,
#     never from the body). POST /ask blocks for questions, 202-queues notifications;
#     each side long-polls GET /inbox for messages addressed to it and POSTs /reply.
MODE = os.environ.get("MODE", "proxy").strip().lower()

if MODE == "relay":
    # single-edge env (used only when RELAY_REGISTRY is unset — see the registry loader)
    AGENT_A = os.environ.get("AGENT_A", "").strip()
    TOKEN_A = os.environ.get("TOKEN_A", "").strip()
    AGENT_B = os.environ.get("AGENT_B", "").strip()
    TOKEN_B = os.environ.get("TOKEN_B", "").strip()
    LOCAL_AGENT = PEER_AGENT = EDGE_BEARER = LOCAL_TOKEN = ""
    if not os.environ.get("RELAY_REGISTRY", "").strip() and not (AGENT_A and AGENT_B):
        raise SystemExit("relay mode needs either RELAY_REGISTRY or AGENT_A/TOKEN_A/AGENT_B/TOKEN_B")
else:
    LOCAL_AGENT = os.environ["LOCAL_AGENT"].strip()
    PEER_AGENT = os.environ["PEER_AGENT"].strip()
    EDGE_BEARER = os.environ["EDGE_BEARER"].strip()
    LOCAL_TOKEN = os.environ["LOCAL_TOKEN"].strip()
    AGENT_A = TOKEN_A = AGENT_B = TOKEN_B = ""
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

# ── multi-tenant registry (KN2) ──────────────────────────────────────────────────────────────
# relay mode serves MANY accounts and edges from one box. Config source (relay mode only):
#   RELAY_REGISTRY=@/path.json  (or inline JSON) — the source of truth for a hosted service:
#     {"accounts":[{"agent":"a","token_sha256":"…"}|{"agent":"a","token":"…"}],
#      "edges":[{"agents":["a","b"],"types":[…],"max_per_day":N,"thread_depth":N,"expires":"…"}]}
#   else (no registry) — a single edge is SYNTHESIZED from AGENT_A/B + TOKEN_A/B + GRANT_* env,
#     so the single-edge deployment keeps working unchanged.
# Tokens are held as sha256 (the registry file at rest never carries live bearers). Identity is
# ALWAYS the presented token; a registered EDGE (both accounts opted in) is required to exchange
# mail — transport-level allowlist + per-edge grant, NOT authority (the act-grant stays at each
# domain's gateway, SPEC §1/§5).
RELAY_REGISTRY = os.environ.get("RELAY_REGISTRY", "").strip()
_TOKEN_TO_AGENT = {}          # sha256(token) -> agent name
_AGENTS = set()               # all registered account names
_EDGES = {}                   # frozenset({a,b}) -> {"types":set,"max_per_day","thread_depth","expires"}
_registry_lock = threading.Lock()


def _sha(t: str) -> str:
    return __import__("hashlib").sha256(t.encode()).hexdigest()


def _edge_key(a: str, b: str) -> str:
    return "|".join(sorted((a, b)))


def _register_account(agent: str, token: str = "", token_sha256: str = ""):
    _AGENTS.add(agent)
    _TOKEN_TO_AGENT[(token_sha256 or _sha(token))] = agent


def _register_edge(a, b, types, max_per_day, thread_depth, expires):
    _EDGES[frozenset((a, b))] = {"types": set(types), "max_per_day": int(max_per_day),
                                 "thread_depth": int(thread_depth), "expires": expires or ""}


def _load_registry():
    """(Re)build the account/edge tables from the registry file (or synthesized single-edge env).
    Rebuilds into fresh dicts and swaps them atomically, so it is safe to call live (SIGHUP) while
    requests are in flight — the koine.network control plane rewrites registry.json + signals to
    add an account or edge without a restart."""
    global _TOKEN_TO_AGENT, _AGENTS, _EDGES
    t2a, agents, edges = {}, set(), {}

    def reg_account(agent, token="", token_sha256=""):
        agents.add(agent)
        t2a[(token_sha256 or _sha(token))] = agent

    def reg_edge(a, b, types, mpd, depth, expires):
        edges[frozenset((a, b))] = {"types": set(types), "max_per_day": int(mpd),
                                    "thread_depth": int(depth), "expires": expires or ""}

    if RELAY_REGISTRY:
        raw = RELAY_REGISTRY
        data = json.load(open(raw[1:])) if raw.startswith("@") else json.loads(raw)
        for acc in data.get("accounts", []):
            reg_account(acc["agent"], acc.get("token", ""), acc.get("token_sha256", ""))
        for e in data.get("edges", []):
            a, b = e["agents"]
            reg_edge(a, b, e.get("types", ["question", "notification"]),
                     e.get("max_per_day", 20), e.get("thread_depth", 6), e.get("expires", ""))
    elif MODE == "relay":                 # single-edge, synthesized from env (backward compat)
        reg_account(AGENT_A, TOKEN_A)
        reg_account(AGENT_B, TOKEN_B)
        reg_edge(AGENT_A, AGENT_B, GRANT_TYPES, GRANT_MAX_PER_DAY,
                 GRANT_THREAD_DEPTH, GRANT_EXPIRES)
    with _registry_lock:                  # atomic swap
        _TOKEN_TO_AGENT, _AGENTS, _EDGES = t2a, agents, edges


def _edge_grant(a: str, b: str):
    return _EDGES.get(frozenset((a, b)))

DB_PATH = STATE_DIR / "edge.db"
_db_lock = threading.Lock()
STATE_DIR.mkdir(parents=True, exist_ok=True)
KILL = STATE_DIR / "DISABLED"
AUDIT = STATE_DIR / "audit.jsonl"
_audit_lock = threading.Lock()

OUTBOX = deque()                 # proxy mode: queued outbound envelopes awaiting pickup
RESULTS = {}                     # id -> reply object
EVENTS = {}                      # id -> threading.Event
_lock = threading.Lock()
_outbox_event = threading.Event()

# relay mode: one inbox per agent + who is entitled to reply to a given message id
INBOXES = {}                     # agent -> deque of envelopes addressed to it
INBOX_EVENTS = {}                # agent -> threading.Event (new-mail wakeup)
REPLY_OWNER = {}                 # message id -> the agent whose /reply is accepted


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
                  "(id TEXT PRIMARY KEY, thread_id TEXT, ts REAL, day TEXT, "
                  "sender TEXT DEFAULT '', edge TEXT DEFAULT '')")
        cols = [r[1] for r in c.execute("PRAGMA table_info(asks)").fetchall()]
        if "sender" not in cols:  # upgrade a pre-relay DB in place
            c.execute("ALTER TABLE asks ADD COLUMN sender TEXT DEFAULT ''")
        if "edge" not in cols:    # upgrade a pre-multitenant DB in place
            c.execute("ALTER TABLE asks ADD COLUMN edge TEXT DEFAULT ''")
        c.execute("CREATE INDEX IF NOT EXISTS ix_thread ON asks(thread_id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_day ON asks(day)")


def _grant_gate(msg, grant, sender="", edge=""):
    """Per-edge grant enforcement + /ask idempotency, against the given grant dict
    ({types,max_per_day,thread_depth,expires}). Daily cap counts PER (edge, sender) — each
    direction of each edge gets its own rate; dedup is global by id; thread-depth is per thread
    (a conversation is one thread regardless of who speaks). Expired grant -> refused."""
    mtype = str(msg.get("type", "question"))
    if mtype not in grant["types"]:
        return 403, f"type '{mtype}' not permitted by this edge's grant ({sorted(grant['types'])})"
    exp = grant.get("expires", "")
    if exp and datetime.now(timezone.utc).strftime("%Y-%m-%d") > exp:
        return 403, f"edge grant expired ({exp})"
    mid = str(msg.get("id", "")).strip()
    tid = str(msg.get("thread_id", "") or mid).strip()
    now = time.time()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _db_lock, _db() as c:
        if mid:
            row = c.execute("SELECT ts FROM asks WHERE id=?", (mid,)).fetchone()
            if row and now - row["ts"] < SEEN_TTL:
                return 409, "duplicate message id (replay/retry) — already handled"
        n_day = c.execute("SELECT COUNT(*) n FROM asks WHERE day=? AND sender=? AND edge=?",
                          (day, sender, edge)).fetchone()["n"]
        if n_day >= grant["max_per_day"]:
            return 429, f"edge daily cap reached ({grant['max_per_day']}/day)"
        n_thr = c.execute("SELECT COUNT(*) n FROM asks WHERE thread_id=?", (tid,)).fetchone()["n"]
        if n_thr >= grant["thread_depth"]:
            return 429, f"edge thread-depth cap reached ({grant['thread_depth']})"
        c.execute("INSERT OR REPLACE INTO asks (id, thread_id, ts, day, sender, edge) "
                  "VALUES (?,?,?,?,?,?)",
                  (mid or os.urandom(6).hex(), tid, now, day, sender, edge))
    return None


def _days_to_expiry():
    """Soonest edge-grant expiry in days (for Gatus). Considers all registered edges in relay
    mode, else the single GRANT_EXPIRES. None if nothing expires."""
    exps = [g["expires"] for g in _EDGES.values() if g.get("expires")] or \
           ([GRANT_EXPIRES] if GRANT_EXPIRES else [])
    days = []
    for e in exps:
        try:
            exp = datetime.strptime(e, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days.append((exp - datetime.now(timezone.utc)).days)
        except ValueError:
            pass
    return min(days) if days else None


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
            gate = _grant_gate(msg, {"types": GRANT_TYPES, "max_per_day": GRANT_MAX_PER_DAY,
                                     "thread_depth": GRANT_THREAD_DEPTH, "expires": GRANT_EXPIRES},
                                sender=PEER_AGENT, edge=_edge_key(PEER_AGENT, LOCAL_AGENT))
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


class RelayHandler(BaseH):
    """MODE=relay — a NEUTRAL, MULTI-TENANT host (KN2): many accounts, many edges, one box.

    Identity is the TOKEN: sha256(bearer) -> account name; the body's `from` is overwritten,
    never trusted. Two accounts may exchange mail only across a REGISTERED EDGE (both opted in),
    under that edge's grant (types/rate/depth/expiry) — transport allowlist, not authority.
    Isolation: an account reads only its own inbox, may reply only to messages addressed to it,
    and cannot reach an account it has no edge with. A `question` blocks until the recipient
    replies; a `notification` returns 202 (the recipient may be offline)."""

    def _whoami(self):
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        return _TOKEN_TO_AGENT.get(_sha(tok)) if tok else None

    def do_GET(self):
        if self.path == "/health":
            edges = [{"agents": sorted(k), "expires": v.get("expires", "")}
                     for k, v in _EDGES.items()]
            body = {"status": "ok", "service": SERVICE_NAME, "mode": "relay",
                    "disabled": KILL.exists(), "accounts": len(_AGENTS), "edges": edges,
                    "inbox": {a: len(INBOXES.get(a, ())) for a in sorted(_AGENTS)}}
            d = _days_to_expiry()
            if d is not None:
                body["days_until_grant_expiry"] = d
            return self._send(200, body)
        if KILL.exists():
            return self._send(503, {"error": "mailbox disabled (kill switch)"})
        me = self._whoami()
        if me is None:
            return self._send(401, {"error": "unauthorized"})
        if self.path.startswith("/inbox"):
            wait, only_from = 0, ""
            for part in self.path.split("?", 1)[-1].split("&"):
                if part.startswith("wait="):
                    try:
                        wait = max(0, min(60, int(part[5:])))
                    except ValueError:
                        pass
                elif part.startswith("from="):
                    only_from = part[5:]   # multi-edge: drain just one peer's mail
            box = INBOXES.setdefault(me, deque())
            ev = INBOX_EVENTS.setdefault(me, threading.Event())
            deadline = time.time() + wait
            while True:
                with _lock:
                    idx = next((i for i, e in enumerate(box)
                                if not only_from or e.get("from") == only_from), None)
                    if idx is not None:
                        env = box[idx]
                        del box[idx]
                        _audit_write("inbox_pickup", agent=me, frm=env.get("from"),
                                     id=env.get("id"), type=env.get("type"))
                        return self._send(200, {"envelopes": [env]})
                    ev.clear()
                remaining = deadline - time.time()
                if remaining <= 0:
                    return self._send(200, {"envelopes": []})
                ev.wait(min(remaining, 5))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if KILL.exists():
            return self._send(503, {"error": "mailbox disabled (kill switch)"})
        me = self._whoami()
        if me is None:
            return self._send(401, {"error": "unauthorized"})
        msg = self._body()
        if msg is None:
            return self._send(400, {"error": "bad body"})
        if self.path == "/reply":
            rid = str(msg.get("reply_to", "")).strip()
            if not rid:
                return self._send(400, {"error": "reply_to required"})
            with _lock:
                if REPLY_OWNER.get(rid) != me:
                    return self._send(403, {"error": "not the recipient of that message"})
                RESULTS[rid] = msg.get("reply", {})
                ev = EVENTS.get(rid)
            if ev:
                ev.set()
            _audit_write("reply", agent=me, id=rid, ok=msg.get("reply", {}).get("ok"))
            return self._send(200, {"ok": True})
        if self.path == "/ask":
            to = str(msg.get("to", "")).strip()
            if to not in _AGENTS:
                return self._send(400, {"ok": False, "body": f"unknown recipient '{to}'"})
            grant = _edge_grant(me, to)
            if grant is None:
                _audit_write("ask_refused", frm=me, to=to, code=403, reason="no edge")
                return self._send(403, {"ok": False,
                                        "body": f"no registered edge {me}<->{to}"})
            gate = _grant_gate(msg, grant, sender=me, edge=_edge_key(me, to))
            if gate:
                code, reason = gate
                _audit_write("ask_refused", frm=me, to=to, id=msg.get("id"),
                             type=msg.get("type"), code=code, reason=reason)
                return self._send(code, {"ok": False, "body": reason})
            msg["from"] = me                  # token-derived, never body-claimed
            msg["to"] = to
            msg.setdefault("id", os.urandom(6).hex())
            msg.setdefault("thread_id", msg["id"])
            msg.setdefault("ts", _now())
            mtype = str(msg.get("type", "question"))
            box = INBOXES.setdefault(to, deque())
            ev_new = INBOX_EVENTS.setdefault(to, threading.Event())
            with _lock:
                if len(box) >= MAX_QUEUE:
                    return self._send(429, {"ok": False, "body": "recipient inbox full"})
                box.append(msg)
                REPLY_OWNER[msg["id"]] = to
                if mtype != "notification":
                    ev = EVENTS[msg["id"]] = threading.Event()
            ev_new.set()
            _audit_write("relay_queued", frm=me, to=to, id=msg["id"], type=mtype)
            if mtype == "notification":
                # fire-and-forget: delivery ack is pipeline-level (SPEC §4) — don't hold the line
                return self._send(202, {"ok": True, "body": "queued",
                                        "id": msg["id"], "thread_id": msg["thread_id"]})
            ok = ev.wait(REPLY_TIMEOUT)
            with _lock:
                EVENTS.pop(msg["id"], None)
                REPLY_OWNER.pop(msg["id"], None)
                reply = RESULTS.pop(msg["id"], None)
            if not ok or reply is None:
                return self._send(504, {"ok": False,
                                        "body": f"no reply from '{to}' within {REPLY_TIMEOUT}s "
                                                "(recipient poller down or slow?)"})
            _lf.log_exchange(
                trace_id=msg.get("thread_id") or msg["id"],
                name=f"{me}->{to}:{mtype}", sender=me, target=to, mtype=mtype,
                body=msg.get("body", ""), reply=str(reply.get("body", "")),
                ok=bool(reply.get("ok")), domain=DOMAIN)
            return self._send(200 if reply.get("ok") else 502, reply)
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
    _load_registry()
    if MODE == "relay":                   # live registry reload (control plane adds accounts/edges)
        import signal

        def _reload(*_):
            try:
                _load_registry()
                print(f"{SERVICE_NAME}: registry reloaded — {len(_AGENTS)} accounts, "
                      f"{len(_EDGES)} edge(s)", flush=True)
            except Exception as e:
                print(f"{SERVICE_NAME}: registry reload FAILED ({e}); keeping current", flush=True)
        signal.signal(signal.SIGHUP, _reload)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    if MODE == "relay":
        pub = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), RelayHandler)
        pub.socket = ctx.wrap_socket(pub.socket, server_side=True)
        print(f"{SERVICE_NAME}: RELAY public :{PUBLIC_PORT} (TLS) — {len(_AGENTS)} accounts, "
              f"{len(_EDGES)} edge(s) (neutral multi-tenant host)", flush=True)
        pub.serve_forever()
        return
    pub = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), PublicHandler)
    pub.socket = ctx.wrap_socket(pub.socket, server_side=True)
    loc = ThreadingHTTPServer(("127.0.0.1", LOCAL_PORT), LocalHandler)
    threading.Thread(target=pub.serve_forever, daemon=True).start()
    print(f"{SERVICE_NAME}: public :{PUBLIC_PORT} (TLS) + local 127.0.0.1:{LOCAL_PORT} "
          f"[{LOCAL_AGENT} <-> {PEER_AGENT}]", flush=True)
    loc.serve_forever()


if __name__ == "__main__":
    main()
