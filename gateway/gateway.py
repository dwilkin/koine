#!/usr/bin/env python3
"""Koine gateway — a domain's central hub for agent-to-agent messaging (SPEC.md §6.1).

Sits between an initiating agent's `ask_peer` MCP tool (askpeer/) and the recipient's
always-on answer-endpoint (endpoint/, POST /ask). Adds the safety layer a direct endpoint
call lacks:

  * AUDIT      — every message + reply persisted to SQLite (operator-readable via GET /audit).
  * AUTHN      — caller presents an OIDC JWT *or*, for bootstrap, the gateway bearer token.
                 Identity (agent name) is taken from the token, and the message's `from`
                 must match it (no spoofing a peer).
  * RATE/LOOP  — per-agent messages/hour + cooldown, and a per-thread depth cap so an
                 agent<->agent exchange cannot recurse forever. Breach => refuse (+ notify).
  * POLICY     — only known agents, known routes; body/size validation; peering-grant
                 enforcement (types/rate/expiry, SPEC.md §5).
  * NOTIFY     — action_request / escalation classes ping the recipient's human via Telegram
                 (best-effort; a no-op that still audits if Telegram is unconfigured).
  * KILL SWITCH— presence of $STATE_DIR/DISABLED (or `docker stop`) severs all traffic.

Runs in a container (see Dockerfile / docker-compose.yml). Stdlib HTTP + sqlite3 + urllib;
only third-party dep is PyJWT[crypto] for OIDC token validation.

Config via environment (compose + the domain's deploy script from its secret store):
  GW_BIND              listen host:port                       (default 0.0.0.0:8095)
  GW_BEARER_TOKEN      bootstrap/fallback bearer for callers  (required unless OIDC-only)
  OIDC_JWKS_URL        OIDC realm JWKS endpoint               (optional; enables JWT authn)
  OIDC_ISSUER          expected `iss`                         (optional)
  OIDC_AUDIENCE        expected `aud` (comma list ok)         (optional)
  OIDC_CA_FILE         CA bundle for the JWKS fetch TLS       (optional; legacy alias
                                                               LAB_CA_FILE still accepted)
  OIDC_CLIENT_MAP      "clientId=agent,..." azp->agent map    (optional; default convention
                                                               strips an "agent-" prefix)
  DOMAIN               observability label for this domain    (optional)
  AGENTS_JSON          path to the agent-card directory       (default /app/agents.json)
  ENDPOINT_TOKEN       bearer for the peers' /ask endpoints   (required)
  MY_PRIVKEY           this domain's X25519 private key; enables E2E body encryption on
                       edges whose card carries a `pubkey`    (optional)
  MAX_THREAD_DEPTH     messages allowed per thread_id         (default 6)
  MAX_MSGS_PER_HOUR    per-initiator cap                      (default 60)
  COOLDOWN_SECONDS     min gap between one agent's messages   (default 0)
  ROUTE_TIMEOUT        seconds to await a peer's answer       (default 200)
  NOTIFY_MAX_PER_HOUR  POST /notify per-agent hourly cap      (default 10)
  NOTIFY_QUIET         local-hour quiet window "start-end"    (default "22-7"; "" disables)
  NOTIFY_TZ            timezone for the quiet window          (default America/Denver)
  BRIDGE_NOTE_URL      chat-bridge history hook URL           (optional)
  TELEGRAM_BOT_TOKEN   shared/fallback bot token              (optional; notify no-op if unset)
  TELEGRAM_BOT_TOKEN_<AGENT>  per-recipient bot token         (optional; falls back to shared)
  TELEGRAM_CHAT_<AGENT>       chat id for <agent>'s human     (optional; discovered from env)
  OPERATOR_AGENT       agent whose human receives gateway-level notices such as cap-raise
                       proposals                              (default "atlas")
  STATE_DIR            audit db + kill-switch dir             (default /data)
Per-card indirection: an agent card may set `endpoint_token_env` naming the env var holding
that edge's bearer (falls back to ENDPOINT_TOKEN); `ca_file` pins the edge's TLS.
"""
import hmac
import json
import os
import re
import sqlite3
import ssl
import signal
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

try:  # observability is optional — the gateway runs fine without it
    import langfuse_emit as _lf
except Exception:  # pragma: no cover
    class _lf:  # type: ignore
        @staticmethod
        def log_exchange(**_):
            return None

# E2E body encryption (KN1) — optional. MY_PRIVKEY is this domain's X25519 private key; a peer
# card's `pubkey` opts that edge into encryption. Import lazily so the gateway runs without
# `cryptography` when no edge uses crypto.
MY_PRIVKEY = os.environ.get("MY_PRIVKEY", "").strip()
_crypto = None
if MY_PRIVKEY:
    import crypto as _crypto

GW_BIND = os.environ.get("GW_BIND", "0.0.0.0:8095")
GW_BEARER_TOKEN = os.environ.get("GW_BEARER_TOKEN", "").strip()
OIDC_JWKS_URL = os.environ.get("OIDC_JWKS_URL", "").strip()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").strip()
OIDC_AUDIENCE = [a for a in os.environ.get("OIDC_AUDIENCE", "").split(",") if a.strip()]
DOMAIN = os.environ.get("DOMAIN", "").strip()   # observability label for THIS domain
AGENTS_JSON = os.environ.get("AGENTS_JSON", "/app/agents.json")
ENDPOINT_TOKEN = os.environ.get("ENDPOINT_TOKEN", "").strip()
MAX_THREAD_DEPTH = int(os.environ.get("MAX_THREAD_DEPTH", "6"))
MAX_MSGS_PER_HOUR = int(os.environ.get("MAX_MSGS_PER_HOUR", "60"))
COOLDOWN_SECONDS = float(os.environ.get("COOLDOWN_SECONDS", "0"))
ROUTE_TIMEOUT = int(os.environ.get("ROUTE_TIMEOUT", "200"))
# Proactive agent->human sends (POST /notify): self-notify only, capped, quiet-hours-gated.
NOTIFY_MAX_PER_HOUR = int(os.environ.get("NOTIFY_MAX_PER_HOUR", "10"))
NOTIFY_QUIET = os.environ.get("NOTIFY_QUIET", "22-7").strip()   # local-hour window "start-end"; "" disables
NOTIFY_TZ = os.environ.get("NOTIFY_TZ", "America/Denver")
# Bridge history hook: record proactive sends so the human's reply has context. The gateway
# container is on a bridge network, so it reaches the telegram-bridge via the host's published
# port, not 127.0.0.1.
BRIDGE_NOTE_URL = os.environ.get("BRIDGE_NOTE_URL", "").strip()  # optional; a domain that runs a chat bridge sets it
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()  # shared fallback
# Per-recipient Telegram wiring is DISCOVERED from the environment — domain data never lives
# in this file. Every TELEGRAM_CHAT_<AGENT> / TELEGRAM_BOT_TOKEN_<AGENT> variable maps to the
# lowercased agent name; the per-agent bot token falls back to the shared TELEGRAM_BOT_TOKEN
# so one bot can serve several humans (an agent whose human shares another's bot/chat just
# gets that chat id set, e.g. TELEGRAM_CHAT_POSEIDON=<same chat id as atlas's>).
# Example env (the reference deployment): TELEGRAM_CHAT_ATLAS, TELEGRAM_CHAT_GENIE,
# TELEGRAM_CHAT_POSEIDON + TELEGRAM_BOT_TOKEN_GENIE (atlas/poseidon use the shared token).


def _discover_telegram():
    bots, chats = {}, {}
    for k, v in os.environ.items():
        if k.startswith("TELEGRAM_CHAT_") and len(k) > len("TELEGRAM_CHAT_"):
            chats[k[len("TELEGRAM_CHAT_"):].lower()] = v.strip()
        elif k.startswith("TELEGRAM_BOT_TOKEN_") and len(k) > len("TELEGRAM_BOT_TOKEN_"):
            bots[k[len("TELEGRAM_BOT_TOKEN_"):].lower()] = v.strip()
    agents = set(bots) | set(chats)
    return ({a: (bots.get(a, "") or TELEGRAM_BOT_TOKEN) for a in agents},
            {a: chats.get(a, "") for a in agents})


TELEGRAM_BOT, TELEGRAM_CHAT = _discover_telegram()
# Gateway-level operator notices (e.g. cap-raise proposals) go to this agent's human.
OPERATOR_AGENT = os.environ.get("OPERATOR_AGENT", "atlas").strip()
STATE_DIR = os.environ.get("STATE_DIR", "/data")
DB_PATH = os.path.join(STATE_DIR, "audit.db")
KILL = os.path.join(STATE_DIR, "DISABLED")

VALID_TYPES = {"question", "answer", "notification", "action_request", "escalation"}
NOTIFY_TYPES = {"action_request", "escalation"}

# Approval-shaped replies also notify the recipient's human (2026-07-18, Darian's directive:
# "any time cid asks for something that needs my approval, Telegram me"). The sandboxed peer
# answerer can RECORD a pending action but cannot notify, so the gateway watches its reply for
# the ledger/approval phrasing plus an explicit [NEEDS-<HUMAN>] marker answerers may emit.
APPROVAL_RE = re.compile(
    r"\[NEEDS-[A-Z]+"                                   # explicit marker, e.g. [NEEDS-DARIAN]
    r"|\bpending\b[^.\n]{0,48}\bapproval\b"             # "pending Darian's approval"
    r"|\bRecorded \(id"                                 # pending-actions ledger add phrasing
    r"|\bawaiting\b[^.\n]{0,32}\bapproval\b"
    r"|\bneeds?\b[^.\n]{0,32}\b(?:approval|sign-?off)\b",
    re.IGNORECASE)

_db_lock = threading.Lock()
_last_sent = {}          # agent -> monotonic ts of its last accepted message (cooldown)
_last_sent_lock = threading.Lock()

# Optional OIDC JWT validation. Import lazily so the gateway still runs bearer-only.
# If the JWKS endpoint's TLS chains to a private CA, point OIDC_CA_FILE at that CA bundle
# (LAB_CA_FILE is the accepted legacy name).
OIDC_CA_FILE = (os.environ.get("OIDC_CA_FILE") or os.environ.get("LAB_CA_FILE") or "").strip()
try:
    import jwt as _jwt
    from jwt import PyJWKClient as _PyJWKClient
    if OIDC_JWKS_URL:
        _jwks_ctx = ssl.create_default_context(
            cafile=OIDC_CA_FILE if (OIDC_CA_FILE and os.path.exists(OIDC_CA_FILE)) else None)
        _jwk_client = _PyJWKClient(OIDC_JWKS_URL, ssl_context=_jwks_ctx)
    else:
        _jwk_client = None
except Exception as _e:  # pragma: no cover
    print(f"WARN: OIDC init failed ({_e}); bearer-only", flush=True)
    _jwt = None
    _jwk_client = None


def _now():
    return datetime.now(timezone.utc).isoformat()


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    os.makedirs(STATE_DIR, exist_ok=True)
    with _db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts TEXT NOT NULL,
                 direction TEXT NOT NULL,          -- 'request' | 'reply' | 'refused'
                 id TEXT, thread_id TEXT,
                 from_agent TEXT, to_agent TEXT,
                 type TEXT, body TEXT,
                 ok INTEGER, meta TEXT )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS ix_thread ON messages(thread_id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_from_ts ON messages(from_agent, ts)")


def _audit(direction, msg, ok=None, meta=None):
    with _db_lock, _db() as c:
        c.execute(
            "INSERT INTO messages (ts, direction, id, thread_id, from_agent, to_agent, type, body, ok, meta)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_now(), direction, str(msg.get("id", "")), str(msg.get("thread_id", "")),
             str(msg.get("from", "")), str(msg.get("to", "")), str(msg.get("type", "")),
             str(msg.get("body", ""))[:8000], (None if ok is None else int(ok)),
             json.dumps(meta or {}, default=str)),
        )


def _load_agents():
    try:
        with open(AGENTS_JSON) as f:
            data = json.load(f)
        return {a["name"]: a for a in data.get("agents", [])}
    except Exception as e:
        print(f"WARN: could not load agents.json: {e}", flush=True)
        return {}


AGENTS = _load_agents()


# ---- authn -----------------------------------------------------------------

def _bearer(headers):
    return (headers.get("Authorization") or "").removeprefix("Bearer ").strip()


def _identify(headers):
    """Return (agent_name, auth_meta) or (None, reason). Tries Keycloak JWT first,
    then the bootstrap bearer token. The message's `from` is checked against this later."""
    tok = _bearer(headers)
    if not tok:
        return None, "missing bearer token"
    # 1) Keycloak JWT (preferred) — only if configured and PyJWT present.
    if _jwk_client and _jwt:
        try:
            key = _jwk_client.get_signing_key_from_jwt(tok).key
            claims = _jwt.decode(
                tok, key, algorithms=["RS256"],
                audience=OIDC_AUDIENCE or None,
                issuer=OIDC_ISSUER or None,
                options={"verify_aud": bool(OIDC_AUDIENCE)},
            )
            # client_credentials token -> azp / clientId identifies the agent.
            azp = claims.get("azp") or claims.get("client_id") or ""
            agent = _client_to_agent(azp)
            if agent in AGENTS:
                return agent, {"auth": "oidc", "azp": azp}
            return None, f"token client '{azp}' is not a known agent"
        except Exception as e:
            # fall through to bearer only if a bearer is even configured
            if not GW_BEARER_TOKEN:
                return None, f"jwt validation failed: {e}"
    # 2) Bootstrap bearer — shared gateway token; identity must come from the body's `from`,
    #    so we return a sentinel that _authorize() will reconcile against a known agent.
    if GW_BEARER_TOKEN and hmac.compare_digest(tok, GW_BEARER_TOKEN):
        return "*bearer*", {"auth": "bearer"}
    return None, "unauthorized"


# OIDC clientId (azp) -> agent-name mapping. Set OIDC_CLIENT_MAP="clientA=agent1,clientB=agent2"
# explicitly, or rely on the default convention: a client named "agent-<name>" maps to <name>
# (e.g. dedicated per-agent clients agent-atlas -> atlas); any other azp is used as-is.
# Either way the result must still be a known agent (checked by the caller).
_OIDC_CLIENT_MAP = dict(
    p.split("=", 1) for p in os.environ.get("OIDC_CLIENT_MAP", "").split(",") if "=" in p)


def _client_to_agent(azp):
    if _OIDC_CLIENT_MAP:
        return _OIDC_CLIENT_MAP.get(azp, azp)
    return azp[len("agent-"):] if azp.startswith("agent-") else azp


# ---- caps ------------------------------------------------------------------

def _thread_depth(thread_id):
    if not thread_id:
        return 0
    with _db_lock, _db() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM messages WHERE thread_id=? AND direction='request'",
            (thread_id,),
        ).fetchone()
        return r["n"] if r else 0


def _hour_ago_iso():
    # ts is stored as _now() ISO-8601 (with 'T'); comparing against SQLite's
    # datetime('now') space-form is lexicographically wrong (every same-day 'T' row
    # compares greater), so build the cutoff in the SAME format. (Fixed 2026-07-04 —
    # the old comparison silently turned hourly caps into same-day caps.)
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _msgs_last_hour(agent):
    with _db_lock, _db() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM messages WHERE from_agent=? AND direction='request'"
            " AND ts >= ?",
            (agent, _hour_ago_iso()),
        ).fetchone()
        return r["n"] if r else 0


def _notifies_last_hour(agent):
    with _db_lock, _db() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM messages WHERE from_agent=? AND direction='notify'"
            " AND ts >= ?",
            (agent, _hour_ago_iso()),
        ).fetchone()
        return r["n"] if r else 0


def _msgs_last_day_edge(agent):
    """Requests in the last 24h touching this agent (either direction) — grant rate unit."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with _db_lock, _db() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM messages WHERE direction='request' AND ts >= ?"
            " AND (from_agent=? OR to_agent=?)",
            (cutoff, agent, agent),
        ).fetchone()
        return r["n"] if r else 0


def _grant_check(sender, target, mtype, thread_id=""):
    """Peering-grant enforcement (SPEC.md §5): agents whose card carries a `grant`
    are cross-domain edges — types/rate/thread-depth/expiry are hard limits, enforced
    before any spawn. Returns None if OK, else (code, reason)."""
    for edge_agent in (sender, target):
        g = AGENTS.get(edge_agent, {}).get("grant")
        if not g:
            continue
        exp = str(g.get("expires", ""))
        if exp and _now()[:10] > exp:
            return 403, (f"peering grant for '{edge_agent}' expired {exp} — "
                         "renewal is a human act on both sides")
        allowed = g.get("types", ["question", "notification"])
        if mtype not in allowed:
            return 403, (f"type '{mtype}' not allowed by the '{edge_agent}' peering grant "
                         f"(allowed: {allowed})")
        cap = int(g.get("max_per_day", 20))
        if _msgs_last_day_edge(edge_agent) >= cap:
            _propose_cap_raise(edge_agent, cap)
            return 429, f"peering-grant rate cap reached ({cap}/day on the '{edge_agent}' edge)"
        # Per-grant thread depth (SPEC §5 hard field; mirrors the mailbox's _grant_gate).
        # The global MAX_THREAD_DEPTH still applies via _cap_check — this only bites when
        # the grant sets a tighter limit than the global.
        depth = int(g.get("thread_depth", 6))
        if thread_id and _thread_depth(thread_id) >= depth:
            return 429, (f"thread-depth cap reached ({depth} on the '{edge_agent}' "
                         "peering grant) — start a new thread or have a human continue")
    return None


_cap_proposals = {}  # (edge_agent, YYYY-MM-DD) -> True; in-memory is fine (once/day, resets on restart)


def _propose_cap_raise(edge_agent, cap):
    """A capped edge shouldn't strand agents until a human notices: on the first cap hit
    of the day, proactively Telegram the gateway operator's human a concrete raise
    proposal so approval is one reply away (Darian 2026-07-19)."""
    key = (edge_agent, _now()[:10])
    if _cap_proposals.get(key):
        return
    _cap_proposals[key] = True
    proposed = cap * 2
    text = (f"[A2A gateway] the '{edge_agent}' edge hit its {cap}/day grant cap — further "
            f"messages are refused until the 24h window rolls. Proposal: raise to "
            f"{proposed}/day. To approve, tell {OPERATOR_AGENT} \"raise the {edge_agent} cap to "
            f"{proposed}\" (agents.json + gateway redeploy; the peer's human should "
            f"mirror their edge).")
    try:
        note = _telegram(OPERATOR_AGENT, text)
        if note == "sent":
            _bridge_note(OPERATOR_AGENT, text)
        _audit("cap_raise_proposed",
               {"from": edge_agent, "to": OPERATOR_AGENT, "type": "notification",
                "body": f"cap {cap} hit; proposed {proposed}"},
               ok=1, meta={"edge": edge_agent, "cap": cap, "proposed": proposed})
    except Exception:
        pass  # a failed proposal must never break message handling


def _quiet_now():
    """True inside the local quiet-hours window (agents shouldn't buzz sleeping humans)."""
    if not NOTIFY_QUIET:
        return False
    try:
        start, end = (int(x) for x in NOTIFY_QUIET.split("-"))
        h = datetime.now(ZoneInfo(NOTIFY_TZ)).hour
    except Exception:
        return False
    if start == end:
        return False
    return (start <= h or h < end) if start > end else (start <= h < end)


def _cap_check(sender, thread_id):
    """Return None if OK, else a (code, reason) refusal."""
    depth = _thread_depth(thread_id)
    if depth >= MAX_THREAD_DEPTH:
        return 429, f"thread depth cap reached ({depth}/{MAX_THREAD_DEPTH})"
    if _msgs_last_hour(sender) >= MAX_MSGS_PER_HOUR:
        return 429, f"rate cap reached ({MAX_MSGS_PER_HOUR}/hour for {sender})"
    if COOLDOWN_SECONDS > 0:
        with _last_sent_lock:
            last = _last_sent.get(sender, 0.0)
            if time.monotonic() - last < COOLDOWN_SECONDS:
                return 429, f"cooldown: {sender} must wait {COOLDOWN_SECONDS}s between messages"
    return None


# ---- notify ----------------------------------------------------------------

def _telegram(recipient_agent, text):
    """Best-effort human notify for the recipient's owner. Returns a status string.

    Telegram's hard per-message limit is 4096 chars; rather than silently truncate a long
    notification (which chopped cid's reserve proposals + answerer replies mid-content), split
    into numbered chunks so the human gets the WHOLE message across consecutive sends."""
    chat = TELEGRAM_CHAT.get(recipient_agent, "")
    bot = TELEGRAM_BOT.get(recipient_agent, "")
    if not (bot and chat):
        return "telegram-unconfigured"
    CHUNK = 3900  # leaves headroom under 4096 for the "(i/n) " prefix
    chunks = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)] or [""]
    status = "sent"
    for idx, chunk in enumerate(chunks):
        prefix = f"({idx + 1}/{len(chunks)}) " if len(chunks) > 1 else ""
        try:
            payload = json.dumps({"chat_id": chat, "text": prefix + chunk}).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{bot}/sendMessage",
                data=payload, headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.status != 200:
                    status = f"telegram-http-{r.status}"
        except Exception as e:
            status = f"telegram-error:{e}"
    return status


def _bridge_note(agent, text):
    """Best-effort: record a proactive send in the telegram-bridge's rolling history so the
    human's reply spawns an answerer that knows what it was replying to. Never blocks."""
    if not BRIDGE_NOTE_URL:
        return "disabled"
    try:
        req = urllib.request.Request(
            BRIDGE_NOTE_URL,
            data=json.dumps({"agent": agent, "text": text}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {ENDPOINT_TOKEN}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return "noted" if r.status == 200 else f"note-http-{r.status}"
    except Exception as e:
        return f"note-error:{e}"


# ---- routing ---------------------------------------------------------------

def _route(target, msg):
    """Forward the message to the target agent's /ask endpoint; return (ok, reply, meta)."""
    card = AGENTS.get(target)
    if not card:
        return False, f"unknown target agent '{target}'", {"routed": False}
    url = card["endpoint"].rstrip("/") + "/ask"
    # E2E body encryption (KN1): when the card declares a `pubkey` and we hold our own private
    # key (MY_PRIVKEY env), seal the body to the peer before it touches the relay, and open the
    # reply. Cards without a pubkey (genie, cid, …) stay plaintext — gated, zero blast radius.
    peer_pub = card.get("pubkey", "").strip()
    enc = bool(peer_pub and MY_PRIVKEY)
    wire = msg
    if enc:
        msg.setdefault("id", "")
        msg.setdefault("thread_id", msg.get("id") or "")
        wire = _crypto.seal_body(msg, MY_PRIVKEY, peer_pub)
    body = json.dumps(wire).encode()
    # Cross-domain cards may carry their own endpoint bearer (per-domain credential) and a
    # pinned certificate (self-signed TLS on the peer's edge service).
    tok = os.environ.get(card.get("endpoint_token_env", ""), "").strip() or ENDPOINT_TOKEN
    ctx = ssl.create_default_context(cafile=card["ca_file"]) if card.get("ca_file") else None
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=ROUTE_TIMEOUT, context=ctx) as r:
            data = json.loads(r.read())
        if enc and _crypto.is_sealed(data):
            try:
                data = _crypto.open_body(data, MY_PRIVKEY, peer_pub)
            except Exception as e:
                return False, f"reply decrypt failed: {e}", {"routed": True}
        return bool(data.get("ok", True)), data.get("body", ""), {
            "routed": True, "elapsed": round(time.time() - t0, 2),
            "peer_meta": data.get("meta"),
        }
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        return False, f"peer endpoint HTTP {e.code}: {detail}", {"routed": True, "http": e.code}
    except Exception as e:
        return False, f"peer endpoint unreachable: {e}", {"routed": False}


# ---- HTTP ------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "a2a-gateway/1.0"

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
            return self._send(200, {"status": "ok", "service": "a2a-gateway",
                                    "disabled": os.path.exists(KILL),
                                    "agents": sorted(AGENTS.keys()),
                                    "oidc": bool(_jwk_client)})
        if self.path == "/agents":
            return self._send(200, {"agents": list(AGENTS.values())})
        if self.path.startswith("/audit"):
            if not self._authed_readonly():
                return self._send(401, {"error": "unauthorized"})
            limit = 50
            if "limit=" in self.path:
                try:
                    limit = max(1, min(500, int(self.path.split("limit=")[1].split("&")[0])))
                except ValueError:
                    pass
            with _db_lock, _db() as c:
                rows = [dict(r) for r in c.execute(
                    "SELECT * FROM messages ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()]
            return self._send(200, {"count": len(rows), "messages": rows})
        return self._send(404, {"error": "not found"})

    def _authed_readonly(self):
        # /audit is readable with the gateway bearer (Darian's ops token).
        return bool(GW_BEARER_TOKEN) and hmac.compare_digest(_bearer(self.headers), GW_BEARER_TOKEN)

    def _do_notify(self):
        """Proactive agent->human send. SELF-NOTIFY ONLY: an agent may message only its own
        human (atlas->Darian, genie->Marie) — the recipient is derived from the sender, never
        from the body. Capped per hour + quiet-hours gated + audited (direction='notify')."""
        if os.path.exists(KILL):
            return self._send(503, {"error": "gateway disabled (kill switch engaged)"})
        who, auth_meta = _identify(self.headers)
        if who is None:
            _audit("notify_refused", {"type": "notify"}, ok=0,
                   meta={"reason": auth_meta, "peer_ip": self.client_address[0]})
            return self._send(401, {"error": auth_meta})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad content-length"})
        if length <= 0 or length > 8192:
            return self._send(413, {"error": "body must be 1..8192 bytes"})
        try:
            msg = json.loads(self.rfile.read(length))
            assert isinstance(msg, dict)
        except (json.JSONDecodeError, AssertionError):
            return self._send(400, {"error": "body must be a JSON object"})

        sender = str(msg.get("from", "")).strip()
        text = str(msg.get("text", "")).strip()
        if who != "*bearer*" and sender != who:
            return self._send(403, {"error": f"token identity '{who}' != message from '{sender}'"})
        if sender not in AGENTS:
            return self._send(400, {"error": "from must be a known agent"})
        if not text:
            return self._send(400, {"error": "empty text"})

        record = {"id": msg.get("id", ""), "from": sender, "to": sender,
                  "type": "notify", "body": text}
        if _quiet_now():
            _audit("notify_refused", record, ok=0,
                   meta={"reason": f"quiet hours ({NOTIFY_QUIET} {NOTIFY_TZ})", **auth_meta})
            return self._send(429, {"error": f"quiet hours ({NOTIFY_QUIET} {NOTIFY_TZ}) — "
                                             "hold the message or wait for morning"})
        if _notifies_last_hour(sender) >= NOTIFY_MAX_PER_HOUR:
            _audit("notify_refused", record, ok=0,
                   meta={"reason": f"notify cap {NOTIFY_MAX_PER_HOUR}/hour", **auth_meta})
            return self._send(429, {"error": f"notify cap reached ({NOTIFY_MAX_PER_HOUR}/hour)"})

        status = _telegram(sender, text)
        ok = status == "sent"
        note = _bridge_note(sender, text) if ok else "skipped"
        _audit("notify", record, ok=int(ok),
               meta={"telegram": status, "bridge_note": note, **auth_meta})
        return self._send(200 if ok else 502, {"ok": ok, "telegram": status, "bridge_note": note})

    def do_POST(self):
        if self.path == "/notify":
            return self._do_notify()
        if self.path != "/message":
            return self._send(404, {"error": "not found"})
        if os.path.exists(KILL):
            return self._send(503, {"error": "gateway disabled (kill switch engaged)"})

        who, auth_meta = _identify(self.headers)
        if who is None:
            _audit("refused", {"type": "?"}, ok=0, meta={"reason": auth_meta,
                                                         "peer_ip": self.client_address[0]})
            return self._send(401, {"error": auth_meta})

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "bad content-length"})
        if length <= 0 or length > 65536:
            return self._send(413, {"error": "body must be 1..65536 bytes"})
        try:
            msg = json.loads(self.rfile.read(length))
            assert isinstance(msg, dict)
        except (json.JSONDecodeError, AssertionError):
            return self._send(400, {"error": "body must be a JSON object"})

        sender = str(msg.get("from", "")).strip()
        target = str(msg.get("to", "")).strip()
        mtype = str(msg.get("type", "question")).strip()

        # identity binding: a JWT pins the sender; the bootstrap bearer trusts the body's `from`
        if who != "*bearer*" and sender != who:
            return self._send(403, {"error": f"token identity '{who}' != message from '{sender}'"})
        if sender not in AGENTS or target not in AGENTS:
            return self._send(400, {"error": "from/to must be known agents"})
        if sender == target:
            return self._send(400, {"error": "cannot message self"})
        if mtype not in VALID_TYPES:
            return self._send(400, {"error": f"type must be one of {sorted(VALID_TYPES)}"})
        if not str(msg.get("body", "")).strip():
            return self._send(400, {"error": "empty body"})

        msg.setdefault("id", os.urandom(6).hex())
        msg.setdefault("thread_id", msg["id"])
        msg.setdefault("ts", _now())

        cap = (_cap_check(sender, msg["thread_id"])
               or _grant_check(sender, target, mtype, msg["thread_id"]))
        if cap:
            code, reason = cap
            _audit("refused", msg, ok=0, meta={"reason": reason, **auth_meta})
            note = _telegram(target, f"[A2A gateway] refused {sender}->{target}: {reason}")
            if note == "sent":
                _bridge_note(target, f"[A2A gateway] refused {sender}->{target}: {reason}")
            return self._send(code, {"error": reason, "notify": note})

        _audit("request", msg, meta=auth_meta)
        with _last_sent_lock:
            _last_sent[sender] = time.monotonic()

        # High-stakes classes notify the recipient's human (best-effort, non-blocking result).
        # The notification ALSO goes into the telegram-bridge's rolling history via /note —
        # otherwise the human's "approved" reply spawns an answerer with no referent
        # (exactly what happened 2026-07-05 with Genie's backup action_request).
        notify = "n/a"
        notify_note = "n/a"
        if mtype in NOTIFY_TYPES:
            notify = _telegram(target, f"[A2A] {sender} -> {target} ({mtype}):\n{msg.get('body','')}")
            if notify == "sent":
                notify_note = _bridge_note(
                    target, f"[A2A {mtype} from {sender}]\n{msg.get('body','')[:6000]}")

        ok, reply, meta = _route(target, msg)
        meta.update(auth_meta)
        meta["notify"] = notify
        meta["notify_note"] = notify_note

        # Approval-shaped reply => Telegram the recipient's human (see APPROVAL_RE above).
        # Deliberately ignores quiet hours / notify caps, same as NOTIFY_TYPES: an approval
        # request left silent is the failure mode this exists to kill.
        if ok and mtype not in NOTIFY_TYPES and APPROVAL_RE.search(reply or ""):
            meta["approval_notify"] = _telegram(
                target,
                f"[A2A needs-approval] {sender} → {target} (thread {msg['thread_id']}):\n"
                f"ASK: {str(msg.get('body', ''))[:3000]}\n—\n"
                f"ANSWERER: {(reply or '')[:3000]}")
            if meta["approval_notify"] == "sent":
                _bridge_note(target,
                             f"[A2A needs-approval from {sender}, thread {msg['thread_id']}]\n"
                             f"{str(msg.get('body', ''))[:6000]}")

        # Best-effort trace to the Home-domain LangFuse (never blocks / never fails the reply).
        peer_meta = meta.get("peer_meta") or {}
        _lf.log_exchange(
            trace_id=msg["thread_id"], name=f"{sender}->{target}:{mtype}",
            sender=sender, target=target, mtype=mtype,
            body=msg.get("body", ""), reply=reply, ok=ok, domain=DOMAIN,
            latency_ms=int(meta.get("elapsed", 0) * 1000) if meta.get("elapsed") else None,
            cost_usd=peer_meta.get("cost_usd"),
            extra={"num_turns": peer_meta.get("num_turns")} if peer_meta.get("num_turns") else None)
        reply_msg = {"id": msg["id"], "thread_id": msg["thread_id"], "from": target,
                     "to": sender, "type": "answer", "body": reply, "ts": _now()}
        _audit("reply", reply_msg, ok=ok, meta=meta)
        return self._send(200 if ok else 502, {**reply_msg, "ok": ok, "meta": meta})


def main():
    if not ENDPOINT_TOKEN:
        sys.exit("FATAL: ENDPOINT_TOKEN required (bearer for the peers' /ask endpoints)")
    if not (GW_BEARER_TOKEN or _jwk_client):
        sys.exit("FATAL: configure GW_BEARER_TOKEN and/or OIDC_JWKS_URL for caller authn")
    _init_db()

    def _reload_agents(*_):            # edge-sync rewrites agents.json + SIGHUPs -> hot-reload cards
        global AGENTS
        try:
            AGENTS = _load_agents()
            print(f"a2a-gateway: agents reloaded — {sorted(AGENTS.keys())}", flush=True)
        except Exception as e:
            print(f"a2a-gateway: agents reload FAILED ({e}); keeping current", flush=True)
    signal.signal(signal.SIGHUP, _reload_agents)

    host, _, port = GW_BIND.rpartition(":")
    srv = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    print(f"a2a-gateway on {GW_BIND}; agents={sorted(AGENTS.keys())}; "
          f"oidc={'on' if _jwk_client else 'off'}; bearer={'on' if GW_BEARER_TOKEN else 'off'}; "
          f"caps: depth<={MAX_THREAD_DEPTH}, {MAX_MSGS_PER_HOUR}/hr, cooldown={COOLDOWN_SECONDS}s",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
