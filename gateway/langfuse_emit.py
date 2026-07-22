#!/usr/bin/env python3
# SYNCED COPIES: gateway/langfuse_emit.py and mailbox/langfuse_emit.py are byte-identical
# on purpose (each deploys standalone) — any edit here must be mirrored in the other file.
"""langfuse_emit — zero-dependency, best-effort A2A tracing to a per-domain LangFuse.

Deliberately stdlib-only (urllib) so it drops into the gateway, the poller, and the
credential-less sandboxed answerer alike without dragging in the OTel SDK. Every call fires
on a daemon thread and swallows all errors: observability must NEVER touch the message hot
path or fail a reply. Disabled (a no-op) unless LANGFUSE_URL/PUBLIC_KEY/SECRET_KEY are set.

One A2A message = one LangFuse trace (id = the A2A thread_id, so multi-hop threads group),
plus a GENERATION observation carrying the peer spawn's cost/latency for the cost dashboards.
"""
import base64
import json
import os
import threading
import urllib.request
import uuid
from datetime import datetime, timezone

_URL = os.environ.get("LANGFUSE_URL", "").rstrip("/")
_PK = os.environ.get("LANGFUSE_PUBLIC_KEY", "").strip()
_SK = os.environ.get("LANGFUSE_SECRET_KEY", "").strip()
ENABLED = bool(_URL and _PK and _SK)
_AUTH = base64.b64encode(f"{_PK}:{_SK}".encode()).decode() if ENABLED else ""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _post(batch):
    try:
        req = urllib.request.Request(
            _URL + "/api/public/ingestion",
            data=json.dumps({"batch": batch}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Basic {_AUTH}"},
            method="POST")
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass  # best-effort by design


def log_exchange(*, trace_id, name, sender, target, mtype, body, reply, ok,
                 latency_ms=None, cost_usd=None, domain=None, extra=None):
    """Fire-and-forget: record one A2A message exchange as a trace (+ cost generation)."""
    if not ENABLED:
        return
    now = _now()
    tid = str(trace_id or uuid.uuid4().hex)
    meta = {"from": sender, "to": target, "type": mtype, "ok": ok}
    if latency_ms is not None:
        meta["latency_ms"] = latency_ms
    if cost_usd is not None:
        meta["cost_usd"] = cost_usd
    if domain:
        meta["domain"] = domain
    if extra:
        meta.update(extra)
    tags = [str(mtype), f"from:{sender}", f"to:{target}", "ok" if ok else "error"]
    batch = [{
        "id": uuid.uuid4().hex, "type": "trace-create", "timestamp": now,
        "body": {"id": tid, "name": name, "timestamp": now,
                 "input": (body or "")[:4000], "output": (reply or "")[:4000],
                 "metadata": meta, "tags": tags}}]
    gen = {"id": uuid.uuid4().hex, "type": "observation-create", "timestamp": now,
           "body": {"id": uuid.uuid4().hex, "traceId": tid, "type": "GENERATION",
                    "name": "peer-answer", "startTime": now, "endTime": now,
                    "metadata": {k: v for k, v in meta.items() if k != "from"}}}
    if cost_usd is not None:
        gen["body"]["costDetails"] = {"total": cost_usd}
    batch.append(gen)
    threading.Thread(target=_post, args=(batch,), daemon=True).start()
