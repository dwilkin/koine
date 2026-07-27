"""Security-event journal for an answerer (koine reference impl, 2026-07-27).

The tripwire and output-redaction backstops detect probes; this module gives those detections
a **portable, durable home** instead of a host-specific push channel:

  1. an append-only JSONL journal on the agent's own disk — the source of truth, works with no
     network and no third-party tool;
  2. (via `security_forward.py`) a mirror into the agent's koine.network dashboard, so the
     human sees warnings in the same place every koine operator does.

`ALERT_CMD` (a local notifier binary) remains supported and optional — it is now one more sink,
not the only way to learn you were probed.

Design rules:
  * NEVER journal message bodies or secret values. `summary` is a short human label; `detail`
    carries metadata only (matched tripwire labels, peer name, counts).
  * Fail-soft: a journal problem must never break an answer. Every entry point swallows.
  * Event ids are stable and unique so the forwarder can retry/replay idempotently.
"""
from __future__ import annotations

import json
import os
import pathlib
import uuid
from datetime import datetime, timezone

JOURNAL_NAME = "security-events.jsonl"
SEVERITIES = ("info", "warning", "critical")


def journal_path(state_dir) -> pathlib.Path:
    return pathlib.Path(state_dir) / JOURNAL_NAME


def record(state_dir, kind, severity="warning", peer="", summary="", detail=None):
    """Append one security event to the journal. Returns the event dict (or None on failure).

    Never raises: a security backstop that breaks the answer path would be worse than the
    probe it is reporting.
    """
    try:
        if severity not in SEVERITIES:
            severity = "warning"
        event = {
            "event_id": uuid.uuid4().hex[:32],
            "kind": str(kind)[:48],
            "severity": severity,
            "peer": str(peer or "")[:64],
            "summary": str(summary or "")[:400],
            "detail": detail if isinstance(detail, dict) else {},
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
        path = journal_path(state_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps(event) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return event
    except Exception:
        return None


def read_since(state_dir, seen_ids=(), limit=500):
    """Yield journal events whose event_id is not in `seen_ids` (oldest first)."""
    path = journal_path(state_dir)
    out = []
    try:
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("event_id") and ev["event_id"] not in seen_ids:
                    out.append(ev)
                    if len(out) >= limit:
                        break
    except FileNotFoundError:
        return []
    except Exception:
        return out
    return out
