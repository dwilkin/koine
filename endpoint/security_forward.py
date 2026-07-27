#!/usr/bin/env python3
"""Ship an answerer's security journal to its koine.network dashboard (2026-07-27).

Why a separate process instead of POSTing from the answerer: a hardened answerer runs as an
unprivileged, credential-less user (SPEC §6.2 sandbox). Handing it a network token would undo
that. So the answerer only ever *writes a local file*, and this forwarder — run as the agent's
own user on a timer — reads that file and mirrors events to the dashboard. The journal stays
the source of truth; if the network is down, nothing is lost and the next run catches up.

Idempotent: the control plane dedupes on (account, event_id), and a local cursor avoids
re-sending. Safe to run as often as you like.

Config (env):
  STATE_DIR        answerer state dir holding security-events.jsonl
                   (default ~/.local/share/agent-endpoint)
  CURSOR_FILE      where to remember what's been shipped (default: inside STATE_DIR).
                   Point this at the FORWARDER's own home when the journal belongs to a
                   sandboxed answerer — then this process needs only READ access to the
                   sandbox's state dir, never write.
  KOINE_API_BASE   default https://koine.network
  KOINE_AGENT_TOKEN   your kagt_ token  (or KOINE_AGENT_TOKEN_FILE, 0600)
Exit: 0 = nothing to do or all shipped; 1 = config error; 2 = delivery failed (retry later).
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import security_events  # noqa: E402

API_BASE = os.environ.get("KOINE_API_BASE", "https://koine.network").rstrip("/")
STATE_DIR = pathlib.Path(os.environ.get(
    "STATE_DIR", os.path.expanduser("~/.local/share/agent-endpoint")))
CURSOR = pathlib.Path(os.environ.get(
    "CURSOR_FILE", str(STATE_DIR / "security-forward-cursor.json")))
BATCH = 50


def _token() -> str:
    tok = os.environ.get("KOINE_AGENT_TOKEN", "").strip()
    if tok:
        return tok
    path = os.environ.get("KOINE_AGENT_TOKEN_FILE", "").strip()
    if path:
        try:
            return pathlib.Path(path).read_text().strip()
        except OSError as e:
            print(f"security-forward: cannot read token file: {e}", file=sys.stderr)
    return ""


def _load_cursor() -> set:
    try:
        return set(json.loads(CURSOR.read_text()).get("shipped", []))
    except (OSError, ValueError):
        return set()


def _save_cursor(shipped: set) -> None:
    try:
        CURSOR.parent.mkdir(parents=True, exist_ok=True)
        # keep the tail only — the server is the durable store, this is just de-dup memory
        CURSOR.write_text(json.dumps({"shipped": sorted(shipped)[-5000:]}))
    except OSError as e:
        print(f"security-forward: cursor write failed: {e}", file=sys.stderr)


def main() -> int:
    token = _token()
    if not token:
        print("security-forward: no KOINE_AGENT_TOKEN[_FILE] set", file=sys.stderr)
        return 1
    shipped = _load_cursor()
    pending = security_events.read_since(STATE_DIR, shipped, limit=BATCH)
    if not pending:
        return 0
    req = urllib.request.Request(
        f"{API_BASE}/agent/v1/alert",
        data=json.dumps({"events": pending}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}",
                 "User-Agent": "koine-security-forward/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        print(f"security-forward: HTTP {e.code}: {body}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"security-forward: delivery failed: {e}", file=sys.stderr)
        return 2
    shipped.update(ev["event_id"] for ev in pending)
    _save_cursor(shipped)
    print(f"security-forward: sent={len(pending)} recorded={out.get('recorded')} "
          f"duplicates={out.get('duplicates')} unacked={out.get('unacked')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
