#!/usr/bin/env python3
"""Pending-actions ledger for the agent answer-endpoints (Telegram-execution parity,
2026-07-05).

The problem it solves: a confirm-gated action is PROPOSED in one spawned answerer and
APPROVED (by the agent's own human, over Telegram) in a different spawn, possibly hours
later — after the bridge's rolling history has scrolled. This ledger is the durable,
structured referent that survives spawn boundaries: propose -> `add`; human approves in
chat -> the answering spawn finds it (`list`), executes, `resolve`s it, and reports.

Design:
  * One JSON file at $STATE_DIR/pending-actions.json (same dir as the endpoint audit —
    both agents' Tier-1 backup sets already cover it).
  * flock + atomic replace: safe under MAX_CONCURRENCY answerers.
  * Entries auto-expire (default 24h) so a stale approval can never fire late.
  * Resolved entries are kept (status executed/declined/cancelled/expired) — the ledger
    doubles as an approval audit trail.
  * Peer-spawned answerers may run ONLY this script (surgical --allowedTools pattern in
    endpoint.py); human-spawned answerers run with the live-session permission mode.

Usage:
  pending_actions.py add --requester genie --summary "one line" --plan "exact steps" \
      [--ttl-hours 24]                          -> prints the new entry (with id)
  pending_actions.py list [--all]               -> pending entries (or everything)
  pending_actions.py get <id>
  pending_actions.py resolve <id> --status executed|declined|cancelled --note "..."
All output is JSON (agents parse it).
"""
import argparse
import fcntl
import json
import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

STATE_DIR = pathlib.Path(
    os.environ.get("STATE_DIR", os.path.expanduser("~/.local/share/agent-endpoint"))
)

# --- canonical (unified) ledger location ---------------------------------------------
# RULE: every daemon and session that proposes or approves actions for ONE agent must
# resolve to the SAME ledger file — a sandboxed peer daemon writing its own copy while the
# human channel reads another means peer requests silently auto-expire unapproved. The
# sandboxed daemon's state dir is the one path both sides can reach (ReadWritePaths +
# ProtectHome jail it there; POSIX default ACLs let the privileged side in), so it wins
# when writable. (Full war story: the reference deployment's ops repo, split-brain fix
# 2026-07-20.)
# Resolution order:
#   1. $PENDING_LEDGER   — explicit override (daemons/tests).
#   2. the shared sandbox ledger, if that dir is writable by us (unifies both sides on a
#      host that runs the split peer daemon).
#   3. $STATE_DIR/pending-actions.json — per-host fallback (hosts with no split daemon).
_SHARED_STATE = pathlib.Path("/var/lib/agent-peer/state")


def _resolve_ledger():
    override = os.environ.get("PENDING_LEDGER")
    if override:
        return pathlib.Path(override)
    if os.access(_SHARED_STATE, os.W_OK):
        return _SHARED_STATE / "pending-actions.json"
    return STATE_DIR / "pending-actions.json"


LEDGER = _resolve_ledger()
# The lock MUST live beside the ledger, else two writers (peer user + claude) would take
# different locks and race on the shared JSON.
LOCK = LEDGER.parent / ".pending-actions.lock"
RESOLVE_STATUSES = {"executed", "declined", "cancelled"}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat(timespec="seconds")


class _Locked:
    def __enter__(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        # The lock/ledger may live outside STATE_DIR (PENDING_LEDGER override or the shared
        # sandbox dir) — make sure THAT parent exists too, or open(LOCK) crashes.
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(LOCK, "w")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def _load():
    """Read the ledger and expire overdue pending entries (persisted by the caller)."""
    try:
        entries = json.loads(LEDGER.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        entries = []
    now = _iso(_now())
    for e in entries:
        if e["status"] == "pending" and e["expires"] < now:
            e["status"] = "expired"
            e["resolved_ts"] = now
            e["note"] = e.get("note") or "auto-expired"
    return entries


def _save(entries):
    tmp = LEDGER.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=1, ensure_ascii=False) + "\n")
    os.replace(tmp, LEDGER)


def cmd_add(args):
    with _Locked():
        entries = _load()
        entry = {
            "id": os.urandom(4).hex(),
            "ts": _iso(_now()),
            "expires": _iso(_now() + timedelta(hours=args.ttl_hours)),
            "requester": args.requester,
            "summary": args.summary,
            "plan": args.plan,
            "status": "pending",
        }
        entries.append(entry)
        _save(entries)
    print(json.dumps(entry, indent=1))


def cmd_list(args):
    with _Locked():
        entries = _load()
        _save(entries)  # persist any auto-expiry
    if not args.all:
        entries = [e for e in entries if e["status"] == "pending"]
    print(json.dumps(entries, indent=1, ensure_ascii=False))


def cmd_get(args):
    with _Locked():
        entries = _load()
        _save(entries)
    for e in entries:
        if e["id"] == args.id:
            print(json.dumps(e, indent=1, ensure_ascii=False))
            return
    sys.exit(f"no entry with id {args.id}")


def cmd_resolve(args):
    with _Locked():
        entries = _load()
        for e in entries:
            if e["id"] == args.id:
                if e["status"] != "pending":
                    sys.exit(f"entry {args.id} is already '{e['status']}' — not pending")
                e["status"] = args.status
                e["resolved_ts"] = _iso(_now())
                e["note"] = args.note
                _save(entries)
                print(json.dumps(e, indent=1, ensure_ascii=False))
                return
        sys.exit(f"no entry with id {args.id}")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="record a proposed gated action")
    a.add_argument("--requester", required=True, help="who asked (human name or peer agent)")
    a.add_argument("--summary", required=True, help="one-line description")
    a.add_argument("--plan", required=True, help="the exact steps that will run on approval")
    a.add_argument("--ttl-hours", type=float, default=24)
    a.set_defaults(fn=cmd_add)

    l = sub.add_parser("list", help="list pending entries (JSON)")
    l.add_argument("--all", action="store_true", help="include resolved/expired entries")
    l.set_defaults(fn=cmd_list)

    g = sub.add_parser("get", help="show one entry")
    g.add_argument("id")
    g.set_defaults(fn=cmd_get)

    r = sub.add_parser("resolve", help="mark a pending entry executed/declined/cancelled")
    r.add_argument("id")
    r.add_argument("--status", required=True, choices=sorted(RESOLVE_STATUSES))
    r.add_argument("--note", default="")
    r.set_defaults(fn=cmd_resolve)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
