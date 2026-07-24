#!/usr/bin/env python3
"""koine/ack/v1 (2026-07-24): a plain notification from an untrusted peer gets a
deterministic ack from the machine lane — no LLM turn, no timeout risk (a notification
answer timing out after 180s on a live edge is what motivated this). Coord'd
notifications fall through to their lanes; questions are never acked here.
No pip deps, no network. Run: python3 endpoint/test_ack_lane.py
"""
import importlib.util
import json
import os
import sys
import tempfile

os.environ.setdefault("AUTH_TOKEN", "test")
os.environ.setdefault("MACHINE_LANE", "1")
os.environ.setdefault("WORKDIR", tempfile.mkdtemp(prefix="acktest-"))

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("endpoint", os.path.join(HERE, "endpoint.py"))
ep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ep)

_fails = []


def ck(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        _fails.append(name)


def _msg(mtype, body, channel="peer"):
    return {"from": "stranger", "type": mtype, "channel": channel, "body": body,
            "id": "m1", "thread_id": "t1"}


def main():
    # plain-text notification -> deterministic ack
    r = ep._machine_answer(_msg("notification", "FYI: I deployed the thing."))
    ck("plain notification gets machine ack", r is not None)
    if r:
        d = json.loads(r[0])
        ck("ack envelope shape", d["coord"] == "koine/ack/v1" and d["kind"] == "ack")
        ck("ack echoes id + thread", d["id"] == "m1" and d["thread_id"] == "t1")
        ck("ack meta is machine lane / $0",
           r[1]["machine_lane"] is True and r[1]["cost_usd"] == 0.0)

    # JSON-but-uncoordinated notification -> still acked
    r = ep._machine_answer(_msg("notification", json.dumps({"note": "hello"})))
    ck("coordless JSON notification acked", r is not None
       and json.loads(r[0])["coord"] == "koine/ack/v1")

    # coord'd notification falls through to its lane (no skill ctx here -> None,
    # NOT an ack — the lane owns its own ack semantics)
    r = ep._machine_answer(_msg("notification",
                                json.dumps({"coord": "koine/skill/v1", "kind": "catalog"})))
    ck("coord'd notification NOT generic-acked",
       r is None or json.loads(r[0]).get("coord") != "koine/ack/v1")

    # questions are never acked by this path
    r = ep._machine_answer(_msg("question", "what is your uptime?"))
    ck("plain question falls through to the LLM", r is None)

    print("\n" + ("ALL ACK-LANE TESTS PASSED" if not _fails else f"FAILURES: {_fails}"))
    sys.exit(1 if _fails else 0)


if __name__ == "__main__":
    main()
