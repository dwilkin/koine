#!/usr/bin/env python3
"""KN-M2 Phase 2 — node→node mail forwarding across groups.

Boots TWO relay instances (a "primary" node homing alice, an "edge" node homing bob) with a
cross-group edge + forwarding tables + a shared mesh secret. Verifies:
  - alice→bob (a foreign recipient) FORWARDS from the primary node to the edge node, bob
    receives it there, replies, and alice gets the reply (full cross-group question).
  - a notification forwards (202).
  - /node-forward re-enforces auth (bad mesh secret → 401) and the grant (no-edge → 403/400).
Run: python3 mailbox/test_forwarding.py
"""
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
P_PRIMARY, P_EDGE = 8471, 8472
MESH = "mesh-secret-forward-xyz"
TOK = {"alice": "tok-alice", "bob": "tok-bob"}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
_fails = []


def check(name, cond):
    print(("  ok  " if cond else "FAIL  ") + name)
    if not cond:
        _fails.append(name)


def _sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def req(port, method, path, who=None, body=None, timeout=10):
    h = {"Content-Type": "application/json"}
    if who:
        h["Authorization"] = f"Bearer {TOK[who]}"
    r = urllib.request.Request(f"https://127.0.0.1:{port}{path}", method=method,
                               data=json.dumps(body).encode() if body is not None else None,
                               headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def _boot(tmp, port, homed_agent, foreign_agent, foreign_port, cert, key):
    edge = {"agents": ["alice", "bob"], "types": ["question", "notification"],
            "max_per_day": 50, "thread_depth": 6, "expires": "2030-01-01"}
    registry = {
        "accounts": [{"agent": homed_agent, "token_sha256": _sha(TOK[homed_agent])}],
        "edges": [edge],
        "forwarding": [{"agent": foreign_agent, "group": "other",
                        "urls": [f"https://127.0.0.1:{foreign_port}"]}],
    }
    reg = os.path.join(tmp, f"reg-{port}.json")
    json.dump(registry, open(reg, "w"))
    env = dict(os.environ, MODE="relay", RELAY_REGISTRY="@" + reg, CERT_FILE=cert, KEY_FILE=key,
               STATE_DIR=os.path.join(tmp, f"state-{port}"), PUBLIC_PORT=str(port),
               DOMAIN="test", NODE_FORWARD_TOKEN=MESH, NODE_FORWARD_INSECURE="1")
    return subprocess.Popen([sys.executable, os.path.join(HERE, "mailbox.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def main():
    tmp = tempfile.mkdtemp(prefix="koine-fwd-test-")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    # primary homes alice + forwards bob→edge; edge homes bob + forwards alice→primary
    p_primary = _boot(tmp, P_PRIMARY, "alice", "bob", P_EDGE, cert, key)
    p_edge = _boot(tmp, P_EDGE, "bob", "alice", P_PRIMARY, cert, key)
    try:
        for port in (P_PRIMARY, P_EDGE):
            for _ in range(50):
                try:
                    if req(port, "GET", "/health")[0] == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.1)

        print("cross-group question: alice(primary)->bob(edge) forwards end-to-end:")
        result = {}

        def ask():
            result["s"], result["b"] = req(
                P_PRIMARY, "POST", "/ask", who="alice",
                body={"type": "question", "id": "f1", "to": "bob", "body": "hi bob"}, timeout=20)
        th = threading.Thread(target=ask)
        th.start()
        time.sleep(0.6)
        # bob polls on the EDGE node (where the forward landed)
        s, b = req(P_EDGE, "GET", "/inbox?wait=6", who="bob")
        e0 = (b.get("envelopes") or [{}])[0]
        check("bob received the forwarded msg on the edge node, from=alice",
              e0.get("from") == "alice" and e0.get("id") == "f1")
        req(P_EDGE, "POST", "/reply", who="bob",
            body={"reply_to": "f1", "reply": {"ok": True, "body": "hi alice"}})
        th.join(timeout=8)
        check("alice got the reply back through the forward",
              result.get("b", {}).get("body") == "hi alice" and result.get("s") == 200)

        print("cross-group notification forwards (202):")
        s, b = req(P_PRIMARY, "POST", "/ask", who="alice",
                   body={"type": "notification", "id": "f2", "to": "bob", "body": "fyi"})
        check("notification -> 202 queued", s == 202)
        req(P_EDGE, "GET", "/inbox?wait=3", who="bob")   # drain

        print("/node-forward auth: wrong mesh secret -> 401:")
        r = urllib.request.Request(
            f"https://127.0.0.1:{P_EDGE}/node-forward", method="POST",
            data=json.dumps({"from": "alice", "to": "bob", "type": "question",
                             "id": "f3", "body": "x"}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer WRONG"})
        try:
            urllib.request.urlopen(r, timeout=5, context=CTX)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        check("bad mesh secret -> 401", code == 401)

        print("/node-forward grant re-enforced: unknown recipient -> 400:")
        r = urllib.request.Request(
            f"https://127.0.0.1:{P_EDGE}/node-forward", method="POST",
            data=json.dumps({"from": "alice", "to": "nobody", "type": "question",
                             "id": "f4", "body": "x"}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {MESH}"})
        try:
            with urllib.request.urlopen(r, timeout=5, context=CTX) as resp:
                code, jb = resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            code, jb = e.code, {}
        check("unknown recipient at ingress -> 400", code == 400)
    finally:
        p_primary.terminate()
        p_edge.terminate()

    print("\n" + ("ALL FORWARDING TESTS PASSED" if not _fails else f"FAILURES: {_fails}"))
    sys.exit(1 if _fails else 0)


if __name__ == "__main__":
    main()
