#!/usr/bin/env python3
"""KN2 multi-tenant isolation test: THREE accounts on one relay, ONE registered edge
(alice<->bob). carol is registered but has no edge to anyone. Proves the isolation gate:
routing by registered edge, per-account inbox isolation, reply-ownership, and that an account
with no edge is fully walled off. Driven via a RELAY_REGISTRY file. Run: python3 test_multitenant.py
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
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 18544
BASE = f"https://127.0.0.1:{PORT}"
TOK = {"alice": "alice-tok", "bob": "bob-tok", "carol": "carol-tok"}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
_c = {"pass": 0, "fail": 0}


def check(name, cond):
    ok = bool(cond)
    _c["pass" if ok else "fail"] += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    return ok


def req(method, path, who=None, body=None, timeout=10):
    h = {"Content-Type": "application/json"}
    if who:
        h["Authorization"] = f"Bearer {TOK[who]}"
    r = urllib.request.Request(BASE + path, method=method,
                               data=json.dumps(body).encode() if body is not None else None, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def _sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def main():
    tmp = tempfile.mkdtemp(prefix="koine-mt-test-")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
                    "-days", "1", "-nodes", "-subj", "/CN=localhost"], check=True, capture_output=True)
    registry = {
        "accounts": [{"agent": a, "token_sha256": _sha(t)} for a, t in TOK.items()],
        "edges": [{"agents": ["alice", "bob"], "types": ["question", "notification"],
                   "max_per_day": 50, "thread_depth": 6, "expires": "2030-01-01"}],
    }
    reg_path = os.path.join(tmp, "registry.json")
    json.dump(registry, open(reg_path, "w"))
    env = dict(os.environ, MODE="relay", RELAY_REGISTRY="@" + reg_path, CERT_FILE=cert, KEY_FILE=key,
               STATE_DIR=os.path.join(tmp, "state"), PUBLIC_PORT=str(PORT), DOMAIN="test")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "mailbox.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if req("GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)

        print("registry loaded:")
        s, b = req("GET", "/health")
        check("3 accounts", b.get("accounts") == 3)
        check("1 edge alice<->bob", len(b.get("edges", [])) == 1
              and b["edges"][0]["agents"] == ["alice", "bob"])

        print("edge routing: alice->bob works:")
        result = {}
        def ask():
            result["s"], result["b"] = req("POST", "/ask", who="alice",
                body={"type": "question", "id": "m1", "to": "bob", "body": "hi bob"}, timeout=15)
        th = threading.Thread(target=ask); th.start()
        time.sleep(0.5)
        s, b = req("GET", "/inbox?wait=5", who="bob")
        e0 = (b.get("envelopes") or [{}])[0]
        check("bob received it, from=alice (token-derived)", e0.get("from") == "alice")
        req("POST", "/reply", who="bob", body={"reply_to": "m1", "reply": {"ok": True, "body": "hi alice"}})
        th.join(timeout=5)
        check("alice got the reply", result.get("b", {}).get("body") == "hi alice")

        print("no-edge isolation: alice->carol refused (no registered edge):")
        s, b = req("POST", "/ask", who="alice",
                   body={"type": "question", "id": "m2", "to": "carol", "body": "hi"})
        check("alice->carol -> 403 no edge", s == 403 and "no registered edge" in b.get("body", ""))

        print("no-edge isolation: carol->alice refused too:")
        s, b = req("POST", "/ask", who="carol",
                   body={"type": "question", "id": "m3", "to": "alice", "body": "hi"})
        check("carol->alice -> 403 no edge", s == 403)

        print("inbox isolation: carol cannot read bob's inbox (only her own token works):")
        # queue a fresh alice->bob message, then carol polls — she must NOT see it
        def ask2():
            req("POST", "/ask", who="alice",
                body={"type": "question", "id": "m4", "to": "bob", "body": "secret for bob"}, timeout=8)
        threading.Thread(target=ask2, daemon=True).start()
        time.sleep(0.5)
        s, b = req("GET", "/inbox?wait=2", who="carol")
        check("carol's inbox is empty (isolation)", b.get("envelopes") == [])
        # bob drains it (cleanup) + reply so the ask thread ends
        req("GET", "/inbox?wait=3", who="bob")
        req("POST", "/reply", who="bob", body={"reply_to": "m4", "reply": {"ok": True, "body": "ok"}})

        print("reply-ownership: carol cannot reply to a bob-owned message:")
        def ask3():
            req("POST", "/ask", who="alice",
                body={"type": "question", "id": "m5", "to": "bob", "body": "x"}, timeout=8)
        threading.Thread(target=ask3, daemon=True).start()
        time.sleep(0.4)
        s, _ = req("POST", "/reply", who="carol", body={"reply_to": "m5", "reply": {"ok": True, "body": "forged"}})
        check("carol reply to bob's msg -> 403", s == 403)
        req("GET", "/inbox?wait=3", who="bob")
        req("POST", "/reply", who="bob", body={"reply_to": "m5", "reply": {"ok": True, "body": "ok"}})

        print("multi-edge from-filter: bob drains only alice's mail with ?from=alice:")
        # (single peer here, but exercise the filter path)
        def ask4():
            req("POST", "/ask", who="alice",
                body={"type": "notification", "id": "m6", "to": "bob", "body": "fyi"}, timeout=8)
        threading.Thread(target=ask4, daemon=True).start()
        time.sleep(0.4)
        s, b = req("GET", "/inbox?wait=3&from=alice", who="bob")
        check("from=alice filter returns alice's msg", (b.get("envelopes") or [{}])[0].get("id") == "m6")
        s, b = req("GET", "/inbox?wait=1&from=nobody", who="bob")
        check("from=nobody filter returns nothing", b.get("envelopes") == [])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print(f"\n{_c['pass']} passed, {_c['fail']} failed")
    sys.exit(1 if _c["fail"] else 0)


if __name__ == "__main__":
    main()
