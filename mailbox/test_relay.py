#!/usr/bin/env python3
"""Relay-mode integration test: two simulated agents exchange through a neutral mailbox.

Boots mailbox.py in MODE=relay on a throwaway high port with a self-signed cert, then drives
the public HTTP contract exactly as two gateways+pollers would. No pip deps. Exits non-zero on
the first failure. Run: python3 test_relay.py
"""
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
PORT = 18543
BASE = f"https://127.0.0.1:{PORT}"
TOK_A = "tokenA-secret"
TOK_B = "tokenB-secret"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

_checks = {"pass": 0, "fail": 0}


def check(name, cond):
    ok = bool(cond)
    _checks["pass" if ok else "fail"] += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    return ok


def req(method, path, token=None, body=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def main():
    tmp = tempfile.mkdtemp(prefix="koine-relay-test-")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    env = dict(os.environ, MODE="relay", AGENT_A="athena", TOKEN_A=TOK_A,
               AGENT_B="nova", TOKEN_B=TOK_B, CERT_FILE=cert, KEY_FILE=key,
               STATE_DIR=os.path.join(tmp, "state"), PUBLIC_PORT=str(PORT),
               DOMAIN="test", GRANT_TYPES="question,notification",
               GRANT_MAX_PER_DAY="5", GRANT_THREAD_DEPTH="6")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "mailbox.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                s, _b = req("GET", "/health")
                if s == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)

        print("health + mode:")
        s, b = req("GET", "/health")
        check("health 200", s == 200)
        check("mode=relay", b.get("mode") == "relay")
        check("both inboxes present", set(b.get("inbox", {})) == {"athena", "nova"})

        print("auth:")
        check("no token -> 401", req("GET", "/inbox", token=None)[0] == 401)
        check("bad token -> 401", req("GET", "/inbox", token="nope")[0] == 401)

        print("blocking question A->B (B polls inbox, replies):")
        result = {}

        def ask():
            result["s"], result["b"] = req(
                "POST", "/ask", token=TOK_A,
                body={"type": "question", "id": "q1", "thread_id": "t1",
                      "body": "hello nova", "from": "SPOOF"}, timeout=15)

        th = threading.Thread(target=ask)
        th.start()
        time.sleep(0.5)
        s, b = req("GET", "/inbox?wait=5", token=TOK_B)
        env0 = (b.get("envelopes") or [{}])[0]
        check("B inbox got the message", env0.get("id") == "q1")
        check("from is token-derived (athena), NOT the spoofed body value",
              env0.get("from") == "athena")
        check("to stamped nova", env0.get("to") == "nova")
        s2, _ = req("POST", "/reply", token=TOK_B,
                    body={"reply_to": "q1", "reply": {"ok": True, "body": "hi athena"}})
        check("reply accepted", s2 == 200)
        th.join(timeout=5)
        check("A's ask unblocked with the reply", result.get("b", {}).get("body") == "hi athena")

        print("reply-ownership: A may not reply to a message addressed to B:")
        def ask2():
            req("POST", "/ask", token=TOK_A,
                body={"type": "question", "id": "q2", "thread_id": "t2", "body": "x"}, timeout=8)
        th2 = threading.Thread(target=ask2, daemon=True)
        th2.start()
        time.sleep(0.4)
        sown, _ = req("POST", "/reply", token=TOK_A,
                      body={"reply_to": "q2", "reply": {"ok": True, "body": "forged"}})
        check("wrong-agent reply -> 403", sown == 403)
        # let the legit recipient drain+reply so nothing hangs
        req("GET", "/inbox?wait=3", token=TOK_B)
        req("POST", "/reply", token=TOK_B, body={"reply_to": "q2", "reply": {"ok": True, "body": "ok"}})

        print("notification is fire-and-forget (202, no block):")
        t0 = time.time()
        s, b = req("POST", "/ask", token=TOK_B,
                   body={"type": "notification", "id": "n1", "body": "fyi"})
        check("notification -> 202", s == 202)
        check("returned immediately (<2s, did not block)", time.time() - t0 < 2)
        s, b = req("GET", "/inbox?wait=3", token=TOK_A)
        check("A received the notification", (b.get("envelopes") or [{}])[0].get("id") == "n1")

        print("grant: disallowed type -> 403:")
        s, b = req("POST", "/ask", token=TOK_A,
                   body={"type": "action_request", "id": "a1", "body": "do x"})
        check("action_request refused by grant", s == 403 and not b.get("ok"))

        print("grant: per-sender daily cap (5) -> 429 on the 6th from A:")
        # A already spent q1,q2,a1-was-refused(not counted). Send until cap.
        codes = []
        for i in range(6):
            sc, _ = req("POST", "/ask", token=TOK_A,
                        body={"type": "notification", "id": f"cap{i}", "body": "x"})
            codes.append(sc)
        check("cap eventually returns 429", 429 in codes)

        print("kill switch:")
        open(os.path.join(tmp, "state", "DISABLED"), "w").close()
        check("health still 200 when disabled", req("GET", "/health")[0] == 200)
        check("/ask 503 when disabled",
              req("POST", "/ask", token=TOK_A,
                  body={"type": "question", "id": "kz", "body": "x"})[0] == 503)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print(f"\n{_checks['pass']} passed, {_checks['fail']} failed")
    sys.exit(1 if _checks["fail"] else 0)


if __name__ == "__main__":
    main()
