#!/usr/bin/env python3
"""KO-L2: the relay caps concurrent BLOCKING questions (RELAY_MAX_INFLIGHT) so a burst
can't exhaust worker threads. Boots mailbox.py in relay mode with the cap set to 1, holds
one question in flight (no reply), and asserts a second concurrent question is refused 429
(not queued to block another thread). No pip deps. Run: python3 test_relay_inflight.py
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
PORT = 18544
BASE = f"https://127.0.0.1:{PORT}"
TOK_A = "tokenA-secret"
TOK_B = "tokenB-secret"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
_checks = {"pass": 0, "fail": 0}


def check(name, cond):
    _checks["pass" if cond else "fail"] += 1
    print(("  ok  " if cond else "FAIL  ") + name)


def req(method, path, token=None, body=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    tmp = tempfile.mkdtemp(prefix="koine-inflight-test-")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    env = dict(os.environ, MODE="relay", AGENT_A="athena", TOKEN_A=TOK_A,
               AGENT_B="nova", TOKEN_B=TOK_B, CERT_FILE=cert, KEY_FILE=key,
               STATE_DIR=os.path.join(tmp, "state"), PUBLIC_PORT=str(PORT),
               DOMAIN="test", GRANT_TYPES="question,notification",
               GRANT_MAX_PER_DAY="50", GRANT_THREAD_DEPTH="50",
               REPLY_TIMEOUT="3",        # keep the held question's server-side wait short
               RELAY_MAX_INFLIGHT="1")   # cap = 1 for the test
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "mailbox.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if req("GET", "/health")[0] == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("relay did not come up")

        # Hold one blocking question in flight (nova never replies -> stays in wait()).
        def hold():
            try:
                req("POST", "/ask", token=TOK_A, timeout=8,
                    body={"type": "question", "id": "hold1", "thread_id": "h1",
                          "to": "nova", "body": "occupy the slot"})
            except Exception:
                pass
        threading.Thread(target=hold, daemon=True).start()
        time.sleep(0.6)  # let it acquire the single slot and block

        # A second concurrent question must be refused 429, not queued.
        s, b = req("POST", "/ask", token=TOK_A, timeout=8,
                   body={"type": "question", "id": "q2", "thread_id": "t2",
                         "to": "nova", "body": "should be rejected"})
        check("2nd concurrent question -> 429 (in-flight cap)", s == 429)
        check("429 body names the cap", "busy" in str(b.get("body", "")).lower())

        # A notification must NOT be capped (fire-and-forget, doesn't hold a slot).
        s3, _ = req("POST", "/ask", token=TOK_A, timeout=8,
                    body={"type": "notification", "id": "n1", "thread_id": "n1",
                          "to": "nova", "body": "fyi"})
        check("notification still accepted under a full question cap (202)", s3 == 202)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print(f"\n{_checks['pass']} passed, {_checks['fail']} failed", flush=True)
    # os._exit avoids an interpreter-shutdown race with the still-blocked daemon hold thread.
    os._exit(1 if _checks["fail"] else 0)


if __name__ == "__main__":
    main()
