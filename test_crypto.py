#!/usr/bin/env python3
"""koine.crypto self-test. Requires `cryptography`. Run: python3 test_crypto.py"""
import copy
import sys

import crypto

_p = {"pass": 0, "fail": 0}


def check(name, cond):
    ok = bool(cond)
    _p["pass" if ok else "fail"] += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    return ok


def main():
    a_priv, a_pub = crypto.generate_keypair()
    b_priv, b_pub = crypto.generate_keypair()
    c_priv, c_pub = crypto.generate_keypair()   # an interloper (a curious relay's own key)

    env = {"from": "athena", "to": "nova", "id": "m1", "thread_id": "t1",
           "type": "question", "body": "the secret is 42", "ts": "2026-07-21T00:00:00Z"}

    print("round-trip (A seals to B, B opens from A):")
    sealed = crypto.seal_body(env, a_priv, b_pub)
    check("body removed", "body" not in sealed)
    check("enc present with alg", sealed.get("enc", {}).get("alg") == crypto.ALG)
    check("routing stays cleartext", sealed["from"] == "athena" and sealed["to"] == "nova")
    opened = crypto.open_body(sealed, b_priv, a_pub)
    check("B recovers the plaintext", opened.get("body") == "the secret is 42")
    check("enc removed after open", "enc" not in opened)

    print("static-static is symmetric (B seals to A, A opens):")
    s2 = crypto.seal_body({**env, "from": "nova", "to": "athena"}, b_priv, a_pub)
    o2 = crypto.open_body(s2, a_priv, b_pub)
    check("A recovers B's plaintext", o2.get("body") == "the secret is 42")

    print("confidentiality: ciphertext leaks nothing:")
    blob = str(sealed)
    check("plaintext not in the wire form", "the secret is 42" not in blob)

    print("authenticity: an interloper key cannot decrypt:")
    try:
        crypto.open_body(sealed, c_priv, a_pub)
        check("interloper decrypt rejected", False)
    except Exception:
        check("interloper decrypt rejected", True)

    print("tamper-evidence: relay flips a routing field -> decrypt fails (AAD bound):")
    tampered = copy.deepcopy(sealed)
    tampered["from"] = "mallory"
    try:
        crypto.open_body(tampered, b_priv, a_pub)
        check("tampered `from` rejected", False)
    except Exception:
        check("tampered `from` rejected", True)

    print("tamper-evidence: ciphertext bit-flip -> decrypt fails:")
    t2 = copy.deepcopy(sealed)
    raw = bytearray(crypto._b64d(t2["enc"]["ct"]))
    raw[0] ^= 0x01
    t2["enc"]["ct"] = crypto._b64e(bytes(raw))
    try:
        crypto.open_body(t2, b_priv, a_pub)
        check("flipped ciphertext rejected", False)
    except Exception:
        check("flipped ciphertext rejected", True)

    print("passthrough: unsealed message opens unchanged:")
    plain = {"from": "athena", "to": "nova", "id": "m2", "body": "hi"}
    check("open passthrough", crypto.open_body(plain, b_priv, a_pub).get("body") == "hi")
    check("is_sealed false for plaintext", not crypto.is_sealed(plain))
    check("no-body seal is a no-op", "enc" not in crypto.seal_body(
        {"from": "a", "to": "b", "id": "x"}, a_priv, b_pub))

    print("reply-shaped dict (id/thread_id AAD) round-trips:")
    reply = {"ok": True, "id": "m1", "thread_id": "t1", "from": "nova", "to": "athena",
             "type": "answer", "body": "the answer is also 42"}
    rs = crypto.seal_body(reply, b_priv, a_pub)
    ro = crypto.open_body(rs, a_priv, b_pub)
    check("reply body recovered", ro.get("body") == "the answer is also 42" and ro.get("ok"))

    print(f"\n{_p['pass']} passed, {_p['fail']} failed")
    sys.exit(1 if _p["fail"] else 0)


if __name__ == "__main__":
    main()
