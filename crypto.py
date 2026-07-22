"""koine.crypto — end-to-end body encryption for Koine envelopes (KN1).

Confidentiality + authenticity against the transport, including a malicious/curious RELAY
operator: the relay routes on cleartext envelope fields and stores opaque ciphertext, and can
neither read the body nor forge one.

Scheme: X25519 ECDH (static-static — the shared secret is identical in both directions and only
the two domains' private keys can compute it) -> HKDF-SHA256 -> ChaCha20-Poly1305 AEAD. A valid
decrypt proves the message came from the holder of the peer private key (authenticity). The
cleartext routing fields (to/from/id/thread_id/type) are bound as AEAD associated data, so the
relay cannot tamper with them without breaking decryption.

Only a domain's SEND/RECEIVE components import this (they have `cryptography`); the relay never
does — that keeps the multi-tenant relay pure-stdlib and auditable. Keys are per agent/domain:
the private key stays home (vault/local), the public key is exchanged out of band (later: the
directory), pinned per edge. Wire shape when sealed — `body` is replaced by:
    "enc": {"alg": "koine-x25519-chacha20poly1305", "n": <b64 nonce>, "ct": <b64 ciphertext>}
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALG = "koine-x25519-chacha20poly1305"
_HKDF_SALT = b"koine/1 e2e"
_HKDF_INFO = b"koine body v1"
# routing fields bound as associated data (sender-set + relay-idempotent; NOT ts — it is
# stamped at different moments on each side)
_AAD_FIELDS = ("to", "from", "id", "thread_id", "type")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def generate_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64) for a new X25519 identity."""
    priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption)
    pb = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64e(pb), _b64e(ub)


def _derive_key(my_priv_b64: str, peer_pub_b64: str) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(_b64d(my_priv_b64))
    pub = X25519PublicKey.from_public_bytes(_b64d(peer_pub_b64))
    shared = priv.exchange(pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT,
                info=_HKDF_INFO).derive(shared)


def _aad(env: dict) -> bytes:
    return json.dumps({k: str(env.get(k, "")) for k in _AAD_FIELDS},
                      sort_keys=True, separators=(",", ":")).encode()


def is_sealed(env: dict) -> bool:
    return isinstance(env, dict) and isinstance(env.get("enc"), dict)


def seal_body(env: dict, my_priv_b64: str, peer_pub_b64: str) -> dict:
    """Return a copy of env with `body` encrypted into `enc`. No-op if there is no body.
    The sender MUST have populated the routing fields (to/from/id/thread_id/type) first —
    they are bound as AAD and must match what the recipient sees."""
    if "body" not in env or env.get("body") is None:
        return dict(env)
    key = _derive_key(my_priv_b64, peer_pub_b64)
    nonce = os.urandom(12)
    body = env["body"]
    if not isinstance(body, (str, bytes)):
        body = json.dumps(body)
    pt = body.encode() if isinstance(body, str) else body
    ct = ChaCha20Poly1305(key).encrypt(nonce, pt, _aad(env))
    out = {k: v for k, v in env.items() if k != "body"}
    out["enc"] = {"alg": ALG, "n": _b64e(nonce), "ct": _b64e(ct)}
    return out


def open_body(env: dict, my_priv_b64: str, peer_pub_b64: str) -> dict:
    """Return a copy of env with `enc` decrypted back into `body`. Passes through unchanged if
    the message is not sealed. Raises on auth/tamper failure or unknown alg."""
    if not is_sealed(env):
        return dict(env)
    enc = env["enc"]
    if enc.get("alg") != ALG:
        raise ValueError(f"unknown enc alg: {enc.get('alg')!r}")
    key = _derive_key(my_priv_b64, peer_pub_b64)
    pt = ChaCha20Poly1305(key).decrypt(_b64d(enc["n"]), _b64d(enc["ct"]), _aad(env))
    out = {k: v for k, v in env.items() if k != "enc"}
    out["body"] = pt.decode()
    return out
