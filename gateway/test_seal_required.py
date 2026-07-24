#!/usr/bin/env python3
"""KO-M1 unit tests — per-edge seal-required, fail-closed on downgrade (2026-07-23).

Receiving-side enforcement only:
  * gateway._reply_seal_check — an UNSEALED reply body on an E2E edge (peer card has a
    pubkey) is refused; sealed replies and bodyless acks pass; non-E2E edges never call it.
  * poller._inbound_seal_error — an UNSEALED inbound envelope on an encrypted edge is
    refused before any processing; plaintext edges (no keys) are unaffected.

Structural checks only (mirror crypto.is_sealed), so no `cryptography` dependency. When the
`cryptography` package IS available, an extra test proves the check is a NO-OP for a
genuinely-sealed body (the live poseidon edge shape).

Run: python3 gateway/test_seal_required.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_tmp = tempfile.mkdtemp(prefix="sealtest-")
_agents = os.path.join(_tmp, "agents.json")
with open(_agents, "w") as f:
    json.dump({"agents": [{"name": "local", "endpoint": "http://127.0.0.1:1/ask"}]}, f)

os.environ["STATE_DIR"] = _tmp
os.environ["AGENTS_JSON"] = _agents
os.environ.setdefault("ENDPOINT_TOKEN", "test")
os.environ.setdefault("GW_BEARER_TOKEN", "test")
# poller.py import requirements (no keys -> no crypto import)
os.environ.setdefault("MAILBOX_URL", "http://127.0.0.1:1")
os.environ.setdefault("MAILBOX_TOKEN", "test")

spec = importlib.util.spec_from_file_location("gateway", os.path.join(HERE, "gateway.py"))
gw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gw)

pspec = importlib.util.spec_from_file_location("poller", os.path.join(HERE, "poller.py"))
poller = importlib.util.module_from_spec(pspec)
pspec.loader.exec_module(poller)

try:
    sys.path.insert(0, os.path.dirname(HERE))
    import crypto as _crypto_mod
    _crypto_mod.generate_keypair()          # proves `cryptography` actually works here
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


class GatewayReplySealCheck(unittest.TestCase):
    """Reply leg of an E2E edge (gateway._route calls this only when enc=True)."""

    def test_unsealed_reply_with_body_refused(self):
        err = gw._reply_seal_check({"ok": True, "body": "substituted plaintext"})
        self.assertIsNotNone(err)
        self.assertIn("unsealed reply refused", err)

    def test_unsealed_error_reply_becomes_labeled_transport_error(self):
        # koine/error/v1 (2026-07-24): ok=False bodies are no longer hard-refused — relays
        # can't seal (no keys), so their busy/timeout notes are accepted as TRANSPORT
        # errors, prominently labeled unauthenticated, never surfaced as peer content.
        disp, text = gw._unsealed_reply_disposition({"ok": False, "body": "busy (max 1)"})
        self.assertEqual(disp, "transport_error")
        self.assertIn("unauthenticated", text)
        self.assertIn("busy (max 1)", text)

    def test_structured_error_envelope_rendered(self):
        body = json.dumps({"coord": "koine/error/v1", "code": "busy",
                           "message": "answerer at capacity", "retry_after_s": 30})
        disp, text = gw._unsealed_reply_disposition({"ok": False, "body": body})
        self.assertEqual(disp, "transport_error")
        self.assertIn("busy: answerer at capacity", text)
        self.assertIn("retry in ~30s", text)

    def test_unsealed_ok_true_body_still_refused(self):
        # reply INTEGRITY is unchanged: an unsealed ok=true body = content substitution
        disp, text = gw._unsealed_reply_disposition({"ok": True, "body": "substituted"})
        self.assertEqual(disp, "refuse")
        self.assertIn("unsealed reply refused", text)

    def test_bodyless_unsealed_passes_disposition(self):
        self.assertEqual(gw._unsealed_reply_disposition({"ok": True})[0], "pass")

    def test_sealed_reply_passes(self):
        sealed = {"ok": True, "enc": {"alg": "koine-x25519-chacha20poly1305",
                                      "n": "bm9uY2U=", "ct": "Y3Q="}}
        self.assertIsNone(gw._reply_seal_check(sealed))

    def test_bodyless_reply_passes(self):
        # bare status/ack — nothing a relay could have substituted
        self.assertIsNone(gw._reply_seal_check({"ok": True}))
        self.assertIsNone(gw._reply_seal_check({"ok": True, "body": "  "}))

    def test_malformed_reply_refused(self):
        self.assertIsNotNone(gw._reply_seal_check(["not", "an", "object"]))


class PollerInboundSealCheck(unittest.TestCase):
    def test_unsealed_on_enc_edge_refused(self):
        err = poller._inbound_seal_error({"id": "m1", "body": "plaintext"}, enc_edge=True)
        self.assertIsNotNone(err)
        self.assertIn("unencrypted message refused", err)

    def test_sealed_on_enc_edge_passes(self):
        env = {"id": "m1", "enc": {"alg": "koine-x25519-chacha20poly1305",
                                   "n": "bm9uY2U=", "ct": "Y3Q="}}
        self.assertIsNone(poller._inbound_seal_error(env, enc_edge=True))

    def test_plaintext_edge_unaffected(self):
        # a card/edge WITHOUT keys (e.g. cid over the WG tunnel) never requires sealing
        self.assertIsNone(poller._inbound_seal_error({"id": "m1", "body": "plain"},
                                                     enc_edge=False))

    def test_sealed_helper_is_structural(self):
        self.assertTrue(poller._sealed({"enc": {"alg": "x", "n": "a", "ct": "b"}}))
        self.assertFalse(poller._sealed({"body": "x"}))
        self.assertFalse(poller._sealed({"enc": "not-a-dict"}))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed on this box")
class SealedEdgeNoOp(unittest.TestCase):
    """A genuinely-sealed envelope (the live poseidon edge) must pass BOTH checks — the
    KO-M1 tightening is a no-op for a correctly-sealed edge."""

    def test_real_sealed_body_passes_both_checks(self):
        a_priv, a_pub = _crypto_mod.generate_keypair()
        b_priv, b_pub = _crypto_mod.generate_keypair()
        env = {"to": "atlas", "from": "poseidon", "id": "m1", "thread_id": "t1",
               "type": "answer", "body": "the real reply"}
        sealed = _crypto_mod.seal_body(env, b_priv, a_pub)   # poseidon -> atlas
        self.assertIsNone(gw._reply_seal_check(sealed))
        self.assertIsNone(poller._inbound_seal_error(sealed, enc_edge=True))
        opened = _crypto_mod.open_body(sealed, a_priv, b_pub)
        self.assertEqual(opened["body"], "the real reply")


if __name__ == "__main__":
    unittest.main(verbosity=1)
