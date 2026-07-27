"""Send side must be MULTI-PEER (2026-07-27).

Peering is many-to-many by design (SPEC §5) — an agent accumulates edges over time. The RECEIVE
side (poller) has supported MULTI for a while, but the SEND side was pinned to one PEER_AGENT
and 403'd everything else ("this edge only reaches 'X'"). An agent could therefore receive from
many peers but only ever reply/initiate to one. Found in the wild when @poseidon — peered with
both atlas and mitchy — could not send to mitchy at all.

These tests pin the new default and the back-compat path.
"""
import importlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# crypto.py lives at the repo root; deployments place it alongside the daemon.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

BASE = {"LOCAL_AGENT": "me", "RELAY_URL": "https://relay.example:8443",
        "RELAY_TOKEN": "rt", "LOCAL_TOKEN": "lt"}

try:                     # `crypto` needs the optional `cryptography` package
    import crypto as _c  # noqa: F401
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def _load(**env):
    for k in ("PEER_AGENT", "PEERS_FILE", "MY_PRIVKEY", "PEER_PUBKEY"):
        os.environ.pop(k, None)
    os.environ.update(BASE)
    os.environ.update(env)
    import relay_client as rc
    return importlib.reload(rc)


def _peers_file(mapping):
    p = pathlib.Path(tempfile.mkdtemp()) / "koine-peers.json"
    p.write_text(json.dumps(mapping))
    return str(p)


class SinglePeerBackCompat(unittest.TestCase):
    def test_single_mode_still_pins_to_one_peer(self):
        rc = _load(PEER_AGENT="atlas")
        self.assertFalse(rc.MULTI)
        target, pub, err = rc._resolve("atlas")
        self.assertEqual(target, "atlas")
        self.assertIsNone(err)
        target, pub, err = rc._resolve("mitchy")
        self.assertIsNone(target)
        self.assertIn("only reaches 'atlas'", err)

    def test_single_mode_requires_peer_agent(self):
        for k in ("PEER_AGENT", "PEERS_FILE"):
            os.environ.pop(k, None)
        os.environ.update(BASE)
        import relay_client as rc
        with self.assertRaises(KeyError):
            importlib.reload(rc)


class MultiPeer(unittest.TestCase):
    def test_sends_to_any_known_peer(self):
        f = _peers_file({"atlas": {"pubkey": "A" * 44}, "mitchy": {"pubkey": "M" * 44}})
        rc = _load(PEERS_FILE=f)
        rc._load_peers()
        self.assertTrue(rc.MULTI)
        for name, key in (("atlas", "A" * 44), ("mitchy", "M" * 44)):
            target, pub, err = rc._resolve(name)
            self.assertIsNone(err, f"{name} should be reachable")
            self.assertEqual((target, pub), (name, key))

    def test_unknown_peer_is_refused_with_a_useful_list(self):
        f = _peers_file({"atlas": {"pubkey": "A" * 44}})
        rc = _load(PEERS_FILE=f)
        rc._load_peers()
        target, _, err = rc._resolve("stranger")
        self.assertIsNone(target)
        self.assertIn("no edge to 'stranger'", err)
        self.assertIn("atlas", err)          # tells the caller who IS reachable

    @unittest.skipUnless(HAVE_CRYPTO, "needs the optional `cryptography` package")
    def test_peer_without_pubkey_still_routes_plaintext(self):
        """Bootstrap case: an edge exists but the peer hasn't published a key yet. Sending
        plaintext is better than refusing — the relay still enforces the grant."""
        f = _peers_file({"newbie": {}})
        rc = _load(PEERS_FILE=f, MY_PRIVKEY="k")
        rc._load_peers()
        target, pub, err = rc._resolve("newbie")
        self.assertIsNone(err)
        self.assertEqual((target, pub), ("newbie", ""))

    def test_missing_to_is_an_error_not_a_silent_default(self):
        f = _peers_file({"atlas": {"pubkey": "A" * 44}})
        rc = _load(PEERS_FILE=f)
        rc._load_peers()
        target, _, err = rc._resolve("")
        self.assertIsNone(target)
        self.assertIn("required", err)

    def test_multi_mode_makes_peer_agent_optional(self):
        f = _peers_file({"atlas": {"pubkey": "A" * 44}})
        rc = _load(PEERS_FILE=f)          # no PEER_AGENT at all
        self.assertTrue(rc.MULTI)
        self.assertEqual(rc.PEER_AGENT, "")

    def test_hot_reload_picks_up_a_newly_approved_edge(self):
        """edge-sync writes the file; SIGHUP reloads it. A new edge must become sendable
        without restarting the daemon."""
        path = _peers_file({"atlas": {"pubkey": "A" * 44}})
        rc = _load(PEERS_FILE=path)
        rc._load_peers()
        self.assertIsNotNone(rc._resolve("mitchy")[2])       # not reachable yet
        pathlib.Path(path).write_text(json.dumps(
            {"atlas": {"pubkey": "A" * 44}, "mitchy": {"pubkey": "M" * 44}}))
        rc._load_peers()                                      # what SIGHUP triggers
        self.assertIsNone(rc._resolve("mitchy")[2])           # now reachable

    def test_unreadable_peers_file_does_not_crash(self):
        rc = _load(PEERS_FILE="/nonexistent/koine-peers.json")
        rc._load_peers()                                      # logs, does not raise
        self.assertEqual(rc._PEERS, {})


if __name__ == "__main__":
    unittest.main()
