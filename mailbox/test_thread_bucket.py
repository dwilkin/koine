"""Regression: messages that omit thread_id must NOT share one grant bucket.

Found in the wild 2026-07-27. `_grant_gate` reads `msg["thread_id"]`, but the /ask and
/node-forward handlers only stamped id/thread_id AFTER calling it. So any client that omitted
thread_id was gated on tid="" — a single bucket shared by every such message across EVERY edge.
Once `thread_depth` of them accumulated (6 by default), the relay permanently 429'd
"edge thread-depth cap reached" for all of them, on every edge, forever. Dedup was also dead on
those messages, since a blank id skips the replay lookup.

The fix stamps id/thread_id before the gate. These tests pin the contract that made the bug
possible, so it can't come back.
"""
import importlib
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))


def _load():
    os.environ.setdefault("LOCAL_AGENT", "a")
    os.environ.setdefault("PEER_AGENT", "b")
    os.environ.setdefault("EDGE_BEARER", "x")
    os.environ.setdefault("LOCAL_TOKEN", "y")
    os.environ["STATE_DIR"] = tempfile.mkdtemp()
    import mailbox as mb
    mb = importlib.reload(mb)
    mb._init_db()          # the gate writes to the `asks` table; main() normally creates it
    return mb


GRANT = {"types": ["question", "notification"], "max_per_day": 50,
         "thread_depth": 6, "expires": ""}


class ThreadBucketTest(unittest.TestCase):
    def setUp(self):
        self.mb = _load()

    def _gate(self, msg, sender="s", edge="s|r"):
        return self.mb._grant_gate(msg, dict(GRANT), sender=sender, edge=edge)

    def test_distinct_threads_do_not_share_a_bucket(self):
        """The bug: 7 messages, each its OWN thread, must all pass. Pre-fix these collapsed
        into tid='' and the 7th was refused."""
        for i in range(7):
            mid = f"id{i}"
            out = self._gate({"id": mid, "thread_id": mid, "type": "question"})
            self.assertIsNone(out, f"message {i} was wrongly refused: {out}")

    def test_thread_depth_still_enforced_within_one_thread(self):
        """The cap must still work where it's meant to — a single conversation."""
        for i in range(6):
            self.assertIsNone(
                self._gate({"id": f"m{i}", "thread_id": "same-thread", "type": "question"}))
        out = self._gate({"id": "m6", "thread_id": "same-thread", "type": "question"})
        self.assertIsNotNone(out)
        self.assertEqual(out[0], 429)
        self.assertIn("thread-depth", out[1])

    def test_blank_thread_id_is_the_shape_that_caused_the_bug(self):
        """Documents the hazard directly: if a caller reaches the gate with no ids, every such
        message shares the '' bucket. The handlers must therefore never call the gate that way
        — enforced by test_handlers_stamp_ids_before_gating below."""
        for i in range(6):
            self.assertIsNone(self._gate({"type": "question"}))
        out = self._gate({"type": "question"})
        self.assertIsNotNone(out, "blank-id messages should collapse — that's the hazard")
        self.assertEqual(out[0], 429)

    def test_every_gate_callsite_stamps_ids_first(self):
        """Source-level guard on the actual invariant: at EVERY _grant_gate call site, the
        id/thread_id setdefaults must already have run. Checked per call site rather than per
        handler, because `if self.path == "/ask":` appears in more than one handler."""
        src = pathlib.Path(__file__).resolve().parent.joinpath("mailbox.py").read_text()
        sites = [i for i in range(len(src))
                 if src.startswith("_grant_gate(msg", i)
                 and not src[max(0, i - 4):i].endswith("def ")]   # skip the definition itself
        self.assertGreaterEqual(len(sites), 2, "expected at least the /ask + /node-forward sites")
        for i in sites:
            window = src[max(0, i - 1200):i]
            self.assertIn('setdefault("thread_id"', window,
                          f"_grant_gate call at offset {i} is not preceded by a thread_id stamp")
            self.assertIn('setdefault("id"', window,
                          f"_grant_gate call at offset {i} is not preceded by an id stamp")

    def test_duplicate_id_still_detected(self):
        self.assertIsNone(self._gate({"id": "dup", "thread_id": "t1", "type": "question"}))
        out = self._gate({"id": "dup", "thread_id": "t1", "type": "question"})
        self.assertIsNotNone(out)
        self.assertEqual(out[0], 409)


if __name__ == "__main__":
    unittest.main()
