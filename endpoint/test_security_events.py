"""Security journal + forwarder (2026-07-27): the portable, no-third-party warning path."""
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import security_events  # noqa: E402


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())

    def test_record_appends_and_reads_back(self):
        ev = security_events.record(self.dir, "tripwire", "warning", "stranger",
                                    "probe refused", {"labels": ["credential"]})
        self.assertTrue(ev and ev["event_id"])
        lines = security_events.journal_path(self.dir).read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)
        got = json.loads(lines[0])
        self.assertEqual(got["kind"], "tripwire")
        self.assertEqual(got["detail"]["labels"], ["credential"])
        self.assertTrue(got["occurred_at"].endswith("+00:00"))

    def test_event_ids_are_unique(self):
        ids = {security_events.record(self.dir, "tripwire")["event_id"] for _ in range(20)}
        self.assertEqual(len(ids), 20)

    def test_unknown_severity_normalized(self):
        ev = security_events.record(self.dir, "tripwire", "apocalyptic")
        self.assertEqual(ev["severity"], "warning")

    def test_fields_bounded(self):
        ev = security_events.record(self.dir, "k" * 90, "info", "p" * 90, "s" * 900)
        self.assertLessEqual(len(ev["kind"]), 48)
        self.assertLessEqual(len(ev["peer"]), 64)
        self.assertLessEqual(len(ev["summary"]), 400)

    def test_read_since_skips_seen(self):
        a = security_events.record(self.dir, "tripwire")
        b = security_events.record(self.dir, "redaction")
        fresh = security_events.read_since(self.dir, {a["event_id"]})
        self.assertEqual([e["event_id"] for e in fresh], [b["event_id"]])

    def test_read_since_missing_journal_is_empty(self):
        self.assertEqual(security_events.read_since(self.dir / "nope"), [])

    def test_record_never_raises_on_bad_state_dir(self):
        """A security backstop must not break the answer path — even if its disk is gone."""
        blocked = self.dir / "afile"
        blocked.write_text("not a directory")
        self.assertIsNone(security_events.record(blocked / "sub", "tripwire"))

    def test_corrupt_line_does_not_break_reads(self):
        good = security_events.record(self.dir, "tripwire")
        with security_events.journal_path(self.dir).open("a") as fh:
            fh.write("{not json\n")
        after = security_events.record(self.dir, "redaction")
        ids = [e["event_id"] for e in security_events.read_since(self.dir)]
        self.assertIn(good["event_id"], ids)
        self.assertIn(after["event_id"], ids)


class ForwarderTest(unittest.TestCase):
    def test_exits_1_without_token(self):
        import subprocess
        env = dict(os.environ, STATE_DIR=tempfile.mkdtemp())
        env.pop("KOINE_AGENT_TOKEN", None)
        env.pop("KOINE_AGENT_TOKEN_FILE", None)
        r = subprocess.run([sys.executable,
                            str(pathlib.Path(__file__).parent / "security_forward.py")],
                           env=env, capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 1)

    def test_exits_0_when_journal_empty(self):
        import subprocess
        env = dict(os.environ, STATE_DIR=tempfile.mkdtemp(), KOINE_AGENT_TOKEN="kagt_x")
        r = subprocess.run([sys.executable,
                            str(pathlib.Path(__file__).parent / "security_forward.py")],
                           env=env, capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
