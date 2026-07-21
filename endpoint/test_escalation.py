#!/usr/bin/env python3
"""Model-escalation unit tests (Darian's 2026-07-21 policy: default opus,
escalate to fable on error). Uses a FAKE claude binary — no model calls.

Run directly: python3 agent-endpoint/test_escalation.py
"""
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest

_tmp = tempfile.TemporaryDirectory()
TMP = pathlib.Path(_tmp.name)

# Fake `claude`: fails on the model named in FAIL_MODEL (exit 1), succeeds on
# anything else, echoing which model served the call.
FAKE = TMP / "fake-claude"
FAKE.write_text("""#!/usr/bin/env python3
import json, os, sys
model = ""
for i, a in enumerate(sys.argv):
    if a == "--model" and i + 1 < len(sys.argv):
        model = sys.argv[i + 1]
if model == os.environ.get("FAIL_MODEL", ""):
    sys.stderr.write("simulated failure on " + model)
    sys.exit(1)
if model == os.environ.get("SOFTFAIL_MODEL", ""):
    print(json.dumps({"result": "confused", "is_error": True}))
    sys.exit(0)
print(json.dumps({"result": "answered by " + model, "total_cost_usd": 0.01}))
""")
FAKE.chmod(FAKE.stat().st_mode | stat.S_IXUSR)

os.environ["CLAUDE_BIN"] = str(FAKE)
os.environ["MODEL"] = "opus"
os.environ["MODEL_ESCALATION"] = "fable"
os.environ["CALDERA_CTX"] = str(TMP / "nonexistent")
os.environ.setdefault("AGENT_NAME", "atlas-test")
os.environ.setdefault("AUTH_TOKEN", "test-token")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import endpoint  # noqa: E402

MSG = {"from": "cid", "type": "question", "id": "m-1", "body": "freeform question"}


class EscalationTest(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("FAIL_MODEL", None)
        os.environ.pop("SOFTFAIL_MODEL", None)

    def test_primary_success_no_escalation(self):
        ok, text, meta = endpoint._answer(MSG)
        self.assertTrue(ok)
        self.assertEqual(text, "answered by opus")
        self.assertNotIn("escalated_from", meta)

    def test_hard_failure_escalates_to_fable(self):
        os.environ["FAIL_MODEL"] = "opus"
        ok, text, meta = endpoint._answer(MSG)
        self.assertTrue(ok)
        self.assertEqual(text, "answered by fable")
        self.assertEqual(meta["escalated_from"], "opus")
        self.assertIn("simulated failure on opus", meta["first_error"])

    def test_is_error_result_escalates(self):
        os.environ["SOFTFAIL_MODEL"] = "opus"
        ok, text, meta = endpoint._answer(MSG)
        self.assertTrue(ok)
        self.assertEqual(text, "answered by fable")
        self.assertEqual(meta["escalated_from"], "opus")

    def test_both_fail_reports_escalated_failure(self):
        os.environ["FAIL_MODEL"] = "opus"
        os.environ["SOFTFAIL_MODEL"] = "fable"
        ok, text, meta = endpoint._answer(MSG)
        self.assertFalse(ok)
        self.assertEqual(meta["escalated_from"], "opus")

    def test_no_escalation_when_unset(self):
        old = endpoint.MODEL_ESCALATION
        endpoint.MODEL_ESCALATION = ""
        try:
            os.environ["FAIL_MODEL"] = "opus"
            ok, text, meta = endpoint._answer(MSG)
            self.assertFalse(ok)
            self.assertNotIn("escalated_from", meta)
        finally:
            endpoint.MODEL_ESCALATION = old

    def test_human_channel_uses_model_human(self):
        ok, text, _meta = endpoint._answer(
            dict(MSG, channel="human", from_="d") | {"from": "darian"})
        self.assertTrue(ok)
        # MODEL_HUMAN defaults to MODEL (opus) in this env
        self.assertEqual(text, "answered by opus")


if __name__ == "__main__":
    unittest.main(verbosity=1)
