#!/usr/bin/env python3
"""Machine-lane unit tests (cid feedback points 1+2): deterministic caldera
read-only answers + pipeline acks, with state-changing kinds and non-caldera
traffic falling through to the LLM path (None).

Run directly: python3 endpoint/test_machine_lane.py
"""
import json
import os
import pathlib
import sys
import tempfile
import unittest

_tmp = tempfile.TemporaryDirectory()
CTX = pathlib.Path(_tmp.name) / "caldera"
CTX.mkdir()
os.environ["CALDERA_CTX"] = str(CTX)
os.environ.setdefault("AGENT_NAME", "atlas-test")
os.environ.setdefault("AUTH_TOKEN", "test-token")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import endpoint  # noqa: E402

PUBLIC = {
    "coord": "caldera/v1", "as_of": "2026-07-21T00:00:00Z",
    "seller": "wilkin-lab",
    "gpus": [{"id": "etna", "availability": [{"from": "a", "to": "b"}],
              "warmth": {"m1": {"state": "cold"}}, "models": []}],
}
ACCOUNT = {"coord": "caldera/v1", "agent": "cid", "balance_usd": -5.0,
           "owed_usd": 0.0, "credit_usd": 5.0}


def _msg(body, mtype="question", sender="cid", channel=""):
    m = {"from": sender, "type": mtype, "id": "m-1",
         "body": body if isinstance(body, str) else json.dumps(body)}
    if channel:
        m["channel"] = channel
    return m


class MachineLaneTest(unittest.TestCase):
    def setUp(self):
        (CTX / "public.json").write_text(json.dumps(PUBLIC))
        (CTX / "account-cid.json").write_text(json.dumps(ACCOUNT))

    def _body(self, msg):
        out = endpoint._machine_answer(msg)
        self.assertIsNotNone(out)
        text, meta = out
        self.assertTrue(meta["machine_lane"])
        self.assertEqual(meta["cost_usd"], 0.0)
        return json.loads(text)

    def test_catalog_served_verbatim(self):
        got = self._body(_msg({"coord": "caldera/v1", "kind": "catalog"}))
        self.assertEqual(got, PUBLIC)

    def test_availability_filtered_and_unknown_gpu(self):
        got = self._body(_msg({"coord": "caldera/v1", "kind": "availability",
                               "gpu_id": "etna"}))
        self.assertEqual(got["kind"], "availability_report")
        self.assertEqual(got["gpus"], [{"id": "etna",
                                        "availability": [{"from": "a", "to": "b"}],
                                        "warmth": {"m1": {"state": "cold"}}}])
        got = self._body(_msg({"coord": "caldera/v1", "kind": "availability",
                               "gpu_id": "gb10"}))
        self.assertIn("unknown gpu_id 'gb10'", got["error"])
        self.assertIn("etna", got["error"])

    def test_balance_reads_own_account_file_only(self):
        got = self._body(_msg({"coord": "caldera/v1", "kind": "balance"}))
        self.assertEqual(got, ACCOUNT)
        # unknown sender -> no file -> falls through to the LLM
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "caldera/v1", "kind": "balance"}, sender="mallory")))
        # path traversal in the sender name is neutralized by sanitization
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "caldera/v1", "kind": "balance"},
                 sender="../../etc/passwd")))

    def test_notification_gets_pipeline_ack(self):
        got = self._body(_msg({"coord": "caldera/v1", "kind": "usage_report"},
                              mtype="notification"))
        self.assertEqual(got["kind"], "ack")
        self.assertEqual(got["of"], "m-1")
        self.assertEqual(got["of_kind"], "usage_report")
        self.assertIn("no LLM", got["note"])

    def test_state_changing_kinds_fall_through(self):
        for kind in ("reserve_propose", "reserve_cancel", "model_request"):
            self.assertIsNone(endpoint._machine_answer(
                _msg({"coord": "caldera/v1", "kind": kind})))
            self.assertIsNone(endpoint._machine_answer(
                _msg({"coord": "caldera/v1", "kind": kind},
                     mtype="notification")))

    def test_non_caldera_and_human_fall_through(self):
        self.assertIsNone(endpoint._machine_answer(
            _msg("hey, what's the weather on the spark?")))
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "other/v1", "kind": "catalog"})))
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "caldera/v1", "kind": "catalog"}, channel="human")))

    def test_missing_context_dir_falls_through(self):
        (CTX / "public.json").unlink()
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "caldera/v1", "kind": "catalog"})))
        self.assertIsNone(endpoint._machine_answer(
            _msg({"coord": "caldera/v1", "kind": "availability"})))


if __name__ == "__main__":
    unittest.main(verbosity=1)
